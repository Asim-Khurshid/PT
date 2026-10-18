"""
Dynamic analysis using ADB on an emulator/device.
Designed to be lightweight and best-effort (non-fatal on failures).
"""
import os
import re
import time
import subprocess
import ipaddress
from typing import Callable, Dict, List, Optional, Tuple


class DynamicAnalyzer:
    def __init__(
        self,
        apk_path: str,
        package_name: str,
        device_serial: Optional[str] = None,
        duration_seconds: int = 20,
        cancel_check: Optional[Callable[[], bool]] = None,
    ):
        self.apk_path = apk_path
        self.package_name = package_name
        self.device_serial = device_serial
        self.duration_seconds = max(1, duration_seconds)
        self._adb_path = os.environ.get("ADB_PATH", "adb")
        self._install_timeout = int(os.environ.get("DYNAMIC_INSTALL_TIMEOUT", "300"))
        self._cleanup_enabled = os.environ.get("DYNAMIC_CLEANUP", "1") == "1"
        self._capture_network = os.environ.get("DYNAMIC_CAPTURE_NETWORK", "1") == "1"
        self._monkey_events = max(0, int(os.environ.get("DYNAMIC_MONKEY_EVENTS", "50")))
        self._monkey_throttle_ms = max(0, int(os.environ.get("DYNAMIC_MONKEY_THROTTLE_MS", "150")))
        self._take_screenshots = os.environ.get("DYNAMIC_SCREENSHOT", "1") == "1"
        self._screenshot_count = max(1, min(int(os.environ.get("DYNAMIC_SCREENSHOT_COUNT", "1")), 5))
        self._list_app_data = os.environ.get("DYNAMIC_LIST_APP_DATA", "1") == "1"
        self._netstats_enabled = os.environ.get("DYNAMIC_NETSTATS", "1") == "1"
        self._max_data_lines = max(50, min(int(os.environ.get("DYNAMIC_MAX_DATA_LINES", "200")), 1000))
        self._pcap_device_path = None
        self._pcap_local_path = None
        self.cancel_check = cancel_check
        self.step_log: List[Dict] = []

    def _human_bytes(self, num: int) -> str:
        units = ["B", "KB", "MB", "GB", "TB"]
        n = float(num)
        for unit in units:
            if n < 1024 or unit == units[-1]:
                return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} {unit}"
            n /= 1024

    def _log_step(self, step: str, status: str, details: Optional[str] = None):
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "step": step,
            "status": status,
            "details": details or "",
        }
        self.step_log.append(entry)
        print(f"[DYNAMIC] {entry['timestamp']} | {step} | {status} | {entry['details']}")

    def _is_cancelled(self) -> bool:
        if not self.cancel_check:
            return False
        try:
            return bool(self.cancel_check())
        except Exception:
            return False

    def _cancel_result(self, result: Dict) -> Dict:
        result["success"] = False
        result["cancelled"] = True
        result["error"] = "Analysis cancelled by user"
        result["step_log"] = self.step_log
        return result

    def _abort_if_cancelled(self, result: Dict, step: str) -> Optional[Dict]:
        if not self._is_cancelled():
            return None
        self._log_step(step, "cancelled", "Analysis cancelled by user")
        result.setdefault("errors", []).append("Analysis cancelled by user")
        return self._cancel_result(result)

    def _sleep_with_cancel(self, seconds: int, result: Dict, step: str) -> Optional[Dict]:
        remaining = max(0, seconds)
        while remaining > 0:
            cancelled = self._abort_if_cancelled(result, step)
            if cancelled:
                return cancelled
            chunk = min(1, remaining)
            time.sleep(chunk)
            remaining -= chunk
        return None

    def analyze(self) -> Dict:
        result: Dict = {
            "success": False,
            "device": None,
            "device_state": None,
            "package": None,
            "components": {
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": [],
            },
            "main_activity": None,
            "install": None,
            "launch": None,
            "app_uid": None,
            "monkey": {
                "attempted": False,
                "events": 0,
                "result": None,
            },
            "screenshots": [],
            "app_data": {
                "accessible": False,
                "listings": [],
                "errors": [],
            },
            "meminfo": {
                "summary": None,
                "raw": None,
            },
            "netstats": {
                "uid": None,
                "summary": None,
                "raw": None,
                "errors": [],
            },
            "runtime_permissions": [],
            "network_connections": [],
            "running_processes": [],
            "network_capture": {
                "enabled": self._capture_network,
                "device_pcap": None,
                "local_pcap": None,
                "started": False,
                "stopped": False,
                "pulled": False,
                "packet_count": 0,
                "servers": [],
                "analysis": None,
                "errors": [],
            },
            "logcat": {
                "total_lines": 0,
                "matched_lines": 0,
                "sample": [],
                "suspicious_lines": [],
            },
            "indicators": {
                "urls": [],
                "ips": [],
                "keywords": [],
            },
            "server_endpoints": [],
            "findings": [],
            "duration_seconds": self.duration_seconds,
            "errors": [],
            "step_log": [],
            "cleanup": {
                "attempted": False,
                "force_stop": None,
                "pm_clear": None,
                "uninstall": None,
                "errors": [],
            },
        }

        installed = False

        try:
            self._log_step("detect_device", "started", "Listing adb devices")
            device = self._select_device()
            if not device:
                result["errors"].append("No Android device/emulator detected via adb devices")
                self._log_step("detect_device", "failed", "No device found")
                result["step_log"] = self.step_log
                return result

            cancelled = self._abort_if_cancelled(result, "detect_device")
            if cancelled:
                return cancelled

            # Update device_serial if it wasn't set
            if not self.device_serial:
                self.device_serial = device.get("serial")

            result["device"] = device
            result["device_state"] = self._get_device_state(device)
            self._log_step("detect_device", "success", f"{device.get('model','Unknown')} ({device.get('serial')})")

            self._log_step("install_apk", "started", os.path.basename(self.apk_path))
            install_res = self._run_adb(["install", "-r", self.apk_path], timeout=self._install_timeout)
            if not install_res["success"] and self._should_retry_low_target_sdk(install_res):
                self._log_step("install_apk", "started", "retry with --bypass-low-target-sdk-block")
                install_res = self._run_adb(
                    ["install", "-r", "--bypass-low-target-sdk-block", self.apk_path],
                    timeout=self._install_timeout,
                )
            result["install"] = self._summarize_cmd(install_res)
            if not install_res["success"]:
                result["errors"].append("APK install failed")
                self._log_step("install_apk", "failed", result["install"].get("stderr") or "install failed")
                result["step_log"] = self.step_log
                return result
            installed = True
            self._log_step("install_apk", "success", "installed")

            cancelled = self._abort_if_cancelled(result, "install_apk")
            if cancelled:
                return cancelled

            if not self.package_name:
                resolved_pkg = self._resolve_package_name_from_apk()
                if resolved_pkg:
                    self.package_name = resolved_pkg
                else:
                    result["errors"].append("Package name missing; dynamic analysis may be limited")

            if self.package_name:
                self._log_step("package_info", "started")
                pkg_info, components, main_activity = self._get_package_details()
                result["package"] = pkg_info
                result["components"] = components
                result["main_activity"] = main_activity
                self._log_step("package_info", "success", pkg_info.get("version_name") or "ok")

            cancelled = self._abort_if_cancelled(result, "package_info")
            if cancelled:
                return cancelled

            if self.package_name:
                result["app_uid"] = self._get_app_uid()

            if self._capture_network:
                self._log_step("network_capture_start", "started")
                capture_info = self._start_network_capture()
                result["network_capture"].update(capture_info)
                status = "success" if capture_info.get("started") else "failed"
                detail = capture_info.get("error") or "started" if capture_info.get("started") else "not available"
                self._log_step("network_capture_start", status, detail)

            cancelled = self._abort_if_cancelled(result, "network_capture_start")
            if cancelled:
                return cancelled

            self._log_step("logcat_clear", "started")
            self._run_adb(["logcat", "-c"], timeout=15)
            self._log_step("logcat_clear", "success")

            cancelled = self._abort_if_cancelled(result, "logcat_clear")
            if cancelled:
                return cancelled

            self._log_step("launch_app", "started", self.package_name or "(unknown package)")
            if self.package_name:
                component = result.get("main_activity") or self._get_main_activity()
                if component:
                    launch_res = self._run_adb(
                        ["shell", "am", "start", "-n", component, "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER"],
                        timeout=30,
                    )
                else:
                    launch_res = self._run_adb(
                        ["shell", "monkey", "-p", self.package_name, "-c", "android.intent.category.LAUNCHER", "1"],
                        timeout=30,
                    )
                result["launch"] = self._summarize_cmd(launch_res)
                if not launch_res["success"]:
                    result["errors"].append("APK launch failed (monkey)")
                    self._log_step("launch_app", "failed", result["launch"].get("stderr") or "launch failed")
                else:
                    self._log_step("launch_app", "success", "launch ok")
            else:
                result["errors"].append("Package name missing; launch skipped")
                self._log_step("launch_app", "failed", "package name missing")

            cancelled = self._abort_if_cancelled(result, "launch_app")
            if cancelled:
                return cancelled

            self._log_step("runtime_wait", "started", f"{self.duration_seconds}s")
            cancelled = self._sleep_with_cancel(self.duration_seconds, result, "runtime_wait")
            if cancelled:
                return cancelled
            self._log_step("runtime_wait", "success")

            if self.package_name and self._monkey_events > 0:
                self._log_step("monkey_events", "started", f"{self._monkey_events} events")
                monkey_res = self._run_adb(
                    [
                        "shell",
                        "monkey",
                        "-p",
                        self.package_name,
                        "--throttle",
                        str(self._monkey_throttle_ms),
                        str(self._monkey_events),
                    ],
                    timeout=min(self._install_timeout, 120),
                )
                result["monkey"]["attempted"] = True
                result["monkey"]["events"] = self._monkey_events
                result["monkey"]["result"] = self._summarize_cmd(monkey_res)
                status = "success" if monkey_res["success"] else "failed"
                self._log_step("monkey_events", status, result["monkey"]["result"].get("stderr") or "ok")

            cancelled = self._abort_if_cancelled(result, "monkey_events")
            if cancelled:
                return cancelled

            if self._take_screenshots:
                self._log_step("screenshots", "started", f"{self._screenshot_count} capture(s)")
                result["screenshots"] = self._capture_screenshots(self._screenshot_count)
                self._log_step("screenshots", "success", f"{len(result['screenshots'])} saved")

            cancelled = self._abort_if_cancelled(result, "screenshots")
            if cancelled:
                return cancelled

            if self._list_app_data and self.package_name:
                self._log_step("app_data", "started")
                result["app_data"] = self._list_app_data_dir()
                status = "success" if result["app_data"].get("accessible") else "failed"
                self._log_step("app_data", status, "listed" if status == "success" else "not accessible")

            cancelled = self._abort_if_cancelled(result, "app_data")
            if cancelled:
                return cancelled

            if self.package_name:
                self._log_step("meminfo", "started")
                result["meminfo"] = self._get_meminfo()
                self._log_step("meminfo", "success", result["meminfo"].get("summary") or "ok")

            cancelled = self._abort_if_cancelled(result, "meminfo")
            if cancelled:
                return cancelled

            if self._capture_network:
                self._log_step("network_capture_stop", "started")
                capture_stop = self._stop_network_capture()
                result["network_capture"].update(capture_stop)
                if capture_stop.get("servers"):
                    result["server_endpoints"] = capture_stop.get("servers")
                status = "success" if capture_stop.get("stopped") else "failed"
                detail = capture_stop.get("error") or "stopped" if capture_stop.get("stopped") else "not available"
                self._log_step("network_capture_stop", status, detail)

            cancelled = self._abort_if_cancelled(result, "network_capture_stop")
            if cancelled:
                return cancelled

            self._log_step("logcat_dump", "started")
            logcat_res = self._run_adb(["logcat", "-d"], timeout=30)
            log_lines = logcat_res["stdout"].splitlines() if logcat_res["stdout"] else []
            result["logcat"]["total_lines"] = len(log_lines)
            self._log_step("logcat_dump", "success", f"{len(log_lines)} lines")

            cancelled = self._abort_if_cancelled(result, "logcat_dump")
            if cancelled:
                return cancelled

            filtered_lines = self._filter_logcat(log_lines)
            result["logcat"]["matched_lines"] = len(filtered_lines)
            result["logcat"]["sample"] = filtered_lines[:200]

            suspicious_lines, indicators = self._extract_indicators(log_lines)
            result["logcat"]["suspicious_lines"] = suspicious_lines[:100]
            result["indicators"] = indicators

            self._log_step("runtime_permissions", "started")
            result["runtime_permissions"] = self._get_runtime_permissions()
            self._log_step("runtime_permissions", "success", f"{len(result['runtime_permissions'])} entries")

            cancelled = self._abort_if_cancelled(result, "runtime_permissions")
            if cancelled:
                return cancelled

            self._log_step("running_processes", "started")
            result["running_processes"] = self._get_running_processes()
            self._log_step("running_processes", "success", f"{len(result['running_processes'])} entries")

            cancelled = self._abort_if_cancelled(result, "running_processes")
            if cancelled:
                return cancelled

            self._log_step("network_connections", "started")
            result["network_connections"] = self._get_network_connections()
            self._log_step("network_connections", "success", f"{len(result['network_connections'])} entries")

            cancelled = self._abort_if_cancelled(result, "network_connections")
            if cancelled:
                return cancelled

            if self._netstats_enabled and result.get("app_uid"):
                self._log_step("netstats", "started")
                result["netstats"] = self._collect_netstats(result.get("app_uid"))
                self._log_step("netstats", "success", result["netstats"].get("summary") or "ok")

            cancelled = self._abort_if_cancelled(result, "netstats")
            if cancelled:
                return cancelled

            result["findings"] = self._build_findings(
                log_lines=log_lines,
                indicators=indicators,
                runtime_permissions=result["runtime_permissions"],
                network_connections=result["network_connections"],
            )

            cancelled = self._abort_if_cancelled(result, "findings")
            if cancelled:
                return cancelled

            result["success"] = True
            result["step_log"] = self.step_log
            return result
        finally:
            if self._cleanup_enabled and installed and self.package_name:
                cleanup = self._cleanup_app()
                result["cleanup"] = cleanup

    def _select_device(self) -> Optional[Dict]:
        devices = self._list_devices()
        if not devices:
            return None

        if self.device_serial:
            for device in devices:
                if device["serial"] == self.device_serial:
                    return device
            return None

        return devices[0]

    def _list_devices(self) -> List[Dict]:
        res = self._run_adb(["devices"], timeout=10)
        if not res["success"]:
            return []

        devices = []
        for line in res["stdout"].splitlines():
            if "\tdevice" in line:
                serial = line.split("\t")[0].strip()
                device_info = self._get_device_info(serial)
                devices.append(device_info)
        return devices

    def _get_device_info(self, serial: str) -> Dict:
        model = self._run_adb(["-s", serial, "shell", "getprop", "ro.product.model"], timeout=10)
        sdk = self._run_adb(["-s", serial, "shell", "getprop", "ro.build.version.sdk"], timeout=10)
        android_version = self._run_adb(["-s", serial, "shell", "getprop", "ro.build.version.release"], timeout=10)

        return {
            "serial": serial,
            "model": (model["stdout"] or "").strip(),
            "sdk": (sdk["stdout"] or "").strip(),
            "android_version": (android_version["stdout"] or "").strip(),
        }

    def _filter_logcat(self, lines: List[str]) -> List[str]:
        if not self.package_name:
            return lines[-200:]

        filtered = [line for line in lines if self.package_name in line]
        if filtered:
            return filtered[-200:]

        return lines[-200:]

    def _extract_indicators(self, lines: List[str]) -> (List[str], Dict):
        url_pattern = re.compile(r"https?://[^\s]+", re.IGNORECASE)
        ip_pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        keyword_pattern = re.compile(r"(token|password|apikey|api_key|secret|crypto|ssl|tls|http://)", re.IGNORECASE)

        urls = set()
        ips = set()
        keywords = set()
        suspicious_lines = []

        for line in lines:
            for url in url_pattern.findall(line):
                urls.add(url)
            for ip in ip_pattern.findall(line):
                ips.add(ip)
            for kw in keyword_pattern.findall(line):
                keywords.add(kw)
                suspicious_lines.append(line)

        indicators = {
            "urls": sorted(list(urls))[:50],
            "ips": sorted(list(ips))[:50],
            "keywords": sorted(list(keywords))[:50],
        }

        return suspicious_lines, indicators

    def _build_findings(
        self,
        log_lines: List[str],
        indicators: Dict,
        runtime_permissions: List[str],
        network_connections: List[str],
    ) -> List[Dict]:
        findings = []

        http_urls = [u for u in indicators.get("urls", []) if u.lower().startswith("http://")]
        if http_urls:
            findings.append({
                "title": "Cleartext HTTP traffic detected",
                "severity": "high",
                "category": "Network",
                "description": "The application appears to transmit data over cleartext HTTP.",
                "evidence": http_urls[:10],
                "remediation": "Enforce HTTPS and implement network security configuration and certificate pinning.",
                "standard": "OWASP Mobile Top 10: M3 - Insecure Communication",
            })

        tls_errors = self._find_tls_errors(log_lines)
        if tls_errors:
            findings.append({
                "title": "TLS/SSL errors observed during runtime",
                "severity": "medium",
                "category": "Network",
                "description": "Runtime logs indicate TLS/SSL handshake or certificate validation errors.",
                "evidence": tls_errors[:10],
                "remediation": "Validate certificates properly and avoid custom trust managers that accept all certs.",
                "standard": "OWASP Mobile Top 10: M3 - Insecure Communication",
            })

        sensitive_logs = self._find_sensitive_logcat(log_lines)
        if sensitive_logs:
            findings.append({
                "title": "Sensitive data exposed in logs",
                "severity": "high",
                "category": "Data Leakage",
                "description": "Logcat contains potential secrets or tokens which may expose sensitive data.",
                "evidence": sensitive_logs[:10],
                "remediation": "Remove sensitive data from logs and disable verbose logging in production.",
                "standard": "OWASP Mobile Top 10: M2 - Insecure Data Storage",
            })

        net_findings = self._analyze_network_connections(network_connections)
        findings.extend(net_findings)

        dangerous_runtime = [p for p in runtime_permissions if "granted=true" in p]
        if len(dangerous_runtime) >= 6:
            findings.append({
                "title": "Excessive dangerous permissions granted at runtime",
                "severity": "low",
                "category": "Platform Usage",
                "description": "A high number of dangerous permissions were granted at runtime, increasing attack surface.",
                "evidence": dangerous_runtime[:10],
                "remediation": "Request only necessary permissions and justify usage to users.",
                "standard": "OWASP Mobile Top 10: M1 - Improper Platform Usage",
            })

        return findings

    def _find_tls_errors(self, lines: List[str]) -> List[str]:
        tls_patterns = re.compile(
            r"(SSLHandshakeException|CERTIFICATE_VERIFY_FAILED|Trust anchor for certification path not found|SSLPeerUnverifiedException|hostname verification failed|HostnameVerifier|CertPathValidatorException)",
            re.IGNORECASE,
        )
        return [line for line in lines if tls_patterns.search(line)]

    def _find_sensitive_logcat(self, lines: List[str]) -> List[str]:
        sensitive_patterns = re.compile(r"(token=|password=|apikey=|api_key=|secret=|authorization:|bearer )", re.IGNORECASE)
        return [line for line in lines if sensitive_patterns.search(line)]

    def _analyze_network_connections(self, lines: List[str]) -> List[Dict]:
        findings = []
        endpoints = self._extract_network_endpoints(lines)
        suspicious = [e for e in endpoints if e.get("remote_port") in {80, 8080, 8888}]
        public_ips = [e for e in endpoints if self._is_public_ip(e.get("remote_ip"))]

        if suspicious:
            findings.append({
                "title": "Potential cleartext network connections",
                "severity": "medium",
                "category": "Network",
                "description": "Network connections detected on ports typically used for unencrypted HTTP.",
                "evidence": suspicious[:10],
                "remediation": "Ensure all network traffic uses HTTPS and disable cleartext traffic.",
                "standard": "OWASP Mobile Top 10: M3 - Insecure Communication",
            })

        if public_ips:
            findings.append({
                "title": "Connections to public IPs observed",
                "severity": "info",
                "category": "Network",
                "description": "The app is communicating with public IP addresses during runtime.",
                "evidence": public_ips[:10],
                "remediation": "Review external endpoints for legitimacy and monitor for anomalous traffic.",
                "standard": "OWASP Mobile Top 10: M10 - Extraneous Functionality",
            })

        return findings

    def _get_runtime_permissions(self) -> List[str]:
        if not self.package_name:
            return []

        res = self._run_adb(["shell", "dumpsys", "package", self.package_name], timeout=20)
        if not res["success"] or not res["stdout"]:
            return []

        permissions = []
        for line in res["stdout"].splitlines():
            if "granted=true" in line:
                permissions.append(line.strip())
        return permissions[:200]

    def _get_running_processes(self) -> List[str]:
        if not self.package_name:
            return []

        res = self._run_adb(["shell", "ps"], timeout=15)
        if not res["success"] or not res["stdout"]:
            return []

        return [line.strip() for line in res["stdout"].splitlines() if self.package_name in line][:50]

    def _get_network_connections(self) -> List[str]:
        commands = [
            ["shell", "netstat", "-an"],
            ["shell", "ss", "-an"],
            ["shell", "cat", "/proc/net/tcp"],
        ]

        for cmd in commands:
            res = self._run_adb(cmd, timeout=20)
            if res["success"] and res["stdout"]:
                lines = res["stdout"].splitlines()
                return lines[:200]
        return []

    def _extract_network_endpoints(self, lines: List[str]) -> List[Dict]:
        endpoints = []
        ip_port_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+):(\d+)")

        for line in lines:
            matches = ip_port_pattern.findall(line)
            if len(matches) >= 2:
                local_ip, local_port = matches[0]
                remote_ip, remote_port = matches[1]
                endpoints.append({
                    "local_ip": local_ip,
                    "local_port": int(local_port),
                    "remote_ip": remote_ip,
                    "remote_port": int(remote_port),
                    "raw": line.strip(),
                })

        if not endpoints:
            endpoints.extend(self._parse_proc_net(lines))

        return endpoints

    def _parse_proc_net(self, lines: List[str]) -> List[Dict]:
        endpoints = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("sl"):
                continue

            parts = re.split(r"\s+", line)
            if len(parts) < 3:
                continue

            local_hex, remote_hex = parts[1], parts[2]
            local_ip, local_port = self._hex_to_ip_port(local_hex)
            remote_ip, remote_port = self._hex_to_ip_port(remote_hex)
            if local_ip and remote_ip:
                endpoints.append({
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "raw": line,
                })
        return endpoints

    def _hex_to_ip_port(self, value: str) -> Tuple[Optional[str], Optional[int]]:
        try:
            ip_hex, port_hex = value.split(":")
            port = int(port_hex, 16)
            ip_bytes = [ip_hex[i:i+2] for i in range(0, len(ip_hex), 2)]
            ip_bytes.reverse()
            ip = ".".join(str(int(b, 16)) for b in ip_bytes)
            return ip, port
        except Exception:
            return None, None

    def _is_public_ip(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
        except Exception:
            return False

    def _get_app_uid(self) -> Optional[str]:
        if not self.package_name:
            return None
        res = self._run_adb(["shell", "dumpsys", "package", self.package_name], timeout=20)
        if not res["success"] or not res["stdout"]:
            return None
        match = re.search(r"userId=(\d+)", res["stdout"])
        return match.group(1) if match else None

    def _start_network_capture(self) -> Dict:
        info = {"started": False}
        if not self._has_tcpdump():
            info["error"] = "tcpdump not available on device"
            return info

        timestamp = int(time.time())
        self._pcap_device_path = f"/sdcard/falconscan_{timestamp}.pcap"
        cmd = ["shell", f"tcpdump -i any -p -s 0 -w {self._pcap_device_path} >/dev/null 2>&1 &"]
        res = self._run_adb(cmd, timeout=10)
        info["device_pcap"] = self._pcap_device_path
        info["started"] = res["success"]
        if not res["success"]:
            info["error"] = res.get("stderr") or "tcpdump start failed"
        return info

    def _stop_network_capture(self) -> Dict:
        info = {"stopped": False, "pulled": False}
        res = self._run_adb(["shell", "pkill", "-f", "tcpdump"], timeout=10)
        info["stopped"] = res["success"]
        if not res["success"]:
            res = self._run_adb(["shell", "killall", "tcpdump"], timeout=10)
            info["stopped"] = res["success"]

        if self._pcap_device_path:
            local_dir = os.path.join(os.getcwd(), "media", "pcaps")
            os.makedirs(local_dir, exist_ok=True)
            local_path = os.path.join(local_dir, os.path.basename(self._pcap_device_path))
            pull = self._run_adb(["pull", self._pcap_device_path, local_path], timeout=30)
            if pull["success"]:
                self._pcap_local_path = local_path
                info["pulled"] = True
                info["local_pcap"] = local_path
                analysis = self._analyze_pcap(local_path)
                info["analysis"] = analysis
                info["packet_count"] = analysis.get("packet_count", 0)
                info["servers"] = analysis.get("servers", [])
                if analysis.get("errors"):
                    info.setdefault("errors", []).extend(analysis.get("errors", []))
            else:
                info["error"] = pull.get("stderr") or "pcap pull failed"

            self._run_adb(["shell", "rm", "-f", self._pcap_device_path], timeout=10)

        return info

    def _has_tcpdump(self) -> bool:
        res = self._run_adb(["shell", "command", "-v", "tcpdump"], timeout=10)
        return res["success"] and bool((res.get("stdout") or "").strip())

    def _cleanup_app(self) -> Dict:
        cleanup = {
            "attempted": True,
            "force_stop": None,
            "pm_clear": None,
            "uninstall": None,
            "errors": [],
        }

        if not self.package_name:
            cleanup["errors"].append("package name missing")
            return cleanup

        force_stop = self._run_adb(["shell", "am", "force-stop", self.package_name], timeout=20)
        cleanup["force_stop"] = self._summarize_cmd(force_stop)

        pm_clear = self._run_adb(["shell", "pm", "clear", self.package_name], timeout=30)
        cleanup["pm_clear"] = self._summarize_cmd(pm_clear)

        uninstall = self._run_adb(["uninstall", self.package_name], timeout=60)
        cleanup["uninstall"] = self._summarize_cmd(uninstall)

        if not uninstall["success"]:
            cleanup["errors"].append(uninstall.get("stderr") or "uninstall failed")

        return cleanup

    def _get_device_state(self, device: Dict) -> Dict:
        props = {
            "model": device.get("model"),
            "sdk": device.get("sdk"),
            "android_version": device.get("android_version"),
            "fingerprint": self._get_prop("ro.build.fingerprint"),
            "security_patch": self._get_prop("ro.build.version.security_patch"),
            "build_id": self._get_prop("ro.build.id"),
            "brand": self._get_prop("ro.product.brand"),
            "device": self._get_prop("ro.product.device"),
            "manufacturer": self._get_prop("ro.product.manufacturer"),
            "debuggable": self._get_prop("ro.debuggable"),
            "secure": self._get_prop("ro.secure"),
        }

        fingerprint = (props.get("fingerprint") or "").lower()
        model = (props.get("model") or "").lower()
        device_name = (props.get("device") or "").lower()
        emulator_markers = ["generic", "sdk_gphone", "emulator", "goldfish", "ranchu", "virtual"]
        is_emulator = any(m in fingerprint for m in emulator_markers) or any(m in model for m in emulator_markers) or any(m in device_name for m in emulator_markers)

        return {
            "props": props,
            "is_emulator": is_emulator,
        }

    def _get_prop(self, name: str) -> str:
        res = self._run_adb(["shell", "getprop", name], timeout=10)
        return (res.get("stdout") or "").strip()

    def _resolve_package_name_from_apk(self) -> Optional[str]:
        aapt = os.environ.get("AAPT_PATH", "aapt")
        try:
            completed = subprocess.run(
                [aapt, "dump", "badging", self.apk_path],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if completed.returncode != 0:
                return None
            match = re.search(r"package: name='([^']+)'", completed.stdout)
            return match.group(1) if match else None
        except Exception:
            return None

    def _get_package_details(self) -> Tuple[Dict, Dict, Optional[str]]:
        info = {}
        components = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }
        main_activity = None

        if not self.package_name:
            return info, components, main_activity

        res = self._run_adb(["shell", "dumpsys", "package", self.package_name], timeout=30)
        if not res.get("success") or not res.get("stdout"):
            return info, components, main_activity

        text = res.get("stdout") or ""

        info["name"] = self.package_name
        info["version_name"] = self._extract_first_match(text, r"versionName=([^\s]+)")
        info["version_code"] = self._extract_first_match(text, r"versionCode=(\d+)")
        info["min_sdk"] = self._extract_first_match(text, r"minSdk=(\d+)")
        info["target_sdk"] = self._extract_first_match(text, r"targetSdk=(\d+)")
        info["code_path"] = self._extract_first_match(text, r"codePath=([^\s]+)")
        info["data_dir"] = self._extract_first_match(text, r"dataDir=([^\s]+)")
        info["first_install_time"] = self._extract_first_match(text, r"firstInstallTime=([^\n]+)")
        info["last_update_time"] = self._extract_first_match(text, r"lastUpdateTime=([^\n]+)")
        info["debuggable"] = "DEBUGGABLE" in text or "debuggable=true" in text

        components = self._parse_components_from_dumpsys(text)
        main_activity = self._get_main_activity(text)

        return info, components, main_activity

    def _parse_components_from_dumpsys(self, text: str) -> Dict:
        components = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }
        if not text or not self.package_name:
            return components

        section_map = {
            "activities": "activities",
            "services": "services",
            "receivers": "receivers",
            "providers": "providers",
        }

        current = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.lower() == "activities:":
                current = "activities"
                continue
            if stripped.lower() == "services:":
                current = "services"
                continue
            if stripped.lower() == "receivers:":
                current = "receivers"
                continue
            if stripped.lower() == "providers:":
                current = "providers"
                continue

            if not current:
                continue

            component = self._extract_component_from_line(line)
            if component:
                key = section_map.get(current, current)
                components[key].append(component)

        for key in components:
            components[key] = sorted(list(set(components[key])))[:200]

        return components

    def _extract_component_from_line(self, line: str) -> Optional[str]:
        if not self.package_name:
            return None
        match = re.search(rf"({re.escape(self.package_name)}/[^\s]+)", line)
        if not match:
            return None
        return self._normalize_component(match.group(1))

    def _get_main_activity(self, dumpsys_text: Optional[str] = None) -> Optional[str]:
        if not self.package_name:
            return None

        if dumpsys_text:
            lines = dumpsys_text.splitlines()
            lookahead = 0
            for line in lines:
                if "android.intent.action.MAIN" in line or "android.intent.category.LAUNCHER" in line:
                    lookahead = 10
                if lookahead > 0:
                    component = self._extract_component_from_line(line)
                    if component:
                        return component
                    lookahead -= 1

        cmd_component = self._resolve_main_activity_by_cmd()
        return cmd_component

    def _resolve_main_activity_by_cmd(self) -> Optional[str]:
        res = self._run_adb(["shell", "cmd", "package", "resolve-activity", "--brief", self.package_name], timeout=15)
        if not res.get("success") or not res.get("stdout"):
            return None
        for line in res.get("stdout").splitlines():
            line = line.strip()
            if "/" in line and self.package_name in line:
                return self._normalize_component(line)
        return None

    def _normalize_component(self, component: str) -> str:
        if "/" not in component:
            return component
        pkg, activity = component.split("/", 1)
        if activity.startswith("."):
            activity = f"{pkg}{activity}"
        return f"{pkg}/{activity}"

    def _capture_screenshots(self, count: int) -> List[str]:
        if count <= 0:
            return []

        local_dir = os.path.join(os.getcwd(), "media", "screenshots")
        os.makedirs(local_dir, exist_ok=True)
        saved = []

        for i in range(count):
            timestamp = int(time.time())
            device_path = f"/sdcard/falconscan_{timestamp}_{i}.png"
            local_path = os.path.join(local_dir, os.path.basename(device_path))

            cap = self._run_adb(["shell", "screencap", "-p", device_path], timeout=15)
            if not cap.get("success"):
                continue

            pull = self._run_adb(["pull", device_path, local_path], timeout=20)
            if pull.get("success"):
                saved.append(local_path)

            self._run_adb(["shell", "rm", "-f", device_path], timeout=10)
            time.sleep(0.5)

        return saved

    def _list_app_data_dir(self) -> Dict:
        result = {
            "accessible": False,
            "listings": [],
            "errors": [],
        }
        if not self.package_name:
            result["errors"].append("package name missing")
            return result

        commands = [
            ["shell", "run-as", self.package_name, "ls", "-la"],
            ["shell", "run-as", self.package_name, "ls", "-la", "files"],
            ["shell", "run-as", self.package_name, "ls", "-la", "databases"],
        ]

        for cmd in commands:
            res = self._run_adb(cmd, timeout=20)
            if res.get("success") and res.get("stdout"):
                lines = res.get("stdout").splitlines()
                result["listings"].extend(self._safe_trim_lines(lines))
                result["accessible"] = True
            else:
                err = (res.get("stderr") or "").strip()
                if err:
                    result["errors"].append(err)

        return result

    def _get_meminfo(self) -> Dict:
        info = {
            "summary": None,
            "raw": None,
        }
        if not self.package_name:
            return info

        res = self._run_adb(["shell", "dumpsys", "meminfo", self.package_name], timeout=25)
        if not res.get("success") or not res.get("stdout"):
            return info

        lines = res.get("stdout").splitlines()
        info["raw"] = "\n".join(self._safe_trim_lines(lines))

        for line in lines:
            if line.strip().startswith("TOTAL"):
                info["summary"] = line.strip()
                break

        return info

    def _collect_netstats(self, uid: Optional[str]) -> Dict:
        info = {
            "uid": uid,
            "summary": None,
            "raw": None,
            "errors": [],
        }
        if not uid:
            info["errors"].append("uid missing")
            return info

        res = self._run_adb(["shell", "cat", "/proc/net/xt_qtaguid/stats"], timeout=25)
        if res.get("success") and res.get("stdout"):
            lines = res.get("stdout").splitlines()
            summary, filtered = self._parse_qtaguid_stats(lines, uid)
            info["summary"] = summary
            info["raw"] = "\n".join(self._safe_trim_lines(filtered))
        else:
            err = (res.get("stderr") or "").strip()
            if err:
                info["errors"].append(err)

        detail = self._run_adb(["shell", "dumpsys", "netstats", "detail", "--uid", str(uid)], timeout=25)
        if detail.get("success") and detail.get("stdout"):
            detail_lines = detail.get("stdout").splitlines()
            detail_text = "\n".join(self._safe_trim_lines(detail_lines))
            info["raw"] = f"{info.get('raw') or ''}\n\n{detail_text}".strip()

        return info

    def _parse_qtaguid_stats(self, lines: List[str], uid: str) -> Tuple[str, List[str]]:
        total_rx = 0
        total_tx = 0
        filtered = []
        for line in lines:
            if line.startswith("idx"):
                continue
            parts = re.split(r"\s+", line.strip())
            if len(parts) < 9:
                continue
            line_uid = parts[3]
            if line_uid != str(uid):
                continue
            try:
                rx_bytes = int(parts[5])
                tx_bytes = int(parts[7])
                total_rx += rx_bytes
                total_tx += tx_bytes
            except Exception:
                pass
            filtered.append(line)

        if total_rx == 0 and total_tx == 0:
            summary = "No app network traffic observed (0 sent, 0 received)"
        else:
            summary = (
                f"Network data — sent: {self._human_bytes(total_tx)}"
                f" • received: {self._human_bytes(total_rx)}"
            )
        return summary, filtered

    def _analyze_pcap(self, pcap_path: str) -> Dict:
        analysis = {"packet_count": 0, "servers": [], "errors": []}
        if not pcap_path or not os.path.isfile(pcap_path):
            analysis["errors"].append("pcap not found")
            return analysis

        try:
            with open(pcap_path, "rb") as fh:
                global_header = fh.read(24)
                if len(global_header) < 24:
                    analysis["errors"].append("invalid pcap header")
                    return analysis

                magic_le = int.from_bytes(global_header[0:4], byteorder="little")
                magic_be = int.from_bytes(global_header[0:4], byteorder="big")
                endian = "little"
                if magic_be == 0xA1B2C3D4:
                    endian = "big"
                elif magic_le == 0xD4C3B2A1:
                    endian = "little"
                network = int.from_bytes(global_header[20:24], byteorder=endian)

                server_map = {}
                max_packets = 5000

                while analysis["packet_count"] < max_packets:
                    header = fh.read(16)
                    if len(header) < 16:
                        break
                    incl_len = int.from_bytes(header[8:12], byteorder=endian)
                    if incl_len <= 0 or incl_len > 10_000_000:
                        break
                    data = fh.read(incl_len)
                    if len(data) < incl_len:
                        break

                    analysis["packet_count"] += 1
                    ip_offset = self._get_ip_offset(network, data)
                    if ip_offset is None or len(data) < ip_offset + 20:
                        continue

                    version_ihl = data[ip_offset]
                    version = version_ihl >> 4
                    ihl = (version_ihl & 0x0F) * 4
                    if version != 4 or len(data) < ip_offset + ihl + 8:
                        continue

                    ttl = data[ip_offset + 8]
                    proto = data[ip_offset + 9]
                    src_ip = ".".join(str(b) for b in data[ip_offset + 12: ip_offset + 16])
                    dst_ip = ".".join(str(b) for b in data[ip_offset + 16: ip_offset + 20])

                    src_port = None
                    dst_port = None
                    if proto in (6, 17) and len(data) >= ip_offset + ihl + 4:
                        src_port = int.from_bytes(data[ip_offset + ihl: ip_offset + ihl + 2], "big")
                        dst_port = int.from_bytes(data[ip_offset + ihl + 2: ip_offset + ihl + 4], "big")

                    remote_ip = src_ip if self._is_public_ip(src_ip) else dst_ip if self._is_public_ip(dst_ip) else None
                    if not remote_ip:
                        continue

                    entry = server_map.setdefault(remote_ip, {"ip": remote_ip, "ports": set(), "protocols": set(), "ttl_samples": [], "packet_count": 0})
                    entry["packet_count"] += 1
                    if src_port:
                        entry["ports"].add(src_port)
                    if dst_port:
                        entry["ports"].add(dst_port)
                    if proto == 6:
                        entry["protocols"].add("TCP")
                    elif proto == 17:
                        entry["protocols"].add("UDP")
                    else:
                        entry["protocols"].add(str(proto))

                    if self._is_public_ip(src_ip) and not self._is_public_ip(dst_ip):
                        entry["ttl_samples"].append(ttl)
                    elif self._is_public_ip(dst_ip) and not self._is_public_ip(src_ip):
                        entry["ttl_samples"].append(ttl)

                servers = []
                for srv in server_map.values():
                    ttl_guess = srv.get("ttl_samples") or []
                    avg_ttl = sum(ttl_guess) / len(ttl_guess) if ttl_guess else None
                    servers.append({
                        "ip": srv["ip"],
                        "ports": sorted(list(srv["ports"]))[:10],
                        "protocols": sorted(list(srv["protocols"]))[:5],
                        "packet_count": srv["packet_count"],
                        "ttl": int(avg_ttl) if avg_ttl is not None else None,
                        "os_guess": self._guess_os_from_ttl(avg_ttl) if avg_ttl is not None else "unknown",
                    })

                servers = sorted(servers, key=lambda s: s.get("packet_count", 0), reverse=True)
                analysis["servers"] = servers[:20]
                return analysis

        except Exception as exc:
            analysis["errors"].append(str(exc))

        return analysis

    def _get_ip_offset(self, link_type: int, data: bytes) -> Optional[int]:
        if link_type == 1:  # Ethernet
            return 14
        if link_type == 101:  # RAW
            return 0
        if link_type == 113:  # Linux cooked capture
            return 16
        return None

    def _guess_os_from_ttl(self, ttl: Optional[float]) -> str:
        if ttl is None:
            return "unknown"
        candidates = {
            255: "network device (ttl~255)",
            128: "windows family (ttl~128)",
            64: "linux/unix (ttl~64)",
        }
        best = min(candidates.keys(), key=lambda base: abs(base - ttl))
        if abs(best - ttl) > 40:
            return "unknown"
        return candidates[best]

    def _extract_first_match(self, text: str, pattern: str) -> Optional[str]:
        match = re.search(pattern, text)
        return match.group(1) if match else None

    def _safe_trim_lines(self, lines: List[str]) -> List[str]:
        return [line.rstrip() for line in lines][: self._max_data_lines]

    def _summarize_cmd(self, res: Dict) -> Dict:
        return {
            "success": res["success"],
            "stdout": (res["stdout"] or "").strip()[:2000],
            "stderr": (res["stderr"] or "").strip()[:2000],
        }

    def _should_retry_low_target_sdk(self, res: Dict) -> bool:
        if os.environ.get("DYNAMIC_ALLOW_LOW_TARGET_SDK", "1") != "1":
            return False
        stderr = (res.get("stderr") or "") + " " + (res.get("stdout") or "")
        return "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in stderr or "INSTALL_FAILED_OLDER_SDK" in stderr

    def _run_adb(self, args: List[str], timeout: int = 30) -> Dict:
        adb_args = args[:]
        if self.device_serial and "-s" not in adb_args:
            if adb_args and adb_args[0] not in ("devices", "connect", "kill-server", "start-server"):
                adb_args = ["-s", self.device_serial] + adb_args
        cmd = [self._adb_path] + adb_args
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=timeout,
            )
            return {
                "success": completed.returncode == 0,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "returncode": completed.returncode,
                "command": " ".join(cmd),
            }
        except Exception as exc:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(exc),
                "returncode": -1,
                "command": " ".join(cmd),
            }
