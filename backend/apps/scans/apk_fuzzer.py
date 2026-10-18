"""
FalconScan — Android Component Security Analyzer
Fuzzes Android app components: Activities, Services, Broadcast Receivers, Content Providers.

Engines (run in order, all that are available are combined):
  1. falcon-static   manifest attribute inspection (always runs)
  2. falcon-dynamic  DEX/APK code-level analysis: intent→SQL, path-traversal,
                     WebView JS, weak crypto  (always runs, no device required)
  3. falcon-runtime  live ADB probing on connected device/emulator
  4. falcon-deep     full component interaction via Drozer agent
"""
import os
import re
import time
import subprocess
from collections import Counter
from typing import Any, Dict, List, Optional, Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait


# ─── Engine Detection ─────────────────────────────────────────────────────────

def _probe(cmd: list, timeout: int = 5) -> bool:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


ADB_PATH          = os.environ.get("ADB_PATH", "adb")
ADB_AVAILABLE     = _probe([ADB_PATH, "version"])
_DROZER_UP        = _probe(["drozer", "console", "--help"])  
DEEP_ENGINE_ACTIVE = _DROZER_UP and ADB_AVAILABLE              # public: is the deep-analysis engine ready?


# ─── Intent / Component Payloads ─────────────────────────────────────────────
# Validated against CVE-2017-13312, CVE-2015-3836, CVE-2020-0001
# References: OWASP MASTG (MASTG-TEST-0025, 0028), NIST SP 800-124 Rev. 1

INTENT_STRING_PAYLOADS = [
    # === Basic Edge Cases (Test Default Handling) ===
    "",                                             # empty string
    "null",                                         # literal "null"
    
    # === Buffer/Size Attacks (CVE-2017-13312) ===
    "A" * 8096,                                     # buffer overflow attempt
    "A" * 65536,                                    # larger buffer test
    "\x00" * 1024,                                  # null byte padding
    
    # === SQL Injection - Content Providers (OWASP MASWE-0058) ===
    "' OR '1'='1",                                  # classic boolean SQLi
    "' OR 'x'='x",                                  # alternative boolean
    "1' UNION SELECT NULL,NULL,NULL,NULL,NULL--",  # UNION-based injection
    "1 UNION SELECT name,sql,NULL,NULL,NULL FROM sqlite_master--",  # schema enumeration
    "'; DROP TABLE android_metadata; --",          # destructive SQLi
    "' AND LIKE '%',--",                            # time-based via LIKE (SQLite)
    
    # === Path Traversal - Deep Links (MASTG-0025) ===
    "../../../data/data",                           # basic traversal
    "..\\..\\..\\data\\data",                       # backslash traversal
    "..%2F..%2F..%2Fdata%2Fdata",                   # URL-encoded traversal
    "file:///data/data/com.example.app/",          # direct file URI
    
    # === XSS/Code Injection (MASTG-0077) ===
    "<script>alert(1)</script>",                    # basic XSS
    "javascript:alert('xss')",                      # JavaScript URI
    "<img src=x onerror='alert(1)'>",              # image-based XSS
    
    # === Binary/Control Characters (CVE-2020-0001) ===
    "\x00\x01\x02\x03",                            # null + control chars
    "\xff\xff\xff\xff",                            # max byte values
    "\xde\xad\xbe\xef",                            # magic number injection
    
    # === URI Injection/Spoofing (CVE-2015-3836) ===
    "intent://example.com/#Intent;scheme=http;end", # Intent scheme parsing
    "//authority.com@attacker.com/path",           # authority bypass
    "http://example.com%3a%40attacker.com/",      # encoded authority bypass
    "http://example.com#attacker.com",             # fragment confusion
    
    # === Cross-Provider Access (OWASP MASWE-0061) ===
    "content://com.android.contacts/contacts",     # contacts provider
    "content://com.android.media/external/audio/media",  # media provider
    "content://com.android.calendar/calendars",    # calendar provider
    "content://android.media.documents/document/primary:*",  # wildcard access
]

# Persist original seeds for mutation tracking
ORIGINAL_INTENT_STRING_PAYLOADS = list(INTENT_STRING_PAYLOADS)


# Simple mutation helpers — lightweight, fast, and non-intrusive.
def _mutate_string(seed: str) -> str:
    # A tiny set of inexpensive mutations suitable for intents
    if not seed:
        return seed + "A"
    mutations = [
        lambda s: s + s[:64],                # repeat prefix
        lambda s: s[::-1],                    # reverse
        lambda s: s.replace("/", "\\/"),# slash-escape
        lambda s: s + "\x00",              # append null byte
        lambda s: s[:-1] if len(s) > 1 else s,# truncate
        lambda s: s.replace(".", ".."),   # dot duplication
        lambda s: s + ("!" * 256),          # padding
    ]
    try:
        f = mutations[hash(seed) % len(mutations)]
        return f(seed)
    except Exception:
        return seed + "!"


def _build_mutated_intent_list(orig_list: List[str], max_mutations_per_seed: int = 3) -> List[str]:
    out: List[str] = []
    for seed in orig_list:
        out.append(seed)
        for i in range(max_mutations_per_seed):
            m = _mutate_string(f"{seed}:{i}")
            if m and m not in out:
                out.append(m)
    return out


def _persist_seeds_to_file(package_name: str, original_seeds: List[str], mutated_seeds: List[str], apk_path: str = "") -> str:
    """
    Persist seeds to a backend JSON file for internal reference/debugging.
    Returns the file path where seeds were stored.
    """
    try:
        import json
        import uuid
        import tempfile
        from datetime import datetime

        # Group by package to keep related runs together
        seeds_root = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'fuzzing_seeds')
        safe_pkg = (package_name or "unknown").replace('.', '_').replace('/', '_')
        seeds_dir = os.path.join(seeds_root, safe_pkg)
        os.makedirs(seeds_dir, exist_ok=True)

        # Use high-resolution timestamp plus pid and a short uuid to guarantee
        # uniqueness across concurrent runs and avoid accidental overwrites.
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        pid = os.getpid()
        uniq = uuid.uuid4().hex[:8]
        # If an APK path is provided, include a short hash to tie seeds to the exact binary
        apk_name = os.path.basename(apk_path) if apk_path else ""
        apk_hash = ""
        try:
            if apk_path and os.path.exists(apk_path):
                import hashlib
                h = hashlib.md5()
                with open(apk_path, 'rb') as af:
                    for chunk in iter(lambda: af.read(8192), b""):
                        h.update(chunk)
                apk_hash = h.hexdigest()[:12]
        except Exception:
            apk_hash = ""

        filename = f"{safe_pkg}_{timestamp}_pid{pid}_{uniq}" + (f"_{apk_hash}" if apk_hash else "") + ".json"
        filepath = os.path.join(seeds_dir, filename)

        data = {
            "package": package_name,
            "timestamp": timestamp,
            "apk_path": apk_path,
            "apk_name": apk_name,
            "apk_hash": apk_hash,
            "original_seeds": original_seeds,
            "original_count": len(original_seeds),
            "mutated_seeds": mutated_seeds,
            "mutated_count": len(mutated_seeds),
            "coverage": len(mutated_seeds) / max(1, len(original_seeds)),
        }

        # Atomic write: write to a temp file in the same directory then replace.
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False, dir=seeds_dir, prefix=safe_pkg + '_', suffix='.tmp') as tf:
            json.dump(data, tf, indent=2, default=str)
            tf.flush()
            try:
                os.fsync(tf.fileno())
            except Exception:
                # os.fsync may not be available on all platforms; ignore if it fails
                pass
            temp_name = tf.name

        try:
            os.replace(temp_name, filepath)
        except Exception:
            # Fallback: attempt an atomic move via rename
            try:
                os.rename(temp_name, filepath)
            except Exception as e:
                # If all else fails, cleanup temp and raise
                try:
                    os.remove(temp_name)
                except Exception:
                    pass
                raise e

        print(f"[FALCON-SCAN] Seeds persisted to {filepath}")
        return filepath
    except Exception as e:
        print(f"[FALCON-SCAN] Failed to persist seeds: {e}")
        return ""


# Broadcast actions to throw at exported receivers
# References: CVE-2017-13312, OWASP MASWE-0063, MASTG-TEST-0030
BROADCAST_ACTIONS = [
    "android.intent.action.BOOT_COMPLETED",          # System boot (sensitive)
    "android.intent.action.PACKAGE_ADDED",           # App installation (sensitive)
    "android.intent.action.PACKAGE_REMOVED",         # App removal (sensitive)
    "android.provider.Telephony.SMS_RECEIVED",       # SMS interception (sensitive)
    "android.bluetooth.device.action.FOUND",         # Bluetooth discovery
    "android.net.wifi.WIFI_STATE_CHANGED",          # WiFi state change
    "android.net.conn.CONNECTIVITY_CHANGE",          # Network change (sensitive)
    "android.intent.action.USER_PRESENT",            # Device unlock (sensitive)
    "android.net.wifi.WIFI_SCAN_AVAILABLE",          # WiFi scan complete
    "android.intent.action.SCREEN_ON",               # Screen wake
    "android.intent.action.SCREEN_OFF",              # Screen sleep
]

# SQL injection payloads for Content Provider selection args
# References: OWASP MASWE-0058, CVE-2015-3836, NIST SP 800-124 Rev. 1
PROVIDER_SQLI_PAYLOADS = [
    "' OR '1'='1",                                              # classic boolean-based SQLi
    "' OR 'x'='x",                                             # alternative boolean
    "1' UNION SELECT NULL,NULL,NULL,NULL,NULL--",              # UNION-based injection
    "1 UNION SELECT name,sql,NULL,NULL,NULL FROM sqlite_master--",  # schema enumeration
    "' OR 1=1--",                                              # numeric boolean
    "1; DROP TABLE android_metadata; --",                      # destructive SQLi
    "' AND 1=2 UNION SELECT NULL,NULL,NULL--",                 # blind UNION
    "' UNION SELECT SQLITE_MASTER.NAME,NULL,NULL,NULL,NULL FROM SQLITE_MASTER--",  # alternative schema query
]

_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Sensitive broadcast actions that should be protected with permissions (MASWE-0063)
_SENSITIVE_BROADCAST_ACTIONS = {
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.PACKAGE_REMOVED",
    "android.intent.action.USER_PRESENT",
    "android.intent.action.SCREEN_ON",
    "android.intent.action.SCREEN_OFF",
    "android.provider.Telephony.SMS_RECEIVED",
    "android.net.conn.CONNECTIVITY_CHANGE",
    "android.net.wifi.WIFI_SCAN_AVAILABLE",
}

FINDING_SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 1,
}

FINDING_SOURCE_WEIGHTS = {
    "static": 1.0,
    "dynamic": 0.95,
    "runtime": 0.90,
    "fuzzing": 0.70,
    "unknown": 0.85,
}


# ─── Deep Analysis Engine (internal) ─────────────────────────────────────────

class _FalconDeepProbe:
    """
    Internal deep-analysis engine.
    Probes Android components for exploitable attack surface.
    Requires the analysis agent to be running on the connected device/emulator.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 31415,
        timeout: int = 30,
        cancel_check: Optional[Callable[[], bool]] = None,
    ):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.cancel_check = cancel_check

    def _is_cancelled(self) -> bool:
        if not self.cancel_check:
            return False
        try:
            return bool(self.cancel_check())
        except Exception:
            return False

    def _exec(self, module: str, args: str = "") -> Dict:
        cmd = f"{module} {args}".strip()
        try:
            proc = subprocess.Popen(
                ["drozer", "console", "connect",
                 "--host", self.host, "--port", str(self.port),
                 "-c", cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.time() + self.timeout
            while proc.poll() is None:
                if self._is_cancelled():
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)
                    return {"ok": False, "out": "", "err": "cancelled"}
                if time.time() >= deadline:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)
                    return {"ok": False, "out": "", "err": "timeout"}
                time.sleep(0.1)
            stdout, stderr = proc.communicate(timeout=1)
            return {"ok": proc.returncode == 0, "out": stdout or "", "err": stderr or ""}
        except Exception as e:
            return {"ok": False, "out": "", "err": str(e)}

    def probe_activity(self, package: str, activity: str) -> List[Dict]:
        findings = []
        for payload in INTENT_STRING_PAYLOADS[:6]:
            if self._is_cancelled():
                return findings
            safe = payload.replace('"', '\\"')[:200]
            r = self._exec(
                "app.activity.start",
                f"--component {package} {activity} "
                f"--extra string fuzz_input \"{safe}\"",
            )
            combined = r["out"] + r["err"]
            if _crash(combined):
                findings.append(_finding(
                    ftype="Activity Crash via Malformed Intent Extra",
                    severity="high",
                    component=activity,
                    payload=payload[:80],
                    evidence=_crash_line(combined),
                    description=(
                        f"Activity '{activity}' crashed when receiving a malformed Intent extra. "
                        f"Any app on the device can send this Intent if the Activity is exported."
                    ),
                    remediation="Validate all Intent extras in onCreate(). Wrap extra reads in try/catch.",
                ))
        return findings

    def probe_service(self, package: str, service: str) -> List[Dict]:
        findings = []
        for payload in INTENT_STRING_PAYLOADS[:6]:
            if self._is_cancelled():
                return findings
            safe = payload.replace('"', '\\"')[:200]
            r = self._exec(
                "app.service.start",
                f"--component {package} {service} "
                f"--extra string fuzz \"{safe}\"",
            )
            combined = r["out"] + r["err"]
            if _crash(combined):
                findings.append(_finding(
                    ftype="Service Crash via Malformed Intent Extra",
                    severity="high",
                    component=service,
                    payload=payload[:80],
                    evidence=_crash_line(combined),
                    description=f"Service '{service}' crashed on malformed Intent.",
                    remediation="Add null-checks and validation in Service.onStartCommand().",
                ))
        return findings

    def probe_receiver(self, package: str, receiver: str) -> List[Dict]:
        findings = []
        for action in BROADCAST_ACTIONS[:4]:
            if self._is_cancelled():
                return findings
            r = self._exec(
                "app.broadcast.send",
                f"--component {package} {receiver} "
                f"--action {action} "
                f"--extra string data \"{'A' * 2048}\"",
            )
            combined = r["out"] + r["err"]
            if _crash(combined):
                findings.append(_finding(
                    ftype="Broadcast Receiver Crash",
                    severity="medium",
                    component=receiver,
                    payload=action,
                    evidence=_crash_line(combined),
                    description=f"Receiver '{receiver}' crashed on broadcast action '{action}'.",
                    remediation="Protect exported receivers with android:permission or validate incoming Intents.",
                ))
        return findings

    def probe_provider(self, package: str, authority: str) -> List[Dict]:
        findings = []
        uri = f"content://{authority}/"
        for payload in PROVIDER_SQLI_PAYLOADS:
            if self._is_cancelled():
                return findings
            safe = payload.replace('"', '\\"')
            r = self._exec("app.provider.query", f"{uri} --selection \"{safe}\"")
            combined = r["out"] + r["err"]
            if _sqli(combined):
                findings.append(_finding(
                    ftype="Content Provider SQL Injection",
                    severity="critical",
                    component=authority,
                    payload=payload,
                    evidence=_sqli_line(combined),
                    description=(
                        f"Content Provider '{authority}' is vulnerable to SQL injection "
                        f"via the selection parameter."
                    ),
                    remediation=(
                        "Use parameterised queries or SQLiteQueryBuilder with strict mode. "
                        "Never concatenate raw selection strings."
                    ),
                ))
                break
        return findings


# ─── Runtime Analysis Engine (internal) ──────────────────────────────────────

class _FalconRuntimeProbe:
    """
    Internal runtime-analysis engine.
    Interacts with installed app components via Android Debug Bridge.
    Requires a connected device or running emulator.
    """

    def __init__(
        self,
        device_serial: Optional[str] = None,
        timeout: int = 15,
        cancel_check: Optional[Callable[[], bool]] = None,
    ):
        self._serial  = device_serial
        self._timeout = timeout
        self.cancel_check = cancel_check

    def _is_cancelled(self) -> bool:
        if not self.cancel_check:
            return False
        try:
            return bool(self.cancel_check())
        except Exception:
            return False

    def _run(self, *args) -> subprocess.CompletedProcess:
        base = [ADB_PATH]
        if self._serial:
            base += ["-s", self._serial]
        try:
            proc = subprocess.Popen(
                base + list(args),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.time() + self._timeout
            while proc.poll() is None:
                if self._is_cancelled():
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)
                    return subprocess.CompletedProcess(args, 1, "", "cancelled")
                if time.time() >= deadline:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)
                    return subprocess.CompletedProcess(args, 1, "", "timeout")
                time.sleep(0.1)
            stdout, stderr = proc.communicate(timeout=1)
            return subprocess.CompletedProcess(args, proc.returncode or 0, stdout or "", stderr or "")
        except Exception as e:
            return subprocess.CompletedProcess(args, 1, "", str(e))
        except Exception as e:
            return subprocess.CompletedProcess(args, 1, "", str(e))

    def _device_available(self) -> bool:
        r = self._run("devices")
        return any("\tdevice" in ln for ln in r.stdout.splitlines()[1:])

    def probe_activity(self, package: str, activity: str) -> List[Dict]:
        findings = []
        if not self._device_available():
            return findings
        comp = f"{package}/{activity}" if "/" not in activity else activity
        for payload in INTENT_STRING_PAYLOADS[:7]:
            if self._is_cancelled():
                return findings
            safe = payload.replace('"', '\\"').replace("'", "\\'")[:200]
            r = self._run("shell", "am", "start", "-n", comp,
                          "--es", "input", safe, "--ez", "debug", "true")
            combined = r.stdout + r.stderr
            if _crash(combined):
                findings.append(_finding(
                    ftype="Activity Crash via Malformed Intent Extra",
                    severity="high",
                    component=activity,
                    payload=payload[:80],
                    evidence=_crash_line(combined),
                    description=(
                        f"Activity '{activity}' crashed when launched with a malformed Intent extra. "
                        f"Other apps on the device can send this Intent."
                    ),
                    remediation="Validate all Intent extras in onCreate(). Wrap extra reads in try/catch.",
                ))
        return findings

    def probe_service(self, package: str, service: str) -> List[Dict]:
        findings = []
        if not self._device_available():
            return findings
        comp = f"{package}/{service}" if "/" not in service else service
        for payload in INTENT_STRING_PAYLOADS[:7]:
            if self._is_cancelled():
                return findings
            safe = payload.replace('"', '\\"').replace("'", "\\'")[:200]
            r = self._run("shell", "am", "startservice", "-n", comp,
                          "--es", "cmd", safe)
            combined = r.stdout + r.stderr
            if _crash(combined):
                findings.append(_finding(
                    ftype="Service Crash via Malformed Intent Extra",
                    severity="high",
                    component=service,
                    payload=payload[:80],
                    evidence=_crash_line(combined),
                    description=f"Service '{service}' crashed on malformed Intent extra.",
                    remediation="Validate Intent extras in onStartCommand() / onBind().",
                ))
        return findings

    def probe_receiver(self, package: str, receiver: str) -> List[Dict]:
        findings = []
        if not self._device_available():
            return findings
        for action in BROADCAST_ACTIONS[:4]:
            if self._is_cancelled():
                return findings
            r = self._run("shell", "am", "broadcast",
                          "-n", f"{package}/{receiver}",
                          "-a", action,
                          "--es", "data", "A" * 4096)
            combined = r.stdout + r.stderr
            if _crash(combined):
                findings.append(_finding(
                    ftype="Broadcast Receiver Crash",
                    severity="medium",
                    component=receiver,
                    payload=action,
                    evidence=_crash_line(combined),
                    description=f"Receiver '{receiver}' crashed on broadcast action '{action}'.",
                    remediation="Add android:permission to the receiver or validate incoming Intents.",
                ))
        return findings

    def probe_provider(self, package: str, authority: str) -> List[Dict]:
        findings = []
        if not self._device_available():
            return findings
        uri = f"content://{authority}/"
        for payload in PROVIDER_SQLI_PAYLOADS:
            if self._is_cancelled():
                return findings
            safe = payload.replace('"', '\\"')
            r = self._run("shell", "content", "query", "--uri", uri, "--where", safe)
            combined = r.stdout + r.stderr
            if _sqli(combined):
                findings.append(_finding(
                    ftype="Content Provider SQL Injection",
                    severity="critical",
                    component=authority,
                    payload=payload,
                    evidence=_sqli_line(combined),
                    description=(
                        f"Content Provider '{authority}' is vulnerable to SQL injection "
                        f"via the selection parameter."
                    ),
                    remediation=(
                        "Use parameterised queries. "
                        "Never build raw WHERE clauses from untrusted input."
                    ),
                ))
                break
        return findings


# ─── DEX / APK Code-Level Dynamic Analyzer (Androguard-powered) ─────────────

class _FalconCodeProbe:
    """
    Performs DEX bytecode analysis using Androguard's call-graph engine.
    Runs without a connected device — inspects actual method calls in the
    APK's compiled bytecode to surface dangerous data-flow patterns.

    Checks per exported component:
      • Intent/Broadcast extra  → SQL sink     (SQL injection)
      • Intent/Broadcast extra  → File sink    (path traversal)
      • WebView setJavaScriptEnabled / addJavascriptInterface exposure
      • java.util.Random (non-cryptographic) usage
      • Weak algorithm string constants (MD5, SHA-1, DES, AES/ECB)
      • Hardcoded credential/secret string constants
    """

    # ── Dangerous sink descriptors (Dalvik class → set of method names) ────

    _SQL_SINKS: Dict[str, set] = {
        "Landroid/database/sqlite/SQLiteDatabase;": {
            "rawQuery", "execSQL", "compileStatement", "rawQueryWithFactory",
        },
        "Landroid/database/DatabaseUtils;": {"queryNumEntries"},
    }
    _FILE_SINKS: Dict[str, set] = {
        "Ljava/io/File;":              {"<init>"},
        "Ljava/io/FileInputStream;":   {"<init>"},
        "Ljava/io/FileOutputStream;":  {"<init>"},
        "Landroid/content/Context;":   {
            "openFileInput", "openFileOutput", "getFileStreamPath",
        },
    }
    _INTENT_SRCS: Dict[str, set] = {
        "Landroid/content/Intent;": {
            "getStringExtra", "getIntExtra", "getBundleExtra",
            "getSerializableExtra", "getParcelableExtra",
            "getExtras", "getData", "getDataString",
        },
        "Landroid/os/Bundle;": {"getString", "getInt", "getSerializable"},
    }
    _WEBVIEW_SINKS: Dict[str, set] = {
        "Landroid/webkit/WebSettings;": {"setJavaScriptEnabled"},
        "Landroid/webkit/WebView;":     {"addJavascriptInterface", "loadUrl"},
    }
    _WEAK_RAND: Dict[str, set] = {
        "Ljava/util/Random;": {"<init>", "nextInt", "nextLong", "nextBytes"},
    }

    # Weak algorithm constant strings and credential keyword patterns
    _WEAK_ALGO_RE  = re.compile(r'^(MD5|SHA-?1|SHA1|DES|DESede|AES/ECB|RC4|RC2)$', re.I)
    _CRED_KEY_RE   = re.compile(
        r'(?i)(password|passwd|secret|api[_\-]?key|token|private[_\-]?key|access[_\-]?key)',
    )

    def __init__(self, apk_path: str, cancel_check: Optional[Callable[[], bool]] = None):
        self.apk_path  = apk_path
        self._dx       = None   # androguard Analysis object
        self._loaded   = False
        self.cancel_check = cancel_check

    def _is_cancelled(self) -> bool:
        if not self.cancel_check:
            return False
        try:
            return bool(self.cancel_check())
        except Exception:
            return False

    # ── Androguard loader (lazy, cached) ────────────────────────────────────

    def _load(self) -> bool:
        if self._loaded:
            return self._dx is not None
        self._loaded = True
        try:
            from androguard.misc import AnalyzeAPK
            _, _, self._dx = AnalyzeAPK(self.apk_path)
            print(f"[FALCON-CODE] APK loaded for code analysis")
            return True
        except Exception as e:
            print(f"[FALCON-CODE] AnalyzeAPK failed: {e}")
            return False

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _dvm(component: str) -> str:
        """Convert com.example.Foo  →  Lcom/example/Foo;"""
        return "L" + component.replace(".", "/") + ";"

    def _class_callees(self, component: str) -> set:
        """
        Return the set of (class_name, method_name) pairs called by any
        method directly defined in the component class.
        """
        if not self._dx:
            return set()
        ca = self._dx.get_class_analysis(self._dvm(component))
        if ca is None:
            return set()
        callees: set = set()
        for ma in ca.get_methods():
            try:
                for callee_cls, callee_ma, _ in ma.get_xref_to():
                    callees.add((callee_cls.name, callee_ma.name))
            except Exception:
                pass
        return callees

    def _reads_intent(self, callees: set) -> Optional[str]:
        """Return a human-readable source label if the class reads Intent extras."""
        for cls, methods in self._INTENT_SRCS.items():
            for m in methods:
                if (cls, m) in callees:
                    short = cls.split("/")[-1].rstrip(";")
                    return f"{short}.{m}()"
        return None

    def _calls_sql_sink(self, callees: set) -> Optional[str]:
        for cls, methods in self._SQL_SINKS.items():
            for m in methods:
                if (cls, m) in callees:
                    return f"{cls.split('/')[-1].rstrip(';')}.{m}()"
        return None

    def _calls_file_sink(self, callees: set) -> Optional[str]:
        for cls, methods in self._FILE_SINKS.items():
            for m in methods:
                if (cls, m) in callees:
                    return f"{cls.split('/')[-1].rstrip(';')}.{m}()"
        return None

    def _calls_webview(self, callees: set) -> Optional[str]:
        for cls, methods in self._WEBVIEW_SINKS.items():
            for m in methods:
                if (cls, m) in callees:
                    return f"{cls.split('/')[-1].rstrip(';')}.{m}()"
        return None

    def _calls_weak_rand(self, callees: set) -> bool:
        for cls, methods in self._WEAK_RAND.items():
            for m in methods:
                if (cls, m) in callees:
                    return True
        return False

    def _dex_strings_for(self, component: str) -> List[str]:
        """
        Collect string constants referenced from the component's class methods
        via const-string / const-string/jumbo instructions.
        Falls back to an empty list on any error.
        """
        if self._is_cancelled():
            return []
        if not self._dx:
            return []
        ca = self._dx.get_class_analysis(self._dvm(component))
        if ca is None:
            return []
        strings: List[str] = []
        for ma in ca.get_methods():
            if self._is_cancelled():
                return strings
            try:
                for inst in ma.get_method().get_instructions():
                    if self._is_cancelled():
                        return strings
                    # const-string = 0x1a, const-string/jumbo = 0x1b
                    if hasattr(inst, 'get_op_value') and inst.get_op_value() in (0x1a, 0x1b):
                        try:
                            strings.append(str(inst.get_string()))
                        except Exception:
                            pass
            except Exception:
                pass
        return strings

    def _weak_algo_in_strings(self, component: str) -> Optional[str]:
        for s in self._dex_strings_for(component):
            if self._WEAK_ALGO_RE.match(s.strip()):
                return s.strip()
        return None

    def _hardcoded_cred_in_strings(self, component: str) -> Optional[str]:
        for s in self._dex_strings_for(component):
            if len(s) >= 6 and self._CRED_KEY_RE.search(s):
                return s[:80]
        return None

    # ── Common probe logic for any component type ────────────────────────────

    def _probe(self, component: str, comp_type: str) -> List[Dict]:
        findings: List[Dict] = []
        if self._is_cancelled():
            return findings
        if not self._load():
            return findings

        callees = self._class_callees(component)
        if not callees:
            # Class not present in DEX (could be a framework class or missing)
            return findings

        intent_src  = self._reads_intent(callees)
        if self._is_cancelled():
            return findings
        sql_sink    = self._calls_sql_sink(callees)
        if self._is_cancelled():
            return findings
        file_sink   = self._calls_file_sink(callees)
        if self._is_cancelled():
            return findings
        webview_hit = self._calls_webview(callees)
        if self._is_cancelled():
            return findings
        weak_rand   = self._calls_weak_rand(callees)

        # ── Intent extra → SQL injection ────────────────────────────────────
        if intent_src and sql_sink:
            findings.append(_finding(
                ftype=f"Intent Extra → SQL Injection in {comp_type}",
                severity="critical",
                component=component,
                payload=f"DEX call-graph: {intent_src} → {sql_sink}",
                evidence=(
                    f"Androguard xref: {intent_src} and {sql_sink} both reachable "
                    f"from {component.split('.')[-1]} methods"
                ),
                description=(
                    f"{comp_type} '{component}' reads an Intent extra and calls a raw SQL "
                    f"API ({sql_sink}) in the same class. An attacker can craft an Intent "
                    f"with a SQL injection payload to read or corrupt the local database."
                ),
                remediation=(
                    "Pass user-controlled values as selectionArgs[] (parameterised), "
                    "never concatenate them into the SQL string."
                ),
            ))

        # ── Intent extra → path traversal ───────────────────────────────────
        if intent_src and file_sink:
            findings.append(_finding(
                ftype=f"Intent Extra → Path Traversal in {comp_type}",
                severity="high",
                component=component,
                payload=f"DEX call-graph: {intent_src} → {file_sink}",
                evidence=(
                    f"Androguard xref: {intent_src} and {file_sink} both reachable "
                    f"from {component.split('.')[-1]} methods"
                ),
                description=(
                    f"{comp_type} '{component}' reads an Intent extra and opens a file "
                    f"({file_sink}) in the same class. A path-traversal payload such as "
                    f"'../../data/data/...' can read or overwrite arbitrary sandbox files."
                ),
                remediation=(
                    "Canonicalise the path with File.getCanonicalPath() and verify it "
                    "starts with the expected prefix before opening."
                ),
            ))

        # ── WebView JS exposure ─────────────────────────────────────────────
        if webview_hit:
            findings.append(_finding(
                ftype=f"WebView JavaScript Exposure in {comp_type}",
                severity="high",
                component=component,
                payload=f"DEX call-graph: {webview_hit}",
                evidence=(
                    f"Androguard xref: {webview_hit} called from "
                    f"{component.split('.')[-1]}"
                ),
                description=(
                    f"{comp_type} '{component}' calls {webview_hit}. "
                    f"If the WebView loads attacker-controlled URLs, arbitrary JavaScript "
                    f"can execute or native methods can be invoked via the JS bridge."
                ),
                remediation=(
                    "Disable JavaScript where not needed. Restrict URLs to trusted origins. "
                    "Annotate JS interface methods with @JavascriptInterface and expose the minimum."
                ),
            ))

        # ── Non-cryptographic RNG ───────────────────────────────────────────
        if weak_rand:
            findings.append(_finding(
                ftype=f"Non-Cryptographic Random in {comp_type}",
                severity="medium",
                component=component,
                payload="DEX call-graph: java.util.Random.<init>() / nextInt() detected",
                evidence=(
                    f"Androguard xref: java.util.Random called from "
                    f"{component.split('.')[-1]}"
                ),
                description=(
                    f"{comp_type} '{component}' uses java.util.Random, which is not "
                    f"cryptographically secure. Token/nonce generation with java.util.Random "
                    f"is predictable and exploitable."
                ),
                remediation="Replace with java.security.SecureRandom for any security-sensitive randomness.",
            ))

        # ── Weak algorithm string constants ─────────────────────────────────
        weak_algo = self._weak_algo_in_strings(component)
        if weak_algo:
            findings.append(_finding(
                ftype=f"Weak Cryptographic Algorithm in {comp_type}",
                severity="medium",
                component=component,
                payload=f'DEX const-string: "{weak_algo}"',
                evidence=(
                    f"Androguard const-string scan: algorithm literal '{weak_algo}' "
                    f"referenced in {component.split('.')[-1]}"
                ),
                description=(
                    f"{comp_type} '{component}' references the weak algorithm '{weak_algo}'. "
                    f"MD5/SHA-1 are collision-prone; DES/AES-ECB lack semantic security."
                ),
                remediation="Use AES-256-GCM, SHA-256 or SHA-3, and never AES in ECB mode.",
            ))

        # ── Hardcoded credentials ────────────────────────────────────────────
        cred = self._hardcoded_cred_in_strings(component)
        if cred:
            findings.append(_finding(
                ftype=f"Hardcoded Credential / Secret in {comp_type}",
                severity="high",
                component=component,
                payload=f'DEX const-string: "{cred}"',
                evidence=(
                    f"Androguard const-string scan: credential-like literal "
                    f"'{cred[:40]}' found in {component.split('.')[-1]}"
                ),
                description=(
                    f"{comp_type} '{component}' contains a hardcoded credential, API key, "
                    f"or secret token in its string constant pool. These are trivially "
                    f"extractable from the APK by any user with dex2jar/jadx."
                ),
                remediation=(
                    "Store secrets in the Android Keystore system or retrieve them "
                    "from a secure server at runtime — never embed them in code."
                ),
            ))

        return findings

    # ── Public per-component entry points ────────────────────────────────────

    def probe_activity(self, package: str, activity: str) -> List[Dict]:
        return self._probe(activity, "Activity")

    def probe_service(self, package: str, service: str) -> List[Dict]:
        return self._probe(service, "Service")

    def probe_receiver(self, package: str, receiver: str) -> List[Dict]:
        return self._probe(receiver, "Broadcast Receiver")

    def probe_provider(self, package: str, authority: str, provider_name: str = "") -> List[Dict]:
        target = provider_name if provider_name else authority
        return self._probe(target, "Content Provider")


# ─── Static Component Analyzer (no device needed) ────────────────────────────

class StaticComponentFuzzer:
    """
    Analyses AndroidManifest component data for misconfiguration.
    Detects exported components, missing permissions, Intent injection risks.
    Always runs — works without a device.
    """

    def fuzz(self, components: Dict, package: str) -> List[Dict]:
        findings = []
        activities = components.get("activities", [])
        services   = components.get("services", [])
        receivers  = components.get("receivers", [])
        providers  = components.get("providers", [])

        # Activities ──────────────────────────────────────────────────────────
        for a in activities:
            name     = a if isinstance(a, str) else a.get("name", "")
            exported = True if isinstance(a, str) else a.get("exported", False)
            perm     = False if isinstance(a, str) else bool(a.get("permission"))
            intent_actions = [] if isinstance(a, str) else (a.get("intent_actions") or [])
            intent_categories = [] if isinstance(a, str) else (a.get("intent_categories") or [])
            if not name:
                continue

            if exported:
                # Sensitive deep-link / OAuth pattern
                if any(kw in name.lower() for kw in
                       ["deeplink", "share", "oauth", "callback", "web", "browser", "redirect"]):
                    findings.append(_finding(
                        ftype="Exported Deep-Link / OAuth Activity",
                        severity="high",
                        component=name,
                        payload="N/A – static analysis",
                        evidence='android:exported="true" on sensitive Activity',
                        description=(
                            f"Activity '{name}' handles deep-links or OAuth callbacks and is exported "
                            f"without a permission guard. An attacker can redirect sensitive flows to it."
                        ),
                        remediation='Set android:exported="false" or add android:permission to the <activity> tag.',
                    ))
                # Any exported activity without an explicit permission is attack surface
                if not perm:
                    findings.append(_finding(
                        ftype="Exported Activity Without Permission Guard",
                        severity="medium",
                        component=name,
                        payload="N/A – static analysis",
                        evidence='android:exported="true", no android:permission attribute',
                        description=(
                            f"Activity '{name}' is exported and reachable by any app on the device "
                            f"without a permission check. Any third-party app can start or interact "
                            f"with it, potentially bypassing authentication or leaking data."
                        ),
                        remediation=(
                            'Add android:permission to the <activity> tag, or set android:exported="false" '
                            "if the Activity is not intended to be launched by other apps."
                        ),
                    ))
                if (
                    not perm
                    and "android.intent.action.VIEW" in intent_actions
                    and "android.intent.category.BROWSABLE" in intent_categories
                ):
                    findings.append(_finding(
                        ftype="Exported Browsable Activity Deep-Link Abuse Risk",
                        severity="high",
                        component=name,
                        payload="N/A – static analysis",
                        evidence=(
                            'android:exported="true" with VIEW + BROWSABLE intent-filter '
                            "and no permission guard"
                        ),
                        description=(
                            f"Activity '{name}' is exported and browsable via deep links without a permission "
                            f"guard. Malicious apps or crafted URLs can drive users into sensitive flows."
                        ),
                        remediation=(
                            "Require strict URI allow-list validation and authentication checks before "
                            "processing deep-link data."
                        ),
                    ))

        # Services ────────────────────────────────────────────────────────────
        for s in services:
            name     = s if isinstance(s, str) else s.get("name", "")
            exported = True if isinstance(s, str) else s.get("exported", False)
            perm     = False if isinstance(s, str) else bool(s.get("permission"))
            if not name:
                continue
            if exported and not perm:
                findings.append(_finding(
                    ftype="Exported Service Without Permission",
                    severity="medium",
                    component=name,
                    payload="N/A – static analysis",
                    evidence="android:exported=\"true\", no android:permission",
                    description=(
                        f"Service '{name}' is exported with no permission restriction. "
                        f"Any installed app can start or bind to it."
                    ),
                    remediation="Add android:permission to the <service> tag in AndroidManifest.xml.",
                ))

        # Broadcast Receivers ─────────────────────────────────────────────────
        for r in receivers:
            name     = r if isinstance(r, str) else r.get("name", "")
            exported = True if isinstance(r, str) else r.get("exported", False)
            perm     = False if isinstance(r, str) else bool(r.get("permission"))
            intent_actions = [] if isinstance(r, str) else (r.get("intent_actions") or [])
            if not name:
                continue
            if exported and not perm:
                findings.append(_finding(
                    ftype="Exported Broadcast Receiver Without Permission",
                    severity="medium",
                    component=name,
                    payload="N/A – static analysis",
                    evidence="android:exported=\"true\", no android:permission",
                    description=(
                        f"Broadcast Receiver '{name}' is exported. Any app can send arbitrary "
                        f"broadcasts to it, potentially triggering unintended behaviour."
                    ),
                    remediation=(
                        "Protect with android:permission, or use LocalBroadcastManager "
                        "for in-process broadcasts."
                    ),
                ))
            if exported and not perm and any(action in _SENSITIVE_BROADCAST_ACTIONS for action in intent_actions):
                action_preview = ", ".join(intent_actions[:3]) if intent_actions else "sensitive system action"
                findings.append(_finding(
                    ftype="Exported Receiver Handles Sensitive Broadcasts",
                    severity="high",
                    component=name,
                    payload="N/A – static analysis",
                    evidence=(
                        'android:exported="true" receiver with sensitive intent actions '
                        f"({action_preview}) and no permission guard"
                    ),
                    description=(
                        f"Receiver '{name}' listens for sensitive broadcast actions while exported without "
                        "a permission gate. A malicious app can spoof events and trigger privileged code paths."
                    ),
                    remediation=(
                        "Set android:permission on the receiver and validate both sender identity and action "
                        "content before executing logic."
                    ),
                ))

        # Content Providers ───────────────────────────────────────────────────
        for p in providers:
            name      = p if isinstance(p, str) else p.get("name", "")
            authority = p if isinstance(p, str) else p.get("authority", name)
            exported  = True if isinstance(p, str) else p.get("exported", False)
            r_perm    = False if isinstance(p, str) else bool(p.get("readPermission"))
            w_perm    = False if isinstance(p, str) else bool(p.get("writePermission"))
            grant_uri = False if isinstance(p, str) else bool(p.get("grantUriPermissions"))
            if not name:
                continue
            if exported and not r_perm:
                findings.append(_finding(
                    ftype="Content Provider Readable Without Permission",
                    severity="high",
                    component=name,
                    payload="N/A – static analysis",
                    evidence="android:exported=\"true\", no android:readPermission",
                    description=(
                        f"Content Provider '{name}' (authority: {authority}) is exported without a "
                        f"readPermission. Any app can query it and access potentially sensitive data."
                    ),
                    remediation="Set android:readPermission or android:permission on the <provider> tag.",
                ))
            if exported and not w_perm:
                findings.append(_finding(
                    ftype="Content Provider Writable Without Permission",
                    severity="high",
                    component=name,
                    payload="N/A – static analysis",
                    evidence="android:exported=\"true\", no android:writePermission",
                    description=(
                        f"Content Provider '{name}' is exported without a writePermission. "
                        f"Any app can insert or modify its data."
                    ),
                    remediation="Set android:writePermission or android:permission on the <provider> tag.",
                ))
            if exported and grant_uri and not (r_perm or w_perm):
                findings.append(_finding(
                    ftype="Content Provider URI Grant Abuse Risk",
                    severity="critical",
                    component=name,
                    payload="N/A – static analysis",
                    evidence=(
                        'android:exported="true", android:grantUriPermissions="true", '
                        "no read/write permissions"
                    ),
                    description=(
                        f"Content Provider '{name}' allows URI grants while exported and ungated. "
                        "Temporary URI permission grants can be abused to escalate data access."
                    ),
                    remediation=(
                        "Define strict read/write permissions, minimize URI grant scope, and enforce caller "
                        "permission checks inside provider methods."
                    ),
                ))

        return findings


# ─── Main APKFuzzer ───────────────────────────────────────────────────────────

class APKFuzzer:
    """
    FalconScan Android Component Security Analyzer.

    Selects the best available engine automatically:
      falcon-deep    → deep-analysis engine with full component interaction
      falcon-runtime → runtime engine via Android Debug Bridge
      falcon-static  → static manifest analysis (no device required; always runs)

    Pass components extracted by extract_components_for_fuzzing().
    """

    def __init__(
        self,
        apk_path: str = "",
        package_name: str = "",
        components: Optional[Dict] = None,
        device_serial: Optional[str] = None,
        timeout: int = 30,
        max_workers: int = 4,
        enabled: bool = True,
        cancel_check: Optional[Callable[[], bool]] = None,
        max_duration: Optional[int] = None,
        # Mutation options (non-intrusive): default disabled to keep existing behavior
        mutation_enabled: bool = False,
        mutation_max_per_seed: int = 2,
    ):
        self.apk_path     = apk_path
        self.package_name = package_name
        self.components   = components or {}
        self.device_serial = device_serial
        self.timeout      = timeout
        self.max_workers  = max_workers
        self.enabled      = enabled
        # Optional callable returning True when the caller requests cancellation
        self.cancel_check = cancel_check
        # Optional total timeout (seconds) for the entire fuzz run.
        # Kept for compatibility, but the run no longer auto-stops on duration.
        self.max_duration = max_duration

        # Mutation configuration — when enabled we build a small mutated payload
        # corpus from the original intent payloads. This replaces the in-module
        # `INTENT_STRING_PAYLOADS` list so existing probe code continues to use
        # the mutated corpus without branching logic elsewhere.
        self.mutation_enabled = bool(mutation_enabled)
        self.mutation_max_per_seed = int(mutation_max_per_seed)
        self.mutation_seed_file = ""
        
        if self.mutation_enabled:
            try:
                # Override the module-level payload list used by probes
                mutated_list = _build_mutated_intent_list(
                    ORIGINAL_INTENT_STRING_PAYLOADS,
                    max_mutations_per_seed=self.mutation_max_per_seed,
                )
                globals()['INTENT_STRING_PAYLOADS'] = mutated_list
                # Persist seeds to backend file for internal reference only
                self.mutation_seed_file = _persist_seeds_to_file(
                    self.package_name,
                    ORIGINAL_INTENT_STRING_PAYLOADS,
                    mutated_list,
                    apk_path=self.apk_path,
                )
                print(f"[FALCON-SCAN] Mutation enabled: {len(ORIGINAL_INTENT_STRING_PAYLOADS)} seeds → {len(mutated_list)} variants")
            except Exception as e:
                print(f"[FALCON-SCAN] Failed to build mutated payloads: {e}")

        self._deep_up = _DROZER_UP and ADB_AVAILABLE
        self._adb_up  = ADB_AVAILABLE
        self._engine  = "falcon-deep" if self._deep_up else ("falcon-runtime" if self._adb_up else "falcon-static")

    def fuzz(self) -> Dict:
        if not self.enabled:
            return {"enabled": False, "message": "Fuzzing disabled"}

        results: Dict = {
            "enabled":            True,
            "engine":             self._engine,
            "deep_engine_active": self._deep_up,
            "runtime_available":  self._adb_up,
            "package":            self.package_name,
            "start_time":         time.strftime("%Y-%m-%d %H:%M:%S"),
            "components_fuzzed":  0,
            "vulnerabilities":    [],
            "errors":             [],
        }

        total_components = sum(len(v) for v in self.components.values())
        print(f"[FALCON-SCAN] Component scan engine={self._engine} | "
              f"pkg={self.package_name} | components={total_components}")

        all_findings: List[Dict] = []

        # Step 1 – Static manifest analysis (always runs)
        static_f = StaticComponentFuzzer()
        for f in static_f.fuzz(self.components, self.package_name):
            # Check for cancellation between yielded results
            if self.cancel_check and self.cancel_check():
                results.update({
                    "cancelled": True,
                    "vulnerabilities": all_findings,
                    "components_fuzzed": len(all_findings),
                })
                print(f"[FALCON-SCAN] Fuzz cancelled during static stage for {self.package_name}")
                return results
            f["source"] = "static"
            all_findings.append(f)

        # Step 2 – DEX code-level dynamic analysis (always runs, no device needed)
        # Check cancellation before launching code engine
        if self.cancel_check and self.cancel_check():
            results.update({
                "cancelled": True,
                "vulnerabilities": all_findings,
                "components_fuzzed": len(all_findings),
            })
            print(f"[FALCON-SCAN] Fuzz cancelled before code engine for {self.package_name}")
            return results

        code_findings = self._run_code_engine()
        all_findings.extend(code_findings)
        print(f"[FALCON-SCAN] Code engine: {len(code_findings)} findings")

        # Step 3 – Live device probing (deep > runtime > skip)
        if self._deep_up:
            all_findings.extend(self._run_deep_engine())
        elif self._adb_up:
            all_findings.extend(self._run_runtime_engine())
        else:
            print("[FALCON-SCAN] No connected device — skipping live probing")

        all_findings = _deduplicate_findings(all_findings)
        severity_breakdown = _severity_breakdown(all_findings)
        source_breakdown = _source_breakdown(all_findings)
        attack_type_breakdown = _attack_type_breakdown(all_findings)
        top_risky_components = _top_risky_components(all_findings)

        results["components_fuzzed"]     = total_components
        results["vulnerabilities"]       = all_findings
        results["vulnerabilities_found"] = len(all_findings)
        results["severity_breakdown"]    = severity_breakdown
        results["source_breakdown"]      = source_breakdown
        results["attack_type_breakdown"] = attack_type_breakdown
        results["top_risky_components"]  = top_risky_components
        results["recommendations"]       = _recommendations_from_findings(
            attack_type_breakdown,
            top_risky_components,
        )
        results["end_time"]              = time.strftime("%Y-%m-%d %H:%M:%S")

        print(f"[FALCON-SCAN] Scan complete: {total_components} components, "
              f"{len(all_findings)} findings")
        return results

    # ── Deep engine sweep ─────────────────────────────────────────────────────
    def _run_deep_engine(self) -> List[Dict]:
        probe    = _FalconDeepProbe(timeout=self.timeout, cancel_check=self.cancel_check)
        findings = []
        pkg      = self.package_name

        jobs = []
        pool = ThreadPoolExecutor(max_workers=self.max_workers)
        try:
            for a in self.components.get("activities", []):
                n = a if isinstance(a, str) else a.get("name", "")
                if n: jobs.append(pool.submit(probe.probe_activity, pkg, n))
            for s in self.components.get("services", []):
                n = s if isinstance(s, str) else s.get("name", "")
                if n: jobs.append(pool.submit(probe.probe_service, pkg, n))
            for r in self.components.get("receivers", []):
                n = r if isinstance(r, str) else r.get("name", "")
                if n: jobs.append(pool.submit(probe.probe_receiver, pkg, n))
            for p in self.components.get("providers", []):
                auth = p if isinstance(p, str) else p.get("authority", "")
                if auth: jobs.append(pool.submit(probe.probe_provider, pkg, auth))

            pending = set(jobs)
            while pending:
                if self.cancel_check and self.cancel_check():
                    print(f"[FALCON-SCAN] Deep engine cancelled for {self.package_name}")
                    pool.shutdown(wait=False, cancel_futures=True)
                    return findings

                done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                for f in done:
                    if self.cancel_check and self.cancel_check():
                        print(f"[FALCON-SCAN] Deep engine cancelled for {self.package_name}")
                        pool.shutdown(wait=False, cancel_futures=True)
                        return findings
                    try:
                        for finding in f.result():
                            finding["source"] = "runtime"
                            findings.append(finding)
                    except Exception as e:
                        print(f"[FALCON-SCAN] Deep engine task error: {e}")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        return findings

    # ── Runtime engine sweep ──────────────────────────────────────────────────
    def _run_runtime_engine(self) -> List[Dict]:
        probe    = _FalconRuntimeProbe(device_serial=self.device_serial, timeout=self.timeout, cancel_check=self.cancel_check)
        findings = []
        pkg      = self.package_name

        jobs = []
        pool = ThreadPoolExecutor(max_workers=self.max_workers)
        try:
            for a in self.components.get("activities", []):
                n = a if isinstance(a, str) else a.get("name", "")
                if n: jobs.append(pool.submit(probe.probe_activity, pkg, n))
            for s in self.components.get("services", []):
                n = s if isinstance(s, str) else s.get("name", "")
                if n: jobs.append(pool.submit(probe.probe_service, pkg, n))
            for r in self.components.get("receivers", []):
                n = r if isinstance(r, str) else r.get("name", "")
                if n: jobs.append(pool.submit(probe.probe_receiver, pkg, n))
            for p in self.components.get("providers", []):
                auth = p if isinstance(p, str) else p.get("authority", "")
                if auth: jobs.append(pool.submit(probe.probe_provider, pkg, auth))

            pending = set(jobs)
            while pending:
                if self.cancel_check and self.cancel_check():
                    print(f"[FALCON-SCAN] Runtime engine cancelled for {self.package_name}")
                    pool.shutdown(wait=False, cancel_futures=True)
                    return findings

                done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                for f in done:
                    if self.cancel_check and self.cancel_check():
                        print(f"[FALCON-SCAN] Runtime engine cancelled for {self.package_name}")
                        pool.shutdown(wait=False, cancel_futures=True)
                        return findings
                    try:
                        for finding in f.result():
                            finding["source"] = "runtime"
                            findings.append(finding)
                    except Exception as e:
                        print(f"[FALCON-SCAN] Runtime engine task error: {e}")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        return findings

    # ── DEX code-analysis sweep (always runs) ─────────────────────────────────
    def _run_code_engine(self) -> List[Dict]:
        if not self.apk_path or not os.path.exists(self.apk_path):
            return []
        probe    = _FalconCodeProbe(self.apk_path, cancel_check=self.cancel_check)
        findings = []
        pkg      = self.package_name

        jobs = []
        pool = ThreadPoolExecutor(max_workers=self.max_workers)
        try:
            for a in self.components.get("activities", []):
                n = a if isinstance(a, str) else a.get("name", "")
                if n: jobs.append(pool.submit(probe.probe_activity, pkg, n))
            for s in self.components.get("services", []):
                n = s if isinstance(s, str) else s.get("name", "")
                if n: jobs.append(pool.submit(probe.probe_service, pkg, n))
            for r in self.components.get("receivers", []):
                n = r if isinstance(r, str) else r.get("name", "")
                if n: jobs.append(pool.submit(probe.probe_receiver, pkg, n))
            for p in self.components.get("providers", []):
                name = p if isinstance(p, str) else p.get("name", "")
                auth = p if isinstance(p, str) else p.get("authority", name)
                if auth: jobs.append(pool.submit(probe.probe_provider, pkg, auth, name))

            pending = set(jobs)
            while pending:
                if self.cancel_check and self.cancel_check():
                    print(f"[FALCON-SCAN] Code engine cancelled for {self.package_name}")
                    pool.shutdown(wait=False, cancel_futures=True)
                    return findings

                done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                for f in done:
                    if self.cancel_check and self.cancel_check():
                        print(f"[FALCON-SCAN] Code engine cancelled for {self.package_name}")
                        pool.shutdown(wait=False, cancel_futures=True)
                        return findings
                    try:
                        for finding in f.result():
                            finding["source"] = "dynamic"
                            findings.append(finding)
                    except Exception as e:
                        print(f"[FALCON-SCAN] Code engine task error: {e}")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        return findings


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _finding(ftype, severity, component, payload, evidence, description, remediation) -> Dict:
    finding = {
        "type":        ftype,
        "title":       ftype,   # alias used by the frontend reports page
        "severity":    severity,
        "component":   component,
        "payload":     payload,
        "evidence":    evidence,
        "description": description,
        "remediation": remediation,
    }
    finding["detection_technique"] = _infer_detection_technique(finding)
    finding["attack_vector"] = _infer_attack_vector(finding)
    return finding


def _normalize_analysis_source(finding: Dict[str, Any]) -> str:
    origin = (finding.get("origin") or finding.get("analysis_origin") or "").strip().lower()
    if origin:
        return origin
    source = (finding.get("source") or "unknown").strip().lower()
    return source or "unknown"


def _infer_detection_technique(finding: Dict[str, Any]) -> str:
    source = _normalize_analysis_source(finding)
    title = (finding.get("type") or finding.get("title") or "").lower()
    payload = (finding.get("payload") or "").lower()
    text = f"{title} {payload}"

    if source == "static":
        return "AndroidManifest.xml attribute inspection and exported-component permission review"

    if source == "dynamic":
        if "sql" in text or "sqlite" in text:
            return "DEX call-graph tracing from Intent sources to SQLite sinks with Androguard"
        if "webview" in text or "javascript" in text:
            return "DEX call-graph tracing and WebView sink inspection with Androguard"
        if "path traversal" in text or "file" in text:
            return "DEX call-graph tracing from Intent sources to file APIs with Androguard"
        return "DEX bytecode call-graph and constant-string analysis with Androguard"

    if source == "runtime":
        if "provider" in text:
            return "ADB runtime probing of Content Provider query paths and selection arguments"
        if "receiver" in text or "broadcast" in text:
            return "ADB broadcast injection against exported receivers with malformed extras"
        return "ADB component fuzzing with malformed Intent extras and crash-response monitoring"

    if source == "fuzzing":
        if "sql" in text or "sqlite" in text:
            return "Hybrid fuzzing with mutated SQL-style selection payloads and SQLite error monitoring"
        if "path traversal" in text or "file" in text:
            return "Hybrid fuzzing with traversal payload mutation and sandbox file-access monitoring"
        if "webview" in text or "javascript" in text:
            return "Hybrid fuzzing with JavaScript URI mutation and WebView execution monitoring"
        return "Hybrid fuzzing with semantic payload mutation and crash/sink monitoring"

    return "Heuristic pattern matching over component behaviour and sink indicators"


def _infer_attack_vector(finding: Dict[str, Any]) -> str:
    source = _normalize_analysis_source(finding)
    title = (finding.get("type") or finding.get("title") or "").lower()
    payload = (finding.get("payload") or "").lower()
    text = f"{title} {payload}"

    if source == "static":
        return "Exported component or permission configuration reachable by other apps"
    if source == "dynamic":
        if "sql" in text or "sqlite" in text:
            return "Intent-controlled data flows into a raw SQLite query sink"
        if "path traversal" in text or "file" in text:
            return "Intent-controlled data flows into a file path sink"
        if "webview" in text or "javascript" in text:
            return "Component exposes WebView JavaScript execution or bridge access"
        return "Intent-controlled data flows into a sensitive API sink"
    if source == "runtime":
        if "provider" in text:
            return "Live query against an exported Content Provider using malformed selection arguments"
        if "receiver" in text or "broadcast" in text:
            return "Live broadcast injection against an exported receiver"
        return "Live component invocation with malformed Intent extras"
    if source == "fuzzing":
        return "Semantic payload mutation delivered to exported Android component and observed for crash or sink behaviour"
    return "Heuristic attack-surface identification from component metadata and payload response"


def enrich_finding_for_reporting(finding: Dict[str, Any], origin: str = "") -> Dict[str, Any]:
    enriched = dict(finding)
    if origin:
        enriched["origin"] = origin
        enriched.setdefault("analysis_origin", origin)
    source = _normalize_analysis_source(enriched)
    enriched.setdefault("analysis_source", source)
    enriched.setdefault("detection_technique", _infer_detection_technique(enriched))
    enriched.setdefault("attack_vector", _infer_attack_vector(enriched))
    return enriched

def _attack_label(finding: Dict[str, Any]) -> str:
    title = (finding.get("type") or finding.get("title") or "").lower()
    payload = (finding.get("payload") or "").lower()
    text = f"{title} {payload}"

    if "sql" in text or "sqlite" in text:
        return "SQL Injection"
    if "path traversal" in text or "../" in text or "file://" in text:
        return "Path Traversal"
    if "webview" in text or "javascript:" in text or "<script" in text:
        return "Script Injection"
    if "credential" in text or "secret" in text or "token" in text:
        return "Hardcoded Secrets"
    if "provider" in text and "permission" in text:
        return "Provider Access Control"
    if "receiver" in text and "broadcast" in text:
        return "Broadcast Injection"
    if "activity" in text and "intent" in text:
        return "Intent Injection"
    if "service" in text and "intent" in text:
        return "Service Injection"
    if "crash" in text:
        return "Crash/DoS"
    return "Component Misconfiguration"

def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for finding in findings:
        key = (
            (finding.get("severity") or "").lower(),
            (finding.get("type") or finding.get("title") or "").strip().lower(),
            (finding.get("component") or "").strip().lower(),
            (finding.get("source") or "").strip().lower(),
            (finding.get("evidence") or "").strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped

def _severity_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = Counter((f.get("severity") or "info").lower() for f in findings)
    return {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
    }

def _source_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = Counter(_normalize_analysis_source(f) for f in findings)
    return {
        "static": counts.get("static", 0),
        "dynamic": counts.get("dynamic", 0),
        "runtime": counts.get("runtime", 0),
        "fuzzing": counts.get("fuzzing", 0),
        "unknown": counts.get("unknown", 0),
    }

def _attack_type_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = Counter(_attack_label(f) for f in findings)
    return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True))

def _top_risky_components(findings: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    component_stats: Dict[str, Dict[str, Any]] = {}

    for finding in findings:
        component = (finding.get("component") or "Unknown component").strip()
        severity = (finding.get("severity") or "info").lower()
        stat = component_stats.setdefault(component, {
            "component": component,
            "findings": 0,
            "max_severity": "info",
            "risk_score": 0,
            "attack_types": Counter(),
        })
        stat["findings"] += 1
        stat["risk_score"] += _SEVERITY_RANK.get(severity, 0)
        if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(stat["max_severity"], 0):
            stat["max_severity"] = severity
        stat["attack_types"][_attack_label(finding)] += 1

    ranked = sorted(
        component_stats.values(),
        key=lambda x: (x["risk_score"], x["findings"]),
        reverse=True,
    )[:limit]

    for item in ranked:
        attack_types = item.pop("attack_types")
        item["top_attack_type"] = attack_types.most_common(1)[0][0] if attack_types else "Unknown"

    return ranked

def _recommendations_from_findings(
    attack_breakdown: Dict[str, int],
    top_components: List[Dict[str, Any]],
    limit: int = 5,
) -> List[str]:
    recommendations: List[str] = []

    if attack_breakdown.get("Intent Injection", 0) or attack_breakdown.get("Service Injection", 0):
        recommendations.append(
            "Add strict validation for all Intent extras and reject unexpected keys, types, and oversized payloads."
        )
    if attack_breakdown.get("SQL Injection", 0):
        recommendations.append(
            "Replace raw SQL concatenation with parameterized queries (selectionArgs / prepared statements)."
        )
    if attack_breakdown.get("Provider Access Control", 0):
        recommendations.append(
            "Enforce read/write permissions on exported Content Providers and verify caller identity before serving data."
        )
    if attack_breakdown.get("Broadcast Injection", 0):
        recommendations.append(
            "Protect exported receivers with android:permission and validate trusted senders for sensitive actions."
        )
    if attack_breakdown.get("Hardcoded Secrets", 0):
        recommendations.append(
            "Remove embedded secrets from APK code and load credentials from secure backend or Android Keystore."
        )

    if top_components:
        component_names = ", ".join(item.get("component", "") for item in top_components[:2] if item.get("component"))
        if component_names:
            recommendations.append(
                f"Prioritize patching high-risk components first: {component_names}."
            )

    deduped: List[str] = []
    for rec in recommendations:
        if rec not in deduped:
            deduped.append(rec)
    return deduped[:limit]

def _crash(output: str) -> bool:
    patterns = [
        r"FATAL EXCEPTION",
        r"Process.*has died",
        r"java\.lang\.(NullPointerException|ArrayIndexOutOfBoundsException|RuntimeException|IllegalArgumentException)",
        r"android\.content\.ActivityNotFoundException",
        r"Caused by:",
        r"force.clos",
        r"AndroidRuntime.*Error",
    ]
    return any(re.search(p, output, re.IGNORECASE) for p in patterns)

def _sqli(output: str) -> bool:
    patterns = [
        r"SQLiteException",
        r"no such (column|table)",
        r"unrecognized token",
        r"syntax error",
        r"android_metadata",
        r"SQLiteDatabaseCorruptException",
    ]
    return any(re.search(p, output, re.IGNORECASE) for p in patterns)

def _crash_line(output: str) -> str:
    for line in output.splitlines():
        if any(k in line for k in ["Exception", "Error", "FATAL", "Caused by"]):
            return line.strip()[:200]
    return output[:200].strip()

def _sqli_line(output: str) -> str:
    for line in output.splitlines():
        if any(k in line.lower() for k in ["sqlite", "sql", "syntax", "column", "table"]):
            return line.strip()[:200]
    return output[:200].strip()


# ─── Component Extractor (called from tasks.py) ───────────────────────────────

def extract_components_for_fuzzing(scan_data: Dict) -> Dict:
    """
    Extracts Android components from the completed static analysis result.
    Searches all the nested locations where the analyzer may have stored them.
    """
    static   = scan_data.get("static_analysis") or {}
    manifest = scan_data.get("manifest") or {}

    # Components live at several nesting levels depending on which analyzer ran:
    #   scan.static_analysis["components"]  — set by _enrich_static_analysis
    #   scan.static_analysis["manifest"]    — raw manifest stored by enricher
    #   results["manifest"]                 — passed separately
    #   results["components"]               — set by APKAnalyzer
    static_components = static.get("components") or {}
    static_manifest   = static.get("manifest") or {}

    def _pick(key):
        return (
            static_components.get(key)
            or static.get(key)
            or static_manifest.get(key)
            or manifest.get(key)
            or scan_data.get(key)
            or []
        )

    components = {
        "activities": _pick("activities"),
        "services":   _pick("services"),
        "receivers":  _pick("receivers"),
        "providers":  _pick("providers"),
    }

    total = sum(len(v) for v in components.values())
    print(f"[FALCON-SCAN] Identified {total} Android components "
          f"(act={len(components['activities'])}, "
          f"svc={len(components['services'])}, "
          f"rcv={len(components['receivers'])}, "
          f"pvd={len(components['providers'])})")
    return components
