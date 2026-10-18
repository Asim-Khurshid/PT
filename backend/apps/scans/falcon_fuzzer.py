"""
FalconScan Component Security Engine — Display Layer
Presents Android attack-surface analysis results to the user.

This module wraps the core analyzer (apk_fuzzer.APKFuzzer) and converts
raw findings into a structured, human-readable report with risk scoring.
"""
import time
from typing import Dict, List, Optional

from .apk_fuzzer import APKFuzzer, StaticComponentFuzzer, extract_components_for_fuzzing

# ─── Severity weights for risk score ─────────────────────────────────────────
_SEVERITY_WEIGHT = {
    "critical": 25,
    "high":     15,
    "medium":   8,
    "low":      3,
    "info":     1,
}

_SOURCE_WEIGHT = {
    "static": 1.0,
    "dynamic": 0.95,
    "runtime": 0.90,
    "fuzzing": 0.70,
    "unknown": 0.85,
}

_ENGINE_LABELS = {
    "falcon-deep":    "FalconScan Deep Analyzer",
    "falcon-runtime": "FalconScan Runtime Engine",
    "falcon-static":  "FalconScan Static Engine",
}

_RISK_LEVELS = [
    (80, "Critical"),
    (60, "High"),
    (35, "Medium"),
    (15, "Low"),
    ( 0, "Safe"),
]


# ─── FalconComponentScanner ───────────────────────────────────────────────────

class FalconComponentScanner:
    """
    User-facing Android component security scanner.

    Usage:
        scanner = FalconComponentScanner(
            apk_path     = "/path/to/app.apk",
            package_name = "com.example.app",
            scan_data    = static_analysis_results,   # dict with activities/services/etc.
            device_serial= None,                       # optional ADB serial
        )
        report = scanner.scan()
        scanner.display(report)          # pretty-print to console
    """

    BANNER = "FalconScan — Android Component Security Engine v2"

    def __init__(
        self,
        apk_path: str = "",
        package_name: str = "",
        scan_data: Optional[Dict] = None,
        device_serial: Optional[str] = None,
        timeout: int = 30,
        max_workers: int = 4,
        enabled: bool = True,
    ):
        self.apk_path      = apk_path
        self.package_name  = package_name
        self.scan_data     = scan_data or {}
        self.device_serial = device_serial
        self.timeout       = timeout
        self.max_workers   = max_workers
        self.enabled       = enabled

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan(self) -> Dict:
        """
        Run the full component security scan and return a display-ready report.
        """
        if not self.enabled:
            return self._disabled_report()

        t_start = time.time()

        # Extract components from static analysis data
        components = extract_components_for_fuzzing(self.scan_data)

        # Run the core analyzer
        fuzzer = APKFuzzer(
            apk_path      = self.apk_path,
            package_name  = self.package_name,
            components    = components,
            device_serial = self.device_serial,
            timeout       = self.timeout,
            max_workers   = self.max_workers,
            enabled       = True,
        )
        raw = fuzzer.fuzz()

        elapsed = round(time.time() - t_start, 2)
        return self._build_report(raw, components, elapsed)

    def display(self, report: Dict) -> None:
        """Pretty-print a scan report to stdout."""
        SEP  = "=" * 64
        SEP2 = "-" * 64

        print(f"\n{SEP}")
        print(f"  {self.BANNER}")
        print(SEP)

        if not report.get("enabled"):
            print("  Component scanning is disabled.")
            print(SEP)
            return

        summary = report["summary"]
        print(f"  Package   : {report['package']}")
        print(f"  Engine    : {report['engine_label']}")
        print(f"  Scanned   : {summary['components_scanned']} components "
              f"in {report['elapsed_seconds']}s")
        print(f"  Risk Level: {summary['risk_level']}  (score {summary['risk_score']}/100)")
        print(f"  Findings  : {summary['total_findings']}  "
              f"(critical={summary['by_severity']['critical']}, "
              f"high={summary['by_severity']['high']}, "
              f"medium={summary['by_severity']['medium']}, "
              f"low={summary['by_severity']['low']})")
        print(SEP2)

        findings = report.get("findings", [])
        if not findings:
            print("  No vulnerabilities detected.")
        else:
            for i, f in enumerate(findings, 1):
                sev = f["severity"].upper()
                print(f"  [{i:02d}] [{sev}] {f['type']}")
                print(f"       Component : {f['component']}")
                print(f"       Detail    : {f['description'][:100]}")
                print(f"       Fix       : {f['remediation'][:100]}")
                if f.get("evidence"):
                    print(f"       Evidence  : {f['evidence'][:80]}")
                print()

        print(SEP2)
        print("  Component Breakdown")
        for ctype, items in report["component_summary"].items():
            print(f"    {ctype:<12}: {items['total']:>3}  "
                  f"exported={items['exported']}  "
                  f"flagged={items['flagged']}")

        print(SEP)
        print(f"  Scan completed at {report['end_time']}")
        print(SEP + "\n")

    # ── Internal ───────────────────────────────────────────────────────────────

    def _build_report(self, raw: Dict, components: Dict, elapsed: float) -> Dict:
        findings   = raw.get("vulnerabilities", [])
        engine_key = raw.get("engine", "falcon-static")

        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_source = {"static": 0, "dynamic": 0, "runtime": 0, "fuzzing": 0, "unknown": 0}
        weighted_score = 0.0
        for f in findings:
            sev = f.get("severity", "info").lower()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            src = (f.get("origin") or f.get("analysis_origin") or f.get("source", "unknown")).lower()
            by_source[src] = by_source.get(src, 0) + 1
            weighted_score += _SEVERITY_WEIGHT.get(sev, 1) * _SOURCE_WEIGHT.get(src, _SOURCE_WEIGHT["unknown"])

        risk_score = min(100, round(weighted_score))
        risk_level = next(
            label for threshold, label in _RISK_LEVELS if risk_score >= threshold
        )

        component_summary = {}
        flagged_names = {f.get("component", "") for f in findings}
        for ctype in ("activities", "services", "receivers", "providers"):
            items    = components.get(ctype, [])
            exported = sum(1 for c in items if (True if isinstance(c, str) else c.get("exported", False)))
            flagged  = sum(1 for c in items
                           if (c if isinstance(c, str) else c.get("name", "")) in flagged_names)
            component_summary[ctype] = {
                "total":    len(items),
                "exported": exported,
                "flagged":  flagged,
            }

        # Group findings by component for detailed view
        findings_by_component = {}
        for f in findings:
            comp = f.get("component", "Unknown")
            if comp not in findings_by_component:
                findings_by_component[comp] = []
            findings_by_component[comp].append(f)

        return {
            "enabled":        True,
            "scanner":        self.BANNER,
            "package":        self.package_name,
            "engine":         engine_key,
            "engine_label":   _ENGINE_LABELS.get(engine_key, engine_key),
            "start_time":     raw.get("start_time", ""),
            "end_time":       raw.get("end_time", time.strftime("%Y-%m-%d %H:%M:%S")),
            "elapsed_seconds": elapsed,
            "findings":       findings,
            "findings_by_component": findings_by_component,
            "component_summary": component_summary,
            "summary": {
                "total_findings":      len(findings),
                "components_scanned":  raw.get("components_fuzzed", 0),
                "risk_score":          risk_score,
                "risk_level":          risk_level,
                "by_severity":         by_sev,
                "by_source":           by_source,
            },
        }

    def _disabled_report(self) -> Dict:
        return {
            "enabled":  False,
            "scanner":  self.BANNER,
            "package":  self.package_name,
            "message":  "Component security scanning is disabled for this scan.",
            "findings": [],
            "summary":  {
                "total_findings":     0,
                "components_scanned": 0,
                "risk_score":         0,
                "risk_level":         "N/A",
                "by_severity":        {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            },
        }


# ─── Convenience function (used by tasks.py if preferred) ────────────────────

def run_component_scan(
    apk_path: str,
    package_name: str,
    scan_data: Dict,
    device_serial: Optional[str] = None,
    enabled: bool = True,
) -> Dict:
    """
    One-line component security scan — returns a display-ready report dict.
    Equivalent to FalconComponentScanner(...).scan().
    """
    scanner = FalconComponentScanner(
        apk_path      = apk_path,
        package_name  = package_name,
        scan_data     = scan_data,
        device_serial = device_serial,
        enabled       = enabled,
    )
    return scanner.scan()

