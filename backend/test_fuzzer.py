#!/usr/bin/env python
"""
FalconScan Component Security Engine — Test Script
Tests Android component extraction, static analysis and display layer
without requiring a connected device.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

# Minimal Django setup so models can be imported
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "falconscan_backend.settings")

from apps.scans.apk_fuzzer import (
    APKFuzzer,
    StaticComponentFuzzer,
    extract_components_for_fuzzing,
    ADB_AVAILABLE,
    DEEP_ENGINE_ACTIVE,
)
from apps.scans.falcon_fuzzer import FalconComponentScanner, run_component_scan

SEP = "=" * 60

def banner(msg):
    print(f"\n{SEP}\n  {msg}\n{SEP}")

def run_tests():
    banner("FalconScan Component Security Engine — Test")

    print(f"  Deep engine active : {DEEP_ENGINE_ACTIVE}")
    print(f"  ADB available      : {ADB_AVAILABLE}")
    engine = "falcon-deep" if DEEP_ENGINE_ACTIVE else ("falcon-runtime" if ADB_AVAILABLE else "falcon-static")
    print(f"  Active engine      : {engine}")

    # ── Test 1: component extraction ──────────────────────────────────────────
    banner("Test 1 – extract_components_for_fuzzing()")

    fake_scan = {
        "static_analysis": {
            "activities": [
                {"name": "com.app.MainActivity", "exported": True},
                {"name": "com.app.DeepLinkActivity", "exported": True},
                {"name": "com.app.InternalActivity", "exported": False},
            ],
            "services": [
                {"name": "com.app.DownloadService", "exported": True},
                {"name": "com.app.SyncService",     "exported": False},
            ],
            "receivers": [
                {"name": "com.app.BootReceiver", "exported": True},
            ],
            "providers": [
                {"name": "com.app.DataProvider", "authority": "com.app.data",
                 "exported": True, "readPermission": None, "writePermission": None},
            ],
        }
    }

    components = extract_components_for_fuzzing(fake_scan)
    print(f"  activities : {len(components['activities'])}")
    print(f"  services   : {len(components['services'])}")
    print(f"  receivers  : {len(components['receivers'])}")
    print(f"  providers  : {len(components['providers'])}")
    assert len(components["activities"]) == 3, "Expected 3 activities"
    assert len(components["providers"])  == 1, "Expected 1 provider"
    print("  PASS")

    # ── Test 2: static fuzzer ─────────────────────────────────────────────────
    banner("Test 2 – StaticComponentFuzzer.fuzz()")

    sf = StaticComponentFuzzer()
    findings = sf.fuzz(components, "com.app")
    print(f"  Findings: {len(findings)}")
    for f in findings:
        print(f"    [{f['severity'].upper()}] {f['type']} – {f['component']}")

    assert len(findings) > 0, "Expected at least one static finding"
    has_deeplink = any("Deep-Link" in f["type"] or "OAuth" in f["type"] for f in findings)
    has_provider = any("Provider" in f["type"] for f in findings)
    assert has_deeplink, "Expected deep-link/OAuth finding"
    assert has_provider,  "Expected Content Provider finding"
    print("  PASS")

    # ── Test 3: APKFuzzer orchestrator (static-only, no device) ──────────────
    banner("Test 3 – APKFuzzer.fuzz() (static engine)")

    fuzzer = APKFuzzer(
        package_name="com.example.vuln",
        components={
            "activities": [{"name": "com.example.vuln.ShareActivity", "exported": True}],
            "services":   [{"name": "com.example.vuln.RemoteService",  "exported": True}],
            "receivers":  [],
            "providers":  [{"name": "com.example.vuln.ContactsProvider",
                            "authority": "com.example.vuln.contacts",
                            "exported": True,
                            "readPermission": None, "writePermission": None}],
        },
        enabled=True,
    )

    result = fuzzer.fuzz()
    print(f"  Engine            : {result['engine']}")
    print(f"  Components fuzzed : {result['components_fuzzed']}")
    print(f"  Vulnerabilities   : {result['vulnerabilities_found']}")
    for v in result["vulnerabilities"]:
        print(f"    [{v['severity'].upper()}] {v['type']}")

    assert result["enabled"]   is True,  "Fuzzer should be enabled"
    assert result["engine"].startswith("falcon-"), "Engine should be a FalconScan engine"
    assert result["vulnerabilities_found"] > 0, "Expected at least one vulnerability"
    print("  PASS")

    # ── Test 4: disabled fuzzer ───────────────────────────────────────────────────
    banner("Test 4 – APKFuzzer disabled")
    fuzzer2 = APKFuzzer(enabled=False)
    result2  = fuzzer2.fuzz()
    assert result2["enabled"] is False
    print("  PASS")

    # ── Test 5: FalconComponentScanner display layer ────────────────────────────
    banner("Test 5 – FalconComponentScanner (display layer)")

    display_scan_data = {
        "static_analysis": {
            "activities": [
                {"name": "com.vuln.OAuthCallbackActivity", "exported": True},
            ],
            "services":  [{"name": "com.vuln.BackgroundService", "exported": True}],
            "receivers": [],
            "providers": [
                {"name": "com.vuln.FileProvider", "authority": "com.vuln.files",
                 "exported": True, "readPermission": None, "writePermission": None},
            ],
        }
    }

    scanner = FalconComponentScanner(
        package_name="com.vuln",
        scan_data=display_scan_data,
        enabled=True,
    )
    report = scanner.scan()

    # verify display structure
    assert "summary" in report,   "Report must have a summary"
    assert "findings" in report,  "Report must have findings"
    assert "engine_label" in report, "Report must have engine_label"
    assert "FalconScan" in report["engine_label"], "Engine label must be FalconScan-branded"
    assert report["summary"]["risk_score"] > 0,    "Risk score should be non-zero"
    assert report["summary"]["risk_level"] != "N/A", "Risk level should be set"

    print(f"  Engine label  : {report['engine_label']}")
    print(f"  Risk level    : {report['summary']['risk_level']} "
          f"({report['summary']['risk_score']}/100)")
    print(f"  Findings      : {report['summary']['total_findings']}")
    print()

    # pretty-print the display output
    scanner.display(report)
    print("  PASS")

    # ── Test 6: run_component_scan shortcut ──────────────────────────────────
    banner("Test 6 – run_component_scan() shortcut")
    quick = run_component_scan(
        apk_path="",
        package_name="com.shortcut.test",
        scan_data=display_scan_data,
        enabled=True,
    )
    assert quick["enabled"] is True
    assert "FalconScan" in quick["scanner"]
    print(f"  Scanner : {quick['scanner']}")
    print("  PASS")

    banner("All tests passed")


if __name__ == "__main__":
    run_tests()
