# -*- coding: utf-8 -*-
"""
FalconScan — Professional APK Security Assessment Report Generator

Industry-standard format:
  Cover Page → Executive Summary → Application Overview → Methodology →
  Findings Summary → Vulnerability Details → Permissions → Static Analysis →
  Dynamic Analysis → AI Security Intelligence → OWASP Mobile Top 10 →
  Recommendations
"""
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.platypus import Image as RLImage
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from datetime import datetime
import os
from typing import Dict, List, Optional


# ── OWASP Mobile Top 10 (2024) ────────────────────────────────────────────────
OWASP_MOBILE_TOP10 = {
    "M1":  "Improper Credential Usage",
    "M2":  "Inadequate Supply Chain Security",
    "M3":  "Insecure Authentication / Authorization",
    "M4":  "Insufficient Input/Output Validation",
    "M5":  "Insecure Communication",
    "M6":  "Inadequate Privacy Controls",
    "M7":  "Insufficient Binary Protections",
    "M8":  "Security Misconfiguration",
    "M9":  "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}

# ── Severity palette ──────────────────────────────────────────────────────────
_SEV = {
    "critical": colors.HexColor("#dc2626"),
    "high":     colors.HexColor("#ea580c"),
    "medium":   colors.HexColor("#d97706"),
    "low":      colors.HexColor("#65a30d"),
    "safe":     colors.HexColor("#16a34a"),
    "info":     colors.HexColor("#6b7280"),
}
_SEV_BG = {
    "critical": colors.HexColor("#fef2f2"),
    "high":     colors.HexColor("#fff7ed"),
    "medium":   colors.HexColor("#fffbeb"),
    "low":      colors.HexColor("#f7fee7"),
    "safe":     colors.HexColor("#f0fdf4"),
    "info":     colors.HexColor("#f9fafb"),
}

PRIMARY   = colors.HexColor("#1e3a8a")
PRIMARY_L = colors.HexColor("#3b82f6")
DARK      = colors.HexColor("#111827")
TEXT      = colors.HexColor("#374151")
MUTED     = colors.HexColor("#6b7280")
BORDER    = colors.HexColor("#e5e7eb")
ROW_ALT   = colors.HexColor("#f9fafb")
WHITE     = colors.white


class PDFReportGenerator:
    """Generate professional A4 APK security assessment reports."""

    def __init__(self, output_dir="media/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    # ── Custom styles ─────────────────────────────────────────────────────────
    def _setup_styles(self):
        s = self.styles

        def add(name, parent="Normal", **kw):
            if name not in s:
                s.add(ParagraphStyle(name=name, parent=s[parent], **kw))

        add("SectionHdr",  fontSize=13, textColor=PRIMARY,
            fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=6, leading=17)
        add("SubHdr",      fontSize=10, textColor=DARK,
            fontName="Helvetica-Bold", spaceBefore=8,  spaceAfter=4,  leading=14)
        add("Body",        fontSize=9,  textColor=TEXT,
            alignment=TA_JUSTIFY, spaceAfter=4, leading=13)
        add("BodySmall",   fontSize=8,  textColor=TEXT,
            spaceAfter=3, leading=11)
        add("Caption",     fontSize=8,  textColor=MUTED,
            alignment=TA_CENTER, spaceAfter=4)
        add("Footer",      fontSize=7,  textColor=MUTED,
            alignment=TA_CENTER, leading=10)

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _sev_color(sev: str):
        return _SEV.get((sev or "info").lower(), MUTED)

    @staticmethod
    def _sev_bg(sev: str):
        return _SEV_BG.get((sev or "info").lower(), colors.HexColor("#f9fafb"))

    @staticmethod
    def _trunc(text, n=200):
        text = str(text or "")
        return text[:n] + ("\u2026" if len(text) > n else "")

    def _count_list(self, value) -> int:
        return len(value) if isinstance(value, list) else 0

    def _count_dict_items(self, value) -> int:
        if isinstance(value, dict):
            return sum(len(v) if isinstance(v, list) else 1
                       for v in value.values())
        return len(value) if isinstance(value, list) else 0

    def _sample_list(self, items, limit=15) -> List[str]:
        if not items:
            return []
        if isinstance(items, dict):
            items = list(items.values())
        return [str(i) for i in items if i is not None][:limit]

    def _std_table(self, data, col_widths):
        """Standard table: blue header, alternating rows, grid."""
        t = Table(data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1,  0), PRIMARY),
            ("TEXTCOLOR",      (0, 0), (-1,  0), WHITE),
            ("FONTNAME",       (0, 0), (-1,  0), "Helvetica-Bold"),
            ("FONTSIZE",       (0, 0), (-1, -1), 8),
            ("TEXTCOLOR",      (0, 1), (-1, -1), TEXT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, ROW_ALT]),
            ("GRID",           (0, 0), (-1, -1), 0.4, BORDER),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LEFTPADDING",    (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",   (0, 0), (-1, -1), 6),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ]))
        return t

    def _kv_table(self, rows, col_widths=(1.8 * inch, 4.2 * inch)):
        """Two-column key-value info table."""
        t = Table(rows, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("TEXTCOLOR",     (0, 0), (-1, -1), TEXT),
            ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        return t

    def _section_rule(self):
        return HRFlowable(width="100%", thickness=1.2,
                          color=PRIMARY_L, spaceAfter=6, spaceBefore=2)

    # ── Main entry point ──────────────────────────────────────────────────────
    def generate(self,
                 scan_data: Dict,
                 vulnerabilities: List[Dict],
                 permissions: List,
                 static_analysis: Dict,
                 dynamic_analysis: Dict = None,
                 ai_report: Dict = None) -> str:

        app_name  = scan_data.get("app_name", "Unknown")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"security_report_{app_name.replace(' ', '_')}_{timestamp}.pdf"
        filepath  = os.path.join(self.output_dir, filename)

        W, H = A4
        doc = SimpleDocTemplate(
            filepath, pagesize=A4,
            rightMargin=18 * mm, leftMargin=18 * mm,
            topMargin=22 * mm, bottomMargin=18 * mm,
        )

        def _header_footer(canvas, doc):
            canvas.saveState()
            if doc.page > 1:
                canvas.setStrokeColor(PRIMARY)
                canvas.setLineWidth(1.2)
                canvas.line(18 * mm, H - 14 * mm, W - 18 * mm, H - 14 * mm)
                canvas.setFont("Helvetica-Bold", 7.5)
                canvas.setFillColor(PRIMARY)
                canvas.drawString(18 * mm, H - 11.5 * mm,
                                  "FalconScan \u2022 APK Security Assessment Report")
                canvas.setFont("Helvetica", 7.5)
                canvas.setFillColor(MUTED)
                canvas.drawRightString(W - 18 * mm, H - 11.5 * mm, app_name)
                canvas.setStrokeColor(BORDER)
                canvas.setLineWidth(0.5)
                canvas.line(18 * mm, 13 * mm, W - 18 * mm, 13 * mm)
                canvas.setFont("Helvetica", 7)
                canvas.setFillColor(MUTED)
                canvas.drawCentredString(
                    W / 2, 9 * mm,
                    f"Page {doc.page}  \u2022  CONFIDENTIAL \u2014 Internal Use Only"
                )
            canvas.restoreState()

        elements: List = []

        elements.extend(self._create_cover(scan_data, vulnerabilities))
        elements.append(PageBreak())

        elements.extend(self._create_executive_summary(scan_data, vulnerabilities))
        elements.append(Spacer(1, 5 * mm))

        elements.extend(self._create_app_overview(scan_data, static_analysis))
        elements.append(Spacer(1, 5 * mm))

        elements.extend(self._create_methodology(scan_data, dynamic_analysis, ai_report))
        elements.append(Spacer(1, 5 * mm))

        elements.extend(self._create_findings_summary(scan_data, vulnerabilities))
        elements.append(PageBreak())

        elements.extend(self._create_vulnerability_details(vulnerabilities))
        elements.append(PageBreak())

        elements.extend(self._create_permission_analysis(permissions))
        elements.append(Spacer(1, 5 * mm))

        elements.extend(self._create_static_analysis(static_analysis or {}))
        elements.append(PageBreak())

        elements.extend(self._create_dynamic_analysis(dynamic_analysis or {}))
        elements.append(PageBreak())

        if ai_report:
            elements.extend(self._create_ai_analysis(ai_report))
            elements.append(PageBreak())

        elements.extend(self._create_owasp_coverage(vulnerabilities, ai_report))
        elements.append(Spacer(1, 5 * mm))

        elements.extend(self._create_recommendations(vulnerabilities, scan_data, ai_report))

        doc.build(elements,
                  onFirstPage=_header_footer,
                  onLaterPages=_header_footer)
        return filename

    # ════════════════════════════════════════════════════════════════════════
    #  1. COVER PAGE
    # ════════════════════════════════════════════════════════════════════════
    def _create_cover(self, scan_data: Dict, vulnerabilities: List[Dict]) -> List:
        elements: List = []
        threat_level = scan_data.get("threat_level", "unknown").upper()
        threat_score = scan_data.get("threat_score", 0)
        sev_hex = {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM":   "#d97706", "LOW":  "#65a30d",
            "SAFE":     "#16a34a",
        }.get(threat_level, "#6b7280")

        # Blue top banner
        banner_t = Table([[
            Paragraph(
                '<b><font color="white" size="24">FalconScan</font></b><br/>'
                '<font color="#93c5fd" size="11">Advanced APK Security Assessment Platform</font>',
                ParagraphStyle("_cv_b", fontSize=11, leading=30,
                               textColor=WHITE, backColor=PRIMARY)
            ),
            ""
        ]], colWidths=[4.5 * inch, 2.5 * inch])
        banner_t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), PRIMARY),
            ("TOPPADDING",    (0, 0), (-1, -1), 22),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 22),
            ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ]))
        elements.append(banner_t)
        elements.append(Spacer(1, 8 * mm))

        # Report title + threat badge
        badge_t = Table([[
            Paragraph(
                "<b>Security Assessment Report</b>",
                ParagraphStyle("_cv_t", fontSize=20, textColor=DARK,
                               fontName="Helvetica-Bold", leading=24)
            ),
            Paragraph(
                f'<font color="{sev_hex}" size="16"><b>\u25cf {threat_level}</b></font><br/>'
                f'<font color="#374151" size="9">Risk Score: {threat_score} / 100</font>',
                ParagraphStyle("_cv_bd", fontSize=14, alignment=TA_RIGHT, leading=22)
            ),
        ]], colWidths=[4 * inch, 3 * inch])
        badge_t.setStyle(TableStyle([
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        elements.append(badge_t)
        elements.append(Spacer(1, 3 * mm))
        elements.append(HRFlowable(width="100%", thickness=2, color=PRIMARY,
                                   spaceAfter=6 * mm))

        # App info table
        elements.append(self._kv_table([
            ["Application Name", scan_data.get("app_name", "N/A")],
            ["Package Name",     scan_data.get("package_name", "N/A")],
            ["Version",          f"{scan_data.get('version_name', 'N/A')} "
                                 f"(build {scan_data.get('version_code', 'N/A')})"],
            ["Scan Date",        datetime.now().strftime("%d %B %Y  \u2022  %H:%M UTC")],
            ["Report ID",        str(scan_data.get("id", "N/A"))],
            ["Prepared By",      "FalconScan Automated Security Engine"],
            ["Classification",   "CONFIDENTIAL \u2014 Internal Use Only"],
        ], col_widths=(1.8 * inch, 4.5 * inch)))
        elements.append(Spacer(1, 7 * mm))

        # Quick-stats bar
        c  = scan_data.get("critical_issues", 0)
        h  = scan_data.get("high_issues", 0)
        m  = scan_data.get("medium_issues", 0)
        lo = scan_data.get("low_issues", 0)

        def _stat(label, count, hex_c):
            return Paragraph(
                f'<font color="{hex_c}" size="22"><b>{count}</b></font><br/>'
                f'<font color="#6b7280" size="8">{label}</font>',
                ParagraphStyle("_sc", alignment=TA_CENTER, leading=26)
            )

        stats_t = Table([[
            _stat("CRITICAL", c,  "#dc2626"),
            _stat("HIGH",     h,  "#ea580c"),
            _stat("MEDIUM",   m,  "#d97706"),
            _stat("LOW",      lo, "#65a30d"),
            _stat("TOTAL",    len(vulnerabilities), "#1e3a8a"),
        ]], colWidths=[1.4 * inch] * 5)
        stats_t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX",           (0, 0), (-1, -1), 1, BORDER),
            ("INNERGRID",     (0, 0), (-1, -1), 0.5, BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(stats_t)
        elements.append(Spacer(1, 10 * mm))

        elements.append(Paragraph(
            "<i>This report is intended for the application development and security teams only. "
            "Findings are generated by automated static, dynamic, and fuzzing analysis, augmented "
            "by AI-powered security intelligence. Results should be reviewed by a qualified security "
            "professional before remediation decisions are made. Do not distribute externally.</i>",
            ParagraphStyle("_disc", fontSize=8, textColor=MUTED,
                           alignment=TA_JUSTIFY, leading=11)
        ))
        return elements

    # ════════════════════════════════════════════════════════════════════════
    #  2. EXECUTIVE SUMMARY
    # ════════════════════════════════════════════════════════════════════════
    def _create_executive_summary(self, scan_data: Dict,
                                   vulnerabilities: List[Dict]) -> List:
        elements: List = []
        elements.append(Paragraph("1.  Executive Summary", self.styles["SectionHdr"]))
        elements.append(self._section_rule())

        threat_level = scan_data.get("threat_level", "unknown").upper()
        threat_score = scan_data.get("threat_score", 0)
        sev_hex = {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM":   "#d97706", "LOW":  "#65a30d", "SAFE": "#16a34a",
        }.get(threat_level, "#6b7280")

        elements.append(Paragraph(
            f"This security assessment evaluated the Android application "
            f"<b>{scan_data.get('app_name', 'N/A')}</b> "
            f"(package: <i>{scan_data.get('package_name', 'N/A')}</i>) and identified "
            f"<b>{len(vulnerabilities)}</b> security finding(s) across static analysis, "
            f"dynamic runtime testing, and component fuzzing. "
            f"The overall risk posture is rated "
            f'<b><font color="{sev_hex}">{threat_level}</font></b> '
            f"with a composite risk score of <b>{threat_score}/100</b>.",
            self.styles["Body"]
        ))
        elements.append(Spacer(1, 3 * mm))

        c    = scan_data.get("critical_issues", 0)
        h    = scan_data.get("high_issues",     0)
        m    = scan_data.get("medium_issues",   0)
        lo   = scan_data.get("low_issues",      0)
        info = len([v for v in vulnerabilities
                    if v.get("severity", "").lower() == "info"])

        sev_data = [
            ["Severity",       "Count",
             "Description"],
            ["Critical",        str(c),
             "Directly exploitable; severe business impact \u2014 fix before deployment"],
            ["High",            str(h),
             "Significant risk; address in current sprint"],
            ["Medium",          str(m),
             "Moderate risk; schedule for next release"],
            ["Low",             str(lo),
             "Minor issues; track in security backlog"],
            ["Informational",   str(info),
             "No immediate action required; awareness only"],
        ]
        t = Table(sev_data, colWidths=[1.15 * inch, 0.75 * inch, 4.6 * inch])
        sty = [
            ("BACKGROUND",    (0, 0), (-1,  0), PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1,  0), WHITE),
            ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]
        if c  > 0: sty.append(("BACKGROUND", (0, 1), (-1, 1), _SEV_BG["critical"]))
        if h  > 0: sty.append(("BACKGROUND", (0, 2), (-1, 2), _SEV_BG["high"]))
        if m  > 0: sty.append(("BACKGROUND", (0, 3), (-1, 3), _SEV_BG["medium"]))
        t.setStyle(TableStyle(sty))
        elements.append(t)
        return elements

    # ════════════════════════════════════════════════════════════════════════
    #  3. APPLICATION OVERVIEW
    # ════════════════════════════════════════════════════════════════════════
    def _create_app_overview(self, scan_data: Dict, static_analysis: Dict) -> List:
        elements: List = []
        elements.append(Paragraph("2.  Application Overview", self.styles["SectionHdr"]))
        elements.append(self._section_rule())

        s  = static_analysis or {}
        ai = s.get("app_info",    {}) or {}
        mf = s.get("manifest",    {}) or {}
        ct = s.get("certificate", {}) or {}
        co = s.get("components",  {}) or {}

        elements.append(Paragraph("2.1  Application Metadata", self.styles["SubHdr"]))
        elements.append(self._kv_table([
            ["Package Name",     ai.get("package_name") or mf.get("package", "N/A")],
            ["Version Name",     ai.get("version") or scan_data.get("version_name", "N/A")],
            ["Version Code",     str(scan_data.get("version_code", "N/A"))],
            ["File Name",        ai.get("file_name", "N/A")],
            ["File Size",        f"{(ai.get('file_size') or 0) / (1024 * 1024):.2f} MB"],
            ["MD5",              ai.get("hash_md5", "N/A")],
            ["SHA-256",          self._trunc(ai.get("hash_sha256", "N/A"), 70)],
            ["Min SDK",          str(mf.get("min_sdk", "N/A"))],
            ["Target SDK",       str(mf.get("target_sdk", "N/A"))],
            ["Debuggable",       str(mf.get("debuggable", False))],
            ["Allow Backup",     str(mf.get("allow_backup", False))],
            ["Network Sec Conf", str(mf.get("network_security_config", "N/A"))],
        ]))
        elements.append(Spacer(1, 4 * mm))

        if ct:
            elements.append(Paragraph("2.2  Code Signing Certificate",
                                      self.styles["SubHdr"]))
            elements.append(self._kv_table([
                ["Algorithm",      ct.get("algorithm", "N/A")],
                ["Issuer",         self._trunc(ct.get("issuer", "N/A"), 80)],
                ["Subject",        self._trunc(ct.get("subject", "N/A"), 80)],
                ["Valid From",     ct.get("valid_from", "N/A")],
                ["Valid Until",    ct.get("valid_until", "N/A")],
                ["Signature Ver",  ct.get("signature_version", "N/A")],
                ["Serial Number",  ct.get("serial_number", "N/A")],
            ]))
            elements.append(Spacer(1, 4 * mm))

        if co:
            elements.append(Paragraph("2.3  Application Components",
                                      self.styles["SubHdr"]))

            def _exp(lst):
                return len([a for a in lst
                            if isinstance(a, dict) and a.get("exported")])

            acts = co.get("activities", [])
            svcs = co.get("services",   [])
            rcvs = co.get("receivers",  [])
            prvs = co.get("providers",  [])
            elements.append(self._std_table([
                ["Component",   "Total", "Exported (Exposed)"],
                ["Activities",  str(len(acts)), str(_exp(acts))],
                ["Services",    str(len(svcs)), str(_exp(svcs))],
                ["Receivers",   str(len(rcvs)), str(_exp(rcvs))],
                ["Providers",   str(len(prvs)), str(_exp(prvs))],
            ], [2.4 * inch, 1.2 * inch, 1.6 * inch]))
        return elements

    # ════════════════════════════════════════════════════════════════════════
    #  4. ASSESSMENT METHODOLOGY
    # ════════════════════════════════════════════════════════════════════════
    def _create_methodology(self, scan_data: Dict,
                             dynamic_analysis, ai_report) -> List:
        elements: List = []
        elements.append(Paragraph("3.  Assessment Methodology",
                                  self.styles["SectionHdr"]))
        elements.append(self._section_rule())
        elements.append(Paragraph(
            "This assessment was performed by the FalconScan automated security platform, "
            "combining four complementary analysis techniques in alignment with "
            "OWASP MASVS and NIST SP 800-163.",
            self.styles["Body"]
        ))
        elements.append(Spacer(1, 3 * mm))

        has_dyn = bool(dynamic_analysis)
        has_ai  = bool(ai_report)

        meth = [
            ["Technique", "Status", "Coverage"],
            ["Static Analysis (SAST)",   "\u2713 Completed",
             "APK decompilation, manifest analysis, permission enumeration, secrets, "
             "URL/domain/IP extraction, cryptography, code patterns"],
            ["Dynamic Analysis (DAST)",
             "\u2713 Completed" if has_dyn else "\u25cb Not available",
             "Runtime instrumentation: logcat, network interception (PCAP), "
             "component interaction, memory inspection, monkey stress testing"],
            ["Component Fuzzing",        "\u2713 Completed",
             "Automated intent/deep-link fuzzing of exported Activities, Services, "
             "Receivers, and Content Providers"],
            ["AI Security Intelligence",
             "\u2713 Completed" if has_ai else "\u25cb Not requested",
             "LLM analysis: MITRE ATT&CK mapping, threat profiling, severity "
             "re-scoring, remediation roadmap, compliance assessment"],
        ]
        t = Table(meth, colWidths=[1.75 * inch, 1.2 * inch, 3.55 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1,  0), PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1,  0), WHITE),
            ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, ROW_ALT]),
            ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(t)
        return elements

    # ════════════════════════════════════════════════════════════════════════
    #  5. FINDINGS SUMMARY
    # ════════════════════════════════════════════════════════════════════════
    def _create_findings_summary(self, scan_data: Dict,
                                  vulnerabilities: List[Dict]) -> List:
        elements: List = []
        elements.append(Paragraph("4.  Findings Summary", self.styles["SectionHdr"]))
        elements.append(self._section_rule())

        sev_counts = {
            "critical": scan_data.get("critical_issues", 0),
            "high":     scan_data.get("high_issues",     0),
            "medium":   scan_data.get("medium_issues",   0),
            "low":      scan_data.get("low_issues",      0),
        }
        if sum(sev_counts.values()) > 0:
            drawing = Drawing(260, 160)
            pie = Pie()
            pie.x, pie.y = 30, 20
            pie.width = pie.height = 110
            active = [(k, v) for k, v in sev_counts.items() if v > 0]
            pie.data   = [v for _, v in active]
            pie.labels = [f"{k.title()} ({v})" for k, v in active]
            pie.slices.strokeWidth = 0.5
            pie.slices.strokeColor = WHITE
            for i, (k, _) in enumerate(active):
                pie.slices[i].fillColor = _SEV[k]
            drawing.add(pie)
            elements.append(drawing)

        elements.append(Paragraph("Top Findings by Severity", self.styles["SubHdr"]))
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: {"critical": 0, "high": 1, "medium": 2,
                           "low": 3, "info": 4}.get(
                v.get("severity", "info").lower(), 4)
        )
        rows = [["#", "Severity", "Finding Title", "Category", "OWASP Ref"]]
        for i, v in enumerate(sorted_vulns[:20], 1):
            rows.append([
                str(i),
                v.get("severity", "info").upper(),
                self._trunc(v.get("title", "N/A"), 52),
                self._trunc(v.get("category", "General"), 22),
                v.get("owasp", "\u2014"),
            ])
        t = Table(rows, colWidths=[0.3 * inch, 0.75 * inch, 2.85 * inch,
                                   1.5 * inch, 0.7 * inch])
        sty = TableStyle([
            ("BACKGROUND",    (0, 0), (-1,  0), PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1,  0), WHITE),
            ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, ROW_ALT]),
            ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ])
        for i, v in enumerate(sorted_vulns[:20], 1):
            sev = v.get("severity", "info").lower()
            sty.add("BACKGROUND", (1, i), (1, i), self._sev_bg(sev))
            sty.add("TEXTCOLOR",  (1, i), (1, i), self._sev_color(sev))
            sty.add("FONTNAME",   (1, i), (1, i), "Helvetica-Bold")
        t.setStyle(sty)
        elements.append(t)
        if len(sorted_vulns) > 20:
            elements.append(Paragraph(
                f"<i>\u2026 and {len(sorted_vulns) - 20} additional findings. "
                "See Section 5 for full details.</i>",
                ParagraphStyle("_note", fontSize=8, textColor=MUTED, spaceAfter=4)
            ))
        return elements

    # ════════════════════════════════════════════════════════════════════════
    #  6. VULNERABILITY DETAILS
    # ════════════════════════════════════════════════════════════════════════
    def _create_vulnerability_details(self, vulnerabilities: List[Dict]) -> List:
        elements: List = []
        elements.append(Paragraph("5.  Vulnerability Details", self.styles["SectionHdr"]))
        elements.append(self._section_rule())

        if not vulnerabilities:
            elements.append(Paragraph(
                "No vulnerabilities detected. The application passed all automated checks.",
                self.styles["Body"]
            ))
            return elements

        by_sev: Dict[str, List] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": [],
        }
        for v in vulnerabilities:
            by_sev.setdefault(v.get("severity", "info").lower(), []).append(v)

        labels = {"critical": "Critical", "high": "High", "medium": "Medium",
                  "low": "Low", "info": "Informational"}

        for sev in ["critical", "high", "medium", "low", "info"]:
            vulns = by_sev.get(sev, [])
            if not vulns:
                continue

            sev_c = self._sev_color(sev)
            sev_b = self._sev_bg(sev)
            label = labels[sev]

            hdr_t = Table(
                [[Paragraph(f"<b>{label} Severity \u2014 {len(vulns)} finding(s)</b>",
                            ParagraphStyle("_svhdr", fontSize=10, textColor=WHITE,
                                           fontName="Helvetica-Bold"))]],
                colWidths=[7.0 * inch]
            )
            hdr_t.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), sev_c),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ]))
            elements.append(hdr_t)
            elements.append(Spacer(1, 2 * mm))

            for idx, v in enumerate(vulns, 1):
                title       = v.get("title", "Unknown Issue")
                description = v.get("description") or "No description available."
                category    = v.get("category", "General")
                file_path   = v.get("file_path") or v.get("file", "")
                line_num    = v.get("line_number") or v.get("line", "")
                remediation = v.get("remediation") or "No remediation advice available."
                owasp       = v.get("owasp", "")
                cvss        = v.get("cvss_score") or v.get("cvss", "")
                reference   = v.get("reference") or v.get("cve", "")

                title_p = Paragraph(
                    f"<b>5.{idx}  {title}</b>",
                    ParagraphStyle("_fhdr", fontSize=9, textColor=DARK,
                                   fontName="Helvetica-Bold",
                                   backColor=sev_b, spaceAfter=1,
                                   leftIndent=4, leading=13)
                )
                detail_rows = [["Severity", label], ["Category", category]]
                if owasp:     detail_rows.append(["OWASP",      owasp])
                if cvss:      detail_rows.append(["CVSS Score", str(cvss)])
                if file_path: detail_rows.append(
                    ["Location",
                     f"{file_path}:{line_num}" if line_num else file_path])
                if reference: detail_rows.append(["Reference",  str(reference)])
                detail_rows.append(["Description", self._trunc(description, 350)])
                detail_rows.append(["Remediation", self._trunc(remediation, 350)])

                det_t = Table(
                    [[Paragraph(f"<b>{r[0]}</b>", self.styles["BodySmall"]),
                      Paragraph(r[1], self.styles["BodySmall"])]
                     for r in detail_rows],
                    colWidths=[1.15 * inch, 5.85 * inch]
                )
                det_t.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
                    ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE",      (0, 0), (-1, -1), 8),
                    ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
                    ("TOPPADDING",    (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                    ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ]))
                elements.append(KeepTogether([title_p, det_t, Spacer(1, 3 * mm)]))

        return elements

    # ════════════════════════════════════════════════════════════════════════
    #  7. PERMISSION ANALYSIS
    # ════════════════════════════════════════════════════════════════════════
    def _create_permission_analysis(self, permissions: List) -> List:
        elements: List = []
        elements.append(Paragraph("6.  Permission Analysis", self.styles["SectionHdr"]))
        elements.append(self._section_rule())

        if not permissions:
            elements.append(Paragraph("No permissions declared.", self.styles["Body"]))
            return elements

        dangerous = [p for p in permissions
                     if isinstance(p, dict) and p.get("is_dangerous")]
        normal    = [p for p in permissions
                     if not (isinstance(p, dict) and p.get("is_dangerous"))]

        elements.append(Paragraph(
            f"The application declares <b>{len(permissions)}</b> permission(s), of which "
            f"<b>{len(dangerous)}</b> require runtime user consent (Android protection "
            "level: <i>dangerous</i>). Unnecessary dangerous permissions expand the attack "
            "surface and may violate GDPR/CCPA privacy requirements.",
            self.styles["Body"]
        ))
        elements.append(Spacer(1, 3 * mm))

        rows = [["Permission Name", "Type", "Protection Level"]]
        for p in sorted(dangerous, key=lambda x: x.get("permission_name", "")):
            name = self._trunc(p.get("permission_name") or str(p), 58)
            rows.append([name, "Dangerous", p.get("protection_level", "dangerous")])
        for p in sorted(
            normal,
            key=lambda x: x.get("permission_name", "") if isinstance(x, dict) else str(x)
        )[:25]:
            name = self._trunc(
                (p.get("permission_name") if isinstance(p, dict) else str(p)) or "", 58)
            prot = p.get("protection_level", "normal") if isinstance(p, dict) else "normal"
            rows.append([name, "Normal", prot])
        if len(permissions) > len(rows) - 1:
            rows.append([f"\u2026 {len(permissions) - len(rows) + 1} more", "", ""])

        t = Table(rows, colWidths=[4.0 * inch, 1.2 * inch, 1.5 * inch])
        sty = TableStyle([
            ("BACKGROUND",    (0, 0), (-1,  0), PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1,  0), WHITE),
            ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, ROW_ALT]),
            ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ])
        for i in range(1, len(dangerous) + 1):
            sty.add("BACKGROUND", (1, i), (1, i), _SEV_BG["high"])
            sty.add("TEXTCOLOR",  (1, i), (1, i), _SEV["high"])
            sty.add("FONTNAME",   (1, i), (1, i), "Helvetica-Bold")
        t.setStyle(sty)
        elements.append(t)
        return elements

    # ════════════════════════════════════════════════════════════════════════
    #  8. STATIC ANALYSIS
    # ════════════════════════════════════════════════════════════════════════
    def _create_static_analysis(self, static_analysis: Dict) -> List:
        elements: List = []
        elements.append(Paragraph("7.  Static Analysis", self.styles["SectionHdr"]))
        elements.append(self._section_rule())

        if not static_analysis:
            elements.append(Paragraph("No static analysis data available.",
                                      self.styles["Body"]))
            return elements

        urls    = static_analysis.get("urls",         []) or []
        domains = static_analysis.get("domains",      []) or []
        ips     = static_analysis.get("ip_addresses", []) or []
        emails  = static_analysis.get("emails",       []) or []
        api_k   = static_analysis.get("api_keys",     {}) or {}
        secs    = static_analysis.get("secrets",      {}) or {}

        total_api = self._count_dict_items(api_k)
        total_sec = self._count_dict_items(secs)
        total_ck  = self._count_dict_items(static_analysis.get("crypto_keys"))
        total_fb  = self._count_dict_items(static_analysis.get("firebase"))
        total_aws = self._count_dict_items(static_analysis.get("aws"))

        elements.append(Paragraph("7.1  Artifact Inventory", self.styles["SubHdr"]))
        inv_rows = [
            ["Artifact",                "Count", "Risk"],
            ["URLs Extracted",           str(len(urls)),
             "Low"],
            ["Unique Domains",           str(len(domains)),
             "Low"],
            ["IP Addresses",             str(len(ips)),
             "Medium" if ips else "\u2014"],
            ["Email Addresses",          str(len(emails)),
             "Low"],
            ["Hardcoded API Keys",       str(total_api),
             "Critical" if total_api > 0 else "\u2014"],
            ["Secrets / Credentials",    str(total_sec),
             "Critical" if total_sec > 0 else "\u2014"],
            ["Cryptographic Keys",       str(total_ck),
             "High" if total_ck > 0 else "\u2014"],
            ["Firebase References",      str(total_fb),
             "Medium" if total_fb > 0 else "\u2014"],
            ["AWS References",           str(total_aws),
             "High" if total_aws > 0 else "\u2014"],
            ["Base64 Strings",           str(self._count_list(
                static_analysis.get("base64_strings"))), "Low"],
            ["Interesting Strings",      str(self._count_dict_items(
                static_analysis.get("interesting_strings"))), "Medium"],
        ]
        t = Table(inv_rows, colWidths=[2.9 * inch, 0.9 * inch, 1.0 * inch])
        risk_map = {"Critical": _SEV["critical"], "High": _SEV["high"],
                    "Medium": _SEV["medium"],     "Low": _SEV["low"]}
        sty = TableStyle([
            ("BACKGROUND",    (0, 0), (-1,  0), PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1,  0), WHITE),
            ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, ROW_ALT]),
            ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (1, 0), (2, -1),  "CENTER"),
        ])
        for i, row in enumerate(inv_rows[1:], 1):
            c = risk_map.get(row[2])
            if c:
                sty.add("TEXTCOLOR", (2, i), (2, i), c)
                sty.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")
        t.setStyle(sty)
        elements.append(t)

        if total_api > 0 or total_sec > 0:
            elements.append(Spacer(1, 3 * mm))
            elements.append(Paragraph(
                f'<b><font color="#dc2626">\u26a0 CRITICAL:</font></b>  '
                f'{total_api} hardcoded API key(s) and {total_sec} secret(s) detected. '
                "These credentials must be removed from the codebase immediately and rotated "
                "in all environments. Exposure can lead to account takeover, billing fraud, "
                "or data breach.",
                self.styles["Body"]
            ))

        for label, items in [
            ("7.x  Domains (Sample)",     domains),
            ("7.x  IP Addresses (Sample)", ips),
            ("7.x  Emails (Sample)",       emails),
        ]:
            sample = self._sample_list(items, 15)
            if sample:
                elements.append(Spacer(1, 3 * mm))
                elements.append(Paragraph(label, self.styles["SubHdr"]))
                elements.append(Paragraph(", ".join(sample), self.styles["BodySmall"]))
        return elements

    # ════════════════════════════════════════════════════════════════════════
    #  9. DYNAMIC ANALYSIS
    # ════════════════════════════════════════════════════════════════════════
    def _create_dynamic_analysis(self, dynamic_analysis: Dict) -> List:
        elements: List = []
        elements.append(Paragraph("8.  Dynamic Analysis", self.styles["SectionHdr"]))
        elements.append(self._section_rule())

        if not dynamic_analysis:
            elements.append(Paragraph(
                "Dynamic analysis was not performed for this scan. Connect an Android "
                "device or emulator and re-run to enable runtime instrumentation.",
                self.styles["Body"]
            ))
            return elements

        findings   = dynamic_analysis.get("findings",            []) or []
        logcat     = dynamic_analysis.get("logcat",              {}) or {}
        indicators = dynamic_analysis.get("indicators",          {}) or {}
        net_conns  = dynamic_analysis.get("network_connections", []) or []
        rt_perms   = dynamic_analysis.get("runtime_permissions", []) or []
        processes  = dynamic_analysis.get("running_processes",   []) or []
        device     = dynamic_analysis.get("device",              {}) or {}
        device_st  = dynamic_analysis.get("device_state",        {}) or {}
        monkey     = dynamic_analysis.get("monkey",              {}) or {}
        screenshots= dynamic_analysis.get("screenshots",         []) or []
        net_cap    = dynamic_analysis.get("network_capture")        or {}
        net_anl    = net_cap.get("analysis")                        or {}
        servers    = net_cap.get("servers") or net_anl.get("servers") or []

        elements.append(Paragraph("8.1  Runtime Environment", self.styles["SubHdr"]))
        if device:
            env_rows = [
                ["Device Model",    f"{device.get('model', 'Unknown')} "
                                    f"({device.get('serial', 'N/A')})"],
                ["Android Version", f"{device.get('android_version', 'N/A')} "
                                    f"(SDK {device.get('sdk', 'N/A')})"],
                ["Is Emulator",     str(device_st.get("is_emulator", False))],
                ["Monkey Events",   str(monkey.get("events", 0))],
                ["Runtime Perms",   str(len(rt_perms))],
                ["Running Procs",   str(len(processes))],
                ["Screenshots",     str(len(screenshots))],
            ]
        else:
            env_rows = [["Status",
                         "No device available \u2014 dynamic analysis skipped"]]
        elements.append(self._kv_table(env_rows))
        elements.append(Spacer(1, 4 * mm))

        elements.append(Paragraph("8.2  Runtime Metrics", self.styles["SubHdr"]))
        elements.append(self._std_table([
            ["Metric",                   "Value"],
            ["Dynamic Findings",          str(len(findings))],
            ["Total Logcat Lines",         str(logcat.get("total_lines", 0))],
            ["Suspicious Log Lines",       str(len(logcat.get("suspicious_lines", [])))],
            ["Observed URLs",              str(len(indicators.get("urls", [])))],
            ["Observed IPs",               str(len(indicators.get("ips", [])))],
            ["Active Connections",          str(len(net_conns))],
            ["PCAP Servers Identified",     str(len(servers))],
        ], [3.0 * inch, 2.0 * inch]))
        elements.append(Spacer(1, 4 * mm))

        if servers:
            elements.append(Paragraph(
                "8.3  Network Capture \u2014 Server Fingerprints",
                self.styles["SubHdr"]))
            srv_rows = [["IP Address", "Ports", "Protocols", "TTL", "OS Guess", "Pkts"]]
            for srv in servers[:10]:
                srv_rows.append([
                    srv.get("ip", "N/A"),
                    ", ".join(str(p) for p in srv.get("ports", [])[:4]) or "N/A",
                    ", ".join(srv.get("protocols", [])[:3]) or "N/A",
                    str(srv.get("ttl", "N/A")),
                    srv.get("os_guess", "unknown"),
                    str(srv.get("packet_count", 0)),
                ])
            elements.append(self._std_table(
                srv_rows,
                [1.4*inch, 1.1*inch, 1.05*inch, 0.55*inch, 1.15*inch, 0.7*inch]
            ))
            elements.append(Spacer(1, 4 * mm))

        if screenshots:
            elements.append(Paragraph("8.4  Captured Screenshots",
                                      self.styles["SubHdr"]))
            for shot in screenshots[:3]:
                try:
                    if os.path.isfile(shot):
                        elements.append(RLImage(shot, width=3.5*inch, height=6*inch,
                                                anchor="c"))
                        elements.append(Spacer(1, 3 * mm))
                except Exception:
                    continue

        if findings:
            elements.append(Paragraph("8.5  Dynamic Findings", self.styles["SubHdr"]))
            for idx, f in enumerate(findings, 1):
                title = f.get("title", "Finding")
                sev   = (f.get("severity") or "info").lower()
                rows  = [
                    ["Severity",   (f.get("severity") or "info").upper()],
                    ["Category",   f.get("category", "General")],
                ]
                if f.get("standard"):
                    rows.append(["Standard",    f["standard"]])
                if f.get("description"):
                    rows.append(["Description", self._trunc(f["description"], 280)])
                if f.get("remediation"):
                    rows.append(["Remediation", self._trunc(f["remediation"], 280)])
                title_p = Paragraph(
                    f"<b>{idx}. {title}</b>",
                    ParagraphStyle("_dfh", fontSize=9,
                                   textColor=self._sev_color(sev),
                                   fontName="Helvetica-Bold",
                                   backColor=self._sev_bg(sev), spaceAfter=2))
                det_t = Table(
                    [[Paragraph(f"<b>{r[0]}</b>", self.styles["BodySmall"]),
                      Paragraph(r[1], self.styles["BodySmall"])]
                     for r in rows],
                    colWidths=[1.0 * inch, 5.95 * inch]
                )
                det_t.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
                    ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE",      (0, 0), (-1, -1), 8),
                    ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
                    ("TOPPADDING",    (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                    ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ]))
                elements.append(KeepTogether([title_p, det_t, Spacer(1, 3 * mm)]))
        return elements

    # ════════════════════════════════════════════════════════════════════════
    #  10. AI SECURITY INTELLIGENCE
    # ════════════════════════════════════════════════════════════════════════
    def _create_ai_analysis(self, ai_report: Dict) -> List:
        elements: List = []
        elements.append(Paragraph("9.  AI Security Intelligence",
                                  self.styles["SectionHdr"]))
        elements.append(self._section_rule())
        elements.append(Paragraph(
            "The following section was produced by the FalconScan AI Security Engine. "
            "It synthesises all scan findings into business-contextual risk assessments, "
            "MITRE ATT&CK\u00ae mappings, threat actor profiling, and a prioritised "
            "remediation roadmap. AI outputs should be reviewed alongside raw findings.",
            self.styles["Body"]
        ))
        elements.append(Spacer(1, 4 * mm))

        # 9.1 Executive Summary
        if ai_report.get("executive_summary"):
            elements.append(Paragraph("9.1  Executive Summary", self.styles["SubHdr"]))
            elements.append(Paragraph(ai_report["executive_summary"],
                                      self.styles["Body"]))
            elements.append(Spacer(1, 4 * mm))

        # 9.2 Overall Risk Assessment
        if ai_report.get("overall_risk_assessment"):
            elements.append(Paragraph("9.2  Overall Risk Assessment",
                                      self.styles["SubHdr"]))
            elements.append(Paragraph(ai_report["overall_risk_assessment"],
                                      self.styles["Body"]))
            elements.append(Spacer(1, 4 * mm))

        # 9.3 Business Impact
        if ai_report.get("business_impact"):
            elements.append(Paragraph("9.3  Business Impact", self.styles["SubHdr"]))
            biz_t = Table(
                [[Paragraph(ai_report["business_impact"], self.styles["Body"])]],
                colWidths=[7.0 * inch]
            )
            biz_t.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
                ("BOX",           (0, 0), (-1, -1), 1.5, _SEV["medium"]),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))
            elements.append(biz_t)
            elements.append(Spacer(1, 4 * mm))

        # 9.4 Risk Breakdown
        rb = ai_report.get("risk_breakdown", {})
        if rb:
            elements.append(Paragraph("9.4  Risk Breakdown by Category",
                                      self.styles["SubHdr"]))
            rb_rows = [["Category", "Score (0\u2013100)", "Level"]]
            for cat, score in rb.items():
                try:
                    s = int(score)
                except (TypeError, ValueError):
                    s = 0
                level = ("Critical" if s >= 80 else "High"   if s >= 60 else
                         "Medium"   if s >= 40 else "Low"    if s >= 20 else "Safe")
                rb_rows.append([cat.replace("_", " ").title(), str(s), level])
            t = Table(rb_rows, colWidths=[2.5 * inch, 1.5 * inch, 1.5 * inch])
            lmap = {"Critical": _SEV["critical"], "High": _SEV["high"],
                    "Medium": _SEV["medium"],     "Low": _SEV["low"],
                    "Safe":   _SEV["safe"]}
            sty = TableStyle([
                ("BACKGROUND",    (0, 0), (-1,  0), PRIMARY),
                ("TEXTCOLOR",     (0, 0), (-1,  0), WHITE),
                ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, ROW_ALT]),
                ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("ALIGN",         (1, 0), (2, -1),  "CENTER"),
            ])
            for i, row in enumerate(rb_rows[1:], 1):
                c = lmap.get(row[2])
                if c:
                    sty.add("TEXTCOLOR", (2, i), (2, i), c)
                    sty.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")
            t.setStyle(sty)
            elements.append(t)
            elements.append(Spacer(1, 4 * mm))

        # 9.5 Attack Surface
        atk_surf = ai_report.get("attack_surface", [])
        if atk_surf:
            elements.append(Paragraph("9.5  Attack Surface Analysis",
                                      self.styles["SubHdr"]))
            as_rows = [["Category", "Exposed", "Severity", "Description"]]
            for item in atk_surf:
                as_rows.append([
                    item.get("category", ""),
                    "Yes" if item.get("exposed") else "No",
                    (item.get("severity") or "safe").upper(),
                    self._trunc(item.get("description", ""), 120),
                ])
            t = Table(as_rows,
                      colWidths=[1.6*inch, 0.65*inch, 0.9*inch, 3.65*inch])
            sty = TableStyle([
                ("BACKGROUND",    (0, 0), (-1,  0), PRIMARY),
                ("TEXTCOLOR",     (0, 0), (-1,  0), WHITE),
                ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, ROW_ALT]),
                ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ])
            for i, item in enumerate(atk_surf, 1):
                sev = (item.get("severity") or "safe").lower()
                exp = item.get("exposed", False)
                sty.add("TEXTCOLOR", (2, i), (2, i),
                        self._sev_color(sev if exp else "safe"))
                sty.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")
                sty.add("TEXTCOLOR", (1, i), (1, i),
                        _SEV["high"] if exp else _SEV["safe"])
            t.setStyle(sty)
            elements.append(t)
            elements.append(Spacer(1, 4 * mm))

        # 9.6 MITRE ATT&CK
        mitre = ai_report.get("mitre_techniques", [])
        if mitre:
            elements.append(Paragraph(
                "9.6  MITRE ATT&CK\u00ae Mobile Techniques",
                self.styles["SubHdr"]))
            m_rows = [["Technique ID", "Name", "Tactic", "Relevance to Findings"]]
            for tech in mitre:
                m_rows.append([
                    tech.get("id", ""),
                    tech.get("name", ""),
                    tech.get("tactic", ""),
                    self._trunc(tech.get("relevance", ""), 130),
                ])
            t = Table(m_rows, colWidths=[0.85*inch, 1.55*inch, 1.3*inch, 3.1*inch])
            t.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1,  0), PRIMARY),
                ("TEXTCOLOR",     (0, 0), (-1,  0), WHITE),
                ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, ROW_ALT]),
                ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("FONTNAME",      (0, 1), (0, -1),  "Courier"),
                ("TEXTCOLOR",     (0, 1), (0, -1),  PRIMARY_L),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 4 * mm))

        # 9.7 Threat Intelligence
        ti = ai_report.get("threat_intel", {})
        if ti:
            elements.append(Paragraph("9.7  Threat Intelligence Profile",
                                      self.styles["SubHdr"]))
            likelihood = (ti.get("attack_likelihood") or "").upper()
            elements.append(self._kv_table([
                ["Actor Profile",    ti.get("actor_profile", "N/A")],
                ["Attack Likelihood", likelihood or "N/A"],
                ["Primary Motivation", ti.get("motivation", "N/A")],
                ["IoC Patterns",
                 ", ".join(ti.get("ioc_patterns", [])) or "None identified"],
            ]))
            elements.append(Spacer(1, 4 * mm))

        # 9.8 Attack Scenario
        scenario = ai_report.get("attack_scenario", "")
        if scenario:
            elements.append(Paragraph("9.8  Attack Scenario", self.styles["SubHdr"]))
            elements.append(Paragraph(
                "<i>A realistic multi-step exploitation chain based on identified findings:</i>",
                self.styles["BodySmall"]
            ))
            elements.append(Spacer(1, 2 * mm))
            for line in scenario.split("\n"):
                line = line.strip()
                if line:
                    elements.append(Paragraph(line, self.styles["Body"]))
            elements.append(Spacer(1, 4 * mm))

        # 9.9 AI Severity Re-Assessment
        re_scored = ai_report.get("re_scored_findings", [])
        if re_scored:
            elements.append(Paragraph("9.9  AI Severity Re-Assessment",
                                      self.styles["SubHdr"]))
            elements.append(Paragraph(
                "The AI engine recommends the following severity adjustments based on "
                "context, exploitability, and chained attack potential.",
                self.styles["Body"]
            ))
            elements.append(Spacer(1, 2 * mm))
            rs_rows = [["Finding Title", "Reported", "AI Assessment", "Rationale"]]
            for item in re_scored:
                rs_rows.append([
                    self._trunc(item.get("title", "N/A"), 44),
                    (item.get("original_severity") or "N/A").upper(),
                    (item.get("ai_severity")       or "N/A").upper(),
                    self._trunc(item.get("reason", ""), 105),
                ])
            t = Table(rs_rows, colWidths=[2.3*inch, 0.9*inch, 1.0*inch, 2.6*inch])
            sty = TableStyle([
                ("BACKGROUND",    (0, 0), (-1,  0), PRIMARY),
                ("TEXTCOLOR",     (0, 0), (-1,  0), WHITE),
                ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, ROW_ALT]),
                ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ])
            for i, item in enumerate(re_scored, 1):
                c = self._sev_color((item.get("ai_severity") or "info").lower())
                sty.add("TEXTCOLOR", (2, i), (2, i), c)
                sty.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")
            t.setStyle(sty)
            elements.append(t)
            elements.append(Spacer(1, 4 * mm))

        # 9.10 Detailed Finding Analyses
        fa_list = ai_report.get("finding_analyses", [])
        if fa_list:
            elements.append(Paragraph("9.10  Detailed Finding Analysis",
                                      self.styles["SubHdr"]))
            for idx, fa in enumerate(fa_list, 1):
                title = fa.get("title", "Unknown")
                sev   = (fa.get("severity") or "info").lower()
                rows  = []
                if fa.get("technical_analysis"):
                    rows.append(["Technical Analysis",
                                 self._trunc(fa["technical_analysis"], 320)])
                if fa.get("attack_vector"):
                    rows.append(["Attack Vector",
                                 self._trunc(fa["attack_vector"], 200)])
                if fa.get("code_fix"):
                    rows.append(["Recommended Fix",
                                 self._trunc(fa["code_fix"], 320)])

                title_p = Paragraph(
                    f"<b>{idx}. {title}</b>  "
                    f"[{(fa.get('severity') or 'INFO').upper()}]",
                    ParagraphStyle("_fah", fontSize=9,
                                   textColor=self._sev_color(sev),
                                   fontName="Helvetica-Bold",
                                   backColor=self._sev_bg(sev),
                                   spaceAfter=1)
                )
                if rows:
                    det_t = Table(
                        [[Paragraph(f"<b>{r[0]}</b>", self.styles["BodySmall"]),
                          Paragraph(r[1], self.styles["BodySmall"])]
                         for r in rows],
                        colWidths=[1.35 * inch, 5.65 * inch]
                    )
                    det_t.setStyle(TableStyle([
                        ("BACKGROUND",    (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
                        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE",      (0, 0), (-1, -1), 8),
                        ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
                        ("TOPPADDING",    (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                    ]))
                    elements.append(KeepTogether([title_p, det_t, Spacer(1, 3 * mm)]))
                else:
                    elements.append(title_p)
                    elements.append(Spacer(1, 3 * mm))

        # 9.11 Remediation Roadmap
        roadmap = ai_report.get("remediation_roadmap", [])
        if roadmap:
            elements.append(Paragraph("9.11  Remediation Roadmap",
                                      self.styles["SubHdr"]))
            p_labels = {1: "P1 \u2014 Urgent", 2: "P2 \u2014 Important",
                        3: "P3 \u2014 Improve"}
            rm_rows = [["Priority", "Action", "Effort", "Impact", "Category"]]
            for item in sorted(roadmap, key=lambda x: x.get("priority", 3)):
                p = item.get("priority", 3)
                rm_rows.append([
                    p_labels.get(p, f"P{p}"),
                    self._trunc(item.get("action", ""), 95),
                    (item.get("effort") or "").capitalize(),
                    (item.get("impact") or "").capitalize(),
                    item.get("category", ""),
                ])
            t = Table(rm_rows,
                      colWidths=[0.95*inch, 3.35*inch, 0.75*inch, 0.75*inch, 0.95*inch])
            p_cols = {1: _SEV["critical"], 2: _SEV["high"], 3: _SEV["medium"]}
            sty = TableStyle([
                ("BACKGROUND",    (0, 0), (-1,  0), PRIMARY),
                ("TEXTCOLOR",     (0, 0), (-1,  0), WHITE),
                ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, ROW_ALT]),
                ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ])
            for i, item in enumerate(
                    sorted(roadmap, key=lambda x: x.get("priority", 3)), 1):
                c = p_cols.get(item.get("priority", 3), _SEV["medium"])
                sty.add("TEXTCOLOR", (0, i), (0, i), c)
                sty.add("FONTNAME",  (0, i), (0, i), "Helvetica-Bold")
            t.setStyle(sty)
            elements.append(t)
            elements.append(Spacer(1, 4 * mm))

        # 9.12 Top Priority Recommendations
        top_recs = ai_report.get("top_recommendations", [])
        if top_recs:
            elements.append(Paragraph("9.12  Top Priority Recommendations",
                                      self.styles["SubHdr"]))
            for idx, rec in enumerate(top_recs, 1):
                elements.append(Paragraph(f"<b>{idx}.</b>  {rec}",
                                          self.styles["Body"]))
                elements.append(Spacer(1, 2 * mm))
            elements.append(Spacer(1, 2 * mm))

        # 9.13 Compliance Impact
        if ai_report.get("compliance_impact"):
            elements.append(Paragraph("9.13  Compliance & Regulatory Impact",
                                      self.styles["SubHdr"]))
            elements.append(Paragraph(ai_report["compliance_impact"],
                                      self.styles["Body"]))
            elements.append(Spacer(1, 4 * mm))

        if ai_report.get("_model_used"):
            elements.append(Paragraph(
                f"<i>AI analysis: {ai_report['_model_used']}</i>",
                ParagraphStyle("_fn", fontSize=7, textColor=MUTED)
            ))
        return elements

    # ════════════════════════════════════════════════════════════════════════
    #  11. OWASP MOBILE TOP 10 COVERAGE
    # ════════════════════════════════════════════════════════════════════════
    def _create_owasp_coverage(self, vulnerabilities: List[Dict],
                                ai_report=None) -> List:
        elements: List = []
        elements.append(Paragraph("10.  OWASP Mobile Top 10 (2024) Coverage",
                                  self.styles["SectionHdr"]))
        elements.append(self._section_rule())
        elements.append(Paragraph(
            "The table below maps identified findings to the OWASP Mobile Application "
            "Security Verification Standard (MASVS) and OWASP Mobile Top 10 (2024). "
            "Categories marked \u26a0 Affected contain at least one confirmed finding.",
            self.styles["Body"]
        ))
        elements.append(Spacer(1, 3 * mm))

        covered: set = set()
        for v in vulnerabilities:
            for part in (v.get("owasp", "") or "").replace(",", " ").split():
                for key in OWASP_MOBILE_TOP10:
                    if key.upper() in part.upper():
                        covered.add(key)

        rows = [["ID", "Category", "Status", "Count"]]
        for mid, mname in OWASP_MOBILE_TOP10.items():
            is_aff = mid in covered
            count  = sum(1 for v in vulnerabilities
                         if mid.upper() in (v.get("owasp", "") or "").upper())
            rows.append([
                mid,
                mname,
                "\u26a0 Affected"    if is_aff else "\u2713 Not detected",
                str(count) if count > 0 else "\u2014",
            ])

        t = Table(rows, colWidths=[0.52*inch, 2.7*inch, 1.4*inch, 0.7*inch])
        sty = TableStyle([
            ("BACKGROUND",    (0, 0), (-1,  0), PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1,  0), WHITE),
            ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, ROW_ALT]),
            ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("FONTNAME",      (0, 1), (0, -1),  "Courier-Bold"),
            ("TEXTCOLOR",     (0, 1), (0, -1),  PRIMARY_L),
            ("ALIGN",         (3, 0), (3, -1),  "CENTER"),
        ])
        for i, row in enumerate(rows[1:], 1):
            is_aff = row[2].startswith("\u26a0")
            sty.add("TEXTCOLOR", (2, i), (2, i),
                    _SEV["high"] if is_aff else _SEV["safe"])
            sty.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")
        t.setStyle(sty)
        elements.append(t)
        return elements

    # ════════════════════════════════════════════════════════════════════════
    #  12. SECURITY RECOMMENDATIONS
    # ════════════════════════════════════════════════════════════════════════
    def _create_recommendations(self, vulnerabilities: List[Dict],
                                  scan_data: Dict, ai_report=None) -> List:
        elements: List = []
        elements.append(Paragraph("11.  Security Recommendations",
                                  self.styles["SectionHdr"]))
        elements.append(self._section_rule())

        crit_cnt = len([v for v in vulnerabilities if v.get("severity") == "critical"])
        high_cnt = len([v for v in vulnerabilities if v.get("severity") == "high"])

        recs = []
        if crit_cnt:
            recs.append(
                f'<b><font color="#dc2626">IMMEDIATE ACTION REQUIRED:</font></b>  '
                f'{crit_cnt} critical vulnerability/vulnerabilities must be resolved '
                "before the application is deployed to production. Each critical finding "
                "represents a directly exploitable risk to user data or application integrity."
            )
        if high_cnt:
            recs.append(
                f'<b><font color="#ea580c">HIGH PRIORITY:</font></b>  '
                f'{high_cnt} high-severity issue(s) should be addressed in the '
                "current or next development sprint."
            )
        recs += [
            "<b>Secrets Management:</b>  Remove all hardcoded credentials, API keys, and "
            "tokens from source code. Use Android Keystore or a server-side vault.",

            "<b>Network Security:</b>  Enforce TLS 1.2+ for all connections. Deploy a "
            "Network Security Configuration (NSC) file explicitly blocking cleartext. "
            "Implement certificate pinning for backend API calls.",

            "<b>Data at Rest:</b>  Encrypt sensitive files using EncryptedFile / "
            "EncryptedSharedPreferences. Set android:allowBackup=\"false\" or define "
            "explicit backup rules.",

            "<b>Authentication:</b>  Enforce multi-factor authentication. Use "
            "BiometricPrompt for biometric flows. Validate tokens server-side on every "
            "request.",

            "<b>Cryptography:</b>  Replace deprecated algorithms (DES, RC4, MD5, SHA-1) "
            "with AES-256-GCM and SHA-256. Use SecureRandom for all IVs and salts.",

            "<b>Component Exposure:</b>  Set android:exported=\"false\" on all components "
            "not intended for inter-process communication. Add explicit permission checks "
            "to exported components.",

            "<b>Input Validation:</b>  Sanitise all user and IPC inputs. Use parameterised "
            "queries for SQLite. Validate deep-link and Intent extras before processing.",

            "<b>Binary Protections:</b>  Enable ProGuard/R8 obfuscation. Implement root, "
            "debug, and emulator detection before security-sensitive operations.",

            "<b>Dependency Management:</b>  Audit dependencies for known CVEs. Pin versions "
            "in Gradle and subscribe to security advisories.",

            "<b>Secure SDLC:</b>  Integrate SAST/DAST into CI/CD pipelines. Conduct threat "
            "modelling at design time. Schedule annual penetration tests.",
        ]

        for idx, rec in enumerate(recs, 1):
            elements.append(Paragraph(f"<b>{idx}.</b>  {rec}", self.styles["Body"]))
            elements.append(Spacer(1, 2 * mm))

        # Footer
        elements.append(Spacer(1, 8 * mm))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
        elements.append(Spacer(1, 3 * mm))
        elements.append(Paragraph(
            f"<i>Report generated by FalconScan Advanced APK Security Platform on "
            f"{datetime.now().strftime('%d %B %Y at %H:%M UTC')}. "
            "This report is confidential and intended solely for the development and "
            "security teams of the assessed organisation. "
            "Redistribution without written consent is prohibited.</i>",
            ParagraphStyle("_disc2", fontSize=7, textColor=MUTED,
                           alignment=TA_CENTER, leading=10)
        ))
        return elements

    # ── Legacy compatibility aliases ──────────────────────────────────────────
    def _create_header(self, scan_data: Dict) -> List:
        return self._create_cover(scan_data, [])

    def _create_static_analysis_summary(self, static_analysis: Dict) -> List:
        return self._create_static_analysis(static_analysis or {})

    def _create_dynamic_analysis_summary(self, dynamic_analysis: Dict) -> List:
        return self._create_dynamic_analysis(dynamic_analysis or {})
