# FalconScan Project Guide

## Purpose and Scope

FalconScan is a web application for uploading Android APK files, running security checks, saving scan results, and viewing interactive or PDF reports. The application consists of a Next.js frontend and a Django REST Framework backend.

This guide describes behavior found in the repository. It distinguishes implemented behavior from partial, optional, or mock UI. Security findings are produced by automated heuristics and must be reviewed by a qualified analyst; this tool is not a substitute for a complete security assessment.

## Architecture

- **Frontend:** Next.js App Router, React, TypeScript, Tailwind CSS, Axios, and Recharts. Routes and pages are under `app/`; shared UI components are under `components/`; API calls are centralized in `lib/api.ts`.
- **Backend:** Django 4.2 and Django REST Framework. Authentication and user endpoints are in `backend/apps/accounts/`; scan processing and report endpoints are in `backend/apps/scans/`.
- **Persistence:** SQLite by default. PostgreSQL can be selected with `DATABASE_URL`.
- **Analysis:** Androguard-based APK inspection, local static artifact extraction, heuristic vulnerability checks, optional ADB runtime analysis, optional component fuzzing, and optional Gemini AI analysis.
- **Reports:** Scan data is returned through the REST API. The backend also stores a generated Report record and attempts to generate a ReportLab PDF.

The module headings in this guide follow `docs/100%_Documentation.pdf`: User Authentication & APK Management, Static Analysis Engine, Fuzzing Engine, Dynamic Analysis Engine, LLM-Driven Vulnerability Analysis, and Reporting & Dashboard UI. Other PDFs use earlier names or combine/split these areas; those documents were compared, but proposed features are not counted as implemented unless the current source code supports them.

## Backend Scan Pipeline

1. **Receive the upload.** `ScanViewSet.upload` validates request fields, reads the uploaded file, calculates MD5 and SHA-256, and looks for an existing scan belonging to that user. The API does not perform a dedicated APK file-signature check.
2. **Save scan metadata.** The Django model stores the APK, its name and size, hashes, user, enabled analysis options, and scan status. Package and version details are read with Androguard when possible.
3. **Start background work.** The API starts `analyze_apk` in a daemon Python thread in the Django process. This is not a durable task queue; a process restart can interrupt work.
4. **Run selected stages.** Static analysis runs by default. Dynamic analysis, component fuzzing, and AI analysis depend on their options and external configuration. The fuzzer also runs its own static checks whenever fuzzing is enabled.
5. **Store findings and summaries.** The task saves findings, permissions, analysis JSON, severity counts, and a heuristic risk score to the database.
6. **Create reports.** The task creates a text/JSON report record and attempts to create a PDF. It marks the scan completed after the analysis stages, even when an optional stage reports its own failure.
7. **Return results to the web app.** The frontend polls the scan API about every two seconds, displays an estimated progress value, then opens the report when the scan finishes.

**Scanner scope:** The active main pipeline is `APKAnalyzer` + `AndroguardDecompiler` + `StaticAnalyzer`, followed by `VulnerabilityScanner`. If enabled, it also calls `DynamicAnalyzer` and `APKFuzzer`. `APKDecompiler` and `YARAScanner` in `decompiler.py` are separate utilities and are not called by this task; their presence in the repository does not mean JADX or YARA is part of a normal scan.

## Setup and Run

Run the backend and frontend in separate PowerShell terminals.

### Backend

```powershell
Set-Location backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

The API is served at `http://localhost:8000`. The Django admin is available at `/admin/` after creating a superuser with `python manage.py createsuperuser`.

### Backend Environment

The backend reads `backend/.env` if it exists. Relevant settings include:

```env
DEBUG=True
DJANGO_SECRET_KEY=replace-for-local-development
ALLOWED_HOSTS=localhost,127.0.0.1
CORS_ALLOWED_ORIGINS=http://localhost:3000
DATABASE_URL=sqlite:///db.sqlite3
GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.0-flash-lite
```

`GEMINI_API_KEY` is needed for Gemini-backed AI reporting. The backend setting is named `GEMINI_API_KEY`; some repository documentation refers to `AI_API_KEY`, which does not match the settings code.

### Frontend

From the repository root, in a second terminal:

```powershell
pnpm install
pnpm dev
```

The frontend is served at `http://localhost:3000`. Set `NEXT_PUBLIC_API_URL=http://localhost:8000/api` in the frontend environment if the API is not at its default URL.

## Module 1: User Authentication & APK Management

1. **Register.** The register form sends username, email, first/last name, password, and confirmation. The backend creates a Django user and related profile; passwords use Django's user creation API.
2. **Sign in.** Username/password login uses SimpleJWT access and refresh tokens. The frontend stores tokens in `localStorage` and sends the access token with API requests.
3. **Open the dashboard.** Scan listing and statistics are filtered to the authenticated user. The dashboard also requests retries for that user's failed scans.
4. **Choose an APK.** The upload page accepts one `.apk` file by picker or drag-and-drop and uses its filename for the app name when that field is blank.
5. **Choose stages.** Static analysis is on by default. Dynamic analysis, fuzzing, and AI analysis are optional. The page displays a 100 MB limit but does not enforce it in the upload handler.
6. **Upload and deduplicate.** The backend calculates MD5 and SHA-256. A matching APK for the same user and options returns the existing scan; changed options clear prior results and re-run that scan record.
7. **Track work.** A daemon thread runs the analysis. The browser polls the scan approximately every two seconds; progress percentages and stage labels are client-side estimates, not backend stage telemetry.
8. **Review and manage.** The report page shows results. Users can list/search/filter scans, download PDFs, request a rescan, cancel a running scan from the upload flow, or delete an individual scan.

**Implemented:** account registration/login, JWT authentication, current-user lookup, limited first/last-name and email updates, single-APK upload, metadata/hashes, user-scoped scan history, per-user duplicate handling, and individual scan deletion.

**Partial:** access is authenticated and scans are user-scoped, but application roles (admin/user/guest) and role-specific actions are not implemented. Upload selection checks the `.apk` filename in the browser; multiple-file upload, server-side size enforcement, and strict APK-signature validation are absent. Archive and tag actions are also absent.

**Not implemented:** guest access, queue position, developer metadata, audit log screens, archive/tag records, email notifications, and multi-file submission.

**Practical feasibility:** The partial account and upload items are feasible with the existing Django models and REST API, but role rules and stronger file validation are not present today. Queueing, audit history, and archive/tag behavior require additional backend data and workflows; they cannot be enabled by the current UI alone.

## Module 2: Static Analysis Engine

Static analysis is the default analysis mode. The code uses Androguard when installed and runs extraction and checks over APK structure, manifest data, DEX/resource strings, and files. Implemented extraction includes:

- App/package/version and Android manifest information, including SDK values and manifest security flags.
- Requested Android permissions and Activities, Services, Receivers, and Content Providers, including exported/permission metadata when parsing succeeds.
- Certificate metadata where the library can extract it.
- APK strings and file inventory.
- URL, domain, IP address, email, file path, Base64-like string, cryptographic key, API key, Firebase, and AWS indicators.
- Interesting string groups for SQL, file, network, cryptography, and debug/logging patterns.

`VulnerabilityScanner` applies local rules to manifest settings, permission names, certificate metadata, exported components, extracted secret/API-key indicators, weak-crypto strings, HTTP URLs, SQL-related strings, file-operation strings, backup settings, logging strings, and cleartext-traffic configuration. These are pattern-based indicators: SQL-related text or an API-key-like string is not proof of an exploitable vulnerability. The analyzer uses Androguard-derived DEX/resource strings and regular expressions; it does not perform general Java source decompilation or full data-flow analysis.

Additional API actions perform on-demand certificate, string, entropy, class/method metadata, native-library, resource, secret-pattern, and obfuscation-indicator inspection. They are not all separate stages in the normal scan task.

**Scanner techniques present in code:** Androguard APK/DEX parsing; ZIP inventory and text/resource extraction; regular-expression and keyword matching; manifest configuration and permission checks; and heuristic severity/risk aggregation. The score uses Critical/High/Medium/Low weights of 25/15/8/3, applies selected risk multipliers, caps at 100, and maps score bands to Safe/Low/Medium/High/Critical. It is a project-specific prioritization score, not calibrated CVSS.

**Partial or inactive scanner utilities:** `APKDecompiler` contains optional apktool/JADX subprocess code, and `YARAScanner` contains sample YARA rules, but neither is called by the active scan task. `decompiled_sources` returns class/method metadata, not Java source. Certificate checks and secret detection are best-effort heuristics and depend on available extracted data.

**Not implemented:** integrated JADX/APKTool source decompilation in the normal scan, a maintained malware-signature/CVE database, full malware classification, reliable de-obfuscation, and static-analysis audit trails.

**Practical feasibility:** Adding a decompiler or signature database is technically possible, but requires installing/configuring and safely invoking that tool or maintaining the data source; the existing utility class alone does not make either feature active. Pattern-based scanning can be extended, but its results still need analyst validation.

### Risk Score

The static risk score begins with severity weights of 25 for Critical, 15 for High, 8 for Medium, and 3 for Low. Multipliers can increase it for many dangerous permissions, debuggable/backup/cleartext manifest settings, cryptography indicators, or hardcoded-secret indicators. The result is capped at 100 and mapped to threat levels as follows:

| Threat level | Score |
| --- | ---: |
| Critical | 80-100 |
| High | 60-79 |
| Medium | 35-59 |
| Low | 15-34 |
| Safe | 0-14 |

When fuzzing findings are added, the task recalculates the score using severity and finding-source weights. The displayed score should be treated as a prioritization signal, not as a formal CVSS score.

## Module 3: Fuzzing Engine (Optional)

`APKFuzzer` checks Activities, Services, Receivers, and Content Providers. `StaticComponentFuzzer` checks manifest exposure and permission guards; Androguard-based APK/DEX heuristics look for risky component flows and code indicators such as Intent-to-SQL/file paths, WebView exposure, weak random/crypto use, and credential-like strings. These checks inspect the APK without executing it. If ADB is available, the fuzzer runs live component probes; when Drozer is also available, it selects the deeper Drozer probes instead of the ADB runtime probe. Runtime payloads include malformed or oversized Intent extras, SQL-style selections, path-traversal strings, deep-link/URI cases, and broadcasts. Results are deduplicated and returned with severity, source, and attack breakdowns plus remediation suggestions.

The reported engine is `falcon-deep` when the Drozer and ADB commands are detected, `falcon-runtime` when the ADB command is detected, or `falcon-static` otherwise. These labels indicate available tools; `falcon-runtime` does not confirm that a device is connected. The manifest stage always runs; DEX checks need an APK path and Androguard; live probes need a connected device, and deep probes need a working Drozer agent. Optional payload mutation is disabled by default and is not enabled by the scan task.

**Partial:** Static exposure checks and DEX heuristics run without a device. Runtime component invocation and crash observation depend on ADB and an attached device; Drozer deep probing was not available for this review. ADB being installed does not mean a device is connected.

**Not implemented:** CFG/DFG-based static fuzz simulation or mutation of arbitrary method parameters/data flows, batch static fuzzing queues, configurable per-scan targets/cycles/input-size limits, grammar-based API/file-handler fuzzing, broad UI-flow fuzzing, persistent crash/stack-trace archives, and correlation with a dynamic-analysis timeline.

**Practical feasibility:** Existing component metadata and payload probes provide a usable base for adding controls and more test cases. Reliable crash evidence and broader API/UI coverage need an attached test device, repeatable app state, and additional runtime instrumentation.

## Module 4: Dynamic Analysis Engine (Optional)

`DynamicAnalyzer` uses ADB to select a connected device or emulator, install and launch the APK, wait, optionally send Android Monkey events, and collect best-effort runtime observations. Depending on device permissions and available tools, it records device/package state, granted permissions, processes, logcat lines, URLs/IPs/keywords, network connections, tcpdump PCAP summaries, memory/network statistics, app-data listings, screenshots, step logs, and errors. It attempts to stop, clear, and uninstall the app afterward.

Dynamic analysis requires the ADB command and an attached Android device or running emulator. Individual collection steps may fail without failing the full scan. The code does not create a snapshot-capable isolated sandbox, control outbound network access, roll back device state, or instrument Binder/system calls/API hooks. Run untrusted APKs only on a disposable, separately isolated test device/emulator.

**Partial:** ADB install/launch, automated events, logcat, network observations, optional tcpdump, screenshots, and cleanup are implemented, but collection is device-dependent and best-effort. A live run on a vivo 1908 (Android 8.1) completed the install/launch, 20-second wait, 50 Monkey events, screenshot, logcat, permission, process, and network-stat stages. App-data access was unavailable, and tcpdump started but could not be stopped or pulled. The analyzer still returned success, so optional-stage failures must be checked in the result details.

**Not implemented:** isolated snapshot/rollback sandbox, controlled networking, complete file/IPC/Binder/system-call instrumentation, reliable native crash/exception tracing, scripted user journeys, and a full behavior timeline.

**Practical feasibility:** More ADB observations and scripted interactions are practical on a managed emulator. Strong isolation, snapshot rollback, Binder/system-call instrumentation, and controlled networking need supporting emulator/instrumentation infrastructure; the existing ADB collector does not provide those guarantees.

## Module 5: LLM-Driven Vulnerability Analysis (Optional)

The backend can request a structured report from Google's Gemini API using `google-genai`. It sends scan metadata, stored findings, permissions, static artifacts, and fuzzing results; the prompt does not include dynamic-analysis results. The response is requested as JSON and may include summaries, risk breakdowns, attack surface, MITRE ATT&CK mappings, scenarios, severity reassessment, finding explanations, remediation actions, and compliance notes. A configured-model-first cascade and rate-limit retry logic are present; successful output is cached on the scan.

**Implemented:** Optional external Gemini-based report generation, JSON parsing, model fallback, cached results, and AI report sections in the web/PDF report when data is available.

**Partial:** Generated text includes severity reassessment and risk summaries, but this is not a trained malware/benign classifier, calibrated confidence system, or model evaluation pipeline. The report page requests AI analysis automatically when its serialized scan has no `ai_report`; because the scan serializer does not include that field, opening a report can request Gemini even if the upload option was off.

**Not implemented:** local model training, benign/malicious labels backed by a classifier, confidence probabilities/intervals, retraining, dataset/model lifecycle, human false-positive feedback, MCP integration, reasoning-trace audit records, and external vulnerability-feed updates.

**Data handling:** Scan information included in the AI prompt is sent to Google's Gemini service when this request runs. Do not use it for sensitive samples unless this data transfer is permitted.

**Practical feasibility:** Structured summaries and explanations are already supported through the Gemini API. Local classification, calibrated confidence, retraining, MCP, and feedback require separate models/data and lifecycle components; they are not switches that can be enabled in the current integration.

## Module 6: Reporting & Dashboard UI

### Interactive Report

The report detail page contains an overall risk score and level, counts for vulnerabilities/permissions/critical findings, and file size. Its tabs and principal sections are:

- **Static Analysis:** severity charts; package/version/SDK/manifest metadata; hashes; certificate and component information; vulnerability list with severity, category, description, source location, and remediation; permissions; and available APK files, strings, URLs, domains, IPs, emails, paths, keys/secrets, Firebase/AWS references, and interesting-string groups.
- **Dynamic Analysis:** runtime status, device and package details, indicators, diagnostics, network capture/servers/connections, logcat, permissions, processes, app-data information, screenshots, analysis steps, and errors when those data exist.
- **Component Fuzzing:** engine, components scanned, finding counts, severity and source breakdowns, attack vectors, component summaries, riskiest components, and recommendations. If fuzzing was disabled, the page offers a rescan route.
- **AI Analysis:** AI summary, business impact, category risk dashboard, interactive attack-surface map, MITRE mapping, threat intelligence profile, attack scenario, severity adjustments, detailed findings/fixes, remediation roadmap, top recommendations, and compliance impact when the AI request succeeds.

The page also supports filtering vulnerability findings, viewing selected APK entries through a file-view endpoint, copying hashes, downloading the PDF, rescanning, and deleting the scan.

### PDF Report

The PDF generator is designed to include a cover page and severity counts, executive summary, application metadata and hashes, certificate and component information, assessment methodology, a severity chart and top 20 findings, vulnerability details and remediation, permission analysis, static artifact inventory, dynamic results, optional AI sections, an OWASP Mobile Top 10 table, and general security recommendations. AI-specific sections are included only if an AI report exists at PDF-generation time.

The report API returns the stored report record and its JSON content, and the frontend has no dedicated JSON or CSV download control. The dashboard has API-backed scan totals and recent scans, but its scans-over-time chart and trend percentages are sample values; its risk chart also uses the safe-app count for the Low category. The Reports page supports individual PDF download and deletion, search, and risk filtering; bulk actions are not wired.

**Implemented:** scan history and report views, API-backed summary counts, severity/risk presentation, individual PDF generation/download, stored report text/JSON, per-finding remediation, optional dynamic/fuzz/AI sections, toast/in-app notifications, individual deletion, and rescan controls.

**Partial:** Dashboard charts include hard-coded sample trends; PDF OWASP mapping depends on finding fields that standard scanner findings may not supply; PDF methodology labels do not reliably prove that an optional stage succeeded. Report progress uses estimated polling rather than stage events.

**Not implemented:** JSON/CSV download controls, dynamic behavior graphs/system-call maps, bulk actions, streamed analysis updates, persisted email notifications, and an audit log UI.

**Practical feasibility:** The report and API foundations are already present for adding exports and richer visualizations. Accurate live charts or progress require backend data/telemetry that the current dashboard and polling API do not provide.

## Main Pages

| Route | Purpose | Current implementation notes |
| --- | --- | --- |
| `/` | Public landing page | Marketing copy and displayed usage/accuracy metrics are static. |
| `/login` | JWT login | Remember-me checkbox does not control token persistence; forgot-password points to a route not present in the listed project. |
| `/register` | Account creation | Password strength is a client-side display; server enforces password length and confirmation. |
| `/dashboard` | Statistics and recent scans | Scan counts are API-backed; trend percentages and scans-over-time series are hard-coded sample values. |
| `/dashboard/upload` | APK upload and progress | Upload, polling, notifications, and cancellation are connected to APIs. |
| `/dashboard/history` | Scan history | API-backed list, search, risk filter, and report link. The overflow menu is not wired. |
| `/dashboard/reports` | Reports table | API-backed list, filtering, PDF download, and deletion. |
| `/dashboard/reports/{id}` | Detailed report | Reads scan data and offers static/dynamic/fuzzing/AI tabs and scan actions. |
| `/dashboard/profile` | Profile view/edit | First and last name updates are connected; several displayed profile/security controls are not. |
| `/dashboard/settings` | Preference and integration UI | Most controls are local state only; Save displays a toast but does not persist these settings. |
| `/dashboard/documentation` | In-app documentation | Fetches and renders the root `DOCUMENTATION.md` file. |

## API Surface

All scan endpoints and most account endpoints require a JWT bearer token. The route set is defined in `backend/falconscan_backend/urls.py`, `backend/apps/accounts/urls.py`, and `backend/apps/scans/urls.py`.

| Endpoint | Purpose |
| --- | --- |
| `POST /api/accounts/users/register/` | Register a user and return JWTs. |
| `POST /api/token/` | Obtain access and refresh JWTs. |
| `POST /api/token/refresh/` | Refresh an access token. |
| `GET /api/accounts/users/me/` | Get current user. |
| `PATCH /api/accounts/users/update_profile/` | Update supported Django user fields. |
| `GET /api/scans/` | List scans for the current user. |
| `POST /api/scans/upload/` | Upload an APK and start or reuse a scan. |
| `GET /api/scans/{id}/` | Get scan metadata, findings, and analysis JSON. |
| `GET /api/scans/{id}/status/` | Get scan status and summary counters. |
| `GET /api/scans/{id}/report/` | Get the stored report record, or a processing response. |
| `GET /api/scans/statistics/` | Get user scan and threat counts. |
| `POST /api/scans/{id}/rescan/` | Clear previous results and rerun the scan. |
| `POST /api/scans/{id}/cancel_scan/` | Request cancellation of a pending/running scan. |
| `POST /api/scans/cleanup_failed/` | Retry failed scans for the current user. |
| `GET /api/scans/{id}/download_pdf/` | Download the generated PDF. |
| `GET /api/scans/{id}/view-file/?path=...` | Read a text/XML entry from the stored APK. |
| `POST /api/scans/{id}/ai_analysis/` | Generate or retrieve the cached AI report. `?force=true` regenerates it. |
| `GET /api/scans/{id}/certificate_info/`, `strings_extraction/`, `entropy_analysis/`, `decompiled_sources/`, `native_libraries/`, `resource_analysis/`, `hardcoded_secrets/`, `code_obfuscation/` | Additional on-demand APK inspection endpoints. |
| `DELETE /api/scans/{id}/` | Delete a scan and associated stored files. |

The API client includes a refresh-token endpoint but does not install an automatic refresh-and-retry interceptor. The UI primarily stores/uses the access token.

## Incomplete, Mock, or Misleading Areas

- **Dashboard charts:** The scans-over-time line chart and trend percentages are hard-coded. Risk distribution is only partly live, and the UI uses safe-app counts as the Low category.
- **Settings:** Theme, notification, upload-size, API key, webhooks, and third-party integration controls are not persisted or connected to functional backend integrations. The API key shown is a placeholder.
- **Profile:** Name updates work. Avatar upload, phone/organization/job title persistence, password change, 2FA, and email preference persistence are not implemented in the connected flow. Both profile scan counters currently use the same total-scan value.
- **File/decompiler view:** `decompiled_sources` provides class/method metadata; the report viewer reads entries from the APK archive as text/XML. Actual Java-source decompilation is not wired into the displayed feature.
- **Scan status UX:** Upload progress is estimated from polling attempts, not backend stage progress. A report opened during processing does not establish the same continuous status poll. Rescan refreshes once after a delay rather than tracking the full rescan.
- **Analysis combinations:** The task exits early if both static and dynamic analysis are disabled, before creating the normal report. The UI currently defaults static analysis on, but API callers can submit other combinations.
- **OWASP PDF mapping:** The PDF mapping depends on each finding carrying an `owasp` field. The standard scanner findings do not supply that field, so static findings may not map to affected OWASP rows.
- **PDF methodology statuses:** The methodology table labels fuzzing completed unconditionally. Dynamic status is based on whether a result object exists, not whether the dynamic run succeeded. Treat those labels cautiously.
- **AI controls and PDF timing:** The scan serializer omits `ai_report`, while the report page auto-requests AI when that field is absent. Consequently, opening a report can invoke AI even when the upload option was off. AI generated after the PDF was created is not automatically inserted into that existing PDF.
- **Documentation drift:** Some docs list `AI_API_KEY` and an AI endpoint that do not match the backend's `GEMINI_API_KEY` setting and per-scan `ai_analysis` route. Setup and deployment instructions should be checked against code and the actual environment.
- **Background processing:** Scans execute in daemon threads in the Django process rather than a durable task queue. This is simple for local development, but tasks can be interrupted by process restarts and are not a reliable production job system.
- **Test coverage:** The repository includes a fuzzer test script at `backend/test_fuzzer.py`; no broad Django app test suite was found during this review.

## Comparison with `docs/100%_Documentation.pdf`

The PDF is a 119-page academic project report. It includes project vision, requirements, mockups, architecture, methodology, test-result tables, and future work. Its proposed requirements and narrative test results should not automatically be read as features present in this code checkout. The following comparison is based on the current source tree.

### PDF Claims Confirmed by Code

- **Web application and API:** A Next.js UI communicates with Django REST APIs; JWT login/registration, current-user retrieval, scan records, history/report pages, scan status, and scan-specific API access are present.
- **APK metadata and duplicate handling:** The backend computes MD5/SHA-256, stores filename/size/package/version metadata, and deduplicates per user and hash. It reuses an identical-option scan and reruns an existing record when analysis options differ.
- **Static APK inspection:** Androguard-based parsing and local rules inspect manifest fields, permissions, component exposure, certificate-related information, strings, URLs/domains/IPs/emails, paths, API-key/secret-like patterns, crypto indicators, and APK inventory. Results and findings are persisted and returned to the frontend.
- **Risk prioritization:** Severity-weighted scoring, threat levels, severity counts, dashboard statistics, report charts, and findings ordered by severity are implemented. This is the project's own heuristic score, not an implementation of calibrated CVSS 3.1 scoring.
- **Optional dynamic analysis:** The ADB analyzer can install and launch an APK and gather runtime logs, indicators, device/package data, screenshots, network-capture information, and other diagnostics when a usable ADB target is configured. The source accepts an ADB-connected device or emulator; it is not limited in code to AVDs.
- **Component fuzzing:** Static manifest/code checks and crafted component/intent inputs are present. Runtime probing depends on ADB, and deeper probing depends on optional Drozer availability. Fuzzing results can be added to the scan findings and displayed in the report.
- **Gemini-assisted reporting:** The backend builds a structured prompt, requests JSON-shaped security intelligence, has model fallback handling, and caches the result. The report UI can display summaries, risk breakdowns, attack surface, MITRE mapping, attack scenarios, recommendations, and other returned fields.
- **Report generation and scan management:** A PDF generator, a stored JSON/report record, PDF download, scan rescan, scan cancellation, and scan deletion are implemented. Notifications shown by the frontend are in-app notifications, not the email service described in the PDF.

### PDF Requirements or Claims Not Implemented

| PDF feature or claim | Current code status |
| --- | --- |
| Admin, analyst, assignee, standard-user, and guest roles with role-specific dashboards | No application role model or role-based frontend flows were found. Scan APIs require authentication and filter scans to the requesting user; Django's built-in admin exists separately. |
| Login by email, CAPTCHA, lockout after five failures, OTP/password recovery, and role redirect | The login form/API uses username and password. No CAPTCHA, failed-login lockout, OTP/password-reset flow, or role-based routing is wired. |
| Multiple APK selection, 200 MB enforcement, server-side file-signature validation, developer/category metadata, upload shortcuts, and queue position | The UI submits one file, checks its `.apk` extension in the browser, and displays a 100 MB limit without enforcing it here. The backend hashes and attempts to parse the file but has no upload queue or queue-position reporting. |
| Static and dynamic analysis automatically enabled for every upload | Static analysis defaults on; dynamic analysis, fuzzing, and AI default off in the UI. ADB runtime analysis must be opted into and configured. |
| JADX/APKTool Java or Smali decompilation and code snippets linked to findings | The active analyzer uses Androguard and archive/string inspection. The report file viewer reads APK entries as text/XML, and the `decompiled_sources` endpoint returns class/method metadata; actual JADX/APKTool source decompilation and code-snippet linking were not found. |
| Full system-call, Binder, API-hook, file-monitor, sandbox snapshot/rollback, and controlled-network instrumentation | The ADB analyzer gathers device/runtime/log/network observations and can capture PCAP-related data, but the source does not provide the PDF's full instrumentation or an isolated, snapshot-capable sandbox with network controls. |
| Fuzzing configuration for input size, execution cycles, and target components | The upload UI exposes an enable/disable option, not those advanced per-scan controls. Fuzzer internals contain fixed/configured defaults. |
| Locally trained ML classifier, malware/benign predictions, confidence percentages, confidence calibration, model registry, retraining, human feedback, or stored reasoning traces | No local model training or classifier lifecycle was found. AI calls an external Gemini service and returns generated report fields; the prompt schema does not request per-finding confidence scores, and no feedback/retraining workflow is connected. |
| Local vulnerability database, external vulnerability-feed updates, or continuous learning from scans | Findings are generated by in-code heuristics and stored per scan. No separate CVE/vulnerability knowledge-base or update pipeline was found. |
| CSV export, frontend JSON export, bulk actions, scan archive/tag, date/result filters, or bulk deletion | PDF download and an API report endpoint exist. There is no CSV exporter or JSON download control in the frontend. Lists support limited text/risk filtering, individual deletion, and individual rescans; archive/tag/bulk features are absent. |
| False-positive marking, verification workflow, or AI confidence display | The report page has no finding feedback controls or confidence field display. |
| Dynamic behavior timeline and streamed/incremental findings during analysis | Dynamic data and step logs can be displayed after retrieval, but there is no dedicated behavior timeline or streamed finding updates. Upload progress is estimated from polling attempts. |
| Email completion notifications, SMTP, or seven-day notification retention | The UI has in-app notifications and toast messages. No email delivery or persisted notification-retention service was found. |
| WebSockets, model-management/admin analytics UI, user management UI, audit log screens, or concurrent scan queue | These are not present in the inspected frontend/backend workflows. Scans are started in daemon threads within the Django process rather than a durable job queue. |
| Rate limiting, account lockout, encrypted-at-rest storage, immutable audit trails, and guaranteed HTTPS/TLS 1.3 | JWT authentication, CORS configuration, Django ORM use, and user-scoped scan access are present. The specific controls above were not found as implemented application features; HTTPS and storage encryption need deployment-level configuration/hardening. |

### PDF Testing Claims

The PDF includes unit, functional, business-rule, and integration test tables marked as passing, including email notifications and role-based login scenarios. The current repository does not contain the described broad pytest/Django test suite or matching email/role implementations. The checked-in `backend/test_fuzzer.py` is a standalone component-fuzzer script with assertions; the PDF's reported test results should therefore be treated as report claims, not as evidence that those tests can be rerun against this checkout.

### Practical Corrections to the PDF's Run-Time Description

- The upload page's displayed maximum is 100 MB, not the PDF's 200 MB, and the page does not enforce the displayed maximum itself.
- AI analysis is an optional Gemini API call. Scan content included in its prompt is sent to Google's service; it is not a local ML model and no internal training process runs.
- The UI's completion/progress behavior uses polling and in-app notifications. There is no documented email notification or true stage-by-stage backend progress stream.
- Dynamic analysis operates through ADB and can use a connected device or emulator. Use an isolated emulator for untrusted APKs; the application code does not itself guarantee the PDF's claimed sandbox isolation.
- The PDF's statement that all planned modules are fully implemented is broader than the current code supports. Use the confirmed-feature list and the gaps above as the implementation status for this repository.

## Operational and Security Notes

- Keep `DEBUG=True` only for local development. Set a production secret key, restricted `ALLOWED_HOSTS`, correct CORS origins, HTTPS, and a production database before deployment.
- Dynamic analysis installs and runs the submitted APK on the selected Android device/emulator. Use a disposable isolated emulator, not a personal or production device.
- Gemini AI analysis sends its constructed scan prompt to Google's Gemini API. Configure the key and enable this only when the data transfer is permitted.
- Risk scores and static string matches can include false positives and false negatives. Validate findings and exploitability independently.
- APKs, PDF reports, screenshots, and possible PCAP captures may be stored under backend media paths. Plan access controls, retention, and cleanup for any deployment handling sensitive samples.

## Key Implementation Files

- Frontend upload: `app/dashboard/upload/page.tsx`
- Frontend report list/detail: `app/dashboard/reports/page.tsx`, `app/dashboard/reports/[id]/page.tsx`
- Frontend API client: `lib/api.ts`
- Scan API and task pipeline: `backend/apps/scans/views.py`, `backend/apps/scans/tasks.py`
- APK analyzer and artifact extraction: `backend/apps/scans/analyzer.py`, `backend/apps/scans/decompiler_androguard.py`, `backend/apps/scans/static_analyzer.py`
- Vulnerability checks: `backend/apps/scans/vulnerability_scanner.py`
- Dynamic analysis and fuzzing: `backend/apps/scans/dynamic_analyzer.py`, `backend/apps/scans/apk_fuzzer.py`
- AI and PDF generation: `backend/apps/scans/ai_analyzer.py`, `backend/apps/scans/pdf_generator.py`
- Models and API serialization: `backend/apps/scans/models.py`, `backend/apps/scans/serializers.py`
- Authentication: `backend/apps/accounts/views.py`, `backend/apps/accounts/serializers.py`

## Backend Verification in This Workspace

- Python syntax parsing completed successfully for the backend source and scripts.
- `backend/test_fuzzer.py` completed all six standalone checks successfully. These use example component data and do not exercise a real APK or connected device.
- Django `manage.py check` and `manage.py test` could not start: the existing `.venv` has Django 4.2.7, but is missing `dj_database_url`, which is imported by the settings module. No packages were installed for this review.
- A live dynamic-analysis run on the connected vivo 1908 (Android 8.1) installed and launched the selected APK, sent 50 Monkey events, collected 4,087 logcat lines and one screenshot, and read runtime permissions/process/network statistics. It returned two heuristic findings: public IP connections observed and many granted dangerous permissions. These are signals for review, not confirmed vulnerabilities. App-data access failed and the tcpdump capture could not be stopped/pulled; the analyzer nevertheless returned success. The app's data was cleared and it was uninstalled successfully. ADB runtime fuzzing was not run.
- The cleanup, seed-reproduction, and other data-changing utility scripts were not run. No end-to-end Django scan/report pipeline was run because Django settings cannot load without the missing `dj_database_url` dependency in the existing `.venv`.

**Feasibility note:** The partial items with existing models, endpoints, or scanner stages are practically extendable, but need implementation and validation beyond the current code. Features requiring device isolation/instrumentation, trained datasets, external feeds, or durable job processing also require those supporting systems; they are not provided by the current repository.

## Final Module Status

This summary uses the six module names from `docs/100%_Documentation.pdf`. “Implemented” means there is an active code path for the behavior; optional stages still require their stated tools or configuration. “Partial” means a narrower or best-effort version exists. “Not implemented” means the requested behavior was not found in the active application flow.

| Module | Implemented | Partially implemented | Not implemented |
| --- | --- | --- | --- |
| **1. User Authentication & APK Management** | Registration/login, SimpleJWT tokens, current-user lookup, limited first/last-name and email updates, one-APK upload, stored metadata and hashes, user-scoped scan list, same-user duplicate handling, individual scan delete. | Authenticated user isolation exists but there are no application roles; extension validation is client-side and the displayed size limit is not enforced by the upload page. | Guest/role-based access, multi-file uploads, queue position, server-side APK signature/size enforcement in this flow, archive/tags, audit history, email notifications. |
| **2. Static Analysis Engine** | Androguard APK/DEX/manifest parsing, permission/component/certificate extraction, APK file and string/artifact extraction, regex/keyword security rules, heuristic risk scoring, on-demand inspection endpoints. | Checks depend on successfully extracted artifacts and are heuristic; apktool/JADX and YARA utilities exist but are not called by the main task; class metadata is not decompiled source. | Integrated JADX/APKTool source scanning in the normal task, maintained malware/CVE signature feeds, complete de-obfuscation, trained static malware classifier, static audit records. |
| **3. Fuzzing Engine** | Manifest-based component exposure checks, Androguard call-graph heuristics, crafted component/Intent/SQL/path/URI payloads, structured and deduplicated results. | Live ADB/Drozer probes need a configured device/agent; DEX checks need Androguard and an APK path; optional seed mutation is off by default and not enabled by the task. | CFG/DFG static simulation, arbitrary method/data-flow mutation, batch static fuzz queues, configurable per-scan settings, grammar-based API/file-handler fuzzing, broad UI-flow coverage, durable crash/stack-trace archives, correlation with a runtime timeline. |
| **4. Dynamic Analysis Engine** | Optional ADB install/launch and Monkey events; best-effort logs, permissions, processes, network observations, optional tcpdump, screenshots, memory/app-data information, step logs, cleanup. A live run on a connected vivo 1908 is recorded in Backend Verification below. | Collection is device- and privilege-dependent and can fail without failing the overall scan; the recorded run completed key stages but app-data access and PCAP retrieval failed. | Guaranteed isolated snapshot/rollback sandbox, controlled outbound networking, complete syscall/Binder/API-hook monitoring, full file/IPC instrumentation, scripted user journeys and behavior timeline. |
| **5. LLM-Driven Vulnerability Analysis** | Optional Gemini API report, structured JSON prompt/response, model fallback, cached report, summaries and generated remediation/reassessment fields. | Generated risk text is not a calibrated classifier or confidence score; the report page may request Gemini automatically when the serialized scan has no AI report; prompt data is sent to Google. | Local trained benign/malicious classifier, calibrated confidence, training/retraining lifecycle, human feedback, MCP, reasoning-trace audit, dynamic-analysis features in the AI prompt. |
| **6. Reporting & Dashboard UI** | Scan list/history, report detail and filters, API-backed counts, PDF creation/download, report record/JSON data, in-app notices, per-scan delete/rescan, optional analysis tabs. | Dashboard trends are hard-coded; progress is estimated by browser polling; some PDF methodology/OWASP labels depend on data that findings may not contain; bulk actions are absent. | Frontend JSON/CSV export, dynamic behavior/system-call graphs, live streamed findings/progress, bulk actions, email notification delivery, audit-log and model-management UI. |