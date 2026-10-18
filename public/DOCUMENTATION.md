# 🦅 FalconScan

## Enterprise-Grade APK Security Analysis Platform

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![Status](https://img.shields.io/badge/status-production-success.svg)

*Comprehensive security analysis for Android applications with professional reporting*

---

## 📋 Table of Contents

1. [🎯 Overview](#overview)
2. [✨ Features](#features)
3. [🏗️ Architecture](#architecture)
4. [⚙️ Installation & Setup](#installation--setup)
5. [📖 User Guide](#user-guide)
6. [🤖 AI Analysis](#ai-analysis)
7. [🔌 API Documentation](#api-documentation)
8. [🔒 Security Analysis](#security-analysis)
9. [🛠️ Technology Stack](#technology-stack)
10. [🐛 Troubleshooting](#troubleshooting)
11. [📄 License](#license)

---

## 🎯 Overview

> **FalconScan** is an enterprise-grade Android APK security analysis platform that provides comprehensive static analysis, advanced vulnerability detection, and professional security reporting. Built with cutting-edge web technologies and powered by sophisticated security scanning algorithms, FalconScan empowers developers and security researchers to identify and remediate vulnerabilities in Android applications before deployment.

### 🌟 Key Highlights

| ⚡ **Ultra-Fast Analysis** | 🔒 **15+ Security Checks** | 📊 **Professional Reports** | 🎨 **Modern UI** |
|:---:|:---:|:---:|:---:|
| Completes APK analysis in ~1.5-2 seconds | Comprehensive OWASP Mobile Top 10 coverage | Downloadable PDF reports with executive summaries | Beautiful, responsive interface with real-time updates |

| 🔄 **Auto-Recovery** | 📱 **MobSF-Style Analysis** | 🚀 **Real-Time Updates** | 🛡️ **Enterprise Ready** |
|:---:|:---:|:---:|:---:|
| Intelligent error handling and automatic retry mechanism | Extracts URLs, IPs, emails, API keys, and more | Live progress tracking and notifications | Scalable architecture for production use |

---

## ✨ Features

### 1. Static Analysis
FalconScan performs comprehensive static analysis on APK files:

- **Manifest Analysis**: Extracts permissions, components, and configuration
- **Certificate Validation**: Checks for debug certificates and expiry
- **Code Analysis**: Identifies hardcoded secrets, weak crypto, SQL injection risks
- **String Extraction**: Finds URLs, IP addresses, email addresses, phone numbers
- **API Key Detection**: Identifies AWS, Google, Firebase, Slack, GitHub, Stripe keys
- **Component Discovery**: Lists activities, services, receivers, and providers

### 2. Vulnerability Scanning
15+ security checks covering OWASP Mobile Top 10:

#### Manifest Security
- ✓ Debuggable flag detection
- ✓ Backup allowed validation
- ✓ Minimum SDK version check
- ✓ Network security configuration

#### Permission Analysis
- ✓ Dangerous permissions (CAMERA, LOCATION, SMS, etc.)
- ✓ Permission categorization (dangerous vs normal)
- ✓ Unused permission detection

#### Certificate Security
- ✓ Debug certificate detection
- ✓ Certificate expiry validation
- ✓ Signature verification

#### Component Security
- ✓ Exported components analysis
- ✓ Intent filter validation
- ✓ Provider authority checking

#### Code Security
- ✓ Hardcoded API keys and secrets
- ✓ Weak cryptographic algorithms (DES, ECB, MD5, SHA-1)
- ✓ SQL injection pattern detection
- ✓ Path traversal vulnerabilities
- ✓ Insecure network communication (HTTP)
- ✓ Cleartext traffic configuration
- ✓ Sensitive data logging

### 3. Professional Reporting
- **PDF Reports**: Downloadable security assessment reports
- **Executive Summary**: High-level threat overview with risk scores
- **Vulnerability Details**: Categorized by severity (Critical → Low)
- **Visual Analytics**: Pie charts showing severity distribution
- **Remediation Guidance**: Actionable security recommendations
- **Permission Breakdown**: Detailed permission analysis tables

### 4. User Interface
- **Dashboard**: Real-time statistics and recent scans overview
- **Upload Page**: Drag-and-drop APK upload with progress tracking
- **Reports Page**: Tabular view with search, filter, and bulk actions
- **Scan History**: Timeline view of all analyzed APKs
- **Report Details**: Comprehensive vulnerability breakdown with 10+ sections

### 5. Advanced Features
- **Auto-Recovery**: Automatically retries failed scans
- **Duplicate Detection**: Prevents re-analysis of identical APKs
- **Real-time Progress**: Live status updates during analysis
- **Multi-tab Support**: Persistent state across browser tabs
- **Toast Notifications**: User-friendly success/error messages
- **Responsive Design**: Works on desktop, tablet, and mobile

---

## 🏗️ Architecture

### 🔷 High-Level System Architecture

![System Architecture](/images/system-architecture.png)

### 🔶 Data Flow Architecture

![Data Flow Architecture](/images/data-flow.png)

### 🔸 Component Architecture

![Component Architecture](/images/component-architecture.png)

### 📁 Backend Directory Structure

```
backend/
│
├── 📂 falconscan_backend/          # Django Project Configuration
│   ├── ⚙️ settings.py              # App settings & configuration
│   ├── 🔗 urls.py                  # URL routing configuration
│   ├── 🚀 asgi.py                  # ASGI server interface
│   └── 🌐 wsgi.py                  # WSGI server interface
│
├── 📂 apps/
│   │
│   ├── 📂 accounts/                # User Management Module
│   │   ├── 👤 models.py            # User data models
│   │   ├── 🎯 views.py             # Authentication endpoints
│   │   ├── 📊 serializers.py       # Data serialization
│   │   └── 🔗 urls.py              # Account routes
│   │
│   └── 📂 scans/                   # Core Scanning Module
│       ├── 📋 models.py            # Scan, Vulnerability, Report models
│       ├── 🎯 views.py             # REST API endpoints
│       ├── 📊 serializers.py       # Data transformation
│       ├── ⚡ tasks.py             # Background analysis tasks
│       ├── 🔍 analyzer.py          # APK analyzer wrapper
│       ├── 📱 static_analyzer.py   # String/artifact extraction
│       ├── 🔒 vulnerability_scanner.py  # Security validation
│       ├── 📄 pdf_generator.py     # Report generation
│       └── 🔗 urls.py              # Scan routes
│
├── 📂 media/                       # User-uploaded content
│   ├── 📱 apks/                    # Uploaded APK files
│   └── 📄 reports/                 # Generated PDF reports
│
├── 🗄️ db.sqlite3                   # SQLite database
├── ⚙️ manage.py                    # Django management CLI
└── 📝 requirements.txt             # Python dependencies
```

### 📁 Frontend Directory Structure

```
app/
│
├── 🏠 page.tsx                     # Landing page
├── 🎨 layout.tsx                   # Root layout
├── 💅 globals.css                  # Global styles
│
├── 📂 dashboard/                   # Protected Dashboard Area
│   ├── 📊 layout.tsx               # Dashboard shell + sidebar
│   ├── 🏠 page.tsx                 # Dashboard home (stats)
│   │
│   ├── 📂 upload/
│   │   └── 📤 page.tsx             # APK upload interface
│   │
│   ├── 📂 history/
│   │   ├── 📜 page.tsx             # Scan history timeline
│   │   └── ⏳ loading.tsx          # Loading state
│   │
│   ├── 📂 reports/
│   │   ├── 📋 page.tsx             # Reports table view
│   │   ├── ⏳ loading.tsx          # Loading state
│   │   └── 📂 [id]/
│   │       └── 📄 page.tsx         # Report details
│   │
│   ├── 📂 profile/
│   │   └── 👤 page.tsx             # User profile
│   │
│   ├── 📂 settings/
│   │   └── ⚙️ page.tsx             # User settings
│   │
│   └── 📂 documentation/
│       └── 📖 page.tsx             # Documentation viewer
│
├── 📂 login/
│   └── 🔐 page.tsx                 # Login page
│
├── 📂 register/
│   └── ✍️ page.tsx                 # Registration page
│
└── 📂 documentation/
    └── 📖 page.tsx                 # Public documentation

components/
├── 📂 ui/                          # ShadcN UI Components (40+)
│   ├── button.tsx
│   ├── card.tsx
│   ├── table.tsx
│   └── ...
├── 🔐 auth-form.tsx                # Reusable auth component
├── 🦅 falcon-logo.tsx              # Logo component
└── 🛡️ shield-logo.tsx              # Shield icon component

lib/
├── 🔌 api.ts                       # API client (Axios)
└── 🛠️ utils.ts                     # Utility functions

hooks/
├── 📱 use-mobile.ts                # Mobile detection hook
└── 🍞 use-toast.ts                 # Toast notification hook
```

---

## Installation & Setup

### Prerequisites
- **Python**: 3.8 or higher
- **Node.js**: 16.x or higher
- **pnpm**: 8.x or higher (or npm/yarn)
- **Git**: For version control

### Backend Setup

1. **Navigate to backend directory**
```bash
cd backend
```

2. **Create virtual environment**
```bash
python -m venv venv
```

3. **Activate virtual environment**
```bash
# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

4. **Install dependencies**
```bash
pip install -r requirements.txt
```

5. **Run migrations**
```bash
python manage.py migrate
```

6. **Create superuser (optional)**
```bash
python manage.py createsuperuser
```

7. **Start development server**
```bash
python manage.py runserver
```

Backend will be available at: `http://localhost:8000`

### Frontend Setup

1. **Navigate to project root**
```bash
cd ..
```

2. **Install dependencies**
```bash
pnpm install
# or
npm install
```

3. **Set environment variables**
Create `.env.local`:
```env
NEXT_PUBLIC_API_URL=http://localhost:8000/api
```

4. **Start development server**
```bash
pnpm dev
# or
npm run dev
```

Frontend will be available at: `http://localhost:3000`

---

## User Guide

### Getting Started

#### 1. Registration
1. Navigate to `http://localhost:3000/register`
2. Fill in your details:
   - Email
   - Username
   - Password (with confirmation)
3. Click "Create Account"
4. You'll be automatically logged in

#### 2. Login
1. Navigate to `http://localhost:3000/login`
2. Enter your credentials
3. Click "Sign In"
4. Redirected to dashboard

### Dashboard Overview

The dashboard provides:
- **Total Scans**: Count of all analyzed APKs
- **Critical Issues**: Number of critical vulnerabilities found
- **APKs Analyzed**: Total APK count
- **Safe Apps**: Count of low-risk applications
- **Charts**: 
  - Line chart: Scans & threats over time
  - Pie chart: Risk distribution
- **Recent Scans**: Quick access to last 4 scans

### Uploading APKs

1. **Navigate to Upload Page**
   - Click "Upload New APK" on dashboard
   - Or use sidebar navigation

2. **Select APK File**
   - Drag and drop APK file
   - Or click "Browse Files"

3. **Provide Details**
   - **App Name**: Application name (e.g., "MyBankApp")
   - **Package Name**: Java package (e.g., "com.example.app")

4. **Configure Analysis**
   - ✓ Static Analysis (enabled by default)
   - Dynamic Analysis (coming soon)

5. **Start Analysis**
   - Click "Start Analysis"
   - Progress bar shows real-time status
   - Analysis typically completes in 1.5-2 seconds

6. **View Results**
   - Automatic redirect to report page
   - Or click "View Report" button

### Understanding Reports

#### Report Structure

**1. Executive Summary**
- Threat Level: Safe, Low, Medium, High, Critical
- Risk Score: 0-100 numerical score
- Total Vulnerabilities: Count by severity

**2. Application Information**
- App Name & Package
- Version & SDK levels
- File size & hashes (MD5, SHA256)
- Permissions count
- Scan timestamp

**3. Vulnerability Details**
Each vulnerability includes:
- **Title**: Short description
- **Severity**: Critical, High, Medium, Low
- **Category**: Type of vulnerability (e.g., Manifest, Crypto)
- **Description**: Detailed explanation
- **File Path**: Location in APK
- **Remediation**: How to fix

**4. Static Analysis Results**
- **URLs**: All HTTP/HTTPS links found
- **IP Addresses**: IPv4 and IPv6 addresses
- **Emails**: Email addresses in code/resources
- **Phone Numbers**: Phone number patterns
- **API Keys**: Detected third-party API keys
- **File Paths**: Filesystem paths
- **Base64 Strings**: Encoded data
- **Crypto Patterns**: Cryptographic function usage
- **SQL Queries**: Database query strings
- **Secrets**: Potential passwords, tokens, keys

**5. Permission Analysis**
- Permission name
- Protection level (dangerous/normal)
- Description
- Risk assessment

**6. Component Analysis**
- **Activities**: UI screens
- **Services**: Background services
- **Receivers**: Broadcast receivers
- **Providers**: Content providers
- Exported status (security risk indicator)

**7. Certificate Information**
- Issuer & Subject
- Validity period
- Signature algorithm
- Debug certificate warning

**8. Network Security**
- HTTP URLs detected
- Cleartext traffic configuration
- Network security config analysis

**9. Code Security**
- Hardcoded secrets
- Weak cryptography
- SQL injection risks
- Path traversal vulnerabilities

**10. Recommendations**
Prioritized security improvements based on findings

### Downloading PDF Reports

1. **From Reports Page**
   - Locate scan in table
   - Click download icon (⬇)
   - PDF downloads to browser

2. **From Report Detail Page**
   - Scroll to top
   - Click "Download PDF" button
   - Professional report with charts and tables

### Managing Scans

#### Viewing History
1. Navigate to "History" in sidebar
2. View timeline of all scans
3. Filter by:
   - App name (search)
   - Risk level (dropdown)

#### Deleting Scans
1. Go to "Reports" page
2. Find scan to delete
3. Click trash icon (🗑)
4. Confirm deletion
5. Scan and all related data removed

#### Re-scanning APKs
- Upload same APK again
- System detects duplicate (by MD5 hash)
- Shows existing results
- Or retry if previous scan failed

---

## AI Analysis

FalconScan includes an on-demand AI Security Intelligence engine that generates deep contextual analysis for any completed scan. Unlike the automated static checks — which are deterministic rule-based patterns — the AI report provides narrative context, realistic attack chains, and tailored fix guidance based on the specific combination of findings.

### What It Generates

- **Executive Summary** — plain-language overview for non-technical stakeholders
- **Technical Finding Analysis** — expanded explanation of each detected vulnerability in context
- **Attack Chain Scenarios** — realistic exploitation paths chaining multiple weaknesses together
- **Severity Re-scoring** — re-evaluation of each finding's actual risk based on context and combination
- **Code-Level Fix Recommendations** — specific code changes or configuration steps to remediate each issue
- **Compliance Notes** — mapping to OWASP Mobile Top 10, GDPR, and MASVS standards

### How to Enable

1. Obtain an AI API key
2. Add it to `backend/.env`:
```env
AI_API_KEY=your_api_key_here
```
3. Restart the backend server (`python manage.py runserver`)

### Usage

1. Complete a scan — static analysis runs automatically after every APK upload
2. Open the scan report at `/dashboard/reports/{id}`
3. Click the **AI** tab in the report viewer
4. Click **Generate AI Report**
5. The engine analyses all findings and returns a structured report in 10–20 seconds
6. Click **Regenerate** at any time to re-run the analysis

> **Note:** The AI report is generated on demand and is not permanently stored. Each regeneration produces a fresh analysis.

---

## API Documentation

### Authentication Endpoints

#### Register
```http
POST /api/accounts/users/register/
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "username",
  "password": "password123",
  "password_confirm": "password123"
}

Response: 201 Created
{
  "access": "eyJ0eXAiOiJKV1QiLCJ...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJ...",
  "user": {
    "id": 1,
    "username": "username",
    "email": "user@example.com"
  }
}
```

#### Login
```http
POST /api/token/
Content-Type: application/json

{
  "username": "username",
  "password": "password123"
}

Response: 200 OK
{
  "access": "eyJ0eXAiOiJKV1QiLCJ...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJ..."
}
```

#### Get User Profile
```http
GET /api/accounts/users/me/
Authorization: Bearer {access_token}

Response: 200 OK
{
  "id": 1,
  "username": "username",
  "email": "user@example.com",
  "first_name": "",
  "last_name": ""
}
```

### Scan Endpoints

#### Upload APK
```http
POST /api/scans/upload/
Authorization: Bearer {access_token}
Content-Type: multipart/form-data

FormData:
- file_path: <APK file>
- app_name: "MyApp"
- package_name: "com.example.app"

Response: 201 Created
{
  "id": 1,
  "app_name": "MyApp",
  "package_name": "com.example.app",
  "status": "pending",
  "created_at": "2025-11-16T20:00:00Z"
}
```

#### List Scans
```http
GET /api/scans/
Authorization: Bearer {access_token}

Response: 200 OK
{
  "results": [
    {
      "id": 1,
      "app_name": "MyApp",
      "package_name": "com.example.app",
      "status": "completed",
      "threat_level": "medium",
      "threat_score": 45,
      "total_issues": 8,
      "created_at": "2025-11-16T20:00:00Z"
    }
  ]
}
```

#### Get Scan Details
```http
GET /api/scans/{id}/
Authorization: Bearer {access_token}

Response: 200 OK
{
  "id": 1,
  "app_name": "MyApp",
  "package_name": "com.example.app",
  "file_name": "app.apk",
  "file_size": 5242880,
  "version": "1.0",
  "threat_level": "medium",
  "threat_score": 45,
  "total_issues": 8,
  "critical_issues": 1,
  "high_issues": 2,
  "medium_issues": 3,
  "low_issues": 2,
  "status": "completed",
  "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
  "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "static_analysis": { /* ... */ },
  "created_at": "2025-11-16T20:00:00Z",
  "completed_at": "2025-11-16T20:00:02Z"
}
```

#### Get Report
```http
GET /api/scans/{id}/report/
Authorization: Bearer {access_token}

Response: 200 OK
{
  "id": 1,
  "scan": 1,
  "summary": "...",
  "recommendations": "...",
  "pdf_url": "reports/security_report_myapp_20251116.pdf",
  "json_url": "reports/report_1.json",
  "created_at": "2025-11-16T20:00:02Z"
}
```

#### Download PDF
```http
GET /api/scans/{id}/download_pdf/
Authorization: Bearer {access_token}

Response: 200 OK
Content-Type: application/pdf
Content-Disposition: attachment; filename="MyApp_security_report.pdf"

<PDF binary data>
```

#### Delete Scan
```http
DELETE /api/scans/{id}/
Authorization: Bearer {access_token}

Response: 204 No Content
```

#### Rescan (Retry Failed)
```http
POST /api/scans/{id}/rescan/
Authorization: Bearer {access_token}

Response: 200 OK
{
  "message": "Scan restarted successfully",
  "scan": { /* scan object */ }
}
```

#### Cleanup Failed Scans
```http
POST /api/scans/cleanup_failed/
Authorization: Bearer {access_token}

Response: 200 OK
{
  "message": "Cleaned and retried 3 failed scans",
  "cleaned": 3,
  "retried": 3
}
```

#### Statistics
```http
GET /api/scans/statistics/
Authorization: Bearer {access_token}

Response: 200 OK
{
  "total_scans": 25,
  "critical_threats": 3,
  "high_threats": 7,
  "medium_threats": 10,
  "safe_apps": 5
}
```

---

## Security Analysis

### Vulnerability Categories

#### 1. Manifest Security
**What it checks:**
- Debuggable flag in production
- Backup allowed without encryption
- Low minimum SDK version
- Missing network security config

**Example vulnerabilities:**
- `android:debuggable="true"` allows runtime debugging
- `android:allowBackup="true"` enables data backup to cloud
- `minSdkVersion < 21` lacks modern security features

**Impact:** Critical to High
**Remediation:**
- Set `debuggable="false"` in production
- Use encrypted backups with `BackupAgent`
- Target SDK 26+ for improved security

#### 2. Permission Analysis
**What it checks:**
- Dangerous permissions (CAMERA, LOCATION, SMS, CONTACTS, etc.)
- Unnecessary permissions
- Permission over-requesting

**Example vulnerabilities:**
- SEND_SMS without user interaction
- READ_CONTACTS in non-social apps
- ACCESS_FINE_LOCATION without justification

**Impact:** Medium to High
**Remediation:**
- Request only necessary permissions
- Use runtime permission requests (Android 6+)
- Provide clear permission rationale

#### 3. Certificate Security
**What it checks:**
- Debug certificates in production
- Expired certificates
- Weak signature algorithms

**Example vulnerabilities:**
- APK signed with debug keystore
- Certificate expires within 6 months
- SHA-1 signature (deprecated)

**Impact:** Critical
**Remediation:**
- Use production keystore
- Renew certificates timely
- Use SHA-256 or higher

#### 4. Exported Components
**What it checks:**
- Activities/Services with `exported="true"`
- Missing permission protection
- Intent filter security

**Example vulnerabilities:**
- Login activity exported without protection
- Service accessible by any app
- Provider with world-readable data

**Impact:** High to Critical
**Remediation:**
- Set `exported="false"` unless necessary
- Add permission requirements
- Validate incoming intents

#### 5. Hardcoded Secrets
**What it checks:**
- API keys (AWS, Google, Firebase, Slack, GitHub, Stripe)
- Passwords and tokens
- Encryption keys

**Patterns detected:**
```
AWS: AKIA[0-9A-Z]{16}
Google: AIza[0-9A-Za-z\\-_]{35}
Firebase: [0-9a-z]{35,45}
GitHub: ghp_[0-9a-zA-Z]{36}
Stripe: sk_live_[0-9a-zA-Z]{24,}
```

**Impact:** Critical
**Remediation:**
- Use Android Keystore
- Implement server-side API proxies
- Use environment-specific configs

#### 6. Weak Cryptography
**What it checks:**
- DES encryption
- ECB mode
- MD5 hashing
- SHA-1 usage

**Example vulnerabilities:**
```java
Cipher.getInstance("DES/ECB/PKCS5Padding")  // Weak!
MessageDigest.getInstance("MD5")             // Weak!
```

**Impact:** High
**Remediation:**
```java
Cipher.getInstance("AES/GCM/NoPadding")     // Strong
MessageDigest.getInstance("SHA-256")         // Strong
```

#### 7. SQL Injection
**What it checks:**
- Dynamic SQL query construction
- String concatenation in queries
- Unparameterized queries

**Example vulnerabilities:**
```java
String query = "SELECT * FROM users WHERE id=" + userId;  // Vulnerable!
```

**Impact:** Critical
**Remediation:**
```java
String query = "SELECT * FROM users WHERE id=?";
cursor = db.rawQuery(query, new String[]{userId});  // Safe
```

#### 8. Network Security
**What it checks:**
- HTTP URLs (cleartext traffic)
- Missing network security config
- Insecure TLS configurations

**Example vulnerabilities:**
- `http://api.example.com` instead of HTTPS
- `cleartextTrafficPermitted="true"`
- No certificate pinning

**Impact:** High
**Remediation:**
- Use HTTPS only
- Implement network security config
- Pin certificates for sensitive APIs

---

## Technology Stack

### Backend

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.8+ | Programming language |
| Django | 4.2.7 | Web framework |
| Django REST Framework | 3.14+ | API framework |
| Daphne | 4.0.0 | ASGI server |
| Androguard | 4.1.2 | APK analysis |
| ReportLab | 4.4.4 | PDF generation |
| PyOpenSSL | 25.0.0 | Certificate analysis |
| Cryptography | 44.0.3 | Crypto utilities |
| SQLite | 3.x | Database |

### Frontend

| Technology | Version | Purpose |
|------------|---------|---------|
| Next.js | 16.0.0 | React framework |
| React | 19.x | UI library |
| TypeScript | 5.x | Type safety |
| Tailwind CSS | 3.x | Styling |
| ShadcN UI | Latest | Component library |
| Axios | 1.x | HTTP client |
| Recharts | 2.x | Charts |
| Lucide Icons | Latest | Icons |

### Development Tools

| Tool | Purpose |
|------|---------|
| VS Code | Code editor |
| Git | Version control |
| pnpm | Package manager |
| pip | Python packages |
| ESLint | JavaScript linting |
| Prettier | Code formatting |



---

## Troubleshooting

### Common Issues

#### Backend Issues

**Problem**: `ModuleNotFoundError: No module named 'androguard'`
**Solution**:
```bash
pip install androguard
```

**Problem**: Database errors after model changes
**Solution**:
```bash
python manage.py makemigrations
python manage.py migrate
```

**Problem**: Port 8000 already in use
**Solution**:
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# macOS/Linux
lsof -ti:8000 | xargs kill -9
```

**Problem**: CORS errors
**Solution**: Check `CORS_ALLOWED_ORIGINS` in `settings.py`

#### Frontend Issues

**Problem**: `npm ERR! code ENOENT`
**Solution**:
```bash
rm -rf node_modules package-lock.json
npm install
```

**Problem**: API connection refused
**Solution**: Verify backend is running on port 8000

**Problem**: Build errors
**Solution**:
```bash
rm -rf .next
npm run build
```

#### Analysis Issues

**Problem**: APK analysis fails
**Solution**: Check APK file integrity, ensure it's a valid APK

**Problem**: PDF generation fails
**Solution**: Verify reportlab is installed, check disk space

**Problem**: Slow analysis
**Solution**: Normal for large APKs (>100MB), consider upgrading hardware

---

## License

FalconScan is released under the MIT License. See [LICENSE](https://github.com/yourusername/falconscan/blob/master/LICENSE) for details.
- ✅ Modern React + Django architecture
- ✅ Auto-recovery system
- ✅ Comprehensive documentation

---

**Built with ❤️ by the FalconScan Team**

*Last Updated: November 16, 2025*
