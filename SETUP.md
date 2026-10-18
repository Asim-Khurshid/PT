# FalconScan - Complete Setup Guide

## Project Structure

\`\`\`
FalconScan/
├── backend/                    # Django REST API
│   ├── falconscan_backend/    # Django project settings
│   ├── apps/
│   │   ├── accounts/          # User management
│   │   └── scans/             # Scan management
│   ├── manage.py
│   ├── requirements.txt
│   └── db.sqlite3
├── frontend/                   # Next.js application
│   ├── app/
│   ├── components/
│   ├── lib/
│   ├── package.json
│   └── next.config.mjs
\`\`\`

## Backend Setup

### Prerequisites
- Python 3.9+
- pip
- virtualenv

### Installation Steps

1. Navigate to backend directory:
\`\`\`bash
cd backend
\`\`\`

2. Create and activate virtual environment:
\`\`\`bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac/Linux
python3 -m venv venv
source venv/bin/activate
\`\`\`

3. Install dependencies:
\`\`\`bash
pip install -r requirements.txt
\`\`\`

4. Create .env file from example:
\`\`\`bash
cp .env.example .env
\`\`\`

5. Run migrations:
\`\`\`bash
python manage.py migrate
\`\`\`

6. Create superuser (for admin panel):
\`\`\`bash
python manage.py createsuperuser
\`\`\`

7. Start development server:
\`\`\`bash
python manage.py runserver
\`\`\`

Backend will be available at: http://localhost:8000

Admin panel: http://localhost:8000/admin/
API endpoints: http://localhost:8000/api/

## Frontend Setup

### Prerequisites
- Node.js 18+
- npm or yarn

### Installation Steps

1. Navigate to frontend directory:
\`\`\`bash
cd frontend
\`\`\`

2. Install dependencies:
\`\`\`bash
npm install
\`\`\`

3. Create .env.local from example:
\`\`\`bash
cp .env.local.example .env.local
\`\`\`

4. Update .env.local if needed:
\`\`\`env
NEXT_PUBLIC_API_URL=http://localhost:8000/api
\`\`\`

5. Start development server:
\`\`\`bash
npm run dev
\`\`\`

Frontend will be available at: http://localhost:3000

## API Endpoints

### Authentication
- `POST /api/token/` - Login (returns access & refresh tokens)
- `POST /api/token/refresh/` - Refresh access token
- `POST /api/accounts/users/register/` - Register new user

### Scans
- `GET /api/scans/` - List user's scans
- `POST /api/scans/upload/` - Upload and scan APK
- `GET /api/scans/{id}/` - Get scan details
- `GET /api/scans/{id}/report/` - Get scan report
- `GET /api/scans/statistics/` - Get scan statistics
- `POST /api/scans/{id}/rescan/` - Rescan APK
- `DELETE /api/scans/{id}/` - Delete scan

### User Profile
- `GET /api/accounts/users/me/` - Get current user
- `PATCH /api/accounts/users/update_profile/` - Update profile

## Database Models

### User Profile
- user (ForeignKey to User)
- avatar
- bio
- two_factor_enabled
- notifications_enabled
- threat_alerts
- report_delivery
- api_key

### Scan
- user (ForeignKey)
- app_name
- package_name
- file_name
- file_path
- file_size
- version
- threat_level
- threat_score
- total_issues, critical_issues, high_issues, medium_issues, low_issues
- status (pending, scanning, completed, failed)
- hash_md5, hash_sha256
- started_at, completed_at

### Vulnerability
- scan (ForeignKey)
- title, description
- severity (critical, high, medium, low, info)
- category
- file_path, line_number
- remediation

### Permission
- scan (ForeignKey)
- permission_name
- is_dangerous
- description

### Report
- scan (OneToOneField)
- summary, recommendations
- pdf_url, json_url

## Deployment

### Backend Deployment (Heroku example)
\`\`\`bash
cd backend
heroku create your-app-name
heroku config:set DEBUG=False
heroku config:set SECRET_KEY=your-secret-key
git push heroku main
heroku run python manage.py migrate
\`\`\`

### Frontend Deployment (Vercel)
\`\`\`bash
cd frontend
npm install -g vercel
vercel
\`\`\`

## Troubleshooting

### CORS Issues
Update `CORS_ALLOWED_ORIGINS` in `backend/falconscan_backend/settings.py`

### Database Issues
\`\`\`bash
# Reset database (development only)
python manage.py flush
python manage.py migrate
\`\`\`

### Port Already in Use
\`\`\`bash
# Change backend port
python manage.py runserver 8001

# Change frontend port
npm run dev -- -p 3001
\`\`\`

## Development Tips

- Use Django admin (http://localhost:8000/admin) to manage scans
- API documentation available at http://localhost:8000/api/
- Frontend hot-reload enabled for rapid development
- Check console logs for debugging
