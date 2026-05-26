# AccessGuard 🔒
**A Secure Authentication System with Brute-Force Protection and Login Monitoring**

---

## Quick Start

```bash
# 1. Create & activate virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the server
uvicorn main:app --reload

# 4. Open browser
# http://localhost:8000
```

---

## Default Admin
- **Email:** admin@accessguard.com  
- **Password:** admin123

---

## Project Structure
```
accessguard/
├── main.py              ← FastAPI app (all backend logic)
├── requirements.txt     ← Python dependencies
├── accessguard.db       ← SQLite DB (auto-created on first run)
└── templates/
    ├── home.html        ← Landing page
    ├── login.html       ← Login form
    ├── register.html    ← Registration form
    ├── welcome.html     ← User success page
    └── dashboard.html   ← Admin monitoring panel
```

---

## Security Concepts Demonstrated

| # | Concept | Implementation |
|---|---------|---------------|
| 1 | Password Hashing | SHA-256 via Python `hashlib` |
| 2 | Brute-Force Protection | Account locked after 3 failed attempts |
| 3 | Login Monitoring | Every attempt logged with timestamp + IP |
| 4 | Role-Based Access Control | Admins → /dashboard, Users → /welcome |
| 5 | SQL Injection Prevention | Parameterized queries throughout |

---

## API Endpoints

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/` | Home page |
| GET/POST | `/register` | Register new user |
| GET/POST | `/login` | Login |
| GET | `/welcome` | User landing page |
| GET | `/dashboard` | Admin dashboard |
| GET | `/unlock/{email}` | Unlock a locked account |
| POST | `/api/register` | JSON API registration |
| POST | `/api/login` | JSON API login |
| GET | `/api/logs` | JSON API audit logs |
| GET | `/docs` | Swagger UI |
