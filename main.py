import hashlib
import sqlite3
from datetime import datetime
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="AccessGuard - Secure Authentication System")
templates = Jinja2Templates(directory="templates")

DB_PATH = "accessguard.db"
MAX_ATTEMPTS = 3


# ─────────────────────────────────────────────
# Database Setup
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    # Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL,
            email    TEXT    UNIQUE NOT NULL,
            password TEXT    NOT NULL,
            role     TEXT    NOT NULL DEFAULT 'user',
            locked   INTEGER NOT NULL DEFAULT 0
        )
    """)

    # Login logs table
    c.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            email     TEXT NOT NULL,
            status    TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            ip        TEXT
        )
    """)

    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def log_attempt(email: str, status: str, ip: str = ""):
    conn = get_db()
    conn.execute(
        "INSERT INTO login_logs (email, status, timestamp, ip) VALUES (?, ?, ?, ?)",
        (email, status, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip)
    )
    conn.commit()
    conn.close()


def count_recent_failures(email: str) -> int:
    conn = get_db()
    row = conn.execute(
        """SELECT COUNT(*) as cnt FROM login_logs
           WHERE email=? AND status='FAILED'
           AND id > COALESCE(
               (SELECT MAX(id) FROM login_logs WHERE email=? AND status='SUCCESS'), 0
           )""",
        (email, email)
    ).fetchone()
    conn.close()
    return row["cnt"] if row else 0


# ─────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()
    # Create default admin if not exists
    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email=?", ("admin@accessguard.com",)).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            ("Admin", "admin@accessguard.com", hash_password("admin123"), "admin")
        )
        conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# HTML Routes
# ─────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None, "success": None})


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form("user")
):
    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        conn.close()
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Email already registered.",
            "success": None
        })
    conn.execute(
        "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
        (username, email, hash_password(password), role)
    )
    conn.commit()
    conn.close()
    return templates.TemplateResponse("register.html", {
        "request": request,
        "error": None,
        "success": f"Account created for {username}! You can now log in."
    })


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...)
):
    ip = request.client.host if request.client else "unknown"
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()

    if not user:
        log_attempt(email, "FAILED", ip)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials."})

    if user["locked"]:
        log_attempt(email, "BLOCKED", ip)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Account is locked. Contact admin."})

    if user["password"] != hash_password(password):
        log_attempt(email, "FAILED", ip)
        failures = count_recent_failures(email)
        remaining = MAX_ATTEMPTS - failures

        if failures >= MAX_ATTEMPTS:
            conn = get_db()
            conn.execute("UPDATE users SET locked=1 WHERE email=?", (email,))
            conn.commit()
            conn.close()
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Too many failed attempts. Account locked!"
            })

        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": f"Invalid credentials. {remaining} attempt(s) remaining."
        })

    log_attempt(email, "SUCCESS", ip)

    if user["role"] == "admin":
        return RedirectResponse(url=f"/dashboard?email={email}", status_code=303)
    return RedirectResponse(url=f"/welcome?username={user['username']}", status_code=303)


@app.get("/welcome", response_class=HTMLResponse)
def welcome(request: Request, username: str = "User"):
    return templates.TemplateResponse("welcome.html", {"request": request, "username": username})


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, email: str = ""):
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM login_logs ORDER BY id DESC LIMIT 50"
    ).fetchall()
    locked_users = conn.execute(
        "SELECT username, email FROM users WHERE locked=1"
    ).fetchall()
    total_users = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()["cnt"]
    conn.close()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "logs": logs,
        "locked_users": locked_users,
        "total_users": total_users,
        "admin_email": email
    })


@app.get("/unlock/{email}", response_class=HTMLResponse)
def unlock(email: str):
    conn = get_db()
    conn.execute("UPDATE users SET locked=0 WHERE email=?", (email,))
    conn.execute(
        "DELETE FROM login_logs WHERE email=? AND status='FAILED'",
        (email,)
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/dashboard", status_code=303)


# ─────────────────────────────────────────────
# JSON API Routes
# ─────────────────────────────────────────────

@app.post("/api/register")
def api_register(username: str = Form(...), email: str = Form(...), password: str = Form(...), role: str = Form("user")):
    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        conn.close()
        return {"success": False, "message": "Email already registered."}
    conn.execute(
        "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
        (username, email, hash_password(password), role)
    )
    conn.commit()
    conn.close()
    return {"success": True, "message": f"User {username} registered."}


@app.post("/api/login")
def api_login(email: str = Form(...), password: str = Form(...)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not user:
        log_attempt(email, "FAILED")
        return {"success": False, "message": "Invalid credentials."}
    if user["locked"]:
        return {"success": False, "message": "Account locked."}
    if user["password"] != hash_password(password):
        log_attempt(email, "FAILED")
        failures = count_recent_failures(email)
        if failures >= MAX_ATTEMPTS:
            conn = get_db()
            conn.execute("UPDATE users SET locked=1 WHERE email=?", (email,))
            conn.commit()
            conn.close()
            return {"success": False, "message": "Account locked due to too many attempts."}
        return {"success": False, "message": f"Wrong password. {MAX_ATTEMPTS - failures} attempt(s) left."}
    log_attempt(email, "SUCCESS")
    return {"success": True, "role": user["role"], "message": f"Welcome, {user['username']}!"}


@app.get("/api/logs")
def api_logs():
    conn = get_db()
    logs = conn.execute("SELECT * FROM login_logs ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return {"logs": [dict(row) for row in logs]}
