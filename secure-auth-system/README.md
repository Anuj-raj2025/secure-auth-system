# 🔐 Secure Authentication System

A secure user registration and login system using **JWT**, **bcrypt** password hashing and
**field-level encryption**, backed by **PostgreSQL**.

**Tech stack:** Python, Flask, PyJWT, bcrypt, cryptography (Fernet), SQLAlchemy, PostgreSQL, HTML/CSS/JS

## Features
| Area | What is implemented |
|------|---------------------|
| Registration | Input validation, strong-password policy, duplicate-email check |
| Passwords | Hashed with **bcrypt** (salted, 12 rounds) - plain passwords are never stored |
| Authentication | **JWT access token** (15 min) + **refresh token** (7 days), signed with HS256 |
| Session management | Refresh tokens stored **hashed** in DB, **rotated** on every use, **reuse detection**, logout & logout-all-devices |
| Brute-force protection | Account locked for 15 min after 5 wrong passwords |
| Encryption | Phone number encrypted at rest with **Fernet (AES-128)** |
| Protected routes | `@token_required` decorator checks signature, expiry and token type |
| Audit | Every login attempt (success/fail, IP, time) saved and shown on the dashboard |
| Hardening | Generic login errors, timing-safe unknown-user check, security headers (CSP, X-Frame-Options...), SQL-injection safe (ORM) |

## Project structure
```
secure-auth-system/
├── app.py             # Flask app + all API routes
├── security.py        # bcrypt, JWT, encryption, validation, @token_required
├── models.py          # Database tables (users, refresh_tokens, login_logs)
├── config.py          # Settings; auto-creates secrets in .env
├── templates/index.html
├── static/            # style.css, script.js
├── tests/             # 24 pytest tests
├── docker-compose.yml # optional one-command PostgreSQL
├── .env.example
└── requirements.txt
```

## Setup

### 1. Install dependencies
```bash
python -m venv venv
venv\Scripts\activate          # Windows  (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
```

### 2. Set up PostgreSQL (choose one)
**Option A - Docker (easiest):**
```bash
docker compose up -d
```
**Option B - PostgreSQL installed on your PC:** open *pgAdmin* or `psql` and run:
```sql
CREATE USER authuser WITH PASSWORD 'authpass';
CREATE DATABASE authdb OWNER authuser;
```

### 3. Create the `.env` file
Copy `.env.example` to `.env` (the values already match the database above):
```bash
copy .env.example .env         # Windows   (Mac/Linux: cp .env.example .env)
```
Leave `JWT_SECRET_KEY` and `ENCRYPTION_KEY` as `change-me` - the app generates strong keys and saves them to `.env` on first run.

> No PostgreSQL yet? Delete the `DATABASE_URL` line from `.env` and the app uses a local SQLite file so you can try it immediately.

### 4. Run
```bash
python app.py
```
Open **http://127.0.0.1:5000**. Tables are created automatically.

### 5. Run tests
```bash
pytest
```

## API
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/register` | - | `{username, email, password}` |
| POST | `/api/login` | - | `{email, password}` -> access + refresh token |
| POST | `/api/refresh` | - | `{refresh_token}` -> new token pair (old one is revoked) |
| POST | `/api/logout` | - | `{refresh_token}` -> ends this session |
| POST | `/api/logout-all` | Bearer | Ends all sessions |
| GET  | `/api/profile` | Bearer | Current user (phone is decrypted) |
| PUT  | `/api/profile` | Bearer | `{phone}` -> saved encrypted |
| POST | `/api/change-password` | Bearer | `{old_password, new_password}` |
| GET  | `/api/login-history` | Bearer | Last 10 login attempts |

Send the token as `Authorization: Bearer <access_token>`.

### Quick test with curl
```bash
curl -X POST http://127.0.0.1:5000/api/register -H "Content-Type: application/json" \
     -d '{"username":"alice","email":"alice@example.com","password":"Str0ng!Pass"}'

curl -X POST http://127.0.0.1:5000/api/login -H "Content-Type: application/json" \
     -d '{"email":"alice@example.com","password":"Str0ng!Pass"}'
```

## How authentication works
1. **Register** -> password is hashed with bcrypt and stored.
2. **Login** -> password verified; server returns a short-lived *access token* and a long-lived *refresh token*.
3. **Every request** to a protected route carries the access token; the server verifies signature and expiry.
4. When the access token expires, the browser silently calls `/api/refresh`. The refresh token is **single-use**: a new pair is issued and the old one is revoked. If an old token is replayed, all sessions of that user are revoked.
5. **Logout** revokes the refresh token in the database.

## Production notes
- Serve over **HTTPS** only and run with a production server (e.g. `gunicorn`), not `debug=True`.
- Never commit `.env` (it is in `.gitignore`).
- This demo keeps tokens in `localStorage`; for higher security use `HttpOnly` cookies.
- Add rate limiting (e.g. Flask-Limiter) and email verification for a real deployment.
