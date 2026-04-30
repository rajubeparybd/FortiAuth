# Secure Login System Report

## Project Overview

This project is a security-focused authentication system built with:

- **Backend**: Python Flask
- **Database**: SQLite (raw SQL with parameterized queries)
- **Frontend**: HTML, CSS, Vanilla JavaScript
- **Security**: JWT, CSRF protection, 2FA (TOTP), lockout timer, rate limiting, security headers

## Test Coverage

Current test module: `backend/test_security.py`

Covers:

- registration
- login failure/lockout behavior
- CSRF rejection when missing token
- forgot-password flow basics

Run tests:

```bash
source .venv/Scripts/activate
python -m unittest -v backend.test_security
```

---

## Run Instructions

Use the startup script:

```bash
bash run.sh
```

`run.sh` handles:

1. virtual environment activation
2. dependency check/install
3. DB initialization check
4. server start
