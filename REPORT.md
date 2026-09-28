# Task 3: Secure Coding Review

**Language:** Python (Flask) | **Target:** small login/notes web app (`app.py`)
**Methods:** manual inspection + static analysis with `bandit -r app.py`

## Application under review (original code)

```python
from flask import Flask, request, render_template_string
import sqlite3, hashlib, subprocess

app = Flask(__name__)
app.secret_key = "supersecret123"

@app.route("/login", methods=["POST"])
def login():
    u, p = request.form["user"], request.form["pass"]
    db = sqlite3.connect("app.db")
    q = f"SELECT * FROM users WHERE user='{u}' AND pw='{hashlib.md5(p.encode()).hexdigest()}'"
    return "ok" if db.execute(q).fetchone() else "fail"

@app.route("/hello")
def hello():
    return render_template_string("<h1>Hello " + request.args.get("name", "") + "</h1>")

@app.route("/ping")
def ping():
    return subprocess.check_output("ping -c 1 " + request.args["host"], shell=True)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
```

## Findings

| # | Vulnerability | Location | Severity | CWE |
|---|---|---|---|---|
| 1 | SQL injection | `/login` query | Critical | CWE-89 |
| 2 | OS command injection | `/ping` | Critical | CWE-78 |
| 3 | Server-side template injection / XSS | `/hello` | High | CWE-1336 / CWE-79 |
| 4 | Debug mode on, bound to all interfaces | `app.run` | High | CWE-489 |
| 5 | Weak password hashing (unsalted MD5) | `/login` | High | CWE-916 |
| 6 | Hardcoded secret key | `app.secret_key` | Medium | CWE-798 |
| 7 | No rate limiting on login | `/login` | Medium | CWE-307 |
| 8 | Missing input validation / `request.form[...]` KeyError | all routes | Low | CWE-20 |

## Details and remediation

### 1. SQL injection
Input `' OR '1'='1' --` as the username logs in without a password, because user input is concatenated into the query.
**Fix:** parameterized queries.
```python
db.execute("SELECT pw FROM users WHERE user = ?", (u,))
```

### 2. Command injection
`host=8.8.8.8; cat /etc/passwd` runs arbitrary commands because of `shell=True`.
**Fix:** validate input, pass arguments as a list, never use a shell.
```python
import ipaddress
host = str(ipaddress.ip_address(request.args["host"]))   # raises on invalid input
subprocess.check_output(["ping", "-c", "1", host], timeout=5)
```

### 3. Template injection / XSS
`?name={{7*7}}` renders `49`, and `<script>` is reflected unescaped.
**Fix:** pass user data as template variables so Jinja2 auto-escapes it.
```python
render_template_string("<h1>Hello {{ name }}</h1>", name=request.args.get("name", ""))
```

### 4. Debug mode
The Werkzeug debugger allows remote code execution if exposed.
**Fix:** `app.run(debug=False, host="127.0.0.1")` and serve with gunicorn behind a reverse proxy in production.

### 5. Weak password hashing
MD5 is fast and unsalted, so it is cracked easily with rainbow tables.
**Fix:** use a slow, salted hash.
```python
from werkzeug.security import generate_password_hash, check_password_hash
# store:  generate_password_hash(p)
# verify: check_password_hash(stored_hash, p)
```

### 6. Hardcoded secret
**Fix:** load from the environment: `app.secret_key = os.environ["SECRET_KEY"]` (generate with `python -c "import secrets; print(secrets.token_hex(32))"`).

### 7. No rate limiting
Allows brute force. **Fix:** `Flask-Limiter`, e.g. `@limiter.limit("5 per minute")` on `/login`, plus account lockout or delay.

### 8. Input validation
Use `request.form.get()`, check length and type, and return proper 400 responses.

## Fixed version

```python
import os, ipaddress, sqlite3, subprocess
from flask import Flask, request, render_template_string, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
limiter = Limiter(get_remote_address, app=app)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    u, p = request.form.get("user", ""), request.form.get("pass", "")
    if not (0 < len(u) <= 50 and 0 < len(p) <= 128):
        abort(400)
    with sqlite3.connect("app.db") as db:
        row = db.execute("SELECT pw FROM users WHERE user = ?", (u,)).fetchone()
    return ("ok", 200) if row and check_password_hash(row[0], p) else ("fail", 401)

@app.route("/hello")
def hello():
    return render_template_string("<h1>Hello {{ name }}</h1>", name=request.args.get("name", ""))

@app.route("/ping")
def ping():
    try:
        host = str(ipaddress.ip_address(request.args.get("host", "")))
    except ValueError:
        abort(400)
    return subprocess.check_output(["ping", "-c", "1", host], timeout=5)

if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1")
```

## General secure-coding best practices
- Never trust input: validate on the server, use allow-lists.
- Use parameterized queries or an ORM, never string-built SQL.
- Avoid `shell=True`, `eval`, `exec`, and unsafe deserialization (`pickle`).
- Keep secrets out of source code; rotate them.
- Hash passwords with bcrypt/argon2/scrypt.
- Add security headers (CSP, `X-Content-Type-Options`, HSTS) and use HTTPS.
- Run `bandit`, `pip-audit`, and code review in CI.
- Apply least privilege and log security events without logging secrets.

## Verification
After fixes, re-run `bandit -r app.py` and repeat the original payloads (`' OR '1'='1`, `;id`, `{{7*7}}`); all should now fail or be escaped.
