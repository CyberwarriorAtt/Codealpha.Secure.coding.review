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
