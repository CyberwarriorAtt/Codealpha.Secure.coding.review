# INTENTIONALLY VULNERABLE - for security review training only. Do not deploy.
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
