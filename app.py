"""
!!! WARNING: INTENTIONALLY VULNERABLE APPLICATION !!!

This Flask app contains deliberate security flaws for training and portfolio
purposes. Do NOT deploy it anywhere reachable from the internet.

Vulnerabilities (see docs/vulnerabilities-found.md):
  VULN-01  SQL injection in /login             (CWE-89)
  VULN-02  SQL injection in /search            (CWE-89)
  VULN-03  Reflected XSS in /search            (CWE-79)
  VULN-04  IDOR in /user/<id>                  (CWE-639)
  VULN-05  Hard-coded secret key               (CWE-798)
  VULN-06  No rate limiting on /login          (CWE-307)
  VULN-07  Debug mode enabled                  (CWE-489)
  VULN-08  Missing security headers            (CWE-693)
"""
import os

from flask import Flask, redirect, render_template, request, session, url_for

from database import get_db, init_db

app = Flask(__name__)

# VULN-05: Hard-coded secret key - anyone who reads the source can forge sessions.
app.config["SECRET_KEY"] = "supersecret123"


# VULN-08: No security headers are ever set (no CSP, X-Frame-Options,
# X-Content-Type-Options, HSTS...). There is deliberately no after_request hook.


@app.route("/")
def index():
    return render_template("index.html", user=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    # VULN-06: No rate limiting or account lockout - unlimited brute-force attempts.
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULN-01: SQL injection - user input concatenated straight into SQL.
        # Payload: username = admin' --   (password: anything)
        query = (
            "SELECT * FROM users WHERE username = '" + username +
            "' AND password = '" + password + "'"
        )
        conn = get_db()
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["username"], user_id=session["user_id"])


@app.route("/search")
def search():
    q = request.args.get("q", "")

    # VULN-02: SQL injection - LIKE clause built with string formatting.
    # Payload: ' UNION SELECT id, username, password, email FROM users --
    query = "SELECT id, name, description, price FROM products WHERE name LIKE '%" + q + "%'"
    conn = get_db()
    try:
        results = conn.execute(query).fetchall()
    except Exception as exc:  # leaks DB error details to the user
        results = []
        q = f"{q} (error: {exc})"
    finally:
        conn.close()

    # VULN-03: Reflected XSS - the raw query is passed with |safe in the template,
    # disabling Jinja2 auto-escaping. Payload: <script>alert(document.cookie)</script>
    return render_template("search.html", query=q, results=results)


@app.route("/user/<int:user_id>")
def user_profile(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # VULN-04: IDOR - checks the user is logged in, but NOT that they own this record.
    # Any user can read /user/1 (admin) including balance and secret note.
    conn = get_db()
    user = conn.execute(
        "SELECT id, username, email, role, account_balance, secret_note FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()
    if not user:
        return "User not found", 404
    return dict(user)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    if not os.path.exists(os.environ.get("DB_PATH", "vulnapp.db")):
        init_db()
    # VULN-07: Debug mode ON + bound to all interfaces. The Werkzeug debugger
    # allows arbitrary code execution from the browser if the PIN is obtained.
    app.run(host="0.0.0.0", port=5000, debug=True)
