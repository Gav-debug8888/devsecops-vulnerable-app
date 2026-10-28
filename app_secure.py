"""
VulnShop - remediated version (branch: fix/ai-security-remediation).

Every finding from docs/vulnerabilities-found.md is patched here. See
docs/fixes-applied.md for before/after explanations.
"""
import hmac
import logging
import os
from functools import wraps

from flask import Flask, abort, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

from database import get_db, init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

app = Flask(__name__)

# VULN-05 fix: secret loaded from the environment, fail closed if missing/weak.
secret_key = os.environ.get("SECRET_KEY")
if not secret_key or len(secret_key) < 32:
    raise RuntimeError("SECRET_KEY environment variable must be set (>= 32 chars)")
app.config["SECRET_KEY"] = secret_key

FORCE_HTTPS = os.environ.get("FORCE_HTTPS", "false").lower() == "true"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=FORCE_HTTPS,
)

# VULN-08 fix: security headers (CSP, X-Frame-Options, nosniff, HSTS, Referrer-Policy).
Talisman(
    app,
    force_https=FORCE_HTTPS,
    strict_transport_security=True,
    content_security_policy={
        "default-src": "'self'",
        "script-src": "'self'",
        "style-src": "'self'",
        "frame-ancestors": "'none'",
    },
    frame_options="DENY",
    referrer_policy="strict-origin-when-cross-origin",
)

# VULN-06 fix: rate limiting.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return render_template("index.html", user=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")[:64]
        password = request.form.get("password", "")[:128]

        # VULN-01 fix: parameterised query + constant-time comparison.
        conn = get_db()
        user = conn.execute(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        if user and hmac.compare_digest(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            app.logger.info("login_success user=%s ip=%s", user["username"], request.remote_addr)
            return redirect(url_for("dashboard"))
        app.logger.warning("login_failure ip=%s", request.remote_addr)
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session["username"], user_id=session["user_id"])


@app.route("/search")
def search():
    q = request.args.get("q", "")[:100]

    # VULN-02 fix: parameterised LIKE, generic error message.
    conn = get_db()
    try:
        results = conn.execute(
            "SELECT id, name, description, price FROM products WHERE name LIKE ?",
            (f"%{q}%",),
        ).fetchall()
    except Exception:
        app.logger.exception("search query failed")
        results = []
    finally:
        conn.close()

    # VULN-03 fix: template without |safe -> Jinja2 auto-escaping applies.
    return render_template("search_secure.html", query=q, results=results)


@app.route("/user/<int:user_id>")
@login_required
def user_profile(user_id):
    # VULN-04 fix: object-level authorisation.
    if user_id != session["user_id"] and session.get("role") != "admin":
        app.logger.warning("idor_attempt user=%s requested=%s", session["user_id"], user_id)
        abort(403)

    conn = get_db()
    user = conn.execute(
        "SELECT id, username, email, role, account_balance, secret_note FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()
    if not user:
        abort(404)
    return dict(user)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    if not os.path.exists(os.environ.get("DB_PATH", "vulnapp.db")):
        init_db()
    # VULN-07 fix: debug off, localhost by default. Use gunicorn in production.
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=5000, debug=False)
