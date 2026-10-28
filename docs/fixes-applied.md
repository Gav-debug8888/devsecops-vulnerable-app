# Fixes Applied: AI-Assisted Remediation

| Field | Value |
|-------|-------|
| Branch | `fix/ai-security-remediation` |
| PR title | `fix(security): AI-assisted remediation — patch SQLi, XSS, IDOR, secrets` |
| Fixed file | `app_secure.py`. The original `app.py` is kept on `main` for training comparison. |
| New dependencies | `Flask-Limiter`, `Flask-Talisman` |

All 8 findings in [`vulnerabilities-found.md`](vulnerabilities-found.md) were fixed. Each proof of concept was re-run against `app_secure.py` and no longer works.

| ID | Status | Fix |
|----|--------|-----|
| VULN-01 | ✅ Fixed | Parameterised query |
| VULN-02 | ✅ Fixed | Parameterised `LIKE` + generic error |
| VULN-03 | ✅ Fixed | `\|safe` removed from the template rendered by the secure app, so auto-escaping applies |
| VULN-04 | ✅ Fixed | Object-level authorisation check |
| VULN-05 | ✅ Fixed | `SECRET_KEY` from environment, fail-closed |
| VULN-06 | ✅ Fixed | Flask-Limiter `5 per minute` on `/login` |
| VULN-07 | ✅ Fixed | `debug=False`, bound to `127.0.0.1` by default |
| VULN-08 | ✅ Fixed | Flask-Talisman headers + hardened cookies |

---

## VULN-01: SQL injection in `/login`

**Why:** Parameter binding sends user input to SQLite as data, never as SQL. This makes `admin' --` a literal (and wrong) username.

```python
# Before
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
user = conn.execute(query).fetchone()
```
```python
# After
user = conn.execute(
    "SELECT id, username, password, role FROM users WHERE username = ?",
    (username,),
).fetchone()
if user and hmac.compare_digest(user["password"], password):
    ...
```
`hmac.compare_digest` also prevents timing attacks on the comparison. *Follow-up:* move to bcrypt hashes (tracked separately).

## VULN-02: SQL injection in `/search`

```python
# Before
query = "SELECT ... FROM products WHERE name LIKE '%" + q + "%'"
```
```python
# After
q = request.args.get("q", "")[:100]
results = conn.execute(
    "SELECT id, name, description, price FROM products WHERE name LIKE ?",
    (f"%{q}%",),
).fetchall()
```
Input is length-capped. Database errors are logged on the server and a generic message is returned to the user.

## VULN-03: Reflected XSS in `/search`

**Why:** Jinja2 escapes `<`, `>`, `&`, `"` and `'` by default. The `|safe` filter turned that off.

```html
<!-- Before (templates/search.html) -->
<p>Results for: {{ query|safe }}</p>
```
```html
<!-- After (templates/search_secure.html) -->
<p>Results for: {{ query }}</p>
```
The CSP from VULN-08 (`script-src 'self'`) blocks inline script even if an escaping bug is introduced later.

## VULN-04: IDOR in `/user/<id>`

```python
# Before
user = conn.execute("SELECT ... WHERE id = ?", (user_id,)).fetchone()
return dict(user)
```
```python
# After
@login_required
def user_profile(user_id):
    if user_id != session["user_id"] and session.get("role") != "admin":
        app.logger.warning("IDOR attempt: user %s requested %s", session["user_id"], user_id)
        abort(403)
```
A reusable `login_required` decorator now protects `/dashboard` and `/user/<id>`.

## VULN-05: Hard-coded secret key

```python
# Before
app.config["SECRET_KEY"] = "supersecret123"
```
```python
# After
secret_key = os.environ.get("SECRET_KEY")
if not secret_key or len(secret_key) < 32:
    raise RuntimeError("SECRET_KEY environment variable must be set (>= 32 chars)")
app.config["SECRET_KEY"] = secret_key
```
The old key must be treated as compromised and rotated in every environment.

## VULN-06: No rate limiting

```python
# After
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"], storage_uri="memory://")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    ...
```
Clients that go over the limit get HTTP 429. Failed logins are logged for detection. For multi-instance deployments use Redis (`storage_uri="redis://..."`).

## VULN-07: Debug mode

```python
# Before
app.run(host="0.0.0.0", port=5000, debug=True)
```
```python
# After
app.run(host=os.environ.get("HOST", "127.0.0.1"), port=5000, debug=False)
```
In production, run it with `gunicorn app_secure:app` instead.

## VULN-08: Missing security headers

```python
# After
Talisman(
    app,
    force_https=os.environ.get("FORCE_HTTPS", "false").lower() == "true",
    strict_transport_security=True,
    content_security_policy={"default-src": "'self'", "script-src": "'self'",
                             "style-src": "'self'", "frame-ancestors": "'none'"},
    frame_options="DENY",
    referrer_policy="strict-origin-when-cross-origin",
)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("FORCE_HTTPS", "false").lower() == "true")
```

Verification:
```bash
curl -sI http://127.0.0.1:5000/ | grep -iE "content-security|x-frame|x-content-type"
# Content-Security-Policy: default-src 'self'; ...
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
```

---

## Lessons learned: reviewing AI-suggested code
- The AI's first suggestion for VULN-04 compared `str(user_id)` with an `int` session value. That check would always fail and lock admins out. It was caught in manual review.
- The AI first suggested `force_https=True`, which breaks local HTTP testing. It was changed to an environment toggle.
- The AI missed the template-level XSS sink until the template was included in the context. **Always give the AI the full data flow, from source to sink.**
