import os
import sqlite3
import tempfile
from flask import Flask, request, make_response, redirect, g

app = Flask(__name__)
DB_PATH = os.path.join(tempfile.gettempdir(), "test_target.db")


def flag(name, default="1"):
    return os.environ.get(f"VULN_{name.upper()}", default) == "1"


VULNS = {
    "sqli": flag("sqli"),
    "xss": flag("xss"),
    "missing_headers": flag("missing_headers"),
    "insecure_cookies": flag("insecure_cookies"),
    "open_redirect": flag("open_redirect"),
    "path_enum": flag("path_enum"),
    "traversal": flag("traversal"),
    "csrf": flag("csrf"),
}

VULN_META = {
    "sqli": {
        "label": "SQL Injection",
        "desc": "Search box concatenates input straight into the query.",
        "test": "/search?q=%25%27%20OR%20%271%27%3D%271",
        "test_label": "/search?q=' OR '1'='1",
    },
    "xss": {
        "label": "Reflected XSS",
        "desc": "Name param is echoed into the page without escaping.",
        "test": "/greet?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "test_label": "/greet?name=<script>alert(1)</script>",
    },
    "missing_headers": {
        "label": "Missing Security Headers",
        "desc": "Response drops CSP, X-Frame-Options, HSTS, nosniff.",
        "test": "/",
        "test_label": "/ (check response headers)",
    },
    "insecure_cookies": {
        "label": "Insecure Cookies",
        "desc": "Session cookie set without HttpOnly/Secure/SameSite.",
        "test": "/login",
        "test_label": "/login (POST, check Set-Cookie)",
    },
    "open_redirect": {
        "label": "Open Redirect",
        "desc": "next= param redirects anywhere, no allowlist check.",
        "test": "/redirect?next=https://example.com",
        "test_label": "/redirect?next=https://example.com",
    },
    "path_enum": {
        "label": "Path Enumeration",
        "desc": "/admin is reachable with no auth check.",
        "test": "/admin",
        "test_label": "/admin",
    },
    "traversal": {
        "label": "Directory Traversal",
        "desc": "/files/<name> doesn't strip ../ from the path.",
        "test": "/files/..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "test_label": "/files/../../../../etc/passwd",
    },
    "csrf": {
        "label": "CSRF",
        "desc": "/transfer accepts POSTs with no token check.",
        "test": "/transfer",
        "test_label": "/transfer (POST, no csrf_token)",
    },
}


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.executemany(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [("admin", "sup3rsecret"), ("guest", "guest123")],
    )
    conn.commit()
    conn.close()


@app.before_request
def _open_db():
    g.db = sqlite3.connect(DB_PATH)


@app.after_request
def apply_headers_and_cookies(resp):
    # Security headers toggle
    if not VULNS["missing_headers"]:
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    # else: leave them off entirely -> scanner should flag missing headers

    return resp


PANEL_PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Test Target - Vulnerability Toggles</title>
</head>
<body>
<h1>Test Target</h1>
<p>Check a box to turn a vulnerability ON. Uncheck to turn it OFF (patched). Click Save.</p>

<form method="post" action="/_toggle_form">
<table border="1" cellpadding="6" cellspacing="0">
<tr><th>On?</th><th>Vulnerability</th><th>Description</th><th>Test link</th></tr>
{rows}
</table>
<br>
<button type="submit">Save</button>
</form>

<p>Scanner ground truth: <a href="/_state">/_state</a> (JSON)</p>
</body>
</html>
"""

ROW_TEMPLATE = """<tr>
<td><input type="checkbox" name="{key}" {checked}></td>
<td>{label}</td>
<td>{desc}</td>
<td><a href="{test}" target="_blank">{test_label}</a></td>
</tr>
"""


@app.route("/")
def index():
    rows = ""
    for key, meta in VULN_META.items():
        rows += ROW_TEMPLATE.format(
            key=key,
            checked="checked" if VULNS[key] else "",
            label=meta["label"],
            desc=meta["desc"],
            test=meta["test"],
            test_label=meta["test_label"],
        )
    return PANEL_PAGE.format(rows=rows)


@app.route("/_toggle_form", methods=["POST"])
def toggle_form():
    for key in VULNS:
        VULNS[key] = key in request.form
    return redirect("/")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    cur = g.db.cursor()
    if VULNS["sqli"]:
        # intentionally vulnerable - string concatenation
        query = f"SELECT id, username FROM users WHERE username LIKE '%{q}%'"
        try:
            cur.execute(query)
        except sqlite3.Error as e:
            return f"DB error: {e}", 500
    else:
        cur.execute("SELECT id, username FROM users WHERE username LIKE ?", (f"%{q}%",))
    rows = cur.fetchall()
    return {"query_echo": q, "results": rows}


@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    if VULNS["xss"]:
        # intentionally unescaped
        return f"<h2>Hello, {name}!</h2>"
    from markupsafe import escape
    return f"<h2>Hello, {escape(name)}!</h2>"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
        <form method="post">
          <input name="username"><input name="password" type="password">
          <button>Login</button>
        </form>
        """
    resp = make_response("logged in")
    if VULNS["insecure_cookies"]:
        resp.set_cookie("session", "fake-session-token", httponly=False, secure=False, samesite=None)
    else:
        resp.set_cookie("session", "fake-session-token", httponly=True, secure=True, samesite="Strict")
    return resp


@app.route("/redirect")
def open_redirect():
    nxt = request.args.get("next", "/")
    if VULNS["open_redirect"]:
        return redirect(nxt)  # unvalidated
    if nxt.startswith("/") and not nxt.startswith("//"):
        return redirect(nxt)
    return redirect("/")


@app.route("/files/<path:name>")
def files(name):
    base = os.path.join(tempfile.gettempdir(), "test_target_files")
    os.makedirs(base, exist_ok=True)
    sample = os.path.join(base, "report.txt")
    if not os.path.exists(sample):
        with open(sample, "w") as f:
            f.write("sample report contents\n")
    if VULNS["traversal"]:
        path = os.path.join(base, name)  # no sanitization
    else:
        safe_name = os.path.basename(name)
        path = os.path.join(base, safe_name)
    try:
        with open(path) as f:
            return f.read()
    except Exception as e:
        return f"error: {e}", 404


@app.route("/admin")
def admin():
    if VULNS["path_enum"]:
        return "Admin panel (unauthenticated access)", 200
    return "Not found", 404


@app.route("/transfer", methods=["POST"])
def transfer():
    if VULNS["csrf"]:
        # no CSRF token check
        return {"status": "transferred", "amount": request.form.get("amount")}
    token = request.form.get("csrf_token")
    if token != "expected-token-abc123":
        return {"error": "invalid csrf token"}, 403
    return {"status": "transferred", "amount": request.form.get("amount")}


@app.route("/_state")
def state():
    return VULNS


if __name__ == "__main__":
    init_db()
    print("Active vulnerabilities:", {k: v for k, v in VULNS.items() if v})
    print("Disabled (fixed):", {k: v for k, v in VULNS.items() if not v})
    port = int(os.environ.get("PORT", 5000))
    host = "0.0.0.0" if "PORT" in os.environ else "127.0.0.1"
    app.run(host=host, port=port, debug=False)
