import json
import os
import sqlite3
import tempfile
from flask import Flask, request, make_response, redirect, g

app = Flask(__name__)
DB_PATH = os.path.join(tempfile.gettempdir(), "test_target.db")

STATE_PATH = os.environ.get(
    "STATE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_state.json")
)

VULN_KEYS = [
    "sqli",
    "xss",
    "missing_headers",
    "insecure_cookies",
    "open_redirect",
    "path_enum",
    "traversal",
    "csrf",
]


def env_default(name, default="0"):
    # FIX: default changed from "1" to "0". Previously, if the state file
    # was missing (e.g. ephemeral disk reset on redeploy/restart/new
    # instance), every vuln silently defaulted back to ON. Now, if state
    # is ever lost, the app fails SAFE (patched) instead of fails OPEN
    # (vulnerable). An explicit env var (VULN_SQLI=1, etc.) still overrides.
    return os.environ.get(f"VULN_{name.upper()}", default) == "1"


def load_state():
    """
    Load toggle state with this precedence:
      1. Explicit env var (VULN_SQLI=1/0, etc.) always wins if set -- this
         lets you pin state via Render's dashboard, which is consistent
         across every instance and survives redeploys with zero disk needed.
      2. Saved state file, if present and readable.
      3. env_default fallback (now "0" / patched) if neither is available.
    """
    saved = {}
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH) as f:
                saved = json.load(f)
        except (json.JSONDecodeError, OSError):
            saved = {}

    state = {}
    for key in VULN_KEYS:
        env_name = f"VULN_{key.upper()}"
        if env_name in os.environ:
            # Explicit env var always takes precedence over the file,
            # so Render dashboard config can't be silently overridden
            # by a stale/leftover state file.
            state[key] = os.environ[env_name] == "1"
        elif key in saved:
            state[key] = bool(saved[key])
        else:
            state[key] = env_default(key)
    return state


def save_state():
    """
    Persist state atomically (write to temp file, then rename) so a crash
    or concurrent request mid-write can't corrupt the JSON and force a
    fallback to defaults.

    NOTE: on platforms with ephemeral local disks (e.g. Render without a
    Persistent Disk, or any multi-instance/autoscaled deployment), this
    file is NOT a reliable source of truth across restarts or across
    instances. Prefer setting VULN_<KEY> env vars in the platform's
    dashboard for anything you need to survive redeploys or be consistent
    across instances -- this file-based save is best-effort/local only.
    """
    try:
        tmp_path = f"{STATE_PATH}.tmp"
        with open(tmp_path, "w") as f:
            json.dump(VULNS, f, indent=2)
        os.replace(tmp_path, STATE_PATH)
    except OSError as e:
        print(f"Warning: could not persist state to {STATE_PATH}: {e}")


VULNS = load_state()

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
    if not VULNS["missing_headers"]:
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


PANEL_PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Test Target - Vulnerability Toggles</title>
<style>
  :root {{
    --bg: #0f1220;
    --panel: #171b2e;
    --panel-border: #262b45;
    --text: #e6e8f0;
    --muted: #9aa0b4;
    --danger: #ff5470;
    --danger-bg: rgba(255, 84, 112, 0.08);
    --safe: #35d0a1;
    --safe-bg: rgba(53, 208, 161, 0.08);
    --accent: #7c8cff;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 40px 20px;
    background: radial-gradient(circle at top, #1a1f38, var(--bg) 60%);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
  }}
  .wrap {{ max-width: 880px; margin: 0 auto; }}
  h1 {{
    font-size: 26px;
    margin: 0 0 4px;
    letter-spacing: -0.01em;
  }}
  .subtitle {{
    color: var(--muted);
    margin: 0 0 28px;
    font-size: 14px;
  }}
  .banner {{
    background: rgba(124, 140, 255, 0.08);
    border: 1px solid rgba(124, 140, 255, 0.3);
    color: var(--text);
    border-radius: 10px;
    padding: 12px 16px;
    font-size: 13px;
    line-height: 1.5;
    margin-bottom: 20px;
  }}
  .card {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 14px;
    overflow: hidden;
    box-shadow: 0 20px 40px -20px rgba(0,0,0,0.5);
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--muted);
    padding: 14px 18px;
    border-bottom: 1px solid var(--panel-border);
  }}
  tbody tr {{
    border-bottom: 1px solid var(--panel-border);
    transition: background 0.15s ease;
  }}
  tbody tr:last-child {{ border-bottom: none; }}
  tbody tr.vuln-on {{ background: var(--danger-bg); }}
  tbody tr.vuln-off {{ background: var(--safe-bg); }}
  tbody tr:hover {{ filter: brightness(1.08); }}
  td {{ padding: 14px 18px; vertical-align: middle; font-size: 14px; }}
  .name {{ font-weight: 600; }}
  .desc {{ color: var(--muted); font-size: 13px; line-height: 1.4; }}
  .status {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 4px 10px;
    border-radius: 999px;
  }}
  .status.on {{ color: var(--danger); background: rgba(255,84,112,0.15); }}
  .status.off {{ color: var(--safe); background: rgba(53,208,161,0.15); }}
  .status .dot {{ width: 6px; height: 6px; border-radius: 50%; background: currentColor; }}
  a.test-link {{
    color: var(--accent);
    text-decoration: none;
    font-size: 13px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  }}
  a.test-link:hover {{ text-decoration: underline; }}

  .switch {{
    position: relative;
    display: inline-block;
    width: 42px;
    height: 24px;
  }}
  .switch input {{ opacity: 0; width: 0; height: 0; }}
  .switch input:disabled + .slider {{ opacity: 0.4; cursor: not-allowed; }}
  .slider {{
    position: absolute;
    cursor: pointer;
    inset: 0;
    background-color: #3a3f5c;
    transition: 0.2s;
    border-radius: 999px;
  }}
  .slider::before {{
    position: absolute;
    content: "";
    height: 18px;
    width: 18px;
    left: 3px;
    bottom: 3px;
    background-color: white;
    transition: 0.2s;
    border-radius: 50%;
  }}
  .switch input:checked + .slider {{ background-color: var(--danger); }}
  .switch input:checked + .slider::before {{ transform: translateX(18px); }}

  .footer-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 20px;
  }}
  button.save {{
    background: var(--accent);
    color: white;
    border: none;
    padding: 10px 22px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: filter 0.15s ease;
  }}
  button.save:hover {{ filter: brightness(1.1); }}
  button.save:disabled {{ opacity: 0.4; cursor: not-allowed; }}
  .state-link {{
    color: var(--muted);
    font-size: 13px;
    text-decoration: none;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  }}
  .state-link:hover {{ color: var(--accent); }}
  .persist-note {{
    color: var(--muted);
    font-size: 12px;
    margin-top: 16px;
    line-height: 1.5;
  }}
  code {{
    background: rgba(255,255,255,0.06);
    padding: 1px 5px;
    border-radius: 4px;
    font-size: 11px;
  }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Test Target</h1>
  <p class="subtitle">Toggle a vulnerability on to make it exploitable, off to patch it. Saved automatically.</p>

  {env_banner}

  <form method="post" action="/_toggle_form">
    <div class="card">
      <table>
        <thead>
          <tr><th style="width:60px;">On</th><th>Vulnerability</th><th style="width:38%;">Description</th><th style="width:110px;">Status</th><th>Test link</th></tr>
        </thead>
        <tbody>
{rows}
        </tbody>
      </table>
      <div class="footer-row">
        <a class="state-link" href="/_state">/_state (JSON ground truth)</a>
        <button class="save" type="submit">Save changes</button>
      </div>
    </div>
  </form>
  <p class="persist-note">
    State is persisted to <code>{state_path}</code> and reloaded on startup. On platforms with
    ephemeral disks (e.g. Render without a Persistent Disk, or multiple/autoscaled instances),
    this file is best-effort only -- set <code>VULN_&lt;KEY&gt;</code> environment variables
    (e.g. <code>VULN_SQLI=0</code>) in your platform's dashboard for state that reliably survives
    restarts and is consistent across every instance. Env vars always take precedence over the
    saved file. Missing/unset state now defaults to <b>patched</b>, not vulnerable.
  </p>
</div>
</body>
</html>
"""

ROW_TEMPLATE = """<tr class="{row_class}">
  <td>
    <label class="switch">
      <input type="checkbox" name="{key}" {checked} {disabled}>
      <span class="slider"></span>
    </label>
  </td>
  <td class="name">{label}</td>
  <td class="desc">{desc}</td>
  <td><span class="status {status_class}"><span class="dot"></span>{status_text}</span></td>
  <td><a class="test-link" href="{test}" target="_blank">{test_label}</a></td>
</tr>
"""


def _env_locked_keys():
    """Keys whose state is pinned by an explicit env var (can't be toggled via UI)."""
    return {key for key in VULN_KEYS if f"VULN_{key.upper()}" in os.environ}


@app.route("/")
def index():
    locked = _env_locked_keys()
    rows = ""
    for key, meta in VULN_META.items():
        is_on = VULNS[key]
        rows += ROW_TEMPLATE.format(
            key=key,
            checked="checked" if is_on else "",
            disabled="disabled" if key in locked else "",
            label=meta["label"] + (" 🔒" if key in locked else ""),
            desc=meta["desc"],
            test=meta["test"],
            test_label=meta["test_label"],
            row_class="vuln-on" if is_on else "vuln-off",
            status_class="on" if is_on else "off",
            status_text="Vulnerable" if is_on else "Patched",
        )
    env_banner = ""
    if locked:
        env_banner = (
            '<div class="banner">🔒 '
            + ", ".join(VULN_META[k]["label"] for k in sorted(locked))
            + " are pinned by environment variables and can't be changed from this UI."
            " Update the corresponding VULN_&lt;KEY&gt; env var in your platform's"
            " dashboard to change them.</div>"
        )
    return PANEL_PAGE.format(rows=rows, state_path=STATE_PATH, env_banner=env_banner)


@app.route("/_toggle_form", methods=["POST"])
def toggle_form():
    locked = _env_locked_keys()
    for key in VULNS:
        if key in locked:
            continue  # env var wins; don't let a form post silently override it
        VULNS[key] = key in request.form
    save_state()
    return redirect("/")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    cur = g.db.cursor()
    if VULNS["sqli"]:
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
        return redirect(nxt)
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
        path = os.path.join(base, name)
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
    print("State file:", STATE_PATH)
    print("Active vulnerabilities:", {k: v for k, v in VULNS.items() if v})
    print("Disabled (fixed):", {k: v for k, v in VULNS.items() if not v})
    port = int(os.environ.get("PORT", 5000))
    host = "0.0.0.0" if "PORT" in os.environ else "127.0.0.1"
    app.run(host=host, port=port, debug=False)
