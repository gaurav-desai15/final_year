"""A small, deliberately vulnerable Flask app used as a worked example.

The point of this example is that a single-function scanner can't tell
`run_diagnostic` apart from a safe use of it -- the danger only shows up
once you look at *who calls it and with what*. That's exactly the
distinction cpgvd's LLM step is supposed to make using CPG-derived
call-graph context.
"""

import os

from flask import Flask, request

app = Flask(__name__)

# A fixed, developer-controlled allowlist of diagnostics that are safe to run.
ALLOWED_DIAGNOSTICS = {
    "disk": "df -h",
    "memory": "free -m",
    "uptime": "uptime",
}


def run_diagnostic(command: str) -> str:
    """Runs a shell diagnostic command and returns its output.

    This function is not inherently safe or unsafe -- it depends entirely
    on where `command` comes from.
    """
    return os.popen(command).read()


@app.route("/status/<name>")
def status(name: str):
    """SAFE: `name` is validated against a fixed allowlist before it ever
    reaches `run_diagnostic`, so no attacker-controlled string reaches the
    shell regardless of what `run_diagnostic` itself looks like."""
    if name not in ALLOWED_DIAGNOSTICS:
        return "unknown diagnostic", 400
    return run_diagnostic(ALLOWED_DIAGNOSTICS[name])


@app.route("/admin/run")
def admin_run():
    """VULNERABLE (CWE-78): the `cmd` query parameter goes straight into
    `run_diagnostic` -> `os.popen`, with no allowlist, no shell=False
    argument list, nothing. A CPG scan of `run_diagnostic` alone can't see
    this -- it has to walk up to this caller to see that user input reaches
    it unsanitized."""
    cmd = request.args.get("cmd", "uptime")
    return run_diagnostic(cmd)


def build_user_query(user_id: str) -> str:
    """VULNERABLE (CWE-89) when called with untrusted input: builds a SQL
    string via concatenation instead of parameter binding."""
    return f"SELECT * FROM users WHERE id = {user_id}"


@app.route("/users/<user_id>")
def get_user(user_id: str):
    import sqlite3

    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # VULNERABLE: user_id (attacker-controlled path segment) flows into a
    # concatenated SQL string and then straight into cursor.execute.
    query = build_user_query(user_id)
    cur.execute(query)
    return str(cur.fetchall())


@app.route("/users/safe/<int:user_id>")
def get_user_safe(user_id: int):
    import sqlite3

    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # SAFE: parameterized query, and Flask's <int:...> converter already
    # rejects anything that isn't an integer before this code even runs.
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(cur.fetchall())


if __name__ == "__main__":
    app.run(debug=True)
