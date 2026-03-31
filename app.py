from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from flask import Flask, redirect, render_template_string, request, send_from_directory
from werkzeug.security import generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cryptosafe.db"

app = Flask(__name__)


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                userid TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


def build_landing_url(status: str, reason: str | None = None) -> str:
    params = {"status": status}
    if reason:
        params["reason"] = reason
    return f"/landing.html?{urlencode(params)}"


@app.get("/")
def home():
    return redirect("/registration.html")


@app.get("/registration.html")
def registration_page():
    return send_from_directory(BASE_DIR, "registration.html")


@app.get("/landing.html")
def landing_page():
    return send_from_directory(BASE_DIR, "landing.html")


@app.post("/register")
def register_user():
    userid = (request.form.get("userid") or "").strip()
    password = request.form.get("password") or ""

    if not userid or not password:
        return redirect(build_landing_url("fail", "User ID and password are required."))

    if len(userid) < 3 or len(password) < 6:
        return redirect(
            build_landing_url(
                "fail",
                "User ID must be at least 3 chars and password at least 6 chars.",
            )
        )

    password_hash = generate_password_hash(password)
    created_at = datetime.now(timezone.utc).isoformat()

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO users (userid, password_hash, created_at) VALUES (?, ?, ?)",
                (userid, password_hash, created_at),
            )
    except sqlite3.IntegrityError:
        return redirect(
            build_landing_url("fail", "This user ID already exists. Please choose another.")
        )
    except sqlite3.Error:
        return redirect(build_landing_url("fail", "Database error. Please retry."))

    return redirect(build_landing_url("success"))


@app.get("/users")
def list_users():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT userid, password_hash, created_at FROM users ORDER BY id DESC"
            ).fetchall()
    except sqlite3.Error:
        return "Failed to fetch users.", 500

    return render_template_string(
        """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>Stored Users</title>
          <style>
            body { font-family: "Segoe UI", sans-serif; padding: 20px; background: #f8fafc; color: #1e293b; }
            h1 { margin-top: 0; }
            table { width: 100%; border-collapse: collapse; background: #fff; }
            th, td { border: 1px solid #dbe2ea; padding: 10px; text-align: left; }
            th { background: #e2e8f0; }
            a { display: inline-block; margin-top: 12px; color: #0369a1; font-weight: 600; }
          </style>
        </head>
        <body>
          <h1>Users in Database</h1>
          <table>
            <thead>
              <tr>
                <th>User ID</th>
                <th>Password Hash</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              {% if rows %}
                {% for row in rows %}
                <tr>
                  <td>{{ row['userid'] }}</td>
                  <td style="word-break: break-all;">{{ row['password_hash'] }}</td>
                  <td>{{ row['created_at'] }}</td>
                </tr>
                {% endfor %}
              {% else %}
                <tr><td colspan="3">No users found.</td></tr>
              {% endif %}
            </tbody>
          </table>
          <a href="/registration.html">Back to Registration</a>
        </body>
        </html>
        """,
        rows=rows,
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
