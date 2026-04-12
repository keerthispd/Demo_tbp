from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

from flask import Flask, redirect, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cryptosafe.db"
LOCKOUT_DURATION = timedelta(hours=24)
MAX_FAILED_ATTEMPTS = 5

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                userid TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                last_failed_at TEXT
            )
            """
        )

        existing_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "failed_attempts" not in existing_columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0"
            )
        if "locked_until" not in existing_columns:
            conn.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
        if "last_failed_at" not in existing_columns:
            conn.execute("ALTER TABLE users ADD COLUMN last_failed_at TEXT")


def build_url(path: str, **params: str) -> str:
    query = urlencode({key: value for key, value in params.items() if value is not None})
    return f"{path}?{query}" if query else path


def build_landing_url(status: str, reason: str | None = None) -> str:
    return build_url("/landing.html", status=status, reason=reason)


def build_registration_url(error: str | None = None) -> str:
    return build_url("/registration.html", error=error)


def build_login_url(error: str | None = None) -> str:
    return build_url("/login.html", error=error)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


@app.before_request
def ensure_database_ready() -> None:
    init_db()


@app.get("/")
def home():
    if session.get("user_id"):
        return redirect("/dashboard.html")
    return redirect("/login.html")


@app.get("/registration.html")
def registration_page():
    response = send_from_directory(BASE_DIR, "registration.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/login.html")
def login_page():
    response = send_from_directory(BASE_DIR, "login.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/landing.html")
def landing_page():
    response = send_from_directory(BASE_DIR, "landing.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/dashboard.html")
def dashboard_page():
    if not session.get("user_id"):
        return redirect(build_login_url("Please sign in to access the dashboard."))

    response = send_from_directory(BASE_DIR, "dashboard.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/logout")
def logout():
    session.clear()
    return redirect(build_login_url("You have been signed out."))


@app.post("/register")
def register_user():
    userid = (request.form.get("userid") or "").strip()
    password = request.form.get("password") or ""

    if not userid or not password:
        return redirect(build_registration_url("User ID and password are required."))

    if len(userid) < 3 or len(password) < 6:
        return redirect(
            build_registration_url(
                "User ID must be at least 3 characters and password at least 6 characters."
            )
        )

    password_hash = generate_password_hash(password)
    created_at = now_utc().isoformat()

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO users (userid, password_hash, created_at) VALUES (?, ?, ?)",
                (userid, password_hash, created_at),
            )
    except sqlite3.IntegrityError:
        return redirect(build_registration_url("User ID already taken"))
    except sqlite3.Error:
        return redirect(build_registration_url("Database error. Please retry."))

    return redirect(build_landing_url("success"))


@app.post("/login")
def login_user():
    userid = (request.form.get("userid") or "").strip()
    password = request.form.get("password") or ""

    if not userid or not password:
        return redirect(build_login_url("User ID and password are required."))

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            user = conn.execute(
                """
                SELECT userid, password_hash, failed_attempts, locked_until
                FROM users
                WHERE userid = ?
                """,
                (userid,),
            ).fetchone()

            if user is None:
                return redirect(build_login_url("Invalid user ID or password."))

            locked_until = parse_utc(user["locked_until"])
            current_time = now_utc()
            if locked_until and locked_until > current_time:
                remaining_hours = max(1, int((locked_until - current_time).total_seconds() // 3600))
                return redirect(
                    build_login_url(
                        f"Account locked for 24 hours after too many failed attempts. Try again in about {remaining_hours} hour(s)."
                    )
                )

            if check_password_hash(user["password_hash"], password):
                conn.execute(
                    """
                    UPDATE users
                    SET failed_attempts = 0,
                        locked_until = NULL,
                        last_failed_at = NULL
                    WHERE userid = ?
                    """,
                    (userid,),
                )
                session["user_id"] = userid
                return redirect("/dashboard.html")

            failed_attempts = int(user["failed_attempts"] or 0) + 1
            lock_until_value = None
            message = "Invalid user ID or password."

            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                lock_until = current_time + LOCKOUT_DURATION
                lock_until_value = lock_until.isoformat()
                failed_attempts = MAX_FAILED_ATTEMPTS
                message = "Account locked for 24 hours after too many failed attempts."
            else:
                remaining_attempts = MAX_FAILED_ATTEMPTS - failed_attempts
                message = (
                    f"Invalid user ID or password. {remaining_attempts} attempt(s) left before a 24-hour lock."
                )

            conn.execute(
                """
                UPDATE users
                SET failed_attempts = ?,
                    locked_until = ?,
                    last_failed_at = ?
                WHERE userid = ?
                """,
                (failed_attempts, lock_until_value, current_time.isoformat(), userid),
            )

    except sqlite3.Error:
        return redirect(build_login_url("Database error. Please retry."))

    return redirect(build_login_url(message))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)