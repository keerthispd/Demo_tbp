from __future__ import annotations

import base64
import hashlib
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, redirect, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cryptosafe.db"
USER_FILES_DIR = BASE_DIR / "vault_files"
LOCKOUT_DURATION = timedelta(hours=24)
MAX_FAILED_ATTEMPTS = 3

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")


def _key_from_env_or_secret() -> bytes:
    env_key = os.environ.get("DATA_ENCRYPTION_KEY", "").strip()
    if env_key:
        padded = env_key + ("=" * (-len(env_key) % 4))
        try:
            decoded = base64.urlsafe_b64decode(padded)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass

        raw = env_key.encode("utf-8")
        if len(raw) == 32:
            return raw

    return hashlib.sha256(app.config["SECRET_KEY"].encode("utf-8")).digest()


AES_256_KEY = _key_from_env_or_secret()


def encrypt_text(plain_text: str) -> str:
    aes = AESGCM(AES_256_KEY)
    nonce = os.urandom(12)
    cipher = aes.encrypt(nonce, plain_text.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + cipher).decode("ascii")


def decrypt_text(encoded_text: str) -> str:
    raw = base64.urlsafe_b64decode(encoded_text.encode("ascii"))
    nonce = raw[:12]
    cipher = raw[12:]
    aes = AESGCM(AES_256_KEY)
    plain = aes.decrypt(nonce, cipher, None)
    return plain.decode("utf-8")


def init_db() -> None:
    USER_FILES_DIR.mkdir(parents=True, exist_ok=True)

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

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                userid TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                content_encrypted TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(userid) REFERENCES users(userid)
            )
            """
        )

        user_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "failed_attempts" not in user_columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0"
            )
        if "locked_until" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
        if "last_failed_at" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN last_failed_at TEXT")

        file_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(user_files)").fetchall()
        }
        if "file_name" not in file_columns:
            conn.execute("ALTER TABLE user_files ADD COLUMN file_name TEXT NOT NULL DEFAULT ''")
        if "description" not in file_columns:
            conn.execute("ALTER TABLE user_files ADD COLUMN description TEXT NOT NULL DEFAULT ''")
        if "content_encrypted" not in file_columns:
            conn.execute(
                "ALTER TABLE user_files ADD COLUMN content_encrypted TEXT NOT NULL DEFAULT ''"
            )


def db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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


def session_user() -> str | None:
    return session.get("user_id")


def payload_value(name: str) -> str:
    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        return str(payload.get(name, ""))
    return str(request.form.get(name, ""))


def legacy_file_name(title: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", title.strip()).strip("-").lower()
    if not slug:
        slug = "item"
    timestamp = int(now_utc().timestamp() * 1000)
    return f"{slug}-{timestamp}"


def user_folder(userid: str) -> Path:
    folder = USER_FILES_DIR / userid
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def storage_relpath_for_title(userid: str, title: str, file_id: int) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", title.strip()).strip("-").lower()
    if not slug:
        slug = "item"
    return f"{userid}/{slug}-{file_id}.enc"


def storage_abspath_from_relpath(relpath: str) -> Path:
    return USER_FILES_DIR / relpath


def verify_user_password(userid: str, password: str) -> bool:
    with db_connection() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE userid = ?",
            (userid,),
        ).fetchone()
    if row is None:
        return False
    return check_password_hash(row["password_hash"], password)


def json_auth_required():
    if not session_user():
        return jsonify({"error": "Please sign in first."}), 401
    return None


@app.before_request
def ensure_database_ready() -> None:
    init_db()


@app.after_request
def apply_no_store_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.get("/")
def home():
    if session_user():
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
    if not session_user():
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
    confirm_password = request.form.get("confirm_password") or ""

    if not userid or not password:
        return redirect(build_registration_url("User ID and password are required."))

    if password != confirm_password:
        return redirect(build_registration_url("Passwords do not match."))

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
        with db_connection() as conn:
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


@app.get("/api/files")
def list_user_files():
    auth_error = json_auth_required()
    if auth_error:
        return auth_error

    userid = session_user()
    with db_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, title, description, created_at, updated_at
            FROM user_files
            WHERE userid = ?
            ORDER BY id DESC
            """,
            (userid,),
        ).fetchall()

    files = [
        {
            "id": row["id"],
            "title": row["title"],
            "description": row["description"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]
    return jsonify({"files": files})


@app.get("/api/account")
def get_account_info():
    auth_error = json_auth_required()
    if auth_error:
        return auth_error

    return jsonify({"userid": session_user()})


@app.post("/api/files")
def create_user_file():
    auth_error = json_auth_required()
    if auth_error:
        return auth_error

    userid = session_user()
    title = payload_value("title").strip()
    description = payload_value("description").strip()
    content = payload_value("content")

    if not title:
        return jsonify({"error": "Title is required."}), 400

    current_time = now_utc().isoformat()
    encrypted_content = encrypt_text(content)
    with db_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO user_files (userid, title, description, content_encrypted, file_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                userid,
                title,
                description,
                encrypted_content,
                "",
                current_time,
                current_time,
            ),
        )
        file_id = cursor.lastrowid

        relpath = storage_relpath_for_title(userid, title, file_id)
        conn.execute(
            "UPDATE user_files SET file_name = ? WHERE id = ? AND userid = ?",
            (relpath, file_id, userid),
        )

    target_path = storage_abspath_from_relpath(relpath)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(encrypted_content, encoding="utf-8")

    return jsonify({"id": file_id, "message": "File created successfully."}), 201


@app.post("/api/files/<int:file_id>/display")
def display_user_file(file_id: int):
    auth_error = json_auth_required()
    if auth_error:
        return auth_error

    userid = session_user()
    password = payload_value("password")
    if not password:
        return jsonify({"error": "Account password confirmation is required."}), 400
    if not verify_user_password(userid, password):
        return jsonify({"error": "Password confirmation failed."}), 403

    with db_connection() as conn:
        row = conn.execute(
            """
            SELECT id, title, description, content_encrypted, file_name, created_at, updated_at
            FROM user_files
            WHERE id = ? AND userid = ?
            """,
            (file_id, userid),
        ).fetchone()

    if row is None:
        return jsonify({"error": "File not found."}), 404

    try:
        encrypted_payload = row["content_encrypted"] or ""
        if row["file_name"]:
            file_path = storage_abspath_from_relpath(row["file_name"])
            if file_path.exists():
                encrypted_payload = file_path.read_text(encoding="utf-8")

        content = decrypt_text(encrypted_payload) if encrypted_payload else ""
    except Exception:
        return jsonify({"error": "Unable to decrypt stored content."}), 500

    return jsonify(
        {
            "id": row["id"],
            "title": row["title"],
            "description": row["description"],
            "content": content,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    )


@app.post("/api/files/<int:file_id>/update")
def update_user_file(file_id: int):
    auth_error = json_auth_required()
    if auth_error:
        return auth_error

    userid = session_user()
    password = payload_value("password")
    title = payload_value("title").strip()
    description = payload_value("description").strip()
    content = payload_value("content")

    if not password:
        return jsonify({"error": "Account password confirmation is required."}), 400
    if not verify_user_password(userid, password):
        return jsonify({"error": "Password confirmation failed."}), 403
    if not title:
        return jsonify({"error": "Title is required."}), 400

    encrypted_content = encrypt_text(content)
    updated_at = now_utc().isoformat()

    with db_connection() as conn:
        row = conn.execute(
            "SELECT id, file_name FROM user_files WHERE id = ? AND userid = ?",
            (file_id, userid),
        ).fetchone()
        if row is None:
            return jsonify({"error": "File not found."}), 404

        new_relpath = storage_relpath_for_title(userid, title, file_id)

        conn.execute(
            """
            UPDATE user_files
            SET title = ?,
                description = ?,
                content_encrypted = ?,
                file_name = ?,
                updated_at = ?
            WHERE id = ? AND userid = ?
            """,
            (title, description, encrypted_content, new_relpath, updated_at, file_id, userid),
        )

    new_path = storage_abspath_from_relpath(new_relpath)
    new_path.parent.mkdir(parents=True, exist_ok=True)
    new_path.write_text(encrypted_content, encoding="utf-8")

    old_relpath = row["file_name"] or ""
    if old_relpath and old_relpath != new_relpath:
        old_path = storage_abspath_from_relpath(old_relpath)
        if old_path.exists():
            old_path.unlink()

    return jsonify({"message": "File updated successfully."})


@app.post("/api/files/<int:file_id>/delete")
def delete_user_file(file_id: int):
    auth_error = json_auth_required()
    if auth_error:
        return auth_error

    userid = session_user()
    password = payload_value("password")

    if not password:
        return jsonify({"error": "Account password confirmation is required."}), 400
    if not verify_user_password(userid, password):
        return jsonify({"error": "Password confirmation failed."}), 403

    with db_connection() as conn:
        row = conn.execute(
            "SELECT id, file_name FROM user_files WHERE id = ? AND userid = ?",
            (file_id, userid),
        ).fetchone()
        if row is None:
            return jsonify({"error": "File not found."}), 404

        conn.execute(
            "DELETE FROM user_files WHERE id = ? AND userid = ?",
            (file_id, userid),
        )

    relpath = row["file_name"] or ""
    if relpath:
        target_path = storage_abspath_from_relpath(relpath)
        if target_path.exists():
            target_path.unlink()

    return jsonify({"message": "File deleted successfully."})

@app.post("/api/account/delete")
def delete_account():
    auth_error = json_auth_required()
    if auth_error:
        return auth_error

    userid = session_user()
    password = payload_value("password")

    if not password:
        return jsonify({"error": "Account password confirmation is required."}), 400
    if not verify_user_password(userid, password):
        return jsonify({"error": "Password confirmation failed."}), 403

    with db_connection() as conn:
        # Get all user files before deletion
        user_files = conn.execute(
            "SELECT file_name FROM user_files WHERE userid = ?",
            (userid,),
        ).fetchall()

        # Delete all user files from database
        conn.execute("DELETE FROM user_files WHERE userid = ?", (userid,))

        # Delete user account from database
        conn.execute("DELETE FROM users WHERE userid = ?", (userid,))

    # Delete all user files from filesystem
    for row in user_files:
        relpath = row["file_name"] or ""
        if relpath:
            target_path = storage_abspath_from_relpath(relpath)
            if target_path.exists():
                target_path.unlink()

    # Delete empty user folder
    user_folder_path = user_folder(userid)
    try:
        if user_folder_path.exists():
            user_folder_path.rmdir()
    except OSError:
        pass

    # Clear session
    session.clear()

    return jsonify({"message": "Account deleted successfully."})

print("Serving from:", BASE_DIR)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)