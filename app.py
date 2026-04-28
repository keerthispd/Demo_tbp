from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, redirect, request, send_file, send_from_directory, session
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cryptosafe.db"
LOCKOUT_DURATION = timedelta(hours=24)
MAX_FAILED_ATTEMPTS = 3
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_UPLOAD_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "bmp",
    "svg",
    "pdf",
    "doc",
    "docx",
    "txt",
    "rtf",
    "csv",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "mp3",
    "wav",
    "m4a",
    "ogg",
    "aac",
    "flac",
}
ALLOWED_UPLOAD_MIME_PREFIXES = ("image/", "audio/")
ALLOWED_UPLOAD_MIME_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
    "text/csv",
    "application/rtf",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "audio/mpeg",
    "audio/mp3",
    "audio/wav",
    "audio/x-wav",
    "audio/mp4",
    "audio/ogg",
    "audio/aac",
    "audio/flac",
}

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


def encrypt_bytes(payload: bytes) -> str:
    aes = AESGCM(AES_256_KEY)
    nonce = os.urandom(12)
    cipher = aes.encrypt(nonce, payload, None)
    return base64.urlsafe_b64encode(nonce + cipher).decode("ascii")


def decrypt_bytes(encoded_payload: str) -> bytes:
    raw = base64.urlsafe_b64decode(encoded_payload.encode("ascii"))
    nonce = raw[:12]
    cipher = raw[12:]
    aes = AESGCM(AES_256_KEY)
    return aes.decrypt(nonce, cipher, None)


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
        if "webauthn_credential_id" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN webauthn_credential_id TEXT")
        if "webauthn_public_key" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN webauthn_public_key TEXT")
        if "webauthn_sign_count" not in user_columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN webauthn_sign_count INTEGER NOT NULL DEFAULT 0"
            )
        if "biometric_failed_attempts" not in user_columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN biometric_failed_attempts INTEGER NOT NULL DEFAULT 0"
            )
        if "biometric_locked_until" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN biometric_locked_until TEXT")
        if "biometric_last_failed_at" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN biometric_last_failed_at TEXT")
        if "passcode_hash" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN passcode_hash TEXT NOT NULL DEFAULT ''")
        if "backup_question" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN backup_question TEXT NOT NULL DEFAULT ''")
        if "backup_answer_hash" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN backup_answer_hash TEXT NOT NULL DEFAULT ''")
        if "recovery_question_failed_attempts" not in user_columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN recovery_question_failed_attempts INTEGER NOT NULL DEFAULT 0"
            )
        if "recovery_question_locked_until" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN recovery_question_locked_until TEXT")

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
        if "uploaded_file_name" not in file_columns:
            conn.execute(
                "ALTER TABLE user_files ADD COLUMN uploaded_file_name TEXT NOT NULL DEFAULT ''"
            )
        if "uploaded_file_mime" not in file_columns:
            conn.execute(
                "ALTER TABLE user_files ADD COLUMN uploaded_file_mime TEXT NOT NULL DEFAULT ''"
            )
        if "uploaded_file_size" not in file_columns:
            conn.execute(
                "ALTER TABLE user_files ADD COLUMN uploaded_file_size INTEGER NOT NULL DEFAULT 0"
            )
        if "uploaded_file_encrypted" not in file_columns:
            conn.execute(
                "ALTER TABLE user_files ADD COLUMN uploaded_file_encrypted TEXT NOT NULL DEFAULT ''"
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


def build_forgot_url(error: str | None = None, info: str | None = None) -> str:
    return build_url("/forgot-password.html", error=error, info=info)


def build_biometric_url(error: str | None = None) -> str:
    return build_url("/biometric.html", error=error)


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


def payload_bool(name: str) -> bool:
    value = payload_value(name).strip().lower()
    return value in {"1", "true", "yes", "on"}


def encode_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def relying_party_id() -> str:
    host = request.host.split(":", 1)[0].strip().lower()
    if host == "127.0.0.1":
        host = "localhost"
    return host


def expected_origin() -> str:
    origin = request.host_url.rstrip("/")
    if "127.0.0.1" in origin:
        origin = origin.replace("127.0.0.1", "localhost")
    return origin


def uploaded_file_from_request(field_name: str = "upload_file"):
    uploaded = request.files.get(field_name)
    if uploaded is None:
        return None
    if not (uploaded.filename or "").strip():
        return None
    return uploaded


def validate_uploaded_file(filename: str, mime_type: str, size_bytes: int) -> str | None:
    safe_name = secure_filename(filename)
    extension = ""
    if "." in safe_name:
        extension = safe_name.rsplit(".", 1)[1].lower()

    is_allowed_ext = extension in ALLOWED_UPLOAD_EXTENSIONS
    is_allowed_mime = mime_type in ALLOWED_UPLOAD_MIME_TYPES or any(
        mime_type.startswith(prefix) for prefix in ALLOWED_UPLOAD_MIME_PREFIXES
    )

    if not is_allowed_ext and not is_allowed_mime:
        return "Only image, audio, and document files are allowed."
    if size_bytes > MAX_UPLOAD_BYTES:
        return "Uploaded file is too large (max 10 MB)."
    return None


def verify_user_password(userid: str, password: str) -> bool:
    with db_connection() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE userid = ?",
            (userid,),
        ).fetchone()
    if row is None:
        return False
    return check_password_hash(row["password_hash"], password)


def clear_recovery_session() -> None:
    session.pop("recovery_user_id", None)
    session.pop("recovery_biometric_challenge", None)
    session.pop("recovery_alt_verified", None)


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
    response.headers["ETag"] = None
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


@app.get("/forgot-password.html")
def forgot_password_page():
    response = send_from_directory(BASE_DIR, "forgot-password.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/start_login")
def start_login():
    userid = (request.form.get("userid") or "").strip()
    if not userid:
        return redirect(build_login_url("User ID is required."))

    with db_connection() as conn:
        user = conn.execute(
            "SELECT userid FROM users WHERE userid = ?",
            (userid,),
        ).fetchone()
    if user is None:
        return redirect(build_login_url("Invalid user ID."))

    session["pending_user_id"] = userid
    session.pop("biometric_challenge", None)
    session.pop("biometric_verified", None)
    return redirect("/biometric.html")


@app.get("/landing.html")
def landing_page():
    response = send_from_directory(BASE_DIR, "landing.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/biometric.html")
def biometric_page():
    if not session.get("pending_user_id"):
        return redirect(build_login_url("Please complete password sign in first."))

    response = send_from_directory(BASE_DIR, "biometric.html")
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
    biometric_credential_raw = request.form.get("biometric_credential") or ""
    auth_method = (request.form.get("auth_method") or "biometric").strip()
    passcode = request.form.get("passcode") or ""
    passcode_confirm = request.form.get("passcode_confirm") or ""
    backup_question = (request.form.get("backup_question") or "").strip()
    backup_answer = (request.form.get("backup_answer") or "").strip()

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

    if not backup_question or len(backup_answer) < 2:
        return redirect(
            build_registration_url("Backup question and answer are required for recovery.")
        )

    # Support two enrollment methods: biometric (webauthn) or passcode fallback
    password_hash = generate_password_hash(password)
    backup_answer_hash = generate_password_hash(backup_answer)
    created_at = now_utc().isoformat()

    if auth_method == "passcode":
        if not passcode or passcode != passcode_confirm or len(passcode) < 4:
            return redirect(build_registration_url("Passcode required, must match and be at least 4 characters."))
        passcode_hash = generate_password_hash(passcode)

        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    """
                    INSERT INTO users (
                        userid,
                        password_hash,
                        created_at,
                        passcode_hash,
                        backup_question,
                        backup_answer_hash
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        userid,
                        password_hash,
                        created_at,
                        passcode_hash,
                        backup_question,
                        backup_answer_hash,
                    ),
                )
        except sqlite3.IntegrityError:
            return redirect(build_registration_url("User ID already taken"))
        except sqlite3.Error:
            return redirect(build_registration_url("Database error. Please retry."))

        return redirect(build_landing_url("success"))

    # Default: biometric enrollment
    if session.get("registration_userid") != userid:
        return redirect(
            build_registration_url(
                "Biometric setup expired or mismatched. Please try registration again."
            )
        )

    challenge_b64 = session.get("registration_challenge")
    if not challenge_b64 or not biometric_credential_raw:
        return redirect(
            build_registration_url(
                "Biometric setup is required. Use a device that supports biometrics/passkeys."
            )
        )

    try:
        biometric_credential = json.loads(biometric_credential_raw)
        registration_verification = verify_registration_response(
            credential=biometric_credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=relying_party_id(),
            expected_origin=expected_origin(),
            require_user_verification=True,
        )
    except Exception:
        return redirect(
            build_registration_url(
                "Biometric registration failed. Please retry and approve biometric verification."
            )
        )

    credential_id = encode_base64url(registration_verification.credential_id)
    public_key = encode_base64url(registration_verification.credential_public_key)
    sign_count = int(registration_verification.sign_count)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO users (
                    userid,
                    password_hash,
                    created_at,
                    webauthn_credential_id,
                    webauthn_public_key,
                    webauthn_sign_count,
                    backup_question,
                    backup_answer_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    userid,
                    password_hash,
                    created_at,
                    credential_id,
                    public_key,
                    sign_count,
                    backup_question,
                    backup_answer_hash,
                ),
            )
    except sqlite3.IntegrityError:
        return redirect(build_registration_url("User ID already taken"))
    except sqlite3.Error:
        return redirect(build_registration_url("Database error. Please retry."))

    session.pop("registration_challenge", None)
    session.pop("registration_userid", None)

    return redirect(build_landing_url("success"))


@app.post("/api/biometric/register/options")
def biometric_register_options():
    userid = payload_value("userid").strip()
    if len(userid) < 3:
        return jsonify({"error": "User ID must be at least 3 characters."}), 400

    with db_connection() as conn:
        existing = conn.execute(
            "SELECT userid FROM users WHERE userid = ?",
            (userid,),
        ).fetchone()
    if existing is not None:
        return jsonify({"error": "User ID already taken."}), 409

    options = generate_registration_options(
        rp_id=relying_party_id(),
        rp_name="CryptoSafe",
        user_id=os.urandom(16),
        user_name=userid,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )

    session["registration_challenge"] = encode_base64url(options.challenge)
    session["registration_userid"] = userid

    return jsonify(json.loads(options_to_json(options)))


@app.get('/settings.html')
def settings_page():
    if not session_user():
        return redirect(build_login_url("Please sign in to manage settings."))
    response = send_from_directory(BASE_DIR, 'settings.html')
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.post('/api/account/webauthn/register/options')
def account_webauthn_register_options():
    userid = session_user()
    if not userid:
        return jsonify({"error": "Not signed in."}), 401

    options = generate_registration_options(
        rp_id=relying_party_id(),
        rp_name='CryptoSafe',
        user_id=userid.encode('utf-8'),
        user_name=userid,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )

    session['account_registration_challenge'] = encode_base64url(options.challenge)
    return jsonify(json.loads(options_to_json(options)))


@app.post('/api/account/webauthn/register/verify')
def account_webauthn_register_verify():
    userid = session_user()
    if not userid:
        return jsonify({"error": "Not signed in."}), 401

    payload = request.get_json(silent=True) or {}
    credential = payload.get('credential')
    challenge_b64 = session.get('account_registration_challenge')
    if not credential or not challenge_b64:
        return jsonify({"error": "Missing credential or challenge."}), 400

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=relying_party_id(),
            expected_origin=expected_origin(),
            require_user_verification=True,
        )
    except Exception:
        return jsonify({"error": "Registration verification failed."}), 400

    credential_id = encode_base64url(verification.credential_id)
    public_key = encode_base64url(verification.credential_public_key)
    sign_count = int(verification.sign_count)

    with db_connection() as conn:
        conn.execute(
            'UPDATE users SET webauthn_credential_id = ?, webauthn_public_key = ?, webauthn_sign_count = ? WHERE userid = ?',
            (credential_id, public_key, sign_count, userid),
        )

    session.pop('account_registration_challenge', None)
    return jsonify({"message": "Passkey registered."})


@app.post('/api/account/set_passcode')
def account_set_passcode():
    userid = session_user()
    if not userid:
        return jsonify({"error": "Not signed in."}), 401
    payload = request.get_json(silent=True) or {}
    passcode = str(payload.get('passcode') or '').strip()
    if len(passcode) < 4:
        return jsonify({"error": "Passcode must be at least 4 characters."}), 400
    passcode_hash = generate_password_hash(passcode)
    with db_connection() as conn:
        conn.execute('UPDATE users SET passcode_hash = ? WHERE userid = ?', (passcode_hash, userid))
    return jsonify({"message": "Passcode set."})


@app.post('/api/account/remove_webauthn')
def account_remove_webauthn():
    userid = session_user()
    if not userid:
        return jsonify({"error": "Not signed in."}), 401
    with db_connection() as conn:
        conn.execute('UPDATE users SET webauthn_credential_id = NULL, webauthn_public_key = NULL, webauthn_sign_count = 0 WHERE userid = ?', (userid,))
    return jsonify({"message": "Passkey removed."})


@app.post('/api/account/remove_passcode')
def account_remove_passcode():
    userid = session_user()
    if not userid:
        return jsonify({"error": "Not signed in."}), 401
    with db_connection() as conn:
        conn.execute('UPDATE users SET passcode_hash = "" WHERE userid = ?', (userid,))
    return jsonify({"message": "Passcode removed."})


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
                SELECT userid, password_hash, failed_attempts, locked_until,
                       webauthn_credential_id
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
                if not user["webauthn_credential_id"]:
                    return redirect(
                        build_login_url(
                            "This account has no biometric credential enrolled. Please re-register to enable two-phase login."
                        )
                    )

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
                session.pop("user_id", None)
                session["pending_user_id"] = userid
                session.pop("biometric_challenge", None)
                return redirect("/biometric.html")

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


@app.post("/api/biometric/auth/options")
def biometric_auth_options():
    userid = session.get("pending_user_id")
    if not userid:
        return jsonify({"error": "Start login first."}), 401

    with db_connection() as conn:
        user = conn.execute(
            """
            SELECT webauthn_credential_id, passcode_hash, biometric_locked_until
            FROM users
            WHERE userid = ?
            """,
            (userid,),
        ).fetchone()
    if user is None:
        return jsonify({"error": "Account not found."}), 404

    # Check biometric lockout
    locked_until = parse_utc(user["biometric_locked_until"]) if user["biometric_locked_until"] else None
    now = now_utc()
    if locked_until and locked_until > now:
        return jsonify({"error": "Biometric locked due to repeated failures."}), 403

    has_webauthn = bool(user["webauthn_credential_id"])
    has_passcode = bool(user["passcode_hash"])

    if not has_webauthn and not has_passcode:
        return jsonify({"error": "No biometric or passcode configured for this account."}), 400

    result = {"webauthn": has_webauthn, "passcode": has_passcode}

    if has_webauthn:
        options = generate_authentication_options(
            rp_id=relying_party_id(),
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(str(user["webauthn_credential_id"])),
                )
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        session["biometric_challenge"] = encode_base64url(options.challenge)
        result.update(json.loads(options_to_json(options)))

    return jsonify(result)


@app.post("/api/biometric/auth/verify")
def biometric_auth_verify():
    userid = session.get("pending_user_id")
    challenge_b64 = session.get("biometric_challenge")
    if not userid or not challenge_b64:
        # allow passcode verification even if we didn't issue a webauthn challenge
        pass

    payload = request.get_json(silent=True)
    credential = None
    passcode = None
    if isinstance(payload, dict):
        credential = payload.get("credential")
        passcode = payload.get("passcode")

    with db_connection() as conn:
        user = conn.execute(
            "SELECT webauthn_public_key, webauthn_sign_count, biometric_failed_attempts FROM users WHERE userid = ?",
            (userid,),
        ).fetchone()

        if user is None:
            return jsonify({"error": "Account not found."}), 404

        # Passcode path
        if passcode is not None:
            stored = conn.execute(
                "SELECT passcode_hash, biometric_failed_attempts FROM users WHERE userid = ?",
                (userid,),
            ).fetchone()
            if not stored or not stored["passcode_hash"]:
                return jsonify({"error": "Passcode not configured for this account."}), 400

            if not check_password_hash(stored["passcode_hash"], passcode):
                # increment biometric failures
                current = int(stored["biometric_failed_attempts"] or 0) + 1
                lock_until_val = None
                if current >= MAX_FAILED_ATTEMPTS:
                    lock_until = now_utc() + LOCKOUT_DURATION
                    lock_until_val = lock_until.isoformat()
                    current = MAX_FAILED_ATTEMPTS
                conn.execute(
                    "UPDATE users SET biometric_failed_attempts = ?, biometric_locked_until = ?, biometric_last_failed_at = ? WHERE userid = ?",
                    (current, lock_until_val, now_utc().isoformat(), userid),
                )
                return jsonify({"error": "Passcode verification failed."}), 403

            # success
            conn.execute(
                "UPDATE users SET biometric_failed_attempts = 0, biometric_locked_until = NULL, biometric_last_failed_at = NULL WHERE userid = ?",
                (userid,),
            )
            session["biometric_verified"] = True
            return jsonify({"message": "Biometric/passcode verification completed.", "redirect": "/password.html"})

        # WebAuthn credential path
        if credential is None:
            return jsonify({"error": "Missing biometric credential payload."}), 400

        if not user["webauthn_public_key"]:
            return jsonify({"error": "Biometric credential is not configured for this account."}), 400

        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge_b64),
                expected_rp_id=relying_party_id(),
                expected_origin=expected_origin(),
                credential_public_key=base64url_to_bytes(str(user["webauthn_public_key"])),
                credential_current_sign_count=int(user["webauthn_sign_count"] or 0),
                require_user_verification=True,
            )
        except Exception:
            # increment biometric failure counter
            current_fail = int(user["biometric_failed_attempts"] or 0) + 1
            lock_until_val = None
            if current_fail >= MAX_FAILED_ATTEMPTS:
                lock_until = now_utc() + LOCKOUT_DURATION
                lock_until_val = lock_until.isoformat()
                current_fail = MAX_FAILED_ATTEMPTS
            conn.execute(
                "UPDATE users SET biometric_failed_attempts = ?, biometric_locked_until = ?, biometric_last_failed_at = ? WHERE userid = ?",
                (current_fail, lock_until_val, now_utc().isoformat(), userid),
            )
            return jsonify({"error": "Biometric verification failed."}), 403

        # success: reset biometric counters and mark verified for password phase
        conn.execute(
            "UPDATE users SET webauthn_sign_count = ?, biometric_failed_attempts = 0, biometric_locked_until = NULL, biometric_last_failed_at = NULL WHERE userid = ?",
            (int(verification.new_sign_count), userid),
        )

    session["biometric_verified"] = True
    session.pop("biometric_challenge", None)
    return jsonify({"message": "Biometric verification completed.", "redirect": "/password.html"})


@app.get("/password.html")
def password_page():
    if not session.get("pending_user_id") or not session.get("biometric_verified"):
        return redirect(build_login_url("Complete the biometric/passcode step first."))

    response = send_from_directory(BASE_DIR, "password.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/complete_login")
def complete_login():
    userid = session.get("pending_user_id")
    if not userid or not session.get("biometric_verified"):
        return redirect(build_login_url("Session expired. Please login again."))

    password = request.form.get("password") or ""
    if not password:
        return redirect(build_login_url("Password is required."))

    try:
        with db_connection() as conn:
            user = conn.execute(
                "SELECT userid, password_hash, failed_attempts, locked_until FROM users WHERE userid = ?",
                (userid,),
            ).fetchone()

            if user is None:
                return redirect(build_login_url("Invalid user."))

            locked_until = parse_utc(user["locked_until"])
            current_time = now_utc()
            if locked_until and locked_until > current_time:
                remaining_hours = max(1, int((locked_until - current_time).total_seconds() // 3600))
                return redirect(build_login_url(f"Password locked due to repeated failures. Try again in about {remaining_hours} hour(s)."))

            if check_password_hash(user["password_hash"], password):
                # success: clear password failure counters and complete login
                conn.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_failed_at = NULL WHERE userid = ?",
                    (userid,),
                )
                session["user_id"] = userid
                session.pop("pending_user_id", None)
                session.pop("biometric_verified", None)
                return redirect("/dashboard.html")

            # password failure path
            failed_attempts = int(user["failed_attempts"] or 0) + 1
            lock_until_value = None
            message = "Invalid password."
            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                lock_until = current_time + LOCKOUT_DURATION
                lock_until_value = lock_until.isoformat()
                failed_attempts = MAX_FAILED_ATTEMPTS
                message = "Account locked for 24 hours after too many failed password attempts."
            else:
                remaining_attempts = MAX_FAILED_ATTEMPTS - failed_attempts
                message = f"Invalid password. {remaining_attempts} attempt(s) left before a 24-hour lock."

            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ?, last_failed_at = ? WHERE userid = ?",
                (failed_attempts, lock_until_value, current_time.isoformat(), userid),
            )
    except sqlite3.Error:
        return redirect(build_login_url("Database error. Please retry."))

    return redirect(build_login_url(message))


@app.post("/api/forgot/context")
def forgot_context():
    userid = payload_value("userid").strip()
    if not userid:
        return jsonify({"error": "User ID is required."}), 400

    with db_connection() as conn:
        user = conn.execute(
            """
            SELECT userid, failed_attempts, locked_until, passcode_hash,
                   webauthn_credential_id, backup_question, backup_answer_hash
            FROM users
            WHERE userid = ?
            """,
            (userid,),
        ).fetchone()

    if user is None:
        return jsonify({"error": "Invalid user ID."}), 404

    locked_until = parse_utc(user["locked_until"])
    current_time = now_utc()
    if locked_until and locked_until > current_time:
        return (
            jsonify(
                {
                    "error": "Forgot password is disabled after 24-hour lock activates. Wait for lock expiry.",
                }
            ),
            403,
        )

    if not user["backup_question"] or not user["backup_answer_hash"]:
        return jsonify({"error": "Recovery question is not configured for this account."}), 400

    has_webauthn = bool(user["webauthn_credential_id"])
    has_passcode = bool(user["passcode_hash"])
    if not has_webauthn and not has_passcode:
        return jsonify({"error": "No biometric or PIN passcode is configured for this account."}), 400

    clear_recovery_session()
    session["recovery_user_id"] = userid

    with db_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET recovery_question_failed_attempts = 0,
                recovery_question_locked_until = NULL
            WHERE userid = ?
            """,
            (userid,),
        )

    return jsonify(
        {
            "userid": userid,
            "backup_question": user["backup_question"],
            "has_webauthn": has_webauthn,
            "has_passcode": has_passcode,
        }
    )


@app.post("/api/forgot/biometric/options")
def forgot_biometric_options():
    userid = session.get("recovery_user_id")
    if not userid:
        return jsonify({"error": "Start password recovery first."}), 401

    with db_connection() as conn:
        user = conn.execute(
            "SELECT webauthn_credential_id, locked_until FROM users WHERE userid = ?",
            (userid,),
        ).fetchone()

    if user is None:
        return jsonify({"error": "Invalid user."}), 404

    locked_until = parse_utc(user["locked_until"])
    if locked_until and locked_until > now_utc():
        return (
            jsonify(
                {
                    "error": "Forgot password is disabled after 24-hour lock activates. Wait for lock expiry.",
                }
            ),
            403,
        )

    if not user["webauthn_credential_id"]:
        return jsonify({"error": "Biometric is not configured for this account."}), 400

    options = generate_authentication_options(
        rp_id=relying_party_id(),
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(str(user["webauthn_credential_id"])),
            )
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    session["recovery_biometric_challenge"] = encode_base64url(options.challenge)
    return jsonify(json.loads(options_to_json(options)))


@app.post("/api/forgot/biometric/verify")
def forgot_biometric_verify():
    userid = session.get("recovery_user_id")
    challenge_b64 = session.get("recovery_biometric_challenge")
    payload = request.get_json(silent=True) or {}
    credential = payload.get("credential")

    if not userid or not challenge_b64:
        return jsonify({"error": "Start password recovery first."}), 401
    if credential is None:
        return jsonify({"error": "Missing biometric credential payload."}), 400

    with db_connection() as conn:
        user = conn.execute(
            """
            SELECT webauthn_public_key, webauthn_sign_count, locked_until
            FROM users
            WHERE userid = ?
            """,
            (userid,),
        ).fetchone()

        if user is None:
            return jsonify({"error": "Invalid user."}), 404

        locked_until = parse_utc(user["locked_until"])
        if locked_until and locked_until > now_utc():
            return (
                jsonify(
                    {
                        "error": "Forgot password is disabled after 24-hour lock activates. Wait for lock expiry.",
                    }
                ),
                403,
            )

        if not user["webauthn_public_key"]:
            return jsonify({"error": "Biometric is not configured for this account."}), 400

        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge_b64),
                expected_rp_id=relying_party_id(),
                expected_origin=expected_origin(),
                credential_public_key=base64url_to_bytes(str(user["webauthn_public_key"])),
                credential_current_sign_count=int(user["webauthn_sign_count"] or 0),
                require_user_verification=True,
            )
        except Exception:
            return jsonify({"error": "Biometric verification failed."}), 403

        conn.execute(
            "UPDATE users SET webauthn_sign_count = ? WHERE userid = ?",
            (int(verification.new_sign_count), userid),
        )

    session["recovery_alt_verified"] = True
    session.pop("recovery_biometric_challenge", None)
    return jsonify({"message": "Biometric verified for recovery."})


@app.post("/api/forgot/reset")
def forgot_reset():
    payload = request.get_json(silent=True) or {}
    userid = str(payload.get("userid") or "").strip()
    method = str(payload.get("method") or "").strip().lower()
    passcode = str(payload.get("passcode") or "")
    backup_answer = str(payload.get("backup_answer") or "").strip()
    new_password = str(payload.get("new_password") or "")
    confirm_password = str(payload.get("confirm_password") or "")

    if not userid or not method or not backup_answer or not new_password:
        return jsonify({"error": "All required fields must be provided."}), 400
    if new_password != confirm_password:
        return jsonify({"error": "New passwords do not match."}), 400
    if len(new_password) < 6:
        return jsonify({"error": "New password must be at least 6 characters."}), 400
    if session.get("recovery_user_id") != userid:
        return jsonify({"error": "Recovery session mismatch. Restart forgot password."}), 401

    with db_connection() as conn:
        user = conn.execute(
            """
            SELECT locked_until, passcode_hash, webauthn_credential_id,
                   backup_answer_hash, recovery_question_failed_attempts,
                   recovery_question_locked_until
            FROM users
            WHERE userid = ?
            """,
            (userid,),
        ).fetchone()

        if user is None:
            clear_recovery_session()
            return jsonify({"error": "Invalid user."}), 404

        locked_until = parse_utc(user["locked_until"])
        if locked_until and locked_until > now_utc():
            clear_recovery_session()
            return (
                jsonify(
                    {
                        "error": "Forgot password is disabled after 24-hour lock activates. Wait for lock expiry.",
                    }
                ),
                403,
            )

        recovery_locked_until = parse_utc(user["recovery_question_locked_until"])
        current_time = now_utc()
        if recovery_locked_until and recovery_locked_until > current_time:
            clear_recovery_session()
            return (
                jsonify(
                    {
                        "error": "Backup question recovery is locked after 3 failed attempts. Try again later.",
                        "locked_until": recovery_locked_until.isoformat(),
                        "remaining_attempts": 0,
                    }
                ),
                403,
            )

        if not user["backup_answer_hash"] or not check_password_hash(
            user["backup_answer_hash"], backup_answer
        ):
            failed_attempts = int(user["recovery_question_failed_attempts"] or 0) + 1
            lock_until_value = None
            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                lock_until_value = (current_time + LOCKOUT_DURATION).isoformat()
                failed_attempts = MAX_FAILED_ATTEMPTS

            conn.execute(
                """
                UPDATE users
                SET recovery_question_failed_attempts = ?,
                    recovery_question_locked_until = ?
                WHERE userid = ?
                """,
                (failed_attempts, lock_until_value, userid),
            )

            if lock_until_value:
                clear_recovery_session()
                return (
                    jsonify(
                        {
                            "error": "Backup question recovery is locked after 3 failed attempts. Try again later.",
                            "locked_until": lock_until_value,
                            "remaining_attempts": 0,
                        }
                    ),
                    403,
                )

            remaining_attempts = MAX_FAILED_ATTEMPTS - failed_attempts
            return (
                jsonify(
                    {
                        "error": f"Backup answer did not match. {remaining_attempts} attempt(s) left.",
                        "remaining_attempts": remaining_attempts,
                        "locked_until": None,
                    }
                ),
                403,
            )

        if method == "passcode":
            if not user["passcode_hash"]:
                return jsonify({"error": "PIN passcode is not configured for this account."}), 400
            if not passcode or not check_password_hash(user["passcode_hash"], passcode):
                return jsonify({"error": "PIN passcode verification failed."}), 403
        elif method == "biometric":
            if not user["webauthn_credential_id"]:
                return jsonify({"error": "Biometric is not configured for this account."}), 400
            if not session.get("recovery_alt_verified"):
                return jsonify({"error": "Complete biometric verification first."}), 403
        else:
            return jsonify({"error": "Invalid recovery method."}), 400

        conn.execute(
            """
            UPDATE users
            SET password_hash = ?,
                failed_attempts = 0,
                locked_until = NULL,
                last_failed_at = NULL,
                recovery_question_failed_attempts = 0,
                recovery_question_locked_until = NULL
            WHERE userid = ?
            """,
            (generate_password_hash(new_password), userid),
        )

    clear_recovery_session()
    return jsonify({"message": "Password reset successful. Please sign in with your new password."})


@app.get("/api/files")
def list_user_files():
    auth_error = json_auth_required()
    if auth_error:
        return auth_error

    userid = session_user()
    with db_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, title, description, created_at, updated_at,
                   uploaded_file_name, uploaded_file_mime, uploaded_file_size
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
            "has_uploaded_file": bool(row["uploaded_file_name"]),
            "uploaded_file_name": row["uploaded_file_name"],
            "uploaded_file_mime": row["uploaded_file_mime"],
            "uploaded_file_size": row["uploaded_file_size"],
        }
        for row in rows
    ]
    return jsonify({"userid": userid, "files": files})


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
    upload = uploaded_file_from_request("upload_file")

    if not title:
        return jsonify({"error": "Title is required."}), 400
    if not content.strip() and upload is None:
        return jsonify({"error": "Provide details text or upload an image/document."}), 400

    uploaded_name = ""
    uploaded_mime = ""
    uploaded_size = 0
    uploaded_encrypted = ""
    if upload is not None:
        raw_file_bytes = upload.read()
        uploaded_size = len(raw_file_bytes)
        uploaded_name = secure_filename(upload.filename or "")
        uploaded_mime = (upload.mimetype or "application/octet-stream").lower()
        validation_error = validate_uploaded_file(uploaded_name, uploaded_mime, uploaded_size)
        if validation_error:
            return jsonify({"error": validation_error}), 400
        uploaded_encrypted = encrypt_bytes(raw_file_bytes)

    current_time = now_utc().isoformat()
    encrypted_content = encrypt_text(content)
    with db_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO user_files (
                userid,
                title,
                description,
                content_encrypted,
                file_name,
                uploaded_file_name,
                uploaded_file_mime,
                uploaded_file_size,
                uploaded_file_encrypted,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                userid,
                title,
                description,
                encrypted_content,
                "",
                uploaded_name,
                uploaded_mime,
                uploaded_size,
                uploaded_encrypted,
                current_time,
                current_time,
            ),
        )
        file_id = cursor.lastrowid

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
            SELECT id, title, description, content_encrypted,
                   uploaded_file_name, uploaded_file_mime, uploaded_file_size,
                   uploaded_file_encrypted, created_at, updated_at
            FROM user_files
            WHERE id = ? AND userid = ?
            """,
            (file_id, userid),
        ).fetchone()

    if row is None:
        return jsonify({"error": "File not found."}), 404

    try:
        encrypted_payload = row["content_encrypted"] or ""
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
            "has_uploaded_file": bool(row["uploaded_file_encrypted"]),
            "uploaded_file_name": row["uploaded_file_name"],
            "uploaded_file_mime": row["uploaded_file_mime"],
            "uploaded_file_size": row["uploaded_file_size"],
        }
    )


@app.post("/api/files/<int:file_id>/download")
def download_user_file(file_id: int):
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
            SELECT uploaded_file_name, uploaded_file_mime, uploaded_file_encrypted
            FROM user_files
            WHERE id = ? AND userid = ?
            """,
            (file_id, userid),
        ).fetchone()

    if row is None:
        return jsonify({"error": "File not found."}), 404
    if not row["uploaded_file_encrypted"]:
        return jsonify({"error": "No uploaded file is stored for this entry."}), 404

    try:
        plain_bytes = decrypt_bytes(row["uploaded_file_encrypted"])
    except Exception:
        return jsonify({"error": "Unable to decrypt stored file."}), 500

    download_name = row["uploaded_file_name"] or "vault-file"
    mime_type = row["uploaded_file_mime"] or "application/octet-stream"
    return send_file(
        io.BytesIO(plain_bytes),
        mimetype=mime_type,
        as_attachment=True,
        download_name=download_name,
    )


@app.post("/api/files/<int:file_id>/attachment")
def get_user_file_attachment(file_id: int):
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
            SELECT uploaded_file_name, uploaded_file_mime, uploaded_file_encrypted
            FROM user_files
            WHERE id = ? AND userid = ?
            """,
            (file_id, userid),
        ).fetchone()

    if row is None:
        return jsonify({"error": "File not found."}), 404
    if not row["uploaded_file_encrypted"]:
        return jsonify({"error": "No uploaded file is stored for this entry."}), 404

    try:
        plain_bytes = decrypt_bytes(row["uploaded_file_encrypted"])
    except Exception:
        return jsonify({"error": "Unable to decrypt stored file."}), 500

    mime_type = row["uploaded_file_mime"] or "application/octet-stream"
    return jsonify(
        {
            "uploaded_file_name": row["uploaded_file_name"] or "vault-file",
            "uploaded_file_mime": mime_type,
            "uploaded_file_size": len(plain_bytes),
            "content_base64": base64.b64encode(plain_bytes).decode("ascii"),
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
    upload = uploaded_file_from_request("upload_file")
    remove_upload = payload_bool("remove_upload")

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
            """
            SELECT id, uploaded_file_name, uploaded_file_mime,
                   uploaded_file_size, uploaded_file_encrypted
            FROM user_files
            WHERE id = ? AND userid = ?
            """,
            (file_id, userid),
        ).fetchone()
        if row is None:
            return jsonify({"error": "File not found."}), 404

        uploaded_name = row["uploaded_file_name"] or ""
        uploaded_mime = row["uploaded_file_mime"] or ""
        uploaded_size = int(row["uploaded_file_size"] or 0)
        uploaded_encrypted = row["uploaded_file_encrypted"] or ""

        if remove_upload:
            uploaded_name = ""
            uploaded_mime = ""
            uploaded_size = 0
            uploaded_encrypted = ""

        if upload is not None:
            raw_file_bytes = upload.read()
            new_size = len(raw_file_bytes)
            new_name = secure_filename(upload.filename or "")
            new_mime = (upload.mimetype or "application/octet-stream").lower()
            validation_error = validate_uploaded_file(new_name, new_mime, new_size)
            if validation_error:
                return jsonify({"error": validation_error}), 400

            uploaded_name = new_name
            uploaded_mime = new_mime
            uploaded_size = new_size
            uploaded_encrypted = encrypt_bytes(raw_file_bytes)

        if not content.strip() and not uploaded_encrypted:
            return jsonify({"error": "Provide details text or keep/upload a file."}), 400

        conn.execute(
            """
            UPDATE user_files
            SET title = ?,
                description = ?,
                content_encrypted = ?,
                uploaded_file_name = ?,
                uploaded_file_mime = ?,
                uploaded_file_size = ?,
                uploaded_file_encrypted = ?,
                updated_at = ?
            WHERE id = ? AND userid = ?
            """,
            (
                title,
                description,
                encrypted_content,
                uploaded_name,
                uploaded_mime,
                uploaded_size,
                uploaded_encrypted,
                updated_at,
                file_id,
                userid,
            ),
        )

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
            "SELECT id FROM user_files WHERE id = ? AND userid = ?",
            (file_id, userid),
        ).fetchone()
        if row is None:
            return jsonify({"error": "File not found."}), 404

        conn.execute(
            "DELETE FROM user_files WHERE id = ? AND userid = ?",
            (file_id, userid),
        )

    return jsonify({"message": "File deleted successfully."})


@app.post('/admin/wipe_all')
def admin_wipe_all():
    """Dangerous: wipe all users and user files from the database.

    This endpoint is protected by an environment token `ADMIN_WIPE_TOKEN`.
    Callers must supply the same token in the `X-ADMIN-TOKEN` header or
    as form field `admin_token` to authorize the wipe.
    """
    # Require an admin token to avoid accidental data loss.
    provided = (request.headers.get('X-ADMIN-TOKEN') or request.form.get('admin_token') or "").strip()
    expected = os.environ.get('ADMIN_WIPE_TOKEN', '').strip()
    if not expected:
        return jsonify({"error": "Admin wipe token not configured on server."}), 403
    if not provided or provided != expected:
        return jsonify({"error": "Invalid admin token."}), 403

    try:
        with db_connection() as conn:
            conn.execute('DELETE FROM user_files')
            conn.execute('DELETE FROM users')
    except sqlite3.Error:
        return jsonify({"error": "Database error while wiping data."}), 500

    # Re-initialize DB schema to ensure default columns exist after wipe.
    init_db()
    return jsonify({"message": "All user accounts and files have been erased."})

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
        # Delete all user files from database
        conn.execute("DELETE FROM user_files WHERE userid = ?", (userid,))

        # Delete user account from database
        conn.execute("DELETE FROM users WHERE userid = ?", (userid,))

    # Clear session
    session.clear()

    return jsonify({"message": "Account deleted successfully."})

print("Serving from:", BASE_DIR)

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="localhost", port=5000)