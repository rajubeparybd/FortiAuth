import json
import uuid
from datetime import datetime, timedelta
from typing import Any

from flask import Blueprint, current_app, jsonify, make_response, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required

from backend.db import execute_query
from backend.security import (
    build_qr_base64,
    build_tokens,
    build_totp_uri,
    device_fingerprint,
    encode_backup_codes,
    generate_backup_codes,
    generate_csrf_token,
    generate_reset_token,
    hash_password,
    is_lockout_expired,
    lockout_until,
    notification_message,
    now_utc,
    validate_csrf_token,
    verify_backup_code,
    verify_password,
    verify_totp_code,
)
from backend.validators import validate_email_address, validate_password_strength, validate_username

auth_blueprint = Blueprint("auth", __name__, url_prefix="/api")


def _db_path() -> str:
    return current_app.config["DATABASE_PATH"]


def _json_error(message: str, status: int = 400):
    return jsonify({"error": message}), status


def _request_json() -> dict[str, Any]:
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else {}


def _store_login_attempt(user_id: str | None, success: bool) -> None:
    execute_query(
        _db_path(),
        """
        INSERT INTO login_attempts (id, user_id, ip_address, user_agent, success, attempted_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            user_id,
            request.remote_addr or "unknown",
            request.headers.get("User-Agent", "unknown"),
            1 if success else 0,
            now_utc().isoformat(),
        ),
    )


def _ip_lockout_remaining_seconds(ip_address: str) -> int:
    max_failed_attempts = current_app.config["MAX_FAILED_ATTEMPTS"]
    lockout_seconds = current_app.config["LOCKOUT_MINUTES"] * 60
    recent_attempts = execute_query(
        _db_path(),
        """
        SELECT success, attempted_at FROM login_attempts
        WHERE ip_address = ?
        ORDER BY attempted_at DESC
        LIMIT ?
        """,
        (ip_address, max_failed_attempts),
        fetchall=True,
    ) or []
    if len(recent_attempts) < max_failed_attempts:
        return 0

    has_success = any(int(attempt["success"]) == 1 for attempt in recent_attempts)
    if has_success:
        return 0

    oldest_failed_attempt = recent_attempts[-1]
    first_failure_time = datetime.fromisoformat(oldest_failed_attempt["attempted_at"])
    elapsed = int((now_utc() - first_failure_time).total_seconds())
    return max(0, lockout_seconds - elapsed)


def _lockout_remaining_seconds(locked_until: str | None) -> int:
    if not locked_until:
        return 0
    try:
        remaining = datetime.fromisoformat(locked_until) - now_utc()
    except ValueError:
        return 0
    return max(0, int(remaining.total_seconds()))


@auth_blueprint.get("/csrf-token")
def csrf_token():
    session_key = request.remote_addr or "anonymous"
    token = generate_csrf_token(current_app.config["SECRET_KEY"], session_key)
    response = make_response(jsonify({"csrf_token": token}))
    response.set_cookie("csrf_token", token, httponly=False, samesite="Strict", secure=False)
    return response


@auth_blueprint.post("/auth/register")
def register():
    payload = _request_json()
    username = str(payload.get("username", "")).strip()
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))

    valid_username, username_error = validate_username(username)
    if not valid_username:
        return _json_error(username_error)
    valid_email, email_error = validate_email_address(email)
    if not valid_email:
        return _json_error(email_error)
    valid_password, password_error = validate_password_strength(password)
    if not valid_password:
        return _json_error(password_error)

    existing_user = execute_query(
        _db_path(),
        "SELECT id FROM users WHERE username = ? OR email = ?",
        (username, email),
        fetchone=True,
    )
    if existing_user:
        return _json_error("Username or email already exists.")

    user_id = str(uuid.uuid4())
    execute_query(
        _db_path(),
        """
        INSERT INTO users (
            id, username, email, password_hash, is_2fa_enabled, totp_secret, backup_codes,
            failed_login_attempts, locked_until, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 0, NULL, NULL, 0, NULL, ?, ?)
        """,
        (user_id, username, email, hash_password(password), now_utc().isoformat(), now_utc().isoformat()),
    )
    return jsonify({"message": "User registered successfully."}), 201


@auth_blueprint.post("/auth/login")
def login():
    payload = _request_json()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    client_ip = request.remote_addr or "unknown"

    ip_remaining_seconds = _ip_lockout_remaining_seconds(client_ip)
    if ip_remaining_seconds > 0:
        return (
            jsonify(
                {
                    "error": "Too many failed attempts. Login is blocked temporarily.",
                    "retry_after_seconds": ip_remaining_seconds,
                }
            ),
            423,
        )

    user = execute_query(
        _db_path(),
        "SELECT * FROM users WHERE username = ?",
        (username,),
        fetchone=True,
    )
    if not user:
        _store_login_attempt(None, False)
        unknown_user_ip_remaining_seconds = _ip_lockout_remaining_seconds(client_ip)
        if unknown_user_ip_remaining_seconds > 0:
            return (
                jsonify(
                    {
                        "error": "Too many failed attempts. Login is blocked temporarily.",
                        "retry_after_seconds": unknown_user_ip_remaining_seconds,
                    }
                ),
                423,
            )
        return _json_error("Invalid username or password.", 401)

    if not is_lockout_expired(user.get("locked_until")):
        remaining_seconds = _lockout_remaining_seconds(user.get("locked_until"))
        _store_login_attempt(user["id"], False)
        return (
            jsonify(
                {
                    "error": "Account is temporarily locked due to failed attempts.",
                    "retry_after_seconds": remaining_seconds,
                }
            ),
            423,
        )

    # Lockout window has passed; clear stale lockout/attempt counters.
    if user.get("locked_until") or int(user.get("failed_login_attempts", 0)) >= current_app.config["MAX_FAILED_ATTEMPTS"]:
        execute_query(
            _db_path(),
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
            (now_utc().isoformat(), user["id"]),
        )
        user["failed_login_attempts"] = 0
        user["locked_until"] = None

    if not verify_password(password, user["password_hash"]):
        failed_attempts = int(user["failed_login_attempts"]) + 1
        locked_until = lockout_until(current_app.config["LOCKOUT_MINUTES"]) if failed_attempts >= current_app.config["MAX_FAILED_ATTEMPTS"] else None
        execute_query(
            _db_path(),
            "UPDATE users SET failed_login_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?",
            (failed_attempts, locked_until, now_utc().isoformat(), user["id"]),
        )
        _store_login_attempt(user["id"], False)
        ip_remaining_seconds = _ip_lockout_remaining_seconds(client_ip)
        if ip_remaining_seconds > 0:
            return (
                jsonify(
                    {
                        "error": "Too many failed attempts. Login is blocked temporarily.",
                        "retry_after_seconds": ip_remaining_seconds,
                    }
                ),
                423,
            )
        if locked_until:
            remaining_seconds = _lockout_remaining_seconds(locked_until)
            return (
                jsonify(
                    {
                        "error": "Account is temporarily locked due to failed attempts.",
                        "retry_after_seconds": remaining_seconds,
                    }
                ),
                423,
            )
        return _json_error("Invalid username or password.", 401)

    execute_query(
        _db_path(),
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
        (now_utc().isoformat(), user["id"]),
    )

    if int(user["is_2fa_enabled"]) == 1:
        _store_login_attempt(user["id"], True)
        return jsonify({"message": "2FA required.", "requires_2fa": True, "user_id": user["id"]})

    tokens = build_tokens(user["id"])
    _store_login_attempt(user["id"], True)
    return jsonify({"message": "Login successful.", "requires_2fa": False, **tokens})


@auth_blueprint.get("/auth/lockout-status")
def lockout_status():
    client_ip = request.remote_addr or "unknown"
    remaining_seconds = _ip_lockout_remaining_seconds(client_ip)
    return jsonify({"retry_after_seconds": remaining_seconds})


@auth_blueprint.post("/auth/verify-2fa")
def verify_2fa():
    payload = _request_json()
    user_id = str(payload.get("user_id", ""))
    code = str(payload.get("code", "")).strip()

    user = execute_query(_db_path(), "SELECT * FROM users WHERE id = ?", (user_id,), fetchone=True)
    if not user:
        return _json_error("Invalid user.", 404)
    secret = user.get("totp_secret")
    if not secret:
        return _json_error("2FA is not configured for this account.")

    valid_code = verify_totp_code(secret, code)
    updated_codes = user.get("backup_codes")
    if not valid_code and updated_codes:
        valid_code, updated_codes = verify_backup_code(updated_codes, code)
        if valid_code:
            execute_query(
                _db_path(),
                "UPDATE users SET backup_codes = ?, updated_at = ? WHERE id = ?",
                (updated_codes, now_utc().isoformat(), user_id),
            )
    if not valid_code:
        return _json_error("Invalid 2FA code.", 401)

    tokens = build_tokens(user_id)
    return jsonify({"message": "2FA verification successful.", **tokens})


@auth_blueprint.post("/auth/setup-2fa")
@jwt_required()
def setup_2fa():
    user_id = get_jwt_identity()
    user = execute_query(
        _db_path(),
        "SELECT username, is_2fa_enabled FROM users WHERE id = ?",
        (user_id,),
        fetchone=True,
    )
    if not user:
        return _json_error("User not found.", 404)
    if int(user.get("is_2fa_enabled", 0)) == 1:
        return _json_error("2FA is already enabled. Disable it first to regenerate setup.", 409)
    from backend.security import generate_totp_secret

    secret = generate_totp_secret()
    uri = build_totp_uri(secret, user["username"])
    qr_base64 = build_qr_base64(uri)
    backup_codes = generate_backup_codes()

    execute_query(
        _db_path(),
        "UPDATE users SET totp_secret = ?, backup_codes = ?, updated_at = ? WHERE id = ?",
        (secret, encode_backup_codes(backup_codes), now_utc().isoformat(), user_id),
    )
    return jsonify({"totp_secret": secret, "qr_code_base64": qr_base64, "backup_codes": backup_codes})


@auth_blueprint.get("/auth/2fa-status")
@jwt_required()
def two_fa_status():
    user_id = get_jwt_identity()
    user = execute_query(
        _db_path(),
        "SELECT is_2fa_enabled FROM users WHERE id = ?",
        (user_id,),
        fetchone=True,
    )
    if not user:
        return _json_error("User not found.", 404)
    return jsonify({"is_2fa_enabled": int(user["is_2fa_enabled"]) == 1})


@auth_blueprint.post("/auth/enable-2fa")
@jwt_required()
def enable_2fa():
    user_id = get_jwt_identity()
    payload = _request_json()
    code = str(payload.get("code", "")).strip()
    user = execute_query(_db_path(), "SELECT totp_secret FROM users WHERE id = ?", (user_id,), fetchone=True)
    if not user or not user.get("totp_secret"):
        return _json_error("2FA setup required first.")
    if not verify_totp_code(user["totp_secret"], code):
        return _json_error("Invalid verification code.", 401)
    execute_query(
        _db_path(),
        "UPDATE users SET is_2fa_enabled = 1, updated_at = ? WHERE id = ?",
        (now_utc().isoformat(), user_id),
    )
    return jsonify({"message": "2FA enabled successfully."})


@auth_blueprint.post("/auth/disable-2fa")
@jwt_required()
def disable_2fa():
    user_id = get_jwt_identity()
    execute_query(
        _db_path(),
        "UPDATE users SET is_2fa_enabled = 0, totp_secret = NULL, backup_codes = NULL, updated_at = ? WHERE id = ?",
        (now_utc().isoformat(), user_id),
    )
    return jsonify({"message": "2FA disabled successfully."})


@auth_blueprint.post("/auth/forgot-password")
def forgot_password():
    payload = _request_json()
    email = str(payload.get("email", "")).strip().lower()
    user = execute_query(_db_path(), "SELECT id, username FROM users WHERE email = ?", (email,), fetchone=True)
    # Do not reveal whether an account exists.
    if not user:
        print(f"[Password Recovery Debug] email={email} reset_token=<not-generated:user-not-found>", flush=True)
        return _json_error("User not found. Please enter a registered email.", 404)
    token = generate_reset_token()
    expires = (now_utc() + timedelta(hours=1)).isoformat()
    execute_query(
        _db_path(),
        "INSERT INTO password_reset_tokens (id, user_id, token, expires_at, used, created_at) VALUES (?, ?, ?, ?, 0, ?)",
        (str(uuid.uuid4()), user["id"], token, expires, now_utc().isoformat()),
    )
    print(f"[Password Recovery Debug] email={email} reset_token={token}", flush=True)
    return jsonify(
        {
            "message": "If the account exists, reset instructions have been generated.",
            "mock_notification": {
                "channel": "email",
                "to": email,
                "reset_token": token,
            },
        }
    )


@auth_blueprint.post("/auth/reset-password")
def reset_password():
    payload = _request_json()
    token = str(payload.get("token", "")).strip()
    new_password = str(payload.get("new_password", ""))
    valid_password, password_error = validate_password_strength(new_password)
    if not valid_password:
        return _json_error(password_error)
    row = execute_query(
        _db_path(),
        """
        SELECT * FROM password_reset_tokens
        WHERE token = ? AND used = 0
        """,
        (token,),
        fetchone=True,
    )
    if not row:
        return _json_error("Invalid or expired reset token.", 400)
    if row["expires_at"] < now_utc().isoformat():
        return _json_error("Invalid or expired reset token.", 400)

    execute_query(
        _db_path(),
        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
        (hash_password(new_password), now_utc().isoformat(), row["user_id"]),
    )
    execute_query(
        _db_path(),
        "UPDATE password_reset_tokens SET used = 1 WHERE id = ?",
        (row["id"],),
    )
    return jsonify({"message": "Password reset successful."})


@auth_blueprint.post("/auth/logout")
@jwt_required()
def logout():
    claims = get_jwt()
    token_jti = claims["jti"]
    expires_at = now_utc() + timedelta(days=current_app.config["JWT_REFRESH_TOKEN_DAYS"])
    execute_query(
        _db_path(),
        "INSERT INTO token_blacklist (id, token_jti, expires_at, blacklisted_at) VALUES (?, ?, ?, ?)",
        (str(uuid.uuid4()), token_jti, expires_at.isoformat(), now_utc().isoformat()),
    )
    return jsonify({"message": "Logout successful."})


@auth_blueprint.post("/auth/refresh")
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    tokens = build_tokens(identity)
    return jsonify(tokens)


@auth_blueprint.get("/auth/backup-codes")
@jwt_required()
def backup_codes():
    user_id = get_jwt_identity()
    user = execute_query(_db_path(), "SELECT backup_codes FROM users WHERE id = ?", (user_id,), fetchone=True)
    codes = json.loads(user["backup_codes"]) if user and user.get("backup_codes") else []
    return jsonify({"backup_codes_hashes": codes})


@auth_blueprint.get("/devices")
@jwt_required()
def list_devices():
    user_id = get_jwt_identity()
    devices = execute_query(
        _db_path(),
        "SELECT id, ip_address, user_agent, last_used, created_at FROM trusted_devices WHERE user_id = ? ORDER BY last_used DESC",
        (user_id,),
        fetchall=True,
    )
    return jsonify({"devices": devices or []})


@auth_blueprint.delete("/devices/<device_id>")
@jwt_required()
def delete_device(device_id: str):
    user_id = get_jwt_identity()
    execute_query(_db_path(), "DELETE FROM trusted_devices WHERE id = ? AND user_id = ?", (device_id, user_id))
    return jsonify({"message": "Device removed."})


@auth_blueprint.get("/user/profile")
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = execute_query(
        _db_path(),
        "SELECT id, username, email, is_2fa_enabled, created_at FROM users WHERE id = ?",
        (user_id,),
        fetchone=True,
    )
    return jsonify({"user": user})


@auth_blueprint.get("/user/login-history")
@jwt_required()
def login_history():
    user_id = get_jwt_identity()
    logs = execute_query(
        _db_path(),
        "SELECT success, ip_address, user_agent, attempted_at FROM login_attempts WHERE user_id = ? ORDER BY attempted_at DESC LIMIT 50",
        (user_id,),
        fetchall=True,
    )
    return jsonify({"history": logs or []})


@auth_blueprint.post("/security/device-check")
def device_check():
    payload = _request_json()
    user_id = str(payload.get("user_id", ""))
    username = str(payload.get("username", ""))
    ip_address = request.remote_addr or "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")
    fingerprint = device_fingerprint(ip_address, user_agent)

    existing = execute_query(
        _db_path(),
        "SELECT id FROM trusted_devices WHERE user_id = ? AND device_fingerprint = ?",
        (user_id, fingerprint),
        fetchone=True,
    )
    if existing:
        execute_query(
            _db_path(),
            "UPDATE trusted_devices SET last_used = ? WHERE id = ?",
            (now_utc().isoformat(), existing["id"]),
        )
        return jsonify({"is_new_device": False})

    execute_query(
        _db_path(),
        """
        INSERT INTO trusted_devices (id, user_id, device_fingerprint, ip_address, user_agent, last_used, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (str(uuid.uuid4()), user_id, fingerprint, ip_address, user_agent, now_utc().isoformat(), now_utc().isoformat()),
    )
    return jsonify({"is_new_device": True, "mock_notification": notification_message(username, ip_address, user_agent)})


@auth_blueprint.before_app_request
def csrf_guard():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not request.path.startswith("/api/auth/login"):
        csrf_cookie = request.cookies.get("csrf_token", "")
        csrf_header = request.headers.get("X-CSRF-Token", "")
        if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
            return _json_error("CSRF validation failed.", 403)
        if not validate_csrf_token(current_app.config["SECRET_KEY"], csrf_header):
            return _json_error("CSRF validation failed.", 403)
