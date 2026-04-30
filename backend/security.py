import base64
import hashlib
import hmac
import io
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pyotp
import qrcode
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, create_refresh_token


bcrypt = Bcrypt()


def hash_password(password: str) -> str:
    return bcrypt.generate_password_hash(password, rounds=12).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.check_password_hash(password_hash, password)


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp_code(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def build_totp_uri(secret: str, username: str, issuer: str = "SecureLoginApp") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def build_qr_base64(data: str) -> str:
    image = qrcode.make(data)
    buffer = io.BytesIO()
    image.save(buffer)
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def generate_backup_codes(count: int = 10) -> list[str]:
    return [secrets.token_hex(4).upper() for _ in range(count)]


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def encode_backup_codes(codes: list[str]) -> str:
    hashed_codes = [hash_backup_code(code) for code in codes]
    return json.dumps(hashed_codes)


def verify_backup_code(encoded_codes: str, raw_code: str) -> tuple[bool, str]:
    code_hash = hash_backup_code(raw_code)
    stored_codes = json.loads(encoded_codes) if encoded_codes else []
    if code_hash in stored_codes:
        stored_codes.remove(code_hash)
        return True, json.dumps(stored_codes)
    return False, encoded_codes


def build_tokens(identity: str, role: str = "user") -> dict[str, str]:
    claims = {"role": role}
    access_token = create_access_token(identity=identity, additional_claims=claims, fresh=True)
    refresh_token = create_refresh_token(identity=identity, additional_claims=claims)
    return {"access_token": access_token, "refresh_token": refresh_token}


def device_fingerprint(ip_address: str, user_agent: str) -> str:
    payload = f"{ip_address}|{user_agent}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def lockout_until(minutes: int) -> str:
    locked = now_utc() + timedelta(minutes=minutes)
    return locked.isoformat()


def is_lockout_expired(locked_until: str | None) -> bool:
    if not locked_until:
        return True
    return datetime.fromisoformat(locked_until) <= now_utc()


def generate_reset_token() -> str:
    return str(uuid.uuid4())


def generate_csrf_token(secret_key: str, session_key: str) -> str:
    nonce = secrets.token_urlsafe(32)
    payload = f"{session_key}:{nonce}"
    signature = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"


def validate_csrf_token(secret_key: str, token: str) -> bool:
    parts = token.split(":")
    if len(parts) != 3:
        return False
    session_key, nonce, provided_signature = parts
    payload = f"{session_key}:{nonce}"
    expected_signature = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_signature, provided_signature)


def notification_message(username: str, ip_address: str, user_agent: str) -> dict[str, Any]:
    return {
        "channel": "email_or_sms",
        "subject": "New device login detected",
        "message": f"New login for {username} from {ip_address} with device {user_agent}",
    }
