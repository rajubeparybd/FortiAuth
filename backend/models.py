from backend.db import execute_query


SCHEMA_QUERIES: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_2fa_enabled INTEGER NOT NULL DEFAULT 0,
        totp_secret TEXT,
        backup_codes TEXT,
        failed_login_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS login_attempts (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        ip_address TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        success INTEGER NOT NULL,
        attempted_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS trusted_devices (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        device_fingerprint TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        last_used TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS token_blacklist (
        id TEXT PRIMARY KEY,
        token_jti TEXT UNIQUE NOT NULL,
        expires_at TEXT NOT NULL,
        blacklisted_at TEXT NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
    "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
    "CREATE INDEX IF NOT EXISTS idx_login_attempts_user_id ON login_attempts(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_password_reset_token ON password_reset_tokens(token);",
    "CREATE INDEX IF NOT EXISTS idx_trusted_device_fingerprint ON trusted_devices(device_fingerprint);",
    "CREATE INDEX IF NOT EXISTS idx_blacklist_jti ON token_blacklist(token_jti);",
]


def initialize_schema(db_path: str) -> None:
    for query in SCHEMA_QUERIES:
        execute_query(db_path, query)
