from dataclasses import dataclass
import os
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class AppConfig:
    secret_key: str
    jwt_secret_key: str
    database_path: str
    jwt_access_token_minutes: int
    jwt_refresh_token_days: int
    lockout_minutes: int
    max_failed_attempts: int
    csrf_time_limit: int | None


def load_config() -> AppConfig:
    return AppConfig(
        secret_key=os.getenv("SECRET_KEY", "dev-secret"),
        jwt_secret_key=os.getenv("JWT_SECRET_KEY", "dev-jwt-secret"),
        database_path=os.getenv("DATABASE_PATH", "backend/login.db"),
        jwt_access_token_minutes=int(os.getenv("JWT_ACCESS_TOKEN_MINUTES", "15")),
        jwt_refresh_token_days=int(os.getenv("JWT_REFRESH_TOKEN_DAYS", "7")),
        lockout_minutes=int(os.getenv("LOCKOUT_MINUTES", "15")),
        max_failed_attempts=int(os.getenv("MAX_FAILED_ATTEMPTS", "3")),
        csrf_time_limit=None,
    )
