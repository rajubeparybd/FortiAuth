from datetime import timedelta

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from backend.auth import auth_blueprint
from backend.config import load_config
from backend.db import execute_query
from backend.security import bcrypt


def create_app() -> Flask:
    config = load_config()
    app = Flask(__name__, static_folder="../frontend", static_url_path="")

    app.config["SECRET_KEY"] = config.secret_key
    app.config["JWT_SECRET_KEY"] = config.jwt_secret_key
    app.config["DATABASE_PATH"] = config.database_path
    app.config["LOCKOUT_MINUTES"] = config.lockout_minutes
    app.config["MAX_FAILED_ATTEMPTS"] = config.max_failed_attempts
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=config.jwt_access_token_minutes)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=config.jwt_refresh_token_days)
    app.config["JWT_TOKEN_LOCATION"] = ["headers"]
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

    CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": "*"}})
    bcrypt.init_app(app)

    limiter = Limiter(get_remote_address, app=app, default_limits=["100 per hour"])
    jwt = JWTManager(app)

    @jwt.token_in_blocklist_loader
    def is_token_revoked(jwt_header, jwt_payload) -> bool:
        row = execute_query(
            app.config["DATABASE_PATH"],
            "SELECT id FROM token_blacklist WHERE token_jti = ? LIMIT 1",
            (jwt_payload["jti"],),
            fetchone=True,
        )
        return row is not None

    app.register_blueprint(auth_blueprint)

    limiter.limit("5 per 5 minutes")(app.view_functions["auth.login"])
    limiter.limit("5 per day")(app.view_functions["auth.register"])
    limiter.limit("3 per hour")(app.view_functions["auth.forgot_password"])

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/")
    def root():
        return send_from_directory(app.static_folder, "index.html")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
