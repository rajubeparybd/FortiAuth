import re
from email_validator import validate_email, EmailNotValidError

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,50}$")
PASSWORD_SPECIAL_PATTERN = re.compile(r"[!@#$%^&*(),.?\":{}|<>]")


def validate_username(username: str) -> tuple[bool, str]:
    if not USERNAME_PATTERN.match(username):
        return False, "Username must be 3-50 chars and contain letters, numbers, _, ., - only."
    return True, ""


def validate_email_address(email: str) -> tuple[bool, str]:
    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError as error:
        return False, str(error)
    return True, ""


def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password must be 128 characters or less."
    if not any(character.isupper() for character in password):
        return False, "Password must include at least one uppercase letter."
    if not any(character.islower() for character in password):
        return False, "Password must include at least one lowercase letter."
    if not any(character.isdigit() for character in password):
        return False, "Password must include at least one number."
    if not PASSWORD_SPECIAL_PATTERN.search(password):
        return False, "Password must include at least one special character."
    return True, ""
