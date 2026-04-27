from app.core.security import get_password_hash, verify_password
from app.models.entities import User

MIN_PASSWORD_LENGTH = 8


def validate_password_policy(password: str) -> str:
    normalized = password.strip()
    if len(normalized) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    return normalized


def build_user(email: str, password: str, tenant_id) -> User:
    validated_password = validate_password_policy(password)
    return User(
        email=email,
        hashed_password=get_password_hash(validated_password),
        tenant_id=tenant_id,
    )


def verify_user_credentials(user: User | None, password: str) -> bool:
    if user is None:
        return False
    if not user.is_active:
        return False
    return verify_password(password, user.hashed_password)
