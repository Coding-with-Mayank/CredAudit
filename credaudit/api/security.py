"""Password hashing, JWT issuing/verification, and role-based access
control for the findings API.

Uses `bcrypt` directly rather than `passlib` -- passlib is effectively
unmaintained and has a known incompatibility with bcrypt>=4.1 (it probes
`bcrypt.__about__.__version__`, which newer bcrypt releases dropped),
so new code calling bcrypt directly is the current recommended path
rather than a shortcut.

Uses `PyJWT` rather than `python-jose` for the same reason: it's the
actively maintained option as of this writing.
"""
from __future__ import annotations

import os
import time

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, select

from .db import Role, User, get_session

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_SECONDS = 8 * 60 * 60  # 8 hours

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


class ConfigError(RuntimeError):
    pass


def _secret_key() -> str:
    key = os.environ.get("CREDAUDIT_JWT_SECRET")
    if not key:
        raise ConfigError(
            "CREDAUDIT_JWT_SECRET is not set. Generate one and set it before starting the server, e.g.:\n"
            "  export CREDAUDIT_JWT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')\n"
            "This is deliberately not auto-generated or defaulted: a secret that's regenerated on every "
            "process restart would silently invalidate every issued token, and a hardcoded default would "
            "be a shared secret across every install of this software."
        )
    return key


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(username: str, role: str) -> str:
    now = int(time.time())
    payload = {"sub": username, "role": role, "iat": now, "exp": now + JWT_EXPIRE_SECONDS}
    return jwt.encode(payload, _secret_key(), algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, _secret_key(), algorithms=[JWT_ALGORITHM])


def authenticate_user(session: Session, username: str, password: str) -> User:
    user = session.exec(select(User).where(User.username == username)).first()
    if user is None or user.disabled or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        raise credentials_error
    username = payload.get("sub")
    if not username:
        raise credentials_error
    user = session.exec(select(User).where(User.username == username)).first()
    if user is None or user.disabled:
        raise credentials_error
    return user


def require_role(*roles: Role):
    """FastAPI dependency factory: `Depends(require_role(Role.admin))`.
    Explicit allow-lists per endpoint rather than a hierarchy -- more
    verbose, but every endpoint's access rule is readable at its own
    definition without cross-referencing a hierarchy table elsewhere."""

    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            allowed = ", ".join(r.value for r in roles)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of these roles: {allowed}",
            )
        return user

    return checker
