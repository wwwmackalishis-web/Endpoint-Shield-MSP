"""Password hashing and JWT issuance/verification for the MSP dashboard.

Only the dashboard's human users go through this. agent.ps1's heartbeat
stays on the existing MSP_API_KEY scheme (see app/main.py) - an unattended
background script can't practically do an interactive login/refresh cycle
the way a technician's browser session can, and multi-tenant scoping for
agent-reported devices is handled differently (an optional tenant field in
the heartbeat payload, defaulting to a "Default" tenant).
"""

import os
import sys
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User

_DEV_SECRET = "dev-only-insecure-secret-change-me"
SECRET_KEY = os.environ.get("MSP_JWT_SECRET", _DEV_SECRET)
if SECRET_KEY == _DEV_SECRET:
    # MSP_DATABASE_URL is the same signal app/database.py uses to tell local
    # SQLite dev apart from a real deployment (Postgres, e.g. a Render add-on)
    # - see its module docstring. Reuse it here rather than inventing a
    # second "is this production" heuristic: if someone has pointed this
    # process at a real database, this is not localhost anymore, and a
    # forgeable JWT secret is a full auth bypass (anyone can mint a token for
    # any username/tenant_id), not just a config nag. Fail loudly instead of
    # letting a real deployment run on the well-known dev secret because a
    # warning scrolled off a log somewhere.
    if os.environ.get("MSP_DATABASE_URL"):
        raise RuntimeError(
            "MSP_JWT_SECRET is not set, but MSP_DATABASE_URL is - this looks "
            "like a real deployment, not local dev. Refusing to start on the "
            "well-known dev JWT secret (every token would be forgeable). Set "
            "MSP_JWT_SECRET to a long random value before starting this "
            "process."
        )
    print(
        "WARNING: MSP_JWT_SECRET is not set - using an insecure, publicly-known "
        "dev secret. Every JWT this process issues is forgeable. Set "
        "MSP_JWT_SECRET before this ever runs anywhere but localhost.",
        file=sys.stderr,
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # one technician workday

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(username: str, tenant_id: int) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "tenant_id": tenant_id, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_error
    except JWTError:
        raise credentials_error

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_error
    return user
