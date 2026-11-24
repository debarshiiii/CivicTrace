from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict

from jose import jwt, JWTError

from .config import settings


# =========================================================
# PASSWORD HASHING
# =========================================================

pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)


# =========================================================
# JWT
# =========================================================

SECRET_KEY = settings.SECRET_KEY

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60


# =========================================================
# PASSWORD
# =========================================================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:

    try:
        return pwd_context.verify(
            plain_password,
            hashed_password
        )

    except Exception:
        return False


# =========================================================
# CREATE TOKEN
# =========================================================

def create_access_token(
    data: Dict[str, str],
    expires_delta: Optional[timedelta] = None
) -> str:

    to_encode = data.copy()

    expire = (
        datetime.now(timezone.utc)
        + (
            expires_delta
            or timedelta(
                minutes=ACCESS_TOKEN_EXPIRE_MINUTES
            )
        )
    )

    to_encode.update({
        "exp": expire
    })

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


# =========================================================
# DECODE TOKEN
# =========================================================

def decode_access_token(
    token: str
) -> Optional[Dict]:

    try:

        return jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

    except JWTError:

        return None

    except Exception:

        return None

# =========================================================
# CASE EVIDENCE KEY (stateless, short lived)
#
# Returned when a citizen creates a case. It proves "I created this
# case just now" so only that person can attach report photos to it.
# =========================================================

CASE_KEY_SCOPE = "case_evidence"
CASE_KEY_MINUTES = 30


def create_case_key(case_id: str) -> str:
    return create_access_token(
        data={"sub": case_id, "scope": CASE_KEY_SCOPE},
        expires_delta=timedelta(minutes=CASE_KEY_MINUTES)
    )


def verify_case_key(token: Optional[str], case_id: str) -> bool:
    if not token:
        return False

    payload = decode_access_token(token)

    return bool(
        payload
        and payload.get("scope") == CASE_KEY_SCOPE
        and payload.get("sub") == case_id
    )


# =========================================================
# LOGIN THROTTLING (in-memory, per email + client IP)
#
# Locks a login key for LOGIN_LOCKOUT_MINUTES after
# LOGIN_MAX_FAILURES wrong passwords. State lives in this process, so
# it resets on restart and is per-worker; use Redis for multi-server.
# =========================================================

import threading
import time as _time

_login_lock = threading.Lock()
_login_state: Dict[str, Dict[str, float]] = {}


def login_blocked_seconds(key: str) -> int:
    """Seconds left on a lockout for `key`, or 0 if allowed."""
    with _login_lock:
        entry = _login_state.get(key)
        if not entry:
            return 0
        remaining = entry.get("locked_until", 0) - _time.time()
        if remaining > 0:
            return int(remaining) + 1
        if entry.get("locked_until"):
            _login_state.pop(key, None)
        return 0


def record_login_failure(key: str) -> bool:
    """Count a failure. Returns True if this failure triggered a lockout."""
    with _login_lock:
        entry = _login_state.setdefault(key, {"fails": 0, "locked_until": 0})
        entry["fails"] += 1
        if entry["fails"] >= settings.LOGIN_MAX_FAILURES:
            entry["locked_until"] = _time.time() + settings.LOGIN_LOCKOUT_MINUTES * 60
            entry["fails"] = 0
            return True
        return False


def clear_login_failures(key: str) -> None:
    with _login_lock:
        _login_state.pop(key, None)