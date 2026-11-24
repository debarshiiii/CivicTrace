# backend/app/routers/officials.py
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from ..database import get_db
from ..models import User, UserRole
from ..auth import (
    verify_password,
    create_access_token,
    login_blocked_seconds,
    record_login_failure,
    clear_login_failures,
)
from ..audit_service import log_audit

router = APIRouter(prefix="/api/officials", tags=["officials"])


class OfficialLogin(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


GOV_ROLES = {UserRole.official, UserRole.admin, UserRole.supervisor, UserRole.auditor}


@router.post("/login", response_model=TokenResponse)
def official_login(payload: OfficialLogin, request: Request, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    ip = request.client.host if request.client else "unknown"
    key = f"{ip}|{email}"

    wait = login_blocked_seconds(key)
    if wait:
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {wait // 60 + 1} minute(s).",
        )

    user = db.query(User).filter(func.lower(User.email) == email).first()

    if (
        not user
        or user.role not in GOV_ROLES
        or not verify_password(payload.password, user.password_hash)
    ):
        record_login_failure(key)
        raise HTTPException(status_code=401, detail="Invalid credentials or not an official")

    clear_login_failures(key)

    token = create_access_token(data={"sub": str(user.id), "role": user.role.value})
    log_audit(
        db,
        actor_type="gov_user",
        action="official.login",
        entity_type="user",
        entity_id=str(user.id),
        actor_id=user.id,
    )
    return {"access_token": token}