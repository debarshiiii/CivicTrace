# backend/app/routers/officials.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..database import get_db
from ..models import User, UserRole
from ..auth import verify_password, create_access_token
from ..audit_service import log_audit

router = APIRouter(prefix="/api/officials", tags=["officials"])


class OfficialLogin(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# Roles considered as "government officials" for login
GOV_ROLES = {UserRole.official, UserRole.admin, UserRole.supervisor, UserRole.auditor}


@router.post("/login", response_model=TokenResponse)
def official_login(payload: OfficialLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or user.role not in GOV_ROLES:
        raise HTTPException(status_code=401, detail="Invalid credentials or not an official")
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(data={"sub": str(user.id), "role": user.role.value})
    log_audit(
        db,
        actor_type="gov_user",
        action="official.login",
        entity_type="user",
        entity_id=str(user.id),
        actor_id=user.id
    )
    return {"access_token": token}