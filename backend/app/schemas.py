from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Any, Dict
from datetime import datetime


# =========================================================
# USER
# =========================================================

class UserCreate(BaseModel):
    email: str
    password: str
    role: str
    name: Optional[str] = None


class UserLogin(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    role: str
    name: Optional[str] = None
    created_at: Optional[datetime] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# =========================================================
# CITIZEN TOKEN
# =========================================================

class CitizenTokenCreate(BaseModel):
    pass


class CitizenTokenResponse(BaseModel):
    token: str


# =========================================================
# CASE
# =========================================================

class CaseCreate(BaseModel):
    id: Optional[str] = None
    title: str
    description: Optional[str] = None
    category: str
    location_text: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    risk_score: int = 0
    reporter_token: Optional[str] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    location_text: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    risk_score: Optional[int] = None
    status: Optional[str] = None


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: Optional[str] = None
    category: str
    location_text: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    risk_score: int
    status: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# =========================================================
# EVIDENCE
# =========================================================

class EvidenceCreate(BaseModel):
    case_id: str
    type: str = "report"
    url: Optional[str] = None
    uploaded_by_type: str = "citizen"
    uploaded_by_id: Optional[int] = None
    description: Optional[str] = None
    photo_data: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: str
    type: str
    url: str
    uploaded_by_type: str
    uploaded_by_id: Optional[int] = None
    meta: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None


# =========================================================
# ASSIGNMENT
# =========================================================

class AssignmentCreate(BaseModel):
    case_id: str
    worker_id: int


# =========================================================
# RESOLUTION CLAIM
# =========================================================

class ResolutionClaimCreate(BaseModel):
    case_id: str
    worker_id: int
    description: Optional[str] = None
    before_evidence_id: Optional[int] = None
    after_evidence_id: Optional[int] = None


# =========================================================
# RESOLUTION VERIFICATION
# =========================================================

class ResolutionVerificationCreate(BaseModel):
    case_id: str
    verifier_id: Optional[int] = None
    decision: str
    notes: Optional[str] = None


# =========================================================
# AUDIT LOG
# =========================================================

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True
    )

    id: int
    actor_type: str
    actor_id: Optional[int] = None
    action: str
    entity_type: str
    entity_id: str

    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        validation_alias="meta",
        serialization_alias="metadata"
    )

    timestamp: datetime