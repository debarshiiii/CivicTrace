from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Optional, Any, Dict
from datetime import datetime


# =========================================================
# USER
# =========================================================

class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=128)
    role: str
    name: str = Field(min_length=1, max_length=100)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or v.startswith("@") or v.endswith("@"):
            raise ValueError("Enter a valid email address")
        return v

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Name is required")
        return v


class UserLogin(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)


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
    # "id" and "risk_score" are deliberately NOT accepted from the client;
    # the server generates the ID and computes the risk score. Unknown
    # fields sent by older clients are ignored.
    title: str = Field(min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    category: str = Field(max_length=40)
    location_text: Optional[str] = Field(default=None, max_length=300)
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    reporter_token: Optional[str] = Field(default=None, max_length=40)


class CaseUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    category: Optional[str] = Field(default=None, max_length=40)
    location_text: Optional[str] = Field(default=None, max_length=300)
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
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

    ai_verified: Optional[bool] = None
    ai_confidence: Optional[float] = None
    ai_detected_category: Optional[str] = None
    ai_severity_score: Optional[int] = None
    ai_reasoning: Optional[str] = None
    ai_flagged: bool = False
    hotspot_score: Optional[int] = None


# =========================================================
# EVIDENCE
# =========================================================

class EvidenceCreate(BaseModel):
    # Public citizen photo upload. The server decides who uploaded it, so
    # "url", "uploaded_by_type" and "uploaded_by_id" are ignored.
    case_id: str = Field(max_length=64)
    type: str = "report"
    description: Optional[str] = Field(default=None, max_length=1000)
    photo_data: Optional[str] = None


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
    worker_id: Optional[int] = None  # ignored; the signed-in worker is used
    description: Optional[str] = Field(default=None, max_length=2000)
    before_evidence_id: Optional[int] = None
    after_evidence_id: Optional[int] = None


# =========================================================
# RESOLUTION VERIFICATION
# =========================================================

class ResolutionVerificationCreate(BaseModel):
    case_id: str
    verifier_id: Optional[int] = None  # ignored; the signed-in official is used
    decision: str
    notes: Optional[str] = Field(default=None, max_length=2000)


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