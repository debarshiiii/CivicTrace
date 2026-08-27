import enum

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Float,
    DateTime,
    Enum,
    ForeignKey,
    Boolean,
    JSON,
    func
)

from sqlalchemy.orm import relationship

from .database import Base


# =========================================================
# ENUMS
# =========================================================

class UserRole(str, enum.Enum):
    worker = "worker"
    supervisor = "supervisor"
    admin = "admin"
    auditor = "auditor"
    official = "official"


class CaseStatus(str, enum.Enum):
    received = "received"
    validated = "validated"
    assigned = "assigned"
    in_progress = "in_progress"
    resolution_claimed = "resolution_claimed"
    verifying = "verifying"
    resolved = "resolved"
    rejected = "rejected"


# =========================================================
# GOVERNMENT USERS
# =========================================================

class User(Base):

    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    name = Column(
        String,
        nullable=False
    )

    email = Column(
        String,
        unique=True,
        index=True,
        nullable=False
    )

    password_hash = Column(
        String,
        nullable=False
    )

    role = Column(
        Enum(UserRole),
        nullable=False
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    assignments = relationship(
        "Assignment",
        back_populates="worker"
    )

    resolution_claims = relationship(
        "ResolutionClaim",
        back_populates="worker"
    )

    verifications = relationship(
        "ResolutionVerification",
        back_populates="verifier"
    )

# =========================================================
# GOVERNMENT REGISTRATION TOKENS
# =========================================================

class OfficialToken(Base):

    __tablename__ = "official_tokens"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    token = Column(
        String,
        unique=True,
        nullable=False,
        index=True
    )

    role = Column(
        Enum(UserRole),
        nullable=False,
        default=UserRole.official
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False
    )

    used = Column(
        Boolean,
        default=False,
        nullable=False
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    used_at = Column(
        DateTime(timezone=True),
        nullable=True
    )


# =========================================================
# CITIZEN TOKENS
# =========================================================

class CitizenToken(Base):

    __tablename__ = "citizen_tokens"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    token = Column(
        String,
        unique=True,
        nullable=False,
        index=True
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    cases = relationship(
        "Case",
        back_populates="reporter_token"
    )


# =========================================================
# CASES
# =========================================================

class Case(Base):

    __tablename__ = "cases"

    id = Column(
        String,
        primary_key=True
    )

    title = Column(
        String,
        nullable=False
    )

    description = Column(
        Text
    )

    category = Column(
        String,
        nullable=False
    )

    location_text = Column(
        String
    )

    latitude = Column(
        Float,
        nullable=True
    )

    longitude = Column(
        Float,
        nullable=True
    )

    risk_score = Column(
        Integer,
        default=0
    )

    status = Column(
        Enum(CaseStatus),
        default=CaseStatus.received,
        nullable=False
    )

    reporter_token_id = Column(
        Integer,
        ForeignKey("citizen_tokens.id"),
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    reporter_token = relationship(
        "CitizenToken",
        back_populates="cases"
    )

    evidence_list = relationship(
        "Evidence",
        back_populates="case"
    )

    assignments = relationship(
        "Assignment",
        back_populates="case"
    )

    resolution_claims = relationship(
        "ResolutionClaim",
        back_populates="case"
    )

    verifications = relationship(
        "ResolutionVerification",
        back_populates="case"
    )


# =========================================================
# EVIDENCE
# =========================================================

class Evidence(Base):

    __tablename__ = "evidence"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        String,
        ForeignKey("cases.id"),
        nullable=False
    )

    type = Column(
        String,
        nullable=False
    )

    url = Column(
        String,
        nullable=False
    )

    uploaded_by_type = Column(
        String,
        nullable=True
    )

    uploaded_by_id = Column(
        Integer,
        nullable=True
    )

    meta = Column(
        JSON,
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    case = relationship(
        "Case",
        back_populates="evidence_list"
    )


# =========================================================
# ASSIGNMENTS
# =========================================================

class Assignment(Base):

    __tablename__ = "assignments"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        String,
        ForeignKey("cases.id"),
        nullable=False
    )

    worker_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    status = Column(
        String,
        default="assigned",
        nullable=False
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    case = relationship(
        "Case",
        back_populates="assignments"
    )

    worker = relationship(
        "User",
        back_populates="assignments"
    )


# =========================================================
# RESOLUTION CLAIM
# =========================================================

class ResolutionClaim(Base):

    __tablename__ = "resolution_claims"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        String,
        ForeignKey("cases.id"),
        nullable=False
    )

    worker_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    before_evidence_id = Column(
        Integer,
        ForeignKey("evidence.id"),
        nullable=True
    )

    after_evidence_id = Column(
        Integer,
        ForeignKey("evidence.id"),
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    case = relationship(
        "Case",
        back_populates="resolution_claims"
    )

    worker = relationship(
        "User",
        back_populates="resolution_claims"
    )


# =========================================================
# RESOLUTION VERIFICATION
# =========================================================

class ResolutionVerification(Base):

    __tablename__ = "resolution_verifications"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        String,
        ForeignKey("cases.id"),
        nullable=False
    )

    verifier_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    decision = Column(
        String,
        nullable=False
    )

    notes = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    case = relationship(
        "Case",
        back_populates="verifications"
    )

    verifier = relationship(
        "User",
        back_populates="verifications"
    )


# =========================================================
# AUDIT LOG
# =========================================================

class AuditLog(Base):

    __tablename__ = "audit_logs"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    actor_type = Column(
        String,
        nullable=False
    )

    actor_id = Column(
        Integer,
        nullable=True
    )

    action = Column(
        String,
        nullable=False
    )

    entity_type = Column(
        String,
        nullable=False
    )

    entity_id = Column(
        String,
        nullable=True
    )

    meta = Column(
        JSON,
        nullable=True
    )

    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )