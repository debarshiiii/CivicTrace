# backend/app/main.py

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request,
    UploadFile,
    File,
    Form
)

from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from sqlalchemy.orm import Session

from typing import List, Optional

from pathlib import Path
import random
import enum
import shutil
import uuid
import base64
import binascii

from .database import engine, get_db, Base

from .models import (
    User,
    UserRole,
    CitizenToken,
    Case,
    Evidence,
    Assignment,
    ResolutionClaim,
    ResolutionVerification,
    AuditLog,
    CaseStatus
)

from .schemas import (
    UserCreate,
    UserLogin,
    TokenResponse,
    CitizenTokenCreate,
    CitizenTokenResponse,
    CaseCreate,
    CaseUpdate,
    EvidenceCreate,
    AssignmentCreate,
    ResolutionClaimCreate,
    ResolutionVerificationCreate,
    AuditLogResponse,
    UserResponse
)

from .auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token
)

from .audit_service import log_audit

from .routers import officials


# ==================================================
# APP
# ==================================================

app = FastAPI(
    title="CivicTrace API",
    version="1.0.0"
)


# ==================================================
# CORS
# ==================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================================================
# UPLOAD DIRECTORIES
# ==================================================

UPLOAD_DIR = Path("uploads")

BEFORE_DIR = UPLOAD_DIR / "before"
AFTER_DIR = UPLOAD_DIR / "after"
CHALLENGE_DIR = UPLOAD_DIR / "challenges"
REPORT_DIR = UPLOAD_DIR / "reports"

BEFORE_DIR.mkdir(parents=True, exist_ok=True)
AFTER_DIR.mkdir(parents=True, exist_ok=True)
CHALLENGE_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

app.mount(
    "/uploads",
    StaticFiles(directory=str(UPLOAD_DIR)),
    name="uploads"
)


# ==================================================
# ROUTERS
# ==================================================

app.include_router(
    officials.router
)


# ==================================================
# DATABASE
# ==================================================

Base.metadata.create_all(
    bind=engine
)


# ==================================================
# GOVERNMENT AUTHENTICATION
# ==================================================

def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
):
    auth_header = request.headers.get(
        "Authorization",
        ""
    )

    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing authentication token"
        )

    token = auth_header.split(
        " ",
        1
    )[1]

    payload = decode_access_token(token)

    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    if "sub" not in payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid token subject"
        )

    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    return user


# ==================================================
# GOVERNMENT ROLE GUARD
# ==================================================

GOV_ROLES = {
    UserRole.supervisor,
    UserRole.admin,
    UserRole.auditor,
    UserRole.official
}


def require_gov_user(
    user: User = Depends(get_current_user)
) -> User:
    if user.role not in GOV_ROLES:
        raise HTTPException(
            status_code=403,
            detail="Government access required"
        )
    return user


# ==================================================
# REGISTER GOVERNMENT USER
# ==================================================

@app.post(
    "/api/auth/register",
    response_model=UserResponse
)
def register_user(
    user_in: UserCreate,
    db: Session = Depends(get_db)
):

    existing = (
        db.query(User)
        .filter(User.email == user_in.email)
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    try:
        role_enum = UserRole(
            user_in.role
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid user role"
        )

    user = User(
        email=user_in.email,
        password_hash=hash_password(
            user_in.password
        ),
        role=role_enum,
        name=user_in.name
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit(
        db,
        actor_type="system",
        action="user.created",
        entity_type="user",
        entity_id=str(user.id)
    )

    return user


# ==================================================
# GOVERNMENT LOGIN
# ==================================================

@app.post(
    "/api/auth/login",
    response_model=TokenResponse
)
def login(
    user_in: UserLogin,
    db: Session = Depends(get_db)
):

    user = (
        db.query(User)
        .filter(User.email == user_in.email)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if not verify_password(
        user_in.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "role": user.role.value
        }
    )

    log_audit(
        db,
        actor_type="gov_user",
        action="user.login",
        entity_type="user",
        entity_id=str(user.id),
        actor_id=user.id
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# ==================================================
# CURRENT USER
# ==================================================

@app.get("/api/auth/me")
def get_me(
    user: User = Depends(get_current_user)
):
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role.value
    }


# ==================================================
# CITIZEN TOKEN
# ==================================================

@app.post(
    "/api/citizens/tokens",
    response_model=CitizenTokenResponse
)
def create_citizen_token(
    payload: Optional[CitizenTokenCreate] = None,
    db: Session = Depends(get_db)
):

    chars = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
    )

    while True:

        part1 = "".join(
            random.choices(
                chars,
                k=4
            )
        )

        part2 = "".join(
            random.choices(
                chars,
                k=4
            )
        )

        token_str = f"CT-{part1}-{part2}"

        existing = (
            db.query(CitizenToken)
            .filter(
                CitizenToken.token == token_str
            )
            .first()
        )

        if not existing:
            break

    token = CitizenToken(
        token=token_str,
        is_active=True
    )

    db.add(token)
    db.commit()
    db.refresh(token)

    log_audit(
        db,
        actor_type="system",
        action="citizen_token.created",
        entity_type="citizen_token",
        entity_id=str(token.id)
    )

    return {
        "token": token_str
    }


# ==================================================
# CREATE CASE
# ==================================================

@app.post("/api/cases")
def create_case(
    case_in: CaseCreate,
    db: Session = Depends(get_db)
):

    reporter_token = None

    if case_in.reporter_token:

        reporter_token = (
            db.query(CitizenToken)
            .filter(
                CitizenToken.token
                == case_in.reporter_token
            )
            .first()
        )

        if (
            not reporter_token
            or not reporter_token.is_active
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid citizen token"
            )

    case_id = case_in.id

    if case_id:

        existing_case = (
            db.query(Case)
            .filter(
                Case.id == case_id
            )
            .first()
        )

        if existing_case:
            raise HTTPException(
                status_code=400,
                detail="Case ID already exists"
            )

    else:

        chars = "0123456789"

        while True:

            candidate = (
                "CVT-KOL-"
                + "".join(
                    random.choices(
                        chars,
                        k=6
                    )
                )
            )

            existing_case = (
                db.query(Case)
                .filter(
                    Case.id == candidate
                )
                .first()
            )

            if not existing_case:
                case_id = candidate
                break

    case = Case(
        id=case_id,
        title=case_in.title,
        description=case_in.description,
        category=case_in.category,
        location_text=case_in.location_text,
        latitude=case_in.latitude,
        longitude=case_in.longitude,
        risk_score=(
            case_in.risk_score
            if case_in.risk_score is not None
            else 50
        ),
        reporter_token_id=(
            reporter_token.id
            if reporter_token
            else None
        ),
        status=CaseStatus.received
    )

    db.add(case)
    db.commit()
    db.refresh(case)

    log_audit(
        db,
        actor_type=(
            "citizen"
            if reporter_token
            else "system"
        ),
        action="case.created",
        entity_type="case",
        entity_id=case.id
    )

    return {
        "id": case.id,
        "status": case.status.value
    }


# ==================================================
# GET SINGLE CASE
# ==================================================

@app.get("/api/cases/{case_id}")
def get_case(
    case_id: str,
    db: Session = Depends(get_db)
):

    case = (
        db.query(Case)
        .filter(
            Case.id == case_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    return {
        "id": case.id,
        "title": case.title,
        "description": case.description,
        "category": case.category,
        "location_text": case.location_text,
        "latitude": case.latitude,
        "longitude": case.longitude,
        "risk_score": case.risk_score,
        "status": case.status.value,
        "created_at": case.created_at,
        "updated_at": case.updated_at
    }


# ==================================================
# GET ALL CASES
# PUBLIC
# ==================================================

@app.get("/api/cases")
def list_cases(
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db)
):

    q = db.query(Case)

    if status_filter:

        try:
            status_enum = CaseStatus(
                status_filter
            )

            q = q.filter(
                Case.status == status_enum
            )

        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid status"
            )

    cases = q.all()

    return [
        {
            "id": case.id,
            "title": case.title,
            "description": case.description,
            "category": case.category,
            "location_text": case.location_text,
            "latitude": case.latitude,
            "longitude": case.longitude,
            "risk_score": case.risk_score,
            "status": case.status.value,
            "created_at": case.created_at,
            "updated_at": case.updated_at
        }
        for case in cases
    ]


# ==================================================
# UPDATE CASE
# GOVERNMENT ONLY
# ==================================================

@app.patch("/api/cases/{case_id}")
def update_case(
    case_id: str,
    case_in: CaseUpdate,
    user: User = Depends(require_gov_user),
    db: Session = Depends(get_db)
):

    case = (
        db.query(Case)
        .filter(
            Case.id == case_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    update_data = case_in.model_dump(
        exclude_unset=True
    )

    changes = {}

    for field, value in update_data.items():

        if field == "status":

            try:
                value = CaseStatus(value)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid case status"
                )

        old = getattr(
            case,
            field
        )

        setattr(
            case,
            field,
            value
        )

        changes[field] = {
            "old": (
                old.value
                if isinstance(old, enum.Enum)
                else old
            ),
            "new": (
                value.value
                if isinstance(value, enum.Enum)
                else value
            )
        }

    db.commit()
    db.refresh(case)

    log_audit(
        db,
        actor_type="gov_user",
        action="case.updated",
        entity_type="case",
        entity_id=case_id,
        actor_id=user.id,
        meta=changes
    )

    return case


# ==================================================
# CREATE EVIDENCE RECORD
# ==================================================

@app.post("/api/evidence")
def create_evidence(
    ev: EvidenceCreate,
    db: Session = Depends(get_db)
):

    case = (
        db.query(Case)
        .filter(
            Case.id == ev.case_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    if not ev.url and not ev.photo_data:
        raise HTTPException(
            status_code=400,
            detail="Either url or photo_data is required"
        )

    url = ev.url

    if ev.photo_data:

        raw = ev.photo_data

        extension = ".jpg"

        if raw.startswith("data:"):

            try:

                header, raw = raw.split(",", 1)

                if "image/png" in header:
                    extension = ".png"
                elif "image/webp" in header:
                    extension = ".webp"
                else:
                    extension = ".jpg"

            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid photo_data format"
                )

        try:

            file_bytes = base64.b64decode(
                raw,
                validate=True
            )

        except (binascii.Error, ValueError):
            raise HTTPException(
                status_code=400,
                detail="Invalid base64 photo_data"
            )

        filename = f"{uuid.uuid4().hex}{extension}"

        filepath = REPORT_DIR / filename

        with filepath.open("wb") as buffer:
            buffer.write(file_bytes)

        url = f"/uploads/reports/{filename}"

    meta = ev.metadata or {}

    if ev.description:
        meta = {
            **meta,
            "description": ev.description
        }

    evidence = Evidence(
        case_id=ev.case_id,
        type=ev.type,
        url=url,
        uploaded_by_type=ev.uploaded_by_type,
        uploaded_by_id=ev.uploaded_by_id,
        meta=meta
    )

    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    actor_type = (
        ev.uploaded_by_type
        if ev.uploaded_by_type
        else "system"
    )

    log_audit(
        db,
        actor_type=actor_type,
        action="evidence.created",
        entity_type="evidence",
        entity_id=str(evidence.id),
        actor_id=ev.uploaded_by_id,
        meta={
            "case_id": ev.case_id,
            "type": ev.type
        }
    )

    return evidence


# ==================================================
# UPLOAD EVIDENCE IMAGE
# ==================================================

@app.post("/api/evidence/upload")
async def upload_evidence(
    case_id: str = Form(...),
    evidence_type: str = Form(...),
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    case = (
        db.query(Case)
        .filter(
            Case.id == case_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    allowed_types = {
        "before",
        "after",
        "challenge",
        "report"
    }

    if evidence_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Invalid evidence type"
        )

    if not file.content_type or not file.content_type.startswith(
        "image/"
    ):
        raise HTTPException(
            status_code=400,
            detail="Only image files are allowed"
        )

    extension = Path(
        file.filename or ""
    ).suffix.lower()

    if extension not in {
        ".jpg",
        ".jpeg",
        ".png",
        ".webp"
    }:
        raise HTTPException(
            status_code=400,
            detail="Unsupported image format"
        )

    if evidence_type == "before":
        directory = BEFORE_DIR
    elif evidence_type == "after":
        directory = AFTER_DIR
    elif evidence_type == "challenge":
        directory = CHALLENGE_DIR
    else:
        directory = UPLOAD_DIR

    filename = (
        f"{uuid.uuid4().hex}"
        f"{extension}"
    )

    filepath = directory / filename

    with filepath.open("wb") as buffer:
        shutil.copyfileobj(
            file.file,
            buffer
        )

    url = (
        f"/uploads/"
        f"{directory.relative_to(UPLOAD_DIR)}/"
        f"{filename}"
    )

    evidence = Evidence(
        case_id=case_id,
        type=evidence_type,
        url=url,
        uploaded_by_type=(
            "worker"
            if user.role == UserRole.worker
            else "gov_user"
        ),
        uploaded_by_id=user.id,
        meta={
            "original_filename": file.filename,
            "content_type": file.content_type
        }
    )

    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    log_audit(
        db,
        actor_type="gov_user",
        action="evidence.uploaded",
        entity_type="evidence",
        entity_id=str(evidence.id),
        actor_id=user.id,
        meta={
            "case_id": case_id,
            "type": evidence_type,
            "filename": file.filename
        }
    )

    return {
        "id": evidence.id,
        "case_id": case_id,
        "type": evidence.type,
        "url": url
    }


# ==================================================
# CASE EVIDENCE
# ==================================================

@app.get(
    "/api/cases/{case_id}/evidence"
)
def get_case_evidence(
    case_id: str,
    db: Session = Depends(get_db)
):

    case = (
        db.query(Case)
        .filter(
            Case.id == case_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    evidence = (
        db.query(Evidence)
        .filter(
            Evidence.case_id == case_id
        )
        .order_by(
            Evidence.created_at.asc()
        )
        .all()
    )

    return [
        {
            "id": item.id,
            "case_id": item.case_id,
            "type": item.type,
            "url": item.url,
            "uploaded_by_type": item.uploaded_by_type,
            "uploaded_by_id": item.uploaded_by_id,
            "metadata": item.meta,
            "created_at": item.created_at
        }
        for item in evidence
    ]


# ==================================================
# ASSIGN WORKER
# GOVERNMENT ONLY
# ==================================================

@app.post("/api/assignments")
def create_assignment(
    a: AssignmentCreate,
    user: User = Depends(require_gov_user),
    db: Session = Depends(get_db)
):

    case = (
        db.query(Case)
        .filter(
            Case.id == a.case_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    worker = (
        db.query(User)
        .filter(
            User.id == a.worker_id
        )
        .first()
    )

    if (
        not worker
        or worker.role != UserRole.worker
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid worker"
        )

    assignment = Assignment(
        case_id=a.case_id,
        worker_id=a.worker_id,
        status="assigned"
    )

    db.add(assignment)

    case.status = CaseStatus.assigned

    db.commit()
    db.refresh(assignment)

    log_audit(
        db,
        actor_type="gov_user",
        action="case.assigned",
        entity_type="case",
        entity_id=a.case_id,
        actor_id=user.id,
        meta={
            "worker_id": a.worker_id,
            "worker_email": worker.email
        }
    )

    return assignment


# ==================================================
# WORKER ASSIGNMENTS
# ==================================================

@app.get("/api/workers/me/assignments")
def get_my_assignments(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    if user.role != UserRole.worker:
        raise HTTPException(
            status_code=403,
            detail="Worker access required"
        )

    assignments = (
        db.query(Assignment)
        .filter(
            Assignment.worker_id == user.id
        )
        .order_by(
            Assignment.created_at.desc()
        )
        .all()
    )

    results = []

    for assignment in assignments:

        case = assignment.case

        results.append({
            "assignment_id": assignment.id,
            "assignment_status": assignment.status,
            "case_id": case.id,
            "title": case.title,
            "description": case.description,
            "category": case.category,
            "location_text": case.location_text,
            "latitude": case.latitude,
            "longitude": case.longitude,
            "risk_score": case.risk_score,
            "case_status": case.status.value,
            "created_at": case.created_at,
            "updated_at": case.updated_at
        })

    return results


# ==================================================
# GET SINGLE WORKER ASSIGNMENT
# ==================================================

@app.get(
    "/api/workers/me/assignments/{assignment_id}"
)
def get_my_assignment(
    assignment_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    if user.role != UserRole.worker:
        raise HTTPException(
            status_code=403,
            detail="Worker access required"
        )

    assignment = (
        db.query(Assignment)
        .filter(
            Assignment.id == assignment_id,
            Assignment.worker_id == user.id
        )
        .first()
    )

    if not assignment:
        raise HTTPException(
            status_code=404,
            detail="Assignment not found"
        )

    case = assignment.case

    return {
        "assignment_id": assignment.id,
        "assignment_status": assignment.status,
        "case": {
            "id": case.id,
            "title": case.title,
            "description": case.description,
            "category": case.category,
            "location_text": case.location_text,
            "latitude": case.latitude,
            "longitude": case.longitude,
            "risk_score": case.risk_score,
            "status": case.status.value,
            "created_at": case.created_at,
            "updated_at": case.updated_at
        }
    }


# ==================================================
# RESOLUTION CLAIM
# WORKER ONLY
# ==================================================

@app.post(
    "/api/resolution-claims"
)
def create_resolution_claim(
    rc: ResolutionClaimCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    if user.role != UserRole.worker:
        raise HTTPException(
            status_code=403,
            detail="Worker access required"
        )

    case = (
        db.query(Case)
        .filter(
            Case.id == rc.case_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    assignment = (
        db.query(Assignment)
        .filter(
            Assignment.case_id == rc.case_id,
            Assignment.worker_id == user.id
        )
        .first()
    )

    if not assignment:
        raise HTTPException(
            status_code=403,
            detail="You are not assigned to this case"
        )

    if rc.before_evidence_id:

        before = (
            db.query(Evidence)
            .filter(
                Evidence.id == rc.before_evidence_id,
                Evidence.case_id == rc.case_id
            )
            .first()
        )

        if not before:
            raise HTTPException(
                status_code=400,
                detail="Invalid before evidence"
            )

    if rc.after_evidence_id:

        after = (
            db.query(Evidence)
            .filter(
                Evidence.id == rc.after_evidence_id,
                Evidence.case_id == rc.case_id
            )
            .first()
        )

        if not after:
            raise HTTPException(
                status_code=400,
                detail="Invalid after evidence"
            )

    claim = ResolutionClaim(
        case_id=rc.case_id,
        worker_id=user.id,
        description=rc.description,
        before_evidence_id=rc.before_evidence_id,
        after_evidence_id=rc.after_evidence_id
    )

    db.add(claim)

    case.status = CaseStatus.resolution_claimed

    assignment.status = "resolution_claimed"

    db.commit()
    db.refresh(claim)

    log_audit(
        db,
        actor_type="gov_user",
        action="resolution_claim.submitted",
        entity_type="case",
        entity_id=rc.case_id,
        actor_id=user.id,
        meta={
            "claim_id": claim.id
        }
    )

    return {
        "id": claim.id,
        "case_id": claim.case_id,
        "worker_id": claim.worker_id,
        "description": claim.description,
        "before_evidence_id": claim.before_evidence_id,
        "after_evidence_id": claim.after_evidence_id,
        "status": case.status.value
    }


# ==================================================
# GET RESOLUTION CLAIM
# ==================================================

@app.get(
    "/api/cases/{case_id}/resolution"
)
def get_resolution(
    case_id: str,
    db: Session = Depends(get_db)
):

    case = (
        db.query(Case)
        .filter(
            Case.id == case_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    claim = (
        db.query(ResolutionClaim)
        .filter(
            ResolutionClaim.case_id == case_id
        )
        .order_by(
            ResolutionClaim.created_at.desc()
        )
        .first()
    )

    if not claim:
        return {
            "claim": None,
            "verification": None
        }

    verification = (
        db.query(ResolutionVerification)
        .filter(
            ResolutionVerification.case_id == case_id
        )
        .order_by(
            ResolutionVerification.created_at.desc()
        )
        .first()
    )

    return {
        "claim": {
            "id": claim.id,
            "case_id": claim.case_id,
            "worker_id": claim.worker_id,
            "description": claim.description,
            "before_evidence_id": claim.before_evidence_id,
            "after_evidence_id": claim.after_evidence_id,
            "created_at": claim.created_at
        },
        "verification": (
            {
                "id": verification.id,
                "verifier_id": verification.verifier_id,
                "decision": verification.decision,
                "notes": verification.notes,
                "created_at": verification.created_at
            }
            if verification
            else None
        )
    }


# ==================================================
# RESOLUTION VERIFICATION
# GOVERNMENT VERIFIER ONLY
# ==================================================

@app.post(
    "/api/resolution-verifications"
)
def create_resolution_verification(
    rv: ResolutionVerificationCreate,
    user: User = Depends(require_gov_user),
    db: Session = Depends(get_db)
):

    case = (
        db.query(Case)
        .filter(
            Case.id == rv.case_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    if rv.decision not in {
        "accepted",
        "rejected"
    }:
        raise HTTPException(
            status_code=400,
            detail="Decision must be accepted or rejected"
        )

    claim = (
        db.query(ResolutionClaim)
        .filter(
            ResolutionClaim.case_id == rv.case_id
        )
        .order_by(
            ResolutionClaim.created_at.desc()
        )
        .first()
    )

    if not claim:
        raise HTTPException(
            status_code=400,
            detail="No resolution claim exists"
        )

    verification = ResolutionVerification(
        case_id=rv.case_id,
        verifier_id=user.id,
        decision=rv.decision,
        notes=rv.notes
    )

    db.add(verification)

    if rv.decision == "accepted":
        case.status = CaseStatus.resolved
    else:
        case.status = CaseStatus.rejected

    db.commit()
    db.refresh(verification)

    log_audit(
        db,
        actor_type="gov_user",
        action="resolution_verification.performed",
        entity_type="case",
        entity_id=rv.case_id,
        actor_id=user.id,
        meta={
            "decision": rv.decision,
            "notes": rv.notes,
            "verification_id": verification.id
        }
    )

    return {
        "id": verification.id,
        "case_id": verification.case_id,
        "verifier_id": verification.verifier_id,
        "decision": verification.decision,
        "notes": verification.notes,
        "status": case.status.value
    }


# ==================================================
# AUDIT LOGS
# ==================================================

@app.get(
    "/api/audit-logs",
    response_model=List[AuditLogResponse]
)
def list_audit_logs(
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    actor_type: Optional[str] = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    q = db.query(AuditLog)

    if entity_type:
        q = q.filter(
            AuditLog.entity_type == entity_type
        )

    if entity_id:
        q = q.filter(
            AuditLog.entity_id == entity_id
        )

    if actor_type:
        q = q.filter(
            AuditLog.actor_type == actor_type
        )

    q = q.order_by(
        AuditLog.timestamp.desc()
    )

    logs = q.all()

    return [
        {
            "id": log.id,
            "actor_type": log.actor_type,
            "actor_id": log.actor_id,
            "action": log.action,
            "entity_type": log.entity_type,
            "entity_id": log.entity_id,
            "metadata": log.meta,
            "timestamp": log.timestamp
        }
        for log in logs
    ]


# ==================================================
# CASE AUDIT LOGS
# ==================================================

@app.get(
    "/api/cases/{case_id}/audit-logs",
    response_model=List[AuditLogResponse]
)
def get_case_audit_logs(
    case_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    logs = (
        db.query(AuditLog)
        .filter(
            AuditLog.entity_type == "case",
            AuditLog.entity_id == case_id
        )
        .order_by(
            AuditLog.timestamp.desc()
        )
        .all()
    )

    return [
        {
            "id": log.id,
            "actor_type": log.actor_type,
            "actor_id": log.actor_id,
            "action": log.action,
            "entity_type": log.entity_type,
            "entity_id": log.entity_id,
            "metadata": log.meta,
            "timestamp": log.timestamp
        }
        for log in logs
    ]


# ==================================================
# HEALTH CHECK
# ==================================================

@app.get("/")
def root():
    return {
        "message": "CivicTrace API is running",
        "status": "ok"
    }