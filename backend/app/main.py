import base64
import binascii
import enum
import logging
import re
import secrets
import time
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import List, Optional

import httpx
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    UploadFile,
    Response,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from sqlalchemy.orm import Session

from .ai_service import (
    ALLOWED_CASE_CATEGORIES,
    analyze_evidence_image,
    combine_risk_score,
    compute_hotspot_score,
)
from .audit_service import actor_type_for, log_audit
from .auth import (
    clear_login_failures,
    create_access_token,
    create_case_key,
    decode_access_token,
    hash_password,
    login_blocked_seconds,
    record_login_failure,
    verify_case_key,
    verify_password,
)
from .config import settings
from .database import Base, engine, get_db
from .models import (
    Assignment,
    AuditLog,
    Case,
    CaseStatus,
    CitizenToken,
    Evidence,
    ResolutionClaim,
    ResolutionVerification,
    User,
    UserRole,
)
from .routers import officials
from .schemas import (
    AssignmentCreate,
    AuditLogResponse,
    CaseCreate,
    CaseUpdate,
    CitizenTokenCreate,
    CitizenTokenResponse,
    EvidenceCreate,
    ResolutionClaimCreate,
    ResolutionVerificationCreate,
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
)

logger = logging.getLogger("civictrace")

_sk = settings.SECRET_KEY.lower()
if len(settings.SECRET_KEY) < 32 or "change" in _sk or "your" in _sk or _sk in {"secret", ""}:
    logger.warning(
        "SECRET_KEY in .env is weak/placeholder. Anyone who can guess it can forge "
        "login tokens. Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )


app = FastAPI(title="CivicTrace API", version="1.1.0")

_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins or ["*"],
    # Bearer-token auth (no cookies), so credentials are not needed and
    # "*" + credentials would be an unsafe combination.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# ----------------------------------------------------------------
# Uploads
# ----------------------------------------------------------------

UPLOAD_DIR = Path("uploads")
BEFORE_DIR = UPLOAD_DIR / "before"
AFTER_DIR = UPLOAD_DIR / "after"
CHALLENGE_DIR = UPLOAD_DIR / "challenges"
REPORT_DIR = UPLOAD_DIR / "reports"

for _d in (BEFORE_DIR, AFTER_DIR, CHALLENGE_DIR, REPORT_DIR):
    _d.mkdir(parents=True, exist_ok=True)

app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

MAX_PHOTO_BYTES = 8 * 1024 * 1024
MAX_REPORT_PHOTOS_PER_CASE = 5

app.include_router(officials.router)

Base.metadata.create_all(bind=engine)


def sniff_image(data: bytes):
    """Real image type from the file's own bytes; (ext, mime) or None."""
    if len(data) < 32:
        return None
    if data[:3] == b"\xff\xd8\xff":
        return ".jpg", "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png", "image/png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp", "image/webp"
    return None


def clean_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value).strip()


# ----------------------------------------------------------------
# Auth dependencies
# ----------------------------------------------------------------

GOV_ROLES = {UserRole.supervisor, UserRole.admin, UserRole.auditor, UserRole.official}
STAFF_ROLES = {UserRole.supervisor, UserRole.admin, UserRole.official}  # auditors are read-only


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authentication token")

    payload = decode_access_token(auth_header.split(" ", 1)[1])

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # Case evidence keys carry a "scope" claim and must never log anyone in.
    if "sub" not in payload or payload.get("scope"):
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token subject")

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def require_gov_user(user: User = Depends(get_current_user)) -> User:
    if user.role not in GOV_ROLES:
        raise HTTPException(status_code=403, detail="Government access required")
    return user


def require_staff(user: User = Depends(get_current_user)) -> User:
    if user.role not in STAFF_ROLES:
        raise HTTPException(status_code=403, detail="Official or supervisor access required")
    return user


def require_worker(user: User = Depends(get_current_user)) -> User:
    if user.role != UserRole.worker:
        raise HTTPException(status_code=403, detail="Worker access required")
    return user


def get_case_or_404(db: Session, case_id: str) -> Case:
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


# ----------------------------------------------------------------
# Accounts
# ----------------------------------------------------------------

@app.post("/api/auth/register", response_model=UserResponse)
def register_user(user_in: UserCreate, request: Request, db: Session = Depends(get_db)):
    """
    Create a staff/worker account.
    - Very first account on an empty database: no login needed, always `admin`.
    - After that: only a signed-in admin can create accounts.
    """

    bootstrap = db.query(User).count() == 0

    creator = None
    if not bootstrap:
        creator = get_current_user(request, db)
        if creator.role != UserRole.admin:
            raise HTTPException(status_code=403, detail="Only an admin can create accounts")

    try:
        role_enum = UserRole(user_in.role)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user role")

    if bootstrap:
        role_enum = UserRole.admin

    if db.query(User).filter(func.lower(User.email) == user_in.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=user_in.email,
        password_hash=hash_password(user_in.password),
        role=role_enum,
        name=user_in.name,
    )

    db.add(user)
    db.flush()

    log_audit(
        db,
        actor_type="gov_user" if creator else "system",
        actor_id=creator.id if creator else None,
        action="user.created",
        entity_type="user",
        entity_id=str(user.id),
        meta={"role": role_enum.value, "bootstrap": bootstrap},
        commit=False,
    )

    db.commit()
    db.refresh(user)

    return user


@app.post("/api/auth/login", response_model=TokenResponse)
def login(user_in: UserLogin, request: Request, db: Session = Depends(get_db)):

    email = user_in.email.strip().lower()
    ip = request.client.host if request.client else "unknown"
    key = f"{ip}|{email}"

    wait = login_blocked_seconds(key)
    if wait:
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {wait // 60 + 1} minute(s).",
        )

    user = db.query(User).filter(func.lower(User.email) == email).first()

    if not user or not verify_password(user_in.password, user.password_hash):
        if record_login_failure(key):
            log_audit(
                db,
                actor_type="system",
                action="user.login_locked",
                entity_type="user",
                entity_id=str(user.id) if user else email,
                meta={"ip": ip},
            )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    clear_login_failures(key)

    access_token = create_access_token(data={"sub": str(user.id), "role": user.role.value})

    log_audit(
        db,
        actor_type=actor_type_for(user),
        action="user.login",
        entity_type="user",
        entity_id=str(user.id),
        actor_id=user.id,
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/auth/me")
def get_me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "name": user.name, "role": user.role.value}


@app.get("/api/workers")
def list_workers(user: User = Depends(require_gov_user), db: Session = Depends(get_db)):
    """Field workers that officials can assign cases to."""

    workers = db.query(User).filter(User.role == UserRole.worker).order_by(User.name.asc()).all()

    counts = dict(
        db.query(Assignment.worker_id, func.count(Assignment.id))
        .filter(Assignment.status.in_(["assigned", "in_progress", "resolution_claimed"]))
        .group_by(Assignment.worker_id)
        .all()
    )

    return [
        {"id": w.id, "name": w.name, "email": w.email, "active_assignments": counts.get(w.id, 0)}
        for w in workers
    ]


# ----------------------------------------------------------------
# Citizen tokens
# ----------------------------------------------------------------

@app.post("/api/citizens/tokens", response_model=CitizenTokenResponse)
def create_citizen_token(payload: Optional[CitizenTokenCreate] = None, db: Session = Depends(get_db)):

    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    while True:
        token_str = (
            "CT-"
            + "".join(secrets.choice(chars) for _ in range(4))
            + "-"
            + "".join(secrets.choice(chars) for _ in range(4))
        )
        if not db.query(CitizenToken).filter(CitizenToken.token == token_str).first():
            break

    token = CitizenToken(token=token_str, is_active=True)
    db.add(token)
    db.flush()

    log_audit(
        db,
        actor_type="system",
        action="citizen_token.created",
        entity_type="citizen_token",
        entity_id=str(token.id),
        commit=False,
    )

    db.commit()

    return {"token": token_str}


# ----------------------------------------------------------------
# Cases
# ----------------------------------------------------------------

def serialize_case(case: Case) -> dict:
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
        "updated_at": case.updated_at,
        "ai_verified": case.ai_verified,
        "ai_confidence": case.ai_confidence,
        "ai_detected_category": case.ai_detected_category,
        "ai_severity_score": case.ai_severity_score,
        "ai_reasoning": case.ai_reasoning,
        "ai_flagged": case.ai_flagged,
        "hotspot_score": case.hotspot_score,
    }


@app.post("/api/cases")
def create_case(case_in: CaseCreate, db: Session = Depends(get_db)):

    category = case_in.category.strip().lower()
    if category not in ALLOWED_CASE_CATEGORIES:
        raise HTTPException(status_code=400, detail="Unknown issue category")

    reporter_token = None

    if case_in.reporter_token:
        reporter_token = (
            db.query(CitizenToken)
            .filter(CitizenToken.token == case_in.reporter_token.strip())
            .first()
        )
        if not reporter_token or not reporter_token.is_active:
            raise HTTPException(status_code=400, detail="Invalid citizen token")

    while True:
        candidate = "CVT-KOL-" + "".join(secrets.choice("0123456789") for _ in range(6))
        if not db.query(Case).filter(Case.id == candidate).first():
            case_id = candidate
            break

    case = Case(
        id=case_id,
        title=clean_text(case_in.title),
        description=clean_text(case_in.description),
        category=category,
        location_text=clean_text(case_in.location_text),
        latitude=case_in.latitude,
        longitude=case_in.longitude,
        risk_score=50,  # always server-decided; AI/hotspot refine it later
        reporter_token_id=reporter_token.id if reporter_token else None,
        status=CaseStatus.received,
    )

    db.add(case)
    db.flush()

    log_audit(
        db,
        actor_type="citizen" if reporter_token else "system",
        action="case.created",
        entity_type="case",
        entity_id=case.id,
        commit=False,
    )

    db.commit()

    return {
        "id": case.id,
        "status": case.status.value,
        # Short-lived key: lets ONLY the creator attach report photos.
        "evidence_key": create_case_key(case.id),
    }


@app.get("/api/cases/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db)):
    return serialize_case(get_case_or_404(db, case_id))


@app.get("/api/cases")
def list_cases(
    status_filter: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
    db: Session = Depends(get_db),
):

    limit = max(1, min(limit, 1000))
    offset = max(0, offset)

    q = db.query(Case)

    if status_filter:
        try:
            q = q.filter(Case.status == CaseStatus(status_filter))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status")

    cases = q.order_by(Case.created_at.desc()).offset(offset).limit(limit).all()

    return [serialize_case(case) for case in cases]


# Manual status changes allowed through PATCH. Everything else moves via
# its own endpoint (assign, claim, verify) so the trail can't be skipped.
MANUAL_TRANSITIONS = {
    CaseStatus.received: {CaseStatus.validated, CaseStatus.rejected},
    CaseStatus.validated: {CaseStatus.rejected},
    CaseStatus.assigned: {CaseStatus.in_progress},
    CaseStatus.resolution_claimed: {CaseStatus.verifying},
}


@app.patch("/api/cases/{case_id}")
def update_case(
    case_id: str,
    case_in: CaseUpdate,
    user: User = Depends(require_staff),
    db: Session = Depends(get_db),
):

    case = get_case_or_404(db, case_id)

    changes = {}

    for field, value in case_in.model_dump(exclude_unset=True).items():

        if field == "status":
            try:
                new_status = CaseStatus(value)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid case status")

            if new_status == case.status:
                continue

            if new_status not in MANUAL_TRANSITIONS.get(case.status, set()):
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Cannot change status from '{case.status.value}' to "
                        f"'{new_status.value}' here. Use assignment, resolution "
                        "claim and verification to move a case forward."
                    ),
                )
            value = new_status

        elif field == "category":
            value = (value or "").strip().lower()
            if value not in ALLOWED_CASE_CATEGORIES:
                raise HTTPException(status_code=400, detail="Unknown issue category")

        elif field in ("title", "description", "location_text"):
            value = clean_text(value)
            if field == "title" and not value:
                raise HTTPException(status_code=400, detail="Title cannot be empty")

        old = getattr(case, field)
        setattr(case, field, value)

        changes[field] = {
            "old": old.value if isinstance(old, enum.Enum) else old,
            "new": value.value if isinstance(value, enum.Enum) else value,
        }

    if changes:
        log_audit(
            db,
            actor_type=actor_type_for(user),
            action="case.updated",
            entity_type="case",
            entity_id=case_id,
            actor_id=user.id,
            meta=changes,
            commit=False,
        )

    db.commit()
    db.refresh(case)

    return serialize_case(case)


# ----------------------------------------------------------------
# AI scoring helper
# ----------------------------------------------------------------

def run_ai_scoring(db: Session, case: Case, image_bytes: bytes, mime_type: str, description, actor: str):
    """Analyse one photo, update the case, write an audit entry."""

    ai_result = analyze_evidence_image(
        image_bytes=image_bytes,
        mime_type=mime_type,
        category=case.category,
        description=description,
    )

    hotspot_score = compute_hotspot_score(
        db,
        category=case.category,
        latitude=case.latitude,
        longitude=case.longitude,
        exclude_case_id=case.id,
    )

    case.hotspot_score = hotspot_score

    if ai_result is not None:
        case.risk_score = combine_risk_score(ai_result, hotspot_score)
        case.ai_verified = ai_result["is_civic_issue"] and ai_result["category_match"]
        case.ai_confidence = ai_result["confidence"]
        case.ai_detected_category = ai_result["detected_category"]
        case.ai_severity_score = ai_result["severity_score"]
        case.ai_reasoning = ai_result["reasoning"]
        case.ai_flagged = not case.ai_verified
    elif case.ai_severity_score is None:
        case.risk_score = combine_risk_score(None, hotspot_score)
    # else: a failed re-run must not wipe an earlier good AI score.

    log_audit(
        db,
        actor_type=actor,
        action=(
            "case.ai_unavailable"
            if ai_result is None
            else ("case.ai_flagged" if case.ai_flagged else "case.ai_verified")
        ),
        entity_type="case",
        entity_id=case.id,
        meta={
            "ai_result": ai_result,
            "hotspot_score": hotspot_score,
            "new_risk_score": case.risk_score,
        },
        commit=False,
    )

    db.commit()
    db.refresh(case)

    return ai_result


def evidence_payload(evidence: Evidence, case: Case) -> dict:
    return {
        "id": evidence.id,
        "case_id": evidence.case_id,
        "type": evidence.type,
        "url": evidence.url,
        "uploaded_by_type": evidence.uploaded_by_type,
        "uploaded_by_id": evidence.uploaded_by_id,
        "metadata": evidence.meta,
        "created_at": evidence.created_at,
        "case_risk_score": case.risk_score,
        "case_ai_flagged": case.ai_flagged,
        "case_ai_verified": case.ai_verified,
        "case_ai_confidence": case.ai_confidence,
        "case_ai_detected_category": case.ai_detected_category,
        "case_ai_severity_score": case.ai_severity_score,
        "case_ai_reasoning": case.ai_reasoning,
        "case_hotspot_score": case.hotspot_score,
    }


# ----------------------------------------------------------------
# Evidence
# ----------------------------------------------------------------

@app.post("/api/evidence")
def create_evidence(
    ev: EvidenceCreate,
    x_case_key: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """
    Citizen photo for the case they just created. Needs the
    `evidence_key` from POST /api/cases, sent as the X-Case-Key header.
    Workers/officials use /api/evidence/upload.
    """

    case = get_case_or_404(db, ev.case_id)

    if not verify_case_key(x_case_key, case.id):
        raise HTTPException(
            status_code=403,
            detail="Missing or expired case key. Photos can only be added by the person who just created the report.",
        )

    if ev.type != "report":
        raise HTTPException(status_code=400, detail="Citizens can only upload 'report' photos")

    if not ev.photo_data:
        raise HTTPException(status_code=400, detail="photo_data is required")

    existing_photos = (
        db.query(func.count(Evidence.id))
        .filter(Evidence.case_id == case.id, Evidence.type == "report")
        .scalar()
    )
    if existing_photos >= MAX_REPORT_PHOTOS_PER_CASE:
        raise HTTPException(status_code=400, detail="Photo limit reached for this report")

    raw = ev.photo_data.strip()
    if raw.startswith("data:"):
        if "," not in raw:
            raise HTTPException(status_code=400, detail="Invalid photo_data format")
        raw = raw.split(",", 1)[1]

    if len(raw) > int(MAX_PHOTO_BYTES * 1.4) + 16:
        raise HTTPException(status_code=413, detail="Photo is too large (max 8 MB)")

    try:
        file_bytes = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Invalid base64 photo_data")

    if len(file_bytes) > MAX_PHOTO_BYTES:
        raise HTTPException(status_code=413, detail="Photo is too large (max 8 MB)")

    sniffed = sniff_image(file_bytes)
    if not sniffed:
        raise HTTPException(status_code=400, detail="That file is not a valid JPEG, PNG or WebP image.")
    extension, mime_type = sniffed

    filename = f"{uuid.uuid4().hex}{extension}"
    (REPORT_DIR / filename).write_bytes(file_bytes)

    meta = {"content_type": mime_type}
    description = clean_text(ev.description)
    if description:
        meta["description"] = description

    evidence = Evidence(
        case_id=case.id,
        type="report",
        url=f"/uploads/reports/{filename}",
        uploaded_by_type="citizen",
        uploaded_by_id=None,
        meta=meta,
    )

    db.add(evidence)
    db.flush()

    log_audit(
        db,
        actor_type="citizen",
        action="evidence.created",
        entity_type="evidence",
        entity_id=str(evidence.id),
        meta={"case_id": case.id, "type": "report"},
        commit=False,
    )

    db.commit()
    db.refresh(evidence)

    # Score only a fresh case, once, so later photos can't overwrite an
    # official's or earlier AI score.
    # (hotspot_score stays NULL until the first scoring attempt has run.)
    if case.status == CaseStatus.received and case.hotspot_score is None:
        run_ai_scoring(db, case, file_bytes, mime_type, description or case.description, "system")

    return evidence_payload(evidence, case)


@app.post("/api/evidence/upload")
async def upload_evidence(
    case_id: str = Form(...),
    evidence_type: str = Form(...),
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    get_case_or_404(db, case_id)

    if evidence_type not in {"before", "after", "challenge", "report"}:
        raise HTTPException(status_code=400, detail="Invalid evidence type")

    if user.role == UserRole.worker:
        if evidence_type not in {"before", "after"}:
            raise HTTPException(status_code=403, detail="Workers can only upload before/after photos")

        active = (
            db.query(Assignment)
            .filter(
                Assignment.case_id == case_id,
                Assignment.worker_id == user.id,
                Assignment.status.in_(["assigned", "in_progress"]),
            )
            .first()
        )
        if not active:
            raise HTTPException(status_code=403, detail="You are not currently assigned to this case")

    elif user.role not in STAFF_ROLES:
        raise HTTPException(status_code=403, detail="Not allowed to upload evidence")

    data = await file.read(MAX_PHOTO_BYTES + 1)

    if len(data) > MAX_PHOTO_BYTES:
        raise HTTPException(status_code=413, detail="Photo is too large (max 8 MB)")

    sniffed = sniff_image(data)
    if not sniffed:
        raise HTTPException(status_code=400, detail="Only valid JPEG, PNG or WebP images are allowed")
    extension, mime_type = sniffed

    directory = {
        "before": BEFORE_DIR,
        "after": AFTER_DIR,
        "challenge": CHALLENGE_DIR,
        "report": REPORT_DIR,
    }[evidence_type]

    filename = f"{uuid.uuid4().hex}{extension}"
    (directory / filename).write_bytes(data)

    url = f"/uploads/{directory.relative_to(UPLOAD_DIR).as_posix()}/{filename}"

    evidence = Evidence(
        case_id=case_id,
        type=evidence_type,
        url=url,
        uploaded_by_type=actor_type_for(user),
        uploaded_by_id=user.id,
        meta={"original_filename": (file.filename or "")[:200], "content_type": mime_type},
    )

    db.add(evidence)
    db.flush()

    log_audit(
        db,
        actor_type=actor_type_for(user),
        action="evidence.uploaded",
        entity_type="evidence",
        entity_id=str(evidence.id),
        actor_id=user.id,
        meta={"case_id": case_id, "type": evidence_type, "filename": (file.filename or "")[:200]},
        commit=False,
    )

    db.commit()
    db.refresh(evidence)

    return {"id": evidence.id, "case_id": case_id, "type": evidence.type, "url": url}


@app.get("/api/cases/{case_id}/evidence")
def get_case_evidence(case_id: str, db: Session = Depends(get_db)):

    get_case_or_404(db, case_id)

    evidence = (
        db.query(Evidence)
        .filter(Evidence.case_id == case_id)
        .order_by(Evidence.created_at.asc(), Evidence.id.asc())
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
            "created_at": item.created_at,
        }
        for item in evidence
    ]


@app.post("/api/cases/{case_id}/reanalyze")
def reanalyze_case(case_id: str, user: User = Depends(require_staff), db: Session = Depends(get_db)):
    """Re-run AI triage on the case's first citizen photo (e.g. after an AI outage)."""

    case = get_case_or_404(db, case_id)

    evidence = (
        db.query(Evidence)
        .filter(Evidence.case_id == case_id, Evidence.type == "report")
        .order_by(Evidence.created_at.asc(), Evidence.id.asc())
        .first()
    )

    if not evidence or not evidence.url.startswith("/uploads/reports/"):
        raise HTTPException(status_code=404, detail="No citizen photo to analyse")

    path = REPORT_DIR / Path(evidence.url).name

    if not path.is_file():
        raise HTTPException(status_code=404, detail="Photo file is missing on the server")

    data = path.read_bytes()
    sniffed = sniff_image(data)
    if not sniffed:
        raise HTTPException(status_code=400, detail="Stored file is not a valid image")

    description = (evidence.meta or {}).get("description") or case.description

    ai_result = run_ai_scoring(db, case, data, sniffed[1], description, actor_type_for(user))

    return {"ai_available": ai_result is not None, "case": serialize_case(case)}


# ----------------------------------------------------------------
# Assignments
# ----------------------------------------------------------------

ACTIVE_ASSIGNMENT = ["assigned", "in_progress"]


@app.post("/api/assignments")
def create_assignment(
    a: AssignmentCreate,
    user: User = Depends(require_staff),
    db: Session = Depends(get_db),
):

    case = get_case_or_404(db, a.case_id)

    if case.status not in {
        CaseStatus.received,
        CaseStatus.validated,
        CaseStatus.assigned,
        CaseStatus.in_progress,
    }:
        raise HTTPException(
            status_code=409,
            detail=f"A case that is '{case.status.value}' cannot be (re)assigned.",
        )

    worker = db.query(User).filter(User.id == a.worker_id).first()

    if not worker or worker.role != UserRole.worker:
        raise HTTPException(status_code=400, detail="Invalid worker")

    current = (
        db.query(Assignment)
        .filter(Assignment.case_id == a.case_id, Assignment.status.in_(ACTIVE_ASSIGNMENT))
        .all()
    )

    if any(x.worker_id == a.worker_id for x in current):
        raise HTTPException(status_code=409, detail="This worker is already assigned to the case")

    for old in current:
        old.status = "reassigned"

    assignment = Assignment(case_id=a.case_id, worker_id=a.worker_id, status="assigned")
    db.add(assignment)

    case.status = CaseStatus.assigned
    db.flush()

    log_audit(
        db,
        actor_type=actor_type_for(user),
        action="case.reassigned" if current else "case.assigned",
        entity_type="case",
        entity_id=a.case_id,
        actor_id=user.id,
        meta={
            "worker_id": a.worker_id,
            "worker_email": worker.email,
            "previous_workers": [x.worker_id for x in current],
        },
        commit=False,
    )

    db.commit()
    db.refresh(assignment)

    return {
        "id": assignment.id,
        "case_id": assignment.case_id,
        "worker_id": assignment.worker_id,
        "status": assignment.status,
        "created_at": assignment.created_at,
    }


@app.get("/api/cases/{case_id}/assignment")
def get_case_assignment(case_id: str, user: User = Depends(require_gov_user), db: Session = Depends(get_db)):
    """Who the case is currently assigned to (government users only)."""

    get_case_or_404(db, case_id)

    assignment = (
        db.query(Assignment)
        .filter(Assignment.case_id == case_id, Assignment.status != "reassigned")
        .order_by(Assignment.id.desc())
        .first()
    )

    if not assignment:
        return {"assignment": None}

    worker = db.query(User).filter(User.id == assignment.worker_id).first()

    return {
        "assignment": {
            "id": assignment.id,
            "status": assignment.status,
            "worker_id": assignment.worker_id,
            "worker_name": worker.name if worker else None,
            "worker_email": worker.email if worker else None,
            "created_at": assignment.created_at,
        }
    }


@app.get("/api/workers/me/assignments")
def get_my_assignments(user: User = Depends(require_worker), db: Session = Depends(get_db)):

    assignments = (
        db.query(Assignment)
        .filter(Assignment.worker_id == user.id, Assignment.status != "reassigned")
        .order_by(Assignment.created_at.desc())
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
            "updated_at": case.updated_at,
        })

    return results


@app.get("/api/workers/me/assignments/{assignment_id}")
def get_my_assignment(assignment_id: int, user: User = Depends(require_worker), db: Session = Depends(get_db)):

    assignment = (
        db.query(Assignment)
        .filter(Assignment.id == assignment_id, Assignment.worker_id == user.id)
        .first()
    )

    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

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
            "updated_at": case.updated_at,
        },
    }


# ----------------------------------------------------------------
# Resolution claim -> verification
# ----------------------------------------------------------------

@app.post("/api/resolution-claims")
def create_resolution_claim(
    rc: ResolutionClaimCreate,
    user: User = Depends(require_worker),
    db: Session = Depends(get_db),
):

    case = get_case_or_404(db, rc.case_id)

    assignment = (
        db.query(Assignment)
        .filter(
            Assignment.case_id == rc.case_id,
            Assignment.worker_id == user.id,
            Assignment.status.in_(ACTIVE_ASSIGNMENT),
        )
        .order_by(Assignment.id.desc())
        .first()
    )

    if not assignment:
        raise HTTPException(status_code=403, detail="You are not currently assigned to this case")

    if case.status not in {CaseStatus.assigned, CaseStatus.in_progress}:
        raise HTTPException(
            status_code=409,
            detail=f"This case is '{case.status.value}' and cannot take a new resolution claim.",
        )

    if not rc.after_evidence_id:
        raise HTTPException(status_code=400, detail="An after-photo is required")

    after = (
        db.query(Evidence)
        .filter(
            Evidence.id == rc.after_evidence_id,
            Evidence.case_id == rc.case_id,
            Evidence.type == "after",
            Evidence.uploaded_by_id == user.id,
        )
        .first()
    )
    if not after:
        raise HTTPException(status_code=400, detail="Invalid after evidence")

    if rc.before_evidence_id:
        before = (
            db.query(Evidence)
            .filter(
                Evidence.id == rc.before_evidence_id,
                Evidence.case_id == rc.case_id,
                Evidence.type.in_(["before", "report"]),
            )
            .first()
        )
        if not before:
            raise HTTPException(status_code=400, detail="Invalid before evidence")

    claim = ResolutionClaim(
        case_id=rc.case_id,
        worker_id=user.id,
        description=clean_text(rc.description),
        before_evidence_id=rc.before_evidence_id,
        after_evidence_id=rc.after_evidence_id,
    )

    db.add(claim)

    case.status = CaseStatus.resolution_claimed
    assignment.status = "resolution_claimed"
    db.flush()

    log_audit(
        db,
        actor_type="worker",
        action="resolution_claim.submitted",
        entity_type="case",
        entity_id=rc.case_id,
        actor_id=user.id,
        meta={"claim_id": claim.id},
        commit=False,
    )

    db.commit()
    db.refresh(claim)

    return {
        "id": claim.id,
        "case_id": claim.case_id,
        "worker_id": claim.worker_id,
        "description": claim.description,
        "before_evidence_id": claim.before_evidence_id,
        "after_evidence_id": claim.after_evidence_id,
        "status": case.status.value,
    }


@app.get("/api/cases/{case_id}/resolution")
def get_resolution(case_id: str, db: Session = Depends(get_db)):
    """
    Latest claim plus the decision made ON THAT claim. While the latest
    claim awaits a verdict, `pending` is true and `verification` is null
    (even if an older claim was rejected) so the review form shows again.
    """

    case = get_case_or_404(db, case_id)

    claims = (
        db.query(ResolutionClaim)
        .filter(ResolutionClaim.case_id == case_id)
        .order_by(ResolutionClaim.created_at.desc(), ResolutionClaim.id.desc())
        .all()
    )

    if not claims:
        return {"claim": None, "verification": None, "pending": False, "attempts": 0}

    claim = claims[0]
    pending = case.status in {CaseStatus.resolution_claimed, CaseStatus.verifying}

    verification = None
    if not pending:
        verification = (
            db.query(ResolutionVerification)
            .filter(ResolutionVerification.case_id == case_id)
            .order_by(ResolutionVerification.created_at.desc(), ResolutionVerification.id.desc())
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
            "created_at": claim.created_at,
        },
        "verification": (
            {
                "id": verification.id,
                "verifier_id": verification.verifier_id,
                "decision": verification.decision,
                "notes": verification.notes,
                "created_at": verification.created_at,
            }
            if verification
            else None
        ),
        "pending": pending,
        "attempts": len(claims),
    }


@app.post("/api/resolution-verifications")
def create_resolution_verification(
    rv: ResolutionVerificationCreate,
    user: User = Depends(require_staff),
    db: Session = Depends(get_db),
):

    case = get_case_or_404(db, rv.case_id)

    if rv.decision not in {"accepted", "rejected"}:
        raise HTTPException(status_code=400, detail="Decision must be accepted or rejected")

    notes = clean_text(rv.notes)

    if rv.decision == "rejected" and not notes:
        raise HTTPException(status_code=400, detail="Explain what is still wrong when rejecting")

    if case.status not in {CaseStatus.resolution_claimed, CaseStatus.verifying}:
        raise HTTPException(status_code=409, detail="There is no pending resolution claim to verify for this case.")

    claim = (
        db.query(ResolutionClaim)
        .filter(ResolutionClaim.case_id == rv.case_id)
        .order_by(ResolutionClaim.created_at.desc(), ResolutionClaim.id.desc())
        .first()
    )

    if not claim:
        raise HTTPException(status_code=400, detail="No resolution claim exists")

    verification = ResolutionVerification(
        case_id=rv.case_id,
        verifier_id=user.id,
        decision=rv.decision,
        notes=notes,
    )

    db.add(verification)

    assignment = (
        db.query(Assignment)
        .filter(
            Assignment.case_id == rv.case_id,
            Assignment.worker_id == claim.worker_id,
            Assignment.status == "resolution_claimed",
        )
        .order_by(Assignment.id.desc())
        .first()
    )

    if rv.decision == "accepted":
        case.status = CaseStatus.resolved
        if assignment:
            assignment.status = "completed"
    else:
        # Sent back for rework: the same worker can submit a new claim.
        case.status = CaseStatus.in_progress
        if assignment:
            assignment.status = "in_progress"

    db.flush()

    log_audit(
        db,
        actor_type=actor_type_for(user),
        action="resolution_verification.performed",
        entity_type="case",
        entity_id=rv.case_id,
        actor_id=user.id,
        meta={
            "decision": rv.decision,
            "notes": notes,
            "verification_id": verification.id,
            "claim_id": claim.id,
        },
        commit=False,
    )

    db.commit()
    db.refresh(verification)

    return {
        "id": verification.id,
        "case_id": verification.case_id,
        "verifier_id": verification.verifier_id,
        "decision": verification.decision,
        "notes": verification.notes,
        "status": case.status.value,
    }


# ----------------------------------------------------------------
# Audit logs (government users only)
# ----------------------------------------------------------------

def serialize_log(log: AuditLog) -> dict:
    return {
        "id": log.id,
        "actor_type": log.actor_type,
        "actor_id": log.actor_id,
        "action": log.action,
        "entity_type": log.entity_type,
        "entity_id": log.entity_id,
        "metadata": log.meta,
        "timestamp": log.timestamp,
    }


@app.get("/api/audit-logs", response_model=List[AuditLogResponse])
def list_audit_logs(
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    actor_type: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
    user: User = Depends(require_gov_user),
    db: Session = Depends(get_db),
):

    q = db.query(AuditLog)

    if entity_type:
        q = q.filter(AuditLog.entity_type == entity_type)
    if entity_id:
        q = q.filter(AuditLog.entity_id == entity_id)
    if actor_type:
        q = q.filter(AuditLog.actor_type == actor_type)

    logs = (
        q.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
        .offset(max(0, offset))
        .limit(max(1, min(limit, 2000)))
        .all()
    )

    return [serialize_log(log) for log in logs]


@app.get("/api/cases/{case_id}/audit-logs", response_model=List[AuditLogResponse])
def get_case_audit_logs(case_id: str, user: User = Depends(require_gov_user), db: Session = Depends(get_db)):

    logs = (
        db.query(AuditLog)
        .filter(AuditLog.entity_type == "case", AuditLog.entity_id == case_id)
        .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
        .all()
    )

    return [serialize_log(log) for log in logs]


# ----------------------------------------------------------------
# Map tile proxy -- keeps the map provider key on the server.
# The browser only ever sees /api/map/tiles/{z}/{x}/{y}.
# ----------------------------------------------------------------

_tile_cache: "OrderedDict[str, tuple]" = OrderedDict()
_TILE_CACHE_MAX = 800
_tile_rate: dict = {}


def _tile_rate_ok(ip: str) -> bool:
    now = time.time()
    start, count = _tile_rate.get(ip, (now, 0))
    if now - start > 60:
        start, count = now, 0
    count += 1
    _tile_rate[ip] = (start, count)
    if len(_tile_rate) > 5000:
        _tile_rate.clear()
    return count <= settings.MAP_TILES_PER_MINUTE


@app.get("/api/map/tiles/{z}/{x}/{y}")
def map_tile(z: int, x: int, y: int, request: Request):

    if not (0 <= z <= 19) or not (0 <= x < 2 ** z) or not (0 <= y < 2 ** z):
        raise HTTPException(status_code=404, detail="No such tile")

    ip = request.client.host if request.client else "unknown"
    if not _tile_rate_ok(ip):
        raise HTTPException(status_code=429, detail="Too many map requests")

    key = f"{z}/{x}/{y}"
    hit = _tile_cache.get(key)

    if hit is None:
        url = (
            settings.MAP_TILE_URL
            .replace("{z}", str(z)).replace("{x}", str(x)).replace("{y}", str(y))
            .replace("{key}", settings.MAP_API_KEY or "")
        )
        try:
            upstream = httpx.get(url, timeout=8, headers={"User-Agent": "CivicTrace/1.1"})
        except Exception as exc:
            # never log the URL: it can contain the provider key
            logger.warning("Map tile fetch failed: %s", type(exc).__name__)
            raise HTTPException(status_code=502, detail="Map tiles unavailable")

        ctype = upstream.headers.get("content-type", "")
        if upstream.status_code != 200 or not ctype.startswith("image/") or len(upstream.content) > 400_000:
            logger.warning("Map provider answered HTTP %s", upstream.status_code)
            raise HTTPException(status_code=502, detail="Map tiles unavailable")

        hit = (upstream.content, ctype)
        _tile_cache[key] = hit
        if len(_tile_cache) > _TILE_CACHE_MAX:
            _tile_cache.popitem(last=False)

    return Response(content=hit[0], media_type=hit[1], headers={"Cache-Control": "public, max-age=86400"})


@app.get("/")
def root():
    return {"message": "CivicTrace API is running", "status": "ok"}