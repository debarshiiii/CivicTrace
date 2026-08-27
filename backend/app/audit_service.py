# backend/app/audit_service.py

from typing import Optional, Dict, Any

from sqlalchemy.orm import Session

from .models import AuditLog


def log_audit(
    db: Session,
    actor_type: str,
    action: str,
    entity_type: str,
    entity_id: str,
    actor_id: Optional[int] = None,
    meta: Optional[Dict[str, Any]] = None
):
    """
    Create a permanent accountability/audit log entry.

    Every important action in CivicTrace can call this function.

    Examples:
        case.created
        case.updated
        case.assigned
        evidence.uploaded
        resolution_claim.submitted
        resolution_verification.performed
        user.login
    """

    audit = AuditLog(
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        meta=meta or {}
    )

    db.add(audit)
    db.commit()
    db.refresh(audit)

    return audit