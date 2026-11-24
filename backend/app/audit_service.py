# backend/app/audit_service.py

from typing import Optional, Dict, Any

from sqlalchemy.orm import Session

from .models import AuditLog, User, UserRole


def actor_type_for(user: User) -> str:
    """Audit label for a signed-in user ("worker" or "gov_user")."""
    return "worker" if user.role == UserRole.worker else "gov_user"


def log_audit(
    db: Session,
    actor_type: str,
    action: str,
    entity_type: str,
    entity_id: str,
    actor_id: Optional[int] = None,
    meta: Optional[Dict[str, Any]] = None,
    commit: bool = True
):
    """
    Create a permanent accountability/audit log entry.

    commit=True  (default): the entry is committed immediately.
    commit=False: the entry joins the caller's open transaction, so the
                  action and its audit record are saved atomically
                  (either both exist or neither does).
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

    if commit:
        db.commit()
        db.refresh(audit)

    return audit