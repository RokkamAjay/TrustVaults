"""Append-only-by-application audit records with a tamper-evident hash chain.

This is not independently immutable storage: a database administrator who can
rewrite the whole table can recompute the chain. Production deployments should
export checkpoints to a separately controlled append-only/WORM destination.
"""
import hashlib
import json
from .extensions import db
from .models import AuditLog, User, utcnow
from datetime import timezone

GENESIS = "0" * 64


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def append_audit(actor, action, document_id=None, target_user_id=None,
                 outcome="success", detail="", request_id=""):
    previous = AuditLog.query.order_by(AuditLog.id.desc()).first()
    previous_hash = previous.entry_hash if previous else GENESIS
    now = utcnow()
    actor_id = actor.id if actor else None
    actor_email = actor.email if actor else "anonymous"
    payload = {"actor_id": actor_id, "actor_email": actor_email, "action": action,
               "document_id": document_id, "target_user_id": target_user_id,
               "outcome": outcome, "detail": detail[:500], "request_id": request_id,
               "occurred_at": now.isoformat(), "previous_hash": previous_hash}
    entry_hash = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
    row = AuditLog(actor_id=actor_id, actor_email=actor_email, action=action,
                   document_id=document_id, target_user_id=target_user_id,
                   outcome=outcome, detail=detail[:500], request_id=request_id,
                   occurred_at=now, previous_hash=previous_hash, entry_hash=entry_hash)
    db.session.add(row)
    db.session.flush()
    return row


def verify_audit_chain():
    previous_hash = GENESIS
    for row in AuditLog.query.order_by(AuditLog.id.asc()).all():
        occurred_at = row.occurred_at
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        payload = {"actor_id": row.actor_id, "actor_email": row.actor_email,
                   "action": row.action, "document_id": row.document_id,
                   "target_user_id": row.target_user_id, "outcome": row.outcome,
                   "detail": row.detail, "request_id": row.request_id,
                   "occurred_at": occurred_at.isoformat(),
                   "previous_hash": row.previous_hash}
        expected = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
        if row.previous_hash != previous_hash or row.entry_hash != expected:
            return False
        previous_hash = row.entry_hash
    return True
