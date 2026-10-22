from functools import wraps
from flask import abort, current_app, request
from flask_login import current_user
from .audit import append_audit
from .extensions import db
from .models import DocumentPermission


def audit_event(action, document_id=None, target_user_id=None, outcome="success", detail=""):
    request_id = getattr(request, "request_id", "")
    append_audit(current_user if current_user.is_authenticated else None, action,
                 document_id=document_id, target_user_id=target_user_id,
                 outcome=outcome, detail=detail, request_id=request_id)
    db.session.commit()


def permission_for(user_id, document_id):
    return DocumentPermission.query.filter_by(user_id=user_id, document_id=document_id).first()


def can_read(user, document):
    if not user or not user.is_authenticated or not user.active or document.deleted_at:
        return False
    if document.owner_id == user.id:
        return True
    grant = permission_for(user.id, document.id)
    return bool(grant and grant.permission in {"read", "edit"})


def can_edit(user, document):
    if not can_read(user, document):
        return False
    if document.owner_id == user.id:
        return True
    grant = permission_for(user.id, document.id)
    return bool(grant and grant.permission == "edit")


def require_role(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if not current_user.active or current_user.role not in roles:
                audit_event("role_access_denied", outcome="denied", detail=request.path)
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator
