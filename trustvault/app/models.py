from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from .extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer", index=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {"id": self.id, "name": self.name, "email": self.email,
                "role": self.role, "active": self.active}


class Document(db.Model):
    __tablename__ = "documents"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(80), nullable=False, default="General", index=True)
    storage_key = db.Column(db.String(80), nullable=False, unique=True)
    sha256 = db.Column(db.String(64), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    content_type = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    owner = db.relationship("User", foreign_keys=[owner_id])

    def to_dict(self):
        return {"id": self.id, "name": self.name, "category": self.category,
                "owner_id": self.owner_id, "owner_name": self.owner.name,
                "size_bytes": self.size_bytes, "content_type": self.content_type,
                "sha256": self.sha256, "created_at": self.created_at.isoformat(),
                "updated_at": self.updated_at.isoformat()}


class DocumentPermission(db.Model):
    __tablename__ = "document_permissions"
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    permission = db.Column(db.String(10), nullable=False)
    granted_by = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    granted_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (
        db.UniqueConstraint("document_id", "user_id", name="uq_document_user_permission"),
        db.CheckConstraint("permission IN ('read', 'edit')", name="ck_permission_value"),
    )
    user = db.relationship("User", foreign_keys=[user_id])


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    # Intentionally not a foreign key: audit identity snapshots must survive user deletion.
    actor_id = db.Column(db.Integer, nullable=True, index=True)
    actor_email = db.Column(db.String(255), nullable=False, default="anonymous")
    action = db.Column(db.String(60), nullable=False, index=True)
    document_id = db.Column(db.Integer, nullable=True, index=True)
    target_user_id = db.Column(db.Integer, nullable=True)
    outcome = db.Column(db.String(20), nullable=False, index=True)
    detail = db.Column(db.String(500), nullable=False, default="")
    request_id = db.Column(db.String(64), nullable=False, default="")
    occurred_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    previous_hash = db.Column(db.String(64), nullable=False, default="0" * 64)
    entry_hash = db.Column(db.String(64), nullable=False, unique=True)

    def to_dict(self):
        return {"id": self.id, "actor_id": self.actor_id, "actor_email": self.actor_email,
                "action": self.action, "document_id": self.document_id,
                "target_user_id": self.target_user_id, "outcome": self.outcome,
                "detail": self.detail, "request_id": self.request_id,
                "occurred_at": self.occurred_at.isoformat(),
                "previous_hash": self.previous_hash, "entry_hash": self.entry_hash}
