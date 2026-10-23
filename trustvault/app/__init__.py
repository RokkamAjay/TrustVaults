import hashlib
import os
import re
import uuid
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFError
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, abort, current_app, jsonify, make_response, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import or_
from werkzeug.utils import secure_filename
from .audit import append_audit, verify_audit_chain
from .extensions import csrf, db, login_manager
from .models import AuditLog, Document, DocumentPermission, User, utcnow
from .security import audit_event, can_edit, can_read, require_role

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt"}
MAX_FILE_BYTES = 10 * 1024 * 1024

def _is_utf8_text(data):
    try:
        data.decode("utf-8", errors="strict")
        return True
    except UnicodeDecodeError:
        return False

def create_app(test_config=None):
    load_dotenv()

    # Vercel's filesystem is read-only except for /tmp.
    instance_dir = os.environ.get("INSTANCE_PATH")
    if not instance_dir:
        instance_dir = (
            "/tmp/trustvault_instance"
            if os.environ.get("VERCEL")
            else str(Path(__file__).resolve().parent.parent / "instance")
        )

    app = Flask(
        __name__,
        instance_relative_config=True,
        instance_path=instance_dir,
    )
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-secret"),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///trustvault.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        STORAGE_PATH=(
            str(Path("/tmp/trustvault_storage"))
            if os.environ.get("VERCEL")
            else os.environ.get(
                "STORAGE_PATH",
                str(Path(app.instance_path) / "private_storage"),
            )
        ),
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", MAX_FILE_BYTES)),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        WTF_CSRF_TIME_LIMIT=None,
    )
    if test_config:
        app.config.update(test_config)

    app.config["WTF_CSRF_SSL_STRICT"] = False

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["STORAGE_PATH"], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    csrf.init_app(app)

    @login_manager.unauthorized_handler
    def unauthorized():
        # Record unauthenticated attempts against document endpoints before returning 401.
        if request.path.startswith("/api/documents"):
            try:
                append_audit(None, "unauthenticated_access_attempt", outcome="denied",
                             detail=f"path={request.path};method={request.method}",
                             request_id=getattr(request, "request_id", ""))
                db.session.commit()
            except Exception:
                db.session.rollback()
                current_app.logger.exception("Failed to record unauthenticated access attempt")
            return jsonify(error="unauthorized", message="Authentication is required."), 401
        return redirect(url_for("login"))

    @login_manager.user_loader
    def load_user(user_id):
        # Disabled accounts cannot keep using an existing session.
        user = db.session.get(User, int(user_id))
        return user if user and user.active else None

    @app.before_request
    def request_id():
        request.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))[:64]

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'")
        return response

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(
            error="file_too_large",
            message="Maximum upload size is 10 MB.",
        ), 413

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        current_app.logger.warning(
            "CSRF validation failed: %s",
            error.description,
        )
        return "CSRF validation failed. Check server logs.", 400

    @app.errorhandler(400)
    def bad_request(error):
        current_app.logger.warning(
            "Bad request: path=%s method=%s error=%s",
            request.path,
            request.method,
            str(error),
        )
        if request.path.startswith("/api/"):
            return jsonify(
                error="bad_request",
                message="The request could not be processed.",
            ), 400
        return "Bad request", 400

    def fail_access(action, doc_id, outcome="denied", status=403):
        try:
            append_audit(current_user if current_user.is_authenticated else None,
                         action, document_id=doc_id, outcome=outcome,
                         detail=f"path={request.path};method={request.method}",
                         request_id=request.request_id)
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Failed to record denied access event")
        abort(status)

    def get_document(doc_id, action="document_read", permission="read"):
        doc = db.session.get(Document, doc_id)
        if not doc or doc.deleted_at:
            fail_access(action, doc_id, status=404)
        allowed = can_read(current_user, doc) if permission == "read" else can_edit(current_user, doc)
        if not allowed:
            fail_access(action, doc_id, status=404)
        return doc

    def json_error(code, message, status):
        return jsonify(error=code, message=message), status

    @app.get("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if not user or not user.active or not user.check_password(password):
            append_audit(user if user and user.active else None, "login", outcome="denied", detail="invalid credentials", request_id=request.request_id)
            db.session.commit()
            return render_template("login.html", error="Invalid email or password."), 401
        login_user(user, remember=False, fresh=True)
        audit_event("login", outcome="success")
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    @login_required
    def logout():
        audit_event("logout")
        logout_user()
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboards.html")

    @app.get("/api/me")
    @login_required
    def me():
        return jsonify({
    **current_user.to_dict(),
    "csrf_token": __import__(
        "flask_wtf.csrf",
        fromlist=["generate_csrf"]
    ).generate_csrf()
})

    @app.get("/api/users")
    @login_required
    @require_role("admin")
    def list_users():
        return jsonify(users=[u.to_dict() for u in User.query.order_by(User.id).all()])

    @app.post("/api/users")
    @login_required
    @require_role("admin")
    def create_user():
        data = request.get_json(silent=True) or {}
        name, email, password, role = (str(data.get(k, "")).strip() for k in ("name", "email", "password", "role"))
        email = email.lower()
        if not name or len(name) > 120 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return json_error("invalid_input", "Provide a name and valid email.", 400)
        if len(password) < 12:
            return json_error("weak_password", "Password must contain at least 12 characters.", 400)
        if role not in {"admin", "owner", "viewer"}:
            return json_error("invalid_role", "Role must be admin, owner, or viewer.", 400)
        if User.query.filter_by(email=email).first():
            return json_error("email_exists", "That email is already registered.", 409)
        user = User(name=name, email=email, role=role, active=True)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        audit_event("user_created", target_user_id=user.id, detail=f"role={role}")
        return jsonify(user=user.to_dict()), 201

    @app.patch("/api/users/<int:user_id>/active")
    @login_required
    @require_role("admin")
    def set_user_active(user_id):
        user = db.session.get(User, user_id)
        if not user:
            return json_error("not_found", "User not found.", 404)
        if user.id == current_user.id and (request.get_json(silent=True) or {}).get("active") is False:
            return json_error("invalid_operation", "You cannot deactivate your own account.", 400)
        active = (request.get_json(silent=True) or {}).get("active")
        if not isinstance(active, bool):
            return json_error("invalid_input", "active must be true or false.", 400)
        user.active = active
        audit_event("user_activated" if active else "user_deactivated", target_user_id=user.id)
        return jsonify(user=user.to_dict())

    @app.post("/api/documents")
    @login_required
    def upload_document():
        if current_user.role not in {"owner", "admin"}:
            audit_event("document_upload", outcome="denied", detail="role cannot upload")
            return json_error("forbidden", "Only document owners or administrators can upload.", 403)
        uploaded = request.files.get("file")
        name = (request.form.get("name") or (uploaded.filename if uploaded else "")).strip()
        category = (request.form.get("category") or "General").strip()
        if not uploaded or not uploaded.filename or not name or len(name) > 255 or not category or len(category) > 80:
            return json_error("invalid_input", "A file, name (max 255 chars), and category (max 80 chars) are required.", 400)
        safe_name = secure_filename(uploaded.filename)
        ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
        if ext not in ALLOWED_EXTENSIONS:
            audit_event("document_upload", outcome="denied", detail=f"disallowed extension: {ext[:20]}")
            return json_error("unsupported_file_type", "Allowed extensions: pdf, png, jpg, jpeg, txt.", 400)
        data = uploaded.read(MAX_FILE_BYTES + 1)
        if not data or len(data) > MAX_FILE_BYTES:
            return json_error("invalid_file_size", "File must be between 1 byte and 10 MB.", 400)
        signatures = {"pdf": data.startswith(b"%PDF-"), "png": data.startswith(b"\x89PNG\r\n\x1a\n"),
                      "jpg": data.startswith(b"\xff\xd8\xff"), "jpeg": data.startswith(b"\xff\xd8\xff"),
                      "txt": b"\x00" not in data and _is_utf8_text(data)}
        if not signatures.get(ext, False):
            audit_event("document_upload", outcome="denied", detail="file signature/content mismatch")
            return json_error("invalid_file_content", "File content does not match its allowed type.", 400)
        key = uuid.uuid4().hex
        path = Path(current_app.config["STORAGE_PATH"]) / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        doc = Document(owner_id=current_user.id, name=name, category=category, storage_key=key,
                       sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data),
                       content_type={"pdf":"application/pdf", "png":"image/png", "jpg":"image/jpeg",
                                     "jpeg":"image/jpeg", "txt":"text/plain"}[ext])
        db.session.add(doc)
        db.session.flush()
        try:
            audit_event("document_upload", document_id=doc.id, detail=f"size={len(data)};sha256={doc.sha256}")
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return jsonify(document=doc.to_dict()), 201

    @app.get("/api/documents")
    @login_required
    def list_documents():
        query = Document.query.filter(Document.deleted_at.is_(None))
        if current_user.role == "admin":
            # Admin sees metadata for investigation, but is not automatically granted file-content access.
            pass
        else:
            grants = db.session.query(DocumentPermission.document_id).filter_by(user_id=current_user.id).subquery()
            query = query.filter(or_(Document.owner_id == current_user.id, Document.id.in_(grants)))
        search = request.args.get("q", "").strip()
        category = request.args.get("category", "").strip()
        owner = request.args.get("owner", "").strip()
        start = request.args.get("from", "").strip()
        end = request.args.get("to", "").strip()
        if search:
            query = query.filter(Document.name.ilike(f"%{search[:100]}%"))
        if category:
            query = query.filter(Document.category.ilike(f"%{category[:80]}%"))
        if owner:
            query = query.join(User, Document.owner_id == User.id).filter(User.name.ilike(f"%{owner[:100]}%"))
        try:
            if start:
                query = query.filter(Document.created_at >= datetime.fromisoformat(start).replace(tzinfo=timezone.utc))
            if end:
                query = query.filter(Document.created_at <= datetime.fromisoformat(end).replace(tzinfo=timezone.utc))
        except ValueError:
            return json_error("invalid_date", "Dates must be ISO format, for example 2026-10-19.", 400)
        docs = query.order_by(Document.created_at.desc()).limit(200).all()
        # Non-owner users should only see docs for which a live grant exists.
        if current_user.role != "admin":
            docs = [d for d in docs if d.owner_id == current_user.id or can_read(current_user, d)]
        audit_event("document_search", detail=f"returned={len(docs)}")
        return jsonify(documents=[{**d.to_dict(), "can_download": can_read(current_user, d), "can_manage_access": d.owner_id == current_user.id, "can_edit": can_edit(current_user, d)} for d in docs])

    @app.get("/api/documents/<int:doc_id>")
    @login_required
    def get_document_metadata(doc_id):
        doc = get_document(doc_id, "document_metadata_read")
        audit_event("document_metadata_read", document_id=doc.id)
        return jsonify(document=doc.to_dict())

    @app.get("/api/documents/<int:doc_id>/download")
    @login_required
    def download_document(doc_id):
        doc = get_document(doc_id, "document_download")
        path = Path(current_app.config["STORAGE_PATH"]) / doc.storage_key
        if not path.is_file():
            audit_event("document_download", document_id=doc.id, outcome="error", detail="stored file missing")
            return json_error("file_unavailable", "Stored file is unavailable.", 500)
        audit_event("document_download", document_id=doc.id, detail=f"sha256={doc.sha256}")
        response = make_response(send_file(path, mimetype=doc.content_type, as_attachment=True, download_name=secure_filename(doc.name), conditional=False))
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.patch("/api/documents/<int:doc_id>")
    @login_required
    def update_document(doc_id):
        doc = get_document(doc_id, "document_edit", permission="edit")
        data = request.get_json(silent=True) or {}
        name, category = data.get("name"), data.get("category")
        if name is not None:
            if not isinstance(name, str) or not name.strip() or len(name.strip()) > 255:
                return json_error("invalid_name", "Name must be 1–255 characters.", 400)
            doc.name = name.strip()
        if category is not None:
            if not isinstance(category, str) or not category.strip() or len(category.strip()) > 80:
                return json_error("invalid_category", "Category must be 1–80 characters.", 400)
            doc.category = category.strip()
        doc.updated_at = utcnow()
        audit_event("document_changed", document_id=doc.id, detail="metadata updated")
        return jsonify(document=doc.to_dict())

    @app.delete("/api/documents/<int:doc_id>")
    @login_required
    def delete_document(doc_id):
        doc = get_document(doc_id, "document_delete", permission="edit")
        doc.deleted_at = utcnow()
        audit_event("document_deleted", document_id=doc.id, detail="soft delete; file retained for recovery")
        return jsonify(message="Document deleted.")

    @app.post("/api/documents/<int:doc_id>/permissions")
    @login_required
    def grant_permission(doc_id):
        doc = db.session.get(Document, doc_id)
        if not doc or doc.deleted_at:
            return json_error("not_found", "Document not found.", 404)
        if doc.owner_id != current_user.id:
            fail_access("permission_grant", doc_id, status=404)
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", "")).strip().lower()
        permission = data.get("permission")
        if permission not in {"read", "edit"} or not email:
            return json_error("invalid_input", "Provide an email and permission read/edit.", 400)
        target = User.query.filter_by(email=email, active=True).first()
        if not target:
            return json_error("user_not_found", "Active user not found.", 404)
        if target.id == current_user.id:
            return json_error("invalid_input", "You already own this document.", 400)
        grant = DocumentPermission.query.filter_by(document_id=doc.id, user_id=target.id).first()
        if grant:
            grant.permission = permission
            grant.granted_by = current_user.id
            grant.granted_at = utcnow()
            action = "permission_changed"
        else:
            grant = DocumentPermission(document_id=doc.id, user_id=target.id,
                                       permission=permission, granted_by=current_user.id)
            db.session.add(grant)
            action = "permission_granted"
        audit_event(action, document_id=doc.id, target_user_id=target.id, detail=f"permission={permission}")
        return jsonify(message="Permission saved.", user=target.to_dict(), permission=permission), 201

    @app.delete("/api/documents/<int:doc_id>/permissions/<int:user_id>")
    @login_required
    def revoke_permission(doc_id, user_id):
        doc = db.session.get(Document, doc_id)
        if not doc or doc.deleted_at or doc.owner_id != current_user.id:
            fail_access("permission_revoke", doc_id, status=404)
        grant = DocumentPermission.query.filter_by(document_id=doc.id, user_id=user_id).first()
        if not grant:
            return json_error("grant_not_found", "Permission grant not found.", 404)
        db.session.delete(grant)
        audit_event("permission_revoked", document_id=doc.id, target_user_id=user_id)
        return jsonify(message="Permission revoked.")

    @app.get("/api/documents/<int:doc_id>/permissions")
    @login_required
    def list_permissions(doc_id):
        doc = db.session.get(Document, doc_id)
        if not doc or doc.deleted_at or doc.owner_id != current_user.id:
            fail_access("permission_list", doc_id, status=404)
        grants = DocumentPermission.query.filter_by(document_id=doc.id).all()
        return jsonify(permissions=[{"user_id": g.user_id, "name": g.user.name,
                                    "email": g.user.email, "permission": g.permission,
                                    "granted_at": g.granted_at.isoformat()} for g in grants])

    @app.get("/api/audit")
    @login_required
    @require_role("admin")
    def audit_feed():
        limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
        rows = AuditLog.query.order_by(AuditLog.id.desc()).limit(limit).all()
        return jsonify(events=[row.to_dict() for row in rows], chain_valid=verify_audit_chain())

    @app.get("/api/audit/verify")
    @login_required
    @require_role("admin")
    def audit_verify():
        valid = verify_audit_chain()
        audit_event("audit_chain_verified", outcome="success" if valid else "error")
        return jsonify(valid=valid), (200 if valid else 409)

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    with app.app_context():
        db.create_all()

    return app

