import io
from app.extensions import db
from app.models import AuditLog, Document, DocumentPermission
from app.audit import verify_audit_chain
from conftest import login_as

PDF_BYTES = b"%PDF-1.4\n% TrustVault test document\n%%EOF"


def upload_pdf(client, name="Confidential contract"):
    return client.post("/api/documents", data={
        "name": name, "category": "Legal",
        "file": (io.BytesIO(PDF_BYTES), "contract.pdf", "application/pdf")
    }, content_type="multipart/form-data")


def test_owner_can_upload_and_download_own_document(client, users):
    login_as(client, users["alice@example.test"])
    response = upload_pdf(client)
    assert response.status_code == 201, response.get_json()
    doc_id = response.get_json()["document"]["id"]
    downloaded = client.get(f"/api/documents/{doc_id}/download")
    assert downloaded.status_code == 200
    assert downloaded.data == PDF_BYTES


def test_ungranted_user_cannot_read_download_edit_delete_or_grant(client, users):
    login_as(client, users["alice@example.test"])
    doc_id = upload_pdf(client).get_json()["document"]["id"]
    login_as(client, users["bob@example.test"])
    assert client.get(f"/api/documents/{doc_id}").status_code == 404
    assert client.get(f"/api/documents/{doc_id}/download").status_code == 404
    assert client.patch(f"/api/documents/{doc_id}", json={"name":"stolen"}).status_code == 404
    assert client.delete(f"/api/documents/{doc_id}").status_code == 404
    assert client.post(f"/api/documents/{doc_id}/permissions", json={"email":"carol@example.test","permission":"read"}).status_code == 404
    with client.application.app_context():
        events = AuditLog.query.filter_by(outcome="denied").count()
        assert events >= 4


def test_read_grant_allows_download_but_not_edit(client, users):
    login_as(client, users["alice@example.test"])
    doc_id = upload_pdf(client).get_json()["document"]["id"]
    grant = client.post(f"/api/documents/{doc_id}/permissions", json={"email":"bob@example.test","permission":"read"})
    assert grant.status_code == 201, grant.get_json()
    login_as(client, users["bob@example.test"])
    assert client.get(f"/api/documents/{doc_id}").status_code == 200
    assert client.get(f"/api/documents/{doc_id}/download").status_code == 200
    assert client.patch(f"/api/documents/{doc_id}", json={"name":"not allowed"}).status_code == 404


def test_revocation_blocks_next_request_and_is_audited(client, users):
    login_as(client, users["alice@example.test"])
    doc_id = upload_pdf(client).get_json()["document"]["id"]
    client.post(f"/api/documents/{doc_id}/permissions", json={"email":"bob@example.test","permission":"read"})
    login_as(client, users["bob@example.test"])
    assert client.get(f"/api/documents/{doc_id}/download").status_code == 200
    login_as(client, users["alice@example.test"])
    assert client.delete(f"/api/documents/{doc_id}/permissions/{users['bob@example.test']}").status_code == 200
    login_as(client, users["bob@example.test"])
    assert client.get(f"/api/documents/{doc_id}/download").status_code == 404
    with client.application.app_context():
        assert AuditLog.query.filter_by(action="permission_revoked", outcome="success").count() == 1


def test_viewer_cannot_upload_and_disallowed_file_is_rejected(client, users):
    login_as(client, users["bob@example.test"])
    assert upload_pdf(client).status_code == 403
    login_as(client, users["alice@example.test"])
    bad = client.post("/api/documents", data={"name":"bad.exe", "category":"General", "file":(io.BytesIO(b"MZ\x00bad"), "bad.exe")}, content_type="multipart/form-data")
    assert bad.status_code == 400


def test_admin_can_review_audit_but_does_not_automatically_download_content(client, users):
    login_as(client, users["alice@example.test"])
    doc_id = upload_pdf(client).get_json()["document"]["id"]
    login_as(client, users["admin@example.test"])
    assert client.get("/api/audit").status_code == 200
    assert client.get(f"/api/documents/{doc_id}/download").status_code == 404


def test_audit_chain_verifies_and_detects_row_tampering(client, users, app):
    login_as(client, users["alice@example.test"])
    upload_pdf(client)
    with app.app_context():
        assert verify_audit_chain() is True
        row = AuditLog.query.first()
        row.detail = "changed without recomputing hash"
        db.session.commit()
        assert verify_audit_chain() is False


def test_unauthenticated_document_request_returns_401_and_is_audited(client, app):
    response = client.get("/api/documents/999/download")
    assert response.status_code == 401
    with app.app_context():
        row = AuditLog.query.filter_by(action="unauthenticated_access_attempt", outcome="denied").first()
        assert row is not None
        assert "/api/documents/999/download" in row.detail
