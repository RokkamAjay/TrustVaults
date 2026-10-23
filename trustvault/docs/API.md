import pytest
from app import create_app
from app.extensions import db
from app.models import User

@pytest.fixture()
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-secret-key-that-is-not-used-in-production",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "STORAGE_PATH": str(tmp_path / "private-storage"),
        "SESSION_COOKIE_SECURE": False,
    })
    with app.app_context():
        db.drop_all()
        db.create_all()
        for name, email, role in [
            ("Admin", "admin@example.test", "admin"),
            ("Alice Owner", "alice@example.test", "owner"),
            ("Bob Viewer", "bob@example.test", "viewer"),
            ("Carol Viewer", "carol@example.test", "viewer"),
        ]:
            user = User(name=name, email=email, role=role)
            user.set_password("test-password-123")
            db.session.add(user)
        db.session.commit()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()

@pytest.fixture()
def client(app):
    return app.test_client()

@pytest.fixture()
def users(app):
    with app.app_context():
        return {u.email: u.id for u in User.query.all()}

def login_as(client, user_id):
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True
