"""Create deterministic demo users for local review only.

For a real public deployment, set unique passwords through environment variables
and do not publish production secrets in a repository.
"""
import os
from app import create_app
from app.extensions import db
from app.models import User

app = create_app()
DEMO_USERS = [
    ("TrustVault Admin", os.environ.get("DEMO_ADMIN_EMAIL", "admin@trustvault.demo"), os.environ.get("DEMO_ADMIN_PASSWORD", "ChangeThisAdmin-2026!"), "admin"),
    ("Document Owner", os.environ.get("DEMO_OWNER_EMAIL", "owner@trustvault.demo"), os.environ.get("DEMO_OWNER_PASSWORD", "ChangeThisOwner-2026!"), "owner"),
    ("Document Viewer", os.environ.get("DEMO_VIEWER_EMAIL", "viewer@trustvault.demo"), os.environ.get("DEMO_VIEWER_PASSWORD", "ChangeThisViewer-2026!"), "viewer"),
]
with app.app_context():
    for name, email, password, role in DEMO_USERS:
        user = User.query.filter_by(email=email.lower()).first()
        if user is None:
            user = User(name=name, email=email.lower(), role=role, active=True)
            user.set_password(password)
            db.session.add(user)
        else:
            user.name, user.role, user.active = name, role, True
            user.set_password(password)
    db.session.commit()
    print("Demo accounts created/updated. Use these only for a controlled demo environment:")
    for name, email, password, role in DEMO_USERS:
        print(f"{role}: {email} / {password}")
    print("Change all demo passwords before exposing a public deployment.")
