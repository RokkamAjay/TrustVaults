
import getpass
import os

from sqlalchemy import create_engine, text
from werkzeug.security import generate_password_hash

database_url = getpass.getpass(
    "Paste your Neon DATABASE_URL (hidden): "
).strip()

if not database_url.startswith(("postgresql://", "postgres://")):
    raise ValueError("Please provide a PostgreSQL URL, not SQLite.")

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://", "postgresql://", 1
    )

name = input("Admin name: ").strip()
email = input("Admin email: ").strip().lower()
password = getpass.getpass("Admin password (12+ characters): ")
confirm = getpass.getpass("Confirm password: ")

if not name or not email:
    raise ValueError("Name and email are required.")
if len(password) < 12:
    raise ValueError("Password must be at least 12 characters.")
if password != confirm:
    raise ValueError("Passwords do not match.")

engine = create_engine(database_url, pool_pre_ping=True)

try:
    with engine.begin() as connection:
        existing = connection.execute(
            text("SELECT id FROM users WHERE email = :email"),
            {"email": email},
        ).first()

        if existing:
            print("That email already exists. No changes made.")
        else:
            connection.execute(
                text("""
                    INSERT INTO users
                        (name, email, password_hash, role, active, created_at)
                    VALUES
                        (:name, :email, :password_hash, 'admin', TRUE, NOW())
                """),
                {
                    "name": name,
                    "email": email,
                    "password_hash": generate_password_hash(password),
                },
            )
            print("Admin account created successfully.")
finally:
    engine.dispose()
