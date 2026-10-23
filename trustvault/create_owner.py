
import getpass
import re

from sqlalchemy import create_engine, text
from werkzeug.security import generate_password_hash

# Read the Neon URL without displaying it.
database_url = getpass.getpass("Neon DATABASE_URL (hidden): ").strip()

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://", "postgresql://", 1
    )

if not database_url.startswith("postgresql://"):
    raise ValueError("Use the PostgreSQL DATABASE_URL from Render.")

# Use psycopg v3.
database_url = database_url.replace(
    "postgresql://", "postgresql+psycopg://", 1
)

name = input("Owner name: ").strip()
email = input("Owner email: ").strip().lower()
password = getpass.getpass("Owner password (at least 12 characters): ")
confirm = getpass.getpass("Confirm password: ")

if not name or len(name) > 120:
    raise ValueError("Name is required and must be at most 120 characters.")

if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
    raise ValueError("Enter a valid email address.")

if len(password) < 12:
    raise ValueError("Password must contain at least 12 characters.")

if password != confirm:
    raise ValueError("Passwords do not match.")

engine = create_engine(database_url, pool_pre_ping=True)

try:
    with engine.begin() as connection:
        tables = connection.execute(text("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_name IN ('users', 'audit_logs')
        """)).scalars().all()

        if not {"users", "audit_logs"}.issubset(set(tables)):
            raise RuntimeError(
                "TrustVault tables not found. Check your Neon database URL."
            )

        existing = connection.execute(
            text("SELECT id FROM users WHERE email = :email"),
            {"email": email},
        ).first()

        if existing:
            print("This email already exists. No changes made.")
        else:
            connection.execute(
                text("""
                    INSERT INTO users
                        (name, email, password_hash, role, active, created_at)
                    VALUES
                        (:name, :email, :password_hash, 'owner', TRUE, NOW())
                """),
                {
                    "name": name,
                    "email": email,
                    "password_hash": generate_password_hash(password),
                },
            )

            print("Owner account created successfully.")
finally:
    engine.dispose()
