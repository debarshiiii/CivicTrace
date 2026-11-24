"""
Create a user straight in the database (works even if you have no admin
login yet, or forgot the password).

Run from the backend folder, with the virtual environment active:

    python create_admin.py you@example.com "StrongPass123" "Your Name" admin
    python create_admin.py w1@example.com  "StrongPass123" "Worker One" worker

Roles: admin, supervisor, official, auditor, worker
"""

import sys

from sqlalchemy import func

from app.auth import hash_password
from app.database import Base, SessionLocal, engine
from app.models import User, UserRole


def main():
    if len(sys.argv) != 5:
        print(__doc__)
        sys.exit(1)

    email, password, name, role = sys.argv[1].strip().lower(), sys.argv[2], sys.argv[3], sys.argv[4]

    if len(password) < 8:
        sys.exit("Password must be at least 8 characters.")

    try:
        role_enum = UserRole(role)
    except ValueError:
        sys.exit(f"Unknown role '{role}'. Use: " + ", ".join(r.value for r in UserRole))

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        existing = db.query(User).filter(func.lower(User.email) == email).first()

        if existing:
            existing.password_hash = hash_password(password)
            existing.role = role_enum
            existing.name = name
            action = "updated"
        else:
            db.add(User(email=email, password_hash=hash_password(password), role=role_enum, name=name))
            action = "created"

        db.commit()
        print(f"User {email} ({role_enum.value}) {action}.")
    finally:
        db.close()


if __name__ == "__main__":
    main()