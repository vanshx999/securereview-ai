"""Seed the database with a demo organization and user."""
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.database import async_session_factory
from app.models import Organization, User, UserRole
from app.services.auth import hash_password, create_audit_log
from sqlalchemy import select


async def seed():
    async with async_session_factory() as db:
        result = await db.execute(select(User).where(User.email == "demo@demo.com"))
        existing = result.scalar_one_or_none()
        if existing:
            print("Demo user already exists — skipping seed")
            return

        org = Organization(
            name="Demo Organization",
            slug="demo-org",
        )
        db.add(org)
        await db.flush()

        user = User(
            org_id=org.id,
            email="demo@demo.com",
            password_hash=hash_password("password123"),
            name="Demo User",
            role=UserRole.ADMIN,
        )
        db.add(user)
        await db.flush()

        await create_audit_log(db, org.id, user.id, "seed", "system", "seed")
        await db.commit()

        print("Demo user created:")
        print("  Email:    demo@demo.com")
        print("  Password: password123")


if __name__ == "__main__":
    asyncio.run(seed())
