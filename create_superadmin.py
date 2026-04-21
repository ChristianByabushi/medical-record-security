"""One-time script to create a SuperAdmin account."""
import asyncio
import sys

sys.path.insert(0, ".")

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.models.user import User
from app.services.auth_service import _hash_password


async def main():
    engine = create_async_engine(settings.DATABASE_URL)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        user = User(
            email="superadmin@hospital.org",
            password_hash=_hash_password("SuperAdmin123!"),
            role="SuperAdmin",
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        print(f"SuperAdmin created successfully!")
        print(f"  ID:    {user.id}")
        print(f"  Email: {user.email}")
        print(f"  Role:  {user.role}")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
