from fastapi import Depends, HTTPException, status
from app.models import User, UserRole
from app.middleware import get_current_user


def require_role(*roles: UserRole):
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of these roles: {', '.join(r.value for r in roles)}",
            )
        return current_user
    return role_checker


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


async def require_security_or_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role not in [UserRole.ADMIN, UserRole.SECURITY]:
        raise HTTPException(status_code=403, detail="Security or Admin access required")
    return current_user


async def require_developer_or_above(current_user: User = Depends(get_current_user)) -> User:
    return current_user
