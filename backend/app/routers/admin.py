from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, and_
from app.database import get_db
from app.models import (
    User, Organization, AuditLog, Repository, PullRequest, Finding,
    FindingSeverity, FindingStatus, Subscription, UserRole, Policy,
)
from app.schemas import AuditLogResponse
from app.middleware import get_current_user
from app.middleware.rbac import require_admin, require_role
from app.services.auth import create_audit_log

router = APIRouter(prefix="/api/admin", tags=["Admin"])


@router.get("/audit-logs")
async def get_audit_logs(
    action: str = None,
    entity_type: str = None,
    user_id: str = None,
    date_from: str = None,
    date_to: str = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    from datetime import datetime
    query = select(AuditLog).where(AuditLog.org_id == current_user.org_id)

    if action:
        query = query.where(AuditLog.action == action)
    if entity_type:
        query = query.where(AuditLog.entity_type == entity_type)
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if date_from:
        query = query.where(AuditLog.created_at >= datetime.fromisoformat(date_from))
    if date_to:
        query = query.where(AuditLog.created_at <= datetime.fromisoformat(date_to))

    total_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(total_query)
    total = total_result.scalar() or 0

    query = query.order_by(desc(AuditLog.created_at)).offset(offset).limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "logs": [AuditLogResponse.model_validate(log) for log in logs],
    }


@router.get("/users")
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    result = await db.execute(
        select(User).where(User.org_id == current_user.org_id).order_by(User.created_at)
    )
    users = result.scalars().all()

    return [
        {
            "id": u.id,
            "email": u.email,
            "name": u.name,
            "role": u.role.value,
            "is_active": u.is_active,
            "avatar_url": u.avatar_url,
            "github_id": u.github_id,
            "created_at": u.created_at.isoformat(),
            "last_login": None,
        }
        for u in users
    ]


@router.post("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    role: str = Query(..., regex="^(admin|security|dev)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    result = await db.execute(
        select(User).where(User.id == user_id, User.org_id == current_user.org_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    old_role = user.role.value
    user.role = UserRole(role)
    await db.commit()

    await create_audit_log(
        db, current_user.org_id, current_user.id,
        "admin.user.role_change", "user", user_id,
        {"old_role": old_role, "new_role": role},
    )

    return {"message": f"User role updated from {old_role} to {role}"}


@router.get("/stats")
async def get_platform_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    org_id = current_user.org_id

    users_count = await db.execute(
        select(func.count()).select_from(User).where(User.org_id == org_id)
    )
    repos_count = await db.execute(
        select(func.count()).select_from(Repository).where(Repository.org_id == org_id)
    )
    prs_count = await db.execute(
        select(func.count()).select_from(PullRequest).where(
            PullRequest.repo_id.in_(
                select(Repository.id).where(Repository.org_id == org_id)
            )
        )
    )
    findings_count = await db.execute(
        select(func.count()).select_from(Finding).where(
            Finding.repo_id.in_(
                select(Repository.id).where(Repository.org_id == org_id)
            )
        )
    )
    policies_count = await db.execute(
        select(func.count()).select_from(select(Policy).where(Policy.org_id == org_id).subquery())
    )

    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()

    return {
        "total_users": users_count.scalar() or 0,
        "total_repositories": repos_count.scalar() or 0,
        "total_prs_analyzed": prs_count.scalar() or 0,
        "total_findings": findings_count.scalar() or 0,
        "total_policies": policies_count.scalar() or 0,
        "plan": org.plan.value if org else "free",
    }
