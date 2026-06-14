from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from app.database import get_db
from app.models import User, Organization, Repository, PullRequest, Finding, Subscription, AuditLog, UserRole
from app.schemas import OrganizationResponse, SubscriptionResponse
from app.middleware import get_current_user, require_admin, get_org_from_user
from app.middleware.rbac import require_role
from app.services.auth import create_audit_log
from datetime import datetime, timezone

router = APIRouter(prefix="/api/orgs", tags=["Organizations"])


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_org(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.org_id != org_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    users_result = await db.execute(
        select(func.count()).select_from(User).where(User.org_id == org_id)
    )
    member_count = users_result.scalar() or 0

    repos_result = await db.execute(
        select(func.count()).select_from(Repository).where(Repository.org_id == org_id)
    )
    repo_count = repos_result.scalar() or 0

    return {
        **OrganizationResponse.model_validate(org).model_dump(),
        "member_count": member_count,
        "repo_count": repo_count,
    }


@router.put("/{org_id}", response_model=OrganizationResponse)
async def update_org(
    org_id: str,
    data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if current_user.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if "name" in data:
        org.name = data["name"]
    if "settings" in data:
        org.settings = data["settings"]

    await create_audit_log(db, org_id, current_user.id, "org.update", "organization", org_id, {"changes": list(data.keys())})
    await db.commit()
    await db.refresh(org)
    return OrganizationResponse.model_validate(org)


@router.get("/{org_id}/billing")
async def get_billing(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if current_user.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    from app.services.billing import get_billing_summary
    try:
        summary = await get_billing_summary(org_id, db)
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{org_id}/billing/upgrade")
async def upgrade_plan(
    org_id: str,
    plan: str = "pro",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if current_user.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    from app.services.billing import create_checkout_session
    try:
        result = await create_checkout_session(
            org_id=org_id,
            plan=plan,
            email=current_user.email,
            org_name=current_user.name or org_id,
            db=db,
        )
        await db.commit()
        await create_audit_log(db, org_id, current_user.id, "billing.upgrade_initiated", "checkout_session", result["session_id"], {"plan": plan})
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upgrade failed: {str(e)}")


@router.post("/{org_id}/billing/cancel")
async def cancel_subscription(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if current_user.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    from app.services.billing import cancel_subscription_at_period_end

    sub_result = await db.execute(
        select(Subscription).where(Subscription.org_id == org_id).order_by(desc(Subscription.created_at)).limit(1)
    )
    sub = sub_result.scalar_one_or_none()
    if not sub or not sub.stripe_subscription_id:
        raise HTTPException(status_code=404, detail="No active subscription")

    try:
        await cancel_subscription_at_period_end(org_id, sub.stripe_subscription_id, db)
        await db.commit()
        await create_audit_log(db, org_id, current_user.id, "billing.canceled", "subscription", sub.id)
        return {"message": "Subscription will cancel at end of billing period"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{org_id}/billing/portal")
async def billing_portal(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if current_user.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    from app.services.billing import create_portal_session
    try:
        url = await create_portal_session(org_id)
        return {"portal_url": url}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{org_id}/billing/reactivate")
async def reactivate_subscription(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if current_user.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    from app.services.billing import reactivate_subscription

    sub_result = await db.execute(
        select(Subscription).where(Subscription.org_id == org_id).order_by(desc(Subscription.created_at)).limit(1)
    )
    sub = sub_result.scalar_one_or_none()
    if not sub or not sub.stripe_subscription_id:
        raise HTTPException(status_code=404, detail="No active subscription")

    try:
        await reactivate_subscription(org_id, sub.stripe_subscription_id, db)
        await db.commit()
        return {"message": "Subscription reactivated"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{org_id}/billing/change-plan")
async def change_plan(
    org_id: str,
    new_plan: str = "pro",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if current_user.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    from app.services.billing import update_subscription_plan

    sub_result = await db.execute(
        select(Subscription).where(Subscription.org_id == org_id).order_by(desc(Subscription.created_at)).limit(1)
    )
    sub = sub_result.scalar_one_or_none()
    if not sub or not sub.stripe_subscription_id:
        raise HTTPException(status_code=404, detail="No active subscription")

    try:
        result = await update_subscription_plan(org_id, new_plan, sub.stripe_subscription_id, db)
        await db.commit()
        await create_audit_log(db, org_id, current_user.id, "billing.plan_changed", "subscription", sub.id, {"new_plan": new_plan})
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
