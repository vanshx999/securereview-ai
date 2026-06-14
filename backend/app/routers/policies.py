import re
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from app.database import get_db
from app.models import User, Policy, Organization, PolicyViolation, Finding, UserRole
from app.schemas import PolicyCreate, PolicyUpdate, PolicyResponse
from app.middleware import get_current_user
from app.middleware.rbac import require_security_or_admin, require_role
from app.services.policy_engine import compile_natural_language_policy
from app.services.auth import create_audit_log

router = APIRouter(prefix="/api/policies", tags=["Policies"])


@router.get("/org/{org_id}")
async def list_policies_by_org(
    org_id: str,
    include_inactive: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.org_id != org_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")

    query = select(Policy).where(Policy.org_id == org_id)
    if not include_inactive:
        query = query.where(Policy.is_active == True)
    query = query.order_by(desc(Policy.created_at))

    result = await db.execute(query)
    policies = result.scalars().all()
    return [PolicyResponse.model_validate(p) for p in policies]


@router.post("/org/{org_id}", response_model=PolicyResponse, status_code=201)
async def create_policy(
    org_id: str,
    data: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_security_or_admin),
):
    if current_user.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    compiled = await compile_natural_language_policy(data.natural_language_rule)

    policy = Policy(
        org_id=org_id,
        name=data.name,
        description=data.description,
        natural_language_rule=data.natural_language_rule,
        compiled_rule=compiled,
        target_file_patterns=data.target_file_patterns,
        severity=data.severity,
        created_by=current_user.id,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    await create_audit_log(
        db, org_id, current_user.id,
        "policy.create", "policy", policy.id,
        {"name": policy.name},
    )

    return PolicyResponse.model_validate(policy)


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Policy).where(
            Policy.id == policy_id,
            Policy.org_id == current_user.org_id,
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    violations_count = await db.execute(
        select(func.count()).select_from(PolicyViolation).where(PolicyViolation.policy_id == policy_id)
    )

    return {
        **PolicyResponse.model_validate(policy).model_dump(),
        "total_violations": violations_count.scalar() or 0,
    }


@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: str,
    data: PolicyUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_security_or_admin),
):
    result = await db.execute(
        select(Policy).where(
            Policy.id == policy_id,
            Policy.org_id == current_user.org_id,
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    update_data = data.model_dump(exclude_unset=True)
    if "natural_language_rule" in update_data and update_data["natural_language_rule"]:
        compiled = await compile_natural_language_policy(update_data["natural_language_rule"])
        policy.compiled_rule = compiled
        policy.version += 1

    for field, value in update_data.items():
        if field != "natural_language_rule" and value is not None:
            setattr(policy, field, value)

    await db.commit()
    await db.refresh(policy)

    await create_audit_log(
        db, current_user.org_id, current_user.id,
        "policy.update", "policy", policy_id,
        {"name": policy.name, "version": policy.version},
    )

    return PolicyResponse.model_validate(policy)


@router.delete("/{policy_id}")
async def delete_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_security_or_admin),
):
    result = await db.execute(
        select(Policy).where(
            Policy.id == policy_id,
            Policy.org_id == current_user.org_id,
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy.is_active = False
    await db.commit()

    await create_audit_log(
        db, current_user.org_id, current_user.id,
        "policy.delete", "policy", policy_id,
    )

    return {"message": "Policy deactivated"}


@router.post("/{policy_id}/test")
async def test_policy(
    policy_id: str,
    sample_code: str = Query(..., min_length=10),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Policy).where(
            Policy.id == policy_id,
            Policy.org_id == current_user.org_id,
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if not policy.compiled_rule or not policy.compiled_rule.get("pattern"):
        return {"matches": [], "note": "Policy has no compiled pattern yet. Save it first."}

    pattern = policy.compiled_rule["pattern"]
    matches = []
    for line_idx, line in enumerate(sample_code.split("\n"), 1):
        if re.search(pattern, line, re.IGNORECASE):
            matches.append({"line": line_idx, "content": line.strip()[:200]})

    return {
        "policy_id": policy_id,
        "policy_name": policy.name,
        "pattern": pattern,
        "total_matches": len(matches),
        "matches": matches,
    }


@router.post("/{policy_id}/activate")
async def toggle_policy_activation(
    policy_id: str,
    active: bool = Query(True),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_security_or_admin),
):
    result = await db.execute(
        select(Policy).where(
            Policy.id == policy_id,
            Policy.org_id == current_user.org_id,
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy.is_active = active
    await db.commit()

    await create_audit_log(
        db, current_user.org_id, current_user.id,
        f"policy.{'activate' if active else 'deactivate'}", "policy", policy_id,
    )

    return {"message": f"Policy {'activated' if active else 'deactivated'}", "is_active": active}
