from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_
from app.database import get_db
from app.models import User, Finding, FindingStatus, FindingSeverity, Repository, PolicyViolation, UserRole
from app.schemas import FindingResponse, FindingUpdate
from app.middleware import get_current_user
from app.middleware.rbac import require_security_or_admin, require_role
from app.services.auth import create_audit_log

router = APIRouter(prefix="/api/findings", tags=["Findings"])


@router.get("/")
async def list_findings(
    severity: str = None,
    status: str = None,
    repo_id: str = None,
    category: str = None,
    date_from: str = None,
    date_to: str = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Finding).where(
        Finding.repo_id.in_(
            select(Repository.id).where(Repository.org_id == current_user.org_id)
        )
    )

    if severity:
        query = query.where(Finding.severity == severity.upper())
    if status:
        query = query.where(Finding.status == status)
    if repo_id:
        query = query.where(Finding.repo_id == repo_id)
    if category:
        query = query.where(Finding.category == category)
    if date_from:
        from datetime import datetime
        query = query.where(Finding.created_at >= datetime.fromisoformat(date_from))
    if date_to:
        from datetime import datetime
        query = query.where(Finding.created_at <= datetime.fromisoformat(date_to))

    total_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(total_query)
    total = total_result.scalar() or 0

    query = query.order_by(desc(Finding.created_at)).offset(offset).limit(limit)
    result = await db.execute(query)
    findings = result.scalars().all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "findings": [FindingResponse.model_validate(f) for f in findings],
    }


@router.get("/stats")
async def get_finding_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    org_repos = select(Repository.id).where(Repository.org_id == current_user.org_id)

    severity_counts = {}
    for sev in FindingSeverity:
        result = await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.repo_id.in_(org_repos),
                Finding.severity == sev,
            )
        )
        severity_counts[sev.value] = result.scalar() or 0

    status_counts = {}
    for st in FindingStatus:
        result = await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.repo_id.in_(org_repos),
                Finding.status == st,
            )
        )
        status_counts[st.value] = result.scalar() or 0

    category_result = await db.execute(
        select(Finding.category, func.count().label("count"))
        .where(Finding.repo_id.in_(org_repos))
        .group_by(Finding.category)
        .order_by(desc("count"))
        .limit(10)
    )
    top_categories = [{"category": r.category, "count": r.count} for r in category_result.all()]

    return {
        "by_severity": severity_counts,
        "by_status": status_counts,
        "top_categories": top_categories,
        "total": sum(severity_counts.values()),
    }


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.repo_id.in_(
                select(Repository.id).where(Repository.org_id == current_user.org_id)
            ),
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    violations_result = await db.execute(
        select(PolicyViolation).where(PolicyViolation.finding_id == finding_id)
    )
    violations = violations_result.scalars().all()

    return {
        **FindingResponse.model_validate(finding).model_dump(),
        "policy_violations": [
            {"policy_id": v.policy_id, "matched_text": v.matched_text, "created_at": v.created_at.isoformat()}
            for v in violations
        ],
    }


@router.post("/{finding_id}/dismiss")
async def dismiss_finding(
    finding_id: str,
    reason: str = Query(..., min_length=1),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_security_or_admin),
):
    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.repo_id.in_(
                select(Repository.id).where(Repository.org_id == current_user.org_id)
            ),
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = FindingStatus.DISMISSED
    finding.dismissed_by = current_user.id
    finding.dismissed_reason = reason
    await db.commit()

    await create_audit_log(
        db, current_user.org_id, current_user.id,
        "finding.dismiss", "finding", finding_id,
        {"reason": reason, "severity": finding.severity.value, "category": finding.category},
    )
    return {"message": "Finding dismissed", "finding_id": finding_id}


@router.post("/{finding_id}/fix")
async def mark_finding_fixed(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.repo_id.in_(
                select(Repository.id).where(Repository.org_id == current_user.org_id)
            ),
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = FindingStatus.FIXED
    finding.metadata = {
        **(finding.metadata or {}),
        "fixed_by": current_user.id,
        "fixed_at": func.now().isoformat() if hasattr(func.now(), 'isoformat') else str(func.now()),
    }
    await db.commit()

    return {"message": "Finding marked as fixed", "finding_id": finding_id}
