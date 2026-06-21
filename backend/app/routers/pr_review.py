import asyncio
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from app.database import get_db
from app.models import (
    User, PullRequest, Finding, FindingStatus, FindingSeverity,
    Repository, Organization, UserRole,
)
from app.schemas import PullRequestResponse, FindingResponse
from app.middleware import get_current_user
from app.middleware.rbac import require_security_or_admin, require_role
from app.middleware.rate_limit import check_org_analysis_rate_limit
from app.services.auth import create_audit_log
from app.tasks import analyze_pr

router = APIRouter(prefix="/api/prs", tags=["Pull Requests"])


@router.get("/")
async def list_prs(
    repo_id: str = None,
    status: str = None,
    author: str = None,
    limit: int = Query(default=20, le=100),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(PullRequest).where(
        PullRequest.repo_id.in_(
            select(Repository.id).where(Repository.org_id == current_user.org_id)
        )
    )
    if repo_id:
        query = query.where(PullRequest.repo_id == repo_id)
    if status:
        query = query.where(PullRequest.status == status)
    if author:
        query = query.where(PullRequest.author == author)

    total_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(total_query)
    total = total_result.scalar() or 0

    query = query.order_by(desc(PullRequest.created_at)).offset(offset).limit(limit)
    result = await db.execute(query)
    prs = result.scalars().all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "pull_requests": [PullRequestResponse.model_validate(pr) for pr in prs],
    }


@router.get("/{pr_id}", response_model=PullRequestResponse)
async def get_pr(
    pr_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(PullRequest).where(
            PullRequest.id == pr_id,
            PullRequest.repo_id.in_(
                select(Repository.id).where(Repository.org_id == current_user.org_id)
            ),
        )
    )
    pr = result.scalar_one_or_none()
    if not pr:
        raise HTTPException(status_code=404, detail="Pull request not found")
    return PullRequestResponse.model_validate(pr)


@router.get("/{pr_id}/findings")
async def get_pr_findings(
    pr_id: str,
    severity: str = None,
    status: str = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Finding).where(Finding.pr_id == pr_id)
    if severity:
        query = query.where(Finding.severity == severity.upper())
    if status:
        query = query.where(Finding.status == status)
    query = query.order_by(desc(Finding.created_at)).offset(offset).limit(limit)

    result = await db.execute(query)
    findings = result.scalars().all()

    return {
        "total": len(findings),
        "limit": limit,
        "offset": offset,
        "findings": [FindingResponse.model_validate(f) for f in findings],
    }


@router.post("/{pr_id}/reanalyze")
async def reanalyze_pr(
    pr_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(PullRequest).where(
            PullRequest.id == pr_id,
            PullRequest.repo_id.in_(
                select(Repository.id).where(Repository.org_id == current_user.org_id)
            ),
        )
    )
    pr = result.scalar_one_or_none()
    if not pr:
        raise HTTPException(status_code=404, detail="PR not found")

    await check_org_analysis_rate_limit(current_user.org_id)

    await analyze_pr(pr_id)
    return {"message": "Re-analysis complete", "pr_id": pr_id}


@router.patch("/{pr_id}/findings/{finding_id}")
async def update_pr_finding(
    pr_id: str,
    finding_id: str,
    data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.pr_id == pr_id,
            Finding.repo_id.in_(
                select(Repository.id).where(Repository.org_id == current_user.org_id)
            ),
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if data.get("status") == "dismissed":
        finding.status = FindingStatus.DISMISSED
        finding.dismissed_by = current_user.id
        finding.dismissed_reason = data.get("dismissed_reason", "")
    elif data.get("status") == "fixed":
        finding.status = FindingStatus.FIXED
    else:
        for key, value in data.items():
            if hasattr(finding, key):
                setattr(finding, key, value)
    await db.commit()
    return {"message": "Finding updated", "finding_id": finding_id}


@router.post("/{pr_id}/override")
async def override_status_check(
    pr_id: str,
    reason: str = Query(..., min_length=10),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_security_or_admin),
):
    result = await db.execute(
        select(PullRequest).where(
            PullRequest.id == pr_id,
            PullRequest.repo_id.in_(
                select(Repository.id).where(Repository.org_id == current_user.org_id)
            ),
        )
    )
    pr = result.scalar_one_or_none()
    if not pr:
        raise HTTPException(status_code=404, detail="PR not found")

    pr.metadata = {
        **(pr.metadata or {}),
        "status_overridden": True,
        "overridden_by": current_user.id,
        "override_reason": reason,
        "overridden_at": func.now().isoformat() if hasattr(func.now(), 'isoformat') else str(func.now()),
    }
    await db.commit()

    await create_audit_log(
        db, current_user.org_id, current_user.id,
        "pr.status_override", "pull_request", pr_id,
        {"reason": reason, "pr_number": pr.pr_number},
    )

    from app.services.github_integration import update_pr_status_check
    repo = await db.execute(select(Repository).where(Repository.id == pr.repo_id))
    repo = repo.scalar_one_or_none()
    if repo:
        await update_pr_status_check(db, repo.id, pr.pr_number, current_user.org_id, "success", f"Overridden: {reason}")

    return {"message": "Status check overridden", "pr_id": pr_id}
