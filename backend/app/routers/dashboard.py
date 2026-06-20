from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, case, and_
from app.database import get_db
from app.models import (
    User, Organization, Repository, PullRequest, Finding,
    FindingSeverity, FindingStatus, Policy, AuditLog,
)
from app.schemas import DashboardStats, PullRequestResponse, FindingResponse
from app.middleware import get_current_user
from app.middleware.rbac import require_security_or_admin, require_admin
from app.services.auth import create_audit_log
from app.services.compliance import generate_compliance_report, export_csv_report
from datetime import datetime, timedelta, timezone
from fastapi.responses import Response

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


async def get_org_repo_ids(org_id: str, db: AsyncSession) -> list:
    result = await db.execute(select(Repository.id).where(Repository.org_id == org_id))
    return [r[0] for r in result.all()]


async def _build_dashboard_stats(
    db: AsyncSession,
    current_user: User,
):
    repo_ids = await get_org_repo_ids(current_user.org_id, db)

    if not repo_ids:
        return DashboardStats(
            total_repos=0, total_prs_analyzed=0, total_findings=0,
            open_findings=0, critical_findings=0, avg_health_score=0.0,
            avg_ai_code_percentage=0.0, mean_time_to_resolution_hours=0.0,
            vulnerability_trends=[], top_vulnerabilities=[], ai_code_trends=[],
        )

    repos_count = len(repo_ids)

    prs_result = await db.execute(
        select(func.count()).select_from(PullRequest).where(PullRequest.repo_id.in_(repo_ids))
    )
    total_prs = prs_result.scalar() or 0

    findings_result = await db.execute(
        select(func.count()).select_from(Finding).where(Finding.repo_id.in_(repo_ids))
    )
    total_findings = findings_result.scalar() or 0

    open_result = await db.execute(
        select(func.count()).select_from(Finding).where(
            Finding.repo_id.in_(repo_ids),
            Finding.status == FindingStatus.OPEN,
        )
    )
    open_findings = open_result.scalar() or 0

    critical_result = await db.execute(
        select(func.count()).select_from(Finding).where(
            Finding.repo_id.in_(repo_ids),
            Finding.severity == FindingSeverity.CRITICAL,
        )
    )
    critical_count = critical_result.scalar() or 0

    health_result = await db.execute(
        select(func.avg(PullRequest.health_score)).where(PullRequest.repo_id.in_(repo_ids))
    )
    avg_health = float(health_result.scalar() or 0.0)

    ai_result = await db.execute(
        select(func.avg(PullRequest.ai_code_percentage)).where(PullRequest.repo_id.in_(repo_ids))
    )
    avg_ai = float(ai_result.scalar() or 0.0)

    mttr = await db.execute(
        select(
            func.avg(
                func.extract('epoch', Finding.updated_at - Finding.created_at) / 3600
            )
        ).where(
            Finding.repo_id.in_(repo_ids),
            Finding.status != FindingStatus.OPEN,
        )
    )
    avg_mttr = float(mttr.scalar() or 0.0)

    top_vuln_result = await db.execute(
        select(Finding.category, func.count().label("count"))
        .where(Finding.repo_id.in_(repo_ids))
        .group_by(Finding.category)
        .order_by(desc("count"))
        .limit(10)
    )
    top_vulns = [{"category": r.category, "count": r.count} for r in top_vuln_result.all()]

    return DashboardStats(
        total_repos=repos_count,
        total_prs_analyzed=total_prs,
        total_findings=total_findings,
        open_findings=open_findings,
        critical_findings=critical_count,
        avg_health_score=round(avg_health, 1),
        avg_ai_code_percentage=round(avg_ai, 1),
        mean_time_to_resolution_hours=round(avg_mttr, 1),
        vulnerability_trends=[],
        top_vulnerabilities=top_vulns,
        ai_code_trends=[],
    )


@router.get("/stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await _build_dashboard_stats(db, current_user)


@router.get("/metrics")
async def get_dashboard_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await _build_dashboard_stats(db, current_user)


@router.get("/recent-prs")
async def get_recent_prs(
    limit: int = Query(default=10, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    repo_ids = await get_org_repo_ids(current_user.org_id, db)
    if not repo_ids:
        return []
    result = await db.execute(
        select(PullRequest)
        .where(PullRequest.repo_id.in_(repo_ids))
        .order_by(desc(PullRequest.created_at))
        .limit(limit)
    )
    return [PullRequestResponse.model_validate(pr) for pr in result.scalars().all()]


@router.get("/recent-findings")
async def get_recent_findings(
    limit: int = Query(default=20, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    repo_ids = await get_org_repo_ids(current_user.org_id, db)
    if not repo_ids:
        return []
    result = await db.execute(
        select(Finding)
        .where(Finding.repo_id.in_(repo_ids))
        .order_by(desc(Finding.created_at))
        .limit(limit)
    )
    return [FindingResponse.model_validate(f) for f in result.scalars().all()]


async def _build_trends(
    db: AsyncSession,
    current_user: User,
    days: int = 30,
):
    repo_ids = await get_org_repo_ids(current_user.org_id, db)
    if not repo_ids:
        return {"daily_findings": [], "daily_prs": []}

    start_date = datetime.now(timezone.utc) - timedelta(days=days)

    daily_findings_result = await db.execute(
        select(
            func.date(Finding.created_at).label('date'),
            Finding.severity,
            func.count().label('count'),
        ).where(
            Finding.repo_id.in_(repo_ids),
            Finding.created_at >= start_date,
        ).group_by(
            func.date(Finding.created_at),
            Finding.severity,
        ).order_by('date')
    )

    trends = {}
    for row in daily_findings_result.all():
        date_str = row.date.isoformat()[:10] if hasattr(row.date, 'isoformat') else str(row.date)[:10]
        if date_str not in trends:
            trends[date_str] = {"date": date_str, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        trends[date_str][row.severity.value] = row.count

    daily_prs_result = await db.execute(
        select(
            func.date(PullRequest.created_at).label('date'),
            func.count().label('count'),
            func.avg(PullRequest.ai_code_percentage).label('avg_ai'),
        ).where(
            PullRequest.repo_id.in_(repo_ids),
            PullRequest.created_at >= start_date,
        ).group_by(
            func.date(PullRequest.created_at),
        ).order_by('date')
    )

    pr_trends = []
    ai_trends = []
    for row in daily_prs_result.all():
        date_str = row.date.isoformat()[:10] if hasattr(row.date, 'isoformat') else str(row.date)[:10]
        pr_trends.append({"date": date_str, "count": row.count})
        if row.avg_ai:
            ai_trends.append({"date": date_str, "ai_percentage": round(float(row.avg_ai), 1)})

    repo_health_result = await db.execute(
        select(Repository.full_name, func.avg(PullRequest.health_score).label("avg_health"))
        .select_from(PullRequest)
        .join(Repository)
        .where(PullRequest.repo_id.in_(repo_ids))
        .group_by(Repository.full_name)
        .order_by(desc("avg_health"))
    )
    repo_health = [{"name": r.full_name, "avg_health": round(float(r.avg_health), 1)} for r in repo_health_result.all() if r.avg_health]

    return {
        "daily_findings": list(trends.values()),
        "daily_prs": pr_trends,
        "ai_code_trends": ai_trends,
        "repo_health_scores": repo_health,
    }


@router.get("/vulnerability-trends")
async def get_vulnerability_trends(
    days: int = Query(default=14, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await _build_trends(db, current_user, days)


@router.get("/trends")
async def get_trends(
    days: int = Query(default=30, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await _build_trends(db, current_user, days)


@router.get("/compliance-report")
async def get_compliance_report(
    format: str = Query(default="pdf", pattern="^(pdf|csv)$"),
    date_from: str = None,
    date_to: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    parsed_from = datetime.fromisoformat(date_from) if date_from else None
    parsed_to = datetime.fromisoformat(date_to) if date_to else None

    if format == "csv":
        content = await export_csv_report(db, current_user.org_id, parsed_from, parsed_to)
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=securereview-compliance-report.csv"},
        )
    else:
        pdf_content = await generate_compliance_report(db, current_user.org_id, parsed_from, parsed_to)
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=securereview-compliance-report.pdf"},
        )


@router.get("/developer-stats")
async def get_developer_stats(
    days: int = Query(default=30, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    repo_ids = await get_org_repo_ids(current_user.org_id, db)
    if not repo_ids:
        return []

    start_date = datetime.now(timezone.utc) - timedelta(days=days)

    result = await db.execute(
        select(
            PullRequest.author,
            func.count(func.distinct(PullRequest.id)).label("total_prs"),
            func.count(Finding.id).label("total_findings"),
            func.sum(case((Finding.severity == "CRITICAL", 1), else_=0)).label("critical_findings"),
            func.sum(case((Finding.severity == "HIGH", 1), else_=0)).label("high_findings"),
            func.avg(PullRequest.ai_code_percentage).label("avg_ai_code"),
        )
        .select_from(PullRequest)
        .outerjoin(Finding, Finding.pr_id == PullRequest.id)
        .where(
            PullRequest.repo_id.in_(repo_ids),
            PullRequest.created_at >= start_date,
        )
        .group_by(PullRequest.author)
        .order_by(desc("total_findings"))
    )

    developers = []
    for row in result.all():
        if not row.author:
            continue
        total = (row.total_findings or 0)
        critical = row.critical_findings or 0
        score = max(0, 100 - (critical * 20 + (total - critical) * 2))
        developers.append({
            "author": row.author,
            "total_prs": row.total_prs,
            "total_findings": total,
            "critical_findings": critical,
            "high_findings": row.high_findings or 0,
            "avg_ai_code_percentage": round(float(row.avg_ai_code or 0), 1),
            "security_score": score,
        })

    return developers
