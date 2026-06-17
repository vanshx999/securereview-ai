from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_
from app.database import get_db
from app.models import (
    User, Repository, Organization, Integration, PullRequest, Finding,
    FindingSeverity, UserRole,
)
from app.schemas import RepositoryResponse
from app.middleware import get_current_user, require_admin
from app.middleware.rbac import require_role
from app.services.auth import create_audit_log
from app.services.encryption import encrypt, decrypt
import httpx

router = APIRouter(prefix="/api/repos", tags=["Repositories"])
repositories_router = APIRouter(prefix="/api/repositories", tags=["Repositories"])


async def get_org_repos(org_id: str, db: AsyncSession):
    result = await db.execute(
        select(Repository).where(Repository.org_id == org_id, Repository.is_active == True).order_by(Repository.full_name)
    )
    return result.scalars().all()


@router.get("/org/{org_id}")
async def list_repos(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.org_id != org_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")

    repos = await get_org_repos(org_id, db)
    results = []

    for repo in repos:
        last_pr_result = await db.execute(
            select(PullRequest).where(PullRequest.repo_id == repo.id).order_by(desc(PullRequest.created_at)).limit(1)
        )
        last_pr = last_pr_result.scalar_one_or_none()

        findings_result = await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.repo_id == repo.id,
                Finding.status == "open",
            )
        )
        open_findings = findings_result.scalar() or 0

        results.append({
            **RepositoryResponse.model_validate(repo).model_dump(),
            "last_analyzed_at": last_pr.created_at.isoformat() if last_pr else None,
            "open_findings": open_findings,
            "total_prs": 0,
        })

    return results


@router.post("/org/{org_id}/install")
async def install_repos(
    org_id: str,
    installation_id: str = Query(None),
    repos: list[str] = Query(default=[]),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if current_user.org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    integration_result = await db.execute(
        select(Integration).where(
            Integration.org_id == org_id,
            Integration.provider == "github",
            Integration.is_active == True,
        )
    )
    integration = integration_result.scalar_one_or_none()

    if not integration:
        raise HTTPException(status_code=400, detail="GitHub integration not installed. Complete OAuth first.")

    token = integration.access_token

    async with httpx.AsyncClient() as client:
        if installation_id:
            resp = await client.get(
                f"https://api.github.com/installation/repositories",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
        else:
            resp = await client.get(
                "https://api.github.com/user/repos?per_page=100&sort=updated",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )

        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch repos from GitHub")

        gh_repos = resp.json()
        if isinstance(gh_repos, dict):
            gh_repos = gh_repos.get("repositories", [])

        created = 0
        for gh_repo in gh_repos:
            if repos and gh_repo["full_name"] not in repos:
                continue

            existing = await db.execute(
                select(Repository).where(
                    Repository.github_repo_id == gh_repo["id"],
                )
            )
            if not existing.scalar_one_or_none():
                repo = Repository(
                    org_id=org_id,
                    github_repo_id=gh_repo["id"],
                    name=gh_repo["name"],
                    full_name=gh_repo["full_name"],
                    git_provider="github",
                    default_branch=gh_repo.get("default_branch", "main"),
                    is_active=True,
                )
                db.add(repo)
                created += 1

    await db.commit()
    await create_audit_log(db, org_id, current_user.id, "repos.install", "repository", None, {"count": created})
    return {"message": f"Installed {created} repository(s)", "count": created}


@router.delete("/{repo_id}")
async def remove_repo(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Repository).where(Repository.id == repo_id, Repository.org_id == current_user.org_id)
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    if current_user.role not in [UserRole.ADMIN, UserRole.SECURITY]:
        raise HTTPException(status_code=403, detail="Access denied")

    repo.is_active = False
    await db.commit()

    await create_audit_log(db, current_user.org_id, current_user.id, "repo.deactivate", "repository", repo_id)
    return {"message": "Repository deactivated"}


@router.post("/{repo_id}/sync")
async def sync_repo(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Repository).where(Repository.id == repo_id, Repository.org_id == current_user.org_id)
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    integration_result = await db.execute(
        select(Integration).where(
            Integration.org_id == current_user.org_id,
            Integration.provider == "github",
            Integration.is_active == True,
        )
    )
    integration = integration_result.scalar_one_or_none()

    if not integration or not integration.access_token:
        raise HTTPException(status_code=400, detail="No GitHub integration found")

    token = integration.access_token
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://api.github.com/repos/{repo.full_name}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"},
        )
        if resp.status_code == 200:
            gh_data = resp.json()
            repo.default_branch = gh_data.get("default_branch", repo.default_branch)
            repo.name = gh_data.get("name", repo.name)

    await db.commit()
    await create_audit_log(db, current_user.org_id, current_user.id, "repo.sync", "repository", repo_id)
    return {"message": "Repository synced"}


@router.get("/{repo_id}/health")
async def get_repo_health(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Repository).where(Repository.id == repo_id, Repository.org_id == current_user.org_id)
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    prs_result = await db.execute(
        select(func.count()).select_from(PullRequest).where(PullRequest.repo_id == repo_id)
    )
    total_prs = prs_result.scalar() or 0

    findings_result = await db.execute(
        select(
            func.count().label("total"),
            func.sum(case((Finding.severity == "CRITICAL", 1), else_=0)).label("critical"),
            func.sum(case((Finding.severity == "HIGH", 1), else_=0)).label("high"),
            func.sum(case((Finding.severity == "MEDIUM", 1), else_=0)).label("medium"),
            func.sum(case((Finding.status == "open", 1), else_=0)).label("open"),
        ).select_from(Finding).where(Finding.repo_id == repo_id)
    )
    stats = findings_result.one()

    critical = stats.critical or 0
    high = stats.high or 0
    medium = stats.medium or 0
    open_count = stats.open or 0

    health_score = 100
    health_score -= critical * 15
    health_score -= high * 8
    health_score -= medium * 3
    health_score = max(0, min(100, health_score))

    ai_result = await db.execute(
        select(func.avg(PullRequest.ai_code_percentage)).where(PullRequest.repo_id == repo_id)
    )
    avg_ai = ai_result.scalar() or 0.0

    return {
        "repo_id": repo_id,
        "repo_name": repo.full_name,
        "health_score": health_score,
        "total_prs_analyzed": total_prs,
        "open_findings": open_count,
        "critical_findings": critical,
        "high_findings": high,
        "medium_findings": medium,
        "avg_ai_code_percentage": round(float(avg_ai), 1),
        "grade": "A" if health_score >= 90 else "B" if health_score >= 75 else "C" if health_score >= 50 else "D" if health_score >= 25 else "F",
    }


from sqlalchemy import case


@repositories_router.get("/install-url")
async def get_install_url():
    from app.config import settings
    url = settings.GITHUB_INSTALLATION_URL or ""
    return {"url": url}


@repositories_router.get("/")
async def list_repositories(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    repos = await get_org_repos(current_user.org_id, db)
    results = []
    for repo in repos:
        last_pr_result = await db.execute(
            select(PullRequest).where(PullRequest.repo_id == repo.id).order_by(desc(PullRequest.created_at)).limit(1)
        )
        last_pr = last_pr_result.scalar_one_or_none()
        findings_result = await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.repo_id == repo.id,
                Finding.status == "open",
            )
        )
        results.append({
            **RepositoryResponse.model_validate(repo).model_dump(),
            "last_analyzed_at": last_pr.created_at.isoformat() if last_pr else None,
            "open_findings": findings_result.scalar() or 0,
            "total_prs": 0,
        })
    return results


@repositories_router.get("/{repo_id}")
async def get_repository(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Repository).where(Repository.id == repo_id, Repository.org_id == current_user.org_id)
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return RepositoryResponse.model_validate(repo)


@repositories_router.delete("/{repo_id}")
async def delete_repository(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Repository).where(Repository.id == repo_id, Repository.org_id == current_user.org_id)
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    if current_user.role not in [UserRole.ADMIN, UserRole.SECURITY]:
        raise HTTPException(status_code=403, detail="Access denied")
    repo.is_active = False
    await db.commit()
    await create_audit_log(db, current_user.org_id, current_user.id, "repo.deactivate", "repository", repo_id)
    return {"message": "Repository deactivated"}


@repositories_router.post("/install-github")
async def install_github_repos(
    code: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    result = await db.execute(
        select(Integration).where(
            Integration.org_id == current_user.org_id,
            Integration.provider == "github",
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration or not integration.access_token:
        raise HTTPException(status_code=400, detail="No GitHub integration. Complete OAuth first.")
    token = integration.access_token
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.github.com/user/repos?per_page=100&sort=updated",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"},
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch repos from GitHub")
        gh_repos = resp.json()
        created = 0
        for gh_repo in gh_repos:
            existing = await db.execute(
                select(Repository).where(Repository.github_repo_id == gh_repo["id"])
            )
            if not existing.scalar_one_or_none():
                repo = Repository(
                    org_id=current_user.org_id,
                    github_repo_id=gh_repo["id"],
                    name=gh_repo["name"],
                    full_name=gh_repo["full_name"],
                    git_provider="github",
                    default_branch=gh_repo.get("default_branch", "main"),
                    is_active=True,
                )
                db.add(repo)
                created += 1
        await db.commit()
    await create_audit_log(db, current_user.org_id, current_user.id, "repos.install", "repository", None, {"count": created})
    return {"message": f"Installed {created} repository(s)", "count": created}
