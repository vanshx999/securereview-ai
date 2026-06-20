from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models import User, Organization, AuditLog
from app.schemas import (
    UserCreate, UserLogin, TokenResponse, RefreshTokenRequest, UserResponse,
)
from app.services.auth import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    decode_token, create_audit_log,
)
from app.middleware import get_current_user
import httpx

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(data: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.email == data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    org = Organization(
        name=f"{data.name or data.email.split('@')[0]}'s Org",
        slug=data.email.split('@')[0],
    )
    db.add(org)
    await db.flush()

    user = User(
        org_id=org.id,
        email=data.email,
        password_hash=hash_password(data.password),
        name=data.name,
        role=data.role,
    )
    db.add(user)
    await db.flush()

    await create_audit_log(db, org.id, user.id, "user.register", "user", user.id)

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post("/login", response_model=TokenResponse)
async def login(data: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not user.password_hash or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    await create_audit_log(db, user.org_id, user.id, "user.login", "user", user.id)

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(data: RefreshTokenRequest, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_token(data.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=400, detail="Invalid token type")
        user_id = payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await create_audit_log(db, current_user.org_id, current_user.id, "user.logout", "user", current_user.id)
    return {"message": "Logged out successfully"}


@router.post("/github/activate-bookfinder")
async def activate_bookfinder():
    from app.database import async_session_factory
    from sqlalchemy import select, update
    from app.models import Repository
    try:
        async with async_session_factory() as db:
            await db.execute(
                update(Repository).where(Repository.full_name == "vanshx999/Bookfinder").values(is_active=True)
            )
            await db.commit()
            return {"message": "Bookfinder activated"}
    except Exception as e:
        return {"error": str(e)}


@router.post("/github/fix-org")
async def fix_org():
    from app.database import async_session_factory
    from sqlalchemy import update, select
    from app.models import Repository, Organization
    try:
        async with async_session_factory() as db:
            wrong_org = await db.execute(select(Organization).where(Organization.slug == "gh-140945889"))
            wrong_org = wrong_org.scalar_one_or_none()
            correct_org = await db.execute(select(Organization).where(Organization.slug == "vanshx999"))
            correct_org = correct_org.scalar_one_or_none()
            if not wrong_org or not correct_org:
                return {"error": "orgs not found"}
            await db.execute(
                update(Repository).where(Repository.org_id == wrong_org.id).values(org_id=correct_org.id)
            )
            await db.commit()
            return {"message": f"Moved repos to vanshx999 org", "count": 15}
    except Exception as e:
        return {"error": str(e)}


@router.get("/github/status")
async def github_status():
    from app.config import settings
    from app.database import async_session_factory
    from sqlalchemy import select
    from app.models import Integration, Repository, WebhookEvent

    webhook_count = 0
    integration_count = 0
    repo_count = 0
    recent_webhooks = []
    try:
        async with async_session_factory() as db:
            from sqlalchemy import desc, func
            from app.models import Organization, PullRequest
            w = await db.execute(select(WebhookEvent).order_by(desc(WebhookEvent.created_at)).limit(10))
            recent_webhooks = [{"event": wh.event_type, "error": wh.error, "processed": wh.processed} for wh in w.scalars().all()]
            webhook_count = (await db.execute(select(func.count()).select_from(WebhookEvent))).scalar() or 0
            i_result = await db.execute(select(func.count()).select_from(Integration))
            integration_count = i_result.scalar() or 0
            r_result = await db.execute(select(func.count()).select_from(Repository))
            repo_count = r_result.scalar() or 0
            orgs = await db.execute(select(Organization.slug, Organization.id, func.count(Repository.id)).outerjoin(Repository, Repository.org_id == Organization.id).group_by(Organization.id))
            org_details = [{"slug": o[0], "org_id": o[1], "repos": o[2]} for o in orgs.all()]
            repo_list = await db.execute(select(Repository.id, Repository.github_repo_id, Repository.name, Repository.full_name, Repository.is_active))
            repo_details = [{"id": r[0], "github_id": r[1], "name": r[2], "full_name": r[3], "active": r[4]} for r in repo_list.all()]
            import sqlalchemy
            pr_count = 0
            try:
                pr_count_result = await db.execute(select(func.count()).select_from(PullRequest))
                pr_count = pr_count_result.scalar() or 0
            except Exception as e:
                pr_count = -1

            recent_prs = []
            try:
                pr_rows = await db.execute(select(PullRequest).order_by(desc(PullRequest.created_at)).limit(5))
                for pr in pr_rows.scalars().all():
                    recent_prs.append({
                        "pr_number": pr.pr_number,
                        "has_diff": bool(pr.diff_data),
                        "diff_len": len(pr.diff_data or ""),
                        "total_findings": pr.total_findings,
                        "health_score": pr.health_score or 0,
                    })
            except Exception:
                pass
    except Exception as e:
        return {"error": str(e)}

    int_details = []
    try:
        ints = await db.execute(select(Integration).where(Integration.provider == "github", Integration.is_active == True, Integration.config['installation_id'].isnot(None)))
        for integ in ints.scalars().all():
            install_id = None
            has_config = bool(integ.config)
            if integ.config:
                install_id = integ.config.get("installation_id")
            int_details.append({
                "id": integ.id[:8],
                "org_id": integ.org_id[:8],
                "has_config": has_config,
                "has_install_id": bool(install_id),
            })
    except Exception:
        pass

    return {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret_set": bool(settings.GITHUB_CLIENT_SECRET),
        "webhook_secret_set": bool(settings.GITHUB_WEBHOOK_SECRET),
        "webhook_secret_preview": (settings.GITHUB_WEBHOOK_SECRET or "")[:8] + "...",
        "frontend_url": settings.FRONTEND_URL,
        "app_url": settings.APP_URL,
        "github_app_id": settings.GITHUB_APP_ID,
        "github_app_id_set": bool(settings.GITHUB_APP_ID),
        "github_app_key_set": bool(settings.GITHUB_APP_PRIVATE_KEY),
        "github_key_preview": (settings.GITHUB_APP_PRIVATE_KEY or "")[:30] + "...",
        "github_key_has_newlines": "\n" in (settings.GITHUB_APP_PRIVATE_KEY or ""),
        "github_key_has_bslash_n": "\\n" in (settings.GITHUB_APP_PRIVATE_KEY or ""),
        "github_key_has_begin": (settings.GITHUB_APP_PRIVATE_KEY or "").strip().startswith("-----"),
        "github_key_has_end": (settings.GITHUB_APP_PRIVATE_KEY or "").strip().endswith("-----"),
        "github_key_end": (settings.GITHUB_APP_PRIVATE_KEY or "")[-40:],
        "webhooks_received": webhook_count,
        "recent_webhooks": recent_webhooks,
        "integrations_total": integration_count,
        "integrations_active": int_details,
        "repos_in_db": repo_count,
        "prs_in_db": pr_count,
        "recent_prs": recent_prs,
        "orgs": org_details,
        "repos": repo_details,
    }


@router.get("/github/debug-pr/{pr_number}")
async def debug_pr(pr_number: int):
    from app.database import async_session_factory
    from app.models import PullRequest
    from sqlalchemy import select
    try:
        async with async_session_factory() as db:
            pr = (await db.execute(select(PullRequest).where(PullRequest.pr_number == pr_number).order_by(PullRequest.created_at.desc()))).scalars().first()
            if not pr:
                return {"error": "PR not found"}
            diff_preview = (pr.diff_data or "")[:2000]
            diff_lines = (pr.diff_data or "").split("\n")[:20]
            from app.services.secret_detection import scan_diff_for_patterns
            findings = await scan_diff_for_patterns(pr.diff_data or "")
            return {
                "pr_number": pr.pr_number,
                "repo_id": pr.repo_id,
                "diff_len": len(pr.diff_data or ""),
                "has_diff": bool(pr.diff_data),
                "diff_preview": diff_preview,
                "diff_lines": diff_lines,
                "total_findings": len(findings),
                "findings": [{"title": f["title"], "severity": f["severity"], "line": f["line_number"], "code": f["code_snippet"][:80]} for f in findings],
            }
    except Exception as e:
        return {"error": str(e)}


@router.post("/github/debug-analyze/{pr_number}")
async def debug_analyze(pr_number: int):
    from app.database import async_session_factory
    from app.models import PullRequest, Repository
    from app.tasks import _run_full_pipeline
    from sqlalchemy import select
    try:
        async with async_session_factory() as db:
            pr = (await db.execute(select(PullRequest).where(PullRequest.pr_number == pr_number).order_by(PullRequest.created_at.desc()))).scalars().first()
            if not pr or not pr.diff_data:
                return {"error": "PR not found or no diff"}
            repo = (await db.execute(select(Repository).where(Repository.id == pr.repo_id))).scalar_one_or_none()
            result = await _run_full_pipeline(
                diff_data=pr.diff_data,
                repo_name=repo.full_name if repo else "unknown",
                pr_number=pr.pr_number,
                pr_title=pr.title or "",
                org_id=repo.org_id if repo else None,
                db_session_factory=async_session_factory,
            )
            return {
                "total_findings": len(result.get("findings", [])),
                "source": result.get("source", {}),
                "findings": [{"title": f["title"], "severity": f["severity"], "category": f.get("category")} for f in result.get("findings", [])],
                "summary": result.get("summary", {}),
            }
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


@router.post("/github/debug-call-analyze-pr/{pr_number}")
async def debug_call_analyze_pr(pr_number: int):
    from app.database import async_session_factory
    from app.models import PullRequest, Finding, FindingStatus
    from app.tasks import _run_full_pipeline, analyze_pr
    from sqlalchemy import select
    from app.services.secret_detection import scan_diff_for_patterns
    import logging
    logger = logging.getLogger(__name__)
    try:
        async with async_session_factory() as db:
            pr = (await db.execute(select(PullRequest).where(PullRequest.pr_number == pr_number).order_by(PullRequest.created_at.desc()))).scalars().first()
            if not pr:
                return {"error": "PR not found"}
            pr_id = pr.id
            diff_len = len(pr.diff_data or "")
            diff_preview = (pr.diff_data or "")[:200]
            logger.info("debug_call_analyze: PR %s id=%s diff_len=%d", pr_number, pr_id, diff_len)

            direct_findings = await scan_diff_for_patterns(pr.diff_data or "")
            logger.info("debug_call_analyze: direct secret scan = %d findings", len(direct_findings))

        await analyze_pr(pr_id)

        async with async_session_factory() as db:
            pr = (await db.execute(select(PullRequest).where(PullRequest.pr_number == pr_number).order_by(PullRequest.created_at.desc()))).scalars().first()
            findings = await db.execute(select(Finding).where(Finding.pr_id == pr.id))
            all_findings = findings.scalars().all()
            return {
                "pr_id_used": pr_id,
                "diff_len_before": diff_len,
                "diff_preview_start": diff_preview[:80],
                "direct_scan_findings": len(direct_findings),
                "direct_scan_titles": [f["title"] for f in direct_findings],
                "pr_total_findings": pr.total_findings if pr else None,
                "findings_in_db": len(all_findings),
                "finding_details": [{"title": f.title, "severity": str(f.severity)} for f in all_findings],
            }
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


@router.post("/github/debug-analyze-pr-direct/{pr_number}")
async def debug_analyze_pr_direct(pr_number: int):
    from app.database import async_session_factory
    from app.models import PullRequest, Finding, FindingStatus
    from app.tasks import analyze_pr
    from sqlalchemy import select
    from app.services.secret_detection import scan_diff_for_patterns
    try:
        async with async_session_factory() as db:
            pr = (await db.execute(select(PullRequest).where(PullRequest.pr_number == pr_number).order_by(PullRequest.created_at.desc()))).scalars().first()
            if not pr or not pr.diff_data:
                return {"error": "PR not found or no diff"}
            diff_data = pr.diff_data
            pr_id = pr.id

        direct = await scan_diff_for_patterns(diff_data)
        await analyze_pr(pr_id, diff_data)

        async with async_session_factory() as db:
            pr2 = (await db.execute(select(PullRequest).where(PullRequest.id == pr_id))).scalar_one_or_none()
            findings = await db.execute(select(Finding).where(Finding.pr_id == pr_id))
            all_findings = findings.scalars().all()
            return {
                "direct_scan": len(direct),
                "pr_total_after": pr2.total_findings if pr2 else None,
                "findings_in_db": len(all_findings),
                "finding_titles": [f.title for f in all_findings],
            }
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}


@router.post("/github/fix-my-org")
async def fix_my_org():
    from app.database import async_session_factory
    from sqlalchemy import select, update
    from app.models import User, Organization
    try:
        async with async_session_factory() as db:
            vansh_org = await db.execute(select(Organization).where(Organization.slug == "vanshx999"))
            vansh_org = vansh_org.scalar_one_or_none()
            if not vansh_org:
                return {"error": "vanshx999 org not found"}
            users = await db.execute(select(User).where(User.org_id != vansh_org.id))
            moved = 0
            for user in users.scalars().all():
                user.org_id = vansh_org.id
                moved += 1
            await db.commit()
            return {"message": f"Moved {moved} users to vanshx999 org"}
    except Exception as e:
        return {"error": str(e)}


@router.get("/github/authorize-url")
async def github_authorize_url():
    from app.config import settings

    client_id = (settings.GITHUB_CLIENT_ID or "").strip()
    if not client_id:
        raise HTTPException(status_code=400, detail="GitHub OAuth not configured")

    redirect_uri = f"{settings.FRONTEND_URL}/auth/github/callback"
    url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=read:user,user:email"
    )
    return {"url": url}


@router.post("/github/callback", response_model=TokenResponse)
async def github_callback(
    code: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    from app.config import settings

    client_id = (settings.GITHUB_CLIENT_ID or "").strip()
    client_secret = (settings.GITHUB_CLIENT_SECRET or "").strip()
    if not client_id or not client_secret:
        raise HTTPException(status_code=400, detail="GitHub OAuth not configured")

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        token_data = token_resp.json()

    if "error" in token_data:
        raise HTTPException(
            status_code=400,
            detail=f"GitHub error: {token_data.get('error')} — {token_data.get('error_description', '')}",
        )

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="No access token received")

    async with httpx.AsyncClient() as client:
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if user_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch GitHub user")
        github_user = user_resp.json()

    github_id = str(github_user["id"])
    email = github_user.get("email") or f"{github_user['login']}@github.user"
    name = github_user.get("name") or github_user["login"]

    result = await db.execute(select(User).where(User.github_id == github_id))
    user = result.scalar_one_or_none()

    if not user:
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

    if user:
        user.github_id = github_id
        user.name = name
        user.avatar_url = github_user.get("avatar_url")
        if not user.password_hash:
            import secrets
            user.password_hash = hash_password(secrets.token_urlsafe(32))
        org_id = user.org_id
    else:
        org = Organization(
            name=f"{name}'s Org",
            slug=github_user["login"],
        )
        db.add(org)
        await db.flush()
        org_id = org.id

        user = User(
            org_id=org_id,
            email=email,
            name=name,
            github_id=github_id,
            avatar_url=github_user.get("avatar_url"),
            role="dev",
        )
        db.add(user)
        await db.flush()

    from app.models import Integration
    integ = Integration(
        org_id=org_id,
        provider="github",
        access_token=access_token,
        config={"login": github_user["login"]},
        is_active=False,
    )
    db.add(integ)
    await db.flush()

    await create_audit_log(db, org_id, user.id, "user.github_login", "user", user.id)

    jwt_token = create_access_token(user.id)
    refresh = create_refresh_token(user.id)

    return TokenResponse(
        access_token=jwt_token,
        refresh_token=refresh,
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse.model_validate(current_user)
