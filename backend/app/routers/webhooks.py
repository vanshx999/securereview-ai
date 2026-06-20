import logging
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models import (
    WebhookEvent, Repository, PullRequest, Integration, Organization,
    Subscription, SubscriptionStatus,
)
from app.middleware.webhook_verification import (
    verify_github_webhook, verify_gitlab_webhook, verify_stripe_webhook,
)
from app.tasks import analyze_pr
from app.services.encryption import encrypt, decrypt
from app.services.github_integration import get_installation_access_token
import asyncio
import httpx

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


@router.post("/github")
async def github_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    body = await verify_github_webhook(request)
    payload = await request.json()
    event = request.headers.get("x-github-event", "")

    webhook_event = WebhookEvent(
        provider="github",
        event_type=event,
        payload=payload,
    )
    db.add(webhook_event)

    result_status = "ok"

    try:
        if event == "ping":
            pass

        elif event == "installation":
            action = payload.get("action")
            installation = payload.get("installation", {})
            gh_account = installation.get("account", {}) or {}
            repos = payload.get("repositories", [])
            if action == "created":
                integration_result = await db.execute(
                    select(Integration).where(
                        Integration.provider == "github",
                        Integration.config['installation_id'].as_string() == str(installation.get("id")),
                    )
                )
                if not integration_result.scalar_one_or_none():
                    org_result = await db.execute(
                        select(Organization).where(Organization.slug == gh_account.get("login"))
                    )
                    org = org_result.scalar_one_or_none()
                    if not org:
                        org = Organization(
                            name=gh_account.get("login", "GitHub User"),
                            slug=gh_account.get("login", f"gh-{installation.get('id')}"),
                        )
                        db.add(org)
                        await db.flush()

                    integration = Integration(
                        org_id=org.id,
                        provider="github",
                        access_token=installation.get("access_tokens_url", ""),
                        config={"installation_id": installation.get("id"), "account": gh_account.get("login")},
                    )
                    db.add(integration)
                    await db.flush()

                    old = await db.execute(
                        select(Integration).where(
                            Integration.org_id == org.id,
                            Integration.provider == "github",
                            Integration.id != integration.id,
                            Integration.is_active == True,
                        )
                    )
                    for o in old.scalars().all():
                        o.is_active = False

                    for repo_data in repos:
                        existing = await db.execute(
                            select(Repository).where(Repository.github_repo_id == repo_data["id"])
                        )
                        if not existing.scalar_one_or_none():
                            repo = Repository(
                                org_id=org.id,
                                github_repo_id=repo_data["id"],
                                name=repo_data["name"],
                                full_name=repo_data["full_name"],
                                git_provider="github",
                                is_active=True,
                            )
                            db.add(repo)

            elif action == "deleted":
                result = await db.execute(
                    select(Integration).where(
                        Integration.provider == "github",
                        Integration.config['installation_id'].as_string() == str(installation.get("id")),
                    )
                )
                integration = result.scalar_one_or_none()
                if integration:
                    integration.is_active = False

            result_status = f"installation.{action}"

        elif event == "installation_repositories":
            action = payload.get("action")
            repos_added = payload.get("repositories_added", [])
            repos_removed = payload.get("repositories_removed", [])

            for repo_data in repos_added:
                existing = await db.execute(
                    select(Repository).where(Repository.github_repo_id == repo_data["id"])
                )
                if not existing.scalar_one_or_none():
                    integration_result = await db.execute(
                        select(Integration).where(
                            Integration.provider == "github",
                            Integration.config['installation_id'].as_string() == str(payload.get("installation", {}).get("id")),
                        )
                    )
                    integration = integration_result.scalar_one_or_none()
                    if integration:
                        repo = Repository(
                            org_id=integration.org_id,
                            github_repo_id=repo_data["id"],
                            name=repo_data["name"],
                            full_name=repo_data["full_name"],
                            git_provider="github",
                            is_active=True,
                        )
                        db.add(repo)

            for repo_data in repos_removed:
                result = await db.execute(
                    select(Repository).where(Repository.github_repo_id == repo_data["id"])
                )
                repo = result.scalar_one_or_none()
                if repo:
                    repo.is_active = False

            result_status = f"installation_repositories.{action}"

        elif event == "pull_request":
            action = payload.get("action")
            if action not in ["opened", "synchronize", "reopened"]:
                result_status = f"ignored_{action}"
            else:
                pr_data = payload.get("pull_request", {})
                gh_repo = payload.get("repository", {})
                gh_repo_id = gh_repo.get("id")

                repo = (await db.execute(
                    select(Repository).where(Repository.github_repo_id == gh_repo_id)
                )).scalars().first()

                if not repo or not repo.is_active:
                    webhook_event.error = "Repository not found or inactive"
                else:
                    diff_url = pr_data.get("diff_url")
                    pr_number = pr_data.get("number")
                    diff_data = None

                    if diff_url:
                        integration = (await db.execute(
                            select(Integration).where(
                                Integration.org_id == repo.org_id,
                                Integration.provider == "github",
                                Integration.is_active == True,
                                Integration.config['installation_id'].isnot(None),
                            ).order_by(Integration.created_at.desc())
                        )).scalars().first()
                        if integration:
                            install_id = None
                            if integration.config:
                                install_id = integration.config.get("installation_id")
                            if install_id:
                                try:
                                    token = await get_installation_access_token(int(install_id))
                                    if token:
                                        async with httpx.AsyncClient() as client:
                                            resp = await client.get(
                                                diff_url,
                                                headers={
                                                    "Authorization": f"Bearer {token}",
                                                    "Accept": "application/vnd.github.v3.diff",
                                                },
                                                follow_redirects=True,
                                            )
                                            if resp.status_code == 200:
                                                diff_data = resp.text
                                            else:
                                                webhook_event.error = f"diff_fetch_status_{resp.status_code}"
                                    else:
                                        webhook_event.error = "token_was_none"
                                except Exception as exc:
                                    webhook_event.error = f"token_exc: {str(exc)[:200]}"
                                    logger.warning("diff_fetch_failed: %s", exc)

                        if not diff_data:
                            oauth = (await db.execute(
                                select(Integration).where(
                                    Integration.org_id == repo.org_id,
                                    Integration.provider == "github",
                                    Integration.access_token.isnot(None),
                                    ~Integration.access_token.like("https://%"),
                                ).order_by(Integration.created_at.desc())
                            )).scalars().first()
                            if oauth and oauth.access_token:
                                try:
                                    async with httpx.AsyncClient() as client:
                                        resp = await client.get(
                                            diff_url,
                                            headers={
                                                "Authorization": f"Bearer {oauth.access_token}",
                                                "Accept": "application/vnd.github.v3.diff",
                                            },
                                            follow_redirects=True,
                                        )
                                        if resp.status_code == 200:
                                            diff_data = resp.text
                                except Exception:
                                    pass

                    pr = (await db.execute(
                        select(PullRequest).where(
                            PullRequest.repo_id == repo.id,
                            PullRequest.pr_number == pr_number,
                        )
                    )).scalar_one_or_none()

                    if pr:
                        pr.commit_sha = pr_data.get("head", {}).get("sha", pr.commit_sha)
                        pr.diff_data = diff_data or pr.diff_data
                        pr.status = "open"
                    else:
                        pr = PullRequest(
                            repo_id=repo.id,
                            pr_number=pr_number,
                            title=pr_data.get("title"),
                            branch=pr_data.get("head", {}).get("ref", ""),
                            base_branch=pr_data.get("base", {}).get("ref", ""),
                            commit_sha=pr_data.get("head", {}).get("sha", ""),
                            author=pr_data.get("user", {}).get("login"),
                            diff_data=diff_data or "",
                        )
                        db.add(pr)

                    await db.flush()
                    webhook_event.processed = True

                    if diff_data:
                        try:
                            await analyze_pr(pr.id)
                        except Exception as exc:
                            logger.exception("inline_analyze_failed: %s", exc)

                    result_status = f"queued_pr_{pr_number}"

        webhook_event.processed = True
    except Exception as exc:
        webhook_event.error = str(exc)[:500]
        logger.exception("webhook_processing_error: event=%s error=%s", event, exc)
    finally:
        await db.commit()

    return {"status": result_status, "event": event}


@router.post("/gitlab")
async def gitlab_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    body = await verify_gitlab_webhook(request)
    payload = await request.json()
    event = request.headers.get("x-gitlab-event", "")

    webhook_event = WebhookEvent(
        provider="gitlab",
        event_type=event,
        payload=payload,
    )
    db.add(webhook_event)
    await db.commit()

    if event == "Merge Request Hook":
        mr = payload.get("object_attributes", {})
        action = mr.get("action")
        if action not in ["open", "update", "reopen"]:
            return {"status": "ignored", "action": action}

        project = payload.get("project", {})

        repo_result = await db.execute(
            select(Repository).where(Repository.gitlab_repo_id == project.get("id"))
        )
        repo = repo_result.scalar_one_or_none()
        if not repo:
            webhook_event.processed = True
            webhook_event.error = "Repository not found"
            await db.commit()
            return {"status": "ignored", "reason": "repo_not_found"}

        diff_data = None
        integration_result = await db.execute(
            select(Integration).where(
                Integration.org_id == repo.org_id,
                Integration.provider == "gitlab",
                Integration.is_active == True,
            )
        )
        integration = integration_result.scalar_one_or_none()
        if integration and integration.access_token:
            try:
                project_path = project.get("path_with_namespace", "")
                mr_iid = mr.get("iid")
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        f"https://gitlab.com/api/v4/projects/{project_path.replace('/', '%2F')}/merge_requests/{mr_iid}/diffs",
                        headers={"PRIVATE-TOKEN": integration.access_token},
                    )
                    if resp.status_code == 200:
                        diff_data = str(resp.json())
            except Exception:
                pass

        pr = PullRequest(
            repo_id=repo.id,
            pr_number=mr.get("iid", 0),
            title=mr.get("title"),
            branch=mr.get("source_branch", ""),
            base_branch=mr.get("target_branch", ""),
            commit_sha=mr.get("last_commit", {}).get("id", ""),
            author=payload.get("user", {}).get("username"),
            diff_data=diff_data or "",
        )
        db.add(pr)
        await db.commit()
        await db.refresh(pr)

        if diff_data:
            asyncio.ensure_future(analyze_pr(pr.id))

        webhook_event.processed = True
        await db.commit()
        return {"status": "queued", "pr_id": pr.id}

    return {"status": "received", "event": event}


@router.post("/stripe")
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    event = await verify_stripe_webhook(request)
    event_type = event["type"]
    data = event["data"]["object"]

    webhook_event = WebhookEvent(
        provider="stripe",
        event_type=event_type,
        payload=event,
    )
    db.add(webhook_event)
    await db.flush()

    from app.services.billing import (
        handle_checkout_completed,
        handle_invoice_paid,
        handle_invoice_payment_failed,
        handle_subscription_deleted,
        handle_subscription_updated,
    )

    try:
        if event_type == "checkout.session.completed":
            await handle_checkout_completed(data, db)

        elif event_type == "checkout.session.async_payment_succeeded":
            await handle_checkout_completed(data, db)

        elif event_type == "invoice.paid":
            await handle_invoice_paid(data, db)

        elif event_type == "invoice.payment_failed":
            await handle_invoice_payment_failed(data, db)

        elif event_type == "customer.subscription.deleted":
            await handle_subscription_deleted(data, db)

        elif event_type == "customer.subscription.updated":
            await handle_subscription_updated(data, db)

        elif event_type == "customer.subscription.trial_will_end":
            sub_result = await db.execute(
                select(Subscription).where(
                    Subscription.stripe_subscription_id == data.get("id")
                )
            )
            sub = sub_result.scalar_one_or_none()
            if sub:
                from app.models import NotificationEvent
                notif = NotificationEvent(
                    org_id=sub.org_id,
                    channel="in_app",
                    event_type="trial_ending",
                    title="Trial Ending",
                    message="Trial period ending soon — add payment method to continue",
                )
                db.add(notif)

        elif event_type == "invoice.payment_action_required":
            subscription_id = data.get("subscription")
            if subscription_id:
                sub_result = await db.execute(
                    select(Subscription).where(
                        Subscription.stripe_subscription_id == subscription_id
                    )
                )
                sub = sub_result.scalar_one_or_none()
                if sub:
                    sub.status = SubscriptionStatus.PAST_DUE
                    from app.models import NotificationEvent
                    notif = NotificationEvent(
                        org_id=sub.org_id,
                        channel="in_app",
                        event_type="payment_action_required",
                        title="Payment Action Required",
                        message="Additional payment action required — please check your payment method",
                    )
                    db.add(notif)

        webhook_event.processed = True
        webhook_event.processed_at = datetime.now(timezone.utc)
    except Exception as exc:
        webhook_event.processed = False
        webhook_event.error = str(exc)[:500]

    await db.commit()
    return {"status": "processed", "event": event_type}


from datetime import datetime, timezone
