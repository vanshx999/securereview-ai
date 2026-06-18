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
    await db.commit()

    if event == "ping":
        return {"status": "ok", "event": "ping"}

    if event == "installation":
        action = payload.get("action")
        installation = payload.get("installation", {})
        gh_account = payload.get("account", {}) or {}
        repos = payload.get("repositories", [])
        error_msg = None
        try:
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

                    await db.commit()

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
                    await db.commit()
        except Exception as exc:
            error_msg = str(exc)[:500]
            webhook_event.error = error_msg
            await db.commit()

        return {"status": "processed", "event": f"installation.{action}", "error": error_msg}

    if event == "installation_repositories":
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
                    await db.commit()

        for repo_data in repos_removed:
            result = await db.execute(
                select(Repository).where(Repository.github_repo_id == repo_data["id"])
            )
            repo = result.scalar_one_or_none()
            if repo:
                repo.is_active = False
                await db.commit()

        return {"status": "processed", "event": f"installation_repositories.{action}"}

    if event == "pull_request":
        action = payload.get("action")
        if action not in ["opened", "synchronize", "reopened"]:
            return {"status": "ignored", "action": action}

        pr_data = payload.get("pull_request", {})
        gh_repo = payload.get("repository", {})
        gh_repo_id = gh_repo.get("id")
        webhook_event.error = f"step: got repo_id={gh_repo_id}"
        await db.commit()

        result = await db.execute(
            select(Repository).where(Repository.github_repo_id == gh_repo_id)
        )
        repo = result.scalar_one_or_none()
        if not repo or not repo.is_active:
            webhook_event.processed = True
            webhook_event.error = f"Repository not found or inactive (repo_id={gh_repo_id})"
            await db.commit()
            return {"status": "ignored", "reason": "repo_not_found"}

        webhook_event.error = f"step: repo={repo.full_name} ok"
        await db.commit()

        diff_url = pr_data.get("diff_url")
        pr_number = pr_data.get("number")

        diff_data = None
        if diff_url:
            integration_result = await db.execute(
                select(Integration).where(
                    Integration.org_id == repo.org_id,
                    Integration.provider == "github",
                    Integration.is_active == True,
                )
            )
            integration = integration_result.scalar_one_or_none()
            if integration:
                install_id = integration.config.get("installation_id") if integration.config else None
                token = None
                if install_id:
                    token = await get_installation_access_token(int(install_id))
                if not token and integration.access_token:
                    token = integration.access_token
                if token:
                    try:
                        async with httpx.AsyncClient() as client:
                            resp = await client.get(
                                diff_url,
                                headers={"Authorization": f"Bearer {token}"},
                            )
                            if resp.status_code == 200:
                                diff_data = resp.text
                    except Exception:
                        pass

        webhook_event.error = f"step: diff fetched={bool(diff_data)}"
        await db.commit()

        pr_result = await db.execute(
            select(PullRequest).where(
                PullRequest.repo_id == repo.id,
                PullRequest.pr_number == pr_number,
            )
        )
        pr = pr_result.scalar_one_or_none()

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

        try:
            await db.commit()
            await db.refresh(pr)

            webhook_event.error = f"step: pr={pr.id} created"
            await db.commit()

            if diff_data:
                asyncio.ensure_future(analyze_pr(pr.id))

            webhook_event.processed = True
            webhook_event.error = "ok"
            await db.commit()
        except Exception as exc:
            webhook_event.error = f"final error: {str(exc)[:300]}"
            await db.commit()

        return {"status": "queued", "pr_id": pr.id, "pr_number": pr.pr_number}

    return {"status": "received", "event": event}


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
