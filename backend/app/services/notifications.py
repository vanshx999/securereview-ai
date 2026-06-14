import httpx
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import NotificationSetting, Finding, FindingSeverity


async def send_slack_notification(webhook_url: str, message: dict) -> bool:
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(webhook_url, json=message)
            return resp.status_code == 200
    except Exception:
        return False


async def send_discord_notification(webhook_url: str, message: dict) -> bool:
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(webhook_url, json=message)
            return resp.status_code == 204
    except Exception:
        return False


async def send_email_notification(to: str, subject: str, body: str) -> bool:
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body, "html")
        msg["Subject"] = subject
        msg["To"] = to
        msg["From"] = "notifications@securereview.ai"
        return True
    except Exception:
        return False


async def notify_critical_finding(
    db: AsyncSession,
    org_id: str,
    finding: Finding,
    repo_name: str,
    pr_number: int,
):
    result = await db.execute(
        select(NotificationSetting).where(
            NotificationSetting.org_id == org_id,
            NotificationSetting.enabled == True,
        )
    )
    settings = result.scalars().all()

    for setting in settings:
        channel = setting.channel
        config = setting.config

        if channel == "slack" and config.get("webhook_url"):
            await send_slack_notification(config["webhook_url"], {
                "text": f"🔴 *Critical Finding: {finding.title}*\n"
                        f"Repository: {repo_name}\n"
                        f"PR: #{pr_number}\n"
                        f"File: {finding.file_path}:{finding.line_start}\n"
                        f"Description: {finding.description}",
            })

        elif channel == "discord" and config.get("webhook_url"):
            await send_discord_notification(config["webhook_url"], {
                "content": f"🔴 **Critical Finding: {finding.title}**\n"
                           f"Repository: {repo_name}\n"
                           f"PR: #{pr_number}\n"
                           f"File: {finding.file_path}:{finding.line_start}\n"
                           f"Description: {finding.description}",
            })

        elif channel == "email" and config.get("email"):
            await send_email_notification(
                config["email"],
                f"[SecureReview] Critical: {finding.title} in {repo_name}#{pr_number}",
                f"<h2>Critical Security Finding</h2><p>{finding.description}</p>",
            )


async def send_daily_digest(db: AsyncSession, org_id: str):
    from app.models import PullRequest, Finding
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import func

    yesterday = datetime.now(timezone.utc) - timedelta(days=1)

    result = await db.execute(
        select(PullRequest).where(
            PullRequest.repo_id.in_(
                select(Repository.id).where(Repository.org_id == org_id)
            ),
            PullRequest.created_at >= yesterday,
        )
    )
    prs = result.scalars().all()

    total_findings = 0
    critical_count = 0
    for pr in prs:
        f_result = await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.pr_id == pr.id,
            )
        )
        total_findings += f_result.scalar() or 0
        c_result = await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.pr_id == pr.id,
                Finding.severity == FindingSeverity.CRITICAL,
            )
        )
        critical_count += c_result.scalar() or 0

    notif_result = await db.execute(
        select(NotificationSetting).where(
            NotificationSetting.org_id == org_id,
            NotificationSetting.enabled == True,
        )
    )
    settings = notif_result.scalars().all()

    digest_text = (
        f"📋 *SecureReview Daily Digest*\n"
        f"PRs analyzed: {len(prs)}\n"
        f"Total findings: {total_findings}\n"
        f"Critical: {critical_count}\n"
    )

    for setting in settings:
        if setting.channel == "slack" and setting.config.get("webhook_url"):
            await send_slack_notification(setting.config["webhook_url"], {"text": digest_text})
