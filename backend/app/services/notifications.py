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
    import logging
    logger = logging.getLogger(__name__)
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(webhook_url, json=message)
            logger.info("send_discord_notification: status=%d url=%s", resp.status_code, webhook_url[:50])
            return resp.status_code == 204
    except Exception as e:
        logger.exception("send_discord_notification failed: %s", str(e))
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


def _format_findings_summary(findings: list[Finding], repo_name: str, pr_number: int, pr_title: str) -> str:
    total = len(findings)
    critical = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    high = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    medium = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    low = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    summary = (
        f"🔒 *SecureReview Analysis Complete*\n"
        f"Repo: {repo_name}  |  PR: #{pr_number}  |  {pr_title}\n"
        f"\n"
        f"*Findings Summary:*\n"
        f"  🔴 Critical: {critical}\n"
        f"  🟠 High: {high}\n"
        f"  🟡 Medium: {medium}\n"
        f"  🟢 Low: {low}\n"
        f"  ─────────────\n"
        f"  Total: {total}\n"
    )
    return summary


async def notify_analysis_complete(
    db: AsyncSession,
    org_id: str,
    findings: list[Finding],
    repo_name: str,
    pr_number: int,
    pr_title: str,
    dashboard_url: str = "",
):
    import logging
    logger = logging.getLogger(__name__)
    logger.info("notify_analysis_complete: org_id=%s findings=%d", org_id, len(findings))

    result = await db.execute(
        select(NotificationSetting).where(
            NotificationSetting.org_id == org_id,
            NotificationSetting.enabled == True,
        )
    )
    settings = result.scalars().all()
    logger.info("notify_analysis_complete: found %d enabled notification settings", len(settings))
    if not settings:
        logger.info("notify_analysis_complete: no enabled settings found for org %s", org_id)
        return

    for s in settings:
        logger.info("notify_analysis_complete: channel=%s config=%s", s.channel, s.config)

    slack_text = _format_findings_summary(findings, repo_name, pr_number, pr_title)
    if dashboard_url:
        slack_text += f"\n<{dashboard_url}|View on Dashboard>"

    for setting in settings:
        channel = setting.channel
        config = setting.config

        if channel == "slack" and config.get("webhook_url"):
            blocks = [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": slack_text},
                }
            ]
            if dashboard_url:
                blocks.append({
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "View on Dashboard"},
                            "url": dashboard_url,
                        }
                    ],
                })
            await send_slack_notification(config["webhook_url"], {
                "text": slack_text,
                "blocks": blocks,
            })

        elif channel == "discord" and config.get("webhook_url"):
            content = _format_findings_summary(findings, repo_name, pr_number, pr_title)
            content = content.replace("*", "**").replace("<", "[").replace(">", "](")
            await send_discord_notification(config["webhook_url"], {
                "content": content,
            })


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
