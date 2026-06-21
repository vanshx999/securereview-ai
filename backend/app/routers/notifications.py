from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.database import get_db
from app.models import User, NotificationSetting, NotificationEvent, Organization
from app.schemas import NotificationSettingUpdate
from app.middleware import get_current_user
from app.services.notifications import (
    send_slack_notification, send_discord_notification, send_email_notification,
)
from app.services.auth import create_audit_log
from datetime import datetime, timezone

router = APIRouter(prefix="/api/notifications", tags=["Notifications"])


@router.get("/")
async def list_notifications(
    unread_only: bool = False,
    limit: int = Query(default=50, le=100),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(NotificationEvent).where(
        NotificationEvent.org_id == current_user.org_id,
    )
    if unread_only:
        query = query.where(NotificationEvent.is_read == False)

    result = await db.execute(
        query.order_by(desc(NotificationEvent.created_at)).offset(offset).limit(limit)
    )
    notifs = result.scalars().all()

    return [
        {
            "id": n.id,
            "channel": n.channel,
            "event_type": n.event_type,
            "title": n.title,
            "message": n.message,
            "link": n.link,
            "is_read": n.is_read,
            "created_at": n.created_at.isoformat(),
        }
        for n in notifs
    ]


@router.post("/{notification_id}/read")
async def mark_as_read(
    notification_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(NotificationEvent).where(
            NotificationEvent.id == notification_id,
            NotificationEvent.org_id == current_user.org_id,
        )
    )
    notif = result.scalar_one_or_none()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")

    notif.is_read = True
    notif.read_at = datetime.now(timezone.utc)
    await db.commit()
    return {"message": "Marked as read"}


@router.get("/settings")
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(NotificationSetting).where(NotificationSetting.org_id == current_user.org_id)
    )
    settings = result.scalars().all()

    channel_map = {s.channel: s for s in settings}
    result_arr = []
    for ch in ["slack", "discord", "email"]:
        if ch in channel_map:
            s = channel_map[ch]
            result_arr.append({
                "id": s.id,
                "channel": s.channel,
                "enabled": s.enabled,
                "config": s.config,
            })
        else:
            result_arr.append({
                "id": "",
                "channel": ch,
                "enabled": False,
                "config": {},
            })

    return result_arr


@router.post("/settings")
async def update_settings(
    data: NotificationSettingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(NotificationSetting).where(
            NotificationSetting.org_id == current_user.org_id,
            NotificationSetting.channel == data.channel,
        )
    )
    setting = result.scalar_one_or_none()

    if setting:
        setting.enabled = data.enabled
        if data.config:
            setting.config = {**setting.config, **data.config}
    else:
        setting = NotificationSetting(
            org_id=current_user.org_id,
            channel=data.channel,
            enabled=data.enabled,
            config=data.config,
        )
        db.add(setting)

    await db.commit()
    return {"message": f"Notification settings updated for {data.channel}"}


@router.post("/test/{channel}")
async def send_test_by_path(
    channel: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await _send_notification_test(db, current_user, channel)


@router.post("/test")
async def send_test(
    channel: str = Query(..., pattern="^(slack|discord|email)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await _send_notification_test(db, current_user, channel)


async def _send_notification_test(
    db: AsyncSession,
    current_user: User,
    channel: str,
):
    result = await db.execute(
        select(NotificationSetting).where(
            NotificationSetting.org_id == current_user.org_id,
            NotificationSetting.channel == channel,
        )
    )
    setting = result.scalar_one_or_none()
    if not setting or not setting.config:
        raise HTTPException(status_code=400, detail=f"No {channel} configuration found")

    success = False
    if channel == "slack":
        success = await send_slack_notification(
            setting.config.get("webhook_url", ""),
            {"text": f"🔒 *SecureReview AI Test Notification*\nHello {current_user.name or current_user.email}! Your Slack integration is working."},
        )
    elif channel == "discord":
        success = await send_discord_notification(
            setting.config.get("webhook_url", ""),
            {"content": f"🔒 **SecureReview AI Test Notification**\nHello {current_user.name or current_user.email}! Your Discord integration is working."},
        )
    elif channel == "email":
        success = await send_email_notification(
            setting.config.get("email", current_user.email),
            "SecureReview AI - Test Notification",
            f"<h2>Test Notification</h2><p>Hello {current_user.name or current_user.email},</p><p>Your email notification settings are working correctly.</p>",
        )

    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to send {channel} notification")

    await create_audit_log(
        db, current_user.org_id, current_user.id,
        f"notification.test.{channel}", "notification", None,
    )

    return {"message": f"Test {channel} notification sent successfully"}
