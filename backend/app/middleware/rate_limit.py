import time
from fastapi import Request, HTTPException, Depends
from app.config import settings

REDIS_RATE_LIMIT_PREFIX = "ratelimit:"

async def check_rate_limit(
    request: Request,
    max_requests: int = 100,
    window_seconds: int = 60,
) -> None:
    import redis.asyncio as redis

    client_ip = request.client.host if request.client else "unknown"
    route = request.url.path
    key = f"{REDIS_RATE_LIMIT_PREFIX}{client_ip}:{route}"

    try:
        r = redis.from_url(settings.REDIS_URL, decoding_responses=True, socket_connect_timeout=2)
        current = await r.get(key)

        if current is None:
            await r.setex(key, window_seconds, 1)
        else:
            current_count = int(current)
            if current_count >= max_requests:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. {max_requests} requests per {window_seconds}s",
                )
            await r.incr(key)

        await r.aclose()
    except HTTPException:
        raise
    except Exception:
        pass


def rate_limit(max_requests: int = 100, window_seconds: int = 60):
    async def limiter(request: Request):
        await check_rate_limit(request, max_requests, window_seconds)
    return limiter


async def check_user_rate_limit(
    user_id: str,
    max_requests: int = 1000,
    window_seconds: int = 3600,
) -> None:
    import redis.asyncio as redis

    key = f"{REDIS_RATE_LIMIT_PREFIX}user:{user_id}"

    try:
        r = redis.from_url(settings.REDIS_URL, decoding_responses=True, socket_connect_timeout=2)
        current = await r.get(key)

        if current is None:
            await r.setex(key, window_seconds, 1)
        else:
            current_count = int(current)
            if current_count >= max_requests:
                raise HTTPException(
                    status_code=429,
                    detail=f"User rate limit exceeded. {max_requests} per {window_seconds // 3600}h",
                )
            await r.incr(key)

        await r.aclose()
    except HTTPException:
        raise
    except Exception:
        pass


async def check_org_analysis_rate_limit(org_id: str) -> None:
    import redis.asyncio as redis
    from datetime import datetime, timezone

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = f"{REDIS_RATE_LIMIT_PREFIX}org:{org_id}:analysis:{today}"

    try:
        r = redis.from_url(settings.REDIS_URL, decoding_responses=True, socket_connect_timeout=2)
        current = await r.get(key)

        if current is None:
            await r.setex(key, window_seconds, 1)
        else:
            current_count = int(current)
            from app.models import SubscriptionPlan, Organization, Subscription
            from sqlalchemy import select
            from app.database import async_session_factory

            async with async_session_factory() as db:
                sub_result = await db.execute(
                    select(Subscription).where(Subscription.org_id == org_id).order_by(Subscription.created_at.desc()).limit(1)
                )
                sub = sub_result.scalar_one_or_none()
                plan = sub.plan if sub else SubscriptionPlan.FREE

            daily_limits = {
                SubscriptionPlan.FREE: 10,
                SubscriptionPlan.STARTER: 50,
                SubscriptionPlan.PRO: 100,
                SubscriptionPlan.ENTERPRISE: 999999,
            }
            limit = daily_limits.get(plan, 10)

            if current_count >= limit:
                raise HTTPException(
                    status_code=429,
                    detail=f"Daily analysis limit reached ({limit}/day). Upgrade your plan for more.",
                )
            await r.incr(key)

        await r.aclose()
    except HTTPException:
        raise
    except Exception:
        pass
