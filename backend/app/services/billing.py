import stripe
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from app.config import settings
from app.models import (
    Organization, Subscription, SubscriptionPlan, SubscriptionStatus,
    BillingCycle, Invoice, InvoiceStatus, NotificationEvent,
    User, PullRequest, Repository,
)


async def _notify_billing_event(
    db: AsyncSession,
    org_id: str,
    message: str,
    event_type: str = "billing_notification",
) -> None:
    try:
        event = NotificationEvent(
            org_id=org_id,
            channel="in_app",
            event_type=event_type,
            title="Billing Update",
            message=message,
        )
        db.add(event)
    except Exception:
        pass



stripe.api_key = settings.STRIPE_SECRET_KEY


PLAN_CONFIG = {
    SubscriptionPlan.FREE: {
        "name": "Free",
        "price": 0,
        "repo_limit": 1,
        "daily_analysis_limit": 10,
        "monthly_pr_limit": 10,
        "features": ["1 repository", "10 PRs/month", "Basic rules", "Email alerts"],
        "stripe_price_id": None,
    },
    SubscriptionPlan.STARTER: {
        "name": "Starter",
        "price": 29,
        "repo_limit": 5,
        "daily_analysis_limit": 50,
        "monthly_pr_limit": 100,
        "features": ["5 repositories", "100 PRs/month", "Custom policies", "Slack alerts"],
        "stripe_price_id": settings.STRIPE_PRICE_STARTER,
    },
    SubscriptionPlan.PRO: {
        "name": "Pro",
        "price": 99,
        "repo_limit": 20,
        "daily_analysis_limit": 200,
        "monthly_pr_limit": 1000,
        "features": ["20 repositories", "1,000 PRs/month", "Custom policies", "Slack alerts", "Priority support"],
        "stripe_price_id": settings.STRIPE_PRICE_PRO,
    },
    SubscriptionPlan.ENTERPRISE: {
        "name": "Enterprise",
        "price": 25,
        "repo_limit": 999999,
        "daily_analysis_limit": 999999,
        "monthly_pr_limit": 999999,
        "features": ["Unlimited repos", "Unlimited PRs", "SSO", "Compliance reports", "Dedicated support"],
        "stripe_price_id": settings.STRIPE_PRICE_ENTERPRISE,
        "per_seat": True,
        "min_seats": 20,
    },
}


async def get_plan_config(plan: SubscriptionPlan) -> dict:
    return PLAN_CONFIG.get(plan, PLAN_CONFIG[SubscriptionPlan.FREE])


async def get_or_create_customer(
    org: Organization,
    email: str,
    name: Optional[str] = None,
) -> str:
    if org.stripe_customer_id:
        try:
            customer = stripe.Customer.retrieve(org.stripe_customer_id)
            if customer.get("deleted"):
                org.stripe_customer_id = None
            else:
                return org.stripe_customer_id
        except stripe.error.StripeError:
            org.stripe_customer_id = None

    customer = stripe.Customer.create(
        email=email,
        name=name or org.name,
        metadata={
            "org_id": org.id,
            "org_name": org.name,
        },
    )
    return customer.id


async def create_checkout_session(
    org_id: str,
    plan: str,
    email: str,
    org_name: str,
    db: AsyncSession,
) -> dict:
    plan_enum = SubscriptionPlan(plan)

    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise ValueError("Organization not found")

    plan_config = await get_plan_config(plan_enum)
    price_id = plan_config["stripe_price_id"]
    if not price_id:
        raise ValueError(f"No Stripe price configured for plan: {plan}")

    customer_id = await get_or_create_customer(org, email, org_name)
    org.stripe_customer_id = customer_id
    await db.flush()

    line_items = [{"price": price_id, "quantity": 1}]

    session = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=line_items,
        metadata={
            "org_id": org_id,
            "plan": plan,
        },
        success_url=f"{settings.APP_URL}/admin?upgrade=success&session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{settings.APP_URL}/admin?upgrade=canceled",
        allow_promotion_codes=True,
        billing_address_collection="auto",
    )

    from app.services.auth import create_audit_log
    await create_audit_log(
        db, org_id, None, "billing.checkout_session_created",
        "checkout_session", session.id, {"plan": plan},
    )

    return {
        "checkout_url": session.url,
        "session_id": session.id,
    }


async def create_portal_session(org_id: str) -> str:
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org or not org.stripe_customer_id:
        raise ValueError("No Stripe customer found")

    session = stripe.billing_portal.Session.create(
        customer=org.stripe_customer_id,
        return_url=f"{settings.APP_URL}/admin/billing",
    )
    return session.url


async def handle_checkout_completed(session: dict, db: AsyncSession) -> None:
    metadata = session.get("metadata", {}) or {}
    org_id = metadata.get("org_id")
    plan_str = metadata.get("plan", "free")
    customer_id = session.get("customer")
    subscription_id = session.get("subscription")

    if not org_id:
        return

    plan_enum = SubscriptionPlan(plan_str)
    period_start = datetime.fromtimestamp(session.get("created", 0), tz=timezone.utc) if session.get("created") else None
    period_end = datetime.fromtimestamp(
        session.get("expires_at", 0) or session.get("created", 0) + 2592000,
        tz=timezone.utc,
    ) if session.get("created") else None

    existing_sub = await db.execute(
        select(Subscription).where(
            Subscription.org_id == org_id,
            Subscription.status.in_([SubscriptionStatus.ACTIVE, SubscriptionStatus.PAST_DUE]),
        ).order_by(desc(Subscription.created_at)).limit(1)
    )
    existing = existing_sub.scalar_one_or_none()

    if existing:
        existing.plan = plan_enum
        existing.status = SubscriptionStatus.ACTIVE
        existing.stripe_subscription_id = subscription_id
        existing.current_period_start = period_start
        existing.current_period_end = period_end
    else:
        sub = Subscription(
            org_id=org_id,
            plan=plan_enum,
            seat_count=1,
            billing_cycle=BillingCycle.MONTHLY,
            status=SubscriptionStatus.ACTIVE,
            stripe_subscription_id=subscription_id,
            current_period_start=period_start,
            current_period_end=period_end,
        )
        db.add(sub)

    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()
    if org:
        org.plan = plan_enum
        if customer_id:
            org.stripe_customer_id = customer_id

    await db.flush()
    await _notify_billing_event(db, org_id, f"Subscription activated: {plan_str}")


async def retreive_stripe_subscription(
    subscription_id: str,
) -> Optional[dict]:
    if not subscription_id:
        return None
    try:
        return stripe.Subscription.retrieve(subscription_id)
    except stripe.error.StripeError:
        return None


async def handle_invoice_paid(invoice: dict, db: AsyncSession) -> None:
    subscription_id = invoice.get("subscription")
    if not subscription_id:
        return

    sub_result = await db.execute(
        select(Subscription).where(Subscription.stripe_subscription_id == subscription_id)
    )
    sub = sub_result.scalar_one_or_none()
    if not sub:
        return

    sub.status = SubscriptionStatus.ACTIVE
    period_end = invoice.get("period_end")
    if period_end:
        sub.current_period_end = datetime.fromtimestamp(period_end, tz=timezone.utc)

    invoice_record = Invoice(
        org_id=sub.org_id,
        stripe_invoice_id=invoice.get("id"),
        amount=invoice.get("amount_paid", 0) / 100,
        currency=invoice.get("currency", "usd"),
        status=InvoiceStatus.PAID,
        paid_at=datetime.fromtimestamp(invoice.get("paid_at", 0), tz=timezone.utc) if invoice.get("paid_at") else None,
        period_start=datetime.fromtimestamp(invoice.get("period_start", 0), tz=timezone.utc) if invoice.get("period_start") else None,
        period_end=datetime.fromtimestamp(invoice.get("period_end", 0), tz=timezone.utc) if invoice.get("period_end") else None,
        invoice_pdf=invoice.get("invoice_pdf"),
    )
    db.add(invoice_record)
    await db.flush()


async def handle_invoice_payment_failed(invoice: dict, db: AsyncSession) -> None:
    subscription_id = invoice.get("subscription")
    if not subscription_id:
        return

    sub_result = await db.execute(
        select(Subscription).where(Subscription.stripe_subscription_id == subscription_id)
    )
    sub = sub_result.scalar_one_or_none()
    if not sub:
        return

    sub.status = SubscriptionStatus.PAST_DUE

    attempt_count = invoice.get("attempt_count", 1)
    next_attempt = invoice.get("next_payment_attempt")
    message = f"Payment failed (attempt {attempt_count})"
    if next_attempt:
        next_attempt_dt = datetime.fromtimestamp(next_attempt, tz=timezone.utc)
        message += f". Next attempt: {next_attempt_dt.isoformat()}"

    invoice_record = Invoice(
        org_id=sub.org_id,
        stripe_invoice_id=invoice.get("id"),
        amount=invoice.get("amount_due", 0) / 100,
        currency=invoice.get("currency", "usd"),
        status=InvoiceStatus.OPEN,
        invoice_pdf=invoice.get("invoice_pdf"),
    )
    db.add(invoice_record)
    await db.flush()

    await _notify_billing_event(db, sub.org_id, message, "payment_failed")
    await _send_payment_failed_notification(db, sub.org_id)


async def handle_subscription_deleted(subscription_data: dict, db: AsyncSession) -> None:
    subscription_id = subscription_data.get("id")
    if not subscription_id:
        return

    sub_result = await db.execute(
        select(Subscription).where(Subscription.stripe_subscription_id == subscription_id)
    )
    sub = sub_result.scalar_one_or_none()
    if not sub:
        return

    sub.status = SubscriptionStatus.CANCELED

    org_result = await db.execute(select(Organization).where(Organization.id == sub.org_id))
    org = org_result.scalar_one_or_none()
    if org:
        org.plan = SubscriptionPlan.FREE

    await db.flush()
    await _notify_billing_event(db, sub.org_id, "Subscription canceled — downgraded to Free")


async def handle_subscription_updated(subscription_data: dict, db: AsyncSession) -> None:
    subscription_id = subscription_data.get("id")
    if not subscription_id:
        return

    sub_result = await db.execute(
        select(Subscription).where(Subscription.stripe_subscription_id == subscription_id)
    )
    sub = sub_result.scalar_one_or_none()
    if not sub:
        return

    status = subscription_data.get("status")
    if status == "past_due":
        sub.status = SubscriptionStatus.PAST_DUE
    elif status == "canceled":
        sub.status = SubscriptionStatus.CANCELED
        org_result = await db.execute(select(Organization).where(Organization.id == sub.org_id))
        org = org_result.scalar_one_or_none()
        if org:
            org.plan = SubscriptionPlan.FREE
    elif status in ("active", "trialing"):
        sub.status = SubscriptionStatus.ACTIVE

    cancel_at_period_end = subscription_data.get("cancel_at_period_end", False)
    sub.cancel_at_period_end = cancel_at_period_end

    current_period_end = subscription_data.get("current_period_end")
    if current_period_end:
        sub.current_period_end = datetime.fromtimestamp(current_period_end, tz=timezone.utc)

    items = subscription_data.get("items", {}).get("data", [])
    if items:
        price_id = items[0].get("price", {}).get("id")
        if price_id:
            sub.stripe_price_id = price_id

    await db.flush()


async def get_billing_summary(
    org_id: str,
    db: AsyncSession,
) -> dict:
    sub_result = await db.execute(
        select(Subscription).where(Subscription.org_id == org_id).order_by(desc(Subscription.created_at)).limit(1)
    )
    sub = sub_result.scalar_one_or_none()

    prs_result = await db.execute(
        select(func.count()).select_from(PullRequest).where(
            PullRequest.repo_id.in_(
                select(Repository.id).where(Repository.org_id == org_id)
            ),
            PullRequest.created_at >= func.now() - func.make_interval(months=1),
        )
    )
    monthly_prs = prs_result.scalar() or 0

    users_result = await db.execute(
        select(func.count()).select_from(User).where(User.org_id == org_id)
    )
    seat_count = users_result.scalar() or 0

    repos_result = await db.execute(
        select(func.count()).select_from(Repository).where(
            Repository.org_id == org_id, Repository.is_active == True
        )
    )
    active_repos = repos_result.scalar() or 0

    daily_usage = await _get_daily_analysis_count(org_id)
    plan = sub.plan if sub else SubscriptionPlan.FREE
    plan_config = await get_plan_config(plan)

    invoices_result = await db.execute(
        select(Invoice).where(Invoice.org_id == org_id).order_by(desc(Invoice.created_at)).limit(12)
    )
    invoices = invoices_result.scalars().all()

    return {
        "plan": plan.value,
        "plan_name": plan_config["name"],
        "plan_price": plan_config["price"],
        "plan_features": plan_config["features"],
        "status": sub.status.value if sub else "no_subscription",
        "billing_cycle": sub.billing_cycle.value if sub else "monthly",
        "seat_count": seat_count,
        "current_period_end": sub.current_period_end.isoformat() if sub and sub.current_period_end else None,
        "cancel_at_period_end": sub.cancel_at_period_end if sub else False,
        "usage": {
            "monthly_prs": monthly_prs,
            "monthly_pr_limit": plan_config["monthly_pr_limit"],
            "active_repos": active_repos,
            "repo_limit": plan_config["repo_limit"],
            "active_seats": seat_count,
            "seat_limit": sub.seat_count if sub else 1,
            "daily_analyses_today": daily_usage,
            "daily_analysis_limit": plan_config["daily_analysis_limit"],
        },
        "invoices": [
            {
                "id": inv.id,
                "amount": inv.amount,
                "currency": inv.currency,
                "status": inv.status.value,
                "date": inv.paid_at.isoformat() if inv.paid_at else inv.created_at.isoformat(),
                "pdf_url": inv.invoice_pdf,
                "period_start": inv.period_start.isoformat() if inv.period_start else None,
                "period_end": inv.period_end.isoformat() if inv.period_end else None,
            }
            for inv in invoices
        ],
    }


async def cancel_subscription_at_period_end(
    org_id: str,
    subscription_id: str,
    db: AsyncSession,
) -> None:
    try:
        stripe.Subscription.update(
            subscription_id,
            cancel_at_period_end=True,
        )
    except stripe.error.StripeError as e:
        raise ValueError(f"Stripe cancellation failed: {str(e)}")

    sub_result = await db.execute(
        select(Subscription).where(
            Subscription.stripe_subscription_id == subscription_id,
            Subscription.org_id == org_id,
        )
    )
    sub = sub_result.scalar_one_or_none()
    if sub:
        sub.cancel_at_period_end = True
        await db.flush()

    await _notify_billing_event(db, org_id, "Subscription will cancel at period end", "subscription_canceling")


async def reactivate_subscription(
    org_id: str,
    subscription_id: str,
    db: AsyncSession,
) -> None:
    try:
        stripe.Subscription.update(
            subscription_id,
            cancel_at_period_end=False,
        )
    except stripe.error.StripeError as e:
        raise ValueError(f"Stripe reactivation failed: {str(e)}")

    sub_result = await db.execute(
        select(Subscription).where(
            Subscription.stripe_subscription_id == subscription_id,
            Subscription.org_id == org_id,
        )
    )
    sub = sub_result.scalar_one_or_none()
    if sub:
        sub.cancel_at_period_end = False
        sub.status = SubscriptionStatus.ACTIVE
        await db.flush()


async def update_subscription_plan(
    org_id: str,
    new_plan: str,
    subscription_id: str,
    db: AsyncSession,
) -> dict:
    plan_enum = SubscriptionPlan(new_plan)
    plan_config = await get_plan_config(plan_enum)
    price_id = plan_config["stripe_price_id"]

    if not price_id:
        raise ValueError(f"No Stripe price configured for plan: {new_plan}")

    try:
        subscription = stripe.Subscription.retrieve(subscription_id)
        current_item_id = subscription["items"]["data"][0]["id"]

        stripe.Subscription.modify(
            subscription_id,
            items=[{
                "id": current_item_id,
                "price": price_id,
            }],
            proration_behavior="create_prorations",
        )
    except stripe.error.StripeError as e:
        raise ValueError(f"Stripe plan change failed: {str(e)}")

    sub_result = await db.execute(
        select(Subscription).where(
            Subscription.stripe_subscription_id == subscription_id,
            Subscription.org_id == org_id,
        )
    )
    sub = sub_result.scalar_one_or_none()
    if sub:
        sub.plan = plan_enum
        sub.stripe_price_id = price_id
        await db.flush()

    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()
    if org:
        org.plan = plan_enum

    await db.flush()
    return {"plan": new_plan, "status": "updated"}


async def check_analysis_limit(org_id: str) -> tuple[bool, int, int]:
    daily_usage = await _get_daily_analysis_count(org_id)

    sub_result = await db.execute(
        select(Subscription).where(Subscription.org_id == org_id).order_by(desc(Subscription.created_at)).limit(1)
    )
    sub = sub_result.scalar_one_or_none()
    plan = sub.plan if sub else SubscriptionPlan.FREE
    plan_config = await get_plan_config(plan)
    limit = plan_config["daily_analysis_limit"]

    return daily_usage < limit, daily_usage, limit


async def _get_daily_analysis_count(org_id: str) -> int:
    import redis.asyncio as redis_client
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = f"billing:org:{org_id}:analysis:{today}"

    try:
        r = redis_client.from_url(settings.REDIS_URL, decoding_responses=True)
        count = await r.get(key)
        await r.aclose()
        return int(count) if count else 0
    except Exception:
        return 0


async def increment_daily_analysis_count(org_id: str) -> None:
    import redis.asyncio as redis_client
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = f"billing:org:{org_id}:analysis:{today}"

    try:
        r = redis_client.from_url(settings.REDIS_URL, decoding_responses=True)
        current = await r.get(key)
        if current is None:
            await r.setex(key, 86400, 1)
        else:
            await r.incr(key)
        await r.aclose()
    except Exception:
        pass


async def _send_payment_failed_notification(db: AsyncSession, org_id: str) -> None:
    try:
        from app.models import NotificationEvent
        event = NotificationEvent(
            org_id=org_id,
            channel="email",
            event_type="payment_failed",
            title="Payment Failed",
            message="Your recent payment failed. Please update your payment method to avoid service interruption.",
            link=f"{settings.APP_URL}/admin/billing",
        )
        db.add(event)
        await db.flush()
    except Exception:
        pass


async def sync_stripe_subscription(sub: Subscription) -> None:
    if not sub.stripe_subscription_id:
        return
    try:
        stripe_sub = stripe.Subscription.retrieve(sub.stripe_subscription_id)
        status = stripe_sub.get("status")
        if status == "active":
            sub.status = SubscriptionStatus.ACTIVE
        elif status in ("past_due", "incomplete"):
            sub.status = SubscriptionStatus.PAST_DUE
        elif status in ("canceled", "unpaid"):
            sub.status = SubscriptionStatus.CANCELED

        period_end = stripe_sub.get("current_period_end")
        if period_end:
            sub.current_period_end = datetime.fromtimestamp(period_end, tz=timezone.utc)

        sub.cancel_at_period_end = stripe_sub.get("cancel_at_period_end", False)
    except stripe.error.StripeError:
        pass
