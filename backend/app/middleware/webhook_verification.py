import hmac
import hashlib
from fastapi import Request, HTTPException, Depends
from app.config import settings


async def verify_github_webhook(request: Request) -> bytes:
    body = await request.body()
    signature_header = request.headers.get("x-hub-signature-256", "")
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing GitHub webhook signature")

    expected_sig = "sha256=" + hmac.new(
        settings.GITHUB_WEBHOOK_SECRET.encode() if settings.GITHUB_WEBHOOK_SECRET else b"",
        body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, signature_header):
        raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature")

    return body


async def verify_gitlab_webhook(request: Request) -> bytes:
    body = await request.body()
    token = request.headers.get("x-gitlab-token", "")
    if not token:
        raise HTTPException(status_code=401, detail="Missing GitLab webhook token")

    if not settings.GITLAB_WEBHOOK_SECRET or token != settings.GITLAB_WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="Invalid GitLab webhook token")

    return body


async def verify_stripe_webhook(request: Request) -> dict:
    import stripe
    body = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    if not sig_header:
        raise HTTPException(status_code=401, detail="Missing Stripe signature")

    try:
        event = stripe.Webhook.construct_event(
            body, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
        return event
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=401, detail="Invalid Stripe signature")
