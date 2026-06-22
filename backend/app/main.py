from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
from app.config import settings
from app.database import init_db

from app.routers import (
    auth, orgs, repositories, pr_review, findings, policies,
    dashboard, webhooks, notifications, admin,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description="The security layer for AI-generated code",
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def add_cors_headers(request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT"
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"],
)


app.include_router(auth.router)
app.include_router(orgs.router)
app.include_router(repositories.router)
app.include_router(repositories.repositories_router)
app.include_router(pr_review.router)
app.include_router(findings.router)
app.include_router(policies.router)
app.include_router(dashboard.router)
app.include_router(webhooks.router)
app.include_router(notifications.router)
app.include_router(admin.router)


@app.get("/api/health")
async def health_check():
    import time
    return {
        "status": "healthy",
        "version": "1.0.0",
        "service": settings.APP_NAME,
        "timestamp": time.time(),
        "environment": settings.ENVIRONMENT,
    }


@app.get("/api/health/db")
async def db_health_check():
    from app.database import async_session_factory
    from sqlalchemy import text
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
            return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": str(e)}
