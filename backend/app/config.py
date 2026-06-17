from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "SecureReview AI"
    APP_URL: str = "http://localhost:3000"
    FRONTEND_URL: str = "http://localhost:5173"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    DATABASE_URL: str = "postgresql+asyncpg://securereview:securereview_dev@localhost:5432/securereview"
    REDIS_URL: str = "redis://localhost:6379/0"

    JWT_SECRET: str = "super-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24
    JWT_REFRESH_EXPIRATION_DAYS: int = 7

    ENCRYPTION_KEY: Optional[str] = None

    GROQ_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    LLM_PROVIDER: str = "anthropic"
    LLM_MODEL: str = "claude-3-5-sonnet-20241022"

    GITHUB_CLIENT_ID: Optional[str] = None
    GITHUB_CLIENT_SECRET: Optional[str] = None
    GITHUB_WEBHOOK_SECRET: Optional[str] = None
    GITHUB_APP_ID: Optional[str] = None
    GITHUB_APP_PRIVATE_KEY: Optional[str] = None
    GITHUB_INSTALLATION_URL: Optional[str] = None

    GITLAB_CLIENT_ID: Optional[str] = None
    GITLAB_CLIENT_SECRET: Optional[str] = None
    GITLAB_WEBHOOK_SECRET: Optional[str] = None

    SLACK_BOT_TOKEN: Optional[str] = None
    SLACK_SIGNING_SECRET: Optional[str] = None
    DISCORD_BOT_TOKEN: Optional[str] = None

    STRIPE_SECRET_KEY: Optional[str] = None
    STRIPE_WEBHOOK_SECRET: Optional[str] = None
    STRIPE_PUBLISHABLE_KEY: Optional[str] = None
    STRIPE_PRICE_STARTER: Optional[str] = None
    STRIPE_PRICE_PRO: Optional[str] = None
    STRIPE_PRICE_ENTERPRISE: Optional[str] = None
    STRIPE_PRICE_ENTERPRISE_SEAT: Optional[str] = None
    STRIPE_SUCCESS_URL: str = "http://localhost:3000"
    STRIPE_CANCEL_URL: str = "http://localhost:3000"

    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"
    MAX_FILE_SIZE_MB: int = 10
    RATE_LIMIT_PER_MINUTE: int = 60

    DATA_RETENTION_DAYS: int = 7
    FINDING_RETENTION_DAYS: int = 365

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
