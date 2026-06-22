import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, Integer, Boolean, Float, DateTime, ForeignKey, Enum, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base
import enum


def utcnow():
    return datetime.now(timezone.utc)


def generate_uuid():
    return str(uuid.uuid4())


# Enums
class UserRole(str, enum.Enum):
    ADMIN = "admin"
    SECURITY = "security"
    DEVELOPER = "dev"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    FIXED = "fixed"
    DISMISSED = "dismissed"


class PRStatus(str, enum.Enum):
    OPEN = "open"
    CLOSED = "closed"
    MERGED = "merged"


class SubscriptionPlan(str, enum.Enum):
    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class BillingCycle(str, enum.Enum):
    MONTHLY = "monthly"
    ANNUAL = "annual"


class SubscriptionStatus(str, enum.Enum):
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    EXPIRED = "expired"


class InvoiceStatus(str, enum.Enum):
    PAID = "paid"
    OPEN = "open"
    VOID = "void"
    UNCOLLECTIBLE = "uncollectible"


# Models
class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    plan = Column(Enum(SubscriptionPlan), default=SubscriptionPlan.FREE)
    stripe_customer_id = Column(String(255), nullable=True)
    settings = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    users = relationship("User", back_populates="organization")
    repositories = relationship("Repository", back_populates="organization")
    policies = relationship("Policy", back_populates="organization")
    audit_logs = relationship("AuditLog", back_populates="organization")
    subscriptions = relationship("Subscription", back_populates="organization")
    invoices = relationship("Invoice", back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=True)
    role = Column(Enum(UserRole), default=UserRole.DEVELOPER)
    github_id = Column(String(255), nullable=True)
    gitlab_id = Column(String(255), nullable=True)
    name = Column(String(255), nullable=True)
    avatar_url = Column(String(512), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    organization = relationship("Organization", back_populates="users")
    pull_requests = relationship("PullRequest", back_populates="author_user")
    policy_violations_created = relationship("Policy", back_populates="created_by_user")
    audit_logs = relationship("AuditLog", back_populates="user")


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    github_repo_id = Column(Integer, nullable=True)
    gitlab_repo_id = Column(Integer, nullable=True)
    name = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    git_provider = Column(String(50), default="github")
    is_active = Column(Boolean, default=True)
    webhook_secret = Column(String(255), nullable=True)
    default_branch = Column(String(255), default="main")
    settings = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    organization = relationship("Organization", back_populates="repositories")
    pull_requests = relationship("PullRequest", back_populates="repository")


class PullRequest(Base):
    __tablename__ = "pull_requests"

    id = Column(String, primary_key=True, default=generate_uuid)
    repo_id = Column(String, ForeignKey("repositories.id"), nullable=False)
    pr_number = Column(Integer, nullable=False)
    title = Column(String(512), nullable=True)
    branch = Column(String(255), nullable=False)
    base_branch = Column(String(255), nullable=False)
    commit_sha = Column(String(255), nullable=False)
    author = Column(String(255), nullable=True)
    author_id = Column(String, ForeignKey("users.id"), nullable=True)
    status = Column(Enum(PRStatus), default=PRStatus.OPEN)
    diff_data = Column(Text, nullable=True)
    ai_code_percentage = Column(Float, default=0.0)
    health_score = Column(Integer, default=100)
    total_findings = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    meta_data = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    repository = relationship("Repository", back_populates="pull_requests")
    author_user = relationship("User", back_populates="pull_requests")
    findings = relationship("Finding", back_populates="pull_request", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=generate_uuid)
    pr_id = Column(String, ForeignKey("pull_requests.id"), nullable=False)
    repo_id = Column(String, ForeignKey("repositories.id"), nullable=True)
    file_path = Column(String(512), nullable=False)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    severity = Column(Enum(FindingSeverity), nullable=False)
    category = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    code_snippet = Column(Text, nullable=True)
    suggested_fix = Column(Text, nullable=True)
    is_ai_generated = Column(Boolean, default=False)
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN)
    dismissed_by = Column(String, ForeignKey("users.id"), nullable=True)
    dismissed_reason = Column(Text, nullable=True)
    meta_data = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    pull_request = relationship("PullRequest", back_populates="findings")


class Policy(Base):
    __tablename__ = "policies"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    natural_language_rule = Column(Text, nullable=False)
    compiled_rule = Column(JSON, nullable=True)
    target_file_patterns = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    severity = Column(Enum(FindingSeverity), default=FindingSeverity.HIGH)
    version = Column(Integer, default=1)
    created_by = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    organization = relationship("Organization", back_populates="policies")
    created_by_user = relationship("User", back_populates="policy_violations_created")


class PolicyViolation(Base):
    __tablename__ = "policy_violations"

    id = Column(String, primary_key=True, default=generate_uuid)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    policy_id = Column(String, ForeignKey("policies.id"), nullable=False)
    matched_text = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String(255), nullable=False)
    entity_type = Column(String(255), nullable=False)
    entity_id = Column(String(255), nullable=True)
    meta_data = Column(JSON, default=dict)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    organization = relationship("Organization", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    plan = Column(Enum(SubscriptionPlan), default=SubscriptionPlan.FREE)
    seat_count = Column(Integer, default=5)
    billing_cycle = Column(Enum(BillingCycle), default=BillingCycle.MONTHLY)
    status = Column(Enum(SubscriptionStatus), default=SubscriptionStatus.ACTIVE)
    stripe_subscription_id = Column(String(255), nullable=True)
    stripe_price_id = Column(String(255), nullable=True)
    cancel_at_period_end = Column(Boolean, default=False)
    trial_end = Column(DateTime(timezone=True), nullable=True)
    current_period_start = Column(DateTime(timezone=True), nullable=True)
    current_period_end = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    organization = relationship("Organization", back_populates="subscriptions")
    invoices = relationship("Invoice", back_populates="subscription")


class Invoice(Base):
    __tablename__ = "invoices"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    sub_id = Column(String, ForeignKey("subscriptions.id"), nullable=True)
    stripe_invoice_id = Column(String(255), nullable=True)
    amount = Column(Float, nullable=False)
    currency = Column(String(3), default="usd")
    status = Column(Enum(InvoiceStatus), default=InvoiceStatus.OPEN)
    paid_at = Column(DateTime(timezone=True), nullable=True)
    period_start = Column(DateTime(timezone=True), nullable=True)
    period_end = Column(DateTime(timezone=True), nullable=True)
    invoice_pdf = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    organization = relationship("Organization")
    subscription = relationship("Subscription", back_populates="invoices")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    token = Column(String(255), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class NotificationSetting(Base):
    __tablename__ = "notification_settings"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    channel = Column(String(50), nullable=False)
    enabled = Column(Boolean, default=True)
    config = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class WebhookEvent(Base):
    __tablename__ = "webhook_events"

    id = Column(String, primary_key=True, default=generate_uuid)
    provider = Column(String(50), nullable=False)
    event_type = Column(String(100), nullable=False)
    payload = Column(JSON, nullable=False)
    processed = Column(Boolean, default=False)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    processed_at = Column(DateTime(timezone=True), nullable=True)


class Integration(Base):
    __tablename__ = "integrations"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    provider = Column(String(50), nullable=False)
    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    token_expires_at = Column(DateTime(timezone=True), nullable=True)
    config = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class NotificationEvent(Base):
    __tablename__ = "notification_events"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    channel = Column(String(50), nullable=False)
    event_type = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=True)
    link = Column(String(512), nullable=True)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    read_at = Column(DateTime(timezone=True), nullable=True)
