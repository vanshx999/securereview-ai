from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Any
from datetime import datetime
from app.models import UserRole, FindingSeverity, FindingStatus, PRStatus, SubscriptionPlan, BillingCycle, SubscriptionStatus, InvoiceStatus


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: Optional[str] = None
    role: UserRole = UserRole.DEVELOPER


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    name: Optional[str]
    role: UserRole
    org_id: str
    avatar_url: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 86400
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class OrganizationCreate(BaseModel):
    name: str
    slug: str


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    plan: SubscriptionPlan
    created_at: datetime

    class Config:
        from_attributes = True


class RepositoryResponse(BaseModel):
    id: str
    org_id: str
    name: str
    full_name: str
    git_provider: str
    is_active: bool
    default_branch: str
    created_at: datetime

    class Config:
        from_attributes = True


class PullRequestResponse(BaseModel):
    id: str
    repo_id: str
    pr_number: int
    title: Optional[str]
    branch: str
    base_branch: str
    commit_sha: str
    author: Optional[str]
    status: PRStatus
    ai_code_percentage: float
    health_score: int
    total_findings: int
    critical_findings: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: str
    pr_id: str
    file_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    severity: FindingSeverity
    category: str
    title: str
    description: Optional[str]
    code_snippet: Optional[str]
    suggested_fix: Optional[str]
    is_ai_generated: bool
    status: FindingStatus
    dismissed_by: Optional[str]
    dismissed_reason: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    status: FindingStatus
    dismissed_reason: Optional[str] = None


class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    natural_language_rule: str
    target_file_patterns: list[str] = []
    severity: FindingSeverity = FindingSeverity.HIGH


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    natural_language_rule: Optional[str] = None
    target_file_patterns: Optional[list[str]] = None
    is_active: Optional[bool] = None
    severity: Optional[FindingSeverity] = None


class PolicyResponse(BaseModel):
    id: str
    org_id: str
    name: str
    description: Optional[str]
    natural_language_rule: str
    compiled_rule: Optional[Any]
    target_file_patterns: list
    is_active: bool
    severity: FindingSeverity
    version: int
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AuditLogResponse(BaseModel):
    id: str
    org_id: str
    user_id: Optional[str]
    action: str
    entity_type: str
    entity_id: Optional[str]
    metadata: Optional[Any]
    ip_address: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class SubscriptionResponse(BaseModel):
    id: str
    org_id: str
    plan: SubscriptionPlan
    seat_count: int
    billing_cycle: BillingCycle
    status: SubscriptionStatus
    current_period_end: Optional[datetime]

    class Config:
        from_attributes = True


class InvoiceResponse(BaseModel):
    id: str
    amount: float
    currency: str
    status: InvoiceStatus
    date: str
    pdf_url: Optional[str] = None
    period_start: Optional[str] = None
    period_end: Optional[str] = None

    class Config:
        from_attributes = True


class UsageResponse(BaseModel):
    monthly_prs: int
    monthly_pr_limit: int
    active_repos: int
    repo_limit: int
    active_seats: int
    seat_limit: int
    daily_analyses_today: int
    daily_analysis_limit: int


class BillingResponse(BaseModel):
    plan: str
    plan_name: str
    plan_price: int
    plan_features: list[str]
    status: str
    billing_cycle: str
    seat_count: int
    current_period_end: Optional[str] = None
    cancel_at_period_end: bool = False
    usage: UsageResponse
    invoices: list[InvoiceResponse] = []


class UpgradeRequest(BaseModel):
    plan: SubscriptionPlan
    success_url: Optional[str] = None
    cancel_url: Optional[str] = None


class UpgradeResponse(BaseModel):
    checkout_url: str
    session_id: str


class DashboardStats(BaseModel):
    total_repos: int
    total_prs_analyzed: int
    total_findings: int
    open_findings: int
    critical_findings: int
    avg_health_score: float
    avg_ai_code_percentage: float
    mean_time_to_resolution_hours: float
    vulnerability_trends: list
    top_vulnerabilities: list
    ai_code_trends: list


class ComplianceReportRequest(BaseModel):
    format: str = "pdf"
    date_from: Optional[str] = None
    date_to: Optional[str] = None


class NotificationSettingUpdate(BaseModel):
    channel: str
    enabled: bool = True
    config: dict = {}


class IntegrationConfig(BaseModel):
    provider: str
    access_token: Optional[str] = None
    config: dict = {}
