"""initial schema

Revision ID: 001
Revises:
Create Date: 2025-01-01
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON

revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('organizations',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(255), nullable=False),
        sa.Column('plan', sa.String(50), server_default='free'),
        sa.Column('stripe_customer_id', sa.String(255), nullable=True),
        sa.Column('settings', JSON(), server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('slug'),
    )
    op.create_index('ix_organizations_slug', 'organizations', ['slug'])

    op.create_table('users',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=True),
        sa.Column('role', sa.String(20), server_default='dev'),
        sa.Column('github_id', sa.String(255), nullable=True),
        sa.Column('gitlab_id', sa.String(255), nullable=True),
        sa.Column('name', sa.String(255), nullable=True),
        sa.Column('avatar_url', sa.String(512), nullable=True),
        sa.Column('is_active', sa.Boolean(), server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.UniqueConstraint('email'),
    )
    op.create_index('ix_users_email', 'users', ['email'])

    op.create_table('repositories',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('github_repo_id', sa.Integer(), nullable=True),
        sa.Column('gitlab_repo_id', sa.Integer(), nullable=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255), nullable=False),
        sa.Column('git_provider', sa.String(50), server_default='github'),
        sa.Column('is_active', sa.Boolean(), server_default='true'),
        sa.Column('webhook_secret', sa.String(255), nullable=True),
        sa.Column('default_branch', sa.String(255), server_default='main'),
        sa.Column('settings', JSON(), server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
    )

    op.create_table('pull_requests',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('repo_id', sa.String(), nullable=False),
        sa.Column('pr_number', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(512), nullable=True),
        sa.Column('branch', sa.String(255), nullable=False),
        sa.Column('base_branch', sa.String(255), nullable=False),
        sa.Column('commit_sha', sa.String(255), nullable=False),
        sa.Column('author', sa.String(255), nullable=True),
        sa.Column('author_id', sa.String(), nullable=True),
        sa.Column('status', sa.String(20), server_default='open'),
        sa.Column('diff_data', sa.Text(), nullable=True),
        sa.Column('ai_code_percentage', sa.Float(), server_default='0'),
        sa.Column('health_score', sa.Integer(), server_default='100'),
        sa.Column('total_findings', sa.Integer(), server_default='0'),
        sa.Column('critical_findings', sa.Integer(), server_default='0'),
        sa.Column('metadata', JSON(), server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['repo_id'], ['repositories.id']),
        sa.ForeignKeyConstraint(['author_id'], ['users.id']),
    )

    op.create_table('findings',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('pr_id', sa.String(), nullable=False),
        sa.Column('repo_id', sa.String(), nullable=True),
        sa.Column('file_path', sa.String(512), nullable=False),
        sa.Column('line_start', sa.Integer(), nullable=True),
        sa.Column('line_end', sa.Integer(), nullable=True),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('category', sa.String(100), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('code_snippet', sa.Text(), nullable=True),
        sa.Column('suggested_fix', sa.Text(), nullable=True),
        sa.Column('is_ai_generated', sa.Boolean(), server_default='false'),
        sa.Column('status', sa.String(20), server_default='open'),
        sa.Column('dismissed_by', sa.String(), nullable=True),
        sa.Column('dismissed_reason', sa.Text(), nullable=True),
        sa.Column('metadata', JSON(), server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['pr_id'], ['pull_requests.id']),
        sa.ForeignKeyConstraint(['repo_id'], ['repositories.id']),
        sa.ForeignKeyConstraint(['dismissed_by'], ['users.id']),
    )

    op.create_table('policies',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('natural_language_rule', sa.Text(), nullable=False),
        sa.Column('compiled_rule', JSON(), nullable=True),
        sa.Column('target_file_patterns', JSON(), server_default='[]'),
        sa.Column('is_active', sa.Boolean(), server_default='true'),
        sa.Column('severity', sa.String(20), server_default='HIGH'),
        sa.Column('version', sa.Integer(), server_default='1'),
        sa.Column('created_by', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['created_by'], ['users.id']),
    )

    op.create_table('policy_violations',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('finding_id', sa.String(), nullable=False),
        sa.Column('policy_id', sa.String(), nullable=False),
        sa.Column('matched_text', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id']),
        sa.ForeignKeyConstraint(['policy_id'], ['policies.id']),
    )

    op.create_table('audit_logs',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('action', sa.String(255), nullable=False),
        sa.Column('entity_type', sa.String(255), nullable=False),
        sa.Column('entity_id', sa.String(255), nullable=True),
        sa.Column('metadata', JSON(), server_default='{}'),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(512), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )

    op.create_table('subscriptions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('plan', sa.String(50), server_default='free'),
        sa.Column('seat_count', sa.Integer(), server_default='5'),
        sa.Column('billing_cycle', sa.String(20), server_default='monthly'),
        sa.Column('status', sa.String(20), server_default='active'),
        sa.Column('stripe_subscription_id', sa.String(255), nullable=True),
        sa.Column('current_period_start', sa.DateTime(timezone=True), nullable=True),
        sa.Column('current_period_end', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
    )

    op.create_table('notification_settings',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('channel', sa.String(50), nullable=False),
        sa.Column('enabled', sa.Boolean(), server_default='true'),
        sa.Column('config', JSON(), server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
    )

    op.create_table('webhook_events',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('provider', sa.String(50), nullable=False),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('payload', JSON(), nullable=False),
        sa.Column('processed', sa.Boolean(), server_default='false'),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table('integrations',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('provider', sa.String(50), nullable=False),
        sa.Column('access_token', sa.Text(), nullable=True),
        sa.Column('refresh_token', sa.Text(), nullable=True),
        sa.Column('token_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('config', JSON(), server_default='{}'),
        sa.Column('is_active', sa.Boolean(), server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
    )

    op.create_table('notification_events',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('channel', sa.String(50), nullable=False),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('link', sa.String(512), nullable=True),
        sa.Column('is_read', sa.Boolean(), server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )


def downgrade() -> None:
    op.drop_table('notification_events')
    op.drop_table('integrations')
    op.drop_table('webhook_events')
    op.drop_table('notification_settings')
    op.drop_table('subscriptions')
    op.drop_table('audit_logs')
    op.drop_table('policy_violations')
    op.drop_table('policies')
    op.drop_table('findings')
    op.drop_table('pull_requests')
    op.drop_table('repositories')
    op.drop_table('users')
    op.drop_table('organizations')
