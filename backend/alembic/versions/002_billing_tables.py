"""add invoice table and billing fields to subscriptions

Revision ID: 002
Revises: 001
Create Date: 2025-06-15
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

revision: str = '002'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('subscriptions', sa.Column('stripe_price_id', sa.String(255), nullable=True))
    op.add_column('subscriptions', sa.Column('cancel_at_period_end', sa.Boolean(), server_default='false'))
    op.add_column('subscriptions', sa.Column('trial_end', sa.DateTime(timezone=True), nullable=True))

    op.create_table('invoices',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('sub_id', sa.String(), nullable=True),
        sa.Column('stripe_invoice_id', sa.String(255), nullable=True),
        sa.Column('amount', sa.Float(), nullable=False),
        sa.Column('currency', sa.String(3), server_default='usd'),
        sa.Column('status', sa.String(20), server_default='open'),
        sa.Column('paid_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('period_start', sa.DateTime(timezone=True), nullable=True),
        sa.Column('period_end', sa.DateTime(timezone=True), nullable=True),
        sa.Column('invoice_pdf', sa.String(512), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['sub_id'], ['subscriptions.id']),
    )


def downgrade() -> None:
    op.drop_table('invoices')
    op.drop_column('subscriptions', 'trial_end')
    op.drop_column('subscriptions', 'cancel_at_period_end')
    op.drop_column('subscriptions', 'stripe_price_id')
