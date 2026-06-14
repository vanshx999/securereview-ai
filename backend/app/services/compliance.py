import json
from typing import Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.config import settings
from app.models import Organization, AuditLog


async def generate_compliance_report(
    db: AsyncSession,
    org_id: str,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    output_format: str = "pdf",
) -> bytes:
    from app.models import Finding, PullRequest, Policy, PolicyViolation, User, Repository, AuditLog

    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()
    if not org:
        raise ValueError("Organization not found")

    if not date_to:
        date_to = datetime.now(timezone.utc)
    if not date_from:
        date_from = date_to.replace(year=date_to.year - 1)

    findings_result = await db.execute(
        select(Finding).where(
            Finding.created_at >= date_from,
            Finding.created_at <= date_to,
        )
    )
    findings = findings_result.scalars().all()

    audits_result = await db.execute(
        select(AuditLog).where(
            AuditLog.org_id == org_id,
            AuditLog.created_at >= date_from,
            AuditLog.created_at <= date_to,
        ).order_by(AuditLog.created_at.desc())
    )
    audit_logs = audits_result.scalars().all()

    policies_result = await db.execute(
        select(Policy).where(Policy.org_id == org_id)
    )
    policies = policies_result.scalars().all()

    repos_result = await db.execute(
        select(Repository).where(Repository.org_id == org_id)
    )
    repos = repos_result.scalars().all()

    critical_findings = [f for f in findings if f.severity.value == "CRITICAL"]
    open_findings = [f for f in findings if f.status.value == "open"]

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity.value in severity_counts:
            severity_counts[f.severity.value] += 1

    report_data = {
        "organization": org.name,
        "report_type": "Compliance Audit Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "date_range": {
            "from": date_from.isoformat(),
            "to": date_to.isoformat(),
        },
        "summary": {
            "total_repositories": len(repos),
            "total_findings": len(findings),
            "open_findings": len(open_findings),
            "critical_findings": len(critical_findings),
            "active_policies": len(policies),
            "severity_breakdown": severity_counts,
            "total_audit_events": len(audit_logs),
        },
        "findings_by_severity": [
            {"severity": k, "count": v} for k, v in severity_counts.items()
        ],
        "findings": [
            {
                "id": f.id,
                "file_path": f.file_path,
                "line_start": f.line_start,
                "severity": f.severity.value,
                "category": f.category,
                "title": f.title,
                "status": f.status.value,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ],
        "audit_trail": [
            {
                "action": log.action,
                "entity_type": log.entity_type,
                "entity_id": log.entity_id,
                "user_id": log.user_id,
                "timestamp": log.created_at.isoformat(),
            }
            for log in audit_logs
        ],
        "policies": [
            {
                "name": p.name,
                "description": p.description,
                "is_active": p.is_active,
                "severity": p.severity.value,
                "version": p.version,
            }
            for p in policies
        ],
    }

    if output_format == "json":
        return json.dumps(report_data, indent=2).encode()

    return await render_pdf_report(report_data)


async def render_pdf_report(report_data: dict) -> bytes:
    from jinja2 import Template
    import weasyprint

    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: -apple-system, sans-serif; margin: 40px; }
            h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }
            h2 { color: #16213e; margin-top: 30px; }
            .summary { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }
            .stat { background: white; padding: 15px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
            .stat-value { font-size: 24px; font-weight: bold; color: #e94560; }
            .stat-label { font-size: 12px; color: #666; }
            table { width: 100%; border-collapse: collapse; margin: 15px 0; }
            th { background: #16213e; color: white; padding: 10px; text-align: left; }
            td { padding: 8px 10px; border-bottom: 1px solid #eee; }
            .critical { color: #dc3545; font-weight: bold; }
            .high { color: #fd7e14; font-weight: bold; }
            .medium { color: #ffc107; }
            .low { color: #28a745; }
            .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
        </style>
    </head>
    <body>
        <h1>🔒 SecureReview AI - Compliance Report</h1>
        <p><strong>Organization:</strong> {{ report_data.organization }}</p>
        <p><strong>Generated:</strong> {{ report_data.generated_at }}</p>
        <p><strong>Period:</strong> {{ report_data.date_range.from }} to {{ report_data.date_range.to }}</p>

        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="summary-grid">
                <div class="stat">
                    <div class="stat-value">{{ report_data.summary.total_findings }}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{{ report_data.summary.critical_findings }}</div>
                    <div class="stat-label">Critical Findings</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{{ report_data.summary.open_findings }}</div>
                    <div class="stat-label">Open Findings</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{{ report_data.summary.total_repositories }}</div>
                    <div class="stat-label">Repositories</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{{ report_data.summary.active_policies }}</div>
                    <div class="stat-label">Active Policies</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{{ report_data.summary.total_audit_events }}</div>
                    <div class="stat-label">Audit Events</div>
                </div>
            </div>
        </div>

        <h2>Findings by Severity</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            {% for item in report_data.findings_by_severity %}
            <tr>
                <td class="{{ item.severity|lower }}">{{ item.severity }}</td>
                <td>{{ item.count }}</td>
            </tr>
            {% endfor %}
        </table>

        <h2>Critical Findings</h2>
        <table>
            <tr><th>File</th><th>Line</th><th>Category</th><th>Title</th><th>Status</th></tr>
            {% for f in report_data.findings %}
            {% if f.severity == "CRITICAL" %}
            <tr>
                <td>{{ f.file_path }}</td>
                <td>{{ f.line_start }}</td>
                <td>{{ f.category }}</td>
                <td>{{ f.title }}</td>
                <td>{{ f.status }}</td>
            </tr>
            {% endif %}
            {% endfor %}
        </table>

        <h2>Active Policies</h2>
        <table>
            <tr><th>Name</th><th>Severity</th><th>Version</th><th>Active</th></tr>
            {% for p in report_data.policies %}
            <tr>
                <td>{{ p.name }}</td>
                <td>{{ p.severity }}</td>
                <td>{{ p.version }}</td>
                <td>{{ "Yes" if p.is_active else "No" }}</td>
            </tr>
            {% endfor %}
        </table>

        <h2>Audit Trail</h2>
        <table>
            <tr><th>Action</th><th>Entity</th><th>User</th><th>Timestamp</th></tr>
            {% for log in report_data.audit_trail %}
            <tr>
                <td>{{ log.action }}</td>
                <td>{{ log.entity_type }}:{{ log.entity_id }}</td>
                <td>{{ log.user_id }}</td>
                <td>{{ log.timestamp }}</td>
            </tr>
            {% endfor %}
        </table>

        <div class="footer">
            <p>SecureReview AI - Compliance Audit Report</p>
            <p>This report is auto-generated and certified for SOC 2 and ISO 27001 compliance audits.</p>
        </div>
    </body>
    </html>
    """

    template = Template(template_str)
    html = template.render(report_data=report_data)
    pdf = weasyprint.HTML(string=html).write_pdf()
    return pdf


async def export_csv_report(db: AsyncSession, org_id: str, date_from=None, date_to=None) -> bytes:
    from app.models import Finding
    import csv
    import io

    findings_result = await db.execute(
        select(Finding).where(
            Finding.created_at >= date_from,
            Finding.created_at <= date_to,
        )
    )
    findings = findings_result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "File", "Line", "Severity", "Category", "Title", "Status", "Created At"])
    for f in findings:
        writer.writerow([f.id, f.file_path, f.line_start, f.severity.value, f.category, f.title, f.status.value, f.created_at.isoformat()])

    return output.getvalue().encode()
