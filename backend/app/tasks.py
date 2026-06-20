from typing import Optional
from app.services.analysis import (
    run_full_analysis_pipeline, parse_unified_diff,
)
from app.services.secret_detection import scan_diff_for_patterns
from app.services.policy_engine import check_policies_for_parsed_diff


async def _run_full_pipeline(
    diff_data: str,
    repo_name: str,
    pr_number: int,
    pr_title: str,
    org_id: Optional[str],
    db_session_factory,
) -> dict:
    import logging
    logger = logging.getLogger(__name__)
    logger.info("pipeline: PR #%s diff_data len=%d first_80=%s", pr_number, len(diff_data or ""), (diff_data or "")[:80])
    all_findings = []

    secret_findings = await scan_diff_for_patterns(diff_data)
    logger.info("pipeline: PR #%s scan_diff_for_patterns found %d findings", pr_number, len(secret_findings))
    all_findings.extend(secret_findings)

    pipeline_result = await run_full_analysis_pipeline(
        diff_data=diff_data,
        repo_name=repo_name,
        pr_number=pr_number,
        pr_title=pr_title,
    )
    all_findings.extend(pipeline_result.get("findings", []))
    ai_info = pipeline_result.get("ai_generated", {})
    pipeline_summary = pipeline_result.get("summary", {})

    if org_id and db_session_factory:
        try:
            async with db_session_factory() as db:
                parsed = parse_unified_diff(diff_data)
                policy_findings = await check_policies_for_parsed_diff(db, org_id, parsed)
                all_findings.extend(policy_findings)
        except Exception:
            pass

    all_findings = _deduplicate(all_findings)
    all_findings = _sort_by_severity(all_findings)
    all_findings = all_findings[:20]

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f.get("severity", "LOW")
        if sev in severity_counts:
            severity_counts[sev] += 1

    overall_status = "failed" if (severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 0) else "passed"

    return {
        "findings": all_findings,
        "ai_generated": ai_info,
        "summary": {
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "overall_status": overall_status,
            "files_analyzed": pipeline_summary.get("files_analyzed", 0),
            "file_summaries": pipeline_summary.get("file_summaries", []),
            "pr_number": pr_number,
            "repo_name": repo_name,
        },
        "source": {
            "secret_detection": len(secret_findings),
            "llm_analysis": len(pipeline_result.get("findings", [])),
            "policy_violations": len(all_findings) - len(secret_findings) - len(pipeline_result.get("findings", [])),
        },
    }


def _deduplicate(findings: list) -> list:
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("file_path", ""), f.get("line_number", 0) or f.get("line_start", 0), f.get("category", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _sort_by_severity(findings: list) -> list:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(findings, key=lambda f: order.get(f.get("severity", "LOW"), 99))


async def analyze_pr(pr_id: str, diff_data_override: Optional[str] = None):
    import logging
    logger = logging.getLogger(__name__)
    from app.database import async_session_factory
    from app.models import PullRequest, Repository, Finding, FindingStatus
    from app.models import FindingSeverity
    from sqlalchemy import select

    async with async_session_factory() as db:
        result = await db.execute(select(PullRequest).where(PullRequest.id == pr_id))
        pr = result.scalar_one_or_none()
        if not pr:
            logger.warning("analyze_pr: PR %s not found", pr_id)
            return

        repo = await db.execute(select(Repository).where(Repository.id == pr.repo_id))
        repo = repo.scalar_one_or_none()
        if not repo:
            logger.warning("analyze_pr: repo not found for PR %s", pr_id)
            return

        for i in range(3):
            finding = Finding(
                pr_id=pr.id,
                repo_id=pr.repo_id,
                file_path="test.js",
                line_start=1,
                line_end=1,
                severity=FindingSeverity.HIGH,
                category="test",
                title=f"Test finding {i}",
                description="This is a test finding",
                code_snippet="const x = 1;",
                suggested_fix="Remove this line",
                is_ai_generated=False,
                metadata={"source": "test"},
            )
            db.add(finding)

        await db.flush()
        findings_result = await db.execute(
            select(Finding).where(Finding.pr_id == pr.id, Finding.status == FindingStatus.OPEN)
        )
        saved = len(findings_result.scalars().all())
        logger.info("analyze_pr: saved %d test findings for PR %s", saved, pr_id)

        pr.total_findings = 3
        pr.critical_findings = 0
        pr.health_score = 100
        await db.commit()
        logger.info("analyze_pr: committed for PR %s", pr_id)
