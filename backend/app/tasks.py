import asyncio
from typing import Optional
from app.celery_app import celery_app
from app.services.analysis import (
    run_full_analysis_pipeline, parse_unified_diff,
)
from app.services.secret_detection import scan_diff_for_patterns
from app.services.policy_engine import check_policies_for_parsed_diff


def sync_run_analysis_pipeline(
    diff_data: str,
    repo_name: str = "",
    pr_number: int = 0,
    pr_title: str = "",
    org_id: str = None,
    db_session_factory=None,
) -> dict:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(
            _run_full_pipeline(diff_data, repo_name, pr_number, pr_title, org_id, db_session_factory)
        )
    finally:
        loop.close()


async def _run_full_pipeline(
    diff_data: str,
    repo_name: str,
    pr_number: int,
    pr_title: str,
    org_id: Optional[str],
    db_session_factory,
) -> dict:
    all_findings = []

    # Step 1: Secret detection (fast, no LLM)
    secret_findings = await scan_diff_for_patterns(diff_data)
    all_findings.extend(secret_findings)

    # Step 2: LLM-based analysis
    pipeline_result = await run_full_analysis_pipeline(
        diff_data=diff_data,
        repo_name=repo_name,
        pr_number=pr_number,
        pr_title=pr_title,
    )
    all_findings.extend(pipeline_result.get("findings", []))
    ai_info = pipeline_result.get("ai_generated", {})
    pipeline_summary = pipeline_result.get("summary", {})

    # Step 3: Policy enforcement
    if org_id and db_session_factory:
        try:
            async with db_session_factory() as db:
                parsed = parse_unified_diff(diff_data)
                policy_findings = await check_policies_for_parsed_diff(db, org_id, parsed)
                all_findings.extend(policy_findings)
        except Exception:
            pass

    # Step 4: Deduplicate
    all_findings = _deduplicate(all_findings)

    # Step 5: Sort by severity
    all_findings = _sort_by_severity(all_findings)

    # Step 6: Limit to top 20
    all_findings = all_findings[:20]

    # Step 7: Calculate overall status
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


@celery_app.task(queue="analysis", bind=True, max_retries=3, acks_late=True, soft_time_limit=600)
def analyze_pr_task(self, pr_id: str):
    from app.database import async_session_factory
    from app.models import PullRequest, Repository, Finding, FindingStatus
    from sqlalchemy import select

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _run():
        async with async_session_factory() as db:
            result = await db.execute(select(PullRequest).where(PullRequest.id == pr_id))
            pr = result.scalar_one_or_none()
            if not pr or not pr.diff_data:
                return

            repo = await db.execute(select(Repository).where(Repository.id == pr.repo_id))
            repo = repo.scalar_one_or_none()
            if not repo:
                return

            pipeline_result = await _run_full_pipeline(
                diff_data=pr.diff_data,
                repo_name=repo.full_name,
                pr_number=pr.pr_number,
                pr_title=pr.title or "",
                org_id=repo.org_id,
                db_session_factory=async_session_factory,
            )

            for finding_data in pipeline_result["findings"]:
                finding = Finding(
                    pr_id=pr.id,
                    repo_id=pr.repo_id,
                    file_path=str(finding_data.get("file_path", "unknown")),
                    line_start=finding_data.get("line_number") or finding_data.get("line_start"),
                    line_end=finding_data.get("line_end") or finding_data.get("line_number") or finding_data.get("line_start"),
                    severity=finding_data.get("severity", "MEDIUM"),
                    category=finding_data.get("category", "unknown"),
                    title=str(finding_data.get("title", "Security finding"))[:255],
                    description=finding_data.get("description"),
                    code_snippet=finding_data.get("code_snippet"),
                    suggested_fix=finding_data.get("suggested_fix"),
                    is_ai_generated=finding_data.get("is_ai_generated", False),
                    metadata={
                        "cwe_id": finding_data.get("cwe_id", ""),
                        "policy_id": finding_data.get("policy_id"),
                        "source": finding_data.get("source", "auto"),
                    },
                )
                db.add(finding)
                await db.flush()

                if finding_data.get("policy_id"):
                    from app.models import PolicyViolation
                    violation = PolicyViolation(
                        finding_id=finding.id,
                        policy_id=finding_data["policy_id"],
                        matched_text=finding_data.get("code_snippet", "")[:500],
                    )
                    db.add(violation)

                if finding.severity.value == "CRITICAL":
                    from app.services.notifications import notify_critical_finding
                    await notify_critical_finding(db, repo.org_id, finding, repo.full_name, pr.pr_number)

            summary = pipeline_result["summary"]
            pr.ai_code_percentage = pipeline_result.get("ai_generated", {}).get("ai_percentage", 0.0)
            pr.total_findings = summary.get("total_findings", len(pipeline_result["findings"]))
            pr.critical_findings = summary.get("severity_counts", {}).get("CRITICAL", 0)
            pr.health_score = max(0, 100 - (pr.critical_findings * 20 + (pr.total_findings - pr.critical_findings) * 2))
            await db.commit()

            from app.services.github_integration import post_pr_review_comment
            findings_result = await db.execute(
                select(Finding).where(Finding.pr_id == pr.id, Finding.status == FindingStatus.OPEN)
            )
            db_findings = findings_result.scalars().all()
            await post_pr_review_comment(db, pr.repo_id, pr.pr_number, db_findings, repo.org_id)

    try:
        loop.run_until_complete(_run())
    except Exception as exc:
        import traceback
        traceback.print_exc()
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)
    finally:
        loop.close()
