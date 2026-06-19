import hmac
import hashlib
import time
from typing import Optional, Union
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.config import settings
from app.models import Repository, PullRequest, Finding, Integration
import httpx


async def get_installation_access_token(installation_id: int) -> Optional[str]:
    if not settings.GITHUB_APP_ID or not settings.GITHUB_APP_PRIVATE_KEY:
        return None
    import base64
    raw = settings.GITHUB_APP_PRIVATE_KEY.strip()
    if not raw.startswith("-----"):
        try:
            raw = base64.b64decode(raw).decode("utf-8")
        except Exception:
            pass
    raw = raw.replace("\\n", "\n").replace("\\r", "\r").strip()
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        key_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
        private_key = serialization.load_pem_private_key(
            key_bytes, password=None, backend=default_backend()
        )
        clean_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        from jose import jwt
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + 600,
            "iss": str(settings.GITHUB_APP_ID),
        }
        jose_token = jwt.encode(payload, clean_pem, algorithm="RS256")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"https://api.github.com/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {jose_token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            if resp.status_code == 201:
                data = resp.json()
                return data.get("token")
            else:
                body = resp.text[:300]
                raise Exception(f"github_status_{resp.status_code}: {body}")
    except Exception as exc:
        import logging
        msg = str(exc)[:500]
        logging.getLogger(__name__).warning("token_failed: %s", msg)
        raise Exception(f"token_error: {msg}") from exc

SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
SEVERITY_LABEL = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


async def get_github_client_for_org(org_id: str, db: AsyncSession):
    result = await db.execute(
        select(Integration).where(
            Integration.org_id == org_id,
            Integration.provider == "github",
            Integration.is_active == True,
        )
    )
    integration = result.scalar_one_or_none()
    if not integration or not integration.access_token:
        return None
    from github import Github
    return Github(integration.access_token)


async def verify_github_webhook(payload_body: bytes, signature_header: str) -> bool:
    if not settings.GITHUB_WEBHOOK_SECRET:
        return False
    expected_sig = "sha256=" + hmac.new(
        settings.GITHUB_WEBHOOK_SECRET.encode(),
        payload_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected_sig, signature_header)


async def post_pr_review_comment(
    db: AsyncSession,
    repo_id: str,
    pr_number: int,
    findings: list,
    org_id: str,
):
    g = await get_github_client_for_org(org_id, db)
    if not g:
        return

    result = await db.execute(select(Repository).where(Repository.id == repo_id))
    repo = result.scalar_one_or_none()
    if not repo or not repo.github_repo_id:
        return

    try:
        gh_repo = g.get_repo(repo.full_name)
        pr = gh_repo.get_pull(pr_number)
    except Exception:
        return

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", getattr(f, 'severity', None))
        if isinstance(sev, str) and sev in severity_counts:
            severity_counts[sev] += 1
        elif hasattr(sev, 'value') and sev.value in severity_counts:
            severity_counts[sev.value] += 1

    body = _build_summary_comment(findings, severity_counts, repo.full_name, pr_number)
    try:
        pr.create_issue_comment(body)
    except Exception:
        pass

    try:
        for f in findings:
            if isinstance(f, dict):
                file_path = f.get("file_path", "")
                line = f.get("line_number") or f.get("line_start")
                sev = f.get("severity", "MEDIUM")
                title = f.get("title", "Security finding")
                desc = f.get("description", "")
            else:
                file_path = f.file_path
                line = f.line_start
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                title = f.title
                desc = f.description or ""

            if file_path and line and sev in ("CRITICAL", "HIGH"):
                emoji = SEVERITY_EMOJI.get(sev, "⚪")
                comment_body = f"{emoji} **[{sev}] {title}**\n\n{desc}\n\n"
                if isinstance(f, dict) and f.get("suggested_fix"):
                    comment_body += f"**Suggested fix:**\n```\n{f['suggested_fix']}\n```\n"
                elif hasattr(f, 'suggested_fix') and f.suggested_fix:
                    comment_body += f"**Suggested fix:**\n```\n{f.suggested_fix}\n```\n"

                try:
                    pr.create_review_comment(
                        body=comment_body,
                        commit_id=pr.head.sha,
                        path=file_path,
                        line=int(line),
                    )
                except Exception:
                    pass
    except Exception:
        pass

    await _update_status_check(gh_repo, pr_number, severity_counts)


async def update_pr_status_check(
    db: AsyncSession,
    repo_id: str,
    pr_number: int,
    org_id: str,
    state: str = "success",
    description: str = "",
) -> bool:
    g = await get_github_client_for_org(org_id, db)
    if not g:
        return False

    result = await db.execute(select(Repository).where(Repository.id == repo_id))
    repo = result.scalar_one_or_none()
    if not repo or not repo.github_repo_id:
        return False

    try:
        gh_repo = g.get_repo(repo.full_name)
        pr = gh_repo.get_pull(pr_number)
        pr.create_commit_status(
            state=state,
            description=description or "SecureReview AI security check",
            context="SecureReview AI / security-review",
        )
        return True
    except Exception:
        return False


async def _update_status_check(gh_repo, pr_number: int, severity_counts: dict):
    try:
        pr = gh_repo.get_pull(pr_number)
        total_critical = severity_counts.get("CRITICAL", 0)
        total_high = severity_counts.get("HIGH", 0)
        total = sum(severity_counts.values())

        if total_critical > 0 or total_high > 0:
            state = "failure"
            desc = f"{total_critical} critical, {total_high} high severity issues found"
        elif total > 0:
            state = "neutral"
            desc = f"{total} issue(s) found, none critical or high"
        else:
            state = "success"
            desc = "No security issues found"

        pr.create_commit_status(
            state=state,
            description=desc,
            context="SecureReview AI / security-review",
        )
    except Exception:
        pass


def _build_summary_comment(findings: list, severity_counts: dict, repo_name: str, pr_number: int) -> str:
    total = len(findings)
    c = severity_counts.get("CRITICAL", 0)
    h = severity_counts.get("HIGH", 0)
    m = severity_counts.get("MEDIUM", 0)
    l = severity_counts.get("LOW", 0)

    lines = [
        "## 🔒 SecureReview AI — Code Review Results",
        "",
        f"**Repository:** {repo_name}",
        f"**Pull Request:** #{pr_number}",
        "",
        "### Summary",
        "",
        f"| Severity | Count |",
        f"| -------- | ----- |",
    ]
    if c: lines.append(f"| 🔴 **Critical** | **{c}** |")
    else: lines.append(f"| 🔴 Critical | 0 |")
    if h: lines.append(f"| 🟠 **High** | **{h}** |")
    else: lines.append(f"| 🟠 High | 0 |")
    if m: lines.append(f"| 🟡 Medium | {m} |")
    else: lines.append(f"| 🟡 Medium | 0 |")
    if l: lines.append(f"| 🟢 Low | {l} |")
    else: lines.append(f"| 🟢 Low | 0 |")

    lines.append("")
    lines.append(f"**Total findings: {total}**")
    lines.append("")

    if c > 0 or h > 0:
        lines.append("> ⚠️ **Action required:** Critical or high severity issues found. Review and fix before merging.")
    else:
        lines.append("> ✅ No critical or high severity issues found.")

    lines.append("")

    if total > 0:
        lines.append("### Top Findings")
        lines.append("")
        shown = 0
        for f in findings:
            if shown >= 5:
                lines.append(f"\n*...and {total - shown} more findings*")
                break
            if isinstance(f, dict):
                sev = f.get("severity", "LOW")
                title = f.get("title", "Finding")
                fp = f.get("file_path", "")
                ln = f.get("line_number") or f.get("line_start") or ""
            else:
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                title = f.title if hasattr(f, 'title') else "Finding"
                fp = f.file_path if hasattr(f, 'file_path') else ""
                ln = f.line_start if hasattr(f, 'line_start') else ""

            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            loc = f"`{fp}:{ln}`" if fp else ""
            lines.append(f"{emoji} **[{sev}]** {title} {loc}")
            shown += 1

    lines.append("")
    lines.append("---")
    lines.append("*Powered by SecureReview AI — The security layer for AI-generated code*")

    return "\n".join(lines)


async def get_github_pr_diff(repo_full_name: str, pr_number: int, access_token: str) -> Optional[str]:
    import httpx
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github.v3.diff",
    }
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}",
                headers=headers,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                return resp.text
    except Exception:
        pass
    return None


async def parse_github_webhook(payload: dict, event: str) -> Optional[dict]:
    if event == "pull_request" and payload.get("action") in ["opened", "synchronize", "reopened"]:
        pr = payload.get("pull_request", {})
        repo = payload.get("repository", {})
        return {
            "action": payload["action"],
            "repo_full_name": repo.get("full_name"),
            "repo_name": repo.get("name"),
            "repo_id": repo.get("id"),
            "pr_number": pr.get("number"),
            "pr_title": pr.get("title"),
            "pr_body": pr.get("body"),
            "branch": pr.get("head", {}).get("ref"),
            "base_branch": pr.get("base", {}).get("ref"),
            "commit_sha": pr.get("head", {}).get("sha"),
            "author": pr.get("user", {}).get("login"),
            "author_id": pr.get("user", {}).get("id"),
            "diff_url": pr.get("diff_url"),
            "html_url": pr.get("html_url"),
        }
    return None
