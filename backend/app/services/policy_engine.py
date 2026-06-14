import json
import re
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.config import settings
from app.models import Policy, PolicyViolation, Finding, FindingSeverity

POLICY_COMPILATION_PROMPT = """You are a policy compiler. Convert the following natural language security policy into a structured JSON rule.

Natural Language Rule: "{rule}"

Output ONLY a valid JSON object with these exact fields:
{{
  "type": "regex_pattern" | "function_call" | "import_check" | "data_flow" | "file_pattern",
  "pattern": "regex pattern to match against added diff lines",
  "file_patterns": ["*.py", "src/**/*.ts"] or [] for all files,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "description": "Brief description of what this rule checks",
  "condition": "When this rule triggers (natural language)",
  "message_template": "Template for violation message, use {file}, {line} placeholders"
}}

Examples:
1. Rule: "Flag any function handling PII that calls logger.info without calling approved_anonymize first"
   -> {{"type": "data_flow", "pattern": "logger\\.(info|error|warning)\\(.*(?!approved_anonymize)", "file_patterns": ["*.py"], "severity": "HIGH", "description": "PII logged without anonymization", "condition": "When logger.info/error/warning is called without approved_anonymize in the same function", "message_template": "PII may be logged without anonymization in {file}:{line}"}}

2. Rule: "Block any import of the os module in lambda handler files"
   -> {{"type": "import_check", "pattern": "^import os\\b|^from os\\b", "file_patterns": ["**/handlers/*.py", "**/lambdas/*.py"], "severity": "MEDIUM", "description": "os module import not allowed in lambda handlers", "condition": "When os module is imported in a handler file", "message_template": "os module import not allowed in lambda handler at {file}:{line}"}}

Generate the JSON now:"""


async def compile_natural_language_policy(natural_language_rule: str) -> dict:
    prompt = POLICY_COMPILATION_PROMPT.format(rule=natural_language_rule)

    result = await _call_llm_for_policy(prompt)
    if not result:
        return _fallback_compilation(natural_language_rule)

    try:
        text = result.strip()
        if text.startswith("```"):
            text = re.sub(r'^```(?:json)?\s*', '', text)
            text = re.sub(r'\s*```$', '', text)
        compiled = json.loads(text)
        required = ["type", "pattern", "severity", "description"]
        if not all(k in compiled for k in required):
            return _fallback_compilation(natural_language_rule)
        return compiled
    except (json.JSONDecodeError, Exception):
        return _fallback_compilation(natural_language_rule)


def _fallback_compilation(natural_language_rule: str) -> dict:
    rule_lower = natural_language_rule.lower()

    file_patterns = []
    ext_indicators = {
        ".py": ["python", ".py"], ".js": ["javascript", ".js"], ".ts": ["typescript", ".ts"],
        ".java": ["java", ".java"], ".go": ["go", ".go"], ".rb": ["ruby", ".rb"],
    }
    for ext, keywords in ext_indicators.items():
        if any(k in rule_lower for k in keywords):
            file_patterns.append(f"*{ext}")
            break

    severity = "HIGH"
    if any(w in rule_lower for w in ["critical", "block", "must not", "forbid", "prohibit"]):
        severity = "CRITICAL"
    elif any(w in rule_lower for w in ["should", "recommend", "consider", "low", "minor"]):
        severity = "LOW" if "minor" in rule_lower or "low" in rule_lower else "MEDIUM"

    keywords = re.findall(r'\b([a-zA-Z_]\w*)\b', natural_language_rule)
    significant = [k for k in keywords if len(k) > 3 and k.lower() not in
                   {"this", "that", "with", "from", "they", "have", "been", "will", "would", "could",
                    "should", "must", "shall", "after", "before", "when", "what", "where", "which",
                    "their", "there", "about", "into", "over", "than", "then", "also", "just"}]
    if significant:
        pattern = "|".join(re.escape(k) for k in significant[:5])
    else:
        pattern = ""

    return {
        "type": "regex_pattern",
        "pattern": pattern,
        "file_patterns": file_patterns,
        "severity": severity,
        "description": natural_language_rule[:200],
        "condition": natural_language_rule,
        "message_template": "Policy violation: {rule_name} at {file}:{line}",
    }


async def _call_llm_for_policy(prompt: str) -> Optional[str]:
    from app.services.analysis import analyze_with_anthropic, analyze_with_openai, analyze_with_groq

    for func in [analyze_with_groq, analyze_with_openai, analyze_with_anthropic]:
        try:
            result = await func(prompt)
            if result:
                return result
        except Exception:
            continue
    return None


async def check_policies_for_finding(
    db: AsyncSession,
    org_id: str,
    finding: Finding,
    code_snippet: str,
    file_path: str,
) -> list[PolicyViolation]:
    result = await db.execute(
        select(Policy).where(
            Policy.org_id == org_id,
            Policy.is_active == True,
        )
    )
    policies = result.scalars().all()
    violations = []

    for policy in policies:
        if not policy.compiled_rule:
            continue

        rule = policy.compiled_rule
        pattern = rule.get("pattern", "")
        if not pattern:
            continue

        if _matches_file_pattern(file_path, rule.get("file_patterns", [])):
            if re.search(pattern, code_snippet, re.IGNORECASE):
                violation = PolicyViolation(
                    finding_id=finding.id,
                    policy_id=policy.id,
                    matched_text=code_snippet[:500],
                )
                db.add(violation)
                violations.append(violation)

    if violations:
        await db.commit()
    return violations


async def check_policies_for_diff(
    db: AsyncSession,
    org_id: str,
    diff_data: str,
    file_path: str = None,
) -> list[dict]:
    result = await db.execute(
        select(Policy).where(
            Policy.org_id == org_id,
            Policy.is_active == True,
        )
    )
    policies = result.scalars().all()
    findings = []

    for policy in policies:
        if not policy.compiled_rule:
            continue

        rule = policy.compiled_rule
        pattern = rule.get("pattern", "")
        if not pattern:
            continue

        lines = diff_data.split('\n')
        for line_idx, line in enumerate(lines):
            if not line.startswith('+'):
                continue

            code = line[1:].strip()
            file_matches = _matches_file_pattern(file_path or "", rule.get("file_patterns", []))

            if file_matches is False:
                continue

            if file_matches is True or file_matches is None:
                if re.search(pattern, code, re.IGNORECASE):
                    findings.append(_make_policy_finding(policy, rule, code, line_idx + 1, file_path))

    return findings


async def check_policies_for_parsed_diff(
    db: AsyncSession,
    org_id: str,
    parsed_diff: "ParsedDiff",
) -> list[dict]:
    result = await db.execute(
        select(Policy).where(
            Policy.org_id == org_id,
            Policy.is_active == True,
        )
    )
    policies = result.scalars().all()
    all_findings = []

    for policy in policies:
        if not policy.compiled_rule:
            continue

        rule = policy.compiled_rule
        pattern = rule.get("pattern", "")
        if not pattern:
            continue

        for file in parsed_diff.files:
            if file.should_skip:
                continue

            file_matches = _matches_file_pattern(file.filename, rule.get("file_patterns", []))
            if file_matches is False:
                continue

            for line_num, code in file.added_lines:
                if re.search(pattern, code.strip(), re.IGNORECASE):
                    all_findings.append(_make_policy_finding(
                        policy, rule, code.strip(), line_num, file.filename
                    ))

    return all_findings


def _make_policy_finding(policy: Policy, rule: dict, code: str, line_number: int, file_path: str = None) -> dict:
    msg = rule.get("message_template", "Policy violation: {rule_name} at {file}:{line}")
    message = msg.replace("{rule_name}", policy.name).replace("{file}", file_path or "unknown").replace("{line}", str(line_number))

    return {
        "file_path": file_path or "unknown",
        "line_number": line_number,
        "line_start": line_number,
        "line_end": line_number,
        "severity": rule.get("severity", policy.severity.value if hasattr(policy.severity, 'value') else policy.severity),
        "category": f"policy:{policy.name}",
        "title": f"Policy Violation: {policy.name}",
        "description": message,
        "code_snippet": code[:500],
        "suggested_fix": "Review the policy requirements and update the code accordingly.",
        "is_ai_generated": False,
        "policy_id": policy.id,
    }


def _matches_file_pattern(file_path: str, file_patterns: list) -> Optional[bool]:
    if not file_patterns:
        return None
    import fnmatch
    for pattern in file_patterns:
        if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(file_path.split("/")[-1], pattern):
            return True
    return False
