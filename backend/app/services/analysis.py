import re
import json
import os
from typing import Optional
from pathlib import Path
from app.config import settings

SKIPPED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf',
                      '.zip', '.tar', '.gz', '.bz2', '.rar', '.7z', '.exe', '.dll', '.so', '.dylib', '.bin',
                      '.pyc', '.pyo', '.pyd', '.class', '.jar', '.war',
                      '.min.js', '.min.css', '.map'}
SKIPPED_PATTERNS = [r'(^|/)node_modules/', r'(^|/)vendor/', r'(^|/)dist/', r'(^|/)build/', r'(^|/)\.next/',
                    r'(^|/)__pycache__/', r'(^|/)\.git/', r'(^|/)target/', r'(^|/)bin/',
                    r'(^|/)package-lock\.json$', r'(^|/)yarn\.lock$', r'(^|/)Gemfile\.lock$',
                    r'(^|/)poetry\.lock$', r'(^|/)\.env\.example$', r'(^|/)\.gitignore$']

LANGUAGE_MAP = {
    '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript React',
    '.jsx': 'JavaScript React', '.java': 'Java', '.go': 'Go', '.rs': 'Rust',
    '.rb': 'Ruby', '.php': 'PHP', '.c': 'C', '.cpp': 'C++', '.h': 'C/C++ Header',
    '.cs': 'C#', '.swift': 'Swift', '.kt': 'Kotlin', '.scala': 'Scala',
    '.sh': 'Shell', '.bash': 'Shell', '.zsh': 'Shell', '.ps1': 'PowerShell',
    '.sql': 'SQL', '.yaml': 'YAML', '.yml': 'YAML', '.json': 'JSON',
    '.tf': 'Terraform', '.tfvars': 'Terraform', '.Dockerfile': 'Dockerfile',
    '.dockerfile': 'Dockerfile', '.gradle': 'Groovy', '.mjs': 'JavaScript',
    '.vue': 'Vue', '.svelte': 'Svelte', '.astro': 'Astro',
}

CWE_MAP = {
    "secrets": "CWE-798", "injection": "CWE-89", "xss": "CWE-79",
    "auth": "CWE-287", "crypto": "CWE-327", "ssrf": "CWE-918",
    "race_condition": "CWE-362", "path_traversal": "CWE-22",
    "deserialization": "CWE-502", "ai_hallucination": "CWE-1104",
}


class ParsedDiff:
    def __init__(self):
        self.files: list[ParsedFile] = []


class ParsedFile:
    def __init__(self, filename: str = ""):
        self.filename = filename
        self.language = "Unknown"
        self.added_lines: list[tuple[int, str]] = []
        self.removed_lines: list[tuple[int, str]] = []
        self.context_lines: list[tuple[int, str]] = []
        self.raw_diff = ""
        self.should_skip = False

    def get_added_code(self) -> str:
        return "\n".join(line for _, line in self.added_lines)


def parse_unified_diff(diff_data: str) -> ParsedDiff:
    result = ParsedDiff()
    current_file: Optional[ParsedFile] = None
    line_num = 0
    new_start = 0

    for line in diff_data.split("\n"):
        if line.startswith("diff --git"):
            if current_file:
                result.files.append(current_file)
            current_file = ParsedFile()
            current_file.raw_diff = ""
        elif line.startswith("--- a/") or line.startswith("+++ b/"):
            if line.startswith("+++ b/"):
                filename = line[6:]
                current_file.filename = filename
                ext = Path(filename).suffix.lower()
                current_file.language = LANGUAGE_MAP.get(ext, "Unknown")
                current_file.should_skip = should_skip_file(filename)
        elif line.startswith("@@") and current_file:
            match = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', line)
            if match:
                new_start = int(match.group(1))
                line_num = new_start
        elif current_file:
            current_file.raw_diff += line + "\n"
            if line.startswith("+") and not line.startswith("+++"):
                current_file.added_lines.append((line_num, line[1:]))
                line_num += 1
            elif line.startswith("-") and not line.startswith("---"):
                current_file.removed_lines.append((line_num, line[1:]))
            elif line.startswith(" "):
                current_file.context_lines.append((line_num, line[1:]))
                line_num += 1
            elif line == r'\ No newline at end of file':
                pass

    if current_file:
        result.files.append(current_file)

    return result


def should_skip_file(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    if ext in SKIPPED_EXTENSIONS:
        return True
    for pattern in SKIPPED_PATTERNS:
        if re.search(pattern, filename):
            return True
    return False


ANALYSIS_PROMPT = """You are an expert security engineer reviewing a code diff. Analyze ONLY the changed lines for security vulnerabilities.

FILE: {filename}
LANGUAGE: {language}
DIFF:
{diff}

Check for:
1. Hardcoded secrets (API keys, passwords, tokens) — even in test files
2. SQL injection (string concatenation in queries, unsanitized inputs)
3. XSS (innerHTML, document.write, unsafe React dangerouslySetInnerHTML)
4. Insecure authentication (weak password checks, missing MFA, JWT without expiry)
5. Insecure deserialization (pickle, yaml.load, eval)
6. Path traversal (user input in file paths without sanitization)
7. Insecure crypto (MD5, SHA1, weak randomness)
8. SSRF (server-side requests with user-controlled URLs)
9. Race conditions (TOCTOU patterns)
10. AI hallucination patterns — importing non-existent libraries, using deprecated/removed APIs, incorrect auth patterns common in AI-generated code

For each finding, return a JSON object. Return ONLY valid JSON, no markdown, no backticks:
{{
  "findings": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "secrets|injection|xss|auth|crypto|ssrf|race_condition|path_traversal|deserialization|ai_hallucination|other",
      "title": "Brief actionable title",
      "description": "Detailed vulnerability explanation",
      "line_number": 42,
      "suggested_fix": "Secure code snippet that fixes the issue",
      "cwe_id": "CWE-xxx"
    }}
  ],
  "ai_generated_probability": 0.0,
  "summary": "Brief overall assessment of this file"
}}

Rules:
- Only report issues in CHANGED lines (both added and removed), not existing surrounding code
- Be precise with line numbers from the diff
- suggested_fix must be syntactically correct {language}
- If no issues found, return {{"findings": [], "ai_generated_probability": 0.0, "summary": "No security issues detected."}}
"""


async def analyze_with_groq(prompt: str) -> Optional[str]:
    import httpx
    api_key = os.environ.get("GROQ_API_KEY") or settings.GROQ_API_KEY
    if not api_key:
        return None
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": "llama-3.1-70b-versatile",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens": 4096,
                },
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
            return None
    except Exception:
        return None


async def analyze_with_ollama(prompt: str, model: str = "llama3.1:70b") -> Optional[str]:
    import httpx
    ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{ollama_url}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "options": {"temperature": 0.1, "num_predict": 4096},
                },
            )
            if resp.status_code == 200:
                return resp.json()["message"]["content"]
            return None
    except Exception:
        return None


async def analyze_with_openai(prompt: str, model: str = "gpt-4o") -> Optional[str]:
    from openai import AsyncOpenAI
    api_key = settings.OPENAI_API_KEY
    if not api_key:
        return None
    try:
        client = AsyncOpenAI(api_key=api_key)
        response = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=4096,
        )
        return response.choices[0].message.content
    except Exception:
        return None


async def analyze_with_anthropic(prompt: str, model: str = "claude-3-5-sonnet-20241022") -> Optional[str]:
    from anthropic import AsyncAnthropic
    api_key = settings.ANTHROPIC_API_KEY
    if not api_key:
        return None
    try:
        client = AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model=model,
            max_tokens=4096,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text
    except Exception:
        return None


async def call_llm(prompt: str) -> Optional[str]:
    provider_order = ["groq", "ollama", "openai", "anthropic"]
    configured_providers = {
        "groq": (os.environ.get("GROQ_API_KEY") or getattr(settings, 'GROQ_API_KEY', None)),
        "ollama": bool(os.environ.get("OLLAMA_URL")),
        "openai": settings.OPENAI_API_KEY,
        "anthropic": settings.ANTHROPIC_API_KEY,
    }
    for provider in provider_order:
        if configured_providers.get(provider):
            func = {
                "groq": analyze_with_groq,
                "ollama": analyze_with_ollama,
                "openai": analyze_with_openai,
                "anthropic": analyze_with_anthropic,
            }[provider]
            result = await func(prompt)
            if result:
                return result
    return None


def parse_llm_response(response_text: str) -> list[dict]:
    if not response_text:
        return []
    text = response_text.strip()
    if text.startswith("```"):
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("findings", [])
    except json.JSONDecodeError:
        match = re.search(r'\[\s*\{.*\}\s*\]', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        match = re.search(r'"findings"\s*:\s*(\[\s*\{.*\}\s*\])', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
    return []


def extract_ai_probability(response_text: str) -> float:
    if not response_text:
        return 0.0
    try:
        text = response_text.strip()
        if text.startswith("```"):
            text = re.sub(r'^```(?:json)?\s*', '', text)
            text = re.sub(r'\s*```$', '', text)
        data = json.loads(text)
        if isinstance(data, dict):
            return float(data.get("ai_generated_probability", 0.0))
    except Exception:
        match = re.search(r'"ai_generated_probability"\s*:\s*([\d.]+)', response_text)
        if match:
            return float(match.group(1))
    return 0.0


def extract_summary(response_text: str) -> str:
    if not response_text:
        return ""
    try:
        text = response_text.strip()
        if text.startswith("```"):
            text = re.sub(r'^```(?:json)?\s*', '', text)
            text = re.sub(r'\s*```$', '', text)
        data = json.loads(text)
        if isinstance(data, dict):
            return data.get("summary", "")
    except Exception:
        match = re.search(r'"summary"\s*:\s*"([^"]+)"', response_text)
        if match:
            return match.group(1)
    return ""


async def analyze_file_with_llm(file: ParsedFile) -> tuple[list[dict], float, str]:
    added_code = file.get_added_code()
    if not added_code.strip():
        return [], 0.0, "No added lines to analyze"

    prompt = ANALYSIS_PROMPT.format(
        filename=file.filename,
        language=file.language,
        diff=added_code[:12000],
    )
    response = await call_llm(prompt)
    if not response:
        return [], 0.0, "LLM analysis unavailable"

    findings = parse_llm_response(response)
    ai_prob = extract_ai_probability(response)
    summary = extract_summary(response)

    for f in findings:
        f["file_path"] = f.get("file_path", file.filename)
        f["is_ai_generated"] = ai_prob > 0.5
        if not f.get("cwe_id"):
            f["cwe_id"] = CWE_MAP.get(f.get("category", ""), "")

    return findings, ai_prob, summary


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("file_path", ""), f.get("line_number", 0), f.get("category", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def sort_findings(findings: list[dict]) -> list[dict]:
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(findings, key=lambda f: severity_order.get(f.get("severity", "LOW"), 99))


def truncate_findings(findings: list[dict], max_count: int = 20) -> list[dict]:
    return findings[:max_count]


AI_DETECTION_HEURISTICS = [
    (r'//\s*(?:This|The)\s+(?:function|class|method|code)\s+(?:is|will|does|handles|checks)\s', "Overly verbose comments"),
    (r'/\*\*\s*\n\s*\*\s*(?:@param|@return|@throws|@see)', "JSDoc-style comments (AI hallmark)"),
    (r'(?:TODO|FIXME|HACK|XXX):?\s*(?:fix|implement|add|handle|check|validate|need|should)', "Stub/TODO patterns common in AI code"),
    (r'\.\s*(?:catch|then|finally)\s*\(\s*(?:async\s*)?\(?\s*(?:e|err|error|ex)\)?\s*=>\s*\{?\s*(?:console\.(?:error|log)|\/\/)', "Generic error handling in promises"),
    (r'(?:var|let|const)\s+[a-z]+[A-Z]\w*\s*=\s*(?:await\s+)?[a-z]+[A-Z]\w*\s*\(', "Inconsistent camelCase variable names"),
    (r'const\s+\{[^}]*\}\s*=\s*require\s*\(', "Destructured require (CommonJS + ESM mix)"),
    (r'import\s+\{\s*\w+\s*\}\s+from\s+["\'](?:[./]*[a-z-]+(?:sdk|client|api|utils|helper))["\']', "Suspicious AI-hallucinated imports"),
]


def detect_ai_code_heuristic(parsed_diff: ParsedDiff) -> dict:
    total_lines = 0
    indicator_matches = {}

    for file in parsed_diff.files:
        for _, line in file.added_lines:
            total_lines += 1
            for pattern, label in AI_DETECTION_HEURISTICS:
                if re.search(pattern, line):
                    indicator_matches[label] = indicator_matches.get(label, 0) + 1

    if total_lines == 0:
        return {"is_ai_generated": False, "confidence": 0.0, "indicators": [], "ai_percentage": 0.0}

    total_matches = sum(indicator_matches.values())
    match_rate = total_matches / total_lines
    indicators = [{"label": k, "count": v} for k, v in sorted(indicator_matches.items(), key=lambda x: -x[1])]

    confidence = min(1.0, match_rate * 3)
    return {
        "is_ai_generated": confidence > 0.3,
        "confidence": round(confidence, 2),
        "ai_percentage": round(confidence * 100, 1),
        "indicators": indicators,
    }


async def detect_ai_code_llm(parsed_diff: ParsedDiff) -> float:
    combined = ""
    for f in parsed_diff.files[:3]:
        code = f.get_added_code()
        if code:
            combined += f"--- {f.filename} ---\n{code}\n"

    if not combined.strip():
        return 0.0

    prompt = f"""Analyze this code diff and determine if it was likely written by an AI coding assistant (Copilot, Cursor, Claude Code).

Indicators of AI-generated code:
- Overly verbose comments explaining obvious code
- Unnecessarily defensive null checks
- Excessive type annotations
- Code that looks correct but uses wrong library APIs
- Hallucinated function names or library calls
- Boilerplate patterns that are overly generic
- Missing edge case handling
- Inconsistent naming conventions within the same diff

Code:
```
{combined[:10000]}
```

Respond with ONLY a number between 0.0 and 1.0 indicating AI-generation probability:"""

    response = await call_llm(prompt)
    if response:
        match = re.search(r'([\d.]+)', response.strip())
        if match:
            try:
                return min(1.0, max(0.0, float(match.group(1))))
            except ValueError:
                pass
    return 0.0


async def run_full_analysis_pipeline(
    diff_data: str,
    repo_name: str = "",
    pr_number: int = 0,
    pr_title: str = "",
) -> dict:
    parsed = parse_unified_diff(diff_data)

    all_findings = []
    total_ai_prob = 0.0
    file_count = 0
    file_summaries = []

    for file in parsed.files:
        if file.should_skip:
            continue
        if not file.get_added_code().strip():
            continue
        file_count += 1

        findings, ai_prob, summary = await analyze_file_with_llm(file)
        for f in findings:
            f["file_path"] = file.filename
            f["language"] = file.language
        all_findings.extend(findings)
        total_ai_prob += ai_prob
        if summary:
            file_summaries.append({"file": file.filename, "summary": summary})

    heuristic_result = detect_ai_code_heuristic(parsed)
    if heuristic_result["confidence"] > 0.5:
        llm_ai_prob = await detect_ai_code_llm(parsed)
        combined_ai_prob = max(heuristic_result["confidence"], llm_ai_prob)
    else:
        combined_ai_prob = heuristic_result["confidence"] if file_count > 0 else 0.0

    all_findings = deduplicate_findings(all_findings)
    all_findings = sort_findings(all_findings)
    all_findings = truncate_findings(all_findings, max_count=20)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f.get("severity", "LOW")
        if sev in severity_counts:
            severity_counts[sev] += 1

    overall_status = "passed"
    if severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 0:
        overall_status = "failed"

    return {
        "findings": all_findings,
        "ai_generated": {
            "is_ai_generated": combined_ai_prob > 0.4,
            "confidence": round(combined_ai_prob, 2),
            "ai_percentage": round(combined_ai_prob * 100, 1),
            "heuristic_indicators": heuristic_result.get("indicators", []),
        },
        "summary": {
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "overall_status": overall_status,
            "files_analyzed": file_count,
            "file_summaries": file_summaries,
            "pr_number": pr_number,
            "repo_name": repo_name,
        },
    }
