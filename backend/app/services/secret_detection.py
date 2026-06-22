import re
from typing import Optional
from pathlib import Path
from app.config import settings

SECRET_PATTERNS = [
    (r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', "API Key / Secret", "CRITICAL"),
    (r'(?i)(?:sk-[a-zA-Z0-9]{32,}|pk-[a-zA-Z0-9]{32,})', "OpenAI API Key", "CRITICAL"),
    (r'(?i)ghp_[a-zA-Z0-9]{36,}', "GitHub Personal Access Token", "CRITICAL"),
    (r'(?i)gho_[a-zA-Z0-9]{36,}', "GitHub OAuth Token", "CRITICAL"),
    (r'(?i)(?:ghs|ghu)_[a-zA-Z0-9]{36,}', "GitHub App Token", "CRITICAL"),
    (r'(?i)AKIA[0-9A-Z]{16}', "AWS Access Key ID", "HIGH"),
    (r'(?i)(?:aws[_-]?secret[_-]?access[_-]?key|aws_secret_key)\s*[:=]\s*["\']?([a-zA-Z0-9\/+=]{40})["\']?', "AWS Secret Access Key", "CRITICAL"),
    (r'-----BEGIN RSA PRIVATE KEY-----', "RSA Private Key", "CRITICAL"),
    (r'-----BEGIN OPENSSH PRIVATE KEY-----', "OpenSSH Private Key", "CRITICAL"),
    (r'-----BEGIN DSA PRIVATE KEY-----', "DSA Private Key", "CRITICAL"),
    (r'-----BEGIN EC PRIVATE KEY-----', "EC Private Key", "CRITICAL"),
    (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "PGP Private Key", "CRITICAL"),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?([^"\'}\s;]{8,})["\']?', "Hardcoded Password", "CRITICAL"),
    (r'(?i)(?:slack[_-]?token|slack[_-]?bot[_-]?token)\s*[:=]\s*["\']?(xox[baprs]-[a-zA-Z0-9\-]{10,})["\']?', "Slack Token", "CRITICAL"),
    (r'(?i)sk_live_[a-zA-Z0-9]{20,}', "Stripe Live Secret Key", "CRITICAL"),
    (r'(?i)pk_live_[a-zA-Z0-9]{20,}', "Stripe Live Publishable Key", "HIGH"),
    (r'(?i)(?:JWT_SECRET|jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', "JWT Secret", "HIGH"),
    (r'(?i)(?:mongo[_-]?uri|mongodb[_-]?uri)\s*[:=]\s*["\']?(mongodb(?:\+srv)?://[^"\' ]+)["\']?', "MongoDB Connection String", "HIGH"),
    (r'(?i)(?:postgres(?:ql)?[_-]?uri|postgres(?:ql)?[_-]?url|postgres(?:ql)?_[_-]?dsn)\s*[:=]\s*["\']?(postgres(?:ql)?(?:\+?[a-z]+)?://[^"\' ]+)["\']?', "PostgreSQL Connection String", "HIGH"),
    (r'(?i)(?:redis[_-]?uri|redis[_-]?url)\s*[:=]\s*["\']?(redis://[^"\' ]+)["\']?', "Redis Connection String", "MEDIUM"),
    (r'(?i)glpat-[a-zA-Z0-9_\-]{20,}', "GitLab Personal Access Token", "CRITICAL"),
    (r'(?i)xox[baprs]-[a-zA-Z0-9\-]{10,}', "Slack Token/Bot Token", "CRITICAL"),
    (r'(?i)SFDC_[a-zA-Z0-9]{30,}', "Salesforce API Token", "HIGH"),
    (r'(?i)(?:heroku[_-]?api[_-]?key|heroku[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9\-]{20,})["\']?', "Heroku API Key", "HIGH"),
    (r'(?i)(?:google[_-]?api[_-]?key|google[_-]?credentials)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{30,})["\']?', "Google API Key", "HIGH"),
    (r'(?i)AIza[0-9A-Za-z\-_]{35}', "Google Cloud API Key", "HIGH"),
    (r'(?i)(?:-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----)', "Embedded Certificate", "HIGH"),
    (r'(?i)(?:azure|azure_devops|azuread)_?(?:key|token|secret|connection_string)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.=]{20,})["\']?', "Azure Key/Token", "HIGH"),
    (r'(?i)(?:twilio|twil)_?(?:account|auth|api|token|sid)\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\']?', "Twilio Credential", "HIGH"),
    (r'(?i)(?:sendgrid|send_grid|sendgrid_)?api_key\s*[:=]\s*["\']?(SG\.[a-zA-Z0-9_\-\.]{20,})["\']?', "SendGrid API Key", "HIGH"),
    (r'(?i)(?:yt|youtube|google)_?api_key\s*[:=]\s*["\']?(AIza[0-9A-Za-z\-_]{35})["\']?', "YouTube/Google API Key", "HIGH"),
    (r'(?i)(?:db_pass|db_password|mysql_pass|mongo_pass|pg_pass|mariadb_pass)\s*[:=]\s*["\']?([^"\'}\s;]{8,})["\']?', "Database Password", "CRITICAL"),
    (r'(?i)S3?_?(?:secret|access|key|bucket)_?(?:key|secret|id)?\s*[:=]\s*["\']?([a-zA-Z0-9\/+=]{20,})["\']?', "S3 Credential", "HIGH"),
]

SUSPICIOUS_FUNCTIONS = [
    (r'eval\s*\(', "Use of eval()", "HIGH"),
    (r'exec\s*\(', "Use of exec()", "HIGH"),
    (r'setTimeout\s*\(\s*["\']', "setTimeout with string (RCE risk)", "MEDIUM"),
    (r'setInterval\s*\(\s*["\']', "setInterval with string (RCE risk)", "MEDIUM"),
    (r'Function\s*\(', "Dynamic function creation", "MEDIUM"),
    (r'document\.write\s*\(', "document.write (XSS risk)", "HIGH"),
    (r'innerHTML\s*=', "innerHTML assignment (XSS risk)", "HIGH"),
    (r'outerHTML\s*=', "outerHTML assignment (XSS risk)", "HIGH"),
    (r' dangerouslySetInnerHTML', "dangerouslySetInnerHTML (React XSS risk)", "HIGH"),
    (r'new\s+Function\s*\(', "Dynamic function constructor", "MEDIUM"),
    (r'(?i)v-html\s*=', "Vue v-html directive (XSS risk)", "MEDIUM"),
]

SQL_INJECTION_PATTERNS = [
    (r'(?i)(?:execute|exec|query|run|raw)\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)', "Raw SQL query execution", "CRITICAL"),
    (r'(?i)\.\s*exec(?:ute)?\s*\(\s*f["\']', "f-string in SQL execution", "CRITICAL"),
    (r'(?i)format\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*["\']', "String formatting in SQL query", "HIGH"),
    (r'(?i)\+\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*["\']', "String concatenation in SQL", "HIGH"),
    (r'(?i)raw\(', "Raw SQL execution", "HIGH"),
    (r'(?i)db\.execute\s*\(\s*["\']', "Direct database execute", "HIGH"),
    (r'(?i)\.query\s*\(\s*f["\']', "f-string in SQL query method", "HIGH"),
    (r'(?i)\$\{[^}]*\}\s*(?:SELECT|INSERT|UPDATE|DELETE)', "Template literal in SQL", "HIGH"),
    (r'(?i)where\s+1\s*=\s*1', "Always-true WHERE clause (SQL injection test)", "MEDIUM"),
    (r'(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\bOR\b\s+1\s*=\s*1', "SQL injection attempt", "CRITICAL"),
]

PATH_TRAVERSAL_PATTERNS = [
    (r'(?i)\.\.\/', "Path traversal (../)", "HIGH"),
    (r'(?i)\.\.\\\\', "Path traversal (..\\)", "HIGH"),
    (r'(?i)(?:os\.path\.join|pathlib\.Path)\s*\(\s*[^,)]+\s*,\s*(?:request|user_input|data|filename|path|file)', "Path traversal in join()", "HIGH"),
    (r'(?i)(?:open|fopen|file_get_contents|readfile|include|require)\s*\(\s*(?:request|user_input|data|filename|path|file)', "Path traversal in file read", "HIGH"),
    (r'(?i)sendfile\s*\(\s*(?:request|user_input|data|filename|path)', "Path traversal in sendfile", "HIGH"),
    (r'(?i)__dirname\s*\+\s*["\']/\.\.\/', "Path traversal via __dirname", "MEDIUM"),
]

INSECURE_CRYPTO = [
    (r'(?i)md5\s*\(', "MD5 hash (insecure)", "MEDIUM"),
    (r'(?i)sha1\s*\(', "SHA-1 hash (insecure)", "MEDIUM"),
    (r'(?i)Crypto\.Cipher\.DES', "DES encryption (insecure)", "HIGH"),
    (r'(?i)Crypto\.Hash\.MD5', "MD5 hash (insecure)", "MEDIUM"),
    (r'(?i)hashlib\.md5', "MD5 hash (insecure)", "MEDIUM"),
    (r'(?i)hashlib\.sha1', "SHA-1 hash (insecure)", "MEDIUM"),
    (r'(?i)(?:Math\.random|random\.randint|random\.choice)\s*\(', "Weak random number generator", "MEDIUM"),
    (r'(?i)ecdsa|weak_key_size|RC4|DES_EDE|Blowfish', "Weak encryption algorithm", "HIGH"),
    (r'(?i)Cipher\.getInstance\s*\(\s*["\'](?:DES|RC4|Blowfish|RSA/ECB)', "Weak cipher in Java", "HIGH"),
]

DESERIALIZATION_PATTERNS = [
    (r'(?i)pickle\.loads?\s*\(', "Insecure pickle deserialization", "CRITICAL"),
    (r'(?i)yaml\.load\s*\(', "Insecure YAML deserialization", "CRITICAL"),
    (r'(?i)marshal\.loads?\s*\(', "Insecure marshal deserialization", "HIGH"),
    (r'(?i)ObjectInputStream\.readObject', "Java insecure deserialization", "CRITICAL"),
    (r'(?i)JSON\.parse\s*\(\s*[^"\'][^)]*request|input|user|data', "JSON.parse from untrusted source", "MEDIUM"),
    (r'(?i)unsafeUnmarshal|json\.Unmarshal\s*\(', "Go unsafe unmarshal", "HIGH"),
]

SSRF_PATTERNS = [
    (r'(?i)(?:requests|urllib|httpx|aiohttp|axios|fetch|curl|http\.get|http\.post)\s*\(.*(?:request\.url|request\.get|user_input|input_data|data\[|params\[)', "SSRF from user input", "HIGH"),
    (r'(?i)(?:urlopen|urlretrieve|file_get_contents|download|getcontents)\s*\(.*(?:request|_GET|_POST|_REQUEST)', "SSRF via URL open", "HIGH"),
    (r'(?i)(?:requests|urllib|httpx)\.(?:get|post|put|delete)\s*\(\s*f["\']', "f-string in HTTP request URL", "HIGH"),
    (r'(?i)(?:base_url|api_url|webhook_url|callback_url)\s*=\s*(?:request|input|_GET|_POST)', "User-controlled URL", "MEDIUM"),
]

RACE_CONDITION_PATTERNS = [
    (r'(?i)(?:os\.rename|shutil\.move|os\.replace)\s*\(', "TOCTOU rename (race condition)", "MEDIUM"),
    (r'(?i)(?:check|exists|isfile|isdir)\s*\(.*\).*[\n\r].*(?:open|remove|unlink|delete)\s*\(', "TOCTOU check-then-use", "HIGH"),
    (r'(?i)(?:if\s+not\s+(?:os\.path\.exists|os\.path\.isfile)).*[\n\r].*[\n\r].*(?:open|write)', "TOCTOU file check-then-write", "HIGH"),
    (r'(?i)(?:check|validate).*(?:permission|auth|access).*[\n\r].*(?:allow|grant|exec)', "TOCTOU auth check-then-act", "MEDIUM"),
]

AI_HALLUCINATION_PATTERNS = [
    (r'pip install\s+[a-zA-Z]+-(?:sdk|client|api)\s*==\s*\d+\.\d+\.\d+', "Version-pinned fake package", "MEDIUM"),
    (r'import\s+(?:LangChain|langchain)\s*$', "LangChain import (verify installation)", "LOW"),
    (r'from\s+anthropic\s+import\s+', "Anthropic SDK import (verify version)", "LOW"),
    (r'import\s+(?:openai|OpenAI)\s*$', "OpenAI import (verify version)", "LOW"),
    (r'from\s+transformers\s+import\s+', "HuggingFace import (verify model name)", "LOW"),
    (r'client\.(?:chat|completions|messages)\.create\s*\(\s*model\s*=\s*["\"\'](?:gpt|claude|llama|mixtral)[^"\"\'"]*["\"\'"]', "LLM API call (verify model name)", "LOW"),
    (r'(?i)vector_store|VectorStore|Pinecone|Weaviate|Chroma|Qdrant', "Vector DB usage (verify correct SDK)", "LOW"),
    (r'(?i)embedding|Embedding|text-embedding-|ADA|ada-002', "Embeddings usage (verify API)", "LOW"),
    (r'(?i)function_calling|tool_use|tools\s*=\s*\[', "Function calling pattern (verify API version)", "LOW"),
]

HTTP_INSECURE_PATTERNS = [
    (r'http://[a-zA-Z][a-zA-Z0-9.-]+\.(?:com|org|net|io|app|dev|ai|co|uk|de|jp)', "HTTP URL (should use HTTPS)", "LOW"),
    (r'(?i)(?:http_get|http_post|http_request)\s*\(\s*["\']http://', "Insecure HTTP request", "MEDIUM"),
]

ALL_CATEGORIES = [
    ("SECRETS", SECRET_PATTERNS),
    ("SUSPICIOUS_FUNCTIONS", SUSPICIOUS_FUNCTIONS),
    ("SQL_INJECTION", SQL_INJECTION_PATTERNS),
    ("PATH_TRAVERSAL", PATH_TRAVERSAL_PATTERNS),
    ("INSECURE_CRYPTO", INSECURE_CRYPTO),
    ("DESERIALIZATION", DESERIALIZATION_PATTERNS),
    ("SSRF", SSRF_PATTERNS),
    ("RACE_CONDITION", RACE_CONDITION_PATTERNS),
    ("AI_HALLUCINATION", AI_HALLUCINATION_PATTERNS),
    ("HTTP_INSECURE", HTTP_INSECURE_PATTERNS),
]

FALSE_POSITIVE_PATTERNS = [
    r'(?i)example\.(?:com|org|net)',
    r'(?i)your-(?:key|token|secret|password|api)',
    r'(?i)(?:sample|demo|test|mock|fake|dummy|placeholder)_?(?:key|token|secret|password|api)',
    r'(?i)(?:TODO|FIXME|HACK|XXX)\s*[:,-]?\s*(?:add|insert|put|replace|use|implement|fix)',
    r'(?i)(?:{{.*}}|<\s*%|%\s*>|{{\s*\.\.\.\s*}}|___|\.\.\.)',
    r'(?i)ssl_cert|ssl_key|certificate_file',
    r'(?i)from\s+typing\s+import',
    r'(?i)SECRET_KEY\s*=\s*["\']django-insecure-',
]


def get_file_language(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    lang_map = {
        '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.tsx': 'typescriptreact',
        '.jsx': 'javascriptreact', '.java': 'java', '.go': 'go', '.rs': 'rust',
        '.rb': 'ruby', '.php': 'php', '.c': 'c', '.cpp': 'cpp', '.cs': 'csharp',
        '.swift': 'swift', '.kt': 'kotlin', '.sh': 'shell', '.bash': 'shell',
        '.sql': 'sql', '.yaml': 'yaml', '.yml': 'yaml', '.json': 'json',
        '.tf': 'terraform', '.Dockerfile': 'dockerfile', '.dockerfile': 'dockerfile',
    }
    return lang_map.get(ext, 'unknown')


def is_false_positive(line: str) -> bool:
    for fp_pattern in FALSE_POSITIVE_PATTERNS:
        if re.search(fp_pattern, line):
            return True
    if line.count('=') > 3 and len(line) < 60:
        return True
    if 'import' in line and 'api_key' not in line.lower():
        return False
    return False


def get_severity_for_finding(severity_str: str, category: str) -> str:
    if severity_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return severity_str
    if "CRITICAL" in category:
        return "CRITICAL"
    return "MEDIUM"


def generate_fix_suggestion(category: str, code: str, language: str = "") -> str:
    suggestions = {
        "API Key / Secret": "Use environment variables or a secrets manager. Replace with `os.getenv('API_KEY')`.",
        "Private Key": "Store private keys in a secrets manager. Use SSH agent or HSM.",
        "Password": "Use environment variables or a secrets manager. Consider OAuth or token-based auth.",
        "SQL injection": "Use parameterized queries / prepared statements instead of string interpolation.",
        "XSS": "Use textContent instead of innerHTML. For React, use dangerouslySetInnerHTML only with sanitized input.",
        "eval()": "Never use eval(). Use JSON.parse() for JSON, or proper function references.",
        "exec()": "Never use exec(). Use subprocess.run() with argument lists instead of shell strings.",
        "Path traversal": "Sanitize file paths. Use os.path.basename() and reject paths containing '..'.",
        "MD5 hash (insecure)": "Use SHA-256 or bcrypt instead. MD5 is cryptographically broken.",
        "SHA-1 hash (insecure)": "Use SHA-256 or bcrypt instead. SHA-1 is deprecated.",
        "Insecure pickle deserialization": "Never unpickle untrusted data. Use JSON or a schema-validated format.",
        "Insecure YAML deserialization": "Use yaml.safe_load() instead of yaml.load() to prevent code execution.",
        "SSRF": "Validate and restrict URLs to an allowlist. Never pass user input directly to HTTP clients.",
        "TOCTOU": "Use atomic file operations. Open files directly instead of checking then opening.",
        "Hardcoded Password": "Use environment variables or a secrets manager.",
    }
    for key, suggestion in suggestions.items():
        if key.lower() in category.lower():
            return suggestion
    return "Move sensitive data to environment variables or a secrets management service."


async def scan_diff_for_patterns(
    diff_data: str,
    file_path: str = None,
) -> list[dict]:
    findings = []
    lines = diff_data.split('\n')
    current_file = file_path or "unknown"
    target_line_num = 0

    for line_idx, line in enumerate(lines):
        if line.startswith('+++ b/'):
            current_file = line[6:]
            target_line_num = 0
            continue

        if line.startswith('@@'):
            match = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', line)
            if match:
                target_line_num = int(match.group(1))
            continue

        if not (line.startswith('+') or line.startswith('-')):
            if line.startswith(' '):
                target_line_num += 1
            continue

        if is_false_positive(line):
            continue

        code = line[1:].strip()
        if not code:
            target_line_num += 1
            continue

        for category_name, patterns in ALL_CATEGORIES:
            for pattern, title, severity in patterns:
                matches = re.finditer(pattern, code)
                for match in matches:
                    findings.append({
                        "file_path": current_file,
                        "line_number": target_line_num,
                        "line_start": target_line_num,
                        "line_end": target_line_num,
                        "severity": severity,
                        "category": category_name.lower(),
                        "title": title,
                        "description": f"Potential {title.lower()} detected in {current_file} at line {target_line_num}",
                        "code_snippet": code[:500],
                        "suggested_fix": generate_fix_suggestion(title, code),
                        "is_ai_generated": category_name == "AI_HALLUCINATION",
                        "cwe_id": _cwe_for_category(category_name),
                    })

        target_line_num += 1

    return findings


def _cwe_for_category(category: str) -> str:
    mapping = {
        "SECRETS": "CWE-798", "SUSPICIOUS_FUNCTIONS": "CWE-94",
        "SQL_INJECTION": "CWE-89", "PATH_TRAVERSAL": "CWE-22",
        "INSECURE_CRYPTO": "CWE-327", "DESERIALIZATION": "CWE-502",
        "SSRF": "CWE-918", "RACE_CONDITION": "CWE-362",
        "AI_HALLUCINATION": "CWE-1104", "HTTP_INSECURE": "CWE-319",
    }
    return mapping.get(category, "")
