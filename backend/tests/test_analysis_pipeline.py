import pytest
import sys
sys.path.insert(0, "..")

from app.services.analysis import (
    parse_unified_diff, deduplicate_findings, sort_findings,
    truncate_findings, detect_ai_code_heuristic,
)
from app.services.secret_detection import scan_diff_for_patterns


class TestDiffParsing:
    def test_parse_simple_diff(self):
        diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 def hello():
+    print("world")
     return True
 """
        parsed = parse_unified_diff(diff)
        assert len(parsed.files) == 1
        assert parsed.files[0].filename == "app.py"
        assert len(parsed.files[0].added_lines) == 1
        assert parsed.files[0].added_lines[0][1] == 'print("world")'

    def test_parse_multiple_files(self):
        diff = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1,2 @@
+line1
 line0
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -1 +1,2 @@
+line2
 oldline
"""
        parsed = parse_unified_diff(diff)
        assert len(parsed.files) == 2

    def test_skip_binary_file(self):
        diff = """diff --git a/image.png b/image.png
--- a/image.png
+++ b/image.png
@@ -0,0 +1 @@
+binarydata"""
        parsed = parse_unified_diff(diff)
        assert len(parsed.files) == 1
        assert parsed.files[0].should_skip is True

    def test_skip_node_modules(self):
        diff = """diff --git a/node_modules/pkg/index.js b/node_modules/pkg/index.js
--- a/node_modules/pkg/index.js
+++ b/node_modules/pkg/index.js
@@ -1 +1 @@
-old
+new"""
        parsed = parse_unified_diff(diff)
        assert len(parsed.files) == 1
        assert parsed.files[0].should_skip is True

    def test_language_detection(self):
        diff = """diff --git a/main.py b/main.py
--- a/main.py
+++ b/main.py
@@ -0,0 +1 @@
+x=1"""
        parsed = parse_unified_diff(diff)
        assert parsed.files[0].language == "Python"

        diff2 = """diff --git a/app.tsx b/app.tsx
--- a/app.tsx
+++ b/app.tsx
@@ -0,0 +1 @@
+x=1"""
        parsed2 = parse_unified_diff(diff2)
        assert parsed2.files[0].language == "TypeScript React"


class TestFindingProcessing:
    def test_deduplicate(self):
        findings = [
            {"file_path": "a.py", "line_number": 1, "category": "secrets"},
            {"file_path": "a.py", "line_number": 1, "category": "secrets"},
            {"file_path": "a.py", "line_number": 2, "category": "injection"},
        ]
        deduped = deduplicate_findings(findings)
        assert len(deduped) == 2

    def test_sort_by_severity(self):
        findings = [
            {"severity": "LOW", "title": "low"},
            {"severity": "CRITICAL", "title": "critical"},
            {"severity": "HIGH", "title": "high"},
            {"severity": "MEDIUM", "title": "medium"},
        ]
        sorted_f = sort_findings(findings)
        assert sorted_f[0]["severity"] == "CRITICAL"
        assert sorted_f[1]["severity"] == "HIGH"
        assert sorted_f[2]["severity"] == "MEDIUM"
        assert sorted_f[3]["severity"] == "LOW"

    def test_truncate(self):
        findings = [{"severity": "LOW", "title": f"f{i}"} for i in range(30)]
        truncated = truncate_findings(findings, max_count=20)
        assert len(truncated) == 20

    def test_truncate_within_limit(self):
        findings = [{"severity": "LOW", "title": f"f{i}"} for i in range(5)]
        truncated = truncate_findings(findings, max_count=20)
        assert len(truncated) == 5


class TestAIDetection:
    def test_heuristic_verbose_comments(self):
        diff = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -0,0 +1,5 @@
+# This function handles user authentication
+def login():
+    # This checks if the user is valid
+    if user:
+        return True"""
        parsed = parse_unified_diff(diff)
        result = detect_ai_code_heuristic(parsed)
        assert result["is_ai_generated"] is True

    def test_heuristic_normal_code(self):
        diff = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -0,0 +1,3 @@
+def factorial(n):
+    if n <= 1:
+        return 1"""
        parsed = parse_unified_diff(diff)
        result = detect_ai_code_heuristic(parsed)
        assert result["confidence"] < 0.5


class TestSecretScanningIntegration:
    @pytest.mark.asyncio
    async def test_real_world_api_key_diff(self):
        diff = """+import os
+import requests
+
+API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
+
+headers = {"Authorization": f"Bearer {API_KEY}"}
+response = requests.get("https://api.example.com/data", headers=headers)
+print(response.json())"""
        findings = await scan_diff_for_patterns(diff, "client.py")
        assert len(findings) >= 1
        secrets = [f for f in findings if f.get("category") == "secrets"]
        assert len(secrets) >= 1

    @pytest.mark.asyncio
    async def test_real_world_sql_injection(self):
        diff = """+def get_user(email):
+    conn = get_db_connection()
+    query = f"SELECT * FROM users WHERE email = '{email}'"
+    cursor = conn.cursor()
+    cursor.execute(query)
+    return cursor.fetchone()"""
        findings = await scan_diff_for_patterns(diff, "queries.py")
        sql = [f for f in findings if f.get("category") == "sql_injection"]
        assert len(sql) >= 1

    @pytest.mark.asyncio
    async def test_clean_code_no_findings(self):
        diff = """+def add(a: int, b: int) -> int:
+    \"\"\"Add two numbers together.\"\"\"
+    return a + b
+
+result = add(3, 5)
+print(f"The result is {result}")"""
        findings = await scan_diff_for_patterns(diff, "math.py")
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_findings_in_added_lines_only(self):
        diff = """ old_line
-old_secret = "sk-old-abc"
+new_secret = "sk-new-def"
 context"""
        findings = await scan_diff_for_patterns(diff, "config.py")
        assert len(findings) >= 1
