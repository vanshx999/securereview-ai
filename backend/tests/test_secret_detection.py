import pytest
import sys
sys.path.insert(0, "..")

from app.services.secret_detection import scan_diff_for_patterns, is_false_positive


class TestSecretDetection:
    """20 test cases for secret detection and pattern scanning."""

    @pytest.mark.asyncio
    async def test_aws_access_key(self):
        diff = """+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
+- aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"""
        findings = await scan_diff_for_patterns(diff, "config.env")
        assert len(findings) >= 1
        assert any("AKIA" in f.get("code_snippet", "") or "AKIA" in f.get("title", "") for f in findings)

    @pytest.mark.asyncio
    async def test_github_token(self):
        diff = """+GITHUB_TOKEN = ghp_abc123def456ghi789jkl012mno345pqr678st"""
        findings = await scan_diff_for_patterns(diff, "ci.yml")
        assert len(findings) >= 1
        assert any("ghp_" in f.get("code_snippet", "") for f in findings)

    @pytest.mark.asyncio
    async def test_slack_token(self):
        diff = """+slack_bot_token: xoxb-EXAMPLE-1234567890-FAKE1234567890-TEST"""
        findings = await scan_diff_for_patterns(diff, "config.yml")
        assert len(findings) >= 1
        assert any("xoxb" in f.get("code_snippet", "") for f in findings)

    @pytest.mark.asyncio
    async def test_stripe_secret_key(self):
        diff = """+STRIPE_SECRET_KEY=ssk_test_EXAMPLE1234567890abcdefFAKE1234567890"""
        findings = await scan_diff_for_patterns(diff, ".env")
        assert len(findings) >= 1
        assert any("sk_live" in f.get("code_snippet", "") for f in findings)

    @pytest.mark.asyncio
    async def test_private_key_leak(self):
        diff = """+-----BEGIN RSA PRIVATE KEY-----
+MIIEpAIBAAKCAQEA1qB0l0jQvA8F0j6G9QxYZhS9dQkR8K3aHjYm7D2sW5Vh
+-----END RSA PRIVATE KEY-----"""
        findings = await scan_diff_for_patterns(diff, "cert.pem")
        assert len(findings) >= 1
        assert any("PRIVATE KEY" in f.get("title", "") for f in findings)

    @pytest.mark.asyncio
    async def test_openai_api_key(self):
        diff = """+openai.api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"""
        findings = await scan_diff_for_patterns(diff, "app.py")
        assert len(findings) >= 1
        assert any("OpenAI" in f.get("title", "") for f in findings)

    @pytest.mark.asyncio
    async def test_sql_injection_string_concat(self):
        diff = """+query = "SELECT * FROM users WHERE id = " + user_id
+cursor.execute(query)"""
        findings = await scan_diff_for_patterns(diff, "db.py")
        assert len(findings) >= 1
        assert any("SQL" in f.get("category", "").upper() or "SQL" in f.get("title", "").upper() for f in findings)

    @pytest.mark.asyncio
    async def test_sql_injection_fstring(self):
        diff = """+query = f"SELECT * FROM users WHERE email = '{email}'"
+db.execute(query)"""
        findings = await scan_diff_for_patterns(diff, "user.py")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_xss_inner_html(self):
        diff = """+document.getElementById("output").innerHTML = userInput;"""
        findings = await scan_diff_for_patterns(diff, "app.js")
        assert len(findings) >= 1
        assert any("innerHTML" in f.get("title", "") for f in findings)

    @pytest.mark.asyncio
    async def test_xss_react_dangerously(self):
        diff = """+<div dangerouslySetInnerHTML={{ __html: comment.body }} />"""
        findings = await scan_diff_for_patterns(diff, "Comment.tsx")
        assert len(findings) >= 1
        assert any("dangerouslySetInnerHTML" in f.get("code_snippet", "") for f in findings)

    @pytest.mark.asyncio
    async def test_path_traversal(self):
        diff = """+filepath = os.path.join("/var/www", user_input)"""
        findings = await scan_diff_for_patterns(diff, "files.py")
        assert len(findings) >= 1
        assert any("path" in f.get("category", "").lower() for f in findings)

    @pytest.mark.asyncio
    async def test_insecure_crypto_md5(self):
        diff = """+hashed = hashlib.md5(password.encode()).hexdigest()"""
        findings = await scan_diff_for_patterns(diff, "auth.py")
        assert len(findings) >= 1
        assert any("MD5" in f.get("title", "") for f in findings)

    @pytest.mark.asyncio
    async def test_insecure_pickle(self):
        diff = """+data = pickle.loads(untrusted_input)"""
        findings = await scan_diff_for_patterns(diff, "serialize.py")
        assert len(findings) >= 1
        assert any("pickle" in f.get("code_snippet", "").lower() for f in findings)

    @pytest.mark.asyncio
    async def test_eval_function(self):
        diff = """+result = eval(user_code)"""
        findings = await scan_diff_for_patterns(diff, "runner.py")
        assert len(findings) >= 1
        assert any("eval" in f.get("title", "").lower() for f in findings)

    @pytest.mark.asyncio
    async def test_hardcoded_password(self):
        diff = """+db_password = "superSecret123!" """
        findings = await scan_diff_for_patterns(diff, "config.py")
        assert len(findings) >= 1
        assert any("Password" in f.get("title", "") for f in findings)

    @pytest.mark.asyncio
    async def test_false_positive_example(self):
        diff = """+# Replace with your-api-key-here
+api_key = "your-api-key" """
        findings = await scan_diff_for_patterns(diff, "example.py")
        api_key_findings = [f for f in findings if "API" in f.get("category", "").upper()]
        assert len(api_key_findings) == 0

    @pytest.mark.asyncio
    async def test_ssrf_pattern(self):
        diff = """+response = requests.get(request.GET.get('url'))"""
        findings = await scan_diff_for_patterns(diff, "proxy.py")
        ssrf = [f for f in findings if "ssrf" in f.get("category", "").lower()]
        assert len(ssrf) >= 1

    @pytest.mark.asyncio
    async def test_gitlab_token(self):
        diff = """+GITLAB_TOKEN = 'glpat-ABCDEFGHIJ1234567890'"""
        findings = await scan_diff_for_patterns(diff, "deploy.yml")
        assert len(findings) >= 1
        assert any("GitLab" in f.get("title", "") for f in findings)

    @pytest.mark.asyncio
    async def test_jwt_secret(self):
        diff = """+JWT_SECRET = 'my-super-secret-key-that-should-not-be-hardcoded'"""
        findings = await scan_diff_for_patterns(diff, "auth.py")
        jwt = [f for f in findings if "JWT" in f.get("title", "").upper()]
        assert len(jwt) >= 1

    @pytest.mark.asyncio
    async def test_mongodb_connection_string(self):
        diff = """+MONGO_URI = 'mongodb+srv://admin:password123@cluster0.mongodb.net/myDB'"""
        findings = await scan_diff_for_patterns(diff, "database.py")
        mongo = [f for f in findings if "MongoDB" in f.get("title", "")]
        assert len(mongo) >= 1


class TestFalsePositiveFilter:
    def test_false_positive_example_key(self):
        assert is_false_positive("# Replace with your-api-key-here") is True

    def test_false_positive_sample(self):
        assert is_false_positive("sample_api_key = 'abc'") is True

    def test_false_positive_todo(self):
        assert is_false_positive("TODO: insert real password here") is True

    def test_actual_secret_not_filtered(self):
        assert is_false_positive("api_key = 'sk-proj-real-key-12345'") is False
        assert is_false_positive("password = 'RealCorrect-horse-battery-staple'") is False
