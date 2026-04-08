"""Tests for asg.detectors."""

import pytest
from asg.detectors import detect, DetectorRegistry


class TestAWSKey:
    def test_aws_access_key_id_found(self):
        findings = detect("AKIAIOSFODNN7EXAMPLE")
        assert len(findings) == 1
        assert findings[0].label == "AWS Access Key ID"

    def test_aws_key_not_found(self):
        findings = detect("AKIAIOSFODNN7")
        assert len(findings) == 0


class TestGitHubToken:
    def test_github_token_found(self):
        findings = detect("ghp_abcdefghij1234567890abcdefghijklmnop")
        assert len(findings) == 1
        assert findings[0].label == "GitHub Token"

    def test_github_workflow_token(self):
        findings = detect("gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        assert len(findings) == 1
        assert findings[0].label == "GitHub Token"

    def test_github_token_not_found_short(self):
        findings = detect("ghp_abc123")
        assert len(findings) == 0  # too short


class TestSlackToken:
    def test_slack_bot_token_found(self):
        findings = detect("xoxb-fake12345678-fake12345678-fakeAbcdefGhijKlmnopQrstuvwx")
        assert len(findings) == 1
        assert findings[0].label == "Slack Token"

    def test_slack_user_token(self):
        findings = detect("xoxa-fake2345678901-fake2345678901-fakeAbcdefGhijKlmnopQrstuvwx")
        assert len(findings) == 1
        assert findings[0].label == "Slack Token"


class TestBearerToken:
    def test_bearer_token_found(self):
        findings = detect("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        assert any(f.label == "Generic Bearer Token" for f in findings)

    def test_bearer_token_case_insensitive(self):
        findings = detect("authorization: bearer super_secret_token_value_here")
        assert any(f.label == "Generic Bearer Token" for f in findings)


class TestJWT:
    def test_jwt_found(self):
        findings = detect("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        assert len(findings) == 1
        assert findings[0].label == "JWT Token"


class TestPEM:
    def test_rsa_private_key_found(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAL...\n-----END RSA PRIVATE KEY-----"
        findings = detect(pem)
        assert len(findings) == 1
        assert findings[0].label == "PEM Private Key"

    def test_ec_private_key_found(self):
        pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----"
        findings = detect(pem)
        assert len(findings) == 1
        assert findings[0].label == "PEM Private Key"

    def test_openssh_private_key_found(self):
        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nbase64...\n-----END OPENSSH PRIVATE KEY-----"
        findings = detect(pem)
        assert len(findings) == 1
        assert findings[0].label == "PEM Private Key"


class TestEnvSecret:
    def test_env_password_found(self):
        findings = detect('DB_PASSWORD="super_secret_12345"')
        assert any(f.label == ".env key=value secret" or f.label == "Generic Secret Word" for f in findings)

    def test_env_api_key_found(self):
        findings = detect('OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz')
        assert any(f.label == "Generic API Key (Bearer pattern)" for f in findings)


class TestLineNumbers:
    def test_line_number_correct(self):
        text = "line one\nline two\nAKIAIOSFODNN7EXAMPLE\nline four"
        findings = detect(text)
        aws = [f for f in findings if f.label == "AWS Access Key ID"][0]
        assert aws.line == 3


class TestDeduplication:
    def test_no_duplicate_overlapping(self):
        # Same token matched by two patterns should only appear once
        text = "ghp_abcdefghij1234567890abcdefghijklmnop"
        findings = detect(text)
        starts = [f.start for f in findings]
        assert len(starts) == len(set(starts)), "Overlapping findings should be deduplicated"


class TestFindingRedaction:
    def test_redact_preserves_length(self):
        text = "token=ghp_abcdef1234567890abcdefghijklmn"
        findings = detect(text)
        assert len(findings) == 1
        redacted = findings[0].redact(text, preserve_length=True)
        assert len(redacted) == len(text)
        assert "ghp_" not in redacted
        assert "***REDACTED***" not in redacted

    def test_redact_default(self):
        text = "token=ghp_abcdef1234567890abcdefghijklmn"
        findings = detect(text)
        redacted = findings[0].redact(text)
        assert "***REDACTED***" in redacted


class TestDiscordToken:
    def test_discord_bot_token(self):
        # Format: [A-Z][A-Za-z0-9]{22}.[A-Za-z0-9]{6}.[A-Za-z0-9]{25,}
        token = "MABCDEFGHIJKLMNOPQRSTUVWXYza.123456.ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        findings = detect(token)
        assert any(f.label == "Discord Bot Token" for f in findings)


class TestEmptyInput:
    def test_empty_string(self):
        findings = detect("")
        assert findings == []

    def test_clean_text(self):
        findings = detect("This is a clean log message with no secrets.")
        assert findings == []
