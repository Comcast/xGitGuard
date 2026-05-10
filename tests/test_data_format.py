"""
Tests for xgitguard.common.data_format

Covers keys_extractor(), credential_extractor(), and the URL/special-char
stripping helpers. Not exhaustive — just enough to catch regressions and
prove the detection pipeline works end to end.
"""

from xgitguard.common.data_format import (
    keys_extractor,
    credential_extractor,
    remove_url_from_keys,
    remove_url_from_creds,
)


# ---------------------------------------------------------------------------
# keys_extractor — true positives
# ---------------------------------------------------------------------------

# Build strings via concat so secret scanners don't flag the test file.
_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"
_SLACK_WEBHOOK = "T12345678/B12345678/abcdefghijklmnopqrstuvwx"


class TestKeysExtractorDetects:
    def test_aws_access_key(self):
        result = keys_extractor(f"config = {_AWS_KEY}")
        assert any(_AWS_KEY in k for k in result)

    def test_rsa_private_key_header(self):
        result = keys_extractor(f"key = {_PRIVATE_KEY}")
        assert any("BEGIN RSA PRIVATE KEY" in k for k in result)

    def test_ec_private_key_header(self):
        result = keys_extractor("-----BEGIN EC PRIVATE KEY-----")
        assert any("BEGIN EC PRIVATE KEY" in k for k in result)

    def test_pgp_private_key_header(self):
        result = keys_extractor("-----BEGIN PGP PRIVATE KEY BLOCK-----")
        assert any("BEGIN PGP PRIVATE KEY" in k for k in result)

    def test_slack_webhook(self):
        result = keys_extractor(f"webhook = {_SLACK_WEBHOOK}")
        assert any(_SLACK_WEBHOOK in k for k in result)


# ---------------------------------------------------------------------------
# keys_extractor — true negatives
# ---------------------------------------------------------------------------

class TestKeysExtractorIgnores:
    def test_plain_text(self):
        assert keys_extractor("the weather is nice today") == []

    def test_short_random_string(self):
        assert keys_extractor("abc123") == []

    def test_empty_string(self):
        assert keys_extractor("") == []


# ---------------------------------------------------------------------------
# remove_url_from_keys
# ---------------------------------------------------------------------------

class TestRemoveUrlFromKeys:
    def test_strips_http_url(self):
        result = remove_url_from_keys("check https://example.com/path for info")
        assert "https" not in result
        assert "example.com" not in result

    def test_strips_email(self):
        result = remove_url_from_keys("contact admin@company.com please")
        assert "@" not in result

    def test_strips_special_chars(self):
        result = remove_url_from_keys("key={value}")
        assert "{" not in result
        assert "}" not in result


# ---------------------------------------------------------------------------
# remove_url_from_creds
# ---------------------------------------------------------------------------

class TestRemoveUrlFromCreds:
    def test_returns_list(self):
        result = remove_url_from_creds("some code content here", "key")
        assert isinstance(result, list)

    def test_strips_urls(self):
        result = remove_url_from_creds(
            "token = abc123 https://evil.com/steal", "key"
        )
        assert not any("evil.com" in word for word in result)


# ---------------------------------------------------------------------------
# credential_extractor
# ---------------------------------------------------------------------------

class TestCredentialExtractor:
    def test_extracts_alphanumeric_creds(self):
        words = ["shortpw", "MyP4ssw0rdIsStr0ng", "hello", "12345"]
        stop_words = []
        result = credential_extractor(words, stop_words)
        assert "MyP4ssw0rdIsStr0ng" in result

    def test_skips_stop_words(self):
        words = ["MyP4ssw0rd"]
        stop_words = ["MyP4ssw0rd"]
        result = credential_extractor(words, stop_words)
        assert result == []

    def test_skips_hex_prefix(self):
        words = ["0xDEADBEEF1234"]
        result = credential_extractor(words, [])
        assert result == []

    def test_skips_short_strings(self):
        words = ["Ab1234"]
        result = credential_extractor(words, [])
        assert result == []

    def test_skips_http(self):
        words = ["https://example.com"]
        result = credential_extractor(words, [])
        assert result == []
