"""Tests for JWT validation module - BDD focused."""

from unittest.mock import patch

from app.auth.jwt_validation import extract_bearer_token, validate_token


class TestExtractBearerToken:
    """Tests for extracting Bearer tokens from Authorization headers."""

    def test_extracts_valid_bearer_token(self):
        """Should extract token when valid Bearer header provided."""
        extracted = extract_bearer_token("Bearer this-is-a-test")
        assert extracted == "this-is-a-test"

    def test_returns_none_when_no_header(self):
        """Should return None when no header provided."""
        assert extract_bearer_token(None) is None
        assert extract_bearer_token("") is None

    def test_returns_none_for_non_bearer_scheme(self):
        """Should return None when scheme is not Bearer."""
        assert extract_bearer_token("Basic dXNlcjpwYXNz") is None
        assert extract_bearer_token("Digest realm=example") is None

    def test_returns_none_for_malformed_header(self):
        """Should return None when header is malformed."""
        assert extract_bearer_token("Bearer") is None
        assert extract_bearer_token("JustAToken") is None
        assert extract_bearer_token("Bearer    ") is None

    def test_handles_case_insensitive_bearer(self):
        """Should handle Bearer in any case."""
        assert extract_bearer_token("bearer token123") == "token123"
        assert extract_bearer_token("BEARER token456") == "token456"
        assert extract_bearer_token("BeArEr token789") == "token789"


class TestValidateToken:
    """Tests for token validation."""

    @patch("app.auth.jwt_validation.validate_azure_token")
    def test_delegates_to_azure_validator(self, mock_azure_validate):
        """Should delegate validation to Azure validator."""
        mock_azure_validate.return_value = True

        result = validate_token("test-token")

        assert result is True
        mock_azure_validate.assert_called_once_with("test-token")

    def test_no_token_returns_false(self):
        """Should return False when no token provided."""
        assert validate_token(None) is False
        assert validate_token("") is False
