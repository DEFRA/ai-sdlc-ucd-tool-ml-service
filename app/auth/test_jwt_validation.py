"""Tests for JWT validation module - BDD focused."""

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.auth.jwt_validation import extract_bearer_token, validate_token


class TestExtractBearerToken:
    """Tests for extracting Bearer tokens from Authorization headers."""

    def test_extracts_valid_bearer_token(self):
        """Should extract token when valid Bearer header provided."""
        extracted = extract_bearer_token("Bearer this-is-a-test")
        assert extracted == "this-is-a-test"

    def test_raises_exception_when_no_header(self):
        """Should raise HTTPException when no header provided."""
        with pytest.raises(HTTPException) as exc_info:
            extract_bearer_token(None)
        assert exc_info.value.status_code == 401
        assert "Authorization header required" in exc_info.value.detail

        with pytest.raises(HTTPException) as exc_info:
            extract_bearer_token("")
        assert exc_info.value.status_code == 401

    def test_raises_exception_for_non_bearer_scheme(self):
        """Should raise HTTPException when scheme is not Bearer."""
        with pytest.raises(HTTPException) as exc_info:
            extract_bearer_token("Basic dXNlcjpwYXNz")
        assert exc_info.value.status_code == 401
        assert "Bearer required" in exc_info.value.detail

        with pytest.raises(HTTPException) as exc_info:
            extract_bearer_token("Digest realm=example")
        assert exc_info.value.status_code == 401

    def test_raises_exception_for_malformed_header(self):
        """Should raise HTTPException when header is malformed."""
        with pytest.raises(HTTPException) as exc_info:
            extract_bearer_token("Bearer")
        assert exc_info.value.status_code == 401
        assert "Invalid authorization header format" in exc_info.value.detail

        with pytest.raises(HTTPException) as exc_info:
            extract_bearer_token("JustAToken")
        assert exc_info.value.status_code == 401
        assert "Invalid authorization header format" in exc_info.value.detail

        with pytest.raises(HTTPException) as exc_info:
            extract_bearer_token("Bearer    ")
        assert exc_info.value.status_code == 401
        assert "Bearer token is empty" in exc_info.value.detail

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
        mock_decoded = {"sub": "user123", "exp": 9999999999}
        mock_azure_validate.return_value = mock_decoded

        result = validate_token("test-token")

        assert result == mock_decoded
        mock_azure_validate.assert_called_once_with("test-token")

    def test_no_token_raises_exception(self):
        """Should raise HTTPException when no token provided."""
        with pytest.raises(HTTPException) as exc_info:
            validate_token(None)
        assert exc_info.value.status_code == 401
        assert "No token provided" in exc_info.value.detail

        with pytest.raises(HTTPException) as exc_info:
            validate_token("")
        assert exc_info.value.status_code == 401
