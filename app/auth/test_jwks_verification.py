from unittest.mock import MagicMock, patch

import jwt
import pytest
from fastapi import HTTPException

from app.auth.jwks_verification import validate_azure_token


class TestValidateAzureToken:
    """Tests for Azure token validation."""

    def test_raises_exception_when_no_token(self):
        """Should raise HTTPException when no token provided."""
        with pytest.raises(HTTPException) as exc_info:
            validate_azure_token("")
        assert exc_info.value.status_code == 401
        assert "No token provided" in exc_info.value.detail

        with pytest.raises(HTTPException) as exc_info:
            validate_azure_token(None)
        assert exc_info.value.status_code == 401

    @patch("app.auth.jwks_verification.PyJWKClient")
    def test_returns_decoded_token_for_valid_token(self, mock_jwks_client):
        """Should return decoded token when token is valid."""
        # Mock the JWKS client
        mock_client_instance = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = "mock_key"
        mock_client_instance.get_signing_key_from_jwt.return_value = mock_signing_key
        mock_jwks_client.return_value = mock_client_instance

        # Mock jwt.decode to return valid decoded token
        with patch("app.auth.jwks_verification.jwt.decode") as mock_decode:
            expected_decoded = {"sub": "user123", "exp": 9999999999}
            mock_decode.return_value = expected_decoded

            result = validate_azure_token("valid.jwt.token")
            assert result == expected_decoded

    @patch("app.auth.jwks_verification.PyJWKClient")
    def test_raises_exception_for_expired_token(self, mock_jwks_client):
        """Should raise HTTPException when token is expired."""
        mock_client_instance = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = "mock_key"
        mock_client_instance.get_signing_key_from_jwt.return_value = mock_signing_key
        mock_jwks_client.return_value = mock_client_instance

        with patch("app.auth.jwks_verification.jwt.decode") as mock_decode:
            mock_decode.side_effect = jwt.ExpiredSignatureError("Token expired")

            with pytest.raises(HTTPException) as exc_info:
                validate_azure_token("expired.jwt.token")
            assert exc_info.value.status_code == 401
            assert "expired" in exc_info.value.detail

    @patch("app.auth.jwks_verification.PyJWKClient")
    def test_raises_exception_for_invalid_signature(self, mock_jwks_client):
        """Should raise HTTPException when token has invalid signature."""
        mock_client_instance = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = "mock_key"
        mock_client_instance.get_signing_key_from_jwt.return_value = mock_signing_key
        mock_jwks_client.return_value = mock_client_instance

        with patch("app.auth.jwks_verification.jwt.decode") as mock_decode:
            mock_decode.side_effect = jwt.InvalidSignatureError("Invalid signature")

            with pytest.raises(HTTPException) as exc_info:
                validate_azure_token("invalid.jwt.token")
            assert exc_info.value.status_code == 401
            assert "Invalid token" in exc_info.value.detail

    @patch("app.auth.jwks_verification.PyJWKClient")
    def test_raises_exception_on_jwks_fetch_error(self, mock_jwks_client):
        """Should raise HTTPException when JWKS fetch fails."""
        mock_client_instance = MagicMock()
        # Make get_signing_key_from_jwt raise a network error
        mock_client_instance.get_signing_key_from_jwt.side_effect = Exception(
            "Network error"
        )
        mock_jwks_client.return_value = mock_client_instance

        # Use a properly formatted JWT token (header.payload.signature)
        fake_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.fake_signature"

        with pytest.raises(HTTPException) as exc_info:
            validate_azure_token(fake_jwt)
        assert exc_info.value.status_code == 500
        assert "Internal server error" in exc_info.value.detail
