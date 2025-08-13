from unittest.mock import MagicMock, patch

import jwt

from app.auth.jwks_verification import validate_azure_token


class TestValidateAzureToken:
    """Tests for Azure token validation."""

    def test_returns_false_when_no_token(self):
        """Should return False when no token provided."""
        assert validate_azure_token("") is False
        assert validate_azure_token(None) is False

    @patch("app.auth.jwks_verification.PyJWKClient")
    def test_returns_true_for_valid_token(self, mock_jwks_client):
        """Should return True when token is valid."""
        # Mock the JWKS client
        mock_client_instance = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = "mock_key"
        mock_client_instance.get_signing_key_from_jwt.return_value = mock_signing_key
        mock_jwks_client.return_value = mock_client_instance

        # Mock jwt.decode to return valid decoded token
        with patch("app.auth.jwks_verification.jwt.decode") as mock_decode:
            mock_decode.return_value = {"sub": "user123", "exp": 9999999999}

            result = validate_azure_token("valid.jwt.token")
            assert result is True

    @patch("app.auth.jwks_verification.PyJWKClient")
    def test_returns_false_for_expired_token(self, mock_jwks_client):
        """Should return False when token is expired."""
        mock_client_instance = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = "mock_key"
        mock_client_instance.get_signing_key_from_jwt.return_value = mock_signing_key
        mock_jwks_client.return_value = mock_client_instance

        with patch("app.auth.jwks_verification.jwt.decode") as mock_decode:
            mock_decode.side_effect = jwt.ExpiredSignatureError("Token expired")

            result = validate_azure_token("expired.jwt.token")
            assert result is False

    @patch("app.auth.jwks_verification.PyJWKClient")
    def test_returns_false_for_invalid_signature(self, mock_jwks_client):
        """Should return False when token has invalid signature."""
        mock_client_instance = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = "mock_key"
        mock_client_instance.get_signing_key_from_jwt.return_value = mock_signing_key
        mock_jwks_client.return_value = mock_client_instance

        with patch("app.auth.jwks_verification.jwt.decode") as mock_decode:
            mock_decode.side_effect = jwt.InvalidSignatureError("Invalid signature")

            result = validate_azure_token("invalid.jwt.token")
            assert result is False

    @patch("app.auth.jwks_verification.PyJWKClient")
    def test_returns_false_on_jwks_fetch_error(self, mock_jwks_client):
        """Should return False when JWKS fetch fails."""
        mock_jwks_client.side_effect = Exception("Network error")

        result = validate_azure_token("any.jwt.token")
        assert result is False
