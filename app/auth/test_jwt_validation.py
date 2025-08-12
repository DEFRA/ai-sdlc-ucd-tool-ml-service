import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.auth.jwt_validation import (
    JWTConfig,
    JWTExceptionHandler,
    JWTValidationService,
    get_current_session,
    validate_jwt_token,
)

# Only mark async tests with asyncio


class TestJWTValidation:
    """Test JWT validation for backend API authentication"""

    @pytest.fixture
    def valid_token_payload(self):
        """Valid JWT payload with session_id"""
        return {
            "session_id": "test-session-123",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }

    @pytest.fixture
    def valid_token(self, valid_token_payload):
        """Generate a valid JWT token"""
        secret = "test-jwt-secret"  # noqa: S105
        return jwt.encode(valid_token_payload, secret, algorithm="HS256")

    @pytest.fixture
    def expired_token(self):
        """Generate an expired JWT token"""
        secret = "test-jwt-secret"  # noqa: S105
        payload = {
            "session_id": "expired-session-123",
            "iat": datetime.now(timezone.utc) - timedelta(hours=2),
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        }
        return jwt.encode(payload, secret, algorithm="HS256")

    @pytest.fixture
    def invalid_signature_token(self, valid_token_payload):
        """Generate a token with invalid signature"""
        wrong_secret = "wrong-secret"  # noqa: S105
        return jwt.encode(valid_token_payload, wrong_secret, algorithm="HS256")

    @pytest.mark.asyncio
    async def test_validate_jwt_token_with_valid_token(self, valid_token):
        """
        Given a valid JWT token with correct signature
        When validate_jwt_token is called
        Then it should return the decoded payload with session_id
        """
        with patch.dict(os.environ, {"JWT_SECRET": "test-jwt-secret"}):
            result = await validate_jwt_token(valid_token)

            assert result is not None
            assert result["session_id"] == "test-session-123"
            assert "exp" in result
            assert "iat" in result

    @pytest.mark.asyncio
    async def test_validate_jwt_token_with_expired_token(self, expired_token):
        """
        Given an expired JWT token
        When validate_jwt_token is called
        Then it should raise HTTPException with 401 status
        """
        with patch.dict(os.environ, {"JWT_SECRET": "test-jwt-secret"}):
            with pytest.raises(HTTPException) as exc_info:
                await validate_jwt_token(expired_token)

            assert exc_info.value.status_code == 401
            assert exc_info.value.detail == "Token has expired"

    @pytest.mark.asyncio
    async def test_validate_jwt_token_with_invalid_signature(
        self, invalid_signature_token
    ):
        """
        Given a JWT token with invalid signature
        When validate_jwt_token is called
        Then it should raise HTTPException with 401 status
        """
        with patch.dict(os.environ, {"JWT_SECRET": "test-jwt-secret"}):
            with pytest.raises(HTTPException) as exc_info:
                await validate_jwt_token(invalid_signature_token)

            assert exc_info.value.status_code == 401
            assert exc_info.value.detail == "Invalid token signature"

    @pytest.mark.asyncio
    async def test_validate_jwt_token_with_malformed_token(self):
        """
        Given a malformed JWT token
        When validate_jwt_token is called
        Then it should raise HTTPException with 401 status
        """
        malformed_token = "not.a.valid.jwt.token"  # noqa: S105

        with patch.dict(os.environ, {"JWT_SECRET": "test-jwt-secret"}):
            with pytest.raises(HTTPException) as exc_info:
                await validate_jwt_token(malformed_token)

            assert exc_info.value.status_code == 401
            assert exc_info.value.detail == "Invalid token format"

    @pytest.mark.asyncio
    async def test_validate_jwt_token_without_session_id(self):
        """
        Given a JWT token without session_id claim
        When validate_jwt_token is called
        Then it should raise HTTPException with 401 status
        """
        secret = "test-jwt-secret"  # noqa: S105
        payload = {
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            # Missing session_id
        }
        token = jwt.encode(payload, secret, algorithm="HS256")

        with patch.dict(os.environ, {"JWT_SECRET": "test-jwt-secret"}):
            with pytest.raises(HTTPException) as exc_info:
                await validate_jwt_token(token)

            assert exc_info.value.status_code == 401
            assert exc_info.value.detail == "Invalid token: missing session_id"

    @pytest.mark.asyncio
    async def test_get_current_session_with_bearer_token(self, valid_token):
        """
        Given a request with valid Bearer token in Authorization header
        When get_current_session is called
        Then it should extract and validate the token, returning session data
        """
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=valid_token
        )

        with patch.dict(os.environ, {"JWT_SECRET": "test-jwt-secret"}):
            result = await get_current_session(credentials)

            assert result is not None
            assert result["session_id"] == "test-session-123"

    @pytest.mark.asyncio
    async def test_get_current_session_without_bearer_scheme(self, valid_token):
        """
        Given a request with non-Bearer authorization scheme
        When get_current_session is called
        Then it should raise HTTPException with 401 status
        """
        credentials = HTTPAuthorizationCredentials(
            scheme="Basic",  # Wrong scheme
            credentials=valid_token,
        )

        with patch.dict(os.environ, {"JWT_SECRET": "test-jwt-secret"}):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_session(credentials)

            assert exc_info.value.status_code == 401
            assert exc_info.value.detail == "Invalid authentication scheme"

    @pytest.mark.asyncio
    async def test_missing_jwt_secret_env_var(self, valid_token):
        """
        Given JWT_SECRET environment variable is not set
        When validate_jwt_token is called
        Then it should raise HTTPException with 500 status
        """
        # Ensure JWT_SECRET is not in environment
        env_copy = os.environ.copy()
        if "JWT_SECRET" in env_copy:
            del env_copy["JWT_SECRET"]

        with patch.dict(os.environ, env_copy, clear=True):
            with pytest.raises(HTTPException) as exc_info:
                await validate_jwt_token(valid_token)

            assert exc_info.value.status_code == 500
            assert exc_info.value.detail == "JWT_SECRET not configured"


class TestJWTConfig:
    """Test JWT configuration management"""

    def test_jwt_config_default_initialization(self):
        """Test that JWTConfig initializes with correct defaults"""
        config = JWTConfig()

        assert config.secret_env_var == "JWT_SECRET"  # noqa: S105
        assert config.algorithms == ["HS256"]

    def test_jwt_config_custom_initialization(self):
        """Test that JWTConfig can be initialized with custom values"""
        config = JWTConfig(
            secret_env_var="CUSTOM_SECRET",  # noqa: S106
            algorithms=["HS512", "RS256"],
        )

        assert config.secret_env_var == "CUSTOM_SECRET"  # noqa: S105
        assert config.algorithms == ["HS512", "RS256"]

    def test_get_secret_success(self):
        """Test getting secret from environment successfully"""
        config = JWTConfig()

        with patch.dict(os.environ, {"JWT_SECRET": "test-secret"}):
            secret = config.get_secret()
            assert secret == "test-secret"  # noqa: S105

    def test_get_secret_missing_env_var(self):
        """Test getting secret when environment variable is missing"""
        config = JWTConfig()

        env_copy = os.environ.copy()
        if "JWT_SECRET" in env_copy:
            del env_copy["JWT_SECRET"]

        with patch.dict(os.environ, env_copy, clear=True):
            with pytest.raises(HTTPException) as exc_info:
                config.get_secret()

            assert exc_info.value.status_code == 500
            assert exc_info.value.detail == "JWT_SECRET not configured"

    def test_get_secret_custom_env_var(self):
        """Test getting secret from custom environment variable"""
        config = JWTConfig(secret_env_var="CUSTOM_SECRET")  # noqa: S106

        with patch.dict(os.environ, {"CUSTOM_SECRET": "custom-secret"}):
            secret = config.get_secret()
            assert secret == "custom-secret"  # noqa: S105


class TestJWTExceptionHandler:
    """Test JWT exception handling"""

    def test_handle_http_exception_passthrough(self):
        """Test that HTTPException is passed through unchanged"""
        handler = JWTExceptionHandler()
        original_exception = HTTPException(status_code=401, detail="Test error")

        result = handler.handle_jwt_exception(original_exception)

        assert result is original_exception

    def test_handle_expired_signature_error(self):
        """Test handling of ExpiredSignatureError"""
        handler = JWTExceptionHandler()
        exception = jwt.ExpiredSignatureError("Token expired")

        result = handler.handle_jwt_exception(exception)

        assert isinstance(result, HTTPException)
        assert result.status_code == 401
        assert result.detail == "Token has expired"

    def test_handle_invalid_signature_error(self):
        """Test handling of InvalidSignatureError"""
        handler = JWTExceptionHandler()
        exception = jwt.InvalidSignatureError("Invalid signature")

        result = handler.handle_jwt_exception(exception)

        assert isinstance(result, HTTPException)
        assert result.status_code == 401
        assert result.detail == "Invalid token signature"

    def test_handle_decode_error(self):
        """Test handling of DecodeError"""
        handler = JWTExceptionHandler()
        exception = jwt.DecodeError("Decode failed")

        result = handler.handle_jwt_exception(exception)

        assert isinstance(result, HTTPException)
        assert result.status_code == 401
        assert result.detail == "Invalid token format"

    def test_handle_invalid_token_error(self):
        """Test handling of InvalidTokenError"""
        handler = JWTExceptionHandler()
        exception = jwt.InvalidTokenError("Invalid token")

        result = handler.handle_jwt_exception(exception)

        assert isinstance(result, HTTPException)
        assert result.status_code == 401
        assert result.detail == "Invalid token format"

    def test_handle_generic_exception(self):
        """Test handling of generic exceptions"""
        handler = JWTExceptionHandler()
        exception = ValueError("Some error")

        result = handler.handle_jwt_exception(exception)

        assert isinstance(result, HTTPException)
        assert result.status_code == 401
        assert result.detail == "Invalid token format"


class TestJWTValidationService:
    """Test JWT validation service"""

    @pytest.fixture
    def service(self):
        """Create JWT validation service with test configuration"""
        config = JWTConfig()
        return JWTValidationService(config=config)

    @pytest.fixture
    def valid_token_payload(self):
        """Valid JWT payload with session_id"""
        return {
            "session_id": "test-session-123",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }

    @pytest.fixture
    def valid_token(self, valid_token_payload):
        """Generate a valid JWT token"""
        secret = "test-jwt-secret"  # noqa: S105
        return jwt.encode(valid_token_payload, secret, algorithm="HS256")

    def test_service_initialization_with_defaults(self):
        """Test service initializes with default config and handler"""
        service = JWTValidationService()

        assert isinstance(service.config, JWTConfig)
        assert isinstance(service.exception_handler, JWTExceptionHandler)

    def test_service_initialization_with_custom_components(self):
        """Test service initializes with custom config and handler"""
        config = JWTConfig(secret_env_var="CUSTOM_SECRET")  # noqa: S106
        handler = JWTExceptionHandler()
        service = JWTValidationService(config=config, exception_handler=handler)

        assert service.config is config
        assert service.exception_handler is handler

    def test_decode_token_success(self, service, valid_token):
        """Test successful token decoding"""
        with patch.dict(os.environ, {"JWT_SECRET": "test-jwt-secret"}):
            payload = service.decode_token(valid_token)

            assert payload["session_id"] == "test-session-123"
            assert "iat" in payload
            assert "exp" in payload

    def test_decode_token_invalid_secret(self, service, valid_token):
        """Test token decoding with wrong secret"""
        with patch.dict(os.environ, {"JWT_SECRET": "wrong-secret"}):
            with pytest.raises(HTTPException) as exc_info:
                service.decode_token(valid_token)

            assert exc_info.value.status_code == 401
            assert exc_info.value.detail == "Invalid token signature"

    def test_validate_session_id_success(self, service):
        """Test successful session_id validation"""
        payload = {"session_id": "test-session-123", "other": "data"}

        # Should not raise exception
        service.validate_session_id(payload)

    def test_validate_session_id_missing(self, service):
        """Test session_id validation when missing"""
        payload = {"other": "data"}

        with pytest.raises(HTTPException) as exc_info:
            service.validate_session_id(payload)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid token: missing session_id"

    def test_validate_token_success(self, service, valid_token):
        """Test complete token validation success"""
        with patch.dict(os.environ, {"JWT_SECRET": "test-jwt-secret"}):
            payload = service.validate_token(valid_token)

            assert payload["session_id"] == "test-session-123"
            assert "iat" in payload
            assert "exp" in payload

    def test_validate_token_missing_session_id(self, service):
        """Test token validation when session_id is missing"""
        secret = "test-jwt-secret"  # noqa: S105
        payload_without_session = {
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        token = jwt.encode(payload_without_session, secret, algorithm="HS256")

        with patch.dict(os.environ, {"JWT_SECRET": "test-jwt-secret"}):
            with pytest.raises(HTTPException) as exc_info:
                service.validate_token(token)

            assert exc_info.value.status_code == 401
            assert exc_info.value.detail == "Invalid token: missing session_id"
