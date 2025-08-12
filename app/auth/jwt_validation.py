import os
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidSignatureError,
    InvalidTokenError,
)


class JWTConfig:
    """Configuration management for JWT validation."""

    def __init__(
        self,
        secret_env_var: str = "JWT_SECRET",  # noqa: S107
        algorithms: list[str] | None = None,  # noqa: S107
    ):
        self.secret_env_var = secret_env_var
        self.algorithms = algorithms or ["HS256"]

    def get_secret(self) -> str:
        """Get JWT secret from environment variable.

        Returns:
            JWT secret string

        Raises:
            HTTPException: 500 if secret not configured
        """
        secret = os.environ.get(self.secret_env_var)
        if not secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"{self.secret_env_var} not configured",
            )
        return secret


class JWTExceptionHandler:
    """Handles JWT-related exceptions and converts them to HTTP exceptions."""

    @staticmethod
    def handle_jwt_exception(exception: Exception) -> HTTPException:
        """Convert JWT exceptions to appropriate HTTP exceptions.

        Args:
            exception: JWT-related exception

        Returns:
            HTTPException with appropriate status and detail
        """
        if isinstance(exception, HTTPException):
            return exception
        if isinstance(exception, ExpiredSignatureError):
            return HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
            )
        if isinstance(exception, InvalidSignatureError):
            return HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token signature",
            )
        if isinstance(exception, (DecodeError, InvalidTokenError)):
            return HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format"
            )
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format"
        )


class JWTValidationService:
    """Service for JWT token validation."""

    def __init__(
        self, config: JWTConfig = None, exception_handler: JWTExceptionHandler = None
    ):
        self.config = config or JWTConfig()
        self.exception_handler = exception_handler or JWTExceptionHandler()

    def decode_token(self, token: str) -> dict[str, Any]:
        """Decode and verify JWT token.

        Args:
            token: JWT token string

        Returns:
            Decoded token payload

        Raises:
            HTTPException: For any validation errors
        """
        try:
            secret = self.config.get_secret()
            return jwt.decode(token, secret, algorithms=self.config.algorithms)
        except Exception as e:
            raise self.exception_handler.handle_jwt_exception(e) from e

    def validate_session_id(self, payload: dict[str, Any]) -> None:
        """Validate that session_id exists in token payload.

        Args:
            payload: Decoded JWT payload

        Raises:
            HTTPException: If session_id is missing
        """
        if "session_id" not in payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing session_id",
            )

    def validate_token(self, token: str) -> dict[str, Any]:
        """Validate JWT token and return decoded payload.

        Args:
            token: JWT token string

        Returns:
            Decoded and validated token payload

        Raises:
            HTTPException: For any validation errors
        """
        payload = self.decode_token(token)
        self.validate_session_id(payload)
        return payload


# Global instances for backward compatibility
_jwt_service = JWTValidationService()
security = HTTPBearer()


async def validate_jwt_token(token: str) -> dict[str, Any]:
    """
    Validate JWT token and return decoded payload.

    Args:
        token: JWT token string

    Returns:
        Decoded token payload

    Raises:
        HTTPException: 401 for invalid/expired tokens, 500 for config errors
    """
    return _jwt_service.validate_token(token)


async def get_current_session(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict[str, Any]:
    """
    Extract and validate JWT token from Authorization header.

    Args:
        credentials: Bearer token from Authorization header

    Returns:
        Decoded session data from token

    Raises:
        HTTPException: 401 for invalid authentication
    """
    if credentials.scheme != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme",
        )

    return await validate_jwt_token(credentials.credentials)
