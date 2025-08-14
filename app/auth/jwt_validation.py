"""JWT validation module for Azure AD token authentication."""

import logging
from typing import Optional

from fastapi import HTTPException

from app.auth.jwks_verification import validate_azure_token

logger = logging.getLogger(__name__)


def extract_bearer_token(authorization_header: Optional[str]) -> str:
    """
    Extract Bearer token from Authorization header.

    Returns the token if valid Bearer header found.
    Raises HTTPException if header is missing or malformed.
    """
    if not authorization_header:
        raise HTTPException(
            status_code=401,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization_header.split(" ", 1)
    if len(parts) != 2:
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header format",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scheme, token = parts
    if scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization scheme - Bearer required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = token.strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Bearer token is empty",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token


def validate_token(token: Optional[str]) -> dict:
    """
    Validate token against Azure JWKS endpoint.

    Returns the decoded token payload if valid.
    Raises HTTPException if token is invalid or missing.
    """
    if not token:
        logger.debug("No token provided for validation")
        raise HTTPException(
            status_code=401,
            detail="No token provided for validation",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return validate_azure_token(token)
