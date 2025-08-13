"""JWT validation module for Azure AD token authentication."""

import logging
from typing import Optional

from app.auth.jwks_verification import validate_azure_token

logger = logging.getLogger(__name__)


def extract_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
    """
    Extract Bearer token from Authorization header.

    Returns None if no valid Bearer token found, otherwise returns the token.
    """
    if not authorization_header:
        return None

    parts = authorization_header.split(None, 1)
    if len(parts) != 2:
        return None

    scheme, token = parts
    if scheme.lower() != "bearer":
        return None

    token = token.strip()
    return token if token else None


def validate_token(token: Optional[str]) -> bool:
    """
    Validate token against Azure JWKS endpoint.

    Returns True if token is valid, False otherwise.
    """
    if not token:
        logger.debug("No token provided for validation")
        return False

    return validate_azure_token(token)
