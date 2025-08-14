"""JWKS validation for Azure AD tokens."""

import logging
import time
from typing import Optional

import httpx
import jwt
from fastapi import HTTPException
from jwt import PyJWKClient

from app.config import config

logger = logging.getLogger(__name__)

# Cache for JWKS client
_jwks_client: Optional[PyJWKClient] = None
_jwks_client_created_at: float = 0


def get_jwks_client() -> PyJWKClient:
    """Get or create cached JWKS client."""
    global _jwks_client, _jwks_client_created_at

    current_time = time.time()
    cache_expired = (
        current_time - _jwks_client_created_at
    ) > config.jwks_cache_ttl_seconds

    if not _jwks_client or cache_expired:
        jwks_url = f"{config.az_base_url}/{config.az_endpoint_jwks}"
        logger.info("Creating JWKS client for: %s", jwks_url)

        _jwks_client = PyJWKClient(
            jwks_url,
            cache_keys=True,
            max_cached_keys=16,
            lifespan=config.jwks_cache_max_age_seconds,
        )
        _jwks_client_created_at = current_time

    return _jwks_client


def validate_azure_token(token: str) -> dict:
    """
    Validate Azure AD JWT token against JWKS endpoint.

    Returns the decoded token payload if valid.
    Raises HTTPException with appropriate status code and message if invalid.
    """
    if not token:
        raise HTTPException(
            status_code=401,
            detail="No token provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Get JWKS client
        jwks_client = get_jwks_client()

        # Get signing key from token
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Decode and validate token
        # Azure AD tokens typically use RS256
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": False,  # Set to True and configure audience if needed
                "verify_iss": False,  # Set to True and configure issuer if needed
            },
        )

        logger.info("Token validated successfully")
        return decoded

    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        raise HTTPException(
            status_code=401,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except httpx.TimeoutException:
        logger.error("Timeout fetching JWKS")
        raise HTTPException(
            status_code=503,
            detail="Service temporarily unavailable - JWKS fetch timeout",
        ) from None
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid token: %s", str(e))
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except Exception as e:
        logger.error("Token validation error: %s", str(e))
        raise HTTPException(
            status_code=500,
            detail="Internal server error during token validation",
        ) from None
