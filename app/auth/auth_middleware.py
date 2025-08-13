from logging import getLogger

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth.public_endpoints import is_public_endpoint

logger = getLogger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip authentication for public endpoints
        if is_public_endpoint(request.url.path):
            logger.debug("Skipping auth for public endpoint: %s", request.url.path)
            return await call_next(request)

        # For now, just log that auth would be required
        logger.info("Authentication required for: %s", request.url.path)

        # Check for Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            logger.warning("Missing Authorization header for: %s", request.url.path)
            return JSONResponse(
                status_code=401, content={"detail": "Authorization header required"}
            )

        if not auth_header.startswith("Bearer "):
            logger.warning(
                "Invalid Authorization header format for: %s", request.url.path
            )
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid authorization header format"},
            )

        # Extract JWT token (for now just log it)
        # token = auth_header[7:]  # Remove "Bearer " prefix - will be used for validation
        logger.info("JWT token present for: %s", request.url.path)

        return await call_next(request)
