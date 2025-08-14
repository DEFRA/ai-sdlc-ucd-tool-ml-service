from logging import getLogger

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth.jwt_validation import extract_bearer_token, validate_token
from app.auth.public_endpoints import is_public_endpoint

logger = getLogger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip authentication for public endpoints
        if is_public_endpoint(request.url.path):
            logger.debug("Skipping auth for public endpoint: %s", request.url.path)
            return await call_next(request)

        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        token = extract_bearer_token(auth_header)

        # Validate token against Azure JWKS - will raise HTTPException if invalid
        decoded_token = validate_token(token)

        # Store the decoded token in request state for downstream use
        request.state.user = decoded_token

        logger.info("Valid Azure token provided for: %s", request.url.path)

        # Return success hello world response for valid tokens
        return JSONResponse(
            status_code=200, content={"message": "Hello World! Token is valid."}
        )
