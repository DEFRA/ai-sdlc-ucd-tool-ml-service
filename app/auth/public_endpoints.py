"""
Configuration for public endpoints that do not require authentication.
"""

PUBLIC_ENDPOINTS = {
    "/health",
    "/http",
}


def is_public_endpoint(path: str) -> bool:
    """
    Check if the given path is a public endpoint.

    Args:
        path: The request path to check

    Returns:
        True if the endpoint is public, False otherwise
    """
    return path in PUBLIC_ENDPOINTS
