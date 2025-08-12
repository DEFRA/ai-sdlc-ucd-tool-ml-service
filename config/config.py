"""Pydantic Settings Configuration following RULE-001 through RULE-006."""

import os
from typing import Optional

from pydantic import Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """Application settings following Pydantic Settings rules."""

    model_config = SettingsConfigDict(
        extra="forbid",  # RULE-003: No undefined fields allowed
        validate_default=True,  # RULE-003: Validate even default values
        validate_assignment=True,  # RULE-003: Validate on attribute assignment
        case_sensitive=False,  # RULE-003: Allow case-insensitive env vars
        env_file=f".env.{os.getenv('ENVIRONMENT', 'development')}",  # RULE-002: Environment-specific loading
    )

    # RULE-001: Nullable defaults with Field definitions and validation_alias
    environment: Optional[str] = Field(
        default=None,
        validation_alias="ENVIRONMENT",
        description="Application environment (development, test, production)",
    )

    port: Optional[int] = Field(
        default=None, validation_alias="PORT", description="Server port number"
    )

    mongo_uri: Optional[str] = Field(
        default=None, validation_alias="MONGO_URI", description="MongoDB connection URI"
    )

    mongo_database: Optional[str] = Field(
        default=None,
        validation_alias="MONGO_DATABASE",
        description="MongoDB database name",
    )

    mongo_truststore: Optional[str] = Field(
        default=None,
        validation_alias="MONGO_TRUSTSTORE",
        description="MongoDB truststore identifier",
    )

    http_proxy: Optional[HttpUrl] = Field(
        default=None, validation_alias="HTTP_PROXY", description="HTTP proxy URL"
    )

    enable_metrics: Optional[bool] = Field(
        default=None,
        validation_alias="ENABLE_METRICS",
        description="Enable application metrics collection",
    )

    tracing_header: Optional[str] = Field(
        default=None,
        validation_alias="TRACING_HEADER",
        description="HTTP header name for request tracing",
    )

    # Azure JWKS Configuration
    az_tenant_id: Optional[str] = Field(
        default=None,
        validation_alias="AZ_TENANT_ID",
        description="Azure tenant ID for JWKS validation",
    )

    az_base_url: Optional[HttpUrl] = Field(
        default=None,
        validation_alias="AZ_BASE_URL",
        description="Azure base URL for OIDC endpoints",
    )

    az_jwks_path: Optional[str] = Field(
        default=None,
        validation_alias="AZ_JWKS_PATH",
        description="Path to JWKS endpoint",
    )

    az_client_id: Optional[str] = Field(
        default=None,
        validation_alias="AZ_CLIENT_ID",
        description="Azure client ID for token validation",
    )

    jwks_cache_ttl_seconds: Optional[int] = Field(
        default=None,
        validation_alias="JWKS_CACHE_TTL_SECONDS",
        description="JWKS cache TTL in seconds",
    )

    jwks_cache_max_age_seconds: Optional[int] = Field(
        default=None,
        validation_alias="JWKS_CACHE_MAX_AGE_SECONDS",
        description="JWKS cache maximum age in seconds",
    )

    oidc_http_timeout_seconds: Optional[int] = Field(
        default=None,
        validation_alias="OIDC_HTTP_TIMEOUT_SECONDS",
        description="OIDC HTTP request timeout in seconds",
    )

    oidc_http_retries: Optional[int] = Field(
        default=None,
        validation_alias="OIDC_HTTP_RETRIES",
        description="OIDC HTTP request retry count",
    )

    @field_validator("environment")
    def validate_environment(cls, v: Optional[str]) -> Optional[str]:  # noqa: N805
        """Validate environment is one of the allowed values."""
        if v and v not in ["development", "test", "production"]:
            msg = "Environment must be one of: development, test, production"
            raise ValueError(msg)
        return v

    @field_validator("port")
    def validate_port(cls, v: Optional[int]) -> Optional[int]:  # noqa: N805
        """Validate port is in valid range."""
        if v is not None and (v < 1 or v > 65535):
            msg = "Port must be between 1 and 65535"
            raise ValueError(msg)
        return v

    @field_validator("az_tenant_id", "az_client_id")
    def validate_azure_ids(cls, v: Optional[str]) -> Optional[str]:  # noqa: N805
        """Validate Azure IDs are non-empty strings."""
        if v is not None and not v.strip():
            msg = "Azure tenant ID and client ID must be non-empty"
            raise ValueError(msg)
        return v

    @property
    def issuer(self) -> str:
        """Derive issuer from base URL and tenant ID."""
        if not self.az_base_url or not self.az_tenant_id:
            msg = "az_base_url and az_tenant_id required to generate issuer"
            raise ValueError(msg)
        base_url = str(self.az_base_url).rstrip("/")
        return f"{base_url}/{self.az_tenant_id}/v2.0"

    @property
    def jwks_url(self) -> str:
        """Compose JWKS URL from base URL, tenant ID, and JWKS path."""
        if not self.az_base_url or not self.az_tenant_id or not self.az_jwks_path:
            msg = "az_base_url, az_tenant_id, and az_jwks_path required to generate JWKS URL"
            raise ValueError(msg)
        base_url = str(self.az_base_url).rstrip("/")
        return f"{base_url}/{self.az_tenant_id}/{self.az_jwks_path}"

    @property
    def audience(self) -> str:
        """Audience equals client ID."""
        if not self.az_client_id:
            msg = "az_client_id required to generate audience"
            raise ValueError(msg)
        return self.az_client_id


# Global config instance
config = AppSettings()
