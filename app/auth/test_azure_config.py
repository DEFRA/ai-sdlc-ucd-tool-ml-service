import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from config.config import AppSettings


class TestAppSettings:
    """Test Azure JWKS configuration for F1.S1: Configure Azure endpoints and JWKS composition"""

    def test_config_derives_issuer_from_base_url_and_tenant_id(self):
        """
        Given AZ_BASE_URL, AZ_TENANT_ID are set
        When the config is initialized
        Then it derives the issuer as {AZ_BASE_URL}/{AZ_TENANT_ID}/v2.0
        """
        env_vars = {
            "AZ_BASE_URL": "https://login.microsoftonline.com",
            "AZ_TENANT_ID": "test-tenant-id",
            "AZ_JWKS_PATH": "discovery/v2.0/keys",
            "AZ_CLIENT_ID": "test-client-id",
        }

        with patch.dict(os.environ, env_vars):
            config = AppSettings()

            expected_issuer = "https://login.microsoftonline.com/test-tenant-id/v2.0"
            assert config.issuer == expected_issuer

    def test_config_composes_jwks_url_from_components(self):
        """
        Given AZ_BASE_URL, AZ_TENANT_ID, AZ_JWKS_PATH are set
        When the config is initialized
        Then it composes the JWKS URL as {AZ_BASE_URL}/{AZ_TENANT_ID}/{AZ_JWKS_PATH}
        """
        env_vars = {
            "AZ_BASE_URL": "https://login.microsoftonline.com",
            "AZ_TENANT_ID": "test-tenant-id",
            "AZ_JWKS_PATH": "discovery/v2.0/keys",
            "AZ_CLIENT_ID": "test-client-id",
        }

        with patch.dict(os.environ, env_vars):
            config = AppSettings()

            expected_jwks_url = (
                "https://login.microsoftonline.com/test-tenant-id/discovery/v2.0/keys"
            )
            assert config.jwks_url == expected_jwks_url

    def test_config_with_environment_file_development(self):
        """
        Given ENVIRONMENT=development is set
        When the config is initialized
        Then it loads values from .env.development file
        """
        env_vars = {
            "ENVIRONMENT": "development",
            "AZ_TENANT_ID": "test-tenant-id",
            "AZ_CLIENT_ID": "test-client-id",
        }

        with patch.dict(os.environ, env_vars):
            # Note: In real usage, this would load from config/.env.development
            # For testing, we're just verifying the config accepts these values
            config = AppSettings()

            assert config.environment == "development"
            assert config.az_tenant_id == "test-tenant-id"
            assert config.az_client_id == "test-client-id"

    def test_config_issuer_property_requires_base_url_and_tenant(self):
        """
        Given AZ_BASE_URL or AZ_TENANT_ID is missing
        When accessing the issuer property
        Then it raises ValueError
        """
        env_vars = {"AZ_CLIENT_ID": "test-client-id"}

        with patch.dict(os.environ, env_vars, clear=True):
            config = AppSettings()

            with pytest.raises(
                ValueError, match="az_base_url and az_tenant_id required"
            ):
                _ = config.issuer

    def test_config_jwks_url_property_requires_all_components(self):
        """
        Given any of AZ_BASE_URL, AZ_TENANT_ID, or AZ_JWKS_PATH is missing
        When accessing the jwks_url property
        Then it raises ValueError
        """
        env_vars = {
            "AZ_TENANT_ID": "test-tenant-id",
            "AZ_CLIENT_ID": "test-client-id",
            # Missing AZ_BASE_URL and AZ_JWKS_PATH
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = AppSettings()

            with pytest.raises(
                ValueError, match="az_base_url, az_tenant_id, and az_jwks_path required"
            ):
                _ = config.jwks_url

    def test_config_operational_values_from_env(self):
        """
        Given operational values are set via environment variables
        When the config is initialized
        Then they are loaded correctly
        """
        env_vars = {
            "AZ_TENANT_ID": "test-tenant-id",
            "AZ_CLIENT_ID": "test-client-id",
            "JWKS_CACHE_TTL_SECONDS": "3600",
            "JWKS_CACHE_MAX_AGE_SECONDS": "86400",
            "OIDC_HTTP_TIMEOUT_SECONDS": "5",
            "OIDC_HTTP_RETRIES": "2",
        }

        with patch.dict(os.environ, env_vars):
            config = AppSettings()

            assert config.jwks_cache_ttl_seconds == 3600
            assert config.jwks_cache_max_age_seconds == 86400
            assert config.oidc_http_timeout_seconds == 5
            assert config.oidc_http_retries == 2

    def test_config_properties_are_computed_correctly(self):
        """
        Given different base URLs and paths
        When the config is initialized
        Then issuer and JWKS URL are computed correctly
        """
        env_vars = {
            "AZ_BASE_URL": "https://custom-login.example.com",
            "AZ_TENANT_ID": "my-tenant",
            "AZ_JWKS_PATH": "oauth2/v2.0/keys",
            "AZ_CLIENT_ID": "my-client",
        }

        with patch.dict(os.environ, env_vars):
            config = AppSettings()

            assert config.issuer == "https://custom-login.example.com/my-tenant/v2.0"
            assert (
                config.jwks_url
                == "https://custom-login.example.com/my-tenant/oauth2/v2.0/keys"
            )

    def test_config_validates_base_url_format(self):
        """
        Given an invalid AZ_BASE_URL format
        When the config is initialized
        Then it fails with a validation error
        """
        env_vars = {
            "AZ_BASE_URL": "not-a-valid-url",  # Invalid URL format
            "AZ_TENANT_ID": "test-tenant-id",
            "AZ_JWKS_PATH": "discovery/v2.0/keys",
            "AZ_CLIENT_ID": "test-client-id",
        }

        with patch.dict(os.environ, env_vars):
            with pytest.raises(ValidationError) as exc_info:
                AppSettings()

            error_str = str(exc_info.value)
            assert "az_base_url" in error_str.lower()

    def test_config_audience_equals_client_id(self):
        """
        Given AZ_CLIENT_ID is set
        When the config is initialized
        Then the audience property equals the client ID
        """
        env_vars = {
            "AZ_TENANT_ID": "test-tenant-id",
            "AZ_CLIENT_ID": "my-application-client-id",
        }

        with patch.dict(os.environ, env_vars):
            config = AppSettings()

            assert config.audience == "my-application-client-id"
            assert config.audience == config.az_client_id

    def test_config_audience_property_requires_client_id(self):
        """
        Given AZ_CLIENT_ID is not set
        When accessing the audience property
        Then it raises ValueError
        """
        env_vars = {"AZ_TENANT_ID": "test-tenant-id"}

        with patch.dict(os.environ, env_vars, clear=True):
            config = AppSettings()

            with pytest.raises(ValueError, match="az_client_id required"):
                _ = config.audience

    def test_config_validates_port_range(self):
        """
        Given PORT is set to an invalid value
        When the config is initialized
        Then it fails with a validation error
        """
        env_vars = {
            "PORT": "99999"  # Invalid port
        }

        with patch.dict(os.environ, env_vars):
            with pytest.raises(ValidationError) as exc_info:
                AppSettings()

            error_str = str(exc_info.value)
            assert "port" in error_str.lower()

    def test_config_validates_environment_value(self):
        """
        Given ENVIRONMENT is set to an invalid value
        When the config is initialized
        Then it fails with a validation error
        """
        env_vars = {"ENVIRONMENT": "invalid-env"}

        with patch.dict(os.environ, env_vars):
            with pytest.raises(ValidationError) as exc_info:
                AppSettings()

            error_str = str(exc_info.value)
            assert "environment" in error_str.lower()
