from typing import Optional

from pydantic import HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict()
    port: int = 8085
    mongo_uri: str = "mongodb://127.0.0.1:27017/"
    mongo_database: str = "ai-sdlc-ucd-tool-ml-service"
    mongo_truststore: str = "TRUSTSTORE_CDP_ROOT_CA"
    http_proxy: Optional[HttpUrl] = None
    enable_metrics: bool = False
    tracing_header: str = "x-cdp-request-id"
    az_base_url: HttpUrl = "https://fake-test-auth.example.com"
    az_endpoint_jwks: str = "test/jwks"
    jwks_cache_ttl_seconds: int = 999999
    jwks_cache_max_age_seconds: int = 999999
    oidc_http_timeout_seconds: int = 999


config = AppConfig()
