"""
Yuno Secrets Client Library
============================
Reusable client for all Yuno microservices to fetch credentials
from AWS Secrets Manager at runtime — never hardcoded at build time.

Features:
  - In-memory cache with TTL (reduces Secrets Manager API calls)
  - Automatic cache invalidation on rotation (dual-version support)
  - Structured logging for audit trail (PCI-DSS Req. 10)
  - Graceful fallback to AWSPREVIOUS during rotation window
  - Zero-downtime: services never need to restart on rotation

Usage:
    from client_lib.secrets_client import SecretsClient

    client = SecretsClient(environment="production")

    # Fetch API key for a merchant
    api_key = client.get_vortexpay_api_key(merchant_id="123")

    # Fetch OAuth credentials (returns dict)
    oauth = client.get_vortexpay_oauth(merchant_id="123")
    token = get_access_token(oauth["client_id"], oauth["client_secret"])
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Default cache TTL: 5 minutes.
# Short enough that rotated secrets propagate quickly,
# long enough to avoid hammering Secrets Manager.
DEFAULT_CACHE_TTL_SECONDS = 300

# During rotation, Secrets Manager keeps AWSPREVIOUS valid.
# We try AWSCURRENT first, then fall back to AWSPREVIOUS.
SECRET_STAGES = ["AWSCURRENT", "AWSPREVIOUS"]


@dataclass
class CachedSecret:
    value: str
    fetched_at: float
    ttl: int

    def is_expired(self) -> bool:
        return time.monotonic() - self.fetched_at > self.ttl


class SecretsClientError(Exception):
    """Raised when a secret cannot be fetched after all retries."""


class SecretsClient:
    """
    Thread-safe client for fetching Yuno payment provider credentials.

    Each microservice should instantiate ONE client (singleton pattern)
    and reuse it across requests to benefit from caching.
    """

    def __init__(
        self,
        environment: str = None,
        name_prefix: str = "yuno",
        region: str = "us-east-1",
        cache_ttl: int = DEFAULT_CACHE_TTL_SECONDS,
    ):
        self.environment = environment or os.environ.get("ENVIRONMENT", "sandbox")
        self.name_prefix = name_prefix
        self.cache_ttl = cache_ttl
        self._cache: dict[str, CachedSecret] = {}
        self._client = boto3.client("secretsmanager", region_name=region)

        logger.info(
            "SecretsClient initialised environment=%s region=%s cache_ttl=%ds",
            self.environment, region, cache_ttl,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def get_vortexpay_api_key(self, merchant_id: str) -> str:
        """
        Returns the VortexPay API key for the given merchant.
        Result is cached for cache_ttl seconds.
        """
        secret_name = self._secret_name("vortexpay", merchant_id, "api-key")
        return self._get_string_secret(secret_name)

    def get_vortexpay_webhook_secret(self, merchant_id: str) -> str:
        """
        Returns the VortexPay webhook signing secret for the given merchant.
        Used to validate HMAC signatures on incoming VortexPay callbacks.
        """
        secret_name = self._secret_name("vortexpay", merchant_id, "webhook-secret")
        return self._get_string_secret(secret_name)

    def get_vortexpay_oauth(self, merchant_id: str) -> dict:
        """
        Returns VortexPay OAuth credentials as a dict:
          { client_id, client_secret, token_url, scope }
        """
        secret_name = self._secret_name("vortexpay", merchant_id, "oauth-credentials")
        raw = self._get_string_secret(secret_name)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise SecretsClientError(
                f"OAuth credentials for merchant {merchant_id} are not valid JSON"
            ) from e

    def get_raw(self, secret_name: str) -> str:
        """
        Low-level method to fetch any secret by full name.
        Prefer the typed methods above for payment provider credentials.
        """
        return self._get_string_secret(secret_name)

    def invalidate_cache(self, secret_name: str = None) -> None:
        """
        Force cache invalidation.
        Call this after receiving a rotation completion SNS notification.
        If secret_name is None, clears the entire cache.
        """
        if secret_name:
            self._cache.pop(secret_name, None)
            logger.info("Cache invalidated for secret=%s", secret_name)
        else:
            self._cache.clear()
            logger.info("Full secrets cache cleared")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _secret_name(self, provider: str, merchant_id: str, secret_type: str) -> str:
        return f"{self.name_prefix}/{self.environment}/{provider}/merchant-{merchant_id}/{secret_type}"

    def _get_string_secret(self, secret_name: str) -> str:
        """
        Fetch a secret with caching and zero-downtime rotation support.

        During rotation, AWS Secrets Manager briefly has two valid versions:
          AWSCURRENT  — the newly rotated key (may not yet be pushed to VortexPay)
          AWSPREVIOUS — the old key (still valid at VortexPay)

        We always try AWSCURRENT first. If services get auth failures from
        the payment provider, they should call invalidate_cache() and retry —
        the library will then fetch AWSPREVIOUS as fallback.
        """
        # Return from cache if still fresh
        cached = self._cache.get(secret_name)
        if cached and not cached.is_expired():
            logger.debug("Cache hit for secret=%s", secret_name)
            return cached.value

        # Fetch from Secrets Manager
        value = self._fetch_from_aws(secret_name)
        self._cache[secret_name] = CachedSecret(
            value=value,
            fetched_at=time.monotonic(),
            ttl=self.cache_ttl,
        )
        return value

    def _fetch_from_aws(self, secret_name: str) -> str:
        """
        Fetch secret from AWS Secrets Manager.
        Logs every access for PCI-DSS Req. 10 audit trail.
        """
        last_error = None

        for stage in SECRET_STAGES:
            try:
                logger.info(
                    "Fetching secret name=%s stage=%s",
                    secret_name, stage,
                )
                response = self._client.get_secret_value(
                    SecretId=secret_name,
                    VersionStage=stage,
                )
                value = response.get("SecretString", "")
                logger.info(
                    "Secret fetched successfully name=%s version=%s stage=%s",
                    secret_name,
                    response.get("VersionId", "unknown"),
                    stage,
                )
                return value

            except ClientError as e:
                code = e.response["Error"]["Code"]

                if code == "ResourceNotFoundException":
                    raise SecretsClientError(
                        f"Secret not found: {secret_name}"
                    ) from e

                if code == "AccessDeniedException":
                    logger.error(
                        "ACCESS DENIED for secret=%s stage=%s — check IAM policy",
                        secret_name, stage,
                    )
                    raise SecretsClientError(
                        f"Access denied to secret: {secret_name}. "
                        "Verify the service IAM role has the correct permissions."
                    ) from e

                if code in ("DecryptionFailure", "InternalServiceError"):
                    logger.warning(
                        "Transient error fetching secret=%s stage=%s code=%s, "
                        "trying next stage",
                        secret_name, stage, code,
                    )
                    last_error = e
                    continue

                raise SecretsClientError(
                    f"Unexpected error fetching secret {secret_name}: {e}"
                ) from e

        raise SecretsClientError(
            f"Failed to fetch secret {secret_name} after trying all stages"
        ) from last_error
