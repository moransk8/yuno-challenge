#!/usr/bin/env python3
"""
Emergency Rotation Script
==========================
Triggers immediate rotation of VortexPay credentials for one or all merchants.
Used during the 48-hour VortexPay incident or any credential compromise event.

Usage:
    # Rotate all VortexPay merchants in production
    ENVIRONMENT=production PROVIDER=vortexpay MERCHANT_ID=all python scripts/emergency_rotation.py

    # Rotate single merchant
    ENVIRONMENT=production PROVIDER=vortexpay MERCHANT_ID=123 python scripts/emergency_rotation.py

    # Dry run (shows what would be rotated without doing it)
    DRY_RUN=true ENVIRONMENT=production python scripts/emergency_rotation.py

All rotations are zero-downtime:
    - AWS Secrets Manager queues the rotation
    - Lambda executes 4-step protocol (create → set → test → finish)
    - Services automatically fetch new credentials via SecretsClient cache TTL
    - No service restarts required
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("emergency-rotation")

# Config from environment
ENVIRONMENT = os.environ.get("ENVIRONMENT", "sandbox")
PROVIDER = os.environ.get("PROVIDER", "vortexpay")
MERCHANT_ID = os.environ.get("MERCHANT_ID", "all")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
NAME_PREFIX = os.environ.get("NAME_PREFIX", "yuno")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
ROTATION_REASON = os.environ.get("ROTATION_REASON", "emergency-rotation")
TRIGGERED_BY = os.environ.get("TRIGGERED_BY", "manual")

sm_client = boto3.client("secretsmanager", region_name=AWS_REGION)


def list_secrets_to_rotate() -> list[dict]:
    """List all secrets matching the rotation criteria."""
    prefix = f"{NAME_PREFIX}/{ENVIRONMENT}/{PROVIDER}/"
    if MERCHANT_ID != "all":
        prefix = f"{NAME_PREFIX}/{ENVIRONMENT}/{PROVIDER}/merchant-{MERCHANT_ID}/"

    logger.info("Listing secrets with prefix: %s", prefix)

    secrets = []
    paginator = sm_client.get_paginator("list_secrets")

    for page in paginator.paginate(
        Filters=[{"Key": "name", "Values": [prefix]}]
    ):
        secrets.extend(page["SecretList"])

    logger.info("Found %d secrets to rotate", len(secrets))
    return secrets


def rotate_secret(secret: dict) -> dict:
    """
    Trigger immediate rotation for a single secret.
    Returns result dict with status and timing.
    """
    secret_id = secret["ARN"]
    secret_name = secret["Name"]
    started_at = datetime.now(timezone.utc).isoformat()

    logger.info("Rotating secret: %s", secret_name)

    if DRY_RUN:
        logger.info("DRY RUN — would rotate: %s", secret_name)
        return {
            "secret_name": secret_name,
            "status": "dry_run",
            "started_at": started_at,
        }

    try:
        response = sm_client.rotate_secret(
            SecretId=secret_id,
            # RotateImmediately=True tells Secrets Manager to rotate NOW
            # rather than waiting for the scheduled window
            RotateImmediately=True,
        )

        return {
            "secret_name": secret_name,
            "status": "rotation_triggered",
            "version_id": response.get("VersionId"),
            "started_at": started_at,
        }

    except ClientError as e:
        code = e.response["Error"]["Code"]
        logger.error("Failed to rotate %s: %s - %s", secret_name, code, e)

        if code == "RotationNotEnabledError":
            # Secret exists but rotation Lambda not configured yet
            return {
                "secret_name": secret_name,
                "status": "rotation_not_enabled",
                "error": str(e),
                "action_required": "Configure rotation Lambda for this secret",
                "started_at": started_at,
            }

        return {
            "secret_name": secret_name,
            "status": "error",
            "error": str(e),
            "started_at": started_at,
        }


def wait_for_rotation(secret_name: str, timeout_seconds: int = 120) -> bool:
    """
    Poll until rotation is complete or timeout.
    Returns True if rotation succeeded.
    """
    deadline = time.time() + timeout_seconds
    logger.info("Waiting for rotation to complete: %s", secret_name)

    while time.time() < deadline:
        try:
            response = sm_client.describe_secret(SecretId=secret_name)
            rotation_enabled = response.get("RotationEnabled", False)

            if not rotation_enabled:
                return False

            # Check if any version is in AWSPENDING (rotation in progress)
            versions = response.get("VersionIdsToStages", {})
            in_progress = any(
                "AWSPENDING" in stages
                for stages in versions.values()
            )

            if not in_progress:
                # No AWSPENDING means rotation completed
                logger.info("Rotation complete for: %s", secret_name)
                return True

            logger.info("Rotation in progress for %s, waiting...", secret_name)
            time.sleep(5)

        except ClientError as e:
            logger.error("Error checking rotation status: %s", e)
            return False

    logger.warning("Rotation timed out for: %s", secret_name)
    return False


def main():
    logger.info("=" * 60)
    logger.info("EMERGENCY SECRET ROTATION")
    logger.info("=" * 60)
    logger.info("Environment : %s", ENVIRONMENT)
    logger.info("Provider    : %s", PROVIDER)
    logger.info("Merchant    : %s", MERCHANT_ID)
    logger.info("Triggered by: %s", TRIGGERED_BY)
    logger.info("Reason      : %s", ROTATION_REASON)
    logger.info("Dry run     : %s", DRY_RUN)
    logger.info("=" * 60)

    secrets = list_secrets_to_rotate()

    if not secrets:
        logger.error("No secrets found matching criteria. Check prefix and environment.")
        sys.exit(1)

    results = []
    failed = []

    for i, secret in enumerate(secrets, 1):
        logger.info("[%d/%d] Processing: %s", i, len(secrets), secret["Name"])
        result = rotate_secret(secret)
        results.append(result)

        if result["status"] == "error":
            failed.append(result)
        elif result["status"] == "rotation_triggered" and not DRY_RUN:
            # Wait for this rotation before starting the next
            # Avoids overwhelming the rotation Lambda concurrency
            success = wait_for_rotation(secret["Name"])
            result["completed"] = success

    # Summary report
    logger.info("\n" + "=" * 60)
    logger.info("ROTATION SUMMARY")
    logger.info("=" * 60)
    logger.info("Total secrets  : %d", len(secrets))
    logger.info("Succeeded      : %d", len([r for r in results if r["status"] in ("rotation_triggered", "dry_run")]))
    logger.info("Failed         : %d", len(failed))

    if failed:
        logger.error("\nFAILED ROTATIONS (require manual intervention):")
        for f in failed:
            logger.error("  - %s: %s", f["secret_name"], f.get("error"))

    # Write results to file for CI artifact upload
    report_path = "/tmp/rotation_report.json"
    with open(report_path, "w") as fh:
        json.dump({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": ENVIRONMENT,
            "provider": PROVIDER,
            "merchant_id": MERCHANT_ID,
            "triggered_by": TRIGGERED_BY,
            "reason": ROTATION_REASON,
            "total": len(secrets),
            "results": results,
        }, fh, indent=2, default=str)

    logger.info("Report written to: %s", report_path)

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
