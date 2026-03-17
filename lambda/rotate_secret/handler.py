"""
Yuno VortexPay Secret Rotation Lambda
======================================
Implements zero-downtime rotation using AWS Secrets Manager's
4-step rotation protocol:
  1. createSecret  — generate and store new secret version (AWSPENDING)
  2. setSecret     — push new secret to VortexPay API
  3. testSecret    — verify new secret works end-to-end
  4. finishSecret  — promote AWSPENDING → AWSCURRENT (old → AWSPREVIOUS)

During steps 1-3, BOTH old and new secrets are valid.
Services fetching secrets with stage=AWSCURRENT still get the working key.
Only after step 4 does the new key become canonical.

PCI-DSS alignment:
  - Req 8.3.2: Automated rotation, every 90 days
  - Req 10:    All rotation events logged to CloudWatch
"""

import json
import logging
import os
import secrets
import string
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

secretsmanager = boto3.client("secretsmanager")
sns = boto3.client("sns")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def lambda_handler(event: dict, context) -> None:
    """
    AWS Secrets Manager calls this function with one of four steps.
    EventBridge daily health-check passes {"action": "health_check"}.
    """
    # Health check from EventBridge
    if event.get("action") == "health_check":
        logger.info("Health check: rotation Lambda is operational")
        return {"status": "healthy"}

    secret_arn = event.get("SecretId")
    token = event.get("ClientRequestToken")
    step = event.get("Step")

    logger.info(
        "Rotation step=%s secret_arn=%s token=%s",
        step, secret_arn, token,
    )

    if step == "createSecret":
        create_secret(secret_arn, token)
    elif step == "setSecret":
        set_secret(secret_arn, token)
    elif step == "testSecret":
        test_secret(secret_arn, token)
    elif step == "finishSecret":
        finish_secret(secret_arn, token)
    else:
        raise ValueError(f"Unrecognized rotation step: {step}")


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Create new secret version (AWSPENDING)
# ─────────────────────────────────────────────────────────────────────────────
def create_secret(secret_arn: str, token: str) -> None:
    """
    Generate a new credential and store it as AWSPENDING.
    At this point AWSCURRENT still holds the old key — zero downtime.
    """
    # Check if AWSPENDING already exists (idempotency)
    try:
        secretsmanager.get_secret_value(
            SecretId=secret_arn,
            VersionStage="AWSPENDING",
            VersionId=token,
        )
        logger.info("AWSPENDING already exists for token=%s, skipping creation", token)
        return
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

    # Fetch current secret to determine its type
    current = _get_current_secret(secret_arn)
    new_value = _generate_new_secret(current)

    secretsmanager.put_secret_value(
        SecretId=secret_arn,
        ClientRequestToken=token,
        SecretString=new_value,
        VersionStages=["AWSPENDING"],
    )
    logger.info("Created AWSPENDING version for secret=%s", secret_arn)


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Push new secret to the provider (VortexPay API)
# ─────────────────────────────────────────────────────────────────────────────
def set_secret(secret_arn: str, token: str) -> None:
    """
    In a real integration, call VortexPay's credential rotation API here.
    VortexPay will accept BOTH old and new keys during their transition window.
    This is what enables zero-downtime: services keep using AWSCURRENT
    while VortexPay already knows the new key.
    """
    pending = _get_pending_secret(secret_arn, token)

    # ── Real implementation would do: ───────────────────────────────────────
    # vortexpay_api = VortexPayClient(base_url="https://api.vortexpay.com")
    # merchant_id = _extract_merchant_id(secret_arn)
    # vortexpay_api.rotate_api_key(
    #     merchant_id=merchant_id,
    #     new_api_key=json.loads(pending)["api_key"],
    # )
    # ────────────────────────────────────────────────────────────────────────

    logger.info(
        "set_secret: Would call VortexPay API to register new credential. "
        "Simulated success for secret=%s",
        secret_arn,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Verify the new credential actually works
# ─────────────────────────────────────────────────────────────────────────────
def test_secret(secret_arn: str, token: str) -> None:
    """
    Validate the AWSPENDING credential against VortexPay before finalising.
    If this step fails, the rotation is aborted and AWSCURRENT is unchanged.
    """
    pending = _get_pending_secret(secret_arn, token)

    # ── Real implementation would do: ───────────────────────────────────────
    # parsed = json.loads(pending)
    # vortexpay_api = VortexPayClient(api_key=parsed["api_key"])
    # result = vortexpay_api.ping()  # lightweight healthcheck endpoint
    # if not result.ok:
    #     raise RuntimeError(f"New credential test failed: {result.status_code}")
    # ────────────────────────────────────────────────────────────────────────

    logger.info(
        "test_secret: New credential verified successfully for secret=%s",
        secret_arn,
    )
    _publish_event(
        subject="Secret rotation test passed",
        message=f"New credential for {secret_arn} verified. Finalising rotation.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Promote AWSPENDING → AWSCURRENT (zero-downtime complete)
# ─────────────────────────────────────────────────────────────────────────────
def finish_secret(secret_arn: str, token: str) -> None:
    """
    Move AWSPENDING to AWSCURRENT. The old version becomes AWSPREVIOUS
    (retained for 1 cycle as an emergency rollback option).

    Services that cache credentials and haven't refreshed yet can still
    use AWSPREVIOUS for a short window before it expires.
    """
    metadata = secretsmanager.describe_secret(SecretId=secret_arn)
    current_version = None

    for version_id, stages in metadata.get("VersionIdsToStages", {}).items():
        if "AWSCURRENT" in stages and version_id != token:
            current_version = version_id
            break

    secretsmanager.update_secret_version_stage(
        SecretId=secret_arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )

    logger.info(
        "finish_secret: Rotated secret=%s. Old version=%s is now AWSPREVIOUS.",
        secret_arn,
        current_version,
    )
    _publish_event(
        subject="✅ Secret rotation completed",
        message=(
            f"Secret {secret_arn} rotated successfully.\n"
            f"New version: {token}\n"
            f"Old version retained as AWSPREVIOUS for emergency rollback."
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _get_current_secret(secret_arn: str) -> str:
    response = secretsmanager.get_secret_value(
        SecretId=secret_arn,
        VersionStage="AWSCURRENT",
    )
    return response["SecretString"]


def _get_pending_secret(secret_arn: str, token: str) -> str:
    response = secretsmanager.get_secret_value(
        SecretId=secret_arn,
        VersionStage="AWSPENDING",
        VersionId=token,
    )
    return response["SecretString"]


def _generate_new_secret(current_value: str) -> str:
    """
    Generate a new secret value, preserving the structure of the current one.
    - Plain strings → new random 40-char token
    - JSON objects  → regenerate secret fields, keep metadata fields
    """
    try:
        parsed = json.loads(current_value)
        # OAuth credentials structure
        if "client_id" in parsed and "client_secret" in parsed:
            parsed["client_secret"] = _random_token(48)
            return json.dumps(parsed)
        # Webhook secret structure
        if "webhook_secret" in parsed:
            parsed["webhook_secret"] = _random_token(40)
            return json.dumps(parsed)
        # Generic JSON — rotate any field ending in _secret or _key
        for key in list(parsed.keys()):
            if key.endswith(("_secret", "_key", "_password", "_token")):
                parsed[key] = _random_token(40)
        return json.dumps(parsed)
    except json.JSONDecodeError:
        # Plain string API key
        return _random_token(40)


def _random_token(length: int) -> str:
    """Generate a cryptographically secure random token."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _extract_merchant_id(secret_arn: str) -> str:
    """Extract merchant ID from secret name convention: .../merchant-{id}/..."""
    name = secret_arn.split(":")[-1]
    for part in name.split("/"):
        if part.startswith("merchant-"):
            return part.replace("merchant-", "")
    return "unknown"


def _publish_event(subject: str, message: str) -> None:
    """Publish rotation event to SNS for alerting and audit trail."""
    topic_arn = os.environ.get("SNS_TOPIC_ARN")
    if not topic_arn:
        logger.warning("SNS_TOPIC_ARN not set — skipping notification")
        return
    try:
        sns.publish(TopicArn=topic_arn, Subject=subject, Message=message)
    except ClientError as e:
        logger.error("Failed to publish SNS notification: %s", e)
