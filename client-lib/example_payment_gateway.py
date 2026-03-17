"""
Example: payment-gateway microservice using SecretsClient
==========================================================
Demonstrates how any Yuno microservice fetches credentials
at runtime — never hardcoded, never in environment variables
baked into the container image.

Run locally (sandbox):
    ENVIRONMENT=sandbox python example_payment_gateway.py

The service IAM role (yuno-payment-gateway-sandbox) restricts
access to vortexpay/* secrets only — database/* is denied.
"""

import json
import logging
import os

from secrets_client import SecretsClient, SecretsClientError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("payment-gateway")


def process_payment(merchant_id: str, amount: float, currency: str) -> dict:
    """
    Simulate processing a payment through VortexPay.
    In production: this runs in a long-lived service that keeps the
    SecretsClient singleton alive across thousands of requests.
    """
    # Singleton client — instantiate once per process, reuse across requests
    client = SecretsClient(environment=os.environ.get("ENVIRONMENT", "sandbox"))

    try:
        # Fetch credentials at runtime — cached for 5 minutes
        api_key = client.get_vortexpay_api_key(merchant_id=merchant_id)
        webhook_secret = client.get_vortexpay_webhook_secret(merchant_id=merchant_id)

        logger.info(
            "Processing payment merchant_id=%s amount=%.2f %s",
            merchant_id,
            amount,
            currency,
        )

        # Simulate VortexPay API call (masked for logging)
        logger.info(
            "Authenticating with VortexPay using key=%s...",
            api_key[:8] + "****",
        )

        # In production:
        # response = vortexpay_client.charge(
        #     api_key=api_key,
        #     merchant_id=merchant_id,
        #     amount=amount,
        #     currency=currency,
        # )

        return {
            "status": "success",
            "merchant_id": merchant_id,
            "amount": amount,
            "currency": currency,
            "transaction_id": "txn_demo_12345",
        }

    except SecretsClientError as e:
        logger.error("Failed to fetch credentials for merchant=%s: %s", merchant_id, e)
        # In production: return 503 to the merchant, trigger PagerDuty alert
        return {"status": "error", "message": "Internal credential error"}


def validate_webhook(merchant_id: str, payload: bytes, signature: str) -> bool:
    """
    Validate a VortexPay webhook signature.
    Fetches the webhook secret at runtime — gracefully handles rotation.
    """
    import hashlib
    import hmac

    client = SecretsClient(environment=os.environ.get("ENVIRONMENT", "sandbox"))

    try:
        webhook_secret = client.get_vortexpay_webhook_secret(merchant_id=merchant_id)

        expected = hmac.new(
            webhook_secret.encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()

        is_valid = hmac.compare_digest(f"sha256={expected}", signature)

        if not is_valid:
            # During rotation: try AWSPREVIOUS by invalidating cache
            logger.warning(
                "Webhook signature mismatch for merchant=%s — "
                "possible rotation in progress, retrying with previous secret",
                merchant_id,
            )
            secret_name = f"yuno/{os.environ.get('ENVIRONMENT', 'sandbox')}/vortexpay/merchant-{merchant_id}/webhook-secret"
            client.invalidate_cache(secret_name)
            webhook_secret = client.get_vortexpay_webhook_secret(
                merchant_id=merchant_id
            )

            expected = hmac.new(
                webhook_secret.encode(),
                payload,
                hashlib.sha256,
            ).hexdigest()
            is_valid = hmac.compare_digest(f"sha256={expected}", signature)

        return is_valid

    except SecretsClientError as e:
        logger.error("Cannot validate webhook — credential fetch failed: %s", e)
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("Yuno Payment Gateway — Secrets Client Demo")
    print("=" * 60)

    result = process_payment(
        merchant_id="123",
        amount=99.99,
        currency="THB",
    )
    print(f"\nPayment result: {json.dumps(result, indent=2)}")

    print("\nWebhook validation demo:")
    is_valid = validate_webhook(
        merchant_id="123",
        payload=b'{"event":"payment.success","amount":99.99}',
        signature="sha256=demo_signature",
    )
    print(f"Webhook valid: {is_valid}")
