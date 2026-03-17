# ── Demo secrets demonstrating all 3 required types ──────────────────────────
# Type 1: API Key (string)
resource "aws_secretsmanager_secret" "vortexpay_api_key_merchant_123" {
  name       = "${var.name_prefix}/${var.environment}/vortexpay/merchant-123/api-key"
  kms_key_id = var.kms_key_arn

  description = "VortexPay API key for merchant 123 (Thailand)"

  # Automatic rotation every 90 days (PCI-DSS 8.3.2)
  # rotation_lambda_arn = var.rotation_lambda_arn

  recovery_window_in_days = 7

  tags = {
    MerchantID   = "123"
    Provider     = "vortexpay"
    SecretType   = "api-key"
    Country      = "TH"
    PCIScope     = "true"
    Requirement  = "PCI-DSS-8.3.2"
  }
}

resource "aws_secretsmanager_secret_version" "vortexpay_api_key_merchant_123" {
  secret_id = aws_secretsmanager_secret.vortexpay_api_key_merchant_123.id
  # DEMO VALUE — in production this is set out-of-band, never in Terraform
  secret_string = "vp_live_REPLACE_WITH_REAL_KEY_DO_NOT_COMMIT"

  lifecycle {
    ignore_changes = [secret_string] # Rotation will manage the value
  }
}

# Enable rotation
resource "aws_secretsmanager_secret_rotation" "vortexpay_api_key_merchant_123" {
  secret_id           = aws_secretsmanager_secret.vortexpay_api_key_merchant_123.id
  rotation_lambda_arn = var.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = 90 # PCI-DSS 8.3.2 requires at least annual
  }
}

# Type 2: Webhook Signing Secret (string)
resource "aws_secretsmanager_secret" "vortexpay_webhook_secret_merchant_123" {
  name       = "${var.name_prefix}/${var.environment}/vortexpay/merchant-123/webhook-secret"
  kms_key_id = var.kms_key_arn

  description = "VortexPay webhook signing secret for merchant 123"

  recovery_window_in_days = 7

  tags = {
    MerchantID  = "123"
    Provider    = "vortexpay"
    SecretType  = "webhook-secret"
    PCIScope    = "true"
    Requirement = "PCI-DSS-8.3.2"
  }
}

resource "aws_secretsmanager_secret_version" "vortexpay_webhook_secret_merchant_123" {
  secret_id     = aws_secretsmanager_secret.vortexpay_webhook_secret_merchant_123.id
  secret_string = "whsec_REPLACE_WITH_REAL_SECRET_DO_NOT_COMMIT"

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret_rotation" "vortexpay_webhook_merchant_123" {
  secret_id           = aws_secretsmanager_secret.vortexpay_webhook_secret_merchant_123.id
  rotation_lambda_arn = var.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = 90
  }
}

# Type 3: OAuth Credentials (JSON object)
resource "aws_secretsmanager_secret" "vortexpay_oauth_merchant_123" {
  name       = "${var.name_prefix}/${var.environment}/vortexpay/merchant-123/oauth-credentials"
  kms_key_id = var.kms_key_arn

  description = "VortexPay OAuth2 client credentials for merchant 123"

  recovery_window_in_days = 7

  tags = {
    MerchantID  = "123"
    Provider    = "vortexpay"
    SecretType  = "oauth-credentials"
    PCIScope    = "true"
    Requirement = "PCI-DSS-8.3.2"
  }
}

resource "aws_secretsmanager_secret_version" "vortexpay_oauth_merchant_123" {
  secret_id = aws_secretsmanager_secret.vortexpay_oauth_merchant_123.id
  secret_string = jsonencode({
    client_id     = "REPLACE_WITH_REAL_CLIENT_ID"
    client_secret = "REPLACE_WITH_REAL_CLIENT_SECRET"
    token_url     = "https://auth.vortexpay.com/oauth/token"
    scope         = "payments:read payments:write"
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret_rotation" "vortexpay_oauth_merchant_123" {
  secret_id           = aws_secretsmanager_secret.vortexpay_oauth_merchant_123.id
  rotation_lambda_arn = var.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = 90
  }
}

# Additional merchants for demo (456, 789)
resource "aws_secretsmanager_secret" "vortexpay_api_key_merchant_456" {
  name            = "${var.name_prefix}/${var.environment}/vortexpay/merchant-456/api-key"
  kms_key_id      = var.kms_key_arn
  description     = "VortexPay API key for merchant 456 (Indonesia)"
  recovery_window_in_days = 7
  tags = { MerchantID = "456", Provider = "vortexpay", Country = "ID", PCIScope = "true" }
}

resource "aws_secretsmanager_secret_version" "vortexpay_api_key_merchant_456" {
  secret_id     = aws_secretsmanager_secret.vortexpay_api_key_merchant_456.id
  secret_string = "vp_live_REPLACE_MERCHANT_456_KEY"
  lifecycle { ignore_changes = [secret_string] }
}

resource "aws_secretsmanager_secret" "vortexpay_api_key_merchant_789" {
  name            = "${var.name_prefix}/${var.environment}/vortexpay/merchant-789/api-key"
  kms_key_id      = var.kms_key_arn
  description     = "VortexPay API key for merchant 789 (Philippines)"
  recovery_window_in_days = 7
  tags = { MerchantID = "789", Provider = "vortexpay", Country = "PH", PCIScope = "true" }
}

resource "aws_secretsmanager_secret_version" "vortexpay_api_key_merchant_789" {
  secret_id     = aws_secretsmanager_secret.vortexpay_api_key_merchant_789.id
  secret_string = "vp_live_REPLACE_MERCHANT_789_KEY"
  lifecycle { ignore_changes = [secret_string] }
}

# Sandbox secrets for developer access
resource "aws_secretsmanager_secret" "vortexpay_sandbox_merchant_123" {
  name        = "${var.name_prefix}/sandbox/vortexpay/merchant-123/api-key"
  kms_key_id  = var.kms_key_arn
  description = "VortexPay SANDBOX API key for merchant 123 — safe for developers"
  recovery_window_in_days = 7
  tags = { Environment = "sandbox", MerchantID = "123", DeveloperAccess = "true" }
}

resource "aws_secretsmanager_secret_version" "vortexpay_sandbox_merchant_123" {
  secret_id     = aws_secretsmanager_secret.vortexpay_sandbox_merchant_123.id
  secret_string = "vp_sandbox_kj23h4kjh23k4h23k4h_demo"
  lifecycle { ignore_changes = [secret_string] }
}
