output "demo_secret_arns" {
  value = {
    merchant_123_api_key       = aws_secretsmanager_secret.vortexpay_api_key_merchant_123.arn
    merchant_123_webhook       = aws_secretsmanager_secret.vortexpay_webhook_secret_merchant_123.arn
    merchant_123_oauth         = aws_secretsmanager_secret.vortexpay_oauth_merchant_123.arn
    merchant_456_api_key       = aws_secretsmanager_secret.vortexpay_api_key_merchant_456.arn
    merchant_789_api_key       = aws_secretsmanager_secret.vortexpay_api_key_merchant_789.arn
    sandbox_merchant_123       = aws_secretsmanager_secret.vortexpay_sandbox_merchant_123.arn
  }
}
