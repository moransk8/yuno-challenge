output "kms_key_arn" {
  description = "ARN of the KMS key used to encrypt secrets"
  value       = module.iam.kms_key_arn
  sensitive   = false
}

output "kms_key_id" {
  description = "ID of the KMS key used to encrypt secrets"
  value       = module.iam.kms_key_id
  sensitive   = false
}

output "rotation_lambda_arn" {
  description = "ARN of the secret rotation Lambda function"
  value       = module.lambda.rotation_lambda_arn
}

output "rotation_lambda_name" {
  description = "Name of the secret rotation Lambda function"
  value       = module.lambda.rotation_lambda_name
}

output "payment_gateway_role_arn" {
  description = "IAM role ARN for the payment-gateway service"
  value       = module.iam.payment_gateway_role_arn
}

output "reconciliation_role_arn" {
  description = "IAM role ARN for the reconciliation-service"
  value       = module.iam.reconciliation_role_arn
}

output "audit_log_group_name" {
  description = "CloudWatch Log Group name for secrets audit trail (PCI-DSS Req. 10)"
  value       = module.monitoring.audit_log_group_name
}

output "alert_topic_arn" {
  description = "SNS topic ARN for rotation alerts"
  value       = module.monitoring.alert_topic_arn
}

output "demo_secret_arns" {
  description = "ARNs of demo secrets created for testing"
  value       = module.secrets.demo_secret_arns
  sensitive   = false
}
