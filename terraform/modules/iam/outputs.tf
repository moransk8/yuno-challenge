output "kms_key_arn" { value = aws_kms_key.secrets.arn }
output "kms_key_id" { value = aws_kms_key.secrets.key_id }
output "lambda_rotation_role_arn" { value = aws_iam_role.lambda_rotation.arn }
output "payment_gateway_role_arn" { value = aws_iam_role.payment_gateway.arn }
output "reconciliation_role_arn" { value = aws_iam_role.reconciliation_service.arn }
output "developer_role_arn" { value = aws_iam_role.developer.arn }
