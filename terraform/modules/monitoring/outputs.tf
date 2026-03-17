output "audit_log_group_name" { value = aws_cloudwatch_log_group.secrets_audit.name }
output "alert_topic_arn" { value = aws_sns_topic.rotation_alerts.arn }
output "cloudtrail_bucket" { value = aws_s3_bucket.cloudtrail.bucket }
