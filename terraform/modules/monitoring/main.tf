# ── SNS Alert Topic ───────────────────────────────────────────────────────────
resource "aws_sns_topic" "rotation_alerts" {
  name              = "${var.name_prefix}-rotation-alerts-${var.environment}"
  kms_master_key_id = "alias/aws/sns" # Encrypt SNS messages at rest

  tags = {
    Purpose = "rotation-alerting"
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.rotation_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── CloudWatch Log Group for Audit Trail (PCI-DSS Req. 10) ───────────────────
resource "aws_cloudwatch_log_group" "secrets_audit" {
  name              = "/yuno/secrets-audit/${var.environment}"
  retention_in_days = var.log_retention_days # Minimum 365 days for PCI-DSS

  # Encrypt logs at rest with KMS
  # kms_key_id = var.kms_key_arn  # Uncomment if CloudWatch KMS grants are configured

  tags = {
    Purpose     = "pci-dss-audit-trail"
    Requirement = "PCI-DSS-10"
    Tamper      = "cloudtrail-protected"
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.rotation_lambda_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Purpose = "rotation-lambda-logs"
  }
}

# ── CloudTrail for tamper-evident audit (PCI-DSS 10.3) ───────────────────────
resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "${var.name_prefix}-cloudtrail-audit-${var.environment}-${var.account_id}"
  force_destroy = false # NEVER delete audit logs accidentally

  tags = {
    Purpose     = "cloudtrail-audit"
    Requirement = "PCI-DSS-10"
    PCIScope    = "true"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${var.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "DenyDelete"
        Effect = "Deny"
        Principal = "*"
        Action   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource = "${aws_s3_bucket.cloudtrail.arn}/*"
      }
    ]
  })
}

# CloudTrail — captures ALL Secrets Manager API calls (tamper-evident)
resource "aws_cloudtrail" "secrets_audit" {
  name                          = "${var.name_prefix}-secrets-audit-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true # Tamper detection (PCI-DSS 10.3.2)
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.secrets_audit.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::SecretsManager::Secret"
      values = ["arn:aws:secretsmanager"]
    }
  }

  tags = {
    Purpose     = "pci-dss-audit"
    Requirement = "PCI-DSS-10"
  }
}

resource "aws_iam_role" "cloudtrail_cw" {
  name = "${var.name_prefix}-cloudtrail-cw-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  name = "${var.name_prefix}-cloudtrail-cw-policy"
  role = aws_iam_role.cloudtrail_cw.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.secrets_audit.arn}:*"
    }]
  })
}

# ── CloudWatch Alarms ─────────────────────────────────────────────────────────
# Alert on rotation failures
resource "aws_cloudwatch_metric_alarm" "rotation_failure" {
  alarm_name          = "${var.name_prefix}-rotation-failure-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Secret rotation Lambda failed — immediate action required"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = var.rotation_lambda_name
  }

  alarm_actions = [aws_sns_topic.rotation_alerts.arn]
  ok_actions    = [aws_sns_topic.rotation_alerts.arn]
}

# Alert on unauthorized secret access attempts
resource "aws_cloudwatch_log_metric_filter" "unauthorized_access" {
  name           = "${var.name_prefix}-unauthorized-secret-access"
  pattern        = "{ $.errorCode = \"AccessDenied\" && $.eventSource = \"secretsmanager.amazonaws.com\" }"
  log_group_name = aws_cloudwatch_log_group.secrets_audit.name

  metric_transformation {
    name      = "UnauthorizedSecretAccess"
    namespace = "Yuno/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_access" {
  alarm_name          = "${var.name_prefix}-unauthorized-access-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedSecretAccess"
  namespace           = "Yuno/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Unauthorized attempt to access secrets detected"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.rotation_alerts.arn]
}
