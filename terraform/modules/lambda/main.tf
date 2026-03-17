locals {
  lambda_name = "${var.name_prefix}-rotate-secret-${var.environment}"
}

# Package the Lambda function from local source
data "archive_file" "rotation_lambda" {
  type        = "zip"
  source_dir  = var.lambda_source_path
  output_path = "${path.module}/lambda_rotation.zip"
}

resource "aws_lambda_function" "rotation" {
  function_name = local.lambda_name
  role          = var.lambda_role_arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.11"
  timeout       = 60
  memory_size   = 256

  filename         = data.archive_file.rotation_lambda.output_path
  source_code_hash = data.archive_file.rotation_lambda.output_base64sha256

  kms_key_arn = var.kms_key_arn

  environment {
    variables = {
      ENVIRONMENT = var.environment
      LOG_LEVEL   = "INFO"
      # SNS topic set at runtime via Terraform output injection
    }
  }

  # Enable X-Ray tracing for audit trail
  tracing_config {
    mode = "Active"
  }

  tags = {
    Purpose  = "secret-rotation"
    PCIScope = "true"
  }
}

# Grant Secrets Manager permission to invoke the Lambda
resource "aws_lambda_permission" "secrets_manager" {
  statement_id  = "AllowSecretsManagerInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotation.function_name
  principal     = "secretsmanager.amazonaws.com"
}

# EventBridge rule for scheduled emergency rotation sweeps
resource "aws_cloudwatch_event_rule" "rotation_check" {
  name                = "${var.name_prefix}-rotation-check-${var.environment}"
  description         = "Triggers rotation health check daily"
  schedule_expression = "rate(1 day)"

  tags = {
    Purpose = "rotation-monitoring"
  }
}

resource "aws_cloudwatch_event_target" "rotation_check" {
  rule      = aws_cloudwatch_event_rule.rotation_check.name
  target_id = "RotationLambda"
  arn       = aws_lambda_function.rotation.arn

  input = jsonencode({
    action = "health_check"
  })
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.rotation_check.arn
}
