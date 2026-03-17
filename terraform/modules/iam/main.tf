# ── KMS Key for secrets encryption (PCI-DSS 3.5/3.6) ─────────────────────────
resource "aws_kms_key" "secrets" {
  description             = "Yuno secrets encryption key - ${var.environment}"
  deletion_window_in_days = 30
  enable_key_rotation     = true # AWS rotates the KMS key material annually

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowSecretsManager"
        Effect = "Allow"
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowLambdaRotation"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_rotation.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.name_prefix}-secrets-kms-${var.environment}"
    PCIScope    = "true"
    Requirement = "PCI-DSS-3.5"
  }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.name_prefix}-secrets-${var.environment}"
  target_key_id = aws_kms_key.secrets.key_id
}

# ── Lambda Rotation Role ───────────────────────────────────────────────────────
resource "aws_iam_role" "lambda_rotation" {
  name = "${var.name_prefix}-lambda-rotation-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Service = "rotation-lambda"
  }
}

resource "aws_iam_role_policy" "lambda_rotation" {
  name = "${var.name_prefix}-lambda-rotation-policy-${var.environment}"
  role = aws_iam_role.lambda_rotation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsManagerRotation"
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage",
          "secretsmanager:ListSecretVersionIds"
        ]
        # Scoped to vortexpay secrets only
        Resource = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/vortexpay/*"
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.secrets.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${var.name_prefix}-rotate-secret-${var.environment}:*"
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = "arn:aws:sns:${var.region}:${var.account_id}:${var.name_prefix}-rotation-alerts-${var.environment}"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda_rotation.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# ── payment-gateway Service Role (Least Privilege) ────────────────────────────
# PCI-DSS 3.6: Only access credentials for payment providers, NOT database/*
resource "aws_iam_role" "payment_gateway" {
  name = "${var.name_prefix}-payment-gateway-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        # In production: replace with EKS OIDC or ECS task principal
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Service  = "payment-gateway"
    PCIScope = "true"
  }
}

resource "aws_iam_role_policy" "payment_gateway_secrets" {
  name = "${var.name_prefix}-payment-gateway-secrets-policy"
  role = aws_iam_role.payment_gateway.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadVortexPaySecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        # ONLY vortexpay/* — explicitly cannot read database/* or other namespaces
        Resource = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/${var.environment}/vortexpay/*"
      },
      {
        Sid      = "DenyDatabaseSecrets"
        Effect   = "Deny"
        Action   = "secretsmanager:*"
        Resource = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/${var.environment}/database/*"
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.secrets.arn
      }
    ]
  })
}

# ── reconciliation-service Role (Scoped to specific merchants) ────────────────
# PCI-DSS 3.6: Can only read specific merchant IDs, not all 847
resource "aws_iam_role" "reconciliation_service" {
  name = "${var.name_prefix}-reconciliation-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Service  = "reconciliation-service"
    PCIScope = "true"
  }
}

resource "aws_iam_role_policy" "reconciliation_secrets" {
  name = "${var.name_prefix}-reconciliation-secrets-policy"
  role = aws_iam_role.reconciliation_service.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadSpecificMerchants"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        # Scoped to specific merchant IDs — cannot access all 847
        Resource = [
          "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/${var.environment}/vortexpay/merchant-123*",
          "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/${var.environment}/vortexpay/merchant-456*",
          "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/${var.environment}/vortexpay/merchant-789*"
        ]
      },
      {
        Sid      = "DenyAllOtherMerchants"
        Effect   = "Deny"
        Action   = "secretsmanager:GetSecretValue"
        Resource = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/${var.environment}/vortexpay/merchant-*"
        Condition = {
          StringNotLike = {
            "secretsmanager:SecretId" = [
              "*/merchant-123*",
              "*/merchant-456*",
              "*/merchant-789*"
            ]
          }
        }
      },
      {
        Sid      = "KMSDecrypt"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey"]
        Resource = aws_kms_key.secrets.arn
      }
    ]
  })
}

# ── Developer Role (sandbox only, never production) ───────────────────────────
resource "aws_iam_role" "developer" {
  name = "${var.name_prefix}-developer-sandbox"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.account_id}:root"
      }
      Action = "sts:AssumeRole"
      Condition = {
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"
        }
      }
    }]
  })

  tags = {
    Role = "developer"
    Note = "Sandbox access only - MFA required"
  }
}

resource "aws_iam_role_policy" "developer_secrets" {
  name = "${var.name_prefix}-developer-sandbox-policy"
  role = aws_iam_role.developer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadSandboxSecretsOnly"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecrets"
        ]
        Resource = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/sandbox/*"
      },
      {
        Sid    = "DenyProductionAccess"
        Effect = "Deny"
        Action = "secretsmanager:*"
        Resource = [
          "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/production/*",
          "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/staging/*"
        ]
      },
      {
        Sid      = "KMSDecryptSandbox"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey"]
        Resource = aws_kms_key.secrets.arn
      }
    ]
  })
}
