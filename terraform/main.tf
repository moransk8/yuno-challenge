terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # Uncomment and configure for remote state
  # backend "s3" {
  #   bucket         = "yuno-terraform-state"
  #   key            = "secrets-management/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "yuno-terraform-locks"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "yuno-secrets-management"
      Environment = var.environment
      ManagedBy   = "terraform"
      Team        = "devsecops"
    }
  }
}

# ── Data sources ──────────────────────────────────────────────────────────────
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# ── Modules ───────────────────────────────────────────────────────────────────
module "iam" {
  source = "./modules/iam"

  account_id  = local.account_id
  region      = local.region
  environment = var.environment
  name_prefix = var.name_prefix
}

module "secrets" {
  source = "./modules/secrets"

  environment         = var.environment
  name_prefix         = var.name_prefix
  kms_key_arn         = module.iam.kms_key_arn
  rotation_lambda_arn = module.lambda.rotation_lambda_arn

  depends_on = [module.iam, module.lambda]
}

module "lambda" {
  source = "./modules/lambda"

  environment        = var.environment
  name_prefix        = var.name_prefix
  lambda_role_arn    = module.iam.lambda_rotation_role_arn
  kms_key_arn        = module.iam.kms_key_arn
  lambda_source_path = "${path.root}/../lambda/rotate_secret"

  depends_on = [module.iam]
}

module "monitoring" {
  source = "./modules/monitoring"

  environment          = var.environment
  name_prefix          = var.name_prefix
  alert_email          = var.alert_email
  log_retention_days   = var.log_retention_days
  account_id           = local.account_id
  region               = local.region
  rotation_lambda_name = module.lambda.rotation_lambda_name

  depends_on = [module.lambda]
}
