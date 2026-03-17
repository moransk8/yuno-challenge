variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (sandbox, staging, production)"
  type        = string
  default     = "sandbox"

  validation {
    condition     = contains(["sandbox", "staging", "production"], var.environment)
    error_message = "Environment must be one of: sandbox, staging, production."
  }
}

variable "name_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "yuno"
}

variable "alert_email" {
  description = "Email address for rotation alerts and failure notifications"
  type        = string
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs (PCI-DSS requires minimum 1 year)"
  type        = number
  default     = 365

  validation {
    condition     = var.log_retention_days >= 365
    error_message = "PCI-DSS Requirement 10 mandates log retention of at least 1 year (365 days)."
  }
}

variable "rotation_schedule_days" {
  description = "How often (in days) to automatically rotate secrets"
  type        = number
  default     = 90
}
