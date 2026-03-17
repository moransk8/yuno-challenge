# Copy this file to terraform.tfvars and fill in your values
# NEVER commit terraform.tfvars to Git if it contains real secrets

aws_region             = "us-east-1"
environment            = "sandbox"
name_prefix            = "yuno"
alert_email            = "davidmoeg@gmail.com"
log_retention_days     = 365
rotation_schedule_days = 90
