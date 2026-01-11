# Variables for monitoring-baseline deployment unit with compliance integration
# Organization: 25cf5df0-b603-4ea5-9b55-8bfde0b728a9
# Compliance Frameworks: 

# =============================================================================
# Terraform State Configuration (for cross-unit data sources)
# =============================================================================

variable "stack_name" {
  description = "Name of the infrastructure stack (used in state paths)"
  type        = string
}

variable "environment" {
  description = "Deployment environment (e.g., dev, staging, production)"
  type        = string
}

# Note: Add backend-specific variables as needed:
# - For S3: terraform_state_bucket, aws_region
# - For Azure: terraform_state_storage_account, terraform_state_container
# - For GCS: terraform_state_bucket

# ============================================================================
# CORE CONFIGURATION
# ============================================================================

variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "us-west-2"
}

variable "common_tags" {
  description = "Generated from context: common_tags"
  type        = map(string)
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = length(var.environment) > 0
    error_message = "Environment name cannot be empty."
  }
}

variable "tags" {
  description = "Common tags to be applied to all resources"
  type        = map(string)
  default     = {
  Owner = "security-team"
  Project = "logging-monitoring-baseline"
  ManagedBy = "terraform"
  CostCenter = "security"
  Environment = "dev"
}
}

# ============================================================================
# VPC FLOW LOGS
# ============================================================================

variable "security_log_retention_days" {
  description = "Number of days to retain security logs"
  type        = number
  default     = 365
}

# ============================================================================
# CLOUDTRAIL
# ============================================================================

variable "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs"
  type        = string

  validation {
    condition     = var.cloudtrail_bucket_name == None || (length(var.cloudtrail_bucket_name) >= 3 && length(var.cloudtrail_bucket_name) <= 63 && can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.cloudtrail_bucket_name)))
    error_message = "S3 bucket name must be between 3 and 63 characters, start and end with lowercase letter or number, and contain only lowercase letters, numbers, hyphens, and periods."
  }
}

variable "cloudtrail_kms_key_id" {
  description = "KMS key ID for encrypting CloudTrail logs"
  type        = string
}

variable "cloudtrail_name" {
  description = "Name of the CloudTrail"
  type        = string
}

variable "cloudtrail_s3_key_prefix" {
  description = "S3 key prefix for CloudTrail logs"
  type        = string
  default     = "cloudtrail-logs"
}

variable "enable_cloudtrail" {
  description = "Whether to enable CloudTrail"
  type        = bool
  default     = true
}

variable "enable_cloudtrail_cloudwatch_logs" {
  description = "Whether to enable CloudWatch Logs for CloudTrail"
  type        = bool
  default     = true
}

# ============================================================================
# AWS CONFIG
# ============================================================================

variable "config_bucket_name" {
  description = "Name of the S3 bucket for AWS Config logs"
  type        = string

  validation {
    condition     = var.config_bucket_name == None || (length(var.config_bucket_name) >= 3 && length(var.config_bucket_name) <= 63 && can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.config_bucket_name)))
    error_message = "S3 bucket name must be between 3 and 63 characters, start and end with lowercase letter or number, and contain only lowercase letters, numbers, hyphens, and periods."
  }
}

variable "config_delivery_channel_name" {
  description = "Name of the AWS Config delivery channel"
  type        = string
}

variable "config_delivery_frequency" {
  description = "Frequency for AWS Config snapshot delivery"
  type        = string
  default     = "TwentyFour_Hours"

  validation {
    condition     = contains([One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours], var.config_delivery_frequency)
    error_message = "Config delivery frequency must be one of: One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours."
  }
}

variable "config_include_global_resource_types" {
  description = "Whether to include global resource types in AWS Config"
  type        = bool
  default     = true
}

variable "config_record_all_resource_types" {
  description = "Whether to record all resource types in AWS Config"
  type        = bool
  default     = true
}

variable "config_recorder_name" {
  description = "Name of the AWS Config recorder"
  type        = string
}

variable "config_resource_types" {
  description = "List of resource types to record in AWS Config (used when config_record_all_resource_types is false)"
  type        = list(string)
  default     = []
}

variable "config_role_arn" {
  description = "ARN of the IAM role for AWS Config (if not provided, will be created)"
  type        = string
}

variable "config_role_name" {
  description = "Name of the IAM role for AWS Config"
  type        = string
  default     = "config-service-role"
}

variable "config_s3_key_prefix" {
  description = "S3 key prefix for AWS Config logs"
  type        = string
  default     = "config-logs"
}

variable "enable_config" {
  description = "Whether to enable AWS Config"
  type        = bool
  default     = true
}

variable "enable_config_rules" {
  description = "Enable AWS Config rules"
  type        = bool
  default     = true
}

# ============================================================================
# GUARDDUTY
# ============================================================================

variable "create_guardduty_findings_sns" {
  description = "Create an SNS topic for GuardDuty findings"
  type        = bool
  default     = false
}

variable "create_guardduty_s3_destination" {
  description = "Whether to create S3 destination for GuardDuty findings"
  type        = bool
  default     = false
}

variable "enable_guardduty" {
  description = "Whether to enable GuardDuty"
  type        = bool
  default     = true
}

variable "enable_guardduty_kubernetes_audit_logs" {
  description = "Whether to enable Kubernetes audit logs monitoring in GuardDuty"
  type        = bool
  default     = true
}

variable "enable_guardduty_malware_protection" {
  description = "Whether to enable malware protection in GuardDuty"
  type        = bool
  default     = true
}

variable "enable_guardduty_notifications" {
  description = "Whether to enable GuardDuty notifications"
  type        = bool
  default     = true
}

variable "enable_guardduty_s3_logs" {
  description = "Whether to enable S3 data event monitoring in GuardDuty"
  type        = bool
  default     = true
}

variable "guardduty_event_rule_name" {
  description = "Name of the EventBridge rule for GuardDuty findings"
  type        = string
  default     = "guardduty-findings-rule"
}

variable "guardduty_finding_kms_key_arn" {
  description = "KMS key ARN to use for encrypting GuardDuty findings"
  type        = string
}

variable "guardduty_finding_publishing_frequency" {
  description = "Frequency of publishing GuardDuty findings to CloudWatch Events"
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains([FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS], var.guardduty_finding_publishing_frequency)
    error_message = "GuardDuty finding publishing frequency must be one of: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS."
  }
}

variable "guardduty_findings_bucket_name" {
  description = "Name of the S3 bucket for GuardDuty findings"
  type        = string

  validation {
    condition     = var.guardduty_findings_bucket_name == None || (length(var.guardduty_findings_bucket_name) >= 3 && length(var.guardduty_findings_bucket_name) <= 63 && can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.guardduty_findings_bucket_name)))
    error_message = "S3 bucket name must be between 3 and 63 characters, start and end with lowercase letter or number, and contain only lowercase letters, numbers, hyphens, and periods."
  }
}

variable "guardduty_findings_kms_key_arn" {
  description = "KMS key ARN for encrypting GuardDuty findings in S3"
  type        = string
}

variable "guardduty_findings_sns_topic_name" {
  description = "Name of the SNS topic for GuardDuty findings"
  type        = string
  default     = "guardduty-findings"
}

variable "guardduty_notification_emails" {
  description = "List of email addresses to notify about GuardDuty findings"
  type        = list(string)
  default     = []
}

# ============================================================================
# SECURITY HUB
# ============================================================================

variable "create_security_hub_findings_sns" {
  description = "Create an SNS topic for Security Hub findings"
  type        = bool
  default     = false
}

variable "enable_default_security_hub_standards" {
  description = "Enable default security standards in Security Hub"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Whether to enable Security Hub"
  type        = bool
  default     = true
}

variable "enable_security_hub_integration" {
  description = "Enable integration with Security Hub"
  type        = bool
  default     = false
}

variable "security_hub_event_rule_name" {
  description = "Name of the EventBridge rule for Security Hub findings"
  type        = string
  default     = "security-hub-critical-findings-rule"
}

variable "security_hub_findings_sns_topic_name" {
  description = "Name of the SNS topic for Security Hub findings"
  type        = string
  default     = "security-hub-findings"
}

# ============================================================================
# CLOUDWATCH
# ============================================================================

variable "cloudwatch_logs_kms_key_arn" {
  description = "KMS key ARN to use for encrypting CloudWatch logs"
  type        = string
}

variable "cloudwatch_logs_kms_key_id" {
  description = "KMS key ID for encrypting CloudWatch logs"
  type        = string
}

variable "cloudwatch_logs_retention" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.cloudwatch_logs_retention)
    error_message = "CloudWatch logs retention must be one of: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653."
  }
}

variable "create_cloudwatch_dashboard" {
  description = "Whether to create CloudWatch dashboard for monitoring"
  type        = bool
  default     = true
}

variable "create_security_alarms_sns" {
  description = "Create an SNS topic for security alarms"
  type        = bool
  default     = false
}

variable "enable_cloudwatch" {
  description = "Enable CloudWatch monitoring"
  type        = bool
  default     = true
}

variable "enable_security_alarms" {
  description = "Enable security-related CloudWatch alarms"
  type        = bool
  default     = true
}

variable "security_alarms_sns_topic_name" {
  description = "Name of the SNS topic for security alarms"
  type        = string
  default     = "security-alarms"
}

variable "security_log_group_name" {
  description = "Name of the CloudWatch log group for security logs"
  type        = string
  default     = "security-logs"
}

# ============================================================================
# KMS CONFIGURATION
# ============================================================================

variable "kms_deletion_window_in_days" {
  description = "Number of days before KMS key deletion (7-30 days)"
  type        = number
  default     = 7

  validation {
    condition     = var.kms_deletion_window_in_days >= 7 && var.kms_deletion_window_in_days <= 30
    error_message = "KMS key deletion window must be between 7 and 30 days."
  }
}

# ============================================================================
# NOTIFICATIONS
# ============================================================================

variable "alert_emails" {
  description = "List of email addresses to receive monitoring alerts"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for email in var.alert_emails : can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))])
    error_message = "All email addresses must be valid email format."
  }
}

variable "create_sns_topic" {
  description = "Whether to create SNS topic for monitoring alerts"
  type        = bool
  default     = true
}

# ============================================================================
# OTHER CONFIGURATION
# ============================================================================

variable "api_call_volume_threshold" {
  description = "Threshold for API call volume to trigger an alarm"
  type        = number
  default     = 100
}

variable "create_critical_findings_eventbridge_rule" {
  description = "Create an EventBridge rule for critical Security Hub findings"
  type        = bool
  default     = false
}

variable "create_security_dashboard" {
  description = "Create a CloudWatch dashboard for security monitoring"
  type        = bool
  default     = false
}

variable "enable_aws_foundational_security_best_practices" {
  description = "Enable AWS Foundational Security Best Practices standard in Security Hub"
  type        = bool
  default     = true
}

variable "enable_cis_aws_foundations_benchmark" {
  description = "Enable CIS AWS Foundations Benchmark in Security Hub"
  type        = bool
  default     = true
}

variable "enable_cis_standard" {
  description = "Whether to enable CIS AWS Foundations Benchmark standard in Security Hub"
  type        = bool
  default     = true
}

variable "enable_finding_aggregation" {
  description = "Enable finding aggregation across regions in Security Hub"
  type        = bool
  default     = false
}

variable "enable_nist_800_53" {
  description = "Enable NIST 800-53 standard in Security Hub"
  type        = bool
  default     = true
}

variable "enable_nist_standard" {
  description = "Whether to enable NIST Cybersecurity Framework standard in Security Hub"
  type        = bool
  default     = true
}

variable "enable_pci_dss" {
  description = "Enable PCI DSS standard in Security Hub"
  type        = bool
  default     = true
}

variable "enable_pci_dss_standard" {
  description = "Whether to enable PCI DSS standard in Security Hub"
  type        = bool
  default     = true
}

variable "failed_login_threshold" {
  description = "Threshold for failed login attempts to trigger an alarm"
  type        = number
  default     = 3
}

variable "force_destroy_buckets" {
  description = "Whether to force destroy S3 buckets even if they contain objects"
  type        = bool
  default     = false
}

variable "monitor_lambda_data_events" {
  description = "Whether to monitor Lambda data events in CloudTrail"
  type        = bool
  default     = true
}

variable "security_dashboard_name" {
  description = "Name of the CloudWatch dashboard for security monitoring"
  type        = string
  default     = "security-dashboard"
}

