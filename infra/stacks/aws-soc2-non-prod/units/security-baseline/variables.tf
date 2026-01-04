# Variables for security-baseline deployment unit with compliance integration
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

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string

  validation {
    condition     = var.aws_account_id == None || can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "AWS account ID must be a 12-digit number."
  }
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.aws_region))
    error_message = "AWS region must be a valid region identifier."
  }
}

variable "common_tags" {
  description = "Generated from context: common_tags"
  type        = map(string)
}

variable "environment" {
  description = "Environment name (e.g., dev, stage, prod)"
  type        = string
  default     = "prod"

  validation {
    condition     = can(regex("^(dev|stage|prod|test)$", var.environment))
    error_message = "Environment must be one of: dev, stage, prod, test."
  }
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {
  Owner = "Security Team"
  Project = "AWS Compliance Baseline"
  Purpose = "Security and Compliance"
  CostCenter = "Security"
}
}

# ============================================================================
# CLOUDTRAIL
# ============================================================================

variable "cloudtrail_kms_key_id" {
  description = "KMS key ID for CloudTrail encryption (auto-generated if not specified)"
  type        = string
}

variable "cloudtrail_name" {
  description = "Name for the CloudTrail trail"
  type        = string
  default     = "compliance-audit-trail"
}

variable "cloudtrail_s3_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs (auto-generated if not specified)"
  type        = string
}

variable "enable_cloudtrail" {
  description = "Whether to enable AWS CloudTrail for audit logging"
  type        = bool
  default     = true
}

variable "enable_cloudtrail_data_events" {
  description = "Whether to enable CloudTrail data events (S3 object-level API operations)"
  type        = bool
  default     = true
}

# ============================================================================
# AWS CONFIG
# ============================================================================

variable "config_delivery_frequency" {
  description = "The frequency with which AWS Config delivers configuration snapshots"
  type        = string
  default     = "Six_Hours"

  validation {
    condition     = contains([One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours], var.config_delivery_frequency)
    error_message = "Config delivery frequency must be one of: One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours."
  }
}

variable "config_excluded_resource_types" {
  description = "List of resource types to exclude from Config recording"
  type        = list(string)
  default     = []
}

variable "config_include_global_resources" {
  description = "Whether Config should include global resources (IAM, etc.)"
  type        = bool
  default     = true
}

variable "config_record_all_resources" {
  description = "Whether Config should record all supported resources"
  type        = bool
  default     = true
}

variable "config_s3_bucket_name" {
  description = "Name of the S3 bucket for AWS Config delivery (auto-generated if not specified)"
  type        = string
}

variable "config_sns_topic_name" {
  description = "Name of the SNS topic for AWS Config notifications (auto-generated if not specified)"
  type        = string
}

variable "enable_config" {
  description = "Whether to enable AWS Config for compliance monitoring"
  type        = bool
  default     = true
}

variable "enable_config_rules" {
  description = "Whether to enable AWS Config compliance rules"
  type        = bool
  default     = true
}

# ============================================================================
# GUARDDUTY
# ============================================================================

variable "enable_guardduty" {
  description = "Whether to enable AWS GuardDuty"
  type        = bool
  default     = true
}

variable "enable_guardduty_eks_protection" {
  description = "Whether to enable GuardDuty EKS protection"
  type        = bool
  default     = true
}

variable "enable_guardduty_malware_protection" {
  description = "Whether to enable GuardDuty malware protection"
  type        = bool
  default     = true
}

variable "enable_guardduty_notifications" {
  description = "Whether to enable GuardDuty finding notifications"
  type        = bool
  default     = true
}

variable "enable_guardduty_s3_protection" {
  description = "Whether to enable GuardDuty S3 protection"
  type        = bool
  default     = true
}

variable "guardduty_export_findings_to_s3" {
  description = "Whether to export GuardDuty findings to S3"
  type        = bool
  default     = true
}

variable "guardduty_finding_frequency" {
  description = "Frequency of findings publication from GuardDuty"
  type        = string
  default     = "SIX_HOURS"

  validation {
    condition     = contains([FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS], var.guardduty_finding_frequency)
    error_message = "GuardDuty finding frequency must be one of: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS."
  }
}

variable "guardduty_notification_severity_levels" {
  description = "List of GuardDuty finding severity levels to notify on"
  type        = list(string)
  default     = ["HIGH", "CRITICAL"]

  validation {
    condition     = alltrue([for level in var.guardduty_notification_severity_levels : contains([LOW, MEDIUM, HIGH, CRITICAL], level)])
    error_message = "GuardDuty notification severity levels must be from: LOW, MEDIUM, HIGH, CRITICAL."
  }
}

# ============================================================================
# SECURITY HUB
# ============================================================================

variable "compliance_frameworks" {
  description = "List of compliance frameworks to enable"
  type        = list(string)
  default     = ["pci_dss", "hipaa", "gdpr", "sox", "fedramp"]

  validation {
    condition     = alltrue([for framework in var.compliance_frameworks : contains([pci_dss, hipaa, gdpr, sox, fedramp, soc2, iso27001], framework)])
    error_message = "Compliance frameworks must be from: pci_dss, hipaa, gdpr, sox, fedramp, soc2, iso27001."
  }
}

variable "enable_security_hub" {
  description = "Whether to enable AWS Security Hub"
  type        = bool
  default     = true
}

variable "enable_securityhub_notifications" {
  description = "Whether to enable Security Hub finding notifications"
  type        = bool
  default     = true
}

variable "security_hub_enable_standards" {
  description = "Map of Security Hub standards to enable"
  type        = map(bool)
  default     = {
  pci_dss = true
  cis_aws_foundations_benchmark = true
  aws_foundational_security_best_practices = true
}
}

variable "securityhub_notification_severity_levels" {
  description = "List of Security Hub finding severity levels to notify on"
  type        = list(string)
  default     = ["HIGH", "CRITICAL"]

  validation {
    condition     = alltrue([for level in var.securityhub_notification_severity_levels : contains([INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL], level)])
    error_message = "Security Hub notification severity levels must be from: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL."
  }
}

# ============================================================================
# MACIE
# ============================================================================

variable "create_macie_dashboard" {
  description = "Whether to create CloudWatch dashboard for Macie metrics"
  type        = bool
  default     = true
}

variable "enable_macie" {
  description = "Whether to enable Amazon Macie"
  type        = bool
  default     = true
}

variable "enable_macie_classification_jobs" {
  description = "Whether to enable Macie classification jobs"
  type        = bool
  default     = true
}

variable "enable_macie_notifications" {
  description = "Whether to enable Macie finding notifications"
  type        = bool
  default     = true
}

variable "macie_classification_bucket_names" {
  description = "List of S3 bucket names for Macie classification"
  type        = list(string)
  default     = []
}

variable "macie_classification_schedule_frequency" {
  description = "Schedule frequency for Macie classification jobs"
  type        = string
  default     = "WEEKLY"

  validation {
    condition     = contains([DAILY, WEEKLY, MONTHLY], var.macie_classification_schedule_frequency)
    error_message = "Macie classification schedule frequency must be one of: DAILY, WEEKLY, MONTHLY."
  }
}

variable "macie_custom_data_identifiers" {
  description = "Custom data identifiers for Macie"
  type        = list(object({
  name        = string
  description = string
  regex       = string
  keywords    = list(string)
}))
  default     = []
}

variable "macie_delegated_admin_account_id" {
  description = "Macie delegated administrator account ID"
  type        = string
}

variable "macie_finding_publishing_frequency" {
  description = "Frequency of findings publication from Macie"
  type        = string
  default     = "SIX_HOURS"

  validation {
    condition     = contains([FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS], var.macie_finding_publishing_frequency)
    error_message = "Macie finding publishing frequency must be one of: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS."
  }
}

variable "macie_kms_key_arn" {
  description = "Custom KMS key ARN for Macie encryption (auto-generated if not specified)"
  type        = string
  default     = ""

  validation {
    condition     = var.macie_kms_key_arn == "" || can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-f0-9-]+$", var.macie_kms_key_arn))
    error_message = "KMS key ARN must be a valid AWS KMS key ARN format."
  }
}

variable "macie_master_account_id" {
  description = "Macie master account ID for multi-account setup"
  type        = string
}

variable "macie_notification_severity_scores" {
  description = "List of Macie finding severity scores to notify on"
  type        = list(number)
  default     = [4.0, 7.0, 8.5]
}

variable "macie_results_expiration_days" {
  description = "Days after which Macie results expire"
  type        = number
  default     = 365
}

variable "macie_results_noncurrent_expiration_days" {
  description = "Days after which non-current Macie results expire"
  type        = number
  default     = 30
}

variable "macie_results_transition_to_glacier_days" {
  description = "Days after which Macie results transition to Glacier storage"
  type        = number
  default     = 90
}

variable "macie_results_transition_to_ia_days" {
  description = "Days after which Macie results transition to IA storage"
  type        = number
  default     = 30
}

# ============================================================================
# AWS BACKUP
# ============================================================================

variable "backup_completion_window" {
  description = "Backup completion window in minutes"
  type        = number
  default     = 120

  validation {
    condition     = var.backup_completion_window >= 60 && var.backup_completion_window <= 720
    error_message = "Backup completion window must be between 60 and 720 minutes."
  }
}

variable "backup_kms_key_arn" {
  description = "Custom KMS key ARN for backup encryption (auto-generated if not specified)"
  type        = string

  validation {
    condition     = var.backup_kms_key_arn == None || can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-f0-9-]+$", var.backup_kms_key_arn))
    error_message = "KMS key ARN must be a valid AWS KMS key ARN format."
  }
}

variable "backup_resource_arns" {
  description = "List of resource ARNs to include in backup selection"
  type        = list(string)
  default     = []
}

variable "backup_start_window" {
  description = "Backup start window in minutes"
  type        = number
  default     = 60

  validation {
    condition     = var.backup_start_window >= 60 && var.backup_start_window <= 720
    error_message = "Backup start window must be between 60 and 720 minutes."
  }
}

variable "backup_tag_conditions" {
  description = "Tag conditions for backup selection"
  type        = list(object({
  key   = string
  value = string
}))
  default     = [
  {key = "Backup", value = "true"},
]
}

variable "backup_vault_lock_changeable_days" {
  description = "Number of days after vault lock when it can be changed"
  type        = number
  default     = 3

  validation {
    condition     = var.backup_vault_lock_changeable_days >= 0 && var.backup_vault_lock_changeable_days <= 36500
    error_message = "Backup vault lock changeable days must be between 0 and 36500."
  }
}

variable "backup_vault_lock_max_retention_days" {
  description = "Maximum retention period in days for backup vault lock"
  type        = number
  default     = 365

  validation {
    condition     = var.backup_vault_lock_max_retention_days >= 1 && var.backup_vault_lock_max_retention_days <= 36500
    error_message = "Backup vault lock max retention days must be between 1 and 36500."
  }
}

variable "backup_vault_lock_min_retention_days" {
  description = "Minimum retention period in days for backup vault lock"
  type        = number
  default     = 7

  validation {
    condition     = var.backup_vault_lock_min_retention_days >= 1 && var.backup_vault_lock_min_retention_days <= 36500
    error_message = "Backup vault lock min retention days must be between 1 and 36500."
  }
}

variable "backup_vault_name" {
  description = "Name of the backup vault"
  type        = string
}

variable "create_critical_backup_vault" {
  description = "Whether to create a separate vault for critical backups"
  type        = bool
  default     = true
}

variable "daily_backup_cold_storage_after" {
  description = "Days after which daily backups move to cold storage"
  type        = number
  default     = 30
}

variable "daily_backup_delete_after" {
  description = "Days after which daily backups are deleted"
  type        = number
  default     = 120
}

variable "daily_backup_schedule" {
  description = "Cron expression for daily backup schedule"
  type        = string
  default     = "cron(0 5 ? * * *)"
}

variable "enable_backup" {
  description = "Whether to enable AWS Backup"
  type        = bool
  default     = true
}

variable "enable_backup_notifications" {
  description = "Whether to enable backup job notifications"
  type        = bool
  default     = true
}

variable "enable_backup_vault_lock" {
  description = "Whether to enable backup vault lock for compliance"
  type        = bool
  default     = true
}

variable "enable_daily_backups" {
  description = "Whether to enable daily backup plans"
  type        = bool
  default     = true
}

variable "enable_monthly_backups" {
  description = "Whether to enable monthly backup plans"
  type        = bool
  default     = true
}

variable "enable_weekly_backups" {
  description = "Whether to enable weekly backup plans"
  type        = bool
  default     = true
}

variable "monthly_backup_cold_storage_after" {
  description = "Days after which monthly backups move to cold storage"
  type        = number
  default     = 30
}

variable "monthly_backup_delete_after" {
  description = "Days after which monthly backups are deleted"
  type        = number
  default     = 2555
}

variable "monthly_backup_schedule" {
  description = "Cron expression for monthly backup schedule"
  type        = string
  default     = "cron(0 5 1 * ? *)"
}

variable "weekly_backup_cold_storage_after" {
  description = "Days after which weekly backups move to cold storage"
  type        = number
  default     = 30
}

variable "weekly_backup_delete_after" {
  description = "Days after which weekly backups are deleted"
  type        = number
  default     = 365
}

variable "weekly_backup_schedule" {
  description = "Cron expression for weekly backup schedule"
  type        = string
  default     = "cron(0 5 ? * SUN *)"
}

# ============================================================================
# IAM CONFIGURATION
# ============================================================================

variable "enable_iam_analyzer" {
  description = "Whether to enable IAM Access Analyzer"
  type        = bool
  default     = true
}

variable "enable_iam_password_policy" {
  description = "Whether to enforce IAM password policy"
  type        = bool
  default     = true
}

variable "iam_password_policy" {
  description = "IAM password policy configuration"
  type        = map(any)
  default     = {
  require_numbers = true
  require_symbols = true
  max_password_age = 90
  minimum_password_length = 14
  password_reuse_prevention = 24
  require_lowercase_characters = true
  require_uppercase_characters = true
  allow_users_to_change_password = true
}
}

# ============================================================================
# KMS CONFIGURATION
# ============================================================================

variable "kms_key_arn" {
  description = "Custom KMS key ARN for encryption (optional)"
  type        = string
  default     = ""

  validation {
    condition     = var.kms_key_arn == "" || can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-f0-9-]+$", var.kms_key_arn))
    error_message = "KMS key ARN must be a valid AWS KMS key ARN format."
  }
}

# ============================================================================
# NOTIFICATIONS
# ============================================================================

variable "enable_analyzer_notifications" {
  description = "Whether to enable Access Analyzer finding notifications"
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Email address for compliance notifications (leave empty to disable)"
  type        = string
  default     = ""

  validation {
    condition     = var.notification_email == "" || can(regex("^[^@]+@[^@]+\\.[^@]+$", var.notification_email))
    error_message = "Notification email must be a valid email address or empty string."
  }
}

# ============================================================================
# OTHER CONFIGURATION
# ============================================================================

variable "create_access_analyzer_dashboard" {
  description = "Whether to create CloudWatch dashboard for Access Analyzer metrics"
  type        = bool
  default     = true
}

variable "create_compliance_dashboard" {
  description = "Whether to create a comprehensive compliance dashboard"
  type        = bool
  default     = true
}

variable "create_custom_analyzer_role" {
  description = "Whether to create a custom IAM role for Access Analyzer"
  type        = bool
  default     = false
}

variable "enable_auto_archive_rules" {
  description = "Whether to create auto-archive rules for trusted findings"
  type        = bool
  default     = true
}

variable "enable_org_analyzer" {
  description = "Whether to enable organization-level analyzer (requires management account)"
  type        = bool
  default     = false
}

variable "trusted_aws_services" {
  description = "List of trusted AWS service principals to auto-archive"
  type        = list(string)
  default     = [
  "lambda.amazonaws.com",
  "ec2.amazonaws.com",
  "ecs-tasks.amazonaws.com",
  "rds.amazonaws.com",
  "backup.amazonaws.com",
]
}

variable "trusted_external_accounts" {
  description = "List of trusted external AWS account IDs to auto-archive"
  type        = list(string)
  default     = []
}

