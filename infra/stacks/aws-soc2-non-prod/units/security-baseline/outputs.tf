# Outputs for security-baseline deployment unit
# Cross-unit coordination and UIC contract fulfillment
# Organization: 25cf5df0-b603-4ea5-9b55-8bfde0b728a9

output "dashboards" {
  description = "CloudWatch dashboard URLs and names"
  value       = module.security-baseline.dashboards
}

output "next_steps" {
  description = "Next steps for complete compliance setup"
  value       = module.security-baseline.next_steps
}

output "config_rules" {
  description = "Map of enabled AWS Config rules"
  value       = module.security-baseline.config_rules
}

output "audit_logging" {
  description = "Audit logging configuration and ARNs"
  value       = module.security-baseline.audit_logging
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN for quick access"
  value       = module.security-baseline.cloudtrail_arn
}

output "data_discovery" {
  description = "Data discovery configuration and ARNs"
  value       = module.security-baseline.data_discovery
}

output "access_analysis" {
  description = "Access analysis configuration and ARNs"
  value       = module.security-baseline.access_analysis
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail"
  value       = module.security-baseline.cloudtrail_name
}

output "data_protection" {
  description = "Data protection configuration and ARNs"
  value       = module.security-baseline.data_protection
}

output "deployment_info" {
  description = "Deployment information"
  value       = module.security-baseline.deployment_info
}

output "backup_schedules" {
  description = "Summary of backup schedules"
  value       = module.security-baseline.backup_schedules
}

output "backup_vault_arn" {
  description = "Primary backup vault ARN for quick access"
  value       = module.security-baseline.backup_vault_arn
}

output "config_s3_bucket" {
  description = "AWS Config S3 bucket name"
  value       = module.security-baseline.config_s3_bucket
}

output "macie_account_id" {
  description = "Macie account ID for quick access"
  value       = module.security-baseline.macie_account_id
}

output "macie_kms_key_id" {
  description = "KMS key ID used for Macie encryption"
  value       = module.security-baseline.macie_kms_key_id
  sensitive   = true
}

output "threat_detection" {
  description = "Threat detection configuration and ARNs"
  value       = module.security-baseline.threat_detection
}

output "backup_kms_key_id" {
  description = "KMS key ID used for backup encryption"
  value       = module.security-baseline.backup_kms_key_id
  sensitive   = true
}

output "backup_vault_name" {
  description = "Name of the main backup vault"
  value       = module.security-baseline.backup_vault_name
}

output "compliance_status" {
  description = "Audit logging compliance status"
  value       = module.security-baseline.compliance_status
}

output "macie_kms_key_arn" {
  description = "KMS key ARN used for Macie encryption"
  value       = module.security-baseline.macie_kms_key_arn
  sensitive   = true
}

output "backup_kms_key_arn" {
  description = "KMS key ARN used for backup encryption"
  value       = module.security-baseline.backup_kms_key_arn
  sensitive   = true
}

output "compliance_metrics" {
  description = "Key compliance metrics and status indicators"
  value       = module.security-baseline.compliance_metrics
}

output "compliance_summary" {
  description = "Overall compliance status and configuration summary"
  value       = module.security-baseline.compliance_summary
}

output "macie_service_role" {
  description = "The service role used by Macie"
  value       = module.security-baseline.macie_service_role
}

output "access_analyzer_arn" {
  description = "Access Analyzer ARN for quick access"
  value       = module.security-baseline.access_analyzer_arn
}

output "backup_iam_role_arn" {
  description = "ARN of the AWS Backup IAM role"
  value       = module.security-baseline.backup_iam_role_arn
}

output "config_iam_role_arn" {
  description = "ARN of the AWS Config IAM role"
  value       = module.security-baseline.config_iam_role_arn
}

output "macie_configuration" {
  description = "Summary of Macie configuration"
  value       = module.security-baseline.macie_configuration
}

output "macie_dashboard_url" {
  description = "URL of the Macie CloudWatch dashboard"
  value       = module.security-baseline.macie_dashboard_url
}

output "macie_kms_key_alias" {
  description = "KMS key alias for Macie encryption"
  value       = module.security-baseline.macie_kms_key_alias
  sensitive   = true
}

output "notification_topics" {
  description = "SNS topic ARNs for compliance notifications"
  value       = module.security-baseline.notification_topics
}

output "protection_features" {
  description = "Enabled protection features"
  value       = module.security-baseline.protection_features
}

output "backup_configuration" {
  description = "Summary of backup configuration"
  value       = module.security-baseline.backup_configuration
}

output "backup_iam_role_name" {
  description = "Name of the AWS Backup IAM role"
  value       = module.security-baseline.backup_iam_role_name
}

output "backup_kms_key_alias" {
  description = "KMS key alias for backup encryption"
  value       = module.security-baseline.backup_kms_key_alias
  sensitive   = true
}

output "cloudtrail_s3_bucket" {
  description = "CloudTrail S3 bucket name"
  value       = module.security-baseline.cloudtrail_s3_bucket
}

output "config_s3_bucket_arn" {
  description = "ARN of the AWS Config S3 bucket"
  value       = module.security-baseline.config_s3_bucket_arn
}

output "config_sns_topic_arn" {
  description = "ARN of the AWS Config SNS topic"
  value       = module.security-baseline.config_sns_topic_arn
}

output "daily_backup_plan_id" {
  description = "ID of the daily backup plan"
  value       = module.security-baseline.daily_backup_plan_id
}

output "guardduty_kms_key_id" {
  description = "KMS key ID used for GuardDuty findings encryption"
  value       = module.security-baseline.guardduty_kms_key_id
  sensitive   = true
}

output "macie_account_status" {
  description = "The status of the Macie account"
  value       = module.security-baseline.macie_account_status
}

output "macie_dashboard_name" {
  description = "Name of the Macie CloudWatch dashboard"
  value       = module.security-baseline.macie_dashboard_name
}

output "audit_logging_enabled" {
  description = "Whether audit logging is enabled"
  value       = module.security-baseline.audit_logging_enabled
}

output "cloudtrail_kms_key_id" {
  description = "KMS key ID used for CloudTrail encryption"
  value       = module.security-baseline.cloudtrail_kms_key_id
  sensitive   = true
}

output "config_s3_bucket_name" {
  description = "Name of the AWS Config S3 bucket"
  value       = module.security-baseline.config_s3_bucket_name
}

output "daily_backup_plan_arn" {
  description = "ARN of the daily backup plan"
  value       = module.security-baseline.daily_backup_plan_arn
}

output "data_discovery_status" {
  description = "Status summary of data discovery capabilities"
  value       = module.security-baseline.data_discovery_status
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID for quick access"
  value       = module.security-baseline.guardduty_detector_id
}

output "guardduty_kms_key_arn" {
  description = "KMS key ARN used for GuardDuty findings encryption"
  value       = module.security-baseline.guardduty_kms_key_arn
  sensitive   = true
}

output "security_hub_insights" {
  description = "Map of Security Hub custom insights"
  value       = module.security-baseline.security_hub_insights
}

output "weekly_backup_plan_id" {
  description = "ID of the weekly backup plan"
  value       = module.security-baseline.weekly_backup_plan_id
}

output "cloudtrail_kms_key_arn" {
  description = "KMS key ARN used for CloudTrail encryption"
  value       = module.security-baseline.cloudtrail_kms_key_arn
  sensitive   = true
}

output "guardduty_detector_arn" {
  description = "The ARN of the GuardDuty detector"
  value       = module.security-baseline.guardduty_detector_arn
}

output "monthly_backup_plan_id" {
  description = "ID of the monthly backup plan"
  value       = module.security-baseline.monthly_backup_plan_id
}

output "weekly_backup_plan_arn" {
  description = "ARN of the weekly backup plan"
  value       = module.security-baseline.weekly_backup_plan_arn
}

output "config_delivery_channel" {
  description = "AWS Config delivery channel name"
  value       = module.security-baseline.config_delivery_channel
}

output "macie_master_account_id" {
  description = "Macie master account ID"
  value       = module.security-baseline.macie_master_account_id
}

output "monthly_backup_plan_arn" {
  description = "ARN of the monthly backup plan"
  value       = module.security-baseline.monthly_backup_plan_arn
}

output "security_hub_account_id" {
  description = "Security Hub account ID for quick access"
  value       = module.security-baseline.security_hub_account_id
}

output "backup_vault_kms_key_arn" {
  description = "KMS key ARN used for backup vault encryption"
  value       = module.security-baseline.backup_vault_kms_key_arn
  sensitive   = true
}

output "cloudtrail_s3_bucket_arn" {
  description = "ARN of the CloudTrail S3 bucket"
  value       = module.security-baseline.cloudtrail_s3_bucket_arn
}

output "macie_results_bucket_arn" {
  description = "ARN of the S3 bucket for Macie results"
  value       = module.security-baseline.macie_results_bucket_arn
}

output "backup_retention_policies" {
  description = "Summary of backup retention policies"
  value       = module.security-baseline.backup_retention_policies
}

output "backup_vault_lock_enabled" {
  description = "Whether backup vault lock is enabled"
  value       = module.security-baseline.backup_vault_lock_enabled
}

output "cloudtrail_s3_bucket_name" {
  description = "Name of the CloudTrail S3 bucket"
  value       = module.security-baseline.cloudtrail_s3_bucket_name
}

output "critical_backup_vault_arn" {
  description = "ARN of the critical backup vault"
  value       = module.security-baseline.critical_backup_vault_arn
}

output "daily_backup_selection_id" {
  description = "ID of the daily backup selection"
  value       = module.security-baseline.daily_backup_selection_id
}

output "guardduty_findings_bucket" {
  description = "S3 bucket for GuardDuty findings"
  value       = module.security-baseline.guardduty_findings_bucket
}

output "macie_invitation_accepted" {
  description = "Whether Macie invitation was accepted"
  value       = module.security-baseline.macie_invitation_accepted
}

output "macie_results_bucket_name" {
  description = "Name of the S3 bucket for Macie results"
  value       = module.security-baseline.macie_results_bucket_name
}

output "critical_backup_vault_name" {
  description = "Name of the critical backup vault"
  value       = module.security-baseline.critical_backup_vault_name
}

output "macie_eventbridge_rule_arn" {
  description = "ARN of the Macie EventBridge rule"
  value       = module.security-baseline.macie_eventbridge_rule_arn
}

output "weekly_backup_selection_id" {
  description = "ID of the weekly backup selection"
  value       = module.security-baseline.weekly_backup_selection_id
}

output "access_analyzer_account_arn" {
  description = "ARN of the account-level Access Analyzer"
  value       = module.security-baseline.access_analyzer_account_arn
}

output "backup_eventbridge_rule_arn" {
  description = "ARN of the backup failure EventBridge rule"
  value       = module.security-baseline.backup_eventbridge_rule_arn
}

output "iam_password_policy_enabled" {
  description = "Whether IAM password policy is enabled"
  value       = module.security-baseline.iam_password_policy_enabled
  sensitive   = true
}

output "macie_classification_job_id" {
  description = "ID of the Macie classification job"
  value       = module.security-baseline.macie_classification_job_id
}

output "protection_features_enabled" {
  description = "Map of enabled threat detection features"
  value       = module.security-baseline.protection_features_enabled
}

output "security_hub_action_targets" {
  description = "Map of Security Hub custom action targets"
  value       = module.security-baseline.security_hub_action_targets
}

output "access_analyzer_account_name" {
  description = "Name of the account-level Access Analyzer"
  value       = module.security-baseline.access_analyzer_account_name
}

output "config_delivery_channel_name" {
  description = "Name of the AWS Config delivery channel"
  value       = module.security-baseline.config_delivery_channel_name
}

output "guardduty_findings_s3_bucket" {
  description = "Name of the S3 bucket for GuardDuty findings"
  value       = module.security-baseline.guardduty_findings_s3_bucket
}

output "iam_password_policy_settings" {
  description = "Current IAM password policy settings"
  value       = module.security-baseline.iam_password_policy_settings
  sensitive   = true
}

output "macie_classification_job_arn" {
  description = "ARN of the Macie classification job"
  value       = module.security-baseline.macie_classification_job_arn
}

output "access_analysis_configuration" {
  description = "Summary of Access Analysis configuration"
  value       = module.security-baseline.access_analysis_configuration
}

output "access_analyzer_archive_rules" {
  description = "Map of Access Analyzer archive rules"
  value       = module.security-baseline.access_analyzer_archive_rules
}

output "access_analyzer_dashboard_url" {
  description = "URL of the Access Analyzer CloudWatch dashboard"
  value       = module.security-baseline.access_analyzer_dashboard_url
}

output "macie_custom_data_identifiers" {
  description = "Map of custom data identifier IDs and ARNs"
  value       = module.security-baseline.macie_custom_data_identifiers
}

output "macie_notifications_topic_arn" {
  description = "ARN of the Macie notifications SNS topic"
  value       = module.security-baseline.macie_notifications_topic_arn
}

output "access_analyzer_dashboard_name" {
  description = "Name of the Access Analyzer CloudWatch dashboard"
  value       = module.security-baseline.access_analyzer_dashboard_name
}

output "backup_notifications_topic_arn" {
  description = "ARN of the backup notifications SNS topic"
  value       = module.security-baseline.backup_notifications_topic_arn
}

output "guardduty_eventbridge_rule_arn" {
  description = "ARN of the GuardDuty EventBridge rule"
  value       = module.security-baseline.guardduty_eventbridge_rule_arn
}

output "security_hub_enabled_standards" {
  description = "Map of enabled Security Hub standards"
  value       = module.security-baseline.security_hub_enabled_standards
}

output "access_analyzer_custom_role_arn" {
  description = "ARN of the custom Access Analyzer IAM role"
  value       = module.security-baseline.access_analyzer_custom_role_arn
}

output "backup_vault_lock_configuration" {
  description = "Backup vault lock configuration details"
  value       = module.security-baseline.backup_vault_lock_configuration
}

output "macie_classification_job_status" {
  description = "Status of the Macie classification job"
  value       = module.security-baseline.macie_classification_job_status
}

output "access_analyzer_custom_role_name" {
  description = "Name of the custom Access Analyzer IAM role"
  value       = module.security-baseline.access_analyzer_custom_role_name
}

output "access_analyzer_organization_arn" {
  description = "ARN of the organization-level Access Analyzer"
  value       = module.security-baseline.access_analyzer_organization_arn
}

output "guardduty_findings_s3_bucket_arn" {
  description = "ARN of the S3 bucket for GuardDuty findings"
  value       = module.security-baseline.guardduty_findings_s3_bucket_arn
}

output "macie_delegated_admin_account_id" {
  description = "Macie delegated administrator account ID"
  value       = module.security-baseline.macie_delegated_admin_account_id
}

output "securityhub_eventbridge_rule_arn" {
  description = "ARN of the Security Hub EventBridge rule"
  value       = module.security-baseline.securityhub_eventbridge_rule_arn
}

output "access_analyzer_organization_name" {
  description = "Name of the organization-level Access Analyzer"
  value       = module.security-baseline.access_analyzer_organization_name
}

output "guardduty_notifications_topic_arn" {
  description = "ARN of the GuardDuty notifications SNS topic"
  value       = module.security-baseline.guardduty_notifications_topic_arn
}

output "config_configuration_recorder_name" {
  description = "Name of the AWS Config configuration recorder"
  value       = module.security-baseline.config_configuration_recorder_name
}

output "access_analyzer_eventbridge_rule_arn" {
  description = "ARN of the Access Analyzer EventBridge rule"
  value       = module.security-baseline.access_analyzer_eventbridge_rule_arn
}

output "guardduty_publishing_destination_arn" {
  description = "ARN of the GuardDuty publishing destination"
  value       = module.security-baseline.guardduty_publishing_destination_arn
}

output "security_hub_notifications_topic_arn" {
  description = "ARN of the Security Hub notifications SNS topic"
  value       = module.security-baseline.security_hub_notifications_topic_arn
}

output "access_analyzer_notifications_topic_arn" {
  description = "ARN of the Access Analyzer notifications SNS topic"
  value       = module.security-baseline.access_analyzer_notifications_topic_arn
}

