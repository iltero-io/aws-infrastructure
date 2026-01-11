# Outputs for monitoring-baseline deployment unit
# Cross-unit coordination and UIC contract fulfillment
# Organization: 25cf5df0-b603-4ea5-9b55-8bfde0b728a9

output "kms_key_id" {
  description = "ID of the KMS key used for encryption"
  value       = module.monitoring-baseline.kms_key_id
  sensitive   = true
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for encryption"
  value       = module.monitoring-baseline.kms_key_arn
  sensitive   = true
}

output "cloudtrail_id" {
  description = "The ID of the CloudTrail"
  value       = module.monitoring-baseline.cloudtrail_id
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for monitoring alerts (if created)"
  value       = module.monitoring-baseline.sns_topic_arn
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail"
  value       = module.monitoring-baseline.cloudtrail_arn
}

output "log_management" {
  description = "Log management module outputs"
  value       = module.monitoring-baseline.log_management
}

output "config_role_arn" {
  description = "The ARN of the IAM role for AWS Config"
  value       = module.monitoring-baseline.config_role_arn
}

output "config_bucket_id" {
  description = "The ID of the S3 bucket for AWS Config logs"
  value       = module.monitoring-baseline.config_bucket_id
}

output "config_role_name" {
  description = "The name of the IAM role for AWS Config"
  value       = module.monitoring-baseline.config_role_name
}

output "security_hub_arn" {
  description = "The ARN of the Security Hub"
  value       = module.monitoring-baseline.security_hub_arn
}

output "config_bucket_arn" {
  description = "The ARN of the S3 bucket for AWS Config logs"
  value       = module.monitoring-baseline.config_bucket_arn
}

output "config_recorder_id" {
  description = "The ID of the AWS Config recorder"
  value       = module.monitoring-baseline.config_recorder_id
}

output "config_s3_bucket_id" {
  description = "ID of the S3 bucket used for AWS Config logs"
  value       = module.monitoring-baseline.config_s3_bucket_id
}

output "security_monitoring" {
  description = "Security monitoring module outputs"
  value       = module.monitoring-baseline.security_monitoring
}

output "cloudtrail_bucket_id" {
  description = "The ID of the S3 bucket for CloudTrail logs"
  value       = module.monitoring-baseline.cloudtrail_bucket_id
}

output "config_recorder_name" {
  description = "The name of the AWS Config recorder"
  value       = module.monitoring-baseline.config_recorder_name
}

output "config_s3_bucket_arn" {
  description = "ARN of the S3 bucket used for AWS Config logs"
  value       = module.monitoring-baseline.config_s3_bucket_arn
}

output "security_hub_enabled" {
  description = "Whether AWS Security Hub is enabled"
  value       = module.monitoring-baseline.security_hub_enabled
}

output "cloudtrail_bucket_arn" {
  description = "The ARN of the S3 bucket for CloudTrail logs"
  value       = module.monitoring-baseline.cloudtrail_bucket_arn
}

output "compliance_monitoring" {
  description = "Compliance monitoring module outputs"
  value       = module.monitoring-baseline.compliance_monitoring
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = module.monitoring-baseline.guardduty_detector_id
}

output "cloudtrail_home_region" {
  description = "The home region of the CloudTrail"
  value       = module.monitoring-baseline.cloudtrail_home_region
}

output "guardduty_detector_arn" {
  description = "ARN of the GuardDuty detector"
  value       = module.monitoring-baseline.guardduty_detector_arn
}

output "guardduty_s3_bucket_id" {
  description = "ID of the S3 bucket used for GuardDuty findings (if created)"
  value       = module.monitoring-baseline.guardduty_s3_bucket_id
}

output "security_log_group_arn" {
  description = "The ARN of the security log group"
  value       = module.monitoring-baseline.security_log_group_arn
}

output "cloudtrail_s3_bucket_id" {
  description = "ID of the S3 bucket used for CloudTrail logs"
  value       = module.monitoring-baseline.cloudtrail_s3_bucket_id
}

output "guardduty_event_rule_id" {
  description = "The ID of the CloudWatch Events rule for high severity GuardDuty findings"
  value       = module.monitoring-baseline.guardduty_event_rule_id
}

output "guardduty_s3_bucket_arn" {
  description = "ARN of the S3 bucket used for GuardDuty findings (if created)"
  value       = module.monitoring-baseline.guardduty_s3_bucket_arn
}

output "security_dashboard_name" {
  description = "The name of the security dashboard"
  value       = module.monitoring-baseline.security_dashboard_name
}

output "security_hub_account_id" {
  description = "AWS account ID where Security Hub is enabled"
  value       = module.monitoring-baseline.security_hub_account_id
}

output "cloudtrail_log_group_arn" {
  description = "The ARN of the CloudWatch log group for CloudTrail"
  value       = module.monitoring-baseline.cloudtrail_log_group_arn
}

output "cloudtrail_s3_bucket_arn" {
  description = "ARN of the S3 bucket used for CloudTrail logs"
  value       = module.monitoring-baseline.cloudtrail_s3_bucket_arn
}

output "cloudwatch_dashboard_url" {
  description = "URL to the CloudWatch dashboard (if created)"
  value       = module.monitoring-baseline.cloudwatch_dashboard_url
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for CloudTrail"
  value       = module.monitoring-baseline.cloudwatch_log_group_arn
}

output "guardduty_event_rule_arn" {
  description = "The ARN of the CloudWatch Events rule for high severity GuardDuty findings"
  value       = module.monitoring-baseline.guardduty_event_rule_arn
}

output "api_call_volume_alarm_arn" {
  description = "The ARN of the API call volume alarm"
  value       = module.monitoring-baseline.api_call_volume_alarm_arn
}

output "cloudtrail_log_group_name" {
  description = "The name of the CloudWatch log group for CloudTrail"
  value       = module.monitoring-baseline.cloudtrail_log_group_name
}

output "config_delivery_channel_id" {
  description = "The ID of the AWS Config delivery channel"
  value       = module.monitoring-baseline.config_delivery_channel_id
}

output "logging_monitoring_baseline" {
  description = "Complete logging monitoring baseline module outputs"
  value       = module.monitoring-baseline.logging_monitoring_baseline
}

output "config_delivery_channel_name" {
  description = "Name of the AWS Config delivery channel"
  value       = module.monitoring-baseline.config_delivery_channel_name
}

output "guardduty_findings_bucket_id" {
  description = "The ID of the S3 bucket for GuardDuty findings"
  value       = module.monitoring-baseline.guardduty_findings_bucket_id
}

output "root_account_usage_alarm_arn" {
  description = "The ARN of the root account usage alarm"
  value       = module.monitoring-baseline.root_account_usage_alarm_arn
}

output "guardduty_findings_bucket_arn" {
  description = "The ARN of the S3 bucket for GuardDuty findings"
  value       = module.monitoring-baseline.guardduty_findings_bucket_arn
}

output "security_alarms_sns_topic_arn" {
  description = "The ARN of the security alarms SNS topic"
  value       = module.monitoring-baseline.security_alarms_sns_topic_arn
}

output "security_hub_standards_enabled" {
  description = "A map of AWS Security Hub standards that are enabled"
  value       = module.monitoring-baseline.security_hub_standards_enabled
}

output "failed_console_logins_alarm_arn" {
  description = "The ARN of the failed console logins alarm"
  value       = module.monitoring-baseline.failed_console_logins_alarm_arn
}

output "guardduty_findings_sns_topic_arn" {
  description = "The ARN of the SNS topic for GuardDuty findings notifications"
  value       = module.monitoring-baseline.guardduty_findings_sns_topic_arn
}

output "config_configuration_recorder_name" {
  description = "Name of the AWS Config configuration recorder"
  value       = module.monitoring-baseline.config_configuration_recorder_name
}

output "security_hub_findings_sns_topic_arn" {
  description = "The ARN of the Security Hub findings SNS topic"
  value       = module.monitoring-baseline.security_hub_findings_sns_topic_arn
}

