# Outputs for network-baseline deployment unit
# Cross-unit coordination and UIC contract fulfillment
# Organization: 25cf5df0-b603-4ea5-9b55-8bfde0b728a9

output "vpc_id" {
  description = "The ID of the VPC"
  value       = module.network-baseline.vpc_id
}

output "vpc_arn" {
  description = "The ARN of the VPC"
  value       = module.network-baseline.vpc_arn
}

output "firewall_id" {
  description = "ID of the Network Firewall"
  value       = module.network-baseline.firewall_id
}

output "firewall_arn" {
  description = "ARN of the Network Firewall"
  value       = module.network-baseline.firewall_arn
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = module.network-baseline.vpc_cidr_block
}

output "waf_web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = module.network-baseline.waf_web_acl_id
}

output "firewall_status" {
  description = "Nested list of information about the current status of the firewall"
  value       = module.network-baseline.firewall_status
}

output "nat_gateway_ids" {
  description = "IDs of the NAT Gateways"
  value       = module.network-baseline.nat_gateway_ids
}

output "network_acl_ids" {
  description = "Map of all network ACL IDs"
  value       = module.network-baseline.network_acl_ids
}

output "vpc_flow_log_id" {
  description = "The ID of the VPC Flow Log resource"
  value       = module.network-baseline.vpc_flow_log_id
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF WebACL"
  value       = module.network-baseline.waf_web_acl_arn
}

output "waf_web_acl_name" {
  description = "Name of the WAF Web ACL"
  value       = module.network-baseline.waf_web_acl_name
}

output "public_subnet_ids" {
  description = "List of IDs of public subnets"
  value       = module.network-baseline.public_subnet_ids
}

output "firewall_policy_id" {
  description = "ID of the Network Firewall policy"
  value       = module.network-baseline.firewall_policy_id
}

output "flow_log_group_arn" {
  description = "ARN of the CloudWatch log group for firewall flow logs"
  value       = module.network-baseline.flow_log_group_arn
}

output "private_subnet_ids" {
  description = "List of IDs of private subnets"
  value       = module.network-baseline.private_subnet_ids
}

output "public_subnet_arns" {
  description = "List of ARNs of public subnets"
  value       = module.network-baseline.public_subnet_arns
}

output "security_group_ids" {
  description = "Map of all security group IDs"
  value       = module.network-baseline.security_group_ids
}

output "alert_log_group_arn" {
  description = "ARN of the CloudWatch log group for firewall alerts"
  value       = module.network-baseline.alert_log_group_arn
}

output "database_subnet_ids" {
  description = "List of IDs of database subnets"
  value       = module.network-baseline.database_subnet_ids
}

output "firewall_policy_arn" {
  description = "ARN of the firewall policy"
  value       = module.network-baseline.firewall_policy_arn
}

output "flow_log_group_name" {
  description = "Name of the flow log group"
  value       = module.network-baseline.flow_log_group_name
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = module.network-baseline.internet_gateway_id
}

output "private_subnet_arns" {
  description = "List of ARNs of private subnets"
  value       = module.network-baseline.private_subnet_arns
}

output "alert_log_group_name" {
  description = "Name of the alert log group"
  value       = module.network-baseline.alert_log_group_name
}

output "database_subnet_arns" {
  description = "List of ARNs of database subnets"
  value       = module.network-baseline.database_subnet_arns
}

output "db_security_group_id" {
  description = "ID of the database security group"
  value       = module.network-baseline.db_security_group_id
}

output "internet_gateway_arn" {
  description = "The ARN of the Internet Gateway"
  value       = module.network-baseline.internet_gateway_arn
}

output "waf_web_acl_capacity" {
  description = "Capacity units used by the WAF Web ACL"
  value       = module.network-baseline.waf_web_acl_capacity
}

output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = module.network-baseline.alb_security_group_id
}

output "app_security_group_id" {
  description = "ID of the application security group"
  value       = module.network-baseline.app_security_group_id
}

output "db_security_group_arn" {
  description = "ARN of the database security group"
  value       = module.network-baseline.db_security_group_arn
}

output "public_network_acl_id" {
  description = "ID of the public network ACL"
  value       = module.network-baseline.public_network_acl_id
}

output "public_route_table_id" {
  description = "ID of the public route table"
  value       = module.network-baseline.public_route_table_id
}

output "alb_security_group_arn" {
  description = "ARN of the ALB security group"
  value       = module.network-baseline.alb_security_group_arn
}

output "app_security_group_arn" {
  description = "ARN of the application security group"
  value       = module.network-baseline.app_security_group_arn
}

output "nat_gateway_public_ips" {
  description = "List of public Elastic IPs associated with the NAT Gateways"
  value       = module.network-baseline.nat_gateway_public_ips
}

output "private_network_acl_id" {
  description = "ID of the private network ACL"
  value       = module.network-baseline.private_network_acl_id
}

output "public_network_acl_arn" {
  description = "ARN of the public network ACL"
  value       = module.network-baseline.public_network_acl_arn
}

output "suricata_rule_group_id" {
  description = "ID of the Suricata rule group"
  value       = module.network-baseline.suricata_rule_group_id
}

output "database_network_acl_id" {
  description = "ID of the database network ACL"
  value       = module.network-baseline.database_network_acl_id
}

output "private_network_acl_arn" {
  description = "ARN of the private network ACL"
  value       = module.network-baseline.private_network_acl_arn
}

output "private_route_table_ids" {
  description = "List of IDs of the private route tables"
  value       = module.network-baseline.private_route_table_ids
}

output "suricata_rule_group_arn" {
  description = "ARN of the Suricata rule group"
  value       = module.network-baseline.suricata_rule_group_arn
}

output "waf_allowlist_ip_set_id" {
  description = "ID of the WAF allowlist IP set"
  value       = module.network-baseline.waf_allowlist_ip_set_id
}

output "waf_blocklist_ip_set_id" {
  description = "ID of the WAF blocklist IP set"
  value       = module.network-baseline.waf_blocklist_ip_set_id
}

output "database_network_acl_arn" {
  description = "ARN of the database network ACL"
  value       = module.network-baseline.database_network_acl_arn
}

output "database_route_table_ids" {
  description = "List of IDs of the database route tables"
  value       = module.network-baseline.database_route_table_ids
}

output "waf_allowlist_ip_set_arn" {
  description = "ARN of the WAF allowlist IP set"
  value       = module.network-baseline.waf_allowlist_ip_set_arn
}

output "waf_blocklist_ip_set_arn" {
  description = "ARN of the WAF blocklist IP set"
  value       = module.network-baseline.waf_blocklist_ip_set_arn
}

output "bastion_security_group_id" {
  description = "ID of the bastion host security group"
  value       = module.network-baseline.bastion_security_group_id
}

output "network_security_baseline" {
  description = "Complete network security baseline configuration"
  value       = module.network-baseline.network_security_baseline
}

output "public_subnet_cidr_blocks" {
  description = "List of CIDR blocks of public subnets"
  value       = module.network-baseline.public_subnet_cidr_blocks
}

output "waf_logging_configuration" {
  description = "WAF logging configuration resource ARN"
  value       = module.network-baseline.waf_logging_configuration
}

output "bastion_security_group_arn" {
  description = "ARN of the bastion security group"
  value       = module.network-baseline.bastion_security_group_arn
}

output "private_subnet_cidr_blocks" {
  description = "List of CIDR blocks of private subnets"
  value       = module.network-baseline.private_subnet_cidr_blocks
}

output "database_subnet_cidr_blocks" {
  description = "List of CIDR blocks of database subnets"
  value       = module.network-baseline.database_subnet_cidr_blocks
}

output "vpc_flow_log_s3_bucket_name" {
  description = "The name of the S3 bucket for VPC Flow Logs"
  value       = module.network-baseline.vpc_flow_log_s3_bucket_name
}

output "domain_filtering_rule_group_id" {
  description = "ID of the domain filtering rule group"
  value       = module.network-baseline.domain_filtering_rule_group_id
}

output "domain_filtering_rule_group_arn" {
  description = "ARN of the domain filtering rule group"
  value       = module.network-baseline.domain_filtering_rule_group_arn
}

output "vpc_flow_log_cloudwatch_log_group_name" {
  description = "The name of the CloudWatch Log Group for VPC Flow Logs"
  value       = module.network-baseline.vpc_flow_log_cloudwatch_log_group_name
}

