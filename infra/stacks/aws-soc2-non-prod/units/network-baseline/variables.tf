# Variables for network-baseline deployment unit with compliance integration
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
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "common_tags" {
  description = "Generated from context: common_tags"
  type        = map(string)
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}

# ============================================================================
# VPC CONFIGURATION
# ============================================================================

variable "create_vpc" {
  description = "Whether to create VPC"
  type        = bool
  default     = true
}

variable "enable_dns_hostnames" {
  description = "Whether to enable DNS hostnames in the VPC"
  type        = bool
  default     = true
}

variable "enable_dns_support" {
  description = "Whether to enable DNS support in the VPC"
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "vpc_id" {
  description = "ID of the VPC where network ACLs will be created"
  type        = string
}

variable "vpc_name" {
  description = "Name of existing VPC"
  type        = string
  default     = "dev-secure-vpc"
}

# ============================================================================
# SUBNET CONFIGURATION
# ============================================================================

variable "azs" {
  description = "A list of availability zones in the region"
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.azs) >= 2 || length(var.azs) == 0
    error_message = "At least 2 availability zones must be specified for high availability, or leave empty for auto-detection."
  }
}

variable "database_subnet_cidrs" {
  description = "List of database subnet CIDR blocks"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.database_subnet_cidrs : can(cidrhost(cidr, 0))])
    error_message = "All database subnet CIDRs must be valid IPv4 CIDR blocks."
  }
}

variable "database_subnet_ids" {
  description = "List of database subnet IDs"
  type        = list(string)
  default     = []
}

variable "database_subnets" {
  description = "Database subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.201.0/24", "10.0.202.0/24", "10.0.203.0/24"]
}

variable "private_subnet_cidrs" {
  description = "List of private subnet CIDR blocks"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.private_subnet_cidrs : can(cidrhost(cidr, 0))])
    error_message = "All private subnet CIDRs must be valid IPv4 CIDR blocks."
  }
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs"
  type        = list(string)
  default     = []
}

variable "private_subnets" {
  description = "Private subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnet_cidrs" {
  description = "List of public subnet CIDR blocks"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.public_subnet_cidrs : can(cidrhost(cidr, 0))])
    error_message = "All public subnet CIDRs must be valid IPv4 CIDR blocks."
  }
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs"
  type        = list(string)
  default     = []
}

variable "public_subnets" {
  description = "Public subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

# ============================================================================
# NAT & VPN GATEWAY
# ============================================================================

variable "enable_nat_gateway" {
  description = "Whether to enable NAT Gateway"
  type        = bool
  default     = true
}

variable "enable_vpn_gateway" {
  description = "Whether to enable VPN Gateway"
  type        = bool
  default     = false
}

variable "single_nat_gateway" {
  description = "Whether to use single NAT Gateway"
  type        = bool
  default     = false
}

# ============================================================================
# SECURITY GROUPS
# ============================================================================

variable "alb_allowed_cidrs" {
  description = "CIDR blocks allowed to access ALB"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "app_custom_ingress_rules" {
  description = "Custom application ingress rules"
  type        = map(object({
  from_port                = number
  to_port                  = number
  protocol                 = string
  cidr_blocks              = optional(list(string))
  source_security_group_id = optional(string)
  description              = string
}))
  default     = {
  app_port = {
    to_port = 8080
    protocol = "tcp"
    from_port = 8080
    cidr_blocks = ["10.0.0.0/16"]
    description = "Application port access from VPC"
  }
}
}

variable "bastion_allowed_cidrs" {
  description = "CIDR blocks allowed to access bastion"
  type        = list(string)
  default     = ["203.0.113.0/24"]
}

variable "create_alb_sg" {
  description = "Whether to create ALB security group"
  type        = bool
  default     = true
}

variable "create_app_sg" {
  description = "Whether to create application security group"
  type        = bool
  default     = true
}

variable "create_bastion_sg" {
  description = "Whether to create bastion security group"
  type        = bool
  default     = true
}

variable "create_db_sg" {
  description = "Whether to create database security group"
  type        = bool
  default     = true
}

variable "db_custom_ingress_rules" {
  description = "Custom database ingress rules"
  type        = map(object({
  from_port                = number
  to_port                  = number
  protocol                 = string
  cidr_blocks              = optional(list(string))
  source_security_group_id = optional(string)
  description              = string
}))
  default     = {}
}

variable "enable_mysql_access" {
  description = "Enable MySQL access"
  type        = bool
  default     = true
}

variable "enable_postgres_access" {
  description = "Enable PostgreSQL access"
  type        = bool
  default     = true
}

# ============================================================================
# WAF CONFIGURATION
# ============================================================================

variable "allowed_ips" {
  description = "IP addresses to allow through WAF"
  type        = list(string)
  default     = []
}

variable "blocked_domains" {
  description = "Domains to block"
  type        = list(string)
  default     = [".malware.com", ".phishing.example", ".botnet.example"]
}

variable "blocked_ips" {
  description = "IP addresses to block through WAF"
  type        = list(string)
  default     = []
}

variable "enable_waf" {
  description = "Whether to enable WAF"
  type        = bool
  default     = true
}

variable "enable_waf_logging" {
  description = "Whether to enable WAF logging"
  type        = bool
  default     = true
}

variable "rate_limit_threshold" {
  description = "WAF rate limit threshold"
  type        = number
  default     = 2000
}

variable "waf_custom_rules" {
  description = "Custom WAF rules"
  type        = list(object({
  name                  = string
  priority              = number
  action                = string
  type                  = string
  country_codes         = optional(list(string))
  ip_set_arn            = optional(string)
  positional_constraint = optional(string)
  search_string         = optional(string)
  field_to_match        = optional(string)
  header_name           = optional(string)
}))
  default     = []
}

variable "waf_log_destination_arn" {
  description = "ARN of the CloudWatch Log Group or Kinesis Data Firehose for WAF logs"
  type        = string
}

variable "waf_name" {
  description = "Name of the WAF web ACL"
  type        = string
  default     = "dev-compliance-waf"
}

variable "waf_redacted_fields" {
  description = "Fields to redact from WAF logs"
  type        = list(object({
  type = string
  name = optional(string)
}))
  default     = []
}

variable "waf_scope" {
  description = "WAF scope"
  type        = string
  default     = "REGIONAL"
}

# ============================================================================
# NETWORK FIREWALL
# ============================================================================

variable "enable_firewall_logging" {
  description = "Whether to enable firewall logging"
  type        = bool
  default     = true
}

variable "enable_network_firewall" {
  description = "Whether to enable Network Firewall"
  type        = bool
  default     = false
}

variable "firewall_subnet_mappings" {
  description = "Subnet IDs for Network Firewall"
  type        = list(string)
  default     = []
}

variable "network_firewall_name" {
  description = "Name of the Network Firewall"
  type        = string
  default     = "dev-compliance-firewall"
}

variable "suricata_rules_capacity" {
  description = "Suricata rules capacity"
  type        = number
  default     = 200
}

variable "suricata_rules_content" {
  description = "Suricata rules content"
  type        = string
}

# ============================================================================
# NETWORK ACLs
# ============================================================================

variable "database_custom_rules" {
  description = "Custom database Network ACL rules"
  type        = map(object({
  rule_number = number
  protocol    = string
  action      = string
  cidr_block  = string
  from_port   = number
  to_port     = number
}))
  default     = {}
}

variable "database_dedicated_network_acl" {
  description = "Use dedicated Network ACL for database subnets"
  type        = bool
  default     = true
}

variable "enable_network_acls" {
  description = "Whether to enable Network ACLs"
  type        = bool
  default     = true
}

variable "private_dedicated_network_acl" {
  description = "Use dedicated Network ACL for private subnets"
  type        = bool
  default     = true
}

variable "public_dedicated_network_acl" {
  description = "Use dedicated Network ACL for public subnets"
  type        = bool
  default     = true
}

# ============================================================================
# VPC FLOW LOGS
# ============================================================================

variable "enable_flow_logs" {
  description = "Whether to enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "flow_logs_destination_arn" {
  description = "ARN of the destination for VPC Flow Logs if using existing resources"
  type        = string
}

variable "flow_logs_destination_type" {
  description = "VPC Flow Logs destination type"
  type        = string
  default     = "cloud-watch-logs"
}

variable "flow_logs_traffic_type" {
  description = "The type of traffic to capture (ACCEPT, REJECT, ALL)"
  type        = string
  default     = "ALL"

  validation {
    condition     = contains([ACCEPT, REJECT, ALL], var.flow_logs_traffic_type)
    error_message = "Flow logs traffic type must be one of ACCEPT, REJECT, or ALL."
  }
}

variable "log_retention_days" {
  description = "Log retention days"
  type        = number
  default     = 90
}

# ============================================================================
# OTHER CONFIGURATION
# ============================================================================

variable "custom_rule_groups" {
  description = "Custom rule groups"
  type        = list(object({
  arn      = string
  priority = number
}))
  default     = []
}

