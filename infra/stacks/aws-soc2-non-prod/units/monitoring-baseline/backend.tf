# Backend configuration for monitoring-baseline deployment unit
# Configuration provided via -backend-config flag
# Use: terraform init -backend-config=config/backend/{environment}.hcl

terraform {
  backend "s3" {
    # Backend-specific configuration loaded from config/backend/{environment}.hcl
    # This empty block is intentional - all values come from -backend-config
  }
}
