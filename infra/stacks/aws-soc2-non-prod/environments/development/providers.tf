provider "aws" {
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::396913727583:role/TerraformExecutionRole"
  }
  default_tags {
    tags = {
      Project = "aws-soc2-non-prod"
      Environment = "${var.environment}"
      ManagedBy = "Terraform"
      Compliance = "AWS-Well-Architected"
    }
  }
}
