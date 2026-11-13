# Identical to infra/base, so both stacks run on the same Terraform and the same provider.
# `terraform init` records the exact provider build in .terraform.lock.hcl, which is committed.

terraform {
  required_version = "~> 1.17"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
  }
}
