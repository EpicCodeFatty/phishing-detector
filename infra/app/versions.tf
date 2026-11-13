# The same Terraform and AWS provider as infra/base. This stack adds the archive provider,
# which zips app/ into the release (artifact.tf). `terraform init` records the exact
# provider builds in .terraform.lock.hcl, which is committed; adding a provider means
# running init once more and committing the updated lock file.

terraform {
  required_version = "~> 1.17"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }

    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }
}
