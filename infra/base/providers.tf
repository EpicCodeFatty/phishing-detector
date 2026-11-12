# The region is not a choice: the account's project-based sign-up assigned eu-north-1,
# and the same region must appear here, in the CLI profile and in the console.

provider "aws" {
  region  = var.region
  profile = var.aws_profile

  # Applied to every resource that supports tags. After `terraform destroy`, one query for
  # Project = phishing-detector verifies the teardown, instead of a checklist per service.
  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Stack     = "base"
    }
  }
}
