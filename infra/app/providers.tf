# Same region and profile as infra/base. Only the Stack tag differs, which is what lets the
# teardown check ask for everything tagged Stack = app and expect nothing back.

provider "aws" {
  region  = var.region
  profile = var.aws_profile

  # Applied to every resource that supports tags, with two exceptions that matter here: the
  # Auto Scaling Group, which the provider never applies default tags to, and the instances
  # it launches. compute.tf tags both explicitly, from these same tags.
  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Stack     = "app"
    }
  }
}
