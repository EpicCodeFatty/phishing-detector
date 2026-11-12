# Both pinned: an unpinned provider lets a later `terraform init` pick up a new major
# version and change behaviour halfway through the project. `terraform init` records the
# exact provider build in .terraform.lock.hcl, which is committed.

terraform {
  required_version = "~> 1.17"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
  }
}
