# All pinned: an unpinned provider lets a later `terraform init` pick up a new major
# version and change behaviour halfway through the project. `terraform init` records the
# exact provider builds in .terraform.lock.hcl, which is committed; adding a provider means
# running init once more and committing the updated lock file.
#
# The random provider generates the cache's AUTH token (cache.tf).

terraform {
  required_version = "~> 1.17"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
  }
}
