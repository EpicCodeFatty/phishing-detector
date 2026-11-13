# Everything this stack knows about infra/base comes from the outputs in base's state file.
#
# Two consequences: this stack can only be planned on the machine that holds that file, and
# base must be applied before this stack and destroyed after it.

data "terraform_remote_state" "base" {
  backend = "local"

  config = {
    path = "${path.module}/../base/terraform.tfstate"
  }
}

locals {
  # Unpacked once, so the long expression appears in one place.
  base = data.terraform_remote_state.base.outputs
}
