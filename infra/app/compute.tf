# The instances: an Amazon Linux 2023 launch template, and an Auto Scaling Group that keeps
# a fixed number of them running, one per availability zone.

# ---------------------------------------------------------------------------------- AMI
#
# The image ID comes from AWS's public parameter, never a literal: IDs differ per region and
# change with every Amazon Linux release. This is the standard image, which ships with the
# SSM agent; the "minimal" one does not, and Session Manager would never connect.

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# Looked up for one attribute, root_device_name. Encrypting the root volume means naming its
# device, and a wrong name does not fail: it attaches a second, empty encrypted volume and
# leaves the real root unencrypted.
data "aws_ami" "al2023" {
  owners = ["amazon"]

  filter {
    name = "image-id"

    # insecure_value, not value: the provider marks `value` as sensitive, which would hide
    # the image ID in every plan for no reason.
    values = [data.aws_ssm_parameter.al2023.insecure_value]
  }
}

# ---------------------------------------------------------------------- Launch template

data "aws_default_tags" "current" {}

locals {
  # The provider's default tags plus a Name, for the two places default_tags does not reach:
  # what the launch template launches, and the Auto Scaling Group itself. Built from
  # aws_default_tags so the tags are still declared once, in providers.tf.
  app_tags = merge(data.aws_default_tags.current.tags, { Name = "${var.project}-app" })
}

resource "aws_launch_template" "app" {
  name          = "${var.project}-app"
  image_id      = data.aws_ami.al2023.id
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.app.arn
  }

  vpc_security_group_ids = [aws_security_group.app.id]

  # IMDSv2 only. Version 1 let any process able to make an HTTP request, including one
  # tricked into it through server-side request forgery, read the instance's credentials.
  # A hop limit of 1 stops a container on the instance from reaching the service.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = data.aws_ami.al2023.root_device_name

    # No volume_size: the image's own size is inherited, so a larger future image cannot
    # break the launch.
    ebs {
      encrypted             = true
      volume_type           = "gp3"
      delete_on_termination = true
    }
  }

  # The default for t3 is "unlimited", which silently bills for burst credits.
  credit_specification {
    cpu_credits = "standard"
  }

  # default_tags does not reach what an Auto Scaling Group launches: the provider tags the
  # launch template itself, not its instances. Without this block the instances and their
  # volumes would carry no Project tag, and the teardown check, which searches by tag, would
  # report a clean account while missing them.
  dynamic "tag_specifications" {
    for_each = toset(["instance", "volume", "network-interface"])

    content {
      resource_type = tag_specifications.value
      tags          = local.app_tags
    }
  }

  # Carriage returns are stripped because Terraform reads the working directory, where a file
  # freshly saved by a Windows editor has CRLF line endings whatever .gitattributes says. On
  # Linux such a script fails at its first line with "/bin/bash^M: bad interpreter".
  #
  # The script is a template: a shell variable written with braces must have its dollar sign
  # doubled there, or the apply fails with an unknown-variable error.
  user_data = base64encode(replace(
    templatefile("${path.module}/../../deploy/user_data.sh.tftpl", {}),
    "\r\n", "\n"
  ))

  update_default_version = true
}

# -------------------------------------------------------------------- Auto Scaling Group

resource "aws_autoscaling_group" "app" {
  name = "${var.project}-app"

  # All three equal: the group replaces failed instances, it does not scale.
  min_size         = var.asg_size
  max_size         = var.asg_size
  desired_capacity = var.asg_size

  vpc_zone_identifier = local.base.private_app_subnet_ids
  target_group_arns   = [aws_lb_target_group.app.arn]

  # "EC2" while building: an instance whose boot script failed stays up to be inspected.
  # With "ELB" it is replaced a few minutes later, before anyone can read its log.
  health_check_type         = var.health_check_type
  health_check_grace_period = 300

  launch_template {
    id = aws_launch_template.app.id

    # The attribute, not the string "$Latest". Both launch the newest version, but only the
    # attribute changes in the plan when the template does.
    version = aws_launch_template.app.latest_version
  }

  # The group is the one resource the provider never applies default_tags to, so it is
  # tagged here. propagate_at_launch is false because these tag the group only: the launch
  # template stays the one place instance tags come from.
  dynamic "tag" {
    for_each = local.app_tags

    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = false
    }
  }

  # Instances start running user_data within seconds of launch. Nothing in this resource
  # refers to the NAT route, the egress rule or the role's policies, so without this
  # Terraform creates them in parallel, and the first boot runs `dnf install` before there
  # is a way out, fails once, and is never retried.
  depends_on = [
    aws_route.private_app_nat,
    aws_vpc_security_group_egress_rule.app_https,
    aws_iam_role_policy_attachment.ssm,
    aws_iam_role_policy_attachment.cloudwatch,
  ]
}
