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
    cpu_credits = "unlimited"
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
  #
  # Everything the instance is told is here, and none of it is a secret: the database
  # password is represented by its ARN only. A new release changes `release` and
  # `artifact_key`, so user_data changes, and that is what creates a new template version.
  user_data = base64encode(replace(
    templatefile("${path.module}/../../deploy/user_data.sh.tftpl", {
      release         = local.release
      region          = var.region
      artifact_bucket = aws_s3_bucket.artifacts.id

      # The object's attribute, not local.artifact_key. The value is the same; the reference
      # is what makes Terraform upload the zip before the template changes. With the local,
      # a new instance could boot and ask for a zip that is not there yet.
      artifact_key = aws_s3_object.release.key

      db_host       = local.base.db_endpoint
      db_port       = local.base.db_port
      db_name       = local.base.db_name
      db_user       = local.base.db_username
      db_secret_arn = local.base.db_secret_arn

      # The CloudWatch agent's configuration, as one line of JSON (agent.tf), and the log
      # file the application writes and the agent reads. The JSON names the log groups by
      # their resources' attributes, so the groups exist before this template does.
      cw_agent_config = local.cw_agent_config
      app_log_file    = local.app_log_file

      # Rendered as "true" or "false", the two values the application accepts.
      enable_error_simulation = var.enable_error_simulation
    }),
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

  # "ELB" is what makes self-healing real: an instance that stops answering /health is
  # terminated and replaced. The price is that a broken instance is replaced before anyone
  # can read its log, so for debugging apply once with -var health_check_type=EC2: the
  # instances then stay up however broken they are.
  #
  # The grace period is how long a new instance is protected from being replaced for
  # failing the load balancer's check. It must be longer than a real boot, or a slow
  # healthy boot is killed and restarted forever.
  health_check_type         = var.health_check_type
  health_check_grace_period = var.health_check_grace_seconds

  # In normal mode the apply returns only when every instance passes the load balancer's
  # health check, so "apply complete" means "serving". In debug mode it does not wait for
  # that. If the boot is broken, the apply fails with a capacity timeout and marks the group
  # as tainted, so the next apply destroys and recreates it: expected, not a second problem.
  wait_for_elb_capacity     = var.health_check_type == "ELB" ? var.asg_size : null
  wait_for_capacity_timeout = "12m"

  launch_template {
    id = aws_launch_template.app.id

    # The attribute, not the string "$Latest". Both launch the newest version, but only the
    # attribute changes in the plan when the template does.
    version = aws_launch_template.app.latest_version
  }

  # A new launch template version, which is what a new release produces, replaces the
  # instances one at a time: with two instances and 50 percent kept healthy, one serves
  # while the other is replaced. Terraform starts the refresh and does not wait for it;
  # applying again while one is running cancels it and starts a new one.
  #
  # The warm-up is how long the refresh waits after launching a replacement before moving
  # on. It must outlast the grace period (variables.tf enforces it): during the grace period
  # the group treats every instance as healthy, so a refresh that moved on inside it would
  # take a release that cannot boot for healthy, and replace the last working instance too.
  instance_refresh {
    strategy = "Rolling"

    preferences {
      min_healthy_percentage = 50
      instance_warmup        = var.instance_warmup_seconds
      skip_matching          = true
    }
  }

  # Group metrics are free. They are what shows self-healing and a rollout on the
  # dashboard: in service drops, pending rises, in service returns.
  enabled_metrics = [
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupPendingInstances",
    "GroupTerminatingInstances",
  ]
  metrics_granularity = "1Minute"

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
  # refers to the NAT routes, the security group rules or the role's policies, so without
  # this Terraform creates them in parallel, and the first boot runs `dnf install` before
  # there is a way out, or asks for a release it may not read yet, fails once, and is never
  # retried. The database rules are here so the application's first connection finds them.
  # aws_route.private_app_nat names the resource, so it covers the route of every zone.
  #
  # The HTTPS listener is here for a different reason. It is the only thing that attaches
  # the target group to the load balancer, and a target group attached to nothing never
  # reports a healthy target. If the certificate or the listener failed to create, the group
  # would wait out its capacity timeout and be tainted; with this, it is not created at all,
  # and the apply stops on the real error.
  depends_on = [
    aws_lb_listener.https,
    aws_route.private_app_nat,
    aws_vpc_security_group_egress_rule.app_https,
    aws_vpc_security_group_egress_rule.app_to_db,
    aws_vpc_security_group_ingress_rule.db_from_app,
    aws_iam_role_policy_attachment.ssm,
    aws_iam_role_policy_attachment.cloudwatch,
    aws_iam_role_policy.read_release,
    aws_iam_role_policy.read_db_secret,
  ]
}
