# A VPC flow log of rejected traffic: one line per connection attempt that a security group
# refused, with the source, the destination port and nothing of the content.
#
# Rejected traffic only. Accepted traffic is already visible in the load balancer's metrics
# and the application log, and logging all of it would multiply the volume for nothing.
# Rejects show what the security groups are stopping: within minutes of the load balancer
# existing, scanners on the internet probe it on ports other than 80. That is the live
# answer to "how would you know if something were probing you?"
#
# In this stack, so it is destroyed daily with everything else. The VPC belongs to
# infra/base; the flow log only refers to it, and checkov's VPC flow-log check there is
# skipped for that reason. First records take ten to fifteen minutes to appear.

data "aws_caller_identity" "current" {}

resource "aws_cloudwatch_log_group" "flow" {
  #checkov:skip=CKV_AWS_158:Encrypted at rest by CloudWatch by default; a customer-managed key adds a key policy and a monthly fee
  #checkov:skip=CKV_AWS_338:Three days is a cost decision; rejects only matter while the stack is up, and it is destroyed daily
  name = "/${var.project}/vpc-flow-rejects"

  # Shorter than the other groups: the rejects are only interesting while the stack is up.
  retention_in_days = 3
}

resource "aws_flow_log" "rejects" {
  vpc_id               = local.base.vpc_id
  traffic_type         = "REJECT"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn

  # Seconds. The other choice is ten minutes, too slow to watch during a demo.
  max_aggregation_interval = 60

  # The role's permissions must exist before the service first tries to deliver. Without
  # them that first delivery fails and the group stays empty.
  depends_on = [aws_iam_role_policy.flow_logs]
}

# ------------------------------------------------------------------------- Delivery role
#
# The flow-log service assumes this role to write into the group. Least privilege: one log
# group, the three actions delivery needs, and the one listing action that cannot be scoped.

# The condition on the account stops another account from getting the flow-log service to
# use this role on its behalf: the "confused deputy" problem.
data "aws_iam_policy_document" "flow_logs_assume_role" {
  statement {
    sid     = "FlowLogServiceOfThisAccount"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.project}-flow-logs"
  description        = "VPC flow log delivery into the ${aws_cloudwatch_log_group.flow.name} log group only."
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume_role.json
}

data "aws_iam_policy_document" "flow_logs" {
  # Both ARNs: the first is the group, the second its streams. With only one of them,
  # delivery fails silently and the group stays empty.
  statement {
    sid    = "DeliverToTheRejectsGroup"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = [
      aws_cloudwatch_log_group.flow.arn,
      "${aws_cloudwatch_log_group.flow.arn}:*",
    ]
  }

  # A read-only listing that IAM cannot scope to one group, hence "*" on its own statement.
  statement {
    sid       = "ListLogGroups"
    effect    = "Allow"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }

  # No logs:CreateLogGroup, although AWS's sample policy has it: without it the service can
  # never recreate the group after `terraform destroy` removes it, outside Terraform.
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "deliver-flow-logs"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs.json
}

# ------------------------------------------------------------------------- Saved query
#
# The busiest sources and the ports they tried. A saved query has no time range of its
# own; Logs Insights opens it on the last hour, which is the window this is meant for. The
# field names are the ones Logs Insights discovers by itself in the default flow log format.

resource "aws_cloudwatch_query_definition" "rejected_traffic" {
  name            = "${var.project}/rejected-traffic"
  log_group_names = [aws_cloudwatch_log_group.flow.name]

  query_string = <<-EOT
    filter action = "REJECT"
    | stats count(*) as attempts by srcAddr, dstPort
    | sort attempts desc
    | limit 25
  EOT
}
