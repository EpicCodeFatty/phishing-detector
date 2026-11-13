# Where the logs go: one log group for the application's JSON lines, one for the boot log,
# and four saved Logs Insights queries.
#
# Terraform creates the groups, not the agent. The agent's managed policy would let it
# create a missing group, but that group would exist outside Terraform: `destroy` would not
# remove it, and it would be kept, and billed, forever. The agent configuration takes each
# name from the resource's attribute, never a literal, and that reference is the ordering:
# the group exists before the launch template that names it, and on destroy the instances
# are gone before the group is.
#
# No customer-managed KMS key: CloudWatch Logs encrypts at rest by default, and a key adds
# a key policy and a monthly cost. A scanner will flag it; it is an accepted finding.

locals {
  # Without a retention period CloudWatch keeps logs, and bills for them, forever.
  log_retention_days = 7

  # The two queries the dashboard also shows, kept here so the saved query and the
  # dashboard widget cannot drift apart. The field names are the ones the application
  # writes (app/logging_setup.py and the log_event calls in app/web.py).
  errors_query = <<-EOT
    fields @timestamp, host, event, path, status, error_type, error_message
    | filter level = "ERROR"
    | sort @timestamp desc
    | limit 50
  EOT

  # `event` is the name of the route: a scan from the browser logs "scan", and one through
  # the JSON API, which is what scripts/load.py sends, logs "api_scan".
  verdicts_query = <<-EOT
    filter event in ["scan", "api_scan"]
    | stats count(*) as scans by verdict
    | sort scans desc
  EOT
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.project}/app"
  retention_in_days = local.log_retention_days
}

# /var/log/cloud-init-output.log from every instance. A boot that fails can be read here,
# without connecting to an instance that the Auto Scaling Group is about to replace.
resource "aws_cloudwatch_log_group" "boot" {
  name              = "/${var.project}/boot"
  retention_in_days = local.log_retention_days
}

# ------------------------------------------------------------------------ Saved queries
#
# These appear in CloudWatch, Logs Insights, Saved queries, in a folder named after the
# project. "Where can the logs be viewed" is answered by opening one and pressing Run.

resource "aws_cloudwatch_query_definition" "errors" {
  name            = "${var.project}/errors"
  log_group_names = [aws_cloudwatch_log_group.app.name]
  query_string    = local.errors_query
}

resource "aws_cloudwatch_query_definition" "verdicts" {
  name            = "${var.project}/verdicts"
  log_group_names = [aws_cloudwatch_log_group.app.name]
  query_string    = local.verdicts_query
}

# Shows the load balancer spreading traffic. Its own health checks are left out: every
# instance receives the same number of them, a dozen a minute, which would bury the
# difference this query is there to show.
resource "aws_cloudwatch_query_definition" "requests_by_instance" {
  name            = "${var.project}/requests-by-instance"
  log_group_names = [aws_cloudwatch_log_group.app.name]

  query_string = <<-EOT
    filter ispresent(duration_ms) and event != "health"
    | stats count(*) as requests, avg(duration_ms) as average_ms by host
    | sort host asc
  EOT
}

resource "aws_cloudwatch_query_definition" "slowest_requests" {
  name            = "${var.project}/slowest-requests"
  log_group_names = [aws_cloudwatch_log_group.app.name]

  query_string = <<-EOT
    fields @timestamp, host, event, path, status, duration_ms
    | filter ispresent(duration_ms)
    | sort duration_ms desc
    | limit 20
  EOT
}
