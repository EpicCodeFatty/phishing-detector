# What an operator looks at: one dashboard whose rows follow the five questions the service
# must answer, and five alarms that email through the SNS topic created in infra/base.
#
# 1. Are the instances healthy?        target group and Auto Scaling Group metrics
# 2. What are they consuming?          EC2 metrics, and memory and disk from the agent
# 3. How many requests arrive?         load balancer metrics
# 4. Are requests succeeding?          load balancer metrics
# 5. Where are the logs?               the log groups and saved queries in logs.tf
#
# A sixth row shows the result cache, which infra/base creates.
#
# The first, third and fourth cost nothing and need no code: AWS publishes them.

locals {
  # Both directions go to the topic, so an email says when a problem starts and when it is
  # over. The topic and its confirmed subscription live in infra/base and outlive this stack.
  alarm_topics = [local.base.sns_topic_arn]

  # The dimension values CloudWatch knows these resources by. The arn_suffix attributes
  # exist for exactly this; ARNs are not sliced by hand.
  alb_dimension          = aws_lb.main.arn_suffix
  target_group_dimension = aws_lb_target_group.app.arn_suffix
  asg_dimension          = aws_autoscaling_group.app.name

  # One-minute periods throughout, except for EC2's own metrics: with basic monitoring,
  # which is free, they arrive every five minutes. Detailed monitoring would give one-minute
  # data for about $2 per instance per month; not needed here.
  period_seconds     = 60
  ec2_period_seconds = 300

  colour_success      = "#2ca02c"
  colour_client_error = "#ff7f0e"
  colour_server_error = "#d62728"
  colour_edge_error   = "#9467bd"

  saved_query_names = [
    aws_cloudwatch_query_definition.errors.name,
    aws_cloudwatch_query_definition.verdicts.name,
    aws_cloudwatch_query_definition.requests_by_instance.name,
    aws_cloudwatch_query_definition.slowest_requests.name,
    aws_cloudwatch_query_definition.rejected_traffic.name,
    aws_cloudwatch_query_definition.cache_hit_ratio.name,
  ]

  # The result cache's metrics, by node. SEARCH with the cluster ID from infra/base's output,
  # never a hand-built string, and with the node in the schema: ElastiCache publishes these
  # host and engine metrics per node, and the one node's ID is AWS's to choose.
  cache_search = "{AWS/ElastiCache,CacheClusterId,CacheNodeId} CacheClusterId=\"${local.base.cache_cluster_id}\""

  # The dashboard is a grid 24 columns wide: x and width are in columns, y and height in
  # rows. Each question gets a one-row heading and a six-row band of widgets under it. The
  # first band ends at row 7, which keeps it on screen without scrolling.
  #
  # Per-instance graphs use SEARCH, never an instance ID: the IDs change with every deploy
  # and every self-heal. A schema in braces matches only metrics with exactly those
  # dimensions, so the agent's schemas below must agree with agent.tf; if a widget stays
  # empty, compare them against CloudWatch, Metrics, CWAgent. SEARCH matches every instance
  # in the account and region, not only this group's. That is acceptable because nothing
  # else runs here.
  dashboard_widgets = [
    # ---------------------------------------------------- 1. Are the instances healthy?
    {
      type       = "text"
      x          = 0
      y          = 0
      width      = 24
      height     = 1
      properties = { markdown = "## 1. Are the instances healthy?", background = "transparent" }
    },
    {
      type   = "metric"
      x      = 0
      y      = 1
      width  = 12
      height = 6

      # Maximum, never Sum: each load balancer node reports the count separately, so Sum
      # would double it.
      properties = {
        title   = "Targets behind the load balancer"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.period_seconds
        stat    = "Maximum"
        yAxis   = { left = { min = 0 } }

        metrics = [
          [
            "AWS/ApplicationELB", "HealthyHostCount",
            "TargetGroup", local.target_group_dimension, "LoadBalancer", local.alb_dimension,
            { label = "Healthy", color = local.colour_success },
          ],
          [
            "AWS/ApplicationELB", "UnHealthyHostCount",
            "TargetGroup", local.target_group_dimension, "LoadBalancer", local.alb_dimension,
            { label = "Unhealthy", color = local.colour_server_error },
          ],
        ]
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 1
      width  = 12
      height = 6

      # Self-healing and a rollout both show here: in service drops, pending rises, in
      # service returns.
      properties = {
        title   = "Auto Scaling Group instances"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.period_seconds
        stat    = "Average"
        yAxis   = { left = { min = 0 } }

        metrics = [
          ["AWS/AutoScaling", "GroupInServiceInstances", "AutoScalingGroupName", local.asg_dimension, { label = "In service" }],
          ["AWS/AutoScaling", "GroupPendingInstances", "AutoScalingGroupName", local.asg_dimension, { label = "Pending" }],
          ["AWS/AutoScaling", "GroupDesiredCapacity", "AutoScalingGroupName", local.asg_dimension, { label = "Desired" }],
        ]
      }
    },

    # ------------------------------------------------------ 2. What are they consuming?
    {
      type       = "text"
      x          = 0
      y          = 7
      width      = 24
      height     = 1
      properties = { markdown = "## 2. What are they consuming?", background = "transparent" }
    },
    {
      type   = "metric"
      x      = 0
      y      = 8
      width  = 6
      height = 6

      properties = {
        title   = "CPU per instance (%)"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.ec2_period_seconds
        yAxis   = { left = { min = 0, max = 100 } }

        metrics = [[{
          id         = "cpu"
          expression = "SEARCH('{AWS/EC2,InstanceId} MetricName=\"CPUUtilization\"', 'Average', ${local.ec2_period_seconds})"
        }]]
      }
    },
    {
      type   = "metric"
      x      = 6
      y      = 8
      width  = 6
      height = 6

      # On the dashboard on purpose. The launch template sets cpu_credits to "unlimited", so
      # an instance that runs out of credits is not throttled: it keeps bursting, and the
      # surplus above its 24-hour average baseline is billed. A balance that stays at zero
      # is what shows that surplus building up. It is also how the slow boots were found:
      # with "standard", a new instance started at zero and booted at its baseline.
      properties = {
        title   = "CPU credit balance per instance"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.ec2_period_seconds
        yAxis   = { left = { min = 0 } }

        metrics = [[{
          id         = "credits"
          expression = "SEARCH('{AWS/EC2,InstanceId} MetricName=\"CPUCreditBalance\"', 'Average', ${local.ec2_period_seconds})"
        }]]
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 8
      width  = 6
      height = 6

      properties = {
        title   = "Memory used per instance (%)"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.period_seconds
        yAxis   = { left = { min = 0, max = 100 } }

        metrics = [[{
          id         = "memory"
          expression = "SEARCH('{CWAgent,AutoScalingGroupName,InstanceId} MetricName=\"mem_used_percent\"', 'Average', ${local.period_seconds})"
        }]]
      }
    },
    {
      type   = "metric"
      x      = 18
      y      = 8
      width  = 6
      height = 6

      # The agent prefixes disk measurements: used_percent is published as
      # disk_used_percent, with the filesystem type and mount path as dimensions.
      properties = {
        title   = "Root disk used per instance (%)"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.period_seconds
        yAxis   = { left = { min = 0, max = 100 } }

        metrics = [[{
          id         = "disk"
          expression = "SEARCH('{CWAgent,AutoScalingGroupName,InstanceId,fstype,path} MetricName=\"disk_used_percent\"', 'Average', ${local.period_seconds})"
        }]]
      }
    },

    # ------------------------------------- 3. How many requests reach the load balancer?
    {
      type       = "text"
      x          = 0
      y          = 14
      width      = 24
      height     = 1
      properties = { markdown = "## 3. How many requests reach the load balancer?", background = "transparent" }
    },
    {
      type   = "metric"
      x      = 0
      y      = 15
      width  = 12
      height = 6

      properties = {
        title   = "Requests per minute"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.period_seconds
        stat    = "Sum"
        yAxis   = { left = { min = 0 } }

        metrics = [
          ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", local.alb_dimension, { label = "Requests" }],
        ]
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 15
      width  = 12
      height = 6

      properties = {
        title   = "Requests per target per minute"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.period_seconds
        stat    = "Sum"
        yAxis   = { left = { min = 0 } }

        metrics = [
          [
            "AWS/ApplicationELB", "RequestCountPerTarget",
            "TargetGroup", local.target_group_dimension, "LoadBalancer", local.alb_dimension,
            { label = "Requests per target" },
          ],
        ]
      }
    },

    # ------------------------------------------------------ 4. Are requests succeeding?
    {
      type       = "text"
      x          = 0
      y          = 21
      width      = 24
      height     = 1
      properties = { markdown = "## 4. Are requests succeeding?", background = "transparent" }
    },
    {
      type   = "metric"
      x      = 0
      y      = 22
      width  = 12
      height = 6

      # A code that never occurred is not reported as zero: it has no data points, so its
      # line is simply absent. An empty 5XX line means no errors, not a broken widget.
      properties = {
        title   = "Responses by status, per minute"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.period_seconds
        stat    = "Sum"
        yAxis   = { left = { min = 0 } }

        metrics = [
          ["AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", "LoadBalancer", local.alb_dimension, { label = "2XX from the application", color = local.colour_success }],
          ["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", local.alb_dimension, { label = "4XX from the application", color = local.colour_client_error }],
          ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", local.alb_dimension, { label = "5XX from the application", color = local.colour_server_error }],
          ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", local.alb_dimension, { label = "5XX from the load balancer", color = local.colour_edge_error }],
        ]
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 22
      width  = 12
      height = 6

      properties = {
        title   = "Response time of the application (seconds)"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.period_seconds
        yAxis   = { left = { min = 0 } }

        metrics = [
          ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", local.alb_dimension, { label = "p50", stat = "p50" }],
          ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", local.alb_dimension, { label = "p95", stat = "p95" }],
        ]
      }
    },

    # ---------------------------------------------------------- 5. Where are the logs?
    {
      type       = "text"
      x          = 0
      y          = 28
      width      = 24
      height     = 1
      properties = { markdown = "## 5. Where are the logs?", background = "transparent" }
    },
    {
      type   = "log"
      x      = 0
      y      = 29
      width  = 12
      height = 6

      properties = {
        title  = "Latest errors in the application log"
        region = var.region
        view   = "table"
        query  = "SOURCE '${aws_cloudwatch_log_group.app.name}' | ${trimspace(local.errors_query)}"
      }
    },
    {
      type   = "log"
      x      = 12
      y      = 29
      width  = 6
      height = 6

      properties = {
        title  = "Scans by verdict"
        region = var.region
        view   = "bar"
        query  = "SOURCE '${aws_cloudwatch_log_group.app.name}' | ${trimspace(local.verdicts_query)}"
      }
    },
    {
      type   = "text"
      x      = 18
      y      = 29
      width  = 6
      height = 6

      properties = {
        markdown = join("\n", concat(
          [
            "**Application log:** `${aws_cloudwatch_log_group.app.name}`. One stream per instance, one JSON object per line.",
            "",
            "**Boot log:** `${aws_cloudwatch_log_group.boot.name}`. Each instance's boot script output: read it first when an instance never becomes healthy.",
            "",
            "**Saved queries**, under Logs Insights, Saved queries:",
            "",
          ],
          [for name in local.saved_query_names : "- `${name}`"],
        ))
      }
    },

    # --------------------------------------------------------------------------- Cache
    #
    # No alarm goes with this row: the cache is optional, and when it fails scans carry on
    # without it. That is not an incident in this design.
    {
      type       = "text"
      x          = 0
      y          = 35
      width      = 24
      height     = 1
      properties = { markdown = "## Cache", background = "transparent" }
    },
    {
      type   = "metric"
      x      = 0
      y      = 36
      width  = 6
      height = 6

      # The engine counts key reads, not scans. Each scan reads its result key once, so hits
      # follow the scans served from the cache and misses the scans the engine analysed,
      # give or take the sighting counter's own bookkeeping.
      properties = {
        title   = "Cache hits and misses per minute"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.period_seconds
        yAxis   = { left = { min = 0 } }

        metrics = [
          [{ id = "hits", label = "Hits", color = local.colour_success, expression = "SEARCH('${local.cache_search} MetricName=\"CacheHits\"', 'Sum', ${local.period_seconds})" }],
          [{ id = "misses", label = "Misses", color = local.colour_client_error, expression = "SEARCH('${local.cache_search} MetricName=\"CacheMisses\"', 'Sum', ${local.period_seconds})" }],
        ]
      }
    },
    {
      type   = "metric"
      x      = 6
      y      = 36
      width  = 6
      height = 6

      # One pooled connection per gunicorn worker that has used the cache: four at most with
      # two instances of two workers.
      properties = {
        title   = "Cache connections"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.period_seconds
        yAxis   = { left = { min = 0 } }

        metrics = [[{
          id         = "connections"
          expression = "SEARCH('${local.cache_search} MetricName=\"CurrConnections\"', 'Maximum', ${local.period_seconds})"
        }]]
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 36
      width  = 6
      height = 6

      properties = {
        title   = "Cache memory used (%)"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.period_seconds
        yAxis   = { left = { min = 0, max = 100 } }

        metrics = [[{
          id         = "memory"
          expression = "SEARCH('${local.cache_search} MetricName=\"DatabaseMemoryUsagePercentage\"', 'Maximum', ${local.period_seconds})"
        }]]
      }
    },
    {
      type   = "metric"
      x      = 18
      y      = 36
      width  = 6
      height = 6

      # The engine's own thread, not the node's whole CPU: Valkey runs its commands on one
      # core, so this is the figure that shows it is busy.
      properties = {
        title   = "Cache engine CPU (%)"
        region  = var.region
        view    = "timeSeries"
        stacked = false
        period  = local.period_seconds
        yAxis   = { left = { min = 0, max = 100 } }

        metrics = [[{
          id         = "engine_cpu"
          expression = "SEARCH('${local.cache_search} MetricName=\"EngineCPUUtilization\"', 'Average', ${local.period_seconds})"
        }]]
      }
    },

    # -------------------------------------------------------------------------- Alarms
    {
      type       = "text"
      x          = 0
      y          = 42
      width      = 24
      height     = 1
      properties = { markdown = "## Alarms", background = "transparent" }
    },
    {
      type   = "alarm"
      x      = 0
      y      = 43
      width  = 24
      height = 3

      properties = {
        title = "Alarm status"

        alarms = [
          aws_cloudwatch_metric_alarm.unhealthy_targets.arn,
          aws_cloudwatch_metric_alarm.target_5xx.arn,
          aws_cloudwatch_metric_alarm.elb_5xx.arn,
          aws_cloudwatch_metric_alarm.cpu_high.arn,
          aws_cloudwatch_metric_alarm.memory_high.arn,
        ]
      }
    },
  ]
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = var.project
  dashboard_body = jsonencode({ widgets = local.dashboard_widgets })
}

# ------------------------------------------------------------------------------- Alarms
#
# Rules all five share:
#
# - Missing data is treated as not breaching. No 5XX data points means no 5XX errors, and
#   the CPU and memory metrics pause during a refresh, which is nothing to email about.
# - The description says what to do. It is the first thing the email shows.
# - Absolute counts, not error rates. With demo-level traffic a percentage swings from 0 to
#   100 on a single request. At production volume these would be rates, with metric math
#   and a minimum request count.
# - CPU and memory are watched by Auto Scaling Group name, not instance ID, so the alarms
#   survive every instance replacement.

# Expected to fire during every deploy and every fresh apply, then clear. A new instance is
# registered with the target group as soon as it launches and fails the health check for
# the minutes its boot takes: capacity really is reduced, and the alarm says so. It is kept
# this sensitive so that a real failure is reported within two minutes.
resource "aws_cloudwatch_metric_alarm" "unhealthy_targets" {
  alarm_name        = "${var.project}-unhealthy-targets"
  alarm_description = "A target is failing its health check. Expected for a few minutes during a deploy. Otherwise read the ${aws_cloudwatch_log_group.boot.name} log group, then the target group's health reasons."

  namespace   = "AWS/ApplicationELB"
  metric_name = "UnHealthyHostCount"

  dimensions = {
    TargetGroup  = local.target_group_dimension
    LoadBalancer = local.alb_dimension
  }

  # Two minutes of failed health checks is not a blip.
  statistic           = "Maximum"
  period              = local.period_seconds
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions = local.alarm_topics
  ok_actions    = local.alarm_topics
}

resource "aws_cloudwatch_metric_alarm" "target_5xx" {
  alarm_name        = "${var.project}-target-5xx"
  alarm_description = "The application is answering with errors. Run the saved query ${aws_cloudwatch_query_definition.errors.name} in Logs Insights to see which requests and why."

  namespace   = "AWS/ApplicationELB"
  metric_name = "HTTPCode_Target_5XX_Count"

  dimensions = {
    LoadBalancer = local.alb_dimension
  }

  statistic           = "Sum"
  period              = local.period_seconds
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  alarm_actions = local.alarm_topics
  ok_actions    = local.alarm_topics
}

resource "aws_cloudwatch_metric_alarm" "elb_5xx" {
  alarm_name        = "${var.project}-elb-5xx"
  alarm_description = "The load balancer itself is failing requests: usually no healthy target to send to (503), or a target that drops connections (502). Check the target group's health, then the Auto Scaling Group's activity."

  namespace   = "AWS/ApplicationELB"
  metric_name = "HTTPCode_ELB_5XX_Count"

  dimensions = {
    LoadBalancer = local.alb_dimension
  }

  statistic           = "Sum"
  period              = local.period_seconds
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  alarm_actions = local.alarm_topics
  ok_actions    = local.alarm_topics
}

# The group dimension, which EC2 publishes for instances in an Auto Scaling Group. Two
# five-minute periods: sustained load, not a spike.
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name        = "${var.project}-cpu-high"
  alarm_description = "Average CPU across the instances has been above 80% for ten minutes. Check the request count on the dashboard for a surge, and the CPU credit balance: an instance out of credits is throttled."

  namespace   = "AWS/EC2"
  metric_name = "CPUUtilization"

  dimensions = {
    AutoScalingGroupName = local.asg_dimension
  }

  statistic           = "Average"
  period              = local.ec2_period_seconds
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  treat_missing_data  = "notBreaching"

  alarm_actions = local.alarm_topics
  ok_actions    = local.alarm_topics
}

# The agent's aggregated metric, carrying the group name only. Maximum, so it follows the
# worst instance: one that is close to running out, where gunicorn's workers would start
# being killed.
resource "aws_cloudwatch_metric_alarm" "memory_high" {
  alarm_name        = "${var.project}-memory-high"
  alarm_description = "An instance has used more than 85% of its memory for three minutes. Find it on the dashboard's memory graph; replacing it through an instance refresh frees the memory while the cause is looked for in the application log."

  namespace   = "CWAgent"
  metric_name = "mem_used_percent"

  dimensions = {
    AutoScalingGroupName = local.asg_dimension
  }

  statistic           = "Maximum"
  period              = local.period_seconds
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = 85
  treat_missing_data  = "notBreaching"

  alarm_actions = local.alarm_topics
  ok_actions    = local.alarm_topics
}
