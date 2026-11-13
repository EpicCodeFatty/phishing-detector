# The CloudWatch agent's configuration. The agent runs on every instance and supplies what
# only the instance knows: memory, disk usage and the two log files. user_data writes this
# JSON to disk and starts the agent with it.
#
# Built with jsonencode rather than kept as a JSON file, so that the log group names come
# from the resources in logs.tf and the JSON is always valid.

locals {
  # Where the application writes its log. Defined once: user_data gives it to the
  # application as LOG_FILE, and the agent reads the same path. The directory is the one
  # the systemd unit creates with LogsDirectory.
  app_log_file  = "/var/log/phishing-app/app.log"
  boot_log_file = "/var/log/cloud-init-output.log"

  cw_agent_config = jsonencode({
    agent = {
      metrics_collection_interval = 60

      # The package creates this user. Root would work, but the agent only reads two files
      # and calls two APIs. Both files must be readable by it: user_data checks the boot
      # log, and the application log is created world-readable.
      run_as_user = "cwagent"
    }

    metrics = {
      namespace = "CWAgent"

      # Placeholders the agent fills in on the instance. The dollar signs are doubled
      # because a single one is Terraform's own interpolation, and the plan would fail on
      # an unknown variable; doubled, the JSON carries the placeholder literally.
      append_dimensions = {
        AutoScalingGroupName = "$${aws:AutoScalingGroupName}"
        InstanceId           = "$${aws:InstanceId}"
      }

      # Each metric is published a second time with the group name alone. That is what the
      # memory alarm watches: instance IDs change with every deploy, and an alarm tied to
      # one would point at a terminated instance after the first refresh.
      aggregation_dimensions = [["AutoScalingGroupName"]]

      # Two metrics, not the agent's default set: each one is billed as a custom metric,
      # and memory and root-disk usage are the two that EC2 cannot report from outside.
      metrics_collected = {
        mem = {
          measurement = ["mem_used_percent"]
        }

        disk = {
          measurement = ["used_percent"]
          resources   = ["/"]

          # The device name (nvme0n1p1) differs between instance types and would make the
          # dimension set unpredictable. The mount path is enough.
          drop_device = true
        }
      }
    }

    logs = {
      logs_collected = {
        files = {
          # One stream per instance in each group. The application log does not exist when
          # the agent starts; the agent waits for a configured file to appear.
          collect_list = [
            {
              file_path       = local.app_log_file
              log_group_name  = aws_cloudwatch_log_group.app.name
              log_stream_name = "{instance_id}"
              timezone        = "UTC"
            },
            {
              file_path       = local.boot_log_file
              log_group_name  = aws_cloudwatch_log_group.boot.name
              log_stream_name = "{instance_id}"
              timezone        = "UTC"
            },
          ]
        }
      }
    }
  })
}
