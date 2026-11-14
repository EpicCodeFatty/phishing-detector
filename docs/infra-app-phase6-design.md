# Phase 6: monitoring

The assignment asks for a service that is "highly available and observable", and names five things an
operator must be able to see:

1. Whether the EC2 instances are healthy.
2. How much CPU or system resources they are consuming.
3. How many requests are reaching the load balancer.
4. Whether requests are succeeding or failing.
5. Where application logs can be viewed.

This phase answers all five from **one CloudWatch dashboard**, sends **email alerts through SNS** when
something breaks, and ships the application log to **CloudWatch Logs**, where it can be searched with
Logs Insights. Everything is managed AWS features; nothing is self-hosted.

Read `docs/code-standards.md`, `docs/infra-app-design.md` and `docs/infra-app-phase5-design.md` first.
Everything there still applies.

**Do not run `terraform init`, `plan` or `apply`.** Write the code, run `terraform fmt` and the test
suite, and stop.

---

## 1. Where each answer comes from

| Question | Source | Needs code? |
|---|---|---|
| Instances healthy? | Target group `HealthyHostCount` / `UnHealthyHostCount`; ASG group metrics | no — AWS publishes them |
| CPU and resources? | EC2 `CPUUtilization`, `CPUCreditBalance`; memory and disk from the CloudWatch agent | agent only |
| Requests reaching the ALB? | ALB `RequestCount` | no |
| Succeeding or failing? | ALB `HTTPCode_Target_2XX/4XX/5XX_Count`, `HTTPCode_ELB_5XX_Count`, `TargetResponseTime` | no |
| Where are the logs? | `app.log` shipped by the agent to a log group; Logs Insights | agent + log group |

Three of the five answers cost nothing and need no code: the load balancer reports them on its own.
What the instance alone knows (memory, disk, the log file) needs the CloudWatch agent. EC2 does not
report memory at all from outside the instance; this surprises people, and it is why the agent exists.

---

## 2. Layout

```
infra/app/
├── logs.tf           NEW: two log groups, saved Logs Insights queries
├── monitoring.tf     NEW: dashboard, five alarms
├── agent.tf          NEW: the agent configuration, built with jsonencode
├── compute.tf        ASG group metrics; agent config passed to user_data
└── outputs.tf        + dashboard_url, log group names
deploy/
└── user_data.sh.tftpl    + install, configure and start the agent
scripts/
└── load.py           NEW: traffic generator for the demo
```

The SNS topic and its confirmed email subscription already exist in `base`
(`local.base.sns_topic_arn`). Nothing here creates or changes them.

---

## 3. Log groups (`logs.tf`)

```hcl
resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.project}/app"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "boot" {
  name              = "/${var.project}/boot"
  retention_in_days = 7
}
```

- **Terraform creates the log groups, not the agent.** The agent's IAM policy allows it to create a
  group that does not exist. If it did, the group would exist outside Terraform, `destroy` would not
  remove it, and it would be kept forever by default. Creating it here, and passing its *name
  attribute* into the agent configuration, guarantees it exists first and is deleted with the stack.
- **The reference is the ordering.** The launch template's `user_data` contains
  `aws_cloudwatch_log_group.app.name`, so Terraform creates the group before the template, and on
  destroy removes the Auto Scaling Group (and its instances) before the group. No `depends_on` needed,
  as long as the name comes from the resource and not from a string literal.
- **Retention 7 days.** Without it, CloudWatch keeps logs forever and bills for storage forever.
- **The boot log is shipped too.** `/var/log/cloud-init-output.log` goes to its own group, one stream
  per instance. A boot that fails can then be read from the console without connecting to an instance
  that the Auto Scaling Group is about to replace. This is the single most useful thing in this phase
  for debugging.
- **No KMS key.** CloudWatch Logs encrypts at rest by default. A customer-managed key adds a key
  policy and cost; record it as an accepted scanner finding for phase 7.

### Saved queries

```hcl
resource "aws_cloudwatch_query_definition" "errors" {
  name            = "${var.project}/errors"
  log_group_names = [aws_cloudwatch_log_group.app.name]
  query_string    = <<-EOT
    fields @timestamp, host, event, path, status, error_type, error_message
    | filter level = "ERROR"
    | sort @timestamp desc
    | limit 50
  EOT
}
```

Three more, same pattern:

| Name | Shows |
|---|---|
| `verdicts` | count of scans by `verdict`, from `event = "scan"` lines |
| `requests-by-instance` | request count and average `duration_ms` by `host` — shows the load balancer spreading traffic |
| `slowest-requests` | the 20 requests with the highest `duration_ms` |

Saved queries appear in CloudWatch → Logs Insights → Saved queries. In the demo, "where can logs be
viewed" is answered by opening one and pressing Run. Check the field names against
`logging_setup.py`: those are the source of truth.

---

## 4. The CloudWatch agent

### Configuration (`agent.tf`)

Built in Terraform with `jsonencode`, not a hand-written JSON file, so the log group names come from
the resources and the JSON is always valid.

```hcl
locals {
  cw_agent_config = jsonencode({
    agent = {
      metrics_collection_interval = 60
      run_as_user                 = "cwagent"
    }
    metrics = {
      namespace = "CWAgent"
      append_dimensions = {
        AutoScalingGroupName = "$${aws:AutoScalingGroupName}"
        InstanceId           = "$${aws:InstanceId}"
      }
      aggregation_dimensions = [["AutoScalingGroupName"]]
      metrics_collected = {
        mem = {
          measurement = ["mem_used_percent"]
        }
        disk = {
          measurement = ["used_percent"]
          resources   = ["/"]
          drop_device = true
        }
      }
    }
    logs = {
      logs_collected = {
        files = {
          collect_list = [
            {
              file_path       = "/var/log/phishing-app/app.log"
              log_group_name  = aws_cloudwatch_log_group.app.name
              log_stream_name = "{instance_id}"
              timezone        = "UTC"
            },
            {
              file_path       = "/var/log/cloud-init-output.log"
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
```

- **`$${aws:InstanceId}` with two dollar signs.** These are placeholders the *agent* fills in on the
  instance. In a Terraform string, `${...}` is Terraform's own interpolation, and a single dollar sign
  makes `plan` fail with an unknown variable. The doubled sign produces a literal `${aws:InstanceId}`
  in the JSON.
- **`run_as_user = "cwagent"`.** The agent package creates this user. Running the agent as root would
  work, but it only needs to read two files and call two APIs. Both files must be readable by that
  user; `user_data` checks the boot log, and section 10 checks the application log.
- **Two metrics, not the default set.** The agent's wizard collects dozens of metrics, each billed as a
  custom metric. Memory and root-disk usage are the two that EC2 cannot report and that the questions
  need.
- **`append_dimensions` and `aggregation_dimensions`.** Every metric carries the instance ID (for the
  per-instance graph) and the group name. The aggregation additionally publishes each metric with the
  group name only. That is what the memory alarm uses: instance IDs change with every deploy, and an
  alarm tied to one instance ID would point at a terminated instance after the first refresh.
- **`drop_device = true`.** The device name (`nvme0n1p1`) differs between instance types and makes the
  dimension set unpredictable. The mount path is enough.

### Installation (`user_data.sh.tftpl`)

**The agent is installed and started early: straight after the first `dnf install`, before the release
is downloaded and before the application service exists.** Two reasons:

1. **Everything after that point is visible in CloudWatch.** The agent ships the boot log from its
   first line and keeps following it. A failed S3 download, a failed `pip install` or a failed
   self-test can then be read in the console, without racing the Auto Scaling Group to an instance it
   is about to replace.
2. **A broken agent stops the boot before the application starts.** If the agent were installed after
   `systemctl enable --now phishing-app`, a failed install would end the script while the application
   was already answering `/health`: the instance would pass the load balancer's check and serve
   traffic with no monitoring, and nothing would say so. Observability is a requirement of the
   assignment; an unmonitored instance must not go into service.

Add the package to the existing install line, so it is one transaction:

```bash
retry 12 dnf install -y python3.12 python3.12-pip amazon-cloudwatch-agent
```

Then, immediately after it:

```bash
# --- monitoring: started first, so the rest of this boot is visible in CloudWatch ---
CW_CONFIG=/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
cat > "$CW_CONFIG" <<'CWEOF'
${cw_agent_config}
CWEOF

# The agent runs as cwagent and must be able to read this boot log. The log
# holds no secrets (nothing in this script prints one), so world-readable is
# acceptable if it is not already.
if ! runuser -u cwagent -- test -r /var/log/cloud-init-output.log; then
  chmod o+r /var/log/cloud-init-output.log
fi

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -s -c "file:$CW_CONFIG"
```

Pass the new template variable from `compute.tf`:

```hcl
cw_agent_config = local.cw_agent_config
```

- **The heredoc is quoted (`<<'CWEOF'`).** Terraform has already replaced `${cw_agent_config}` with the
  JSON before the script reaches the instance. The quotes stop the *shell* from then trying to expand
  `${aws:InstanceId}` inside that JSON, which would fail under `set -u`. The JSON is a single line and
  never contains `CWEOF`.
- **`-s` starts the agent and enables it at boot.** `fetch-config` validates the JSON first; an invalid
  configuration fails here, and under `set -e` the boot stops.
- **The application log does not exist yet when the agent starts.** That is fine: the agent waits for
  a configured file to appear. systemd creates `/var/log/phishing-app` when the service first starts.
- **`runuser`, not `setfacl`.** `runuser` is part of the base system; `setfacl` may not be installed,
  and a missing command here would fail every boot.
- **The agent reaches CloudWatch over the NAT on 443.** No new security group rule.
  `CloudWatchAgentServerPolicy`, attached in phase 4, already grants `PutMetricData`, the log
  permissions and `ec2:DescribeTags` (which `${aws:AutoScalingGroupName}` needs).
- **`user_data` has a hard limit of 16 KB before encoding.** The script is already well commented and
  this phase adds the agent JSON. After rendering, report the size in bytes. If it is over 13 KB,
  shorten comments in the template rather than removing checks.

---

## 5. Auto Scaling Group metrics (`compute.tf`)

```hcl
resource "aws_autoscaling_group" "app" {
  # ... as in phase 5 ...
  enabled_metrics = [
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupPendingInstances",
    "GroupTerminatingInstances",
  ]
  metrics_granularity = "1Minute"
}
```

Group metrics are free. They show self-healing on a graph: in-service drops to 1, pending rises to 1,
in-service returns to 2. During an instance refresh the same graph shows the rollout.

---

## 6. Dashboard (`monitoring.tf`)

One `aws_cloudwatch_dashboard`, body built with `jsonencode`. Rows follow the five questions, top to
bottom, each row headed by a text widget naming the question it answers. Period 60 seconds throughout.

| Row | Widgets |
|---|---|
| **1. Are the instances healthy?** | target group `HealthyHostCount` and `UnHealthyHostCount` (Maximum); ASG `GroupInServiceInstances`, `GroupPendingInstances`, `GroupDesiredCapacity` |
| **2. What are they consuming?** | `CPUUtilization` per instance; `CPUCreditBalance` per instance; memory per instance; root disk per instance |
| **3. How many requests reach the load balancer?** | ALB `RequestCount` (Sum); `RequestCountPerTarget` (Sum) |
| **4. Are requests succeeding?** | target `2XX`, `4XX`, `5XX` and ELB `5XX` counts (Sum, one graph, colour-coded); `TargetResponseTime` p50 and p95 |
| **5. Where are the logs?** | a log widget with the latest `ERROR` lines from the app log group; a log widget counting scans by `verdict` (`stats count() by verdict`); a text widget naming both log groups and the saved queries |
| **Alarms** | an alarm status widget listing all five alarms |

Implementation notes:

- **Dimensions.** ALB metrics use `LoadBalancer = aws_lb.main.arn_suffix`; target group metrics use
  both `TargetGroup = aws_lb_target_group.app.arn_suffix` and `LoadBalancer`. The `arn_suffix`
  attributes exist for exactly this; do not slice ARNs by hand.
- **Per-instance graphs use `SEARCH` expressions**, not fixed instance IDs, because the IDs change
  with every deploy and every self-heal:
  ```
  SEARCH('{AWS/EC2,InstanceId} MetricName="CPUUtilization"', 'Average', 300)
  ```
  `SEARCH` with a schema in braces only matches metrics with *exactly* those dimensions. With the
  agent configuration above the expected schemas are:
  ```
  {CWAgent,AutoScalingGroupName,InstanceId} MetricName="mem_used_percent"
  {CWAgent,AutoScalingGroupName,InstanceId,fstype,path} MetricName="disk_used_percent"
  ```
  The agent prefixes disk measurements, so `used_percent` is published as `disk_used_percent`. If a
  widget is empty after the first apply, compare against CloudWatch → Metrics → CWAgent.
  This SEARCH matches every instance in the account, not only this group's. That is acceptable
  because nothing else runs here; say so in a comment.
- **EC2 metrics arrive every 5 minutes** (basic monitoring, free). Use period 300 for the EC2 widgets
  only. Detailed monitoring would give 1-minute data at about $2 per instance per month; not needed.
- **`CPUCreditBalance` is on the dashboard on purpose.** The launch template sets
  `cpu_credits = "standard"`, so an instance that exhausts its credits is throttled to its baseline
  (20% of a vCPU for `t3.micro`) rather than billed. A falling credit balance explains slowness that
  `CPUUtilization` alone does not.
- **Host counts use Maximum or Minimum, never Sum.** Each load balancer node reports the count
  separately, so Sum doubles it.
- **Response codes that never occurred are not reported.** A `5XX` count with no errors has no data
  points, not zeros, so its line is simply absent. That is normal; do not "fix" it.
- **Title and placement.** Dashboard name `${var.project}`. Keep the first row visible without
  scrolling at 1280 pixels wide: it is what the reviewer sees first.

---

## 7. Alarms (`monitoring.tf`)

Five alarms. Each sends to the existing topic on **both** `alarm_actions` and `ok_actions`, so the
email says when a problem starts and when it is over.

| Alarm | Metric | Condition | Why this threshold |
|---|---|---|---|
| `unhealthy-targets` | TG `UnHealthyHostCount`, Maximum | > 0 for 2 of 2 one-minute periods | a target failing its health check for two minutes is not a blip |
| `target-5xx` | `HTTPCode_Target_5XX_Count`, Sum | ≥ 5 in one minute | the application is throwing errors |
| `elb-5xx` | `HTTPCode_ELB_5XX_Count`, Sum | ≥ 5 in one minute | the load balancer itself is failing: usually no healthy target to send to (503), or a target that drops connections (502) |
| `cpu-high` | EC2 `CPUUtilization` by `AutoScalingGroupName`, Average | > 80% for 2 of 2 five-minute periods | sustained load, not a spike |
| `memory-high` | `CWAgent` `mem_used_percent` by `AutoScalingGroupName` only, Maximum | > 85% for 3 of 3 one-minute periods | the worst instance is close to running out; gunicorn workers would start being killed |

Rules for all five:

- **`treat_missing_data = "notBreaching"`.** No 5XX data means no 5XX errors. For the CPU and memory
  alarms, missing data happens during a refresh, and is not a problem to page about either.
- **`alarm_description` says what to do**, in one sentence pointing at the runbook: for example,
  "Targets failing health checks. Check the boot log group, then the target group's health reasons."
  This is what the email shows first.
- **`unhealthy-targets` is expected to fire during every deploy and every fresh apply, then clear.** A
  new instance is registered with the target group as soon as it launches, and fails health checks
  for the two to three minutes its boot takes. So each replacement produces one ALARM email and one OK
  email. That is the alarm telling the truth: capacity really is reduced for those minutes. It is
  kept this sensitive so that a real failure is reported within two minutes. Record it in the README
  with the production answer: an Auto Scaling lifecycle hook that registers an instance only once
  its boot has finished, or alarm suppression during deployments. Confirm the behaviour on this
  phase's own instance refresh and note what was seen in BUILD_LOG.
- **Absolute counts, not error rates.** With demo-level traffic, a percentage swings from 0 to 100 on a
  single request. At production volumes this would be an error-rate alarm using metric math
  (5XX ÷ RequestCount, with a minimum request count). Record this in the README as a known trade-off.
- **The CPU alarm uses the group dimension**, which EC2 publishes for instances in an Auto Scaling
  Group. Like the memory alarm, it survives instance replacement.
- **Names** are `${var.project}-<alarm>`. They are deleted with the stack; the topic in `base` remains,
  and so does the confirmed subscription.

---

## 8. Outputs

Add `dashboard_url`:

```hcl
output "dashboard_url" {
  value = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards/dashboard/${aws_cloudwatch_dashboard.main.dashboard_name}"
}
```

and `app_log_group`, `boot_log_group`.

---

## 9. Traffic generator (`scripts/load.py`)

Graphs are empty without traffic, and the 5XX alarms cannot be shown without errors. A small script,
standard library plus `requests` (add it to `requirements-dev.txt` if it is not there; it is not an
application dependency).

```
python scripts/load.py --url <alb_url> --insecure --seconds 120 --concurrency 4
python scripts/load.py --url <alb_url> --insecure --errors 10
```

- Default mode: for the given duration, posts the files in `samples/` in rotation to `/api/scan` from a
  small thread pool, and prints a summary at the end: requests sent, count per status code, count per
  `served_by`, and p50/p95 latency.
- `--errors N`: sends N requests to `/simulate-error` and prints their status codes.
- A timeout on every request (10 seconds). Errors are counted, never raised.
- No retries: the point is to see failures, not hide them.
- Keep it under about 120 lines, with a module docstring that says what it is for.

`--concurrency 4` is deliberate: enough to fill the graphs, far from enough to stress two `t3.micro`
instances or spend credits. This is a demonstration tool, not a load test.

---

## 10. Applying and testing

### Plan

```powershell
cd infra\app
terraform plan
```

Expect roughly: 2 log groups, 4 saved queries, 1 dashboard, 5 alarms to add; the launch template and
the group to change in place (new `user_data`, group metrics). That change starts an instance refresh,
like any `user_data` change.

This is a `user_data` change, so the instance refresh is also the first real test of the agent. If the
first replacement cannot boot, the refresh stops there and the old instance keeps serving; read the
`/phishing-detector/boot` log group, then cancel the refresh and fix (phase 5, section 9). Expect the
`unhealthy-targets` emails described in section 7.

Check in the plan: `retention_in_days = 7` on both log groups; every alarm's `alarm_actions` and
`ok_actions` is the topic ARN from `base`; the dashboard body contains no literal instance ID. Review
it with me before applying.

### After the refresh completes

1. **Agent running.** On one instance (Session Manager):
   ```bash
   sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a status
   ```
   `"status": "running"`. If not, the agent's own log is
   `/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log`. Also run
   `ls -l /var/log/phishing-app/`: `app.log` must be readable by others (`-rw-r--r--`). If it is
   not, the agent cannot ship it; fix it in the unit or the app's log setup, not by hand.

2. **Logs arriving.** CloudWatch → Log groups → `/phishing-detector/app`: one stream per instance,
   JSON lines inside. Same for `/phishing-detector/boot`, ending in `user_data finished OK`.

   The logs are deleted with the stack every time it is destroyed. Take the screenshots in the same
   session as the tests.

3. **Metrics arriving.** CloudWatch → Metrics → CWAgent. Allow up to five minutes for the first data
   points.

4. **Traffic.**
   ```powershell
   python scripts\load.py --url (terraform output -raw alb_url) --insecure --seconds 180
   ```
   Open the dashboard (`terraform output -raw dashboard_url`). Requests, 2XX and response time fill
   in within two or three minutes.

5. **The 5XX alarm.**
   ```powershell
   python scripts\load.py --url (terraform output -raw alb_url) --insecure --errors 10
   ```
   Within about two minutes `target-5xx` goes to ALARM and an email arrives. A few minutes later it
   returns to OK, and a second email says so.

6. **The health alarm and self-healing.** On one instance:
   ```bash
   sudo systemctl stop phishing-app
   ```
   The target goes unhealthy within 20 seconds; `unhealthy-targets` fires after two minutes; the Auto
   Scaling Group terminates the instance and launches a replacement; the group-metrics graph shows it;
   the alarm returns to OK when the new instance is healthy. The other instance serves throughout.
   This is the high-availability demonstration and should be rehearsed now, while there is time.

   Stopping the service is used rather than terminating the instance, because a terminated instance is
   simply deregistered: it never becomes "unhealthy", so the alarm would not fire, although the group
   would still replace it.

7. **Logs Insights.** Run each saved query.

### Screenshots for `docs/screenshots/`

The dashboard with data in every row; an alarm in ALARM state; the alarm email; the self-healing
visible on the group-metrics graph; a Logs Insights result.

### Done when

All five questions are answered on the dashboard, an alarm email has arrived for a real event, and
the self-healing drill has been run once.

---

## 11. When it does not work

| Symptom | Likely cause |
|---|---|
| nothing in the boot log group, instance never healthy | the boot died before or at the agent's start: `dnf install`, or `fetch-config` rejecting the JSON (often an unescaped `${...}`). This is the one case that still needs debug mode and Session Manager |
| boot log group shows the failure | read it there; that is what it is for |
| agent running, no log streams | `cwagent` cannot read the file: check `ls -l /var/log/phishing-app/ /var/log/cloud-init-output.log` |
| agent running, no `CWAgent` metrics | `ec2:DescribeTags` denied (agent log says so), or simply less than five minutes |
| a dashboard widget is empty | wrong dimension set in a `SEARCH` schema, wrong `arn_suffix`, or no traffic yet. Check the metric in CloudWatch → Metrics first |
| alarm in `INSUFFICIENT_DATA` | normal for the first minutes of a new alarm. With `notBreaching` it then settles on OK, including the 5XX alarms that have no data at all |
| alarm fires, no email | subscription not `Confirmed` (SNS → Topics → the topic → Subscriptions); check spam |
| a log group still exists after `destroy` | it was created by the agent, not Terraform: its name does not match the resource. Delete it by hand and fix the name |

---

## 12. Cost

| | approximate |
|---|---|
| Custom metrics (memory and disk: per instance and aggregated) | a few cents a day |
| Five alarms | under one cent a day |
| Dashboard | free (the first three per account) |
| Log ingestion and storage at this volume | negligible |
| Logs Insights queries | $0.005 per GB scanned: negligible |

Each instance replacement creates new per-instance metric series. They are billed only for the hours
they report, so this stays in cents.

### Teardown check, added to the existing one

```powershell
aws logs describe-log-groups --profile phishing --log-group-name-prefix /phishing-detector --query "logGroups[].logGroupName"
aws cloudwatch describe-alarms --profile phishing --alarm-name-prefix phishing-detector --query "MetricAlarms[].AlarmName"
```

Both should return empty lists after `terraform destroy`.
