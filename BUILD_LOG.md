# Build log

Running notes while building the project. Every problem gets an entry, however small.
This file is the raw material for the troubleshooting runbook in the README.

Format: what happened, why, how it was resolved.

---

## 2026-11-12 — Environment setup

**Account.** AWS account created through the new project-based sign-up. Free plan, $100 in credits.
Signup required a card for identity verification; the account was not upgraded to a paid plan.

**Region is fixed.** The new sign-up assigns the project a single region based on the contact address,
so this account is `eu-north-1` (Stockholm) and there is no region selector in the console. Choosing a
different region would require activating advanced features, which was deliberately not done. All
provider blocks, the CLI profile and the console therefore use `eu-north-1`.

**Local tooling.** Python 3.12, Git 2.56, Terraform 1.17.1, AWS CLI 2.40.0, Docker 29.9.3, plus the
Python, Pylance, Terraform and Docker extensions for VS Code.
Note: the machine also has Python 3.11 and 3.13, and `python` resolves to 3.13, so the project
virtualenv is created explicitly with `py -3.12 -m venv .venv`.

**Credentials — resolved an open question.** The new account manages IAM Identity Center itself, so
there is no IAM user to create and no access key to store. `aws login --profile phishing` opens a
browser and issues temporary credentials valid for 12 hours, assuming `AccountFullAccessRole`.
The open question was whether Terraform would read that session. Verified directly with a throwaway
configuration containing only a provider block and an `aws_caller_identity` data source:
`terraform plan` returned the correct account ID with the AWS provider v6.73.0.
No access keys are needed anywhere in this project.

**Budget.** A monthly cost budget with email alerts was created by hand in the console rather than in
Terraform, so that it keeps working after `terraform destroy`.

**Repository.** Private repository, folder skeleton, and a `.gitignore` covering `.venv/`, `.env`,
`.terraform/`, `*.tfstate*` and `*.tfvars`. `.terraform.lock.hcl` is intentionally *not* ignored, so
the provider version stays pinned across machines.

---

## Incidents

One entry per incident, oldest first. A detail marked "(from the build session)" was not in the
owner's notes: it was added from the code and documents as they stood during the build.

### 2026-11-12 — RDS rejected Performance Insights for `db.t4g.micro`

**Date.** 12 November 2026.

**Phase.** 3, base infrastructure.

**Symptom.** The RDS API rejected `performance_insights_enabled` for `db.t4g.micro` when the
database was being created. The exact error text was not kept.

**How it was found.** By the rejection itself, at create time.

**Cause.** The API does not accept the setting for this instance class.

**Fix.** The setting was removed. (from the build session) `infra/base/rds.tf` sets nothing for
Performance Insights, and the state records it as disabled. checkov's `CKV_AWS_353` is skipped on
the resource with this reason.

**Lesson.** Keep the exact error text when an API refuses something. This entry cannot quote it.

### 2026-11-13 — First apply failed to assume the Auto Scaling service-linked role

**Date.** 13 November 2026.

**Phase.** 4, application infrastructure.

**Symptom.** The first apply failed with "Access denied when attempting to assume role
...AWSServiceRoleForAutoScaling".

**How it was found.** By the apply's error. The role was then checked, and it existed.

**Cause.** A new account: the Auto Scaling service-linked role was created on first use and had
not propagated yet.

**Fix.** Nothing was changed. A second apply replaced the tainted group and succeeded.

**Lesson.** In a new account, the first use of a service can fail once while its service-linked
role propagates. Check that the role exists and apply again. The second apply replacing the group
is the taint from the failed one, not a second problem.

### 2026-11-13 — Only one instance answered after the apply

**Date.** 13 November 2026.

**Phase.** 4, application infrastructure.

**Symptom.** After the apply, only one instance answered through the load balancer.

**How it was found.** By sending requests through the load balancer. `describe-target-health`
then showed both targets healthy, and requests alternated between the two instances.

**Cause.** With `health_check_type = "EC2"` the apply finishes before the targets are healthy. The
second instance was still booting.

**Fix.** None was needed: the second instance became healthy by itself. It led to
`wait_for_elb_capacity` in phase 5. (from the build session) In `infra/app/compute.tf` that
setting is the group's size whenever `health_check_type` is `ELB`, so the apply returns only once
every instance passes the load balancer's health check.

**Lesson.** In that mode "apply complete" did not mean "serving". Look at the target health before
deciding something is broken.

### 2026-11-13 — gunicorn's control socket needs a home directory the service user lacks

**Date.** 13 November 2026.

**Phase.** 5, the real application. Caught in review, before the deploy.

**Symptom.** None on a running system: it was caught before anything was deployed.

**How it was found.** In review.

**Cause.** gunicorn 25.1 and later creates a control socket under the user's home directory by
default. The service user has no home directory.

**Fix.** Added `--no-control-socket`. (from the build session) It is on the `ExecStart` line of
the unit in `deploy/user_data.sh.tftpl`; the pinned version in `app/requirements.txt` is
gunicorn 27.0.0.

**Lesson.** A service user without a home directory breaks defaults that assume one. The next
entry is the same lesson again.

### 2026-11-13 — Every save failed: libpq could not probe for a client certificate

**Date.** 13 November 2026.

**Phase.** 5, the real application.

**Symptom.** Scans worked, but every save failed with a notice, and `/history` returned 503. The
application degraded as designed.

**How it was found.** By reading the ERROR lines in `/var/log/phishing-app/app.log` over Session
Manager. libpq reported: "could not open certificate file
/home/phishing/.postgresql/postgresql.crt: Permission denied".

**Cause.** `ProtectHome=true` made `/home` inaccessible to the service. libpq's optional probe for
a client certificate therefore got EACCES instead of ENOENT, and aborted the connection.

**Fix.** `ProtectHome=tmpfs`, deployed through Terraform and a rolling instance refresh.
(from the build session) The unit in `deploy/user_data.sh.tftpl` has `ProtectHome=tmpfs`;
`docs/infra-app-phase5-design.md` still shows `ProtectHome=true`.

**Lesson.** A hardening option can turn "file not found" into "permission denied", and software
that shrugs at the first may stop at the second. The application's own error log named the cause
exactly.

### 2026-11-13 — `terraform plan` showed "No changes" after the fix

**Date.** 13 November 2026.

**Phase.** 5, the real application.

**Symptom.** `terraform plan` showed "No changes" after the fix above had been made.

**How it was found.** The edit turned out to be unsaved in the editor.

**Cause.** Terraform read the file on disk, which did not have the edit yet.

**Fix.** Saving the file.

**Lesson.** A plan reflects what is on disk, not what is on screen.

### 2026-11-13 — Boot time measured, and the two timers tuned to it

**Date.** 13 November 2026.

**Phase.** 6, monitoring.

**Symptom.** Not a failure: a measurement. An instance takes 118 seconds to boot.

**How it was found.** From the boot log group, which shows "Up 118.51 seconds".

**Cause.** Not applicable.

**Fix.** The grace period and the warm-up were tuned to 180 s and 240 s. The measurement is from
phase 6; the timers themselves were changed in phase 7. (from the build session)
They are the defaults of `health_check_grace_seconds` and `instance_warmup_seconds` in
`infra/app/variables.tf`, previously 240 and 300. The rule, from the phase 5 design document, is
grace period ≥ boot + 60 and warm-up ≥ grace period + 60.

**Lesson.** Measure, then tune. The boot log group made the measurement possible without
connecting to an instance.

### 2026-11-13 — The unhealthy-targets alarm fires during every instance refresh

**Date.** 13 November 2026.

**Phase.** 6, monitoring.

**Symptom.** `unhealthy-targets` went to ALARM and cleared again during every instance refresh.

**How it was found.** By the alarm itself, on each refresh.

**Cause.** A new instance is registered with the target group at launch, and fails the health
check until its boot finishes.

**Fix.** None: it is expected, and documented in the README. (from the build session) The entry is
"The unhealthy-target alarm fires during every deploy, and is left that way", under Decisions,
Observability.

**Lesson.** Expected alarms are worth writing down, so that nobody investigates them a second time.

### 2026-11-13 — Verification: traffic, and the 5XX alarm end to end

**Date.** 13 November 2026.

**Phase.** 6, monitoring. Verification, not an incident.

**Symptom.** None. `scripts/load.py` sent 900 requests in 180 s. All answered 200, split 451 and
449 between the two instances, with p50 262 ms and p95 338 ms. Then 10 calls to `/simulate-error`
at 19:03 UTC brought the `target-5xx` ALARM email at 19:06 UTC, and the alarm returned to OK later.

**How it was found.** By running the script and watching the alarm's emails.

**Cause.** Not applicable. The three minutes between the errors and the email are metric delay.

**Fix.** Not applicable. (from the build session) 900 requests is the script's default rate, 5 a
second, for 180 seconds. `target-5xx` fires at five or more target 5XX responses in one minute
(`infra/app/monitoring.tf`).

**Lesson.** Allow about three minutes between causing errors and expecting the alarm email.

### 2026-11-13 — Drill: stopping the service on one instance

**Date.** 13 November 2026.

**Phase.** 6, monitoring. A drill, not an incident.

**Symptom.** After `systemctl stop phishing-app` on one instance: the target went unhealthy, the
`unhealthy-targets` ALARM email arrived, the group replaced the instance, and the OK email
followed. The other instance served throughout.

**How it was found.** Deliberately, by running the drill.

**Cause.** The service was stopped on purpose.

**Fix.** None by hand: the Auto Scaling Group replaced the instance.

**Lesson.** Self-healing works as designed, and one instance carries the service while the other
is replaced.

### 2026-11-13 — The CPU widget also lists terminated instances

**Date.** 13 November 2026.

**Phase.** 6, monitoring.

**Symptom.** The CPU widget on the dashboard also lists terminated instances when the time range
covers them.

**How it was found.** On the dashboard.

**Cause.** The widget's SEARCH expression matches them. (from the build session) The expression is
`SEARCH('{AWS/EC2,InstanceId} MetricName="CPUUtilization"', ...)` in `infra/app/monitoring.tf`: it
selects by metric name across every instance, with no group in it.

**Fix.** None: known. All per-instance widgets (CPU, credit balance, memory, disk) list terminated
instances when the time range covers them, because SEARCH matches any metric with data in the
range. Use a 1-hour range in the demo.

**Lesson.** A SEARCH expression shows every series that reported inside the time range, including
series from instances that no longer exist.

### 2026-11-14 — One NAT gateway left the surviving instance unable to heal

**Date.** 14 November 2026.

**Phase.** Bonus A, HTTPS on the load balancer and a NAT gateway per availability zone.

**Symptom.** None on a running system: a gap in the design, not a failure that happened.

**How it was found.** In an availability review of the design.

**Cause.** The stack started with a single NAT gateway, to save cost. Both private route tables
sent internet traffic to it, in the first availability zone. If that zone failed, the instance in
the other zone would keep serving through the load balancer but could not heal: no way out to S3,
Secrets Manager, CloudWatch or Session Manager, and a replacement instance could not boot.

**Fix.** One NAT gateway per availability zone, each private route table pointing at the gateway
in its own zone. (from the build session) The change is in `infra/app/nat.tf`, keyed by zone name
throughout; the `nat_public_ip` output became `nat_public_ips`, a map from zone to address. It
adds about $1.10 a day for the gateway and about $0.12 for its address, while the stack runs.

**Lesson.** Two instances in two zones are not highly available if they share one way out. Ask of
every shared component what the survivors lose when its zone goes. The database is still in one
zone, on purpose.

### 2026-11-14 — First apply of bonus A timed out: instances replaced before they finished booting

**Date.** 14 November 2026.

**Phase.** Bonus A, HTTPS on the load balancer and a NAT gateway per availability zone.

**Symptom.** The first apply timed out after 12 minutes with "want at least 2 healthy instance(s)
registered to Load Balancer, have 1", and the Auto Scaling Group was tainted.

**How it was found.** The group's Activity tab showed one instance terminated for "ELB system health
check failure" about every four minutes: 12:05, 12:09, 12:13 and 12:17 UTC.

**Cause.** The grace period was 180 s and boots were taking 203 to 298 s, so instances were replaced
before they finished booting. Why the boots had become that slow is the next entry.

**Fix.** Grace period 300 s, warm-up 360 s. The next apply replaced the tainted group and succeeded.
(from the build session) They are the defaults of `health_check_grace_seconds` and
`instance_warmup_seconds` in `infra/app/variables.tf`.

**Lesson.** The Activity tab gives the reason for every termination. Terminations for "ELB system
health check failure" at a regular interval mean instances are being replaced before their boot
finishes: compare the grace period with the boot time.

### 2026-11-14 — Root cause of the slow boots: `cpu_credits = "standard"`

**Date.** 14 November 2026.

**Phase.** Bonus A, HTTPS on the load balancer and a NAT gateway per availability zone.

**Symptom.** Boots took 203 s and 298 s on 14 November, against 118 s measured on 13 November.

**How it was found.** The boot log showed creating the virtualenv alone taking 30 s, and the
dashboard's CPU credit balance for new instances started at 0.

**Cause.** `cpu_credits = "standard"` on the launch template. A new t3 instance with standard
credits starts with none, so it boots at its baseline, 10% per vCPU.

**Fix.** `cpu_credits = "unlimited"`. The next measured boot took 76 s. (from the build session) The
change is in `infra/app/compute.tf`, commit `425f3bb`. Surplus is billed only above the 24-hour
average baseline, and the `cpu-high` alarm guards against a sustained surge.

**Lesson.** Measured boots were 118 s, 203 s and 298 s with "standard" for the same code: one
measurement was not enough to tune the timers against. The credit balance on the dashboard
explained a slowness that the CPU graph alone did not.

### 2026-11-14 — `terraform plan` failed: the login session had expired

**Date.** 14 November 2026.

**Phase.** Not recorded.

**Symptom.** `terraform plan` failed with "No valid credential sources found ... login session has
expired".

**How it was found.** By the error.

**Cause.** The temporary credentials from `aws login` had expired.

**Fix.** Not recorded. (from the build session) The session is renewed with
`aws login --profile phishing`, as in the environment setup above.

**Lesson.** Run `aws sts get-caller-identity` at the start of every session.

### 2026-11-14 — Bonus A applied and verified

**Date.** 14 November 2026.

**Phase.** Bonus A, HTTPS on the load balancer and a NAT gateway per availability zone.
Verification, not an incident.

**Symptom.** None. The self-signed certificate was imported into ACM, the HTTPS listener served the
site with a 301 redirect from port 80, and there was one NAT gateway per zone, with two addresses in
the outputs. 300 of 300 requests over HTTPS succeeded, split 150 and 150 between the two instances.

**How it was found.** From the apply's outputs and the requests sent over HTTPS.

**Cause.** Not applicable.

**Fix.** Not applicable.

**Lesson.** Not applicable.

### 2026-11-14 — Bonus B applied: the result cache works, and saves little time

**Date.** 14 November 2026.

**Phase.** Bonus B, a result cache on ElastiCache (Valkey). Verification, not an incident.

**Symptom.** None. The `infra/base` apply added 6 resources, changed 0 and destroyed 0; the cluster
took about 10 minutes to create. A repeated scan showed "Served from cache" and "Seen 2 times", and
the history showed the cache marker. `scripts/load.py` sent 300 requests: 300 succeeded, split 150
and 150, with p50 420 ms, about the same as before the cache.

**How it was found.** From the apply's output, the result and history pages, and `load.py`'s summary.

**Cause.** Not applicable. The request time is dominated by the network, TLS and the database
write, not by the engine, so skipping the engine changes little.

**Fix.** Not applicable.

**Lesson.** A cache saves only the work it skips. Here that is the engine, and the request time is
dominated by everything else, so the speed gain is not where the cache earns its place.

---

## Template for new entries

### YYYY-MM-DD — short title

**Date.** The day it happened.

**Phase.** Which phase of the build, and what that phase was.

**Symptom.** What was observed, including the exact error message.

**How it was found.** Where the evidence was: a log, a command's output, an alarm, a review.

**Cause.** What was actually wrong.

**Fix.** What resolved it, and where the change lives.

**Lesson.** Anything worth remembering, or that belongs in the runbook.
