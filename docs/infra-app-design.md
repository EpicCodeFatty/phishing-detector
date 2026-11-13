# Application infrastructure — design specification

`infra/app` holds everything that is created for a working session and destroyed at the end of it: the
NAT gateway, the security groups, the load balancer, the instance role, and the Auto Scaling Group that
keeps two instances running.

This document covers **phase 4 only**: standing the infrastructure up with a placeholder application
that answers "hello" and nothing more. The real application, the S3 artifact and the monitoring come in
phases 5 and 6, into the same stack.

Read `docs/code-standards.md` and `docs/infra-base-design.md` first.

---

## 1. Why the placeholder

The goal of this phase is two instances behind a load balancer, each answering with its own instance ID.
No detection engine, no database, no uploaded files.

That is deliberate. Almost everything that can go wrong here is infrastructure: a port that does not
match, a security group that blocks the health check, a missing route to the NAT, a boot script that
exits early. If the real application were running at the same time, every failure would have two
possible causes and you would be debugging both at once.

Once a trivial HTTP server is reachable through the load balancer from both instances, the networking
is proven. Phase 5 then only swaps what runs on port 8000.

---

## 2. Layout

```
infra/app/
├── versions.tf       version constraints, identical to base
├── providers.tf      provider, region, default tags with Stack = "app"
├── variables.tf
├── remote-state.tf   reads infra/base
├── nat.tf            elastic IP, NAT gateway, routes
├── security.tf       alb-sg, app-sg, and the ingress rule on base's db-sg
├── iam.tf            instance role and instance profile
├── alb.tf            load balancer, target group, listener
├── compute.tf        AMI lookup, launch template, Auto Scaling Group
└── outputs.tf

deploy/
└── user_data.sh.tftpl    the boot script
```

---

## 3. Reading the base stack (`remote-state.tf`)

```hcl
data "terraform_remote_state" "base" {
  backend = "local"

  config = {
    path = "${path.module}/../base/terraform.tfstate"
  }
}

locals {
  base = data.terraform_remote_state.base.outputs
}
```

Then `local.base.vpc_id`, `local.base.private_app_subnet_ids`, and so on. Unpacking once into a local
means the long expression appears in one place.

**Two consequences to be aware of.** This stack can only be planned on a machine that has `base`'s state
file, and `base` must exist before `app` is applied and be destroyed after it. Both are recorded in the
README.

---

## 4. NAT gateway (`nat.tf`)

```hcl
resource "aws_eip" "nat" {
  domain = "vpc"        # not the removed `vpc = true`
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = local.base.public_subnet_ids[0]   # a public subnet, in AZ a
}

resource "aws_route" "private_app_nat" {
  for_each = local.base.private_app_route_table_ids

  route_table_id         = each.value
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main.id
}
```

**The NAT goes in a public subnet, not a private one.** This catches people out: the gateway that gives
private instances a way out must itself sit where there is a route to the internet gateway.

**One NAT serves both availability zones.** Both private-app route tables point at it, which is why
`base` created a table per AZ. The accepted risk is stated in the README: if AZ a fails, the instance in
AZ b keeps serving traffic through the load balancer but cannot reach S3, Secrets Manager, CloudWatch or
PyPI, and a replacement instance cannot boot. Production would run one NAT per AZ, which with this
structure is a change to `for_each` and nothing else.

The routes live here rather than in `base` so that `terraform destroy` on this stack removes them, and
the route tables return to having no way out.

---

## 5. Security groups (`security.tf`)

Three groups, each referencing the one before it rather than an address range.

| Group | Ingress | Egress |
|---|---|---|
| `alb-sg` | TCP 80 from `var.allowed_ingress_cidrs` | TCP 8000 to `app-sg` |
| `app-sg` | TCP 8000 from `alb-sg` | TCP 443 to `0.0.0.0/0`, TCP 5432 to `db-sg` |
| `db-sg` (in `base`) | TCP 5432 from `app-sg` — **added here** | none |

Rules:

- Use the singular rule resources (`aws_vpc_security_group_ingress_rule`,
  `aws_vpc_security_group_egress_rule`), not inline `ingress` / `egress` blocks. Inline blocks are
  authoritative for the whole group: this stack adding a rule to `base`'s `db-sg` with an inline block
  would fight with `base` on every apply, each removing the other's rules.
- A group declared with no inline rules has **no egress at all** — Terraform removes the allow-all rule
  AWS adds by default. That is intended; every permitted direction is written out above.
- Every rule carries a `description`. It is what a reviewer reads in the console, and scanners flag
  rules without one.
- Both groups use `name_prefix` with `lifecycle { create_before_destroy = true }`. Changing a group's
  description forces a replacement, and a fixed name makes that replacement fail while the old group is
  still attached to the load balancer or an instance.
- `allowed_ingress_cidrs` is a list variable defaulting to `["0.0.0.0/0"]`, one rule per entry. The
  service is public by design; the variable exists so it can be narrowed to known addresses without
  editing the rule.

**Port 22 appears nowhere.** Shell access is through Session Manager, which works over an outbound
connection on 443.

**Why egress on 443 only is enough.** The instances reach the AWS APIs (SSM, Secrets Manager,
CloudWatch), the Amazon Linux 2023 repositories and PyPI, all over HTTPS. DNS to the VPC resolver, the
instance metadata service and the Amazon time service are link-local and are not filtered by security
groups, so they need no rule.

> **If the boot fails at `dnf install`, this is the first thing to check.** Add port 80 only if a
> repository genuinely needs it, and record it in the BUILD_LOG rather than silently widening the rule.

---

## 6. Instance role (`iam.tf`)

```hcl
resource "aws_iam_role" "app" { ... }          # trust policy: ec2.amazonaws.com

resource "aws_iam_role_policy_attachment" "ssm" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cloudwatch" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "app" { ... }
```

Write the trust policy with `data "aws_iam_policy_document"` rather than a JSON string.

Two AWS-managed policies now; two narrow inline policies are added in phase 5 for the S3 object and the
database secret, each scoped to a single ARN.

This was an open question — whether to use managed policies at all, or write everything inline. Managed
policies are used here because `AmazonSSMManagedInstanceCore` and `CloudWatchAgentServerPolicy` are the
documented requirements for those two agents, and recreating them by hand means guessing at a list that
AWS maintains and changes. The narrow permissions, where the scope genuinely matters, are written by
hand against exact ARNs. Record this in the README as a deliberate split rather than a default.

An instance profile is the wrapper that attaches a role to an instance. It is a separate resource and
easy to forget; without it the role exists and the instance has no credentials.

> **Account guardrails.** This account was created through AWS's project-based sign-up, which applies
> its own service control policies. If `apply` is refused on `iam:CreateRole` or
> `iam:CreateInstanceProfile`, stop there and record the exact error — do not work around it with
> broader credentials.

---

## 7. Load balancer (`alb.tf`)

```hcl
resource "aws_lb" "main" {
  load_balancer_type = "application"
  internal           = false
  subnets            = local.base.public_subnet_ids     # both AZs
  security_groups    = [aws_security_group.alb.id]

  drop_invalid_header_fields = true
  enable_deletion_protection = false    # this stack is destroyed daily
}

resource "aws_lb_target_group" "app" {
  name_prefix = "phish-"                # six characters at most
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = local.base.vpc_id
  target_type = "instance"

  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  deregistration_delay = 30

  lifecycle { create_before_destroy = true }
}

resource "aws_lb_listener" "http" {
  port     = 80
  protocol = "HTTP"
  default_action { type = "forward" ... }
}
```

- **`name_prefix` and `create_before_destroy` on the target group.** Changing its port or protocol
  forces a replacement. With a fixed name the new one cannot be created while the old one exists, and
  the old one cannot be deleted while the listener uses it; the apply deadlocks on itself.
- **`drop_invalid_header_fields`** discards malformed HTTP headers at the edge. It costs nothing and is
  a standard finding when absent.
- **The listener is plain HTTP**, and a scanner will flag it. There is no domain to issue a certificate
  for; the comment on the resource says so, and HTTPS is planned as a late addition.
- **Short health check intervals and a short deregistration delay** are for the demo: a new instance is
  in service about twenty seconds after it starts answering, and terminating one shows quickly.
  Production would use longer values.
- **The load balancer spans both availability zones.** With subnets in only one, an AZ failure takes
  the service down regardless of where the instances are.

An ALB takes two to three minutes to become active. `terraform apply` will sit on it.

---

## 8. Launch template and Auto Scaling Group (`compute.tf`)

### AMI

```hcl
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_ami" "al2023" {
  owners = ["amazon"]

  filter {
    name   = "image-id"
    values = [data.aws_ssm_parameter.al2023.insecure_value]
  }
}
```

The AMI ID comes from the public SSM parameter, never a literal: IDs differ per region and change with
every Amazon Linux release. Use `insecure_value`, not `value` — the provider marks `value` as sensitive,
which would hide the AMI ID in every plan for no reason.

The second lookup exists for one attribute, `root_device_name`. Encrypting the root volume means naming
its device, and a wrong name does not fail: it attaches a second, empty encrypted volume and leaves the
real root unencrypted. Reading the name from the image removes the guess.

This is the standard AL2023 image, which ships with the SSM agent. The "minimal" image does not, and
Session Manager would never connect.

### Launch template

```hcl
data "aws_default_tags" "current" {}

locals {
  # the provider's default tags plus a Name, used by the launch template and the group
  app_tags = merge(data.aws_default_tags.current.tags, { Name = "${var.project}-app" })
}

resource "aws_launch_template" "app" {
  image_id      = data.aws_ami.al2023.id
  instance_type = var.instance_type          # t3.micro

  iam_instance_profile { arn = aws_iam_instance_profile.app.arn }
  vpc_security_group_ids = [aws_security_group.app.id]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = data.aws_ami.al2023.root_device_name
    ebs {
      encrypted             = true
      volume_type           = "gp3"
      delete_on_termination = true
      # no volume_size: inherit the image's, so a larger future image cannot break the launch
    }
  }

  credit_specification { cpu_credits = "standard" }

  dynamic "tag_specifications" {
    for_each = toset(["instance", "volume", "network-interface"])
    content {
      resource_type = tag_specifications.value
      tags          = local.app_tags
    }
  }

  user_data = base64encode(replace(
    templatefile("${path.module}/../../deploy/user_data.sh.tftpl", {}),
    "\r\n", "\n"
  ))

  update_default_version = true
}
```

Five things here are easy to get subtly wrong:

- **`default_tags` does not reach instances launched by an Auto Scaling Group.** The provider tags the
  launch template itself, not what it launches. Without `tag_specifications` the instances and their
  volumes carry no `Project` tag — and the teardown verification, which searches by that tag, would
  report a clean account while missing them. `aws_default_tags` re-uses the provider's tags so they are
  still declared once.
- **`replace(..., "\r\n", "\n")`.** `.gitattributes` normalises line endings in the repository, but a
  file freshly saved by a Windows editor keeps CRLF in the working directory, and Terraform reads the
  working directory. A script with CRLF fails on Linux at its first line with
  `/bin/bash^M: bad interpreter`. Stripping carriage returns here makes the boot independent of editor
  settings.
- **`http_tokens = "required"`** forces IMDSv2. The older version let any process able to make an HTTP
  request — including one tricked into it through server-side request forgery — read the instance's
  credentials. A hop limit of 1 stops a container on the instance from reaching it.
- **`cpu_credits = "standard"`** stops a `t3` instance from silently billing for burst credits. The
  default, `unlimited`, is a surprise on a bill.
- **Template escaping.** `templatefile` treats `${...}` and `%{...}` as its own syntax. The phase 4
  script uses neither, but any shell `${VAR}` added later must be written `$${VAR}` or the apply fails
  with an unknown-variable error. Plain `$VAR` and `$(command)` are untouched.

### Auto Scaling Group

```hcl
resource "aws_autoscaling_group" "app" {
  min_size         = var.asg_size
  max_size         = var.asg_size
  desired_capacity = var.asg_size

  vpc_zone_identifier = local.base.private_app_subnet_ids   # one subnet per AZ
  target_group_arns   = [aws_lb_target_group.app.arn]

  health_check_type         = var.health_check_type         # "EC2" while building
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.app.id
    version = aws_launch_template.app.latest_version
  }

  dynamic "tag" {
    for_each = local.app_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = false     # tags the group only, not its instances
    }
  }

  # Instances start running user_data within seconds of launch. Nothing in this
  # resource refers to the NAT route, the egress rule or the role's policies, so
  # without this Terraform creates them in parallel — and the first boot runs
  # `dnf install` before there is a way out, fails once, and is never retried.
  depends_on = [
    aws_route.private_app_nat,
    aws_vpc_security_group_egress_rule.app_https,
    aws_iam_role_policy_attachment.ssm,
    aws_iam_role_policy_attachment.cloudwatch,
  ]
}
```

- **`depends_on` is the most important line in this stack.** The race it prevents is real: a NAT
  gateway takes about two minutes to become available and an instance boots in under one. Without it
  the first apply produces two instances with a failed boot script, and nothing in the plan or the
  apply output says why.
- **`latest_version`, not the string `"$Latest"`.** Both launch the newest version, but only the
  attribute reference changes in the plan when the template changes. Phase 5's instance refresh is
  triggered by that change; with `"$Latest"` Terraform sees nothing to do and old instances stay.
- **`health_check_type` is a variable, defaulting to `"EC2"` for this phase**, validated to accept only
  `"EC2"` or `"ELB"`. With `"ELB"`, an instance whose boot script failed is replaced a few minutes
  later — before you can connect and read the log. With `"EC2"` it stays up however broken the
  application is. Switch to `"ELB"` in phase 5 once the boot is reliable; that is what makes
  self-healing real.
- **The group is tagged with its own `tag` blocks, with `propagate_at_launch = false`.** The provider
  applies `default_tags` to every taggable resource except `aws_autoscaling_group`, so without them the
  group would be the one untagged resource in the stack. The blocks are built from the same
  `local.app_tags` as the launch template. They tag the group only: with `propagate_at_launch = false`
  nothing is copied to the instances, so the launch template stays the one place instance tags come
  from.
- **No instance refresh in this phase.** It is added in phase 5. Until then, see section 12 for how a
  changed boot script reaches running instances — it does not happen by itself.

---

## 9. The boot script (`deploy/user_data.sh.tftpl`)

Phase 4's version installs Python and runs a small HTTP server. Phase 5 replaces the middle of it.

```bash
#!/bin/bash
set -euxo pipefail

# Every line of this script, and its output, lands in
# /var/log/cloud-init-output.log — the first place to look if an instance
# never becomes healthy. set -x prints each command; set -e stops at the
# first failure rather than carrying on with a half-built instance.

retry() {
  # retry <attempts> <command...> — for steps that depend on the network
  local attempts=$1; shift
  local n=1
  until "$@"; do
    if [ "$n" -ge "$attempts" ]; then
      echo "FAILED after $attempts attempts: $*" >&2
      return 1
    fi
    n=$((n + 1))
    sleep 10
  done
}

imds() {
  local token
  token=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
  curl -sf -H "X-aws-ec2-metadata-token: $token" \
    "http://169.254.169.254/latest/meta-data/$1"
}

INSTANCE_ID=$(retry 5 imds instance-id)
test -n "$INSTANCE_ID"

retry 12 dnf install -y python3.12

useradd --system --no-create-home --shell /sbin/nologin phishing

mkdir -p /opt/app
cat > /opt/app/hello.py <<'PYEOF'
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INSTANCE = os.environ.get("INSTANCE_ID", "unknown")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"hello from {INSTANCE}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
PYEOF

cat > /etc/phishing-app.env <<ENVEOF
INSTANCE_ID=$INSTANCE_ID
ENVEOF
chmod 0640 /etc/phishing-app.env

cat > /etc/systemd/system/phishing-app.service <<'SVCEOF'
[Unit]
Description=Phishing detector (placeholder)
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
User=phishing
Group=phishing
EnvironmentFile=/etc/phishing-app.env
ExecStart=/usr/bin/python3.12 /opt/app/hello.py
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable --now phishing-app

retry 10 curl -sf http://127.0.0.1:8000/health
echo "user_data finished OK"
```

Points that matter beyond this phase:

- **It binds `0.0.0.0`, not `127.0.0.1`.** A server listening only on the loopback address answers
  itself and nothing else, and the health check fails with no clue as to why. This is the single most
  common cause of an unhealthy target.
- **Network steps are retried; nothing else is.** `depends_on` removes the known race, and the retry
  covers the unknown ones — a slow mirror, a metadata service not yet ready. A boot script runs exactly
  once, so a transient failure is otherwise permanent. `retry` writes its failure message to stderr:
  inside `$(...)`, as in the instance ID lookup, stdout is captured as the result and would not reach
  the log.
- **`curl -f`.** Without it a failed request returns exit code 0 with an error page as its output, and
  `set -e` sees nothing wrong.
- **The service runs as its own unprivileged user**, not root. Port 8000 needs no privilege. If the
  application is ever compromised, it is as a user that owns nothing.
- **`StartLimitIntervalSec=0` with `RestartSec=3`.** By default systemd stops restarting a unit that
  fails five times in ten seconds and leaves it dead. For a service whose only supervisor is systemd,
  giving up is the wrong behaviour.
- **The Python and unit-file heredocs are quoted (`<<'EOF'`)** so the shell does not expand anything
  inside them. The environment-file heredoc is unquoted on purpose: it is the one place a shell
  variable must be expanded.
- **The last two lines are a self-test and a marker.** If `user_data finished OK` is absent from the
  log, the script died earlier, and `set -x` shows where.
- **The instance ID comes from IMDSv2** — a PUT for a token, then a GET with it. Phase 5 reuses it for
  the real application's `INSTANCE_ID`.
- **The service is named `phishing-app`** here and in phase 5, so the drills refer to one name.

**Carried into phase 5**, noted here so it is not rediscovered: the real application is started with
`gunicorn --bind 0.0.0.0:8000 'app.web:create_app()'`; it needs `INSTANCE_ID`, `DB_HOST`,
`DB_SECRET_ARN` and `LOG_FILE` in the environment file; and because it runs as `phishing`, its log
directory must be created for that user — `LogsDirectory=phishing-app` in the unit does this.

---

## 10. Variables and outputs

Variables, each with a type and description: `project`, `region`, `aws_profile`,
`instance_type` (`t3.micro`), `asg_size` (`2`), `health_check_type` (`"EC2"`, validated),
`allowed_ingress_cidrs` (`["0.0.0.0/0"]`).

Outputs: `alb_dns_name`, `alb_url` (with `http://` in front), `asg_name`, `target_group_arn`,
`app_security_group_id`, `instance_role_name`, `nat_public_ip`. The role name and security group are
for phase 5; the NAT address is the address the instances appear from, which is useful when reading
third-party logs.

---

## 11. Applying it

### Before the first apply

```powershell
aws sts get-caller-identity --profile phishing
```

The `aws login` session lasts twelve hours. An apply that loses its credentials halfway leaves a
half-built stack; checking takes two seconds.

```powershell
aws service-quotas get-service-quota --service-code ec2 --quota-code L-1216C47A --profile phishing --query Quota.Value
```

This is the vCPU quota for standard on-demand instances. Two `t3.micro` need 4. New accounts sometimes
start lower, and the symptom is one instance launching and the other never appearing.

### Apply

```powershell
cd infra\app
terraform init
terraform validate
terraform plan
terraform apply
```

Expect about 21 resources and five to eight minutes: about two for the NAT gateway, then the
instances (which now wait for it), and two to three for the load balancer in parallel.

In the plan, check that: every resource is in `eu-north-1`; the launch template shows a real AMI ID,
not `(sensitive value)`; the Auto Scaling Group's subnets are the two private-app subnets; and no
security group rule mentions port 22.

### Test

```powershell
$url = terraform output -raw alb_url
curl.exe -s "$url/health"
1..8 | ForEach-Object { curl.exe -s $url }
```

On Windows write `curl.exe`. Plain `curl` in PowerShell is an alias for a different command.

**A 503 for the first minute or two is normal.** It means the load balancer is up and has no healthy
targets yet. Watch EC2 → Target Groups until both read `healthy`.

**Done when** the eight requests show both instance IDs. Do not expect strict alternation: the load
balancer has a node in each availability zone, each keeping its own rotation, so the same instance can
answer twice in a row.

---

## 12. When an instance never becomes healthy

This will happen, probably more than once. Work through it in order rather than changing things at
random — each wrong guess costs a five-minute cycle.

1. **Does the instance exist?** EC2 → Auto Scaling Groups → the group → Activity. A launch that failed
   outright says why here (quota, instance profile not yet visible — the group retries that by itself).
   Instances launching and terminating in a loop means `health_check_type` is `"ELB"`.

2. **What does the target group say?** EC2 → Target Groups → Targets, or:
   ```powershell
   aws elbv2 describe-target-health --profile phishing --target-group-arn (terraform output -raw target_group_arn)
   ```
   `Health checks failed` means the instance was reached and answered wrongly. `Request timed out`
   means it was not reached at all — a security group or port problem, not an application one.

3. **Get onto the instance.** EC2 → Instances → select → Connect → Session Manager. An instance takes
   two to three minutes after launch to appear there. If it never does, it has no way out: check that
   the NAT gateway is `available` and that the route exists in that AZ's route table.

4. **Read the boot log.**
   ```bash
   sudo tail -100 /var/log/cloud-init-output.log
   ```
   Look for `user_data finished OK`. If it is missing, the last command `set -x` printed is the one
   that failed.

5. **Check the service.**
   ```bash
   systemctl status phishing-app
   journalctl -u phishing-app -n 50
   curl -v localhost:8000/health
   ```
   If this answers on the instance while the target group still fails, the problem is between the load
   balancer and the instance: the security group rule, or the port in the target group.

### Getting a fix onto the instances

**A boot script runs once, at first boot. Rebooting an instance does not run it again, and
`terraform apply` after editing it changes the launch template only — running instances keep the old
script.** In this phase there is no instance refresh, so after an apply that changes the script, replace
the instances by hand:

```powershell
aws autoscaling start-instance-refresh --profile phishing --auto-scaling-group-name (terraform output -raw asg_name)
```

or terminate them in the console and let the group launch new ones. Forgetting this is the classic way
to "fix" something three times and see no change.

**Write every failure in BUILD_LOG.md as it happens.** Phase 8 asks for a troubleshooting runbook, and
this is where its contents come from.

---

## 13. Cost and teardown

| | per day |
|---|---|
| NAT gateway | ~$1.10 |
| Load balancer | ~$0.60 |
| 2 × t3.micro | ~$0.50 |
| Public IPv4 addresses (NAT + two load balancer nodes) | ~$0.35 |
| **This stack, running** | **~$2.55** |

At the end of each working session:

```powershell
terraform destroy
```

`base` stays up — that is the $0.40 a day for the database, and it is why the two stacks are split.

Each apply creates a new load balancer with a new DNS name. Nothing depends on the name, but do not
write it down and expect it to work tomorrow; read it from `terraform output` each time.

After a destroy, confirm nothing billable was left behind:

```powershell
aws resourcegroupstaggingapi get-resources --profile phishing --tag-filters Key=Stack,Values=app --query "ResourceTagMappingList[].ResourceARN"
```

An empty list is the expected answer, but not always straight away: the tag query can go on listing
terminated instances and deleted NAT gateways for a while after the destroy. A resource in the list is
only a concern if its state is still `running` (an instance) or `available` (a NAT gateway) when checked
in its own console. Anything shown there as `terminated` or `deleted` is gone, costs nothing, and drops
out of the list by itself.

This works for instances and volumes only because the launch template tags them explicitly.
