# Phishing Email Detector on AWS

A Python service that analyzes an email file, scores it for phishing indicators, and returns a verdict.
Deployed on AWS with Terraform: a frontend and backend running on two EC2 instances behind an
Application Load Balancer, with scan history stored in RDS PostgreSQL.

> Status: work in progress. Sections marked TODO are filled in as the project is built.

---

## 1. Overview

TODO — what the service does, in a few sentences.

## 2. Architecture

TODO — diagram and a short walkthrough of the request path.

**Region:** `eu-north-1` (Stockholm)

## 3. The detection engine

TODO — parsing, the four checkers (links, sender, wording, attachments), and how the score is built.

## 4. Running it

### Locally

The detection engine runs on its own, with no AWS account and no network access. It needs Python 3.12.

```bash
py -3.12 -m venv .venv                  # python3.12 -m venv .venv on Linux and macOS
.venv\Scripts\activate                  # source .venv/bin/activate on Linux and macOS
pip install -r requirements-dev.txt
```

`requirements-dev.txt` pins the development tools, `pytest` and `ruff`, and pulls in the runtime
dependencies from `app/requirements.txt`, so that one command sets up everything.

Analyse an email file:

```bash
python detect.py samples/paypal-phish.eml           # human-readable report
python detect.py samples/paypal-phish.eml --json    # the same result as JSON
```

The exit code carries the verdict: `0` Safe, `1` Suspicious, `2` Phishing, `3` if the file could not
be read.

Run the web application. It needs the local PostgreSQL container, which Docker runs from
`docker-compose.yml`:

```bash
docker compose up -d --wait             # PostgreSQL 16 on localhost:5432
echo DB_PASSWORD=localdev > .env        # once; .env is git-ignored, localdev is the container's password
flask --app app.web run --port 8000     # then open http://127.0.0.1:8000
```

The scans table is created on first use. Without the container the application still starts and
scans still work; results simply are not saved, and the history page returns 503.
`docker compose down` stops the database and keeps its data.

Before every commit:

```bash
ruff format .
ruff check .
pytest -m "not integration"             # needs nothing running
```

The database tests are marked `integration` and run against the container, in a separate
`phishing_test` database so the local history is left alone:

```bash
docker compose up -d --wait
pytest -m integration
```

### On AWS

TODO — `infra/base` first (VPC + RDS), then `infra/app` (everything else).

## 5. Monitoring

TODO — which metric answers which question, dashboard, alarms, where the logs are.

## 6. Troubleshooting runbook

TODO — failure scenarios, what you see, and what to check first.

## 7. Security

TODO — scan findings, what was fixed, and what was accepted with a reason.

## 8. Cleanup

TODO — `terraform destroy` and how the teardown was verified.

---

## 9. Decisions and trade-offs

Every choice below was made deliberately. Where a cheaper or simpler option exists, it is named.

### Infrastructure

**Two Terraform stacks: `infra/base` and `infra/app`.**
`base` holds the VPC and RDS and is applied ahead of time, because RDS takes about ten minutes to
become available. `app` holds everything else and is applied live during the review in a few minutes.
`app` reads `base` outputs through `terraform_remote_state`.
*Trade-off:* two state files instead of one, and a dependency between them.

**`infra/app` finds `infra/base` through its state file, not by looking resources up by tag.**
`terraform_remote_state` reads the outputs of `base`'s local state file: the VPC, the subnets, the
database endpoint, the secret's ARN, the topic. The alternative is a data source per resource in `app`,
each finding its target by tag. That removes the dependency on the file, but it is more code, and it is
a second source of truth: the tags `app` searches for must stay in step with what `base` creates, and a
mismatch shows up as a lookup that finds nothing, or the wrong thing. The outputs are one explicit
contract instead.
*Trade-off:* `app` can only be planned on the machine that holds `base`'s state file, at the path it
expects, which suits a single operator and nothing larger. It also fixes the order: `base` is applied
before `app` and destroyed after it. With a team, both states would live in an S3 backend and
`terraform_remote_state` would read from there, with no other change.

**EC2 instances in private subnets, egress through a NAT Gateway.**
The instances have no public IP. Inbound traffic reaches them only from the load balancer's security
group; everything else is denied at the subnet level, not just by a security group rule.
*Trade-off:* a NAT Gateway costs roughly $1.10/day. A single NAT (in one AZ) is used rather than one
per AZ: if that AZ fails, the instance in the other AZ still serves traffic through the ALB but cannot
reach S3, Secrets Manager or CloudWatch, and a replacement instance cannot boot. In production this
would be one NAT per AZ.

**A NAT Gateway rather than VPC endpoints.**
In production the instances would reach AWS services through VPC endpoints instead: interface endpoints
for Session Manager, Secrets Manager, CloudWatch Logs and CloudWatch metrics, and a gateway endpoint for
S3. That traffic would then never leave the AWS network, and the instances would need no route to the
internet at all, which is the more secure pattern.
*Trade-off:* interface endpoints are billed per endpoint, per availability zone, per hour, and the
handful this project needs, in two zones, costs more than the single NAT. They would also not remove the
NAT: the instances install their Python dependencies from PyPI at boot, which no endpoint reaches. For a
four-day project the NAT is the cheaper way to the same working system.

**Auto Scaling Group with min = max = desired = 2, one instance per AZ, `health_check_type = "ELB"`.**
This gives self-healing with no code: a failing instance is replaced automatically, which can be
demonstrated live by terminating one.
*Trade-off:* harder to debug than two fixed `aws_instance` resources, since a broken instance is
replaced before it can be inspected. During development the health check type is set to `EC2` so
instances survive long enough to investigate.

**Chained security groups.**
`alb-sg` accepts :80 from the internet. `app-sg` accepts :8000 only from `alb-sg`. `db-sg` accepts
:5432 only from `app-sg`. No security group admits traffic from a CIDR range except the load balancer's
listener, and port 22 is not open anywhere. Outbound, the instances are allowed :443 to the internet,
which is required for the AWS APIs and the package repositories.

**RDS PostgreSQL, `db.t4g.micro`, single-AZ, encrypted, not publicly accessible.**
*Trade-off:* the database is a single point of failure, while the application tier is spread across two
AZs. Multi-AZ doubles the cost and the provisioning time, which is not justified for a four-day
exercise. The failure mode is understood and handled: the health check does not touch the database,
so a database outage degrades the service rather than taking it down.

**Application code is delivered through S3.**
Terraform packages `app/` into a versioned zip, uploads it to a private bucket, and the instance's
`user_data` downloads it at boot. The zip is named after the hash of its contents, so a code change is
a new key, and that alone starts a rolling replacement of the instances. The instance role is allowed
`s3:GetObject` on the bucket's `releases/` prefix only: one key would have to be rewritten on every
release, while old and new instances coexist.
*Trade-off:* boot is slower than a pre-baked AMI, and the boot depends on PyPI for dependencies.
Alternatives considered: `git clone` (requires a token on the instance), ECR (an extra service),
a Packer-built AMI (a build step out of proportion to the project).

### Security and access

**No long-lived AWS credentials anywhere.**
Local development uses `aws login`, which issues temporary credentials valid for 12 hours; no access
keys exist on disk. EC2 instances receive credentials through an instance role over IMDSv2, which is
required (not optional) on the launch template. Nothing in the repository contains a key, and
`gitleaks` runs before every push.

**The database password is never written down.**
RDS generates and rotates it (`manage_master_user_password = true`) and stores it in Secrets Manager.
The application reads it at startup and re-reads it if authentication fails, so rotation does not
require a redeploy. The password does not appear in Terraform variables, in state, or on the instance.

**Shell access through SSM Session Manager.**
No key pairs, no bastion host, no port 22 in any security group. Every session is authenticated and
authorized through IAM.

**AWS-managed policies for the two agents, hand-written policies for the data.**
The instance role attaches `AmazonSSMManagedInstanceCore` and `CloudWatchAgentServerPolicy`. They are
the documented requirements of the SSM agent and the CloudWatch agent, and rewriting them by hand means
guessing at a list of actions that AWS maintains and changes. Where the scope matters, reading the
releases in one bucket and one database secret, the permission is an inline policy written against
exactly that: one bucket prefix, one secret ARN.
*Trade-off:* the managed policies are broader than this project uses, and AWS can change them without
anything changing in this repository.

**HTTP only, no TLS.**
There is no domain for this exercise, so there is no ACM certificate to attach to the listener.
*Trade-off:* traffic is unencrypted. With a domain, this would be a Route 53 record, an ACM
certificate, and an HTTPS listener with a redirect from :80.

### Application

**A single Flask process serves both the UI and the API, on both instances.**
The assignment asks for "a simple frontend and backend running on two EC2 instances". Two identical
instances were chosen over one frontend instance and one backend instance, because identical instances
give real high availability: either one can fail without the service going down. Splitting the roles
would make each instance a single point of failure and leave the load balancer distributing traffic
across a target group of one.

**`/health` does not touch the database.**
If the health check queried RDS, a database outage would mark both instances unhealthy at once, the
ALB would fail open, and the ASG could begin replacing healthy instances in a loop. Instead the
instances stay in service and the outage degrades the service rather than taking it down: a scan
still shows its result, with a notice that it was not saved, and the history page returns a friendly
503 that the 5XX alarm picks up.
*Trade-off:* the health check reports less than the full truth. The database is monitored separately
through its own CloudWatch metrics.

**One database connection per request, no pool.**
Each request opens a connection, with a 5-second connect timeout, and closes it when done. At the
traffic of a demo a pool solves no problem, and pooled connections can go stale across an RDS failover.
*Trade-off:* every database request pays for a new connection, a few milliseconds inside the VPC.
`psycopg_pool` would be a two-line change if the load ever justified it.

**Severity levels before additive scoring.**
Each finding carries a severity. One critical finding (a lookalike sender domain such as `paypa1`, an
executable attachment, a link whose text shows a brand domain but points elsewhere) is enough for a
Phishing verdict on its own. Two high findings reach the same verdict; one high finding guarantees at
least Suspicious. Everything else accumulates toward thresholds of 30 and 60.
*Rationale:* purely additive scoring is too forgiving of a single decisive indicator — a spoofed
domain alone would only reach "Suspicious", which is the wrong answer.
*Trade-off:* the weights and the severity assignments are tuned by hand against the sample corpus
rather than learned from data, which keeps them explainable.

**The engine makes no network calls.**
No reputation APIs, no remote suffix-list downloads. The analysis is deterministic and the demo does
not depend on a third party being up.
*Trade-off:* no reputation data. A reputation lookup would be an optional, configuration-gated feature.

### Observability

**CloudWatch only, no self-hosted monitoring.**
The assignment asks to use managed AWS features rather than self-implementation. ALB, EC2, ASG and
RDS metrics come for free; the CloudWatch agent adds memory, disk and the application log. One
dashboard answers all the monitoring questions, and five alarms notify by email through SNS.
*Trade-off:* less flexible than Prometheus and Grafana, with nothing to operate or secure.

**Structured JSON logs.**
Each request is one JSON line. Logs Insights can then filter and aggregate by field instead of parsing
text.
*Trade-off:* less readable when tailing the file directly on an instance.

**Every resource is tagged, and the log groups are created in Terraform.**
A `default_tags` block tags everything with `Project = phishing-detector`, which is what makes the
post-teardown verification reliable. Creating the log groups explicitly means `terraform destroy`
removes them, rather than leaving orphans behind.

**The 5XX alarms count errors, they do not measure an error rate.**
Each fires at five errors in one minute. With demo-level traffic a percentage swings from 0 to 100 on
a single request, so a rate would be either silent or set off by one failure.
*Trade-off:* a fixed count does not scale with traffic. At production volume these would be error-rate
alarms built with metric math (5XX ÷ `RequestCount`), with a minimum request count.

**The unhealthy-target alarm fires during every deploy, and is left that way.**
A new instance is registered with the target group as soon as it launches, and fails the health check
for the two to three minutes its boot takes. So each replacement sends one ALARM email and one OK
email. The alarm is telling the truth: capacity really is reduced for those minutes. It is kept this
sensitive so that a real failure is reported within two minutes.
*Trade-off:* expected emails on every deployment. The production answer is an Auto Scaling lifecycle
hook that registers an instance only once its boot has finished, or suppressing the alarm while a
deployment runs.

### Cost

Small instance types throughout (`t3.micro`, `db.t4g.micro`). `infra/app` is destroyed at the end of
each working day, so only RDS runs overnight at roughly $0.40/day. An AWS Budget with email alerts was
created manually, outside Terraform, so that it survives `terraform destroy`.

---

## 10. What I would do differently with more time

**Match lookalike domains on visual confusability, not on edit distance.**
The engine flags a sender domain within two edits of a brand's domain. Edit distance counts how many
characters differ, but not whether the result could be mistaken for the brand, so it cannot tell
`payppal.com` from `apply.com`: both are one edit away from a brand. Tightening the threshold does not
help, since real typo-squats and ordinary words sit at the same distances. Today the damage is
contained rather than fixed: a near-spelling is only a high-severity finding, so on its own it yields
Suspicious and not Phishing, and an allowlist clears the common collisions.
The principled fix is a Unicode confusables mapping, such as the one published with Unicode Technical
Standard #39. An edit would count as suspicious only when the characters involved are visually
confusable: `rn` for `m`, `1` for `l`, a Cyrillic `а` (U+0430) for a Latin `a`. Swapping `g` for `o` would count
for nothing, and neither would the letters that separate `chess.com` from `chase.com`. That replaces a
measure of spelling with a measure of what a reader would actually misread, and it would make the
allowlist unnecessary.
*Trade-off:* confusability covers imitation that works on the eye, not squats that rely on a typing
slip. `goggle.com` is one of those, and it would need its own signal, such as keyboard adjacency.

**Verify the database's certificate, not only encrypt the connection.**
On EC2 the application connects with `sslmode=require`: the connection to RDS is encrypted or it is not
made, and RDS for PostgreSQL 16 refuses unencrypted connections on its side as well. What `require`
does not do is check who is at the other end. The production step is `sslmode=verify-full` with the
RDS certificate authority bundle shipped on the instance, so that the client also refuses a server
that cannot prove it is the database.

TODO — the rest is written at the end, once the system is running.
