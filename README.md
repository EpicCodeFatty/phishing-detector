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

TODO

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

**EC2 instances in private subnets, egress through a NAT Gateway.**
The instances have no public IP. Inbound traffic reaches them only from the load balancer's security
group; everything else is denied at the subnet level, not just by a security group rule.
*Trade-off:* a NAT Gateway costs roughly $1.10/day. A single NAT (in one AZ) is used rather than one
per AZ: if that AZ fails, the instance in the other AZ still serves traffic through the ALB but cannot
reach S3, Secrets Manager or CloudWatch, and a replacement instance cannot boot. In production this
would be one NAT per AZ.

**Auto Scaling Group with min = max = desired = 2, one instance per AZ, `health_check_type = "ELB"`.**
This gives self-healing with no code: a failing instance is replaced automatically, which can be
demonstrated live by terminating one.
*Trade-off:* harder to debug than two fixed `aws_instance` resources, since a broken instance is
replaced before it can be inspected. During development the health check type is set to `EC2` so
instances survive long enough to investigate.

**Chained security groups.**
`alb-sg` accepts :80 from the internet. `app-sg` accepts :8000 only from `alb-sg`. `db-sg` accepts
:5432 only from `app-sg`. No security group references a CIDR range except the ALB's public ingress,
and port 22 is not open anywhere.

**RDS PostgreSQL, `db.t4g.micro`, single-AZ, encrypted, not publicly accessible.**
*Trade-off:* the database is a single point of failure, while the application tier is spread across two
AZs. Multi-AZ doubles the cost and the provisioning time, which is not justified for a four-day
exercise. The failure mode is understood and handled: the health check does not touch the database,
so a database outage degrades the service rather than taking it down.

**Application code is delivered through S3.**
Terraform packages `app/` into a versioned zip, uploads it to a private bucket, and the instance's
`user_data` downloads it at boot. The instance role is allowed `s3:GetObject` on that key only.
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
database failure surfaces as a 5XX alarm and a friendly error on the scan page, while the instances
stay in service.
*Trade-off:* the health check reports less than the full truth. The database is monitored separately
through its own CloudWatch metrics.

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

**Every resource is tagged, and the log group is created in Terraform.**
A `default_tags` block tags everything with `Project = phishing-detector`, which is what makes the
post-teardown verification reliable. Creating the log group explicitly means `terraform destroy`
removes it, rather than leaving an orphan behind.

### Cost

Small instance types throughout (`t3.micro`, `db.t4g.micro`). `infra/app` is destroyed at the end of
each working day, so only RDS runs overnight at roughly $0.40/day. An AWS Budget with email alerts was
created manually, outside Terraform, so that it survives `terraform destroy`.

---

## 10. What I would do differently with more time

TODO — written at the end, once the system is running.
