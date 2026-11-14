# Fish Scan: a phishing email detector on AWS

Fish Scan is a Python service that analyzes an email file, scores it for phishing indicators, and
returns a verdict.
Deployed on AWS with Terraform: a frontend and backend running on two EC2 instances behind an
Application Load Balancer, with scan history stored in RDS PostgreSQL and an optional result cache,
shared by both instances, on ElastiCache (Valkey).

> Status: work in progress. Sections marked TODO are filled in as the project is built.

---

## 1. Overview

Fish Scan takes an email, as an uploaded `.eml` or `.txt` file or pasted as raw text, and says
whether it is Safe, Suspicious or Phishing, with the evidence behind the verdict: links whose text
and target disagree, lookalike sender domains, pressure wording, dangerous attachments. Every scan
is kept in a history, and an email seen before is answered from a shared cache with a count of how
often it has been seen. TODO: the rest of the overview.

The product is called Fish Scan; the repository and every technical identifier keep the original
name, `phishing-detector`: the Terraform resources, the log groups, the dashboard and the `Project`
tag.

## 2. Architecture

TODO — diagram and a short walkthrough of the request path.

**Region:** `eu-north-1` (Stockholm)

**The scan path, with the cache.** An upload is hashed (SHA-256). The instance asks the cache for a
result stored under that hash and the current release, and counts the sighting, in one round trip.
On a hit the stored result is shown and the engine does not run; on a miss the engine runs and its
result is stored for a day. Either way the scan is saved to RDS, marked with whether it came from the
cache. The cache is optional: when it is unreachable, scans carry on exactly as without it.

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

`requirements-dev.txt` pins the development tools, `pytest`, `ruff`, and the scanners `bandit` and
`pip-audit`, and pulls in the runtime
dependencies from `app/requirements.txt`, so that one command sets up everything.

Analyse an email file:

```bash
python detect.py samples/paypal-phish.eml           # human-readable report
python detect.py samples/paypal-phish.eml --json    # the same result as JSON
```

The exit code carries the verdict: `0` Safe, `1` Suspicious, `2` Phishing, `3` if the file could not
be read.

Run the web application. It needs the local PostgreSQL container, which Docker runs from
`docker-compose.yml` together with a local Valkey for the cache:

```bash
echo DB_PASSWORD=localdev> .env         # once; .env is git-ignored, localdev is the database's password
echo CACHE_PASSWORD=localdev>> .env     # once; docker compose reads it for the cache container
docker compose up -d --wait             # PostgreSQL 16 on localhost:5432, Valkey 8.1 on localhost:6379
flask --app app.web run --port 8000     # then open http://127.0.0.1:8000
```

`docker compose` refuses to start until `.env` sets `CACHE_PASSWORD`, rather than run a cache that
accepts anyone. The scans table is created on first use. Without the database container the
application still starts and scans still work; results simply are not saved, and the history page
returns 503. `docker compose down` stops both containers and keeps the database's data.

The cache is off unless `CACHE_HOST` is set, so the application runs without it by default. To use
the local one, add to `.env`:

```bash
CACHE_HOST=localhost
CACHE_TLS=false                         # the local container has no TLS; ElastiCache has only TLS
```

Before every commit:

```bash
ruff format .
ruff check .
pytest -m "not integration"             # needs nothing running
```

The database and cache tests are marked `integration` and run against the containers: the
database tests in a separate `phishing_test` database so the local history is left alone, the
cache tests under keys of their own that they delete afterwards:

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

Four scanners read the code: **checkov** (Terraform), **bandit** (Python), **pip-audit** (pinned
dependencies) and **gitleaks** (every commit). The goal is not zero findings but zero *unexplained*
ones: each is fixed, accepted with its reason written next to the code, or shown to be a false
positive. The full list, with what each check means, the risk, and what production would do, is in
[docs/security-scan.md](docs/security-scan.md).

- **checkov:** 36 findings. 4 fixed (VPC flow logs, and the three about plain HTTP, which went
  when the load balancer got HTTPS), 31 accepted, 1 false positive. Most of the accepted ones
  trace back to three decisions: a stack destroyed daily (so no deletion protection, short log
  retention), a demo-sized database, and a cache that is optional (so one node, and no rotation
  of its token).
- **bandit:** 2 low-severity false positives, both a variable name containing "password" or
  "token". No SQL is built from strings: every statement takes its values as parameters.
- **pip-audit:** no known vulnerabilities in the 29 pinned packages.
- **gitleaks:** nothing in the 10 commits of history.

Fixed in this pass:

- **Security headers on every response:** a content security policy that allows only this
  origin's own files, plus `nosniff`, `no-referrer` and `X-Frame-Options: DENY`. It is the second
  layer behind template escaping: if hostile markup from an email ever got through, the browser
  would still refuse to run it. No `Strict-Transport-Security`, on purpose: see *HTTPS on the
  load balancer*, under *Decisions*.
- **Stored XSS is tested, not assumed:** an email with script and image tags in its subject, sender,
  links and filename is shown escaped on the result and history pages.
- **Rejected traffic is logged:** a VPC flow log records every connection attempt the security
  groups refuse. The saved query `phishing-detector/rejected-traffic` shows who is probing the load
  balancer, and on which ports.
- **`/simulate-error` is behind a switch:** see *Decisions*, below.
- **A pre-push hook runs gitleaks** and blocks a push that contains a secret.

Added afterwards: **HTTPS on the load balancer**, TLS 1.2 and 1.3 only, with port 80 answering
only with a redirect. The certificate is self-signed; see *Decisions*.

The hook lives in the repository, but where Git looks for hooks is local configuration and is not
cloned. Once per clone:

```bash
git config core.hooksPath .githooks
```

It uses `gitleaks` from `PATH`, or `tools/gitleaks.exe`. Without either it warns and lets the push
through.

To run the scans again (checkov has its own virtualenv, so its many pins cannot change the
project's):

```powershell
py -3.12 -m venv .venv-scan; .venv-scan\Scripts\pip install checkov==3.4.5
.venv-scan\Scripts\checkov -d infra --framework terraform --compact --quiet
bandit -r app scripts -q
pip-audit -r app\requirements.txt
gitleaks git . --redact --verbose
```

## 8. Cleanup

TODO — `terraform destroy` and how the teardown was verified.

The order is always `infra/app` first, then `infra/base`: the application stack holds rules on the
database's and the cache's security groups, which belong to the base stack, and reads the base
stack's outputs.

After `terraform destroy` in `infra/app`, these should all return empty lists. The log-group check
covers the application, boot and VPC flow log groups (`/phishing-detector/app`, `/boot` and
`/vpc-flow-rejects`), since all three share the prefix:

```powershell
aws resourcegroupstaggingapi get-resources --profile phishing --tag-filters Key=Stack,Values=app --query "ResourceTagMappingList[].ResourceARN"
aws logs describe-log-groups --profile phishing --log-group-name-prefix /phishing-detector --query "logGroups[].logGroupName"
aws cloudwatch describe-alarms --profile phishing --alarm-name-prefix phishing-detector --query "MetricAlarms[].AlarmName"
aws s3 ls --profile phishing | Select-String phishing-detector
```

After `terraform destroy` in `infra/base` as well, these should return empty lists too. The secret
is deleted at once, with no recovery window, so recreating the stack does not trip over its name:

```powershell
aws elasticache describe-replication-groups --profile phishing --query "ReplicationGroups[?starts_with(ReplicationGroupId, 'phishing-detector')].ReplicationGroupId"
aws secretsmanager list-secrets --profile phishing --include-planned-deletion --query "SecretList[?starts_with(Name, 'phishing-detector-cache')].Name"
aws resourcegroupstaggingapi get-resources --profile phishing --tag-filters Key=Project,Values=phishing-detector --query "ResourceTagMappingList[].ResourceARN"
```

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

**EC2 instances in private subnets, egress through a NAT gateway in each availability zone.**
The instances have no public IP and sit in private subnets with no route from the internet. The only
inbound path is from the load balancer's security group, on port 8000. There are no network ACLs
beyond the default. Outbound, each private subnet's route table points at the NAT gateway in its own
zone. If a zone fails, the instance in the other zone keeps its way out: it still reaches S3, Secrets
Manager, CloudWatch and Session Manager, and a replacement instance can still boot. The project
started with one gateway for both zones, to save cost; an availability review found that the
surviving instance would then have kept serving but could not have healed (see `BUILD_LOG.md`).
*Trade-off:* each NAT gateway costs roughly $1.10/day, plus about $0.12/day for its public address,
while the stack runs. What is still in one zone is the database: RDS is single-AZ, because Multi-AZ
doubles its cost and provisioning time, and a database outage degrades the service rather than
stopping it (see the RDS entry below).

**NAT gateways rather than VPC endpoints.**
In production the instances would reach AWS services through VPC endpoints instead: interface endpoints
for Session Manager, Secrets Manager, CloudWatch Logs and CloudWatch metrics, and a gateway endpoint for
S3. That traffic would then never leave the AWS network, and the instances would need no route to the
internet at all, which is the more secure pattern.
*Trade-off:* interface endpoints are billed per endpoint, per availability zone, per hour, and the
handful this project needs, in two zones, costs at least as much as the two NAT gateways. They would
also not remove the gateways: the instances install their Python dependencies from PyPI at boot, which
no endpoint reaches. For a four-day project the NAT gateways are the simpler way to the same working
system.

**Auto Scaling Group with min = max = desired = 2, one instance per AZ, `health_check_type = "ELB"`.**
This gives self-healing with no code: a failing instance is replaced automatically, which can be
demonstrated live by terminating one.
*Trade-off:* harder to debug than two fixed `aws_instance` resources, since a broken instance is
replaced before it can be inspected. During development the health check type is set to `EC2` so
instances survive long enough to investigate.

**Chained security groups.**
`alb-sg` accepts :443 from the internet, and :80 only to redirect to it. `app-sg` accepts :8000 only
from `alb-sg`. `db-sg` accepts
:5432 only from `app-sg`. No security group admits traffic from a CIDR range except the load balancer's
listener, and port 22 is not open anywhere. Outbound, the instances are allowed :443 to the internet,
which is required for the AWS APIs and the package repositories.

**RDS PostgreSQL, `db.t4g.micro`, single-AZ, encrypted, not publicly accessible.**
*Trade-off:* the database is a single point of failure, while the application tier is spread across two
AZs. Multi-AZ doubles the cost and the provisioning time, which is not justified for a four-day
exercise. The failure mode is understood and handled: the health check does not touch the database,
so a database outage degrades the service rather than taking it down.

**A result cache on ElastiCache (Valkey 8.2), one node, in `infra/base`.**
The cache is shared by both instances, which is why it is a network service and not a dictionary in
each process: a request can land on either instance, and each has its own memory. It does two things.
The same email scanned again (many people forward the same phishing email to security) is answered
from the cache instead of being analysed again. And every scan increments a counter per email, shared
by both instances and expiring a day after the first sighting, so the result can say "Seen 14 times in
the last 24 hours": phishing arrives in campaigns, and that count is information for an analyst. Every
scan is still saved to the history, marked when it came from the cache.
- **What it does not give today is much speed, and the numbers say so.** The engine is offline and
  fast: on the 15 sample files it takes 3.5 ms on average and 18 ms at most (750 runs on a development
  machine). Most of a request is the network and the database write, which a hit still makes. Run
  locally against the Valkey container, 100 scans of the samples gave an average of 13.0 ms in the
  engine on a miss and 3.9 ms in the cache lookup on a hit, and the whole request took 57 ms on a
  miss and 55 ms on a hit: about 2 ms, or 4 percent, saved. The figures from AWS come from the saved
  query `phishing-detector/cache-hit-ratio`. TODO: record them here after the deploy. The saving
  becomes real the day the engine does something slow, such as a reputation lookup or opening an
  attachment in a sandbox; nothing else would need to change.
- **Valkey 8.2**, the newest 8.x that ElastiCache offers in `eu-north-1` (7.2, 8.0, 8.1, 8.2, 9.0
  and 9.1 are offered). Chosen over 9.x because the 9 series is newer than the client library,
  redis-py, has been widely used against. The local container runs Valkey 8.1: 8.2 is an ElastiCache
  release, with no open-source image, and 8.1 is the closest.
- **The release is part of the key.** Any deploy changes the release, so nothing computed by an older
  version of the code is ever served; old entries simply expire. A stale verdict from a security tool
  is worse than a recomputed one.
- **Nothing is stored that the history does not already hold:** verdict, score, findings, sender and
  subject. The email body and attachments are never stored. The file name and `served_by` always come
  from the current request. A cached value is checked when it is read, and one that does not have the
  expected fields and types is deleted and treated as a miss.
- **It fails open.** A cache that does not answer within half a second is skipped, and after a failure
  each process leaves it alone for 30 seconds, logging one `cache_unavailable` warning rather than one
  per request. If its token cannot be fetched, the cache is left alone for five minutes. `/health` does
  not touch it, for the same reason it does not touch the database.
- **One node, no replica, no failover, no snapshots.** Unlike the database, losing the cache costs
  nothing but time: scans carry on, slower by a few milliseconds, and its contents are recomputed as
  scans come in. A replica in a second zone would double the cost of a component nothing depends on.
  The database is single-zone for a different reason: cost, although losing it does cost something.
- **The counter reveals that the same email was scanned before.** There are no accounts and the
  history is already public, so nothing new is exposed; with accounts, the count would be kept per
  organisation.

*Trade-off:* about $0.30 to $0.50 a day more for `infra/base` (see *Cost*), and a ten-minute create
when `infra/base` is applied, for a speed gain that is small today. The same cluster could carry a
per-address rate limit on uploads, the same mechanism as the sighting counter keyed by client
address; it is not built.

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
required (not optional) on the launch template. Nothing in the repository contains a key: `gitleaks`
found nothing in the history, and a pre-push hook runs it again before every push, once it is turned
on (see *Security*).

**The database password is never written down.**
RDS generates and rotates it (`manage_master_user_password = true`) and stores it in Secrets Manager.
The application reads it at startup and re-reads it if authentication fails, so rotation does not
require a redeploy. The password does not appear in Terraform variables, in state, or on the instance.

**The cache is encrypted in transit and at rest, and needs an AUTH token.**
TLS keeps the token and the results off the network in the clear, and the client verifies the
server's certificate and name; the token means that reaching the port is not enough to read the data.
Only the instances' security group may reach the port. Terraform generates the token and keeps it in
Secrets Manager; the instances read it with their role, on the first scan rather than at startup, and
the environment file holds only the secret's ARN.
*Trade-off:* the token is in `infra/base`'s Terraform state, which is local and git-ignored: the same
accepted demo trade-off as the self-signed certificate's key. It is not rotated, since rotating it
needs a coordinated change to the cluster and every instance. Production would use ElastiCache's IAM
authentication, where the application signs a short-lived token with its role and no long-lived secret
exists at all.

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

**HTTPS on the load balancer, with a self-signed certificate.**
The load balancer answers HTTPS on :443, with TLS 1.2 and 1.3 only, and :80 answers every request
with a 301 redirect to it. TLS ends at the load balancer: from there to the instances the traffic is
plain HTTP on :8000 inside the VPC, as before, so one place holds the certificate and the instances
did not change. There is no domain for this exercise, so no authority will issue a certificate.
Terraform generates a self-signed one, naming the load balancer's DNS name, and imports it into ACM.
The encryption is the same as with a trusted certificate; what is missing is proof of identity. So a
browser warns before showing the site (Advanced, then Continue), `curl` needs `-k`, and
`scripts/load.py` needs `--insecure`.
*Trade-offs:*
- **The certificate's private key is stored in Terraform state.** State is local and git-ignored, so
  the key never reaches git, but this is a demo trade-off. In production the certificate is issued by
  ACM against a real domain, and its private key never leaves AWS.
- **No `Strict-Transport-Security` header.** With a self-signed certificate, HSTS would make browsers
  refuse the site instead of letting the user click through the warning. With a real certificate,
  HSTS would be added.
- **A redirected POST becomes a GET.** Anything that uploads must be given the `https://` address
  (`terraform output -raw alb_url`); an upload posted to :80 is redirected and uploads nothing.

With a domain, this would be a Route 53 record and an ACM-issued certificate on the same two
listeners.

**Scans are viewable by id without authentication** (`/scans/<id>`), which is no new exposure because
`/history` already lists every scan publicly; a production deployment would require sign-in for both.

### Application

**A single Flask process serves both the UI and the API, on both instances.**
The assignment asks for "a simple frontend and backend running on two EC2 instances". Two identical
instances were chosen over one frontend instance and one backend instance, because identical instances
give real high availability: either one can fail without the service going down. Splitting the roles
would make each instance a single point of failure and leave the load balancer distributing traffic
across a target group of one.

**`/health` does not touch the database, or the cache.**
If the health check queried RDS, a database outage would mark both instances unhealthy at once, the
ALB would fail open, and the ASG could begin replacing healthy instances in a loop. Instead the
instances stay in service and the outage degrades the service rather than taking it down: a scan
still shows its result, with a notice that it was not saved, and the history page returns a friendly
503 that the 5XX alarm picks up.
*Trade-off:* the health check reports less than the full truth. The database is monitored separately
through its own CloudWatch metrics.
A shallow health check is not enough on its own, so a circuit breaker in `app/db.py` backs it: once a
connection to the database fails, each process stops trying for 15 seconds and every database call
fails at once, so requests cannot pile up behind the 3-second connect timeout, occupy both gunicorn
workers, and starve the load balancer's health check into replacing healthy instances. The production
alternative is threaded or asynchronous workers, so that a slow dependency cannot starve the health
check at all.

**One database connection per request, no pool.**
Each request opens a connection, with a 3-second connect timeout, and closes it when done. At the
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

**`/simulate-error` exists for the demo, behind a switch.**
The route answers with a deliberate 500, so that the 5XX alarm can be shown firing. Anyone who can
reach it can fire that alarm, so it is off by default: unless `ENABLE_ERROR_SIMULATION` is `true`, it
answers 404, exactly like an address that does not exist. `infra/app` switches it on for the review
(`enable_error_simulation`, default `true`). A production deployment would not have the route at all.
*Trade-off:* while the review stack runs, anyone can still fire the alarm; it is one variable to
turn off.

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

Small instance types throughout (`t3.micro`, `db.t4g.micro`, `cache.t4g.micro`). `infra/app` is
destroyed at the end of each working day, so only `infra/base` runs overnight: RDS at roughly
$0.40/day, and the cache node, like RDS, around the clock. The design estimate for the node is $0.40
to $0.50 a day; ElastiCache prices Valkey nodes about 20 percent below Redis OSS ones, so it is likely
nearer the bottom of that. TODO: confirm the `eu-north-1` price in the console. The cache's secret
adds about $0.40 a month. An AWS Budget with email alerts was created manually, outside Terraform, so
that it survives `terraform destroy`.

While `infra/app` runs:

| | per day |
|---|---|
| 2 NAT gateways, one per zone | ~$2.20 |
| Load balancer | ~$0.60 |
| 2 × t3.micro | ~$0.50 |
| Public IPv4 addresses (two NAT gateways, two load balancer nodes) | ~$0.47 |
| **`infra/app`, running** | **~$3.77** |

The second NAT gateway and its address are about $1.22 of that: the price of each zone having its own
way out. The certificate costs nothing.

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

**Install dependencies by hash, not only by version.**
`app/requirements.txt` pins every package, the dependencies' own dependencies included, so every
instance installs the same versions. It does not pin the files: pip checks no hash, so a tampered
file on the index would be installed at boot. The fix is a lock file with hashes
(`pip-compile --generate-hashes`), installed with `--require-hashes`, or an image with the
dependencies already in it.

**Small changes to the database stack, left alone during the hardening pass.**
`infra/base` was not modified in phase 7, because a change there can modify or restart RDS. Two
cheap ones are worth making at the next planned apply: copying tags to snapshots, and setting
`auto_minor_version_upgrade = true` explicitly so the scanner stops reporting a default it cannot
see. Exporting the PostgreSQL log to CloudWatch would follow.

TODO — the rest is written at the end, once the system is running.
