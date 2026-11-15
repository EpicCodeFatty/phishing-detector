# Security scan: phase 7

Every finding from four scanners, and what was done with it: **fixed**, **accepted** with a reason,
or a **false positive**. The aim is zero *unexplained* findings, not zero findings. Each accepted
finding also carries its reason in the code, on the line or resource it concerns.

## 1. Tools and versions

Run on 13 November 2026, on Windows 10, against commit `d65fa80` plus the phase 7 changes.

| Tool | Version | Scans | Command |
|---|---|---|---|
| checkov | 3.4.5 (own virtualenv, `.venv-scan/`) | `infra/`, both stacks | `.venv-scan\Scripts\checkov -d infra --framework terraform --compact --quiet` |
| bandit | 1.9.4 | `app/`, `scripts/` | `bandit -r app scripts -q` |
| pip-audit | 2.10.1 | `app/requirements.txt` | `pip-audit -r app\requirements.txt` |
| gitleaks | 8.30.1 | every commit (10) and the working tree | `gitleaks git . --redact --verbose` |
| ruff | 0.17.5 | Python style and lint | `ruff check .` |

Also used: Terraform 1.17.1, Python 3.12.10.

**Updated on 14 November 2026**, on the branch `feature/https-nat`: the load balancer got an
HTTPS listener with a self-signed certificate, port 80 became a redirect, and each availability
zone got its own NAT gateway (`docs/design/bonus-https-nat-design.md`). checkov and bandit were run
again with the same versions and commands; the checkov figures below are from that run. pip-audit
and gitleaks were not run again, and their figures are from 13 November.

**Updated again on 14 November 2026**, on the branch `feature/cache`: a result cache on
ElastiCache (Valkey 8.2) in `infra/base`, with its AUTH token in Secrets Manager, the rules and a
third inline policy in `infra/app`, and the `redis` client library in the application
(`docs/design/bonus-cache-design.md`). checkov, bandit and pip-audit were run again with the same versions
and commands; the figures below are from that run. gitleaks was not run again.

- **gitleaks** was installed with `winget install Gitleaks.Gitleaks`. winget checks the download
  against its manifest's SHA-256, and that hash
  (`d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`) was compared with the
  release's own `gitleaks_8.30.1_checksums.txt` on GitHub: they match.
- **bandit excludes `tests/`** by not being given it on the command line: assertions and fake
  passwords in tests are not a vulnerability.
- **No check is skipped on the command line.** Every skip is inline, one per check ID, with its reason.

## 2. Summary

| Tool | Findings | Fixed | Accepted | False positive | Left unexplained |
|---|---|---|---|---|---|
| checkov | 36 | 4 | 31 | 1 | 0 |
| bandit | 2 (both low severity) | 0 | 0 | 2 | 0 |
| pip-audit | 0 known vulnerabilities in 29 pinned packages | 0 | 0 | 0 | 0 |
| gitleaks | 0 in 10 commits, 0 in the working tree | 0 | 0 | 0 | 0 |

The 32 are the findings of the phase 7 run, on 13 November. Three of them, all about plain
HTTP, were accepted then and are fixed now that the load balancer has HTTPS (section 3); their
skips are gone and the checks pass. Of the fixed findings, the VPC flow log is still reported in
`infra/base`, because checkov reads one stack at a time and cannot see the flow log defined in
`infra/app`. It is skipped there with that reason. The new resources (certificate, HTTPS
listener, second NAT gateway and address, port 443 rule) produced no new finding. After the
inline skips, checkov reported **196 passed, 0 failed, 29 skipped**: 27 accepted, the false
positive, and the flow log in `infra/base`.

The cache added four findings, all accepted (section 4, *Cache*): two on the replication group and
two on its secret. Its other checks pass: encryption at rest, encryption in transit, and an AUTH
token. The two 6379 rules and the third inline policy in `infra/app` produced no finding. After the
inline skips, checkov reports **226 passed, 0 failed, 33 skipped**: 31 accepted, the false
positive, and the flow log in `infra/base`. bandit still exits 0 with the two `# nosec` lines, and
pip-audit finds no known vulnerability in the 29 pins, `redis==8.1.0` among them.

Both bandit findings are false positives (section 5), each marked `# nosec B105` on its line with
the reason. After that, bandit reports no issues and exits with code 0.

**IAM Access Analyzer** (`docs/design/hardening-phase7-design.md`, section 5) was not run here; the owner
runs it against the live account:

- `read-release`: *result to be recorded*
- `read-db-secret`: *result to be recorded*
- `read-cache-secret`: *result to be recorded*
- `deliver-flow-logs` (on role `phishing-detector-flow-logs`): *result to be recorded*

## 3. Fixed

- **No VPC flow log** (checkov `CKV2_AWS_11`): rejected traffic is now logged to
  `/phishing-detector/vpc-flow-rejects`, with a least-privilege delivery role, and the saved query
  `phishing-detector/rejected-traffic` shows it. `infra/app/flowlogs.tf`.
- **No security headers**: every response now carries `Content-Security-Policy`,
  `X-Content-Type-Options`, `Referrer-Policy` and `X-Frame-Options`. `app/web.py`. The templates
  needed no change: none had inline script or style.
- **`/simulate-error` open to anyone**: now a 404 unless `ENABLE_ERROR_SIMULATION` is on. Off by
  default in the application; switched on by the `enable_error_simulation` variable in `infra/app`
  for the demo. `app/config.py`, `app/web.py`, `infra/app/variables.tf`, `deploy/user_data.sh.tftpl`.
  `scripts/load.py --errors` reports a 404 as the switch being off.
- **The README claimed `gitleaks` runs before every push; nothing ran it**: `.githooks/pre-push`
  now does, and blocks the push on a finding. `git config core.hooksPath .githooks` turns it on.
- **Stored XSS, checked rather than assumed**: an email with markup in its subject, sender, link
  text and link target, uploaded under a hostile filename, is rendered escaped on the result and
  history pages. Nothing needed fixing; the test now proves it. `tests/fixtures/xss-subject.eml`,
  `tests/test_web.py`.
- **Instance timers tuned to the measured boot** (118 s): health-check grace period 180 s, refresh
  warm-up 240 s. `infra/app/variables.tf`.

Fixed on 14 November, with HTTPS (`infra/app/alb.tf`, `tls.tf`, `security.tf`). All three were
accepted in phase 7 for want of a certificate:

- **The listener was HTTP** (checkov `CKV_AWS_2`): the load balancer now answers HTTPS on 443.
  The check is that traffic between the user and the load balancer is encrypted; the risk was
  that anyone on the network path could read or alter uploads and results.
- **No TLS policy** (checkov `CKV_AWS_103`): the HTTPS listener uses
  `ELBSecurityPolicy-TLS13-1-2-2021-06`, which offers TLS 1.3 and 1.2 and nothing older.
- **No redirect from HTTP to HTTPS** (checkov `CKV2_AWS_20`): the listener on port 80 now answers
  every request with a 301 to port 443.

What the scanner does not see: the certificate is self-signed, because there is no domain. The
encryption is real, the proof of identity is not, and a browser says so. The certificate's
private key is in Terraform state, which is local and git-ignored. Production would use a
certificate issued by ACM for a real domain, whose key never leaves AWS, and would add
`Strict-Transport-Security`, which is left out here because with a self-signed certificate it
would lock browsers out (README, Decisions).

## 4. Accepted

One entry per finding: **the check**, **the risk** if it went wrong, **why it stays here**, and
**what production would do**.

### Load balancer (`infra/app/alb.tf`)

**`CKV_AWS_91`: no access logs.**
- Check: the load balancer should log every request.
- Risk: after an incident there is no record of who sent what at the edge.
- Why here: it needs an S3 bucket with an ELB delivery policy. The ALB metrics and the application's
  own one-line-per-request log already answer this project's questions.
- Production: access logs to a dedicated bucket with a retention policy.

**`CKV_AWS_150`: deletion protection is off.**
- Check: the load balancer should not be deletable by a single API call.
- Risk: an accidental `destroy` takes the service down.
- Why here: the stack is destroyed at the end of every working session, by design.
- Production: on.

**`CKV2_AWS_28`: no WAF.**
- Check: a public load balancer should sit behind a web application firewall.
- Risk: common attacks (injection patterns, floods from one address) reach the application.
- Why here: a WAF costs about $5 a month plus a charge per rule, and the application already caps
  uploads at 5 MB and treats every input as hostile.
- Production: AWS WAF with the managed core rule set and a rate-based rule.

**`CKV_AWS_378`: the target group uses HTTP.**
- Check: traffic from the load balancer to the instances should be encrypted too.
- Risk: someone already inside the VPC could read it.
- Why here: that traffic never leaves the VPC, and the instances admit port 8000 only from the
  load balancer's security group. Encrypting it means certificates on every instance. TLS ends
  at the load balancer, which now has it.
- Production: usually the same, TLS ending at the load balancer. End-to-end TLS only where a
  compliance regime requires it.

### Network (`infra/app/security.tf`, `infra/base/network.tf`)

**`CKV_AWS_260`: port 80 is open to `0.0.0.0/0`.**
- Check: no security group should admit the whole internet on port 80.
- Risk: anyone can reach the service and probe it. The flow log shows that they do.
- Why here: it is a public web service, and port 80 now only answers with a redirect to HTTPS, so
  that an address typed without `https://` still arrives. Port 443 is open to the same ranges;
  checkov has no finding for that. The `allowed_ingress_cidrs` variable narrows both without
  editing the rules.
- Production: the same for a public service, behind a WAF. Narrowed for an internal one.

**`CKV_AWS_394`: the availability-zone lookup does not pin zone IDs.**
- Check: the list of zones should not grow by itself when AWS adds one.
- Risk: a new zone could change subnet placement, and so replace subnets.
- Why here: only the first two zone names, in sorted order, are used, so a zone added later is never
  picked up. Changing this in `infra/base` could replace the subnets and the database's subnet
  group, which this phase must not do.
- Production: pin zone IDs (`use1-az1`), which are the same in every account.

### Database (`infra/base/rds.tf`)

None of these are changed in this phase: any of them can modify or restart RDS. They are listed for
the owner to decide.

**`CKV_AWS_157`: not Multi-AZ.**
- Check: a standby copy in a second zone.
- Risk: losing the database's zone stops scan history until it recovers.
- Why here: it doubles the cost and the provisioning time. `/health` does not touch the database,
  so an outage degrades the service (scans still work, history returns 503) rather than stopping it.
- Production: Multi-AZ.

**`CKV_AWS_161`: no IAM database authentication.**
- Check: log in with short-lived IAM tokens rather than a password.
- Risk: a stolen password works from anywhere that can reach the database.
- Why here: the password is generated, rotated and kept by AWS in Secrets Manager, and read only
  with the instance role. IAM authentication needs application changes (a token per connection)
  and a modify of the database.
- Production: IAM authentication, or keep Secrets Manager with rotation, as here.

**`CKV_AWS_118`: no enhanced monitoring.**
- Check: OS-level metrics from the database host, every few seconds.
- Risk: a slow database is harder to diagnose.
- Why here: it needs a monitoring role and bills log ingestion. The standard RDS metrics are
  enough for one demo table.
- Production: on, at a 60-second interval.

**`CKV_AWS_353`: no Performance Insights.**
- Check: a record of which queries use the database's time.
- Risk: query performance problems are harder to find.
- Why here: it cannot be turned on. The RDS API rejected Performance Insights for `db.t4g.micro`
  when the database was created in phase 3 (`BUILD_LOG.md`, entry of 12 November 2026, "RDS
  rejected Performance Insights for `db.t4g.micro`"). It would also add little: it diagnoses real
  query load, and this database stores one row per scan at demo traffic.
- Production: CloudWatch Database Insights, its successor.

**`CKV_AWS_293`: deletion protection is off.**
- Check: the database cannot be deleted by one call.
- Risk: an accidental `destroy` deletes the scan history.
- Why here: the assignment requires destroying the system and verifying the teardown.
- Production: on, with a final snapshot.

**`CKV_AWS_129`: no log exports to CloudWatch.**
- Check: PostgreSQL's logs should go to CloudWatch Logs.
- Risk: failed logins and errors on the database side are not searchable.
- Why here: changing it modifies the database, which this phase does not touch. The application
  logs every database failure with its error type.
- Production: export the `postgresql` log.

**`CKV2_AWS_30`: no query logging.**
- Check: a parameter group that logs statements.
- Risk: no record of what was run against the database.
- Why here: it needs a custom parameter group and a reboot, out of scope for a demo database.
- Production: a parameter group with `log_min_duration_statement` set, and statement logging
  where an audit trail is required.

**`CKV2_AWS_60`: tags are not copied to snapshots.**
- Check: automated snapshots should carry the database's tags.
- Risk: snapshots escape a tag-based teardown check or cost report.
- Why here: it is cheap and harmless, but it is a change to RDS, and `infra/base` takes comments
  only in this phase. **Worth turning on** (`copy_tags_to_snapshot = true`) when the owner next
  applies `infra/base`.
- Production: on.

### Storage (`infra/app/artifact.tf`)

The bucket holds only release zips, rebuilt from git in seconds, read by one role. That is the
reason behind each of these.

**`CKV_AWS_18`: no access logging.**
- Check: every request to the bucket is logged. Risk: no record of who read an object.
- Why here: it needs a second bucket, to log reads of code that is in git anyway. Production:
  access logs, or CloudTrail data events, for buckets holding data.

**`CKV_AWS_21`: no versioning.**
- Check: overwritten or deleted objects can be recovered. Risk: a release is lost.
- Why here: every release has its own key and is never overwritten, so versions would only copy
  each object. Production: on for any bucket whose objects are not rebuildable.

**`CKV_AWS_144`: no cross-region replication.**
- Check: a copy in another region. Risk: losing the region loses the objects.
- Why here: nothing to protect; the zips are rebuilt from git. Production: for data that cannot be
  rebuilt.

**`CKV_AWS_145`: SSE-S3, not KMS.**
- Check: encryption with a customer-managed key. Risk: no separate key policy controls decryption.
- Why here: the objects are encrypted at rest either way; a key adds a monthly fee and a policy to
  protect code that is in git anyway. Production: KMS where key-level access control or audit is required.

**`CKV2_AWS_61`: no lifecycle configuration.**
- Check: old objects expire. Risk: storage grows forever.
- Why here: Terraform deletes each superseded release itself, and the bucket is destroyed daily.
  Production: a rule expiring old releases and aborting incomplete uploads.

**`CKV2_AWS_62`: no event notifications.**
- Check: object events go somewhere. Risk: no trigger to react to unexpected writes.
- Why here: nothing consumes them; the instances are told the exact key. Production: only if
  something reacts to uploads.

### Logging and notifications (`infra/app/logs.tf`, `flowlogs.tf`, `infra/base/sns.tf`)

**`CKV_AWS_158`: log groups not encrypted with KMS** (`app`, `boot`, `vpc-flow-rejects`).
- Check: a customer-managed key. Risk: no key policy separates who can read the logs.
- Why here: CloudWatch Logs encrypts at rest by default; a key adds a policy and a monthly fee. No
  log line contains a secret (tested). Production: a key per sensitive log group.

**`CKV_AWS_338`: retention under one year** (7 days for `app` and `boot`, 3 for the flow log).
- Check: logs kept a year. Risk: an incident discovered late cannot be investigated.
- Why here: a cost decision for a four-day project whose stack is destroyed daily. Production: set
  by the retention policy, often a year or more, with older data archived to S3.

**`CKV_AWS_26`: the SNS topic is not encrypted.**
- Check: messages encrypted at rest. Risk: alarm text readable by whoever reads the topic's storage.
- Why here: CloudWatch alarms cannot publish to a topic encrypted with the AWS-managed SNS key,
  because its key policy cannot be edited to admit CloudWatch. A customer-managed key with a key
  policy for CloudWatch would be needed, at a monthly fee, to protect alarm text that holds no
  secrets. Production: that key.

### Cache (`infra/base/cache.tf`)

The cache is optional by design: when it is gone, scans carry on without it, slower by a few
milliseconds, and everything in it is recomputed as scans come in. That is the reason behind each
of these.

**`CKV2_AWS_50`: no Multi-AZ automatic failover.**
- Check: a replica in a second zone takes over if the primary fails.
- Risk: losing the node or its zone empties the cache until it is replaced.
- Why here: one node, on purpose. Nothing depends on the cache, so a replica would double the cost
  of a component whose failure costs only time.
- Production: a replica in a second zone with automatic failover, once something depends on the
  cache, such as a rate limit.

**`CKV_AWS_191`: encrypted at rest with the AWS-managed key, not a customer-managed one.**
- Check: a customer-managed KMS key, whose key policy controls decryption.
- Risk: no separate key policy limits who can decrypt the data at rest.
- Why here: the data is encrypted at rest either way, and holds only what the scan history already
  holds; a key adds a key policy and a monthly fee.
- Production: a customer-managed key where key-level access control or audit is required.

**`CKV2_AWS_57`: the AUTH token is not rotated.**
- Check: secrets rotate automatically.
- Risk: a token that leaks stays valid until someone changes it.
- Why here: rotating it means changing the token on the cluster and on every instance in step,
  which needs a rotation function and a coordinated deploy, for a cache that is reachable only from
  the instances' security group. The token is also in `infra/base`'s Terraform state, which is
  local and git-ignored.
- Production: IAM authentication for ElastiCache, where the application signs a short-lived token
  with its role and there is no long-lived secret to rotate.

**`CKV_AWS_149`: the secret is encrypted with the AWS-managed key, not a customer-managed one.**
- Check: a customer-managed KMS key for the secret.
- Risk: no separate key policy limits who can decrypt the secret.
- Why here: reading it already needs `secretsmanager:GetSecretValue` on its exact ARN, which only the
  instance role has; a key adds a key policy and a monthly fee. The same as the RDS-managed secret.
- Production: a customer-managed key where key-level access control or audit is required.

### Dependencies (`app/requirements.txt`)

**No hashes.** Not a scanner finding, recorded on purpose.
- What it means: `requirements.txt` pins every package, the dependencies' own dependencies
  included. That was checked: pip resolves exactly the 29 pinned versions and nothing else. So two
  instances launched a week apart install the same versions; the phase 7 spec's worry about drift
  does not apply. What it does not do is pin the *files*: pip checks no hash.
- Risk: a tampered package file on the index or a mirror would be installed at boot.
- Why accepted: PyPI never lets a published file be replaced, and pip fetches it over TLS.
- Production: a lock file with hashes (`pip-compile --generate-hashes`), installed with
  `--require-hashes`, or a pre-built image with dependencies baked in.

### Expected but not reported

The phase 7 spec expected three more findings that checkov 3.4.5 did not report. They are still
deliberate, and recorded here:

- **EC2 detailed monitoring is off.** Five-minute data is enough; one-minute data costs about $2
  per instance per month.
- **AWS-managed policies on the instance role** (`AmazonSSMManagedInstanceCore`,
  `CloudWatchAgentServerPolicy`). They are the documented requirements of the two agents; the narrow
  permissions are hand-written against exact ARNs.
- **Egress on 443 to `0.0.0.0/0`.** PyPI, the dnf mirrors and the AWS APIs have no fixed addresses.
  VPC endpoints are the production answer (README, Decisions).

## 5. False positives

**checkov `CKV_AWS_226`: "DB instance gets all minor upgrades automatically."** The resource does
not set `auto_minor_version_upgrade`, and the provider's default is `true`, so minor upgrades are on.
The check reads the code, not the default. Skipped inline in `infra/base/rds.tf`. Setting it
explicitly would end the noise; that is a change to `infra/base`, left to the owner.

**bandit `B105` in `app/config.py:57`**: `SECRET_PASSWORD_KEY = "password"`. The name of the key
RDS stores the password under, in its JSON secret, not a password. `# nosec B105` on the line.

**bandit `B105` in `app/detector/lists.py:179`**: `DOMAIN_TOKEN_DELIMITERS = "-._"`. Bandit
matches the word "token" in the name. These are the characters that split a domain into words.
`# nosec B105` on the line: a comment only, the engine's code is unchanged.

## 6. Not covered

What these tools do not check, so a clean report does not claim it:

- **Runtime behaviour.** Static analysis reads code and configuration. It does not see what the
  running service does, how it behaves under load, or whether a header actually reaches a browser.
  That is checked by the tests and by `curl -skI` against the deployed service (`-k`: the
  certificate is self-signed).
- **The AWS account outside Terraform.** The root user, MFA, other IAM users, CloudTrail, the
  budget, and service control policies from the project-based sign-up are not in the code, so no
  scanner here sees them.
- **What the IAM policies allow in practice.** checkov checks policy shape. IAM Access Analyzer
  (section 2) validates the deployed policies against AWS's own rules.
- **Dependencies beyond the pins.** pip-audit checks the 29 pinned versions against published
  advisories. It does not check the system packages the boot installs with `dnf` (Python, the
  CloudWatch agent), the Amazon Linux image, or a vulnerability not yet published.
- **The application's logic.** Bandit finds dangerous patterns, not wrong decisions; the engine's
  verdicts are covered by its own tests.
