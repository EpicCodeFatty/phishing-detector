# Phase 7: hardening and quality checks

The system works and is monitored. This phase checks it the way a reviewer would: automated scanners
over the Terraform, the Python code, the dependencies and the git history; a few small fixes where a
finding is real and cheap; and a written reason for every finding that is accepted.

The goal is not a scanner report with zero findings. It is **zero unexplained findings**: everything a
scanner flags is either fixed or accepted on purpose, with the reason next to the code and in the
README.

Read `docs/code-standards.md` and the phase 4–6 design documents first.

**Do not run `terraform plan` or `apply`.** Scanners read files only. Stop after the fixes, the
scans and the write-up.

### Two rules for this phase

1. **`infra/base` gets comments only.** The base stack holds the database and is never destroyed
   before the review. A "fix" there (a parameter group, logging exports, IAM authentication) can
   modify or restart RDS. In `infra/base`, the only permitted change is an inline skip comment with a
   reason. Anything in base that looks worth changing goes into the report for the owner to decide.
2. **In `infra/app`, no change beyond section 2 that replaces a resource.** A finding whose fix would
   recreate the load balancer, the security groups or the Auto Scaling Group is accepted with a reason
   or reported, not fixed tonight.

### The ideas behind the checks

Kept here so the phase can be explained as well as run.

| Term | In one sentence |
|---|---|
| Static analysis | Reading code and configuration for known bad patterns without running anything; cheap, fast, and blind to runtime behaviour. |
| Misconfiguration scanning (checkov) | Compares each Terraform resource with a catalogue of rules ("load balancers should use TLS"); a rule knows best practice, not this project's constraints, which is why accepted findings need reasons. |
| SAST (bandit) | The same idea for Python source: shell injection, SQL built from strings, weak hashes. |
| Dependency audit (pip-audit) | Looks up each pinned library version in a database of published vulnerabilities (CVEs). |
| Secret scanning (gitleaks) | Searches every commit, not only the current files, for things shaped like keys and passwords; a secret deleted in a later commit is still in the history. |
| Risk acceptance | Deciding, in writing, that a known gap stays, with the reason and what production would do instead. This is normal engineering, and the written reason is the difference between a decision and an oversight. |
| Defence in depth | Several independent layers (escaping in templates *and* a content security policy; private subnets *and* security groups), so one mistake is not enough. |
| Least privilege | Every identity and network path gets only what it needs; the flow-log role below may write to one log group and nothing else. |

---

## 1. Tools

| Tool | Scans | Install |
|---|---|---|
| `checkov` | Terraform: misconfigurations against AWS best practices | separate virtualenv, see below |
| `bandit` | Python source: insecure patterns | `requirements-dev.txt`, pinned |
| `pip-audit` | `app/requirements.txt`: dependencies with known CVEs | `requirements-dev.txt`, pinned |
| `gitleaks` | the whole git history: committed secrets | standalone binary |
| `ruff` | already in use | — |

- **`checkov` gets its own virtualenv**, `.venv-scan/` at the repository root (add it to
  `.gitignore`). It pulls in many packages with their own version pins, and installing it into the
  project environment risks changing versions the application and its tests depend on.
  Create it with `py -3.12 -m venv .venv-scan`. If checkov cannot be installed on this machine after
  one honest attempt, stop on that tool and report the error rather than spending the evening on it.
- **`gitleaks`**: use it from `PATH` if installed; otherwise try `winget install Gitleaks.Gitleaks`;
  otherwise download the Windows x64 release from the project's GitHub releases page into `tools/`
  (gitignored) **and verify the file against the release's published SHA-256 checksums before running
  it**. A security tool fetched without verification is its own finding. Record the version used.
  Version 8.19 and later use `gitleaks git`; older versions use `gitleaks detect`. Check with
  `gitleaks version` and use the matching form everywhere, including the hook.
- **False positives in gitleaks** (a fake password in a test, a sample email) are allowed one at a
  time: a `gitleaks:allow` comment on the line, or a `.gitleaks.toml` entry naming one file, each with
  a reason. No allowlisting of whole directories.
- Record every tool's version in the scan report (section 6). A finding list without versions cannot be
  reproduced.

### Commands

```powershell
.venv-scan\Scripts\checkov -d infra --framework terraform --compact --quiet
bandit -r app scripts -q
pip-audit -r app\requirements.txt
tools\gitleaks.exe git . --redact --verbose
```

Scan `infra/` as a whole so both stacks are covered. `--redact` keeps any secret that is found out of
the terminal output and the report.

---

## 2. Small fixes to make first

These are real gaps, cheap to close, and each improves an answer in the review.

### 2.1 VPC flow logs: rejected traffic (`infra/app/flowlogs.tf`)

```hcl
resource "aws_cloudwatch_log_group" "flow" {
  name              = "/${var.project}/vpc-flow-rejects"
  retention_in_days = 3
}

resource "aws_flow_log" "rejects" {
  vpc_id                   = local.base.vpc_id
  traffic_type             = "REJECT"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60
}
```

plus an IAM role trusted by `vpc-flow-logs.amazonaws.com`, with an inline policy:

- `logs:CreateLogStream`, `logs:PutLogEvents`, `logs:DescribeLogStreams` on **both**
  `aws_cloudwatch_log_group.flow.arn` and `"${aws_cloudwatch_log_group.flow.arn}:*"`. The first is the
  group, the second its streams; with only one of them delivery fails silently and the group stays
  empty.
- `logs:DescribeLogGroups` on `*` in its own statement. It is a read-only listing action that cannot
  be scoped to one group.
- **No `logs:CreateLogGroup`.** AWS's sample policy includes it; leaving it out means the service can
  never recreate the group after `terraform destroy` removes it.

Write the trust policy with a condition on `aws:SourceAccount` equal to the current account
(`data.aws_caller_identity`), which stops another account from using the role through the service
(the "confused deputy" problem).

**What it is:** a VPC flow log records one line per network connection attempt: who, to where, which
port, accepted or rejected. It sees metadata only, never content.

- **Rejected traffic only.** Accepted traffic is already visible through the load balancer metrics and
  the application log; logging it all would multiply the volume for nothing. Rejects show what the
  security groups are stopping: within minutes of the load balancer existing, internet scanners probe
  it on ports other than 80. That is a concrete, live answer to "how would you know if something is
  probing you".
- **In the `app` stack**, so it is destroyed daily with everything else. The VPC itself is in `base`;
  the flow log only refers to it.
- Add a saved query `rejected-traffic`: top source addresses and destination ports over the last hour.
  Flow log fields are parsed automatically by Logs Insights (`srcAddr`, `dstPort`, `action`).
- Add the log group to the teardown check in the README.
- **A new role can take a few seconds to become usable.** If the first apply fails on the flow log
  with an access or assume-role error, applying again succeeds. Record it if it happens.
- **checkov will still flag the VPC in `infra/base`** for having no flow log: it cannot see across two
  stacks. Skip it there inline, with the reason "flow log is defined in infra/app".
- First records can take ten to fifteen minutes to appear.

### 2.2 Security headers on every response (`app/web.py`)

An `after_request` hook that sets, if not already set:

| Header | Value | Stops |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'` | injected scripts and styles from other origins; framing |
| `X-Content-Type-Options` | `nosniff` | browsers guessing a content type |
| `Referrer-Policy` | `no-referrer` | leaking URLs to other sites |
| `X-Frame-Options` | `DENY` | framing, in browsers that ignore `frame-ancestors` |

- **Check the CSP against the templates first.** If any template uses an inline `<script>` or a
  `style=""` attribute, `default-src 'self'` blocks it. Move it to the stylesheet rather than
  loosening the policy. Report what had to move.
- **This policy is now a rule for any later redesign of the interface.** Fonts, scripts and styles
  must be files under `static/`; nothing loaded from a CDN, no inline `<script>`, no `style=""`.
  Add that sentence to the template contract in `docs/webapp-design.md`, so a redesign does not
  silently produce a page the browser refuses to style.
- **What it is:** a content security policy is a list the server sends telling the browser which
  sources it may load from. If an attacker does manage to inject markup, the browser refuses to run
  it. It is the second layer behind template escaping.
- **No `Strict-Transport-Security`.** The service is HTTP only; HSTS over HTTP is ignored, and claiming
  it would be misleading.
- A test asserting all four headers on `/`, `/history`, `/health` and an error response.

### 2.3 `/simulate-error` behind a switch

Today anyone on the internet can call `/simulate-error` and fire the 5XX alarm. For a demo that is
acceptable; as a default it is not.

- New setting `ENABLE_ERROR_SIMULATION` in `config.py`, default **off**. When off, the route returns
  404.
- In `infra/app`, a variable `enable_error_simulation` (bool, default `true`, with a description saying
  it exists for the demo) written into the environment file.
- Tests for both states. Existing tests that call the route must turn the setting on explicitly.
- `scripts/load.py --errors` depends on the route. If it gets 404s, it says so in its summary instead
  of reporting "10 errors sent".

The README states it plainly: on for the review, off by default, and a production deployment would not
have the route at all.

### 2.4 The README's `gitleaks` claim

The README says `gitleaks` runs before every push. Make it true or make the README accurate:

- add `.githooks/pre-push`, a short script that runs `gitleaks git --redact` and blocks the push on a
  finding, and set it up with `git config core.hooksPath .githooks` (documented in the README, since a
  hook path is local configuration and not cloned);
- the hook looks for `gitleaks` on `PATH`, then `tools/gitleaks.exe`; if neither is found it prints a
  warning and allows the push, rather than blocking all work on a missing tool;
- it is a POSIX shell script with LF line endings (Git for Windows runs hooks with its own `sh`). Mark
  it executable in the index, since Windows has no executable bit to commit:
  `git update-index --chmod=+x .githooks/pre-push`.

### 2.5 Stored XSS, checked rather than assumed

The webapp design calls stored XSS the clearest risk in the application: sender, subject and evidence
strings come from an attacker-controlled email and are rendered on the result and history pages.

- Add a fixture, `tests/fixtures/xss-subject.eml`, whose subject, sender display name and a link text
  contain `<script>alert(1)</script>` and `"><img src=x onerror=alert(1)>`. It goes under `tests/`,
  not `samples/`: the samples are a verdict corpus with an expected result per file, and
  `load.py` uploads all of them.
- A test that scans it through `/scan` and `/history` and asserts that the raw `<script` and
  `onerror=` do not appear in the response, and the escaped forms do. Upload it under a hostile
  **filename** as well (`"><img src=x onerror=alert(1)>.eml`, set through the test client): the
  filename is attacker-controlled and displayed too.
- **What it is:** stored XSS means hostile text is saved and later shown to another visitor, whose
  browser runs it as code. Here the hostile text arrives inside the email being scanned.
- Confirm again that no template uses `|safe`.

---

## 3. Running the scans

Run each tool after the fixes. For every finding, decide one of three:

1. **Fix**: a real gap, cheap to close. Fix it in this phase.
2. **Accept**: deliberate, with a reason specific to this project (cost, no domain, destroyed daily).
3. **False positive**: the scanner is wrong for this code. Say why.

### Recording an accepted Terraform finding

Inline, on the resource, so the reason travels with the code:

```hcl
resource "aws_lb_listener" "http" {
  #checkov:skip=CKV_AWS_2:No domain for this exercise, so no certificate; HTTPS is a planned bonus
  #checkov:skip=CKV_AWS_103:Same reason; TLS policy applies only to HTTPS listeners
  ...
}
```

- One skip per check ID, each with a reason. **No blanket skips**, no `--skip-check` on the command
  line: a reviewer reading the file must see why.
- If a check is skipped on several resources for the same reason, the reason is still written on each.

### Recording an accepted Python finding

`# nosec B<id> - <reason>` on the line, never a file-level or global exclusion. Exclude `tests/` from
bandit on the command line (assertions are not a vulnerability in tests) and say so in the report.

---

## 4. Findings to expect

A starting point, not a list to copy. Run the scanners and use their real IDs and messages; checkov
check IDs change between versions.

| Area | Likely finding | Expected decision |
|---|---|---|
| ALB listener | HTTP, no TLS | accept: no domain; HTTPS is a bonus with a certificate |
| ALB | no access logs | accept: needs an S3 bucket with an ELB delivery policy; the ALB metrics and the app log cover the questions |
| ALB | no WAF | accept: decided earlier; WAF costs about $5/month plus per rule, and the app has an upload size limit |
| ALB | deletion protection off | accept: destroyed daily by design |
| ALB security group | ingress from 0.0.0.0/0 | accept: a public web service; the variable exists to narrow it |
| App security group | egress 443 to 0.0.0.0/0 | accept: PyPI, dnf mirrors and AWS APIs have no fixed addresses; VPC endpoints are the production answer and are noted in the README |
| VPC | flow logs | **fixed** in 2.1 |
| RDS | not multi-AZ, no IAM auth, no enhanced monitoring, short backups, deletion protection off | accept each, with the reasons already in the base design |
| RDS | Performance Insights | accept: not supported on `db.t4g.micro`, and the feature has reached end of life |
| S3 artifacts | no versioning, no access logs, no replication, SSE-S3 rather than KMS | accept: holds only zips rebuilt from git |
| Log groups | not KMS-encrypted; retention under a year | accept: encrypted at rest by default; short retention is a cost decision for a four-day project |
| SNS topic | not encrypted | accept, **with the real reason**: CloudWatch alarms cannot publish to a topic encrypted with the AWS-managed SNS key; a customer-managed key with a key policy for CloudWatch would be needed |
| EC2 | no detailed monitoring | accept: five-minute data is enough; one-minute costs about $2 per instance per month |
| IAM | AWS-managed policies attached | accept: the documented requirement for the SSM and CloudWatch agents; narrow permissions are hand-written |
| Python | binding to `0.0.0.0` (if flagged) | false positive: the instance has no public address and the security group admits only the load balancer |

Anything **not** in this table that looks like a real gap: fix it if it takes under fifteen minutes,
otherwise accept it with a reason and list it under "What I would do with more time" in the README.

### `pip-audit`

A vulnerable pinned dependency with a fixed version available is a **fix**: bump the pin, run the full
test suite. Only accept one if no fixed version exists, and say whether the vulnerable code path is
reachable from this application.

**Known gap, to record rather than fix tonight:** `requirements.txt` pins the direct dependencies
only. Their own dependencies are resolved at boot, so two instances launched a week apart can run
different versions, and a bad upstream release could break a deploy. The production answer is a fully
resolved lock file with hashes (`pip-compile --generate-hashes`, installed with `--require-hashes`).
List it in the report under accepted, and in the README under "more time".

### `bandit`

Every SQL statement must use parameters (`%s` placeholders with a separate tuple). A finding about SQL
built by string formatting is real unless the formatted part is a constant in the code.

### `gitleaks`

Any finding in the history is a stop. Do not rewrite history and do not continue; report it with the
commit and the file (redacted), so the owner can decide. A real secret in history means rotating the
secret, not only removing the commit.

---

## 5. IAM policies, checked by AWS (owner runs this)

AWS validates policies for free with IAM Access Analyzer. With the stack up:

```powershell
foreach ($p in "read-release", "read-db-secret") {
  aws iam get-role-policy --profile phishing --role-name phishing-detector-app --policy-name $p --query PolicyDocument --output json | Out-File -Encoding ascii "$env:TEMP\$p.json"
  aws accessanalyzer validate-policy --profile phishing --policy-type IDENTITY_POLICY --policy-document "file://$env:TEMP\$p.json" --query "findings[].[findingType,issueCode]"
}
```

Expected: an empty list for each, or suggestions only. `Out-File -Encoding ascii` matters: plain `>`
in Windows PowerShell writes UTF-16, which the CLI cannot read. The commands read the account and
change nothing. Use the actual policy names if they differ, and add the flow-log role's policy once it
exists. Claude Code does not run this; it leaves a line in the report for the result.

---

## 6. The report (`docs/security-scan.md`)

Short and factual:

1. **Tools and versions**, and the date.
2. **Summary**: per tool, findings before and after this phase: fixed, accepted, false positive.
3. **Fixed**: one line each, with the file.
4. **Accepted**: one entry per finding, written so it can be studied before the review:
   the real check ID; **what the check means** in plain words; **the risk** if it were exploited or
   went wrong; **why it is accepted here**; **what production would do**. Group them by resource
   (load balancer, database, storage, logging, network, IAM).
5. **Not covered**: what these tools do not check: runtime behaviour, the AWS account configuration
   outside Terraform, the dependencies' own dependencies beyond what `pip-audit` resolves.

The README's **Security** section summarises the report in a few lines and links to it.

---

## 7. Applying the fixes

The fixes in section 2 change `infra/app` (flow logs, a variable) and the application (headers,
the switch). The owner then runs `terraform plan`. Expect: the flow log, its log group, its role and
policy, and one saved query added; the S3 object, launch template and group changed, because the
application changed and so did the environment file. That is a new release and an instance refresh:
a real deployment of a code change, the drill phase 5 left for later.

After the refresh:

```powershell
curl.exe -sI (terraform output -raw alb_url)
```

The four headers appear. Then, after a few minutes, the `rejected-traffic` saved query returns rows.
Take a screenshot of it: it shows the security groups doing their job against real traffic from the
internet.

---

## 8. Done when

- every finding from the four scanners is fixed, accepted inline with a reason, or explained as a
  false positive;
- `docs/security-scan.md` exists, and the README's security section links to it;
- the full test suite passes, including the new header, switch and XSS tests;
- the headers are visible on the deployed service, and the flow log shows rejected traffic.
