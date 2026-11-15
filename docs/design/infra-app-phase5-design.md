# Phase 5: the real application on the instances

Phase 4 proved the infrastructure with a placeholder that answers "hello". This phase replaces what
runs on port 8000 with the real Flask application, connects it to RDS, and makes deployment a single
`terraform apply`: a code change goes up as a new release, and the Auto Scaling Group replaces the
instances one at a time with no downtime.

Read `docs/design/code-standards.md`, `docs/design/infra-app-design.md` and `docs/design/webapp-design.md` first. Everything
in `infra-app-design.md` still applies unless this document says otherwise.

**Do not run `terraform apply`.** Write the code, run `terraform fmt`, `terraform validate` and the test
suite, and stop. The owner runs `plan` and `apply` himself.

---

## 1. What changes

| Area | Phase 4 | Phase 5 |
|---|---|---|
| What runs on :8000 | `hello.py` on `ThreadingHTTPServer` | the Flask app under gunicorn, 2 workers |
| How code reaches the instance | written inline in `user_data` | zip in a private S3 bucket, downloaded at boot |
| Instance permissions | SSM + CloudWatch managed policies | plus two inline policies: one S3 prefix, one secret |
| Database | rule existed, unused | app connects with TLS, password from Secrets Manager |
| `health_check_type` | `EC2` | `ELB` |
| Code change reaches instances | by hand (`start-instance-refresh`) | automatically, rolling, on `apply` |
| `/health` | `hello from <id>` | JSON with instance ID **and release ID** |

New and changed files:

```
infra/app/
├── versions.tf       + hashicorp/archive provider
├── artifact.tf       NEW: zip, bucket, object
├── iam.tf            + two inline policies
├── compute.tf        templatefile variables, ELB health check, instance_refresh
├── variables.tf      health_check_type default → "ELB"
└── outputs.tf        + artifact_bucket, artifact_key, release
deploy/
└── user_data.sh.tftpl    rewritten middle section
app/
├── config.py         + APP_RELEASE, DB_SSLMODE (small)
└── web.py            /health adds release; startup must survive a DB outage (see section 6)
.gitignore            + infra/app/.build/
```

The engine (`app/detector/`) does not change.

---

## 2. The release artifact (`artifact.tf`)

```hcl
data "archive_file" "app" {
  type             = "zip"
  source_dir       = "${path.module}/../../app"
  output_path      = "${path.module}/.build/app.zip"
  output_file_mode = "0644"

  excludes = [
    "**/__pycache__/**",
    "**/*.pyc",
    "**/.pytest_cache/**",
    "**/.env",
    "**/.env.*",
  ]
}

locals {
  release      = substr(data.archive_file.app.output_sha256, 0, 12)
  artifact_key = "releases/app-${local.release}.zip"
}
```

- **The release ID is the hash of the code.** The same code always produces the same key; any change
  produces a new one. That single value drives the whole deployment: new key → new `user_data` → new
  launch template version → instance refresh. Nothing has to be bumped by hand.
- **`output_file_mode = "0644"`** makes the zip identical on Windows and Linux. Without it, file
  permissions differ between machines, the hash differs, and a plan on another machine shows a new
  release for unchanged code.
- **`.env` is excluded explicitly.** It should not be under `app/`, but if it ever is, it must not
  travel to S3. The other excludes keep build noise out of the hash, so running the tests locally does
  not create a "new release".
- **Check what is actually under `app/` before finalising the excludes.** If tests, fixtures or
  `requirements-dev.txt` live inside `app/`, exclude them too (`"tests/**"`): they do not belong on a
  server, and a test edit should not count as a new release. Everything the app needs at runtime
  (`templates/`, `static/`, any data files the engine reads, `requirements.txt`) must stay in.
- The zip has the *contents* of `app/` at its root (`detector/`, `web.py`, …), not an `app/` folder.
  The boot script extracts it into `/opt/phishing/app` to restore the package name.

```hcl
resource "aws_s3_bucket" "artifacts" {
  bucket_prefix = "${var.project}-artifacts-"
  force_destroy = true    # this stack is destroyed daily; the bucket holds only rebuildable zips
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

data "aws_iam_policy_document" "artifacts_tls_only" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.artifacts.arn,
      "${aws_s3_bucket.artifacts.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifacts_tls_only.json

  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

resource "aws_s3_object" "release" {
  bucket = aws_s3_bucket.artifacts.id
  key    = local.artifact_key
  source = data.archive_file.app.output_path

  source_hash = data.archive_file.app.output_base64sha256

  # A new release creates the new object before removing the old one, so there
  # is never a moment when the launch template points at a key that is gone.
  lifecycle { create_before_destroy = true }
}
```

- **`force_destroy = true`** is what lets `terraform destroy` remove a bucket that still has objects.
  Right here, wrong for a bucket holding anything that cannot be rebuilt. Say so in a comment.
- **Public access block, owner-enforced, SSE-S3, TLS-only policy.** Several of these are already AWS
  defaults for new buckets. They are written out anyway because a scanner reads the code, not the
  defaults, and because the intent is then visible in review.
- **No versioning.** Each release already has its own key, so versioning would only keep copies of
  objects that never change. Record this as a decision, not an omission.
- **`source_hash`, not `etag`.** `etag` equals the file's MD5 only for some encryption settings and
  produces a permanent diff otherwise. `source_hash` is compared by Terraform alone.
- **Accepted scanner findings**, to record in the README in phase 7 rather than fix: no access logging,
  no versioning, SSE-S3 rather than a customer-managed KMS key. Each adds resources and cost to protect
  zips that are rebuilt from git in seconds.
- **`bucket_prefix`, not a fixed name.** Bucket names are global across all AWS accounts; a fixed name
  can collide with someone else's, and a recreated bucket with the same name can briefly fail.

Add to `versions.tf`:

```hcl
archive = {
  source  = "hashicorp/archive"
  version = "~> 2.7"
}
```

Adding a provider means running `terraform init` once more. Commit the updated
`.terraform.lock.hcl`. Add `infra/app/.build/` to `.gitignore`.

---

## 3. Instance permissions (`iam.tf`)

Two inline policies, each scoped to exactly what the instance reads.

```hcl
data "aws_iam_policy_document" "read_release" {
  statement {
    sid       = "ReadReleases"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/releases/*"]
  }
}

data "aws_iam_policy_document" "read_db_secret" {
  statement {
    sid       = "ReadDatabaseSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [local.base.db_secret_arn]
  }
}

resource "aws_iam_role_policy" "read_release" {
  name   = "read-release"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.read_release.json
}

resource "aws_iam_role_policy" "read_db_secret" {
  name   = "read-db-secret"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.read_db_secret.json
}
```

- **The S3 permission covers the `releases/` prefix, not one key.** During an instance refresh old and
  new instances coexist; a policy pinned to one key would be rewritten on every release. The prefix is
  still read-only, one bucket, one folder. No `s3:ListBucket`: the instance knows the exact key.
- **The secret permission is one ARN, read-only.** No `DescribeSecret`, no wildcards.
- **No KMS permission is needed.** The RDS-managed secret is encrypted with the AWS-managed
  `aws/secretsmanager` key, whose key policy already allows decryption through Secrets Manager for any
  principal allowed to read the secret. If the apply or the app fails with a KMS `AccessDenied`, record
  it rather than adding `kms:*`.
- **This completes the split described in phase 4:** managed policies for the two agents, hand-written
  policies wherever the scope matters. Both new policies go into the ASG's `depends_on` (section 5).

---

## 4. The boot script (`deploy/user_data.sh.tftpl`)

The structure stays: strict mode, `retry`, `imds`, unprivileged user, env file, systemd, self-test,
marker. The placeholder is replaced by download → extract → virtualenv → install.

```bash
#!/bin/bash
set -euxo pipefail

# Output of every line lands in /var/log/cloud-init-output.log.
# Release: ${release}

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

retry 12 dnf install -y python3.12 python3.12-pip

id phishing >/dev/null 2>&1 || useradd --system --no-create-home --shell /sbin/nologin phishing

# --- fetch and unpack the release -------------------------------------------
APP_ROOT=/opt/phishing
RELEASE_ZIP=/root/release.zip

retry 6 aws s3 cp --region "${region}" \
  "s3://${artifact_bucket}/${artifact_key}" "$RELEASE_ZIP"

mkdir -p "$APP_ROOT/app"
python3.12 -m zipfile -e "$RELEASE_ZIP" "$APP_ROOT/app"
rm -f "$RELEASE_ZIP"

python3.12 -m venv "$APP_ROOT/venv"
retry 5 "$APP_ROOT/venv/bin/pip" install --no-cache-dir --disable-pip-version-check \
  -r "$APP_ROOT/app/requirements.txt"

# Compile now, as root: the service user cannot write .pyc files, and a
# syntax error should stop the boot here rather than crash gunicorn later.
"$APP_ROOT/venv/bin/python" -m compileall -q "$APP_ROOT/app"

# Code is owned by root and read-only to the service user.
chown -R root:root "$APP_ROOT"
chmod -R u=rwX,go=rX "$APP_ROOT"

# --- configuration ----------------------------------------------------------
cat > /etc/phishing-app.env <<ENVEOF
INSTANCE_ID=$INSTANCE_ID
APP_RELEASE=${release}
AWS_DEFAULT_REGION=${region}
DB_HOST=${db_host}
DB_PORT=${db_port}
DB_NAME=${db_name}
DB_USER=${db_user}
DB_SECRET_ARN=${db_secret_arn}
DB_SSLMODE=require
LOG_FILE=/var/log/phishing-app/app.log
ENVEOF
chmod 0600 /etc/phishing-app.env

cat > /etc/systemd/system/phishing-app.service <<'SVCEOF'
[Unit]
Description=Phishing detector
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
User=phishing
Group=phishing
WorkingDirectory=/opt/phishing
EnvironmentFile=/etc/phishing-app.env
ExecStart=/opt/phishing/venv/bin/gunicorn --chdir /opt/phishing --workers 2 --bind 0.0.0.0:8000 --timeout 30 --graceful-timeout 20 'app.web:create_app()'
Restart=always
RestartSec=3
LogsDirectory=phishing-app
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=tmpfs

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable --now phishing-app

retry 12 curl -sf http://127.0.0.1:8000/health
echo "user_data finished OK (release ${release})"
```

### Template variables

```hcl
user_data = base64encode(replace(
  templatefile("${path.module}/../../deploy/user_data.sh.tftpl", {
    release         = local.release
    region          = var.region
    artifact_bucket = aws_s3_bucket.artifacts.id
    artifact_key    = aws_s3_object.release.key
    db_host         = local.base.db_endpoint
    db_port         = local.base.db_port
    db_name         = local.base.db_name
    db_user         = local.base.db_username
    db_secret_arn   = local.base.db_secret_arn
  }),
  "\r\n", "\n"
))
```

`artifact_key` comes from `aws_s3_object.release.key`, not from `local.artifact_key`. The value is the
same; the reference is what tells Terraform the object must be uploaded before the launch template
changes. With the local, a new instance can boot and ask for a zip that is not there yet.

### Points that are easy to get wrong

- **Escaping.** `${release}`, `${region}` and the rest are template variables, filled in by Terraform.
  `$INSTANCE_ID`, `$APP_ROOT`, `$RELEASE_ZIP`, `$n`, `$*` are shell variables, written without braces
  so the template leaves them alone. Any new shell variable written with braces must be `$${NAME}`.
- **The env-file heredoc is unquoted** because it needs both kinds of substitution: Terraform fills in
  `${db_host}` before the instance exists, and the shell fills in `$INSTANCE_ID` at boot. The unit-file
  heredoc stays quoted: nothing in it should be expanded.
- **The env file holds the secret's ARN, never the password.** It is `0600` and owned by root; systemd
  reads it before dropping to the `phishing` user, so the application never needs to read the file
  itself.
- **`python3.12-pip`** is a separate package on Amazon Linux. Without it, `venv` may be created without
  `pip`, and the install fails on a missing file rather than a network error.
- **`python3.12 -m zipfile -e`** extracts without needing `unzip`, which is one fewer package and one
  fewer thing to assume about the image. The AWS CLI is preinstalled on the standard AL2023 image.
- **`AWS_DEFAULT_REGION`** is required. boto3 does not take the region from the instance metadata, and
  without it the first Secrets Manager call fails with `NoRegionError`.
- **`LogsDirectory=phishing-app`** makes systemd create `/var/log/phishing-app` owned by `phishing`
  before every start. Without it the app, running unprivileged, cannot create its log file, and the
  service dies on its first log line.
- **`ProtectSystem=full`** makes `/usr`, `/boot` and `/etc` read-only for the service. The app writes
  only to its log directory and keeps uploads in memory, so it needs nothing else.
- **`ProtectHome=tmpfs`, not `true`.** libpq, the PostgreSQL client library, looks for an optional
  client certificate in `~/.postgresql/` on every TLS connection. A missing file is fine; a file it is
  not allowed to look at is a fatal error. `ProtectHome=true` makes `/home` unreadable, so the lookup
  fails with "Permission denied" and every database connection fails. `tmpfs` hides the real `/home`
  behind an empty one: the lookup finds nothing, and the protection stays. Found in phase 5 on the
  first deploy; recorded in BUILD_LOG.
- **`--chdir /opt/phishing`** puts `/opt/phishing` on `sys.path`, which is how `app.web` is found.
- **The self-test waits longer than in phase 4** (12 attempts): gunicorn imports Flask, boto3 and the
  engine before it answers.
- **The instance's credentials can lag a few seconds behind its launch.** That is why `aws s3 cp` is
  wrapped in `retry`: the first attempt may fail with "Unable to locate credentials".
- **Do not echo, `cat` or log the env file or the secret anywhere in this script.** `set -x` prints
  commands, not heredoc bodies, so the file's contents stay out of the boot log as written. Keep it so.
- **`requirements.txt` must contain `gunicorn`, pinned.** Check. If it was moved out of the file for
  Windows reasons, install it pinned on its own line after the `-r` install instead.

---

## 5. Auto Scaling Group (`compute.tf`, `variables.tf`)

```hcl
resource "aws_autoscaling_group" "app" {
  # ... as in phase 4 ...

  health_check_type         = var.health_check_type            # default now "ELB"
  health_check_grace_period = var.health_check_grace_seconds   # 240

  # In normal mode, apply returns only when both instances pass the load
  # balancer's health check. In debug mode (EC2) it returns at once.
  wait_for_elb_capacity     = var.health_check_type == "ELB" ? var.asg_size : null
  wait_for_capacity_timeout = "12m"

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = var.instance_warmup_seconds     # 300
      skip_matching          = true
    }
  }

  depends_on = [
    aws_route.private_app_nat,
    aws_vpc_security_group_egress_rule.app_https,
    aws_iam_role_policy_attachment.ssm,
    aws_iam_role_policy_attachment.cloudwatch,
    aws_iam_role_policy.read_release,
    aws_iam_role_policy.read_db_secret,
    # plus the two 5432 rules: app-sg egress to db-sg, and db-sg ingress from app-sg
    # (use the resource names already in security.tf)
  ]
}
```

New variables: `health_check_grace_seconds` (number, default `240`) and `instance_warmup_seconds`
(number, default `300`), with a validation that the warm-up is greater than the grace period.

- **`health_check_type = "ELB"`** is what makes self-healing real: an instance that stops answering
  `/health` is terminated and replaced. Change the variable's default and keep its validation.
- **Debug mode.** When a boot keeps failing, apply once with `-var health_check_type=EC2`. The
  instances then stay up however broken they are, and the apply does not wait for them. Investigate,
  fix, and apply again without the override.
- **`wait_for_elb_capacity`.** In phase 4 the apply finished while one instance was still booting,
  which looked like a failure. Now "apply complete" means "serving". If the boot is broken, the apply
  fails after twelve minutes with a capacity timeout **and marks the group as tainted, so the next
  apply destroys and recreates it.** That is expected, not a second problem. Use debug mode instead of
  re-applying blindly.
- **Two timers, and their order matters.**
  - The *grace period* (240 s) is how long a new instance is protected from being replaced for failing
    the load balancer's health check. It must be longer than a real boot, or a slow healthy boot is
    killed and restarted forever.
  - The *instance warm-up* (300 s) is how long an instance refresh waits after launching a replacement
    before it moves on to the next instance. If it is left unset it silently equals the grace period.
  - **Warm-up must be longer than the grace period.** During the grace period the group treats every
    instance as healthy, whatever the load balancer says. If the refresh moved on inside that window,
    a release that cannot boot would replace the first instance, be assumed healthy, and then take
    down the second one: a full outage caused by a deploy. With warm-up > grace, a broken replacement
    is found unhealthy and replaced before the refresh continues, so the old instance on the other
    side keeps serving. Rehearse this once in phase 8 with a deliberately broken release.
  - **Measure, then tune.** After the first successful boot, read the last line of
    `/var/log/cloud-init-output.log`; it reports the boot time in seconds. Keep grace ≥ boot + 60 and
    warm-up ≥ grace + 60. Shorter values make the live deploy faster; do not go below those margins.
- **Instance refresh.** When the launch template version changes (a new release changes `user_data`,
  which creates a new version, which `latest_version` picks up), the group replaces instances one at a
  time. `min_healthy_percentage = 50` with two instances means one is replaced while the other serves.
  `skip_matching` skips instances that already run the current version. A full rollout takes about
  twice the warm-up: roughly eleven minutes with the defaults. The new release starts answering much
  earlier, as soon as the first replacement is healthy.
- **The refresh runs after `apply` returns.** Terraform starts it and does not wait for it. Watch it as
  shown in section 8. Applying again while a refresh is running cancels it and starts a new one.
- **The inline policies and the database rules join `depends_on`** for the same reason as everything
  else in that list: an instance that boots before its permissions and routes exist fails once, and a
  boot script does not run twice.

---

## 6. Application changes (`app/`)

Small, and each covered by a test.

1. **`APP_RELEASE`** in `config.py`, default `"local"`. Add it to the `/health` response and to every
   log line as `release`:
   ```json
   {"status": "ok", "instance": "i-0abc…", "release": "3f9a1c2b7d10"}
   ```
   This is how a deployment is shown to be working: during a refresh, repeated requests show the old
   release, then a mix, then only the new one.

2. **`DB_SSLMODE`** in `config.py`, default `"prefer"`, passed to the connection as `sslmode`. On EC2 it
   is `require`: the connection to RDS is encrypted or it is not made. RDS for PostgreSQL 16 already
   enforces TLS on its side; this makes the client refuse to downgrade as well. Full certificate
   verification (`verify-full` with the RDS CA bundle) is the production step beyond this; note it in
   the README as not done.

3. **Startup must survive a database outage.** Check where `init_schema()` is called. If `create_app()`
   calls it and lets an exception escape, a database problem at boot makes gunicorn's workers fail to
   start, `/health` never answers, and with ELB health checks the group replaces instances in a loop —
   exactly what the shallow health check exists to prevent. Required behaviour:
   - At startup, try `init_schema()`; on failure, log an `ERROR` with `event: "schema_init_failed"` and
     carry on.
   - Before the first database operation in a process, if the schema was not initialised, try again.
     A module-level flag is enough.
   - Test: patch the database so every call raises, call `create_app()`, and assert that `/health`
     still returns 200.

4. **The secret.** The RDS-managed secret is JSON: `{"username": "...", "password": "..."}`. Confirm
   `config.get_db_password()` parses it and returns the `password` field, and that the authentication
   retry (refresh the cached password once, then retry once) is in place. Test with a fake secret
   string.

5. **Fail fast when AWS is unreachable.** Create the Secrets Manager client with explicit limits:
   `botocore.config.Config(connect_timeout=3, read_timeout=5, retries={"max_attempts": 2})`. The
   defaults wait about a minute per attempt. gunicorn kills a worker that is silent for 30 seconds, so
   with the defaults a network problem at startup becomes a worker restart loop and a failing health
   check, instead of one `schema_init_failed` line and a working `/health`. Create the client once
   per process, not per request.

6. **No secret in any log line or error page.** Exceptions from the database driver can include the
   connection string. Log `error_type` and a short message only; never `repr()` of connection
   parameters. Add a test that the password value does not appear in captured log output when a
   connection fails.

7. **Configuration names.** `config.py` is the source of truth. If any variable name in the env file
   above differs from what `config.py` reads, change the template, not the code, and say so in the
   summary.

Run the full suite. All existing tests must still pass.

---

## 7. Outputs

Add: `artifact_bucket`, `artifact_key`, `release`. Keep the existing ones.

---

## 8. Applying and testing

### Before

```powershell
aws sts get-caller-identity --profile phishing
cd infra\app
terraform init          # new provider: archive
terraform validate
terraform plan
```

In the plan, check:
- one `aws_s3_object` whose key is `releases/app-<12 hex chars>.zip`;
- the two inline policies, and that their resources are one bucket prefix and one secret ARN;
- `health_check_type = "ELB"`, grace period 240, and an `instance_refresh` block with warm-up 300;
- no line anywhere in the plan containing a password;
- the launch template's `user_data` changed (it is shown as a hash; that is expected).

Review the plan with me before applying.

### Apply

```powershell
terraform apply
```

About 8–10 minutes on a fresh stack. It now ends only when both instances are healthy. If it ends with
a capacity timeout, go to section 9 and use debug mode; do not simply apply again.

### Test

```powershell
$url = terraform output -raw alb_url
1..6 | ForEach-Object { curl.exe -sk "$url/health"; "" }
```

Expect both instance IDs and the same release on every line. Then, in a browser:

1. Open the URL. The upload page loads.
2. Upload two or three `.eml` files from the sample corpus. Each result page shows a verdict and
   `served_by`.
3. Open `/history`. The scans are listed — which proves the database round trip — and over a few scans
   both instance IDs appear in `served_by`.

### Test a deployment

This is the live deploy for the review, so it is worth rehearsing now.

1. Make a visible, harmless change: a word in the footer of `base.html`.
2. `terraform plan` shows a new `aws_s3_object` key and an in-place update of the launch template and
   the group. Apply.
3. Watch the rollout:
   ```powershell
   aws autoscaling describe-instance-refreshes --profile phishing --auto-scaling-group-name (terraform output -raw asg_name) --query "InstanceRefreshes[0].[Status,PercentageComplete]"
   1..20 | ForEach-Object { curl.exe -sk "$url/health"; ""; Start-Sleep 15 }
   ```
   Within three or four minutes some answers carry the new release; after about eleven minutes all of
   them do, and no request fails. Run the loop longer if needed.

### Done when

- `/health` answers from both instances with the current release;
- a scan is saved and appears in `/history`;
- a code change reaches both instances through `apply` alone, with no failed requests;
- the measured boot time is written in `BUILD_LOG.md`, and the two timers are tuned to it.

Record in `BUILD_LOG.md` anything that broke and how it was found.

---

## 9. When it does not work

The phase 4 checklist (`infra-app-design.md`, section 12) still applies. New failure points, in the
order they happen during boot:

| Symptom in `cloud-init-output.log` | Likely cause |
|---|---|
| `aws s3 cp` → `Unable to locate credentials` | role credentials not ready yet; the retry normally absorbs it. If all attempts fail, the instance profile is missing |
| `aws s3 cp` → `403` / `Forbidden` | **two possible causes that look identical.** The inline policy is missing or on the wrong prefix; or the key does not exist. Without `s3:ListBucket`, S3 answers 403 for a missing object, never 404. Check the key in the bucket first: `aws s3 ls s3://<bucket>/releases/` from your machine |
| `pip install` hangs, then fails | no route out: NAT, route, or the 443 egress rule |
| `pip` → `No module named pip` | `python3.12-pip` not installed |
| `compileall` fails | a syntax error in the release; fix the code, not the script |
| marker present, target still unhealthy | the app started, then died: `journalctl -u phishing-app -n 50` |

On the instance, after the boot:

| `journalctl -u phishing-app` shows | Likely cause |
|---|---|
| `ModuleNotFoundError: No module named 'app'` | zip extracted to the wrong place, or `--chdir` missing |
| `PermissionError` on `/var/log/phishing-app/app.log` | `LogsDirectory` missing from the unit |
| `NoRegionError` | `AWS_DEFAULT_REGION` missing from the env file |
| `AccessDeniedException` from Secrets Manager | secret policy ARN wrong |
| `connection timeout` to the DB host | `db-sg` ingress or `app-sg` 5432 egress |
| `password authentication failed` | secret parsed wrong (`password` field), or the username differs from the secret's |

The database errors do **not** make the target unhealthy — by design. They show up as an error on the
scan page and in the log. To see them:

```bash
sudo tail -50 /var/log/phishing-app/app.log
```

**With `ELB` health checks, a broken instance is replaced before you can read its log.** If an instance
keeps cycling, or the apply ended with a capacity timeout, apply once with
`-var health_check_type=EC2`, investigate, fix, and apply again without the override.

**A refresh that is going wrong can be stopped:**

```powershell
aws autoscaling cancel-instance-refresh --profile phishing --auto-scaling-group-name (terraform output -raw asg_name)
```

The instance still on the old release keeps serving. Fix the code and apply again.

---

## 10. Cost and teardown

S3 adds well under a cent a day. Nothing else changes: about $2.55 a day while the stack runs.

`terraform destroy` removes the bucket and its objects (`force_destroy`). The teardown check from
phase 4 still applies; also confirm the bucket is gone:

```powershell
aws s3 ls --profile phishing | Select-String phishing-detector
```

An empty result is expected.
