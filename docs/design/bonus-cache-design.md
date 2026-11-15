# Bonus B: a result cache on ElastiCache (Valkey)

An optional cache shared by the two instances. It does two things: the same email scanned again (a
common case: many people forward the same phishing email to security) is answered from the cache
instead of being analysed again, and every scan increments a shared counter, so the result can say
how many times this exact email has been seen in the last day. Every scan is still recorded in the
history.

Built on a branch `feature/cache`, created from `main` **after** `feature/https-nat` is merged.
Merged only after it works on AWS. If it is not working on AWS by the agreed cut-off, it stays on the
branch and is explained in the review instead.

**Do not run `terraform init`, `plan` or `apply`.**

Read `docs/design/code-standards.md`, `docs/design/webapp-design.md`, `docs/design/infra-base-design.md` and the phase 5–7
design documents first.

---

## 1. What it does, and whether it is worth it

### The ideas, in one line each

| Term | Meaning |
|---|---|
| Cache | A fast store for answers that were already computed, so the same question is not worked out twice. |
| ElastiCache / Valkey | AWS's managed in-memory key-value store; Valkey is the open-source engine (a fork of Redis). Data lives in memory, so reads take about a millisecond. |
| Key | The name an answer is stored under. Here: the fingerprint (SHA-256 hash) of the uploaded file, plus the release. |
| TTL | Time to live: how long an entry is kept before it is deleted automatically. |
| Hit / miss | The answer was in the cache / it was not, and had to be computed. |
| Cache-aside | The application checks the cache itself, computes on a miss, and writes the answer back. The cache never talks to the engine or the database. |
| Fail open | If the cache is down, carry on without it. The opposite, fail closed, would refuse to work. |
| AUTH token | A password the client must present to the cache. |

### Behaviour

| | |
|---|---|
| Result key | `scan:v1:<release>:<sha256 of the uploaded bytes>` |
| Result value | JSON with the fields the database row holds for a scan: score, verdict, decided_by, findings, sender, subject |
| Counter key | `seen:v1:<sha256 of the uploaded bytes>`, with no release in it: a sighting is a sighting whatever the code version |
| Lifetime | 24 hours for both (`CACHE_TTL_SECONDS`, default 86400). The counter's expiry is set at the first sighting and not extended by later ones |
| Every scan | the counter is incremented; the result shows "Seen N times in the last 24 hours" when N is 2 or more |
| On a hit | the stored result is returned; the scan is still saved to the database and appears in history, marked as served from cache |
| On a miss | the engine runs as today, the result is stored in the cache, then saved |
| Cache unreachable | the engine runs as today, and no count is shown. **The cache is never required.** |
| `/health` | does not touch the cache, for the same reason it does not touch the database |

- **The release is part of the key.** Any deploy changes the release, so nothing computed by an older
  version of the code is ever served; old entries simply expire. Conservative on purpose: a stale
  verdict from a security tool is worse than a recomputed one.
- **What is stored.** Nothing the database does not already hold: verdict, score, findings, sender and
  subject. Findings include short pieces of evidence taken from the email (a URL, the sender address).
  The email body and attachments are never stored. The file name and "served by" always come from the
  current request, not from the cache. Data is encrypted in transit and at rest.
- **A cached value is checked when it is read.** If it does not have the expected fields and types, it
  is treated as a miss and deleted. The application is the only writer and the key is a hash of the
  content, so a caller cannot choose what is stored under a key; the check is a second layer.
- **The counter reveals that the same email was scanned before.** There are no accounts and the history
  is already public, so nothing new is exposed; with accounts it would be scoped per organisation. One
  sentence in the README.

### Is it worth it? The honest answer

**What it really gives:**

1. **State shared between the two instances.** Each instance has its own memory, and a request can
   land on either. A dictionary inside the process cannot be seen by the other instance; a network
   cache can. That is the reason for ElastiCache rather than a variable in memory.
2. **A security signal: how many times this exact email was seen.** Phishing arrives in campaigns, and
   the same message is submitted by several people. A counter per content hash, shared by both
   instances and expiring after a day, turns the cache into information for the analyst: "seen 14
   times in the last 24 hours". Counters with an expiry are what this kind of store is built for, and
   this is the part of the feature that is useful today.
3. **Identical emails are analysed once.** A phishing campaign sends the same email to many people;
   a security team receives the same file many times.
4. **The pattern is in place.** The day the engine does something slow (a reputation lookup, opening
   an attachment in a sandbox), the saving becomes seconds per scan with no further change.

**What it does not give, today:** much speed. The engine is offline and takes milliseconds; most of a
request's time is the network and the database write, which still happens on a hit. The measured
saving will be small, and the README must say so with the real number rather than imply more.

**So measure it.** Add `analysis_ms` to the scan log line (time spent in the engine on a miss, time
spent on the cache lookup on a hit), measured in the web layer, not inside the engine. After
deployment, the saved query in section 2 reports the average for hits and for misses, and that number
goes into the README.

**A further use of the same cluster**, noted in the README and not built: a per-address rate limit
on uploads. It is the same mechanism as the sighting counter, keyed by client address.

---

## 2. Infrastructure

### Where: `infra/base`

Like the database, the cache is created ahead of time: it takes about ten minutes to provision, which
would otherwise be added to every `apply` of `infra/app`, including the live deploy in the review. Its
security group starts with no ingress; `infra/app` adds the rule from the instances, exactly as it does
for the database.

**This changes `infra/base`.** The plan for base must show **only additions** (new resources and new
outputs). Any line that changes, replaces or destroys an existing resource is a stop, even if it looks
unrelated or harmless, for example a small in-place change on the database caused by drift: report it
and wait.

### `infra/base/cache.tf`

```hcl
resource "aws_elasticache_subnet_group" "cache" {
  name       = "${var.project}-cache"
  subnet_ids = <the private-db subnets>
}

resource "aws_security_group" "cache" {
  name_prefix = "${var.project}-cache-"
  description = "Cache: ingress added by infra/app from the app security group only"
  vpc_id      = aws_vpc.main.id
  lifecycle { create_before_destroy = true }
}

resource "random_password" "cache_auth" {
  length  = 64
  special = false     # AUTH tokens allow only some special characters; alphanumeric avoids the question
}

resource "aws_secretsmanager_secret" "cache_auth" {
  name_prefix             = "${var.project}-cache-auth-"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "cache_auth" {
  secret_id     = aws_secretsmanager_secret.cache_auth.id
  secret_string = random_password.cache_auth.result
}

resource "aws_elasticache_replication_group" "cache" {
  replication_group_id = "${var.project}-cache"
  description          = "Result cache for the phishing detector"

  engine               = "valkey"
  engine_version       = "<current 8.x, check the provider and region>"
  node_type            = "cache.t4g.micro"
  num_cache_clusters   = 1
  port                 = 6379

  subnet_group_name  = aws_elasticache_subnet_group.cache.name
  security_group_ids = [aws_security_group.cache.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.cache_auth.result

  automatic_failover_enabled = false
  multi_az_enabled           = false
  snapshot_retention_limit   = 0
  apply_immediately          = true
}
```

Points that matter:

- **`recovery_window_in_days = 0` on the secret.** By default a deleted secret is kept for 7 to 30 days
  and its name stays taken; destroying and recreating the stack would then fail on the name. Zero
  deletes it at once. `name_prefix` avoids a fixed name as well.
- **`transit_encryption_enabled` and `auth_token` go together**: AWS accepts an AUTH token only with
  in-transit encryption on. Both are required: TLS so the token and the results do not cross the
  network in the clear, and the token so that reaching the port is not enough to read the data.
- **The token is in Terraform state** (base state is local and gitignored), the same accepted trade-off
  as the self-signed certificate. Production would use ElastiCache's IAM authentication, where the
  application signs a short-lived token with its role and no long-lived secret exists. Record this in
  the README.
- **One node, no replica, no failover.** The cache is optional by design: when it is gone the service
  is slower, not down. A replica in a second zone would double the cost for a component nothing
  depends on. Record this next to the RDS single-zone decision; the two have different answers for
  different reasons, and the difference is worth stating.
- **Memory policy.** Leave the parameter group at the engine default. Every key has a TTL, so when
  memory fills the engine evicts the least recently used entries by itself.
- Add `hashicorp/random` to base's `versions.tf`, pinned. A new provider means `terraform init` in
  `infra/base`, and committing its lock file.
- **If the apply is refused** on an ElastiCache or Secrets Manager action (this account was created
  through the project sign-up and carries its own guardrails), stop and record the exact error. Do
  not work around it.
- **The engine version comes from the prompt**, where the owner pastes what the region actually
  offers. Do not guess one. Check the node type and parameter defaults against the provider
  documentation. If Valkey is not offered for this node type in the region, use the Redis OSS engine
  of the closest version and say so.

### `infra/base/outputs.tf`

Add `cache_endpoint` (the primary endpoint address), `cache_port`, `cache_secret_arn`,
`cache_security_group_id`, and `cache_cluster_id` (the single member of the replication group's
`member_clusters`), which the dashboard in `infra/app` needs as the `CacheClusterId` dimension.

### `infra/app`

- `security.tf`: `app-sg` egress 6379 to the cache security group; ingress on the cache security group
  6379 from `app-sg`. Singular rule resources with descriptions, as for the database.
- `iam.tf`: a third inline policy, `read-cache-secret`: `secretsmanager:GetSecretValue` on the cache
  secret's ARN only. Add it to the ASG's `depends_on`, with the two 6379 rules.
- `compute.tf` and the boot script: `CACHE_HOST`, `CACHE_PORT`, `CACHE_SECRET_ARN` in the environment
  file. The token itself is never written to the instance.
- Monitoring (`monitoring.tf`): a dashboard row **"Cache"**, with ElastiCache `CacheHits` and
  `CacheMisses` (Sum), `CurrConnections`, `DatabaseMemoryUsagePercentage` and `EngineCPUUtilization`.
  The `CacheClusterId` dimension comes from the new base output, not from a hand-built string. No new
  alarm: a cache failure is not an incident in this design.
- `logs.tf`: a saved query `cache-hit-ratio`: for scan events, the count and the average
  `analysis_ms` and `duration_ms`, grouped by the `cache` field. This is the measurement section 1
  asks for.

---

## 3. Application

### `app/cache.py` (new)

One small module, the only place that talks to the cache.

```python
def content_hash(raw: bytes) -> str
def lookup(digest: str) -> tuple[dict | None, int | None]   # stored result or None; times seen or None
def store(digest: str, value: dict) -> None
```

- **`lookup` is one round trip:** a pipeline with `GET` on the result key, `INCR` on the counter key,
  and `EXPIRE … NX` on the counter key, so the 24 hours start at the first sighting.
- **Client:** `redis` (redis-py), pinned in `app/requirements.txt` together with anything it pulls
  in, like every other dependency. It works with Valkey. Connect with TLS: `ssl=True`,
  `ssl_cert_reqs="required"`, `ssl_check_hostname=True`. ElastiCache's certificates are issued by
  Amazon's public CA, which the instance's system trust store contains. If verification fails on the
  instance with an unknown-CA error, pass `ssl_ca_certs=certifi.where()` (certifi is already a pinned
  dependency); **never** turn verification off to make it work.
- **Fail fast:** `socket_connect_timeout=0.5`, `socket_timeout=0.5`, no retries. A cache that answers
  slower than the analysis it saves is worse than none.
- **Fail open, quietly:** every exception from the client is caught and treated as a miss. After a
  failure, skip the cache entirely for 30 seconds in that process, so a dead cache does not add half
  a second to every request. Log one `WARNING` with `event: "cache_unavailable"` when that happens,
  not one per request.
- **The token** comes from Secrets Manager through `config.py`: read once and kept in the process. It
  does not rotate, so there is no re-read logic; an authentication error is a failure like any other.
- **Lazy, never at startup, and with its own tight limits.** The token is fetched on the first cache
  use, with a Secrets Manager client limited to `connect_timeout=1, read_timeout=2` and a single
  attempt. Do **not** fetch it in `create_app()`: startup already makes one best-effort attempt at the
  database, and gunicorn kills a worker that takes more than 30 seconds to start. Two slow secret
  reads in a row, on a day Secrets Manager is unreachable, would push startup past that and turn an
  optional cache into a restart loop. If the token cannot be fetched, treat the cache as unavailable
  and do not try again for five minutes in that process.
- **Disabled when `CACHE_HOST` is not set.** That is the local default, so local development and the
  existing tests run without a cache.
- One connection pool per process, created lazily.

### Configuration (`config.py`)

`CACHE_HOST` (unset = off), `CACHE_PORT` (6379), `CACHE_SECRET_ARN`, `CACHE_TTL_SECONDS` (86400),
`CACHE_TLS` (true; false only for the local container). Locally, `CACHE_PASSWORD` may be set instead
of the secret ARN, like `DB_PASSWORD`.

### The scan path (`web.py`)

`/scan` and `/api/scan`:

1. Compute the content hash of the uploaded bytes.
2. `lookup`. On a hit, rebuild the result from the stored value, using the same helper the scan
   detail page already uses to rebuild a result from the database.
3. On a miss, analyse, then `store`.
4. Save to the database either way, with `cache_hit` true or false.
5. The scan log line gains `cache` (`"hit"`, `"miss"`, `"off"` or `"error"`), `seen` (the count, when
   known) and `analysis_ms` (section 1).
6. The result page and the JSON API include the count.

### Database (`db.py`)

A new column, `cache_hit BOOLEAN NOT NULL DEFAULT false`.

**The table already exists on RDS**, and `CREATE TABLE IF NOT EXISTS` will not add a column to it. Add
`ALTER TABLE scans ADD COLUMN IF NOT EXISTS cache_hit BOOLEAN NOT NULL DEFAULT false` to the schema
initialisation, inside the same advisory lock. It is idempotent and safe on a table with rows.

**During the rolling deploy, old and new code use the table at the same time.** The column has a
default, so inserts from the old release keep working. Check that every existing query names its
columns: a `SELECT *` mapped by position would break when the column appears. Say what you found.
The same property is what lets an older release run again after a rollback.

**Look before altering.** Check `information_schema.columns` for the column and run the `ALTER` only
when it is missing. `ALTER TABLE` takes an exclusive lock on the table even when it has nothing to
do, and the initialisation runs in every worker at every start.

`get_scan`, `recent_scans` and the record type gain the field.

### Templates

- Result page: when the result came from the cache, a small, quiet line: "Served from cache (scanned
  before; result reused)". Not a warning.
- Result page: when the count is 2 or more, "Seen N times in the last 24 hours". Not shown on the
  scan detail page opened from history, where the count is not known.
- History: a small marker on cached rows. Keep the table readable.
- Update the template contract in `docs/design/webapp-design.md`.

### Local container

Add a `valkey` service to `docker-compose.yml`, bound to `127.0.0.1` and `[::1]` only, like PostgreSQL,
with a password from `.env`, no TLS. Integration tests run against it; unit tests use a fake client.

---

## 4. Tests

- Key: same bytes → same key; different bytes or a different release → different key.
- Counter: first scan → 1 and no line shown; second → 2 and the line appears; the expiry is set once.
- A malformed cached value is treated as a miss and deleted.
- Token fetch failing: the scan succeeds, the application starts, and no second fetch is attempted
  within five minutes.
- Hit: the engine is not called; the result matches what the engine returned the first time; the row
  is saved with `cache_hit` true.
- Miss: the engine is called once and the result is stored.
- Cache down (fake client raising): the scan succeeds, the engine runs, `cache` is `"error"`, exactly
  one `cache_unavailable` warning across several requests, and the cache is skipped for 30 seconds.
- Cache disabled: no client is created.
- `/health` makes no cache call.
- Schema: the column is added to an existing table without it (integration).
- The token never appears in log output.
- Security headers on the result page are unchanged.

---

## 5. Expected scanner findings

Re-run checkov, bandit and pip-audit. Likely new checkov findings on the replication group: no
automatic failover, no multi-AZ, no snapshots; and on the secret: no rotation. Accept each inline with
its reason (the cache is optional and rebuilt; rotating the AUTH token needs a coordinated update of the
cluster and the application). Update `docs/security-scan.md`.

---

## 6. Applying and testing (owner)

1. `infra/base`: `terraform init`, then `plan`. **Only additions.** Apply: about ten to fifteen minutes.
2. `infra/app`: `plan`, apply. A user_data change, so a rolling refresh.
3. Scan the same file twice. The second result says "Served from cache" and "Seen 2 times in the last
   24 hours". Then run `load.py` for a minute: the samples repeat, so almost every request is a hit,
   and the count keeps rising across both instances. That is the shared state, visible.
4. Logs Insights, `cache-hit-ratio`, and the dashboard's Cache row: hits and misses.
5. **Cache failure:** console → ElastiCache → Valkey caches → `phishing-detector-cache` → the node →
   **Reboot**. For a minute or two the cache is gone. Scans keep working; each process logs one
   `cache_unavailable` warning; `cache` is `"error"`, then `"miss"` again once it is back (the reboot
   empties it). Nothing to repair afterwards.

   Rebooting is used rather than removing the security group rule, as in the database drill, because
   the application keeps its cache connection open: a security group change does not cut connections
   that are already established, so the drill would show nothing.

### Cost

`cache.t4g.micro` runs around the clock in `base`, like RDS: roughly forty to fifty cents a day. Check
the current price for the region. The secret adds about forty cents a month.

### If it is abandoned at the cut-off

The cluster may already exist in AWS while `main` has no code for it. To remove it cleanly: switch to
`main`; apply `infra/app` first (this removes the two 6379 rules, which refer to the cache's security
group); then `terraform plan` in `infra/base`, which must show **only** the cache resources, the
secret and the random password to destroy; apply. The branch stays on the remote, unmerged.

### Teardown

The README's teardown order becomes: `infra/app`, then `infra/base`. Add the cache and the secret to
the verification commands. Because of `recovery_window_in_days = 0`, a destroyed secret does not
block recreating the stack.

---

## 7. Done when

- base and app applied; a repeated scan is served from the cache, shows its count, and is saved to
  history as such;
- the README states the measured engine time and what the cache does and does not save;
- the dashboard shows cache hits; the saved query works;
- the cache failure drill shows scans continuing without it;
- README (architecture, decisions, costs, teardown), `docs/security-scan.md` and the template contract
  updated; the branch merged into `main`.
