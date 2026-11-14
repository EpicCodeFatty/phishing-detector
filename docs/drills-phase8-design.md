# Phase 8: failure drills and the troubleshooting runbook

The system has been shown to work. This phase shows what happens when parts of it break, on purpose,
and writes down how an operator recognises and fixes each failure. The result is the README's
**Troubleshooting runbook** section, built from things that were actually observed, not imagined.

Read `BUILD_LOG.md` and the phase 4–7 design documents first. Several failures have already happened
for real and are logged there; this phase adds the ones that have not.

**Timing.** This phase runs last, on the final `main`, after any bonus work is merged, so the drills,
the screenshots and the runbook all describe the system that is submitted. If HTTPS is merged, every
`curl.exe` command below needs `-k` (self-signed certificate) and the `https://` address; they are
written that way.

---

## 1. The drills

| # | Scenario | Status | Who runs it |
|---|---|---|---|
| 1 | Application process dies on one instance | **done** (phase 6 drill) | — |
| 2 | Burst of application errors | **done** (phase 6, `load.py --errors`) | — |
| 3 | Database unreachable | **done by accident** (phase 5, `ProtectHome`); repeat on purpose below | owner |
| 4 | A release that cannot boot | **new** | owner |
| 5 | Infrastructure drift (someone changes AWS by hand) | **new**, combined with 3 | owner |

Claude Code prepares the drill branch and writes the runbook. The owner runs the drills on AWS and
reports what was seen; the runbook is then corrected to match.

---

## 2. One fix before the drills: fail fast when the database is down

The design says a database outage degrades the service without taking it down, and the health check
is shallow for that reason. There is still a way for the outage to take the service down, and the
drill would find it the hard way:

- Each instance runs two gunicorn workers, each handling one request at a time.
- When the database is unreachable at the network level, every request that touches it waits for
  the connect timeout (5 seconds) before failing.
- With even modest traffic, both workers are permanently stuck waiting. The load balancer's health
  check then waits in the queue behind them, times out, and marks the instance unhealthy.
- The Auto Scaling Group replaces healthy instances because the *database* is down. This is exactly
  the loop the shallow health check was meant to prevent.

**The fix (Claude Code), in `app/db.py`:** a small circuit breaker.

- After a connection attempt fails, remember the time (per process). For the next 15 seconds, any
  operation that needs the database raises the existing storage error immediately, without trying to
  connect. After 15 seconds, one attempt is allowed through; success clears the state.
- Lower `connect_timeout` from 5 to 3 seconds.
- Authentication failures keep their existing behaviour (refresh the password, retry once) and do not
  open the breaker on the first failure.
- Log one `WARNING`, `event: "db_circuit_open"`, when the breaker opens, not one per request.
- Tests: after a simulated connection failure, the next calls fail without a connection attempt; after
  the window, one attempt is made; success closes it; `/health` is unaffected throughout.
- README: one sentence under the health-check decision, and the production alternative (threaded or
  async workers, so slow dependencies cannot starve the health check).

**The idea, in one line:** a circuit breaker stops calling a dependency that is known to be down, so
its slowness cannot spread to everything else.

This goes to `main` and is deployed before the drills.

---

## 3. Drill 4: a release that cannot boot

**The question it answers:** what happens when a broken build is deployed? The design (phase 5,
section 5) says the rolling refresh replaces one instance at a time, and because the warm-up is longer
than the grace period, a replacement that cannot boot is caught before the second instance is touched.
The site should stay up on the old instance throughout. This drill proves it.

### Preparation (Claude Code)

On a branch `drill/broken-release`, add one file, `app/drill_broken.py`:

```python
"""Deliberately invalid. Exists only on the drill/broken-release branch."""
def broken(:
```

That is all. The boot script compiles the release with `compileall` before starting the service, so
this fails the boot at a known step with a clear message, without touching any real code. Commit it on
the branch. Never merge the branch. Linters and the test collection may complain about this file on
this branch; that is expected and is the point.

### Running it (owner)

With the stack up, on `main`, both instances healthy:

```powershell
git switch drill/broken-release
cd infra\app
terraform plan     # expect: new S3 object (new release), launch template and group updated in place
terraform apply
```

In a second terminal, start a request loop before the refresh begins and leave it running:

```powershell
$url = terraform output -raw alb_url
1..150 | ForEach-Object { $r = curl.exe -sk -o NUL -w "%{http_code}" "$url/health"; "$(Get-Date -Format HH:mm:ss) $r"; Start-Sleep 5 }
```

### What should be seen

| When | Where | What |
|---|---|---|
| ~1 min | EC2 → Auto Scaling Groups → Instance refresh | refresh `InProgress`, one new instance launching |
| ~2 min | log group `/phishing-detector/boot`, the new instance's stream | the `compileall` error naming `drill_broken.py`, and no `user_data finished OK` |
| ~3–4 min | email | `unhealthy-targets` ALARM |
| ~4–5 min | Activity tab of the group | the new instance terminated for failing health checks, another launched in its place, which fails the same way |
| throughout | the request loop | **every line `200`**, from the instance still on the old release |
| throughout | `/health` | the old release ID only |

The refresh does not proceed to the second instance. It stays `InProgress` while the group keeps
replacing the broken one.

**Abort rule.** This behaviour is designed, not yet observed. If the request loop starts printing
anything other than `200`, or `/health` stops answering, the refresh has moved on to the second
instance: go straight to Recovery, and record it as a finding. The worst case is a few minutes of
downtime on a demo system, which is what a drill is for.

### Recovery

```powershell
aws autoscaling cancel-instance-refresh --profile phishing --auto-scaling-group-name (terraform output -raw asg_name)
git switch main
terraform apply
```

The apply on `main` puts back the previous release; it starts a new refresh, which now succeeds.
Keep the request loop running through the recovery as well: it should stay at `200`. Watch the alarm
return to OK. Record the times in `BUILD_LOG.md`.

**Do not leave the drill running.** Each failed instance is billed for the minutes it runs, and the
loop of replacements continues until the refresh is cancelled.

### What production adds

The instance refresh supports automatic rollback tied to CloudWatch alarms: if a named alarm fires
during the refresh, the group stops and returns to the previous launch template version on its own.
It is not enabled here because `unhealthy-targets` fires during every normal refresh (a new instance
is registered before it finishes booting), so it would roll back every deploy; it would need its own
alarm on 5XX or on failed boots. Say so in the runbook.

---

## 4. Drills 3 and 5: the database becomes unreachable, and the drift is repaired

**The questions:** what does the user see when the application cannot reach the database, how does
the operator find out, and what happens when someone changes infrastructure by hand?

The failure is created by **removing the security group rule that lets the instances reach the
database**, in the console. It is safe: nothing is deleted, the database keeps running, and Terraform
puts the rule back.

### Running it (owner)

1. Console → EC2 → Security Groups → the database's group (`phishing-detector-db-…`) → Inbound rules →
   **Edit inbound rules** → delete the rule on port 5432 → Save.
2. In the browser: scan a file. The result appears, with the notice that it could not be saved.
   Open History: the friendly 503 page.
3. Logs Insights, saved query `errors`: `save_failed` and `history_unavailable` lines with a
   connection timeout.
4. Within a few minutes, if enough requests fail, the `target-5xx` alarm fires (`/history` answers 503,
   which the load balancer counts as a target 5XX). With only a few clicks it may stay below the
   threshold; that is also a finding worth writing down.
5. Now add traffic for one minute, with the database still unreachable:
   ```powershell
   python ..\..\scripts\load.py --url $url --insecure --seconds 60
   ```
   Scans return 200 (analysed, not saved). Afterwards check the target group: **both targets still
   healthy, no instance replaced.** This is the shallow health check and the circuit breaker doing
   their job together. If a target went unhealthy, that is a finding: stop and report it.
6. Repair:
   ```powershell
   cd infra\app
   terraform plan
   ```
   The plan shows the missing rule to be **created**. That is drift detection: Terraform compared the
   real account with the code and found a difference. `terraform apply` restores it. Scan again: saved.

### Where the rule lives

The ingress rule on the database's security group is created by `infra/app` (`security.tf`), even
though the group itself is in `infra/base`. So `plan` in `infra/app` detects it. Mention this in the
runbook: drift is only detected for what the stack manages.

---

## 5. The runbook (README section 6)

Replace the TODO with a runbook built from `BUILD_LOG.md` and the drills. One entry per scenario, each
in the same six parts, short enough to follow during an incident:

| Part | Content |
|---|---|
| **Signal** | the alarm, email or symptom that starts it |
| **Why it happens** | one or two plain sentences on the mechanism, so the entry teaches as well as instructs |
| **First look** | the one place to look first, with the exact console path or saved query |
| **Likely causes** | in order of likelihood, each with how to confirm it |
| **Fix** | the commands or the change, always through Terraform or a release, never by editing an instance |
| **Verify** | how to know it is over |

Scenarios, in this order:

1. Targets unhealthy (an instance or its process is down)
2. Application errors (target 5XX)
3. Load balancer errors (ELB 5XX: no healthy targets, or targets dropping connections)
4. A deploy that does not boot (drill 4)
5. Database unreachable (drill 3)
6. An instance that never becomes healthy after launch: the phase 4 debugging order, condensed, now
   starting from the boot log group instead of Session Manager
7. High CPU or memory (including the CPU credit balance on `t3`)
8. Alarm fired but no email (subscription not confirmed)
9. Infrastructure drift (drill 5)
10. Availability zone failure: not drilled, described: what keeps working and what does not, given
    the current NAT design. Keep this entry accurate to whatever the NAT design is at the time of
    writing.

Before the scenarios, a short **"General approach"** paragraph: symptom first, then the narrowest
log or metric that explains it, one change at a time, every fix through code, and every incident
written in BUILD_LOG.

After the scenarios, a **"What is not covered"** line: no paging or on-call rotation, no synthetic
checks from outside AWS, no automatic rollback.

Every command in the runbook must have been run at least once in this project, or be marked "not
run". Every console path must name real resource names from the code.

---

## 6. Done when

- the database circuit breaker is in `main`, tested and deployed;
- drill 4 run: the site stayed up, the broken instance was identified from the boot log group, and the
  recovery worked; times recorded in BUILD_LOG;
- drills 3 and 5 run: degraded behaviour observed, drift shown in `plan` and repaired;
- the runbook in the README has all ten entries, matching what was observed;
- the `drill/broken-release` branch exists on the remote but is not merged, and its existence is
  mentioned in the runbook as the way to repeat the drill.
