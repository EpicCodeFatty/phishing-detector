# Demo runbook

The checklist for the live demo, in order. Commands are PowerShell, from the repository root unless
a step says otherwise. The times quoted from the drills are UTC; the console may show local time.
Background for every step is in the [README](../README.md).

## Before: about 20 minutes ahead

- [ ] **Sign in.** The credentials last 12 hours.

  ```powershell
  aws login --profile phishing
  ```

- [ ] **Check that `infra/base` is up.** The plan must say "No changes". If it wants to create
  resources, the base stack is gone, and the database and the cache each take about ten minutes to
  create: there is no time for that.

  ```powershell
  cd infra\base
  terraform plan
  ```

- [ ] **Apply `infra/app`.**

  ```powershell
  cd ..\app
  terraform apply
  ```

  How long it takes: `BUILD_LOG.md` does not record a whole apply. It records a boot of 76 seconds
  since the switch to unlimited CPU credits, and that the apply waits until both instances pass the
  health check, giving up after 12 minutes. Starting 20 minutes ahead leaves room for a second
  apply.

- [ ] **Wait for 2 healthy targets.** The apply returns only once both pass. Check anyway:

  ```powershell
  aws elbv2 describe-target-health --profile phishing --target-group-arn (terraform output -raw target_group_arn)
  ```

  Both targets must read `healthy`. An `unhealthy-targets` ALARM email and its OK email during the
  apply are expected: new instances fail the check until their boot ends.

- [ ] **Open the site once and accept the warning in advance.** `terraform output -raw alb_url`,
  open it in the browser, then Advanced, then Continue.

- [ ] **Open the tabs.** The dashboard (`terraform output -raw dashboard_url`) with a 1-hour range;
  CloudWatch → Alarms; CloudWatch → Logs Insights → Saved queries; EC2 → Target groups → `phish-…`
  → Targets; EC2 → Auto Scaling groups → `phishing-detector-app` → Activity.

- [ ] **Second terminal,** in `infra\app`, ready for the health loop:

  ```powershell
  $url = terraform output -raw alb_url
  ```

## Say before opening the browser

"The browser will warn first. The certificate is self-signed: this project has no domain, so no
certificate authority will issue one. Terraform generates a certificate for the load balancer's name
and imports it into ACM. The encryption is real, TLS 1.2 and 1.3 only; what is missing is proof of
identity. A production setup would use a domain in Route 53 and a certificate issued by ACM, whose
private key never leaves AWS, and would add `Strict-Transport-Security`."

## Walkthrough

1. **Scan a phishing sample.** On the Scan page, upload
   [`samples/paypal-phish.eml`](../samples/paypal-phish.eml). Expect **Phishing**. Point at:
   - the score, and the "Decided by" line: critical findings decide on their own;
   - the findings, by category: a link whose text shows a PayPal domain but points elsewhere, a
     lookalike sender domain, a display name that claims PayPal, a failed DMARC check, an executable
     attachment with a double extension;
   - "Served by": the instance ID that answered.
2. **Scan a clean one.** Upload [`samples/paypal-receipt.eml`](../samples/paypal-receipt.eml), from
   the same brand. Expect **Safe**, with no findings.
3. **The cache.** Upload `paypal-phish.eml` again. The result says "Served from cache — scanned
   before, result reused", and the Seen card shows "N×": how often this exact email was scanned in
   the last 24 hours, counted across both instances.
4. **History.** Every scan, newest first, with the instance that served it and the "cached" marker.
5. **The dashboard,** row by row: healthy targets and the group; CPU, credits, memory and disk;
   requests; status codes and response time; the logs; the cache; alarm status. To fill rows 3 and
   4, send traffic for a minute; the data shows a minute or two later:

   ```powershell
   python ..\..\scripts\load.py --url $url --insecure
   ```

6. **The alarms.** CloudWatch → Alarms: the five `phishing-detector-…` alarms, actions enabled. To
   fire one live (the email comes about 3 minutes later):

   ```powershell
   python ..\..\scripts\load.py --url $url --insecure --errors 10
   ```

7. **One saved query.** Logs Insights → `phishing-detector/cache-hit-ratio` → Run. Hits against
   misses, and `analysis_ms`: the time in the engine on a miss against the time in the cache on a
   hit.

## One live drill: self-heal

1. **Start the health loop** in the second terminal:

   ```powershell
   1..150 | ForEach-Object { $r = curl.exe -sk -o NUL -w "%{http_code}" "$url/health"; "$(Get-Date -Format HH:mm:ss) $r"; Start-Sleep 2 }
   ```

2. **Stop the service on one instance.** EC2 → Instances → one `phishing-detector-app` instance →
   Connect → Session Manager:

   ```bash
   date -u; sudo systemctl stop phishing-app
   ```

3. **Point at each step.** The times are from drill 11, where the service was stopped at 23:07:53.

   | Where | What to see | Drill 11 |
   |---|---|---|
   | The health loop | a few 502s, then only 200s from the other instance | three 502s between 23:07:57 and 23:08:04; about 10 seconds of partial errors |
   | Target group → Targets | the instance unhealthy | about 23:08 |
   | Auto Scaling group → Activity | terminated for "ELB system health check failure", a new instance launched | 23:09:16 and 23:09:18, about 80 seconds after the failure |
   | Email | `unhealthy-targets` ALARM, then OK | ALARM at about 23:10, OK a few minutes later |
   | Dashboard, row 1 | In service drops and Pending rises, then both return | |

4. **Say:** no manual action was needed. The replacement happened before anyone would have looked,
   and nothing pages on an Auto Scaling replacement by itself; an EventBridge rule on Auto Scaling
   events would (not built).
5. **Wait for 2 healthy targets** before going on.

## Numbers to remember

From [`screenshots/notes.txt`](screenshots/notes.txt) and `BUILD_LOG.md`. Times are UTC.

- **Load test:** 600 requests, all 200, split 300 and 300. Client p50 423 ms, p95 591 ms. Server p50
  about 40 ms, p95 up to about 88 ms. The difference is the network and TLS.
- **5XX alarm:** 10 errors at 21:46, ALARM at 21:49:02 (about 3 minutes of metric delay), OK at
  21:55:02. Both emails arrived.
- **Cache:** 96.6% hit ratio (589 of 610 scans). `analysis_ms` 18.6 ms on a miss, 1.8 ms on a hit,
  about 10 times less. Compare `analysis_ms`, not the whole request: the miss average includes
  warm-up.
- **Rejected traffic:** 6,868 records in 3 hours, none reached an instance. The top 4 sources are
  the instances' own NTP, blocked by egress; time syncs through 169.254.169.123 (reach 377, offset
  about 10 µs).
- **Self-heal:** about 10 seconds of partial errors; instance replaced about 80 seconds after the
  failure.
- **Database unreachable:** `/health` stayed 200, nothing replaced; saving back within about 15
  seconds of the fix.
- **Broken release:** a new instance replaced about every 6 minutes; the old one served throughout,
  the loop at 200.
- **Boot:** 76 seconds with unlimited CPU credits; 118, 203 and 298 seconds with standard.

## After

1. **Destroy `infra/app` and verify.** In `infra\app`:

   ```powershell
   terraform destroy
   terraform state list
   aws resourcegroupstaggingapi get-resources --profile phishing --tag-filters Key=Stack,Values=app --query "ResourceTagMappingList[].ResourceARN"
   aws logs describe-log-groups --profile phishing --log-group-name-prefix /phishing-detector --query "logGroups[].logGroupName"
   ```

   `state list` prints nothing; both queries return empty lists. The tag query can go on listing
   terminated instances and deleted NAT gateways for a while; check such an entry in its own
   console.

2. **Destroy `infra/base`**, once nothing else needs the database, and verify by the project tag:

   ```powershell
   cd ..\base
   terraform destroy
   terraform state list
   aws resourcegroupstaggingapi get-resources --profile phishing --tag-filters Key=Project,Values=phishing-detector --query "ResourceTagMappingList[].ResourceARN"
   ```

3. **Record the result** at the `CLEANUP RESULT` marker in README section 8.
