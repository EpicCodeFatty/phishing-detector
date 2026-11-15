# Base infrastructure — design specification

`infra/base` holds what is created once and left running: the network, the database, and the
notification channel. It is applied ahead of the review, because RDS takes ten to fifteen minutes to
become available and nobody should watch that during a demo.

`infra/app` — the load balancer, the instances, the monitoring — is a separate stack applied live, and
it reads this stack's outputs.

Read `docs/design/code-standards.md` for naming and comment conventions; they apply to HCL as well.

---

## 1. Why two stacks

Everything here either takes minutes to create (RDS) or must survive the daily teardown (the email
subscription, which has to be confirmed by hand once). Everything in `infra/app` is cheap to create and
expensive to leave running, so it is destroyed at the end of each working day.

`infra/app` consumes this stack through `terraform_remote_state` pointing at the local state file. The
alternative — looking resources up by tag with data sources — avoids the file dependency but adds code
and a second source of truth. For a single-operator project the state file is simpler and the trade-off
is recorded in the README.

**The cost of this split:** two state files, and `app` breaks if `base` is destroyed first. The teardown
order is therefore always `app`, then `base`.

---

## 2. Layout

```
infra/base/
├── versions.tf     terraform and provider version constraints
├── providers.tf    the AWS provider, region and default tags
├── variables.tf    every value that might change
├── network.tf      VPC, subnets, internet gateway, route tables
├── rds.tf          subnet group, security group, database
├── sns.tf          notification topic and email subscription
└── outputs.tf      everything infra/app needs
```

One concern per file. `terraform` reads every `.tf` in the directory, so the split is for the reader.

---

## 3. Provider and versions

```hcl
terraform {
  required_version = "~> 1.17"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
  }
}
```

Pin both. An unpinned provider means a future `terraform init` can pick up a new major version and
change behaviour halfway through the project. Commit `.terraform.lock.hcl` — it is one of the few
Terraform files that belongs in git.

```hcl
provider "aws" {
  region  = var.region        # eu-north-1
  profile = var.aws_profile   # "phishing"

  default_tags {
    tags = {
      Project   = var.project   # "phishing-detector"
      ManagedBy = "terraform"
      Stack     = "base"
    }
  }
}
```

`default_tags` applies to every resource that supports tagging, without a `tags` block anywhere else.
This is what makes the post-teardown verification work: one query for everything carrying
`Project = phishing-detector`, rather than a checklist per service.

The region is `eu-north-1` and is not a choice. The account was created through AWS's project-based
sign-up, which assigns one region per project based on the contact address; selecting another would
require activating advanced features. The same region must appear in the provider, in the CLI profile,
and in the console.

---

## 4. Network (`network.tf`)

### Addressing

| Tier | AZ a | AZ b | Route out |
|---|---|---|---|
| public | `10.0.1.0/24` | `10.0.2.0/24` | internet gateway |
| private-app | `10.0.21.0/24` | `10.0.22.0/24` | NAT — **added by `infra/app`** |
| private-db | `10.0.11.0/24` | `10.0.12.0/24` | none |

VPC CIDR `10.0.0.0/16`, with `enable_dns_support` and `enable_dns_hostnames` both true. The second is
easy to miss and the failure it causes is confusing: without it the RDS endpoint does not resolve from
inside the VPC, and the application fails with a DNS error that looks like a networking problem.

### Availability zones

```hcl
data "aws_availability_zones" "available" {
  state = "available"
}
```

Take the first two. Never hard-code `eu-north-1a`: zone names are per-account aliases, and a hard-coded
one makes the configuration specific to this account for no benefit.

### Three tiers, and why

- **public** holds only the load balancer and the NAT gateway. Nothing that runs application code.
- **private-app** holds the instances. They have no public IP, so nothing on the internet can reach
  them directly — not merely blocked by a security group, but unreachable at the routing level.
- **private-db** holds the database and has no route to the internet at all. Even a compromised
  instance cannot use the database host to reach out.

Two tiers would be enough to satisfy the assignment. The third costs nothing and makes the blast radius
of a compromise visibly smaller, which is the kind of thing this reviewer will look for.

### Route tables

- **public** — one table, `0.0.0.0/0` to the internet gateway, associated with both public subnets.
- **private-app** — one table per AZ, created here with **no default route**. `infra/app` adds
  `0.0.0.0/0` to the NAT gateway. One table per AZ rather than one shared table: with `for_each` it is
  the same amount of code, and it means moving to a NAT per availability zone later is a change in one
  stack rather than a restructure.
- **private-db** — one table, no routes beyond the implicit local one, associated with both database
  subnets. Creating it explicitly rather than relying on the VPC's main route table means a later change
  to the main table cannot accidentally give the database a path out.

Use `for_each` over a map of subnets rather than `count`. With `count`, removing the first subnet
renumbers every one after it and Terraform destroys and recreates resources that did not change.

---

## 5. Database (`rds.tf`)

### Subnet group and security group

```hcl
resource "aws_db_subnet_group" "main" {
  subnet_ids = [for s in aws_subnet.private_db : s.id]
}
```

The security group is created here with **no ingress rules**. `infra/app` adds the rule allowing port
5432 from the application security group, using `aws_vpc_security_group_ingress_rule`, because that
group does not exist yet when this stack runs.

Keep ingress rules as separate resources rather than inline `ingress` blocks. Inline blocks are
authoritative: a second stack adding a rule to the same group fights with this one, and each `apply`
removes the other's rule.

### The instance

```hcl
resource "aws_db_instance" "main" {
  identifier     = "${var.project}-db"
  engine         = "postgres"
  engine_version = "16"               # major only; AWS selects the current minor
  instance_class = "db.t4g.micro"

  allocated_storage = 20
  storage_encrypted = true

  db_name  = var.db_name              # "phishing"
  username = var.db_username          # "phishing" — not a PostgreSQL reserved word

  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false

  multi_az                = false
  backup_retention_period = 1
  skip_final_snapshot     = true
  deletion_protection     = false
  apply_immediately       = true
}
```

Four of these settings are worth stating plainly, because each one is a decision:

**`manage_master_user_password = true`.** AWS generates the password, stores it in Secrets Manager and
rotates it. The password never appears in a variable, in a `.tfvars` file, or in the state file. Without
this the password would have to be passed in as a variable, and Terraform state stores variable values
in plain text — which is how most projects end up with a database password in a file.

The secret's ARN is at `aws_db_instance.main.master_user_secret[0].secret_arn`. It is a list because the
attribute is empty when the feature is off.

**`skip_final_snapshot = true` and `deletion_protection = false`.** Both are wrong for production and
right here. With either set the other way, `terraform destroy` fails — and the assignment explicitly
requires destroying and verifying. Say so in a comment so the choice reads as deliberate.

**`multi_az = false`.** The application tier spans two availability zones; the database does not. This is
a cost decision, and the failure mode is handled rather than ignored: the health check does not touch
the database, so a database outage degrades the service instead of taking the instances out of service.

**`backup_retention_period = 1`.** The minimum that still leaves automated backups enabled. Zero
disables them, which looks careless; seven costs storage for a project that lives four days.

### Performance monitoring

The assignment's performance bonus is answered from the ALB's `TargetResponseTime` percentiles, the RDS
CloudWatch metrics, and the `duration_ms` field already in the application's JSON logs.

---

## 6. Notifications (`sns.tf`)

```hcl
resource "aws_sns_topic" "alerts" { ... }

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
```

This lives in `base` rather than with the alarms in `app` for one practical reason: **an email
subscription must be confirmed by clicking a link, and Terraform cannot do that.** A topic recreated
with every `app` apply would need confirming again every time, and an unconfirmed subscription delivers
nothing — which would be discovered during the demo, when an alarm fires and no email arrives.

Created once here, the subscription is confirmed once and stays confirmed.

After the first apply, check the inbox and click the confirmation link. In the console the subscription
should read **Confirmed**, not **PendingConfirmation**.

---

## 7. Variables (`variables.tf`)

Every value with a type and a description. Defaults for everything except `alert_email`, so a plain
`terraform apply` works without a `.tfvars` file.

| Variable | Default |
|---|---|
| `project` | `phishing-detector` |
| `region` | `eu-north-1` |
| `aws_profile` | `phishing` |
| `vpc_cidr` | `10.0.0.0/16` |
| `db_name` | `phishing` |
| `db_username` | `phishing` |
| `db_instance_class` | `db.t4g.micro` |
| `db_allocated_storage` | `20` |
| `alert_email` | none — required |

Subnet CIDRs come from a `locals` block built on `var.vpc_cidr` with `cidrsubnet`, rather than nine
separate variables.

**No `terraform.tfvars` file in git.** `.gitignore` already excludes `*.tfvars`. Pass the email on the
command line, or keep a local `terraform.tfvars` that is never committed.

---

## 8. Outputs (`outputs.tf`)

`infra/app` reads all of these. Anything missing here means editing two stacks later.

```
vpc_id
public_subnet_ids               list, ordered by AZ
private_app_subnet_ids          list, ordered by AZ
private_db_subnet_ids           list
private_app_route_table_ids     map of AZ -> route table id   (for the NAT route)
availability_zones              list, so app places resources in the same AZs

db_endpoint                     host only, without the port
db_port
db_name
db_username
db_secret_arn                   master_user_secret[0].secret_arn
db_security_group_id

sns_topic_arn
```

`db_secret_arn` is the ARN, never the secret. Mark nothing here `sensitive`: these are identifiers, and
marking them sensitive only hides them from `terraform output` while they stay in state regardless.

---

## 9. Applying it

```bash
cd infra/base
terraform init
terraform fmt
terraform validate
terraform plan
```

**Read the plan before applying.** Expect roughly 20 resources and `0 to change, 0 to destroy`. Check
three things: the region on every resource is `eu-north-1`; no password appears anywhere in the output;
and the RDS instance is `db.t4g.micro`, not something larger.

```bash
terraform apply
```

Ten to fifteen minutes, almost all of it the database. Go and do something else.

**Verification:**

```bash
terraform output                                   # endpoint and ARNs present
aws rds describe-db-instances --profile phishing \
  --query 'DBInstances[0].[DBInstanceStatus,PubliclyAccessible,StorageEncrypted,MultiAZ]'
```

Expect `available`, `false`, `true`, `false`. Then confirm the SNS email and check the subscription
shows as confirmed.

**From this point the account costs roughly $0.40 a day** until `base` is destroyed. That is the
database, and it is why only this stack stays up.

---

## 10. What is deliberately not here

- **The NAT gateway.** It costs about $1.10 a day and is only useful while the instances exist, so it
  belongs in `infra/app` and is destroyed nightly with it. The route table it attaches to is created
  here; only the route and the gateway are added there.
- **VPC endpoints.** Interface endpoints for SSM, Secrets Manager and CloudWatch would let the instances
  reach those services without a NAT, which is the more secure pattern. They cost per endpoint per
  availability zone, which at this scale is more than the NAT, and they would not help with the one
  thing the instances also need: PyPI. Noted in the README as the production choice.
- **Anything to do with the instances.** Security groups for the application, IAM roles, the load
  balancer and the launch template all live in `infra/app`.
