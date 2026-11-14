# The result cache: one small Valkey node, encrypted, private, behind an AUTH token.
#
# Here rather than in infra/app for the same reason as the database: it takes about ten
# minutes to create, which would otherwise be added to every apply of infra/app, the live
# deploy in the review included.
#
# Optional by design. The application carries on without it, slower but whole, so one node
# with no replica and no snapshots is enough. That is a different answer from the database's
# for a different reason: the database is single-zone to save cost, although losing it does
# cost something (history and saving stop); losing the cache costs nothing but time.

# The private-db subnets, like the database: no route out of the VPC at all.
resource "aws_elasticache_subnet_group" "cache" {
  name        = "${var.project}-cache"
  description = "The private-db subnets, which have no route out of the VPC."
  subnet_ids  = [for subnet in aws_subnet.private_db : subnet.id]
}

# Created with no rules, like the database's group. infra/app adds the one ingress rule, port
# 6379 from the application's security group, as a separate rule resource: that group does
# not exist yet when this stack runs, and inline rules here would delete it on every apply.
resource "aws_security_group" "cache" {
  name_prefix = "${var.project}-cache-"
  description = "Cache: ingress added by infra/app from the app security group only"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project}-cache"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# The AUTH token. Alphanumeric only: ElastiCache accepts a few special characters in a token
# and refuses others, and leaving them all out avoids the question. 64 characters of 62
# symbols is far beyond guessing.
#
# The value is stored in this stack's state, which is local and git-ignored: an accepted
# demo trade-off, like the self-signed certificate's key in infra/app. Production would use
# ElastiCache's IAM authentication, where the application signs a short-lived token with its
# role and no long-lived secret exists at all.
resource "random_password" "cache_auth" {
  length  = 64
  special = false
}

# Where the instances read the token from, with their role. The token is never written to an
# instance: the environment file holds this secret's ARN only.
#
# recovery_window_in_days = 0: by default a deleted secret is kept for 7 to 30 days and its
# name stays taken, so destroying and recreating this stack would fail on the name. Zero
# deletes it at once. name_prefix keeps the name from being fixed in the first place.
resource "aws_secretsmanager_secret" "cache_auth" {
  #checkov:skip=CKV2_AWS_57:Rotating the AUTH token needs a coordinated update of the cluster and every instance; the cache is optional and rebuilt
  #checkov:skip=CKV_AWS_149:Encrypted with the AWS-managed aws/secretsmanager key; a customer-managed key adds a key policy and a monthly fee
  name_prefix             = "${var.project}-cache-auth-"
  description             = "AUTH token of the result cache. Read by the application instances' role."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "cache_auth" {
  secret_id     = aws_secretsmanager_secret.cache_auth.id
  secret_string = random_password.cache_auth.result
}

resource "aws_elasticache_replication_group" "cache" {
  #checkov:skip=CKV2_AWS_50:One node and no failover on purpose: the cache is optional, and when it is gone the service is slower, not down
  #checkov:skip=CKV_AWS_191:Encrypted at rest with the AWS-managed key; a customer-managed key adds a key policy and a monthly fee for rebuildable data
  replication_group_id = "${var.project}-cache"
  description          = "Result cache for the phishing detector"

  engine         = "valkey"
  engine_version = var.cache_engine_version
  node_type      = var.cache_node_type
  port           = local.cache_port

  # One node: a primary with no replica.
  num_cache_clusters         = 1
  automatic_failover_enabled = false
  multi_az_enabled           = false

  subnet_group_name  = aws_elasticache_subnet_group.cache.name
  security_group_ids = [aws_security_group.cache.id]

  # Both, and they go together: AWS accepts an AUTH token only with encryption in transit.
  # TLS keeps the token and the results off the network in the clear; the token means that
  # reaching the port is not enough to read the data.
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.cache_auth.result

  # Every entry expires within a day and can be recomputed, so there is nothing to back up.
  snapshot_retention_limit = 0

  # The parameter group is left at the engine's default. Every key has a time to live, so
  # when memory fills the engine evicts the least recently used of them by itself.

  apply_immediately = true

  tags = {
    Name = "${var.project}-cache"
  }
}

locals {
  # Valkey's standard port. infra/app reads it from the cache_port output, never a literal.
  cache_port = 6379
}
