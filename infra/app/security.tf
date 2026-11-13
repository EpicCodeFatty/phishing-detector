# Three security groups in a chain, each admitting only the one before it:
#
#   alb-sg   in: 80 from var.allowed_ingress_cidrs    out: 8000 to app-sg
#   app-sg   in: 8000 from alb-sg                     out: 443 to anywhere, 5432 to db-sg
#   db-sg    in: 5432 from app-sg (rule added here; the group is in infra/base)
#
# Port 22 appears nowhere. Shell access is through Session Manager, which works over the
# instances' outbound 443.
#
# Every rule is its own resource, never an inline `ingress` or `egress` block. Inline blocks
# are authoritative for the whole group, so this stack and infra/base would each delete the
# other's rules on db-sg at every apply. A group declared without inline rules also has no
# egress at all, because Terraform removes the allow-all rule AWS adds; that is intended, and
# every permitted direction is written out below.

locals {
  http_port  = 80
  https_port = 443

  # The port the application listens on. deploy/user_data.sh.tftpl binds the same number.
  app_port = 8000
}

# ----------------------------------------------------------------------- Load balancer
#
# name_prefix and create_before_destroy on both groups: changing a description replaces the
# group, and with a fixed name the new one cannot be created while the old one is still
# attached to the load balancer or an instance.

resource "aws_security_group" "alb" {
  name_prefix = "${var.project}-alb-"
  description = "Load balancer. HTTP in from the internet, out to the application only."
  vpc_id      = local.base.vpc_id

  tags = {
    Name = "${var.project}-alb"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# The service is public by design. The variable exists so that it can be narrowed to known
# addresses without editing the rule.
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  for_each = toset(var.allowed_ingress_cidrs)

  security_group_id = aws_security_group.alb.id
  description       = "HTTP from the allowed address ranges"
  ip_protocol       = "tcp"
  from_port         = local.http_port
  to_port           = local.http_port
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Requests and health checks to the application"
  ip_protocol                  = "tcp"
  from_port                    = local.app_port
  to_port                      = local.app_port
  referenced_security_group_id = aws_security_group.app.id
}

# -------------------------------------------------------------------------- Application

resource "aws_security_group" "app" {
  name_prefix = "${var.project}-app-"
  description = "Application instances. In from the load balancer only, out over HTTPS and to the database."
  vpc_id      = local.base.vpc_id

  tags = {
    Name = "${var.project}-app"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "Requests and health checks from the load balancer"
  ip_protocol                  = "tcp"
  from_port                    = local.app_port
  to_port                      = local.app_port
  referenced_security_group_id = aws_security_group.alb.id
}

# 443 alone is enough: the AWS APIs (Session Manager, Secrets Manager, CloudWatch), the
# Amazon Linux 2023 repositories and PyPI are all HTTPS. DNS to the VPC resolver, the
# instance metadata service and the Amazon time service are not filtered by security groups
# and need no rule. If a boot ever fails at `dnf install`, check here first, and record any
# widening in the build log.
resource "aws_vpc_security_group_egress_rule" "app_https" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to AWS APIs, package repositories and PyPI, through the NAT gateway"
  ip_protocol       = "tcp"
  from_port         = local.https_port
  to_port           = local.https_port
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "app_to_db" {
  security_group_id            = aws_security_group.app.id
  description                  = "PostgreSQL to the database"
  ip_protocol                  = "tcp"
  from_port                    = local.base.db_port
  to_port                      = local.base.db_port
  referenced_security_group_id = local.base.db_security_group_id
}

# ----------------------------------------------------------------------------- Database
#
# The database's group belongs to infra/base, which creates it with no rules because the
# application's group does not exist yet at that point. Its one ingress rule is added here,
# and removed again when this stack is destroyed.

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = local.base.db_security_group_id
  description                  = "PostgreSQL from the application instances"
  ip_protocol                  = "tcp"
  from_port                    = local.base.db_port
  to_port                      = local.base.db_port
  referenced_security_group_id = aws_security_group.app.id
}
