# The VPC, split into three tiers across two availability zones:
#
#   public       10.0.1.0/24   10.0.2.0/24    load balancer and NAT gateway only
#   private-app  10.0.21.0/24  10.0.22.0/24   the instances; NAT route added by infra/app
#   private-db   10.0.11.0/24  10.0.12.0/24   the database; no route out at all
#
# Two tiers would satisfy the assignment. The third costs nothing and means even a
# compromised instance cannot use the database's subnet to reach the internet.

data "aws_availability_zones" "available" {
  state = "available"

  # Only the region's regular zones, never a Local Zone the account has opted into.
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  # The first two zones, by name. Never hard-coded: zone names are per-account aliases.
  availability_zones = slice(sort(data.aws_availability_zones.available.names), 0, 2)

  # Each subnet is a /24 of the /16 VPC; these are its third octet, one per zone.
  subnet_newbits = 8
  subnet_numbers = {
    public      = [1, 2]
    private_app = [21, 22]
    private_db  = [11, 12]
  }

  # tier -> availability zone -> CIDR, e.g. subnet_cidrs.public["eu-north-1a"] = "10.0.1.0/24".
  subnet_cidrs = {
    for tier, numbers in local.subnet_numbers : tier => {
      for index, zone in local.availability_zones :
      zone => cidrsubnet(var.vpc_cidr, local.subnet_newbits, numbers[index])
    }
  }
}

resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr

  # Both needed. enable_dns_hostnames is the one easy to miss, and confusing when missed:
  # without it the RDS endpoint does not resolve inside the VPC, and the application fails
  # with what looks like a network problem.
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = var.project
  }
}

# The VPC's default security group allows all traffic between its members. Nothing uses
# it, and declaring it without rules strips them, so nothing can ever rely on it by accident.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project}-default-unused"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = var.project
  }
}

# ------------------------------------------------------------------------------ Subnets
#
# for_each keyed by zone name rather than count: with count, removing the first subnet
# renumbers the rest, and Terraform replaces subnets that did not change.

resource "aws_subnet" "public" {
  for_each = local.subnet_cidrs.public

  vpc_id            = aws_vpc.main.id
  availability_zone = each.key
  cidr_block        = each.value

  # Nothing here gets a public address by default. The load balancer and the NAT gateway
  # are given theirs explicitly.
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project}-public-${trimprefix(each.key, var.region)}"
    Tier = "public"
  }
}

resource "aws_subnet" "private_app" {
  for_each = local.subnet_cidrs.private_app

  vpc_id            = aws_vpc.main.id
  availability_zone = each.key
  cidr_block        = each.value

  tags = {
    Name = "${var.project}-private-app-${trimprefix(each.key, var.region)}"
    Tier = "private-app"
  }
}

resource "aws_subnet" "private_db" {
  for_each = local.subnet_cidrs.private_db

  vpc_id            = aws_vpc.main.id
  availability_zone = each.key
  cidr_block        = each.value

  tags = {
    Name = "${var.project}-private-db-${trimprefix(each.key, var.region)}"
    Tier = "private-db"
  }
}

# ------------------------------------------------------------------------- Route tables
#
# Routes are separate aws_route resources, never inline `route` blocks. Inline blocks are
# authoritative: they would delete the NAT route that infra/app adds to the private-app
# tables on every apply of this stack. A table with no `route` argument leaves routes alone.

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project}-public"
    Tier = "public"
  }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# One table per zone, created without a default route; infra/app adds 0.0.0.0/0 to the NAT
# gateway. Per zone rather than shared, so a NAT gateway per zone later changes one stack.
resource "aws_route_table" "private_app" {
  for_each = aws_subnet.private_app

  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project}-private-app-${trimprefix(each.key, var.region)}"
    Tier = "private-app"
  }
}

resource "aws_route_table_association" "private_app" {
  for_each = aws_subnet.private_app

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private_app[each.key].id
}

# No routes beyond the implicit local one. Created explicitly rather than relying on the
# VPC's main table, so a later change to the main table cannot give the database a way out.
resource "aws_route_table" "private_db" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project}-private-db"
    Tier = "private-db"
  }
}

resource "aws_route_table_association" "private_db" {
  for_each = aws_subnet.private_db

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private_db.id
}
