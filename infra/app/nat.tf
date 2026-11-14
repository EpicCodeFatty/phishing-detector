# The private-app subnets' way out: one NAT gateway per availability zone, and in each zone's
# route table a default route to the gateway of that same zone. infra/base created the
# tables without one.

locals {
  # Availability zone -> public subnet. infra/base gives the public subnets as a list in the
  # same order as its list of zones, and the private-app route tables as a map keyed by zone
  # name. With the subnets keyed the same way, the zone name is the for_each key of
  # everything in this file, so aws_nat_gateway.main[each.key] in a route is always the
  # gateway of that route's own zone.
  public_subnet_by_zone = zipmap(local.base.availability_zones, local.base.public_subnet_ids)
}

resource "aws_eip" "nat" {
  for_each = local.public_subnet_by_zone

  domain = "vpc"

  tags = {
    Name = "${var.project}-nat-${trimprefix(each.key, var.region)}"
  }
}

# In a public subnet, not a private one: the gateway that gives private instances a way out
# must itself sit where there is a route to the internet gateway.
#
# One per zone. With a single gateway, losing its zone would leave the instance in the other
# zone serving through the load balancer but with no way out: its logs and metrics would
# stop, nobody could connect to it, and a replacement could not boot. The second gateway
# costs about $1.10 a day, plus its address, while the stack runs.
resource "aws_nat_gateway" "main" {
  for_each = local.public_subnet_by_zone

  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = each.value

  tags = {
    Name = "${var.project}-nat-${trimprefix(each.key, var.region)}"
  }
}

# The routes live here rather than in infra/base so that destroying this stack removes them,
# and the route tables go back to having no way out.
resource "aws_route" "private_app_nat" {
  for_each = local.base.private_app_route_table_ids

  route_table_id         = each.value
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[each.key].id
}
