# The private-app subnets' way out: one NAT gateway, and a default route to it from each of
# the route tables infra/base created without one.

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${var.project}-nat"
  }
}

# In a public subnet, not a private one: the gateway that gives private instances a way out
# must itself sit where there is a route to the internet gateway.
#
# One gateway, in the first availability zone, serves both. If that zone fails, the instance
# in the other keeps serving through the load balancer but loses its way out, and a
# replacement cannot boot. Production would run one per zone.
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = local.base.public_subnet_ids[0]

  tags = {
    Name = "${var.project}-nat"
  }
}

# The routes live here rather than in infra/base so that destroying this stack removes them,
# and the route tables go back to having no way out.
resource "aws_route" "private_app_nat" {
  for_each = local.base.private_app_route_table_ids

  route_table_id         = each.value
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main.id
}
