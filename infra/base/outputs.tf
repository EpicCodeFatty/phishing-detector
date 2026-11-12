# Everything infra/app reads through terraform_remote_state. Anything missing here means
# editing two stacks later.
#
# Nothing is marked sensitive: these are identifiers, not secrets. db_secret_arn says where
# the password lives, not what it is; marking it sensitive would only hide it from
# `terraform output`, while it stays in state regardless.

# ------------------------------------------------------------------------------ Network

output "vpc_id" {
  description = "The VPC."
  value       = aws_vpc.main.id
}

output "availability_zones" {
  description = "The two zones in use, in order, so infra/app places resources in the same ones."
  value       = local.availability_zones
}

output "public_subnet_ids" {
  description = "Public subnets, ordered by availability zone. For the load balancer and the NAT gateway."
  value       = [for zone in local.availability_zones : aws_subnet.public[zone].id]
}

output "private_app_subnet_ids" {
  description = "Private application subnets, ordered by availability zone. For the instances."
  value       = [for zone in local.availability_zones : aws_subnet.private_app[zone].id]
}

output "private_db_subnet_ids" {
  description = "Private database subnets, ordered by availability zone."
  value       = [for zone in local.availability_zones : aws_subnet.private_db[zone].id]
}

output "private_app_route_table_ids" {
  description = "Availability zone -> private-app route table, for infra/app to add the NAT route to."
  value       = { for zone, table in aws_route_table.private_app : zone => table.id }
}

# ----------------------------------------------------------------------------- Database

output "db_endpoint" {
  description = "Database host name, without the port."
  value       = aws_db_instance.main.address
}

output "db_port" {
  description = "Database port."
  value       = aws_db_instance.main.port
}

output "db_name" {
  description = "Name of the application's database."
  value       = aws_db_instance.main.db_name
}

output "db_username" {
  description = "Master user name."
  value       = aws_db_instance.main.username
}

output "db_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the master password. The ARN only, never the secret."
  value       = aws_db_instance.main.master_user_secret[0].secret_arn
}

output "db_security_group_id" {
  description = "The database security group, for infra/app to add the ingress rule from the application."
  value       = aws_security_group.db.id
}

# ------------------------------------------------------------------------ Notifications

output "sns_topic_arn" {
  description = "Topic the alarms in infra/app notify."
  value       = aws_sns_topic.alerts.arn
}
