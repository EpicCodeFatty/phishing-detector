# PostgreSQL for the scan history: one small, encrypted, private instance.

resource "aws_db_subnet_group" "main" {
  name        = "${var.project}-db"
  description = "The private-db subnets, which have no route out of the VPC."
  subnet_ids  = [for subnet in aws_subnet.private_db : subnet.id]

  tags = {
    Name = "${var.project}-db"
  }
}

# Created with no rules at all. infra/app adds the one ingress rule, port 5432 from the
# application's security group, as an aws_vpc_security_group_ingress_rule: that group does
# not exist yet when this stack runs. Rules are never inline `ingress` blocks here, because
# inline blocks are authoritative and each apply of this stack would delete infra/app's rule.
# With no egress rule either, the database cannot open a connection to anything; replies to
# connections made to it are still allowed, because security groups are stateful.
resource "aws_security_group" "db" {
  name        = "${var.project}-db"
  description = "PostgreSQL. Ingress from the application security group is added by infra/app."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.project}-db"
  }
}

resource "aws_db_instance" "main" {
  identifier     = "${var.project}-db"
  engine         = "postgres"
  engine_version = "16" # major version only; AWS selects the current minor
  instance_class = var.db_instance_class

  allocated_storage = var.db_allocated_storage
  storage_encrypted = true

  db_name  = var.db_name
  username = var.db_username # "phishing" is not a PostgreSQL reserved word

  # AWS generates the password, keeps it in Secrets Manager and rotates it. It never
  # appears in a variable, a .tfvars file or the state file, where Terraform would store
  # it in plain text. The application reads it at runtime with the instance role.
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false

  # Single-AZ to save cost, while the application tier spans two zones. The failure mode
  # is handled: /health does not touch the database, so an outage degrades the service
  # rather than taking the instances out of service.
  multi_az = false

  # The minimum that keeps automated backups on. Zero would disable them.
  backup_retention_period = 1

  # Both wrong for production and deliberate here: with either set the other way,
  # `terraform destroy` fails, and the assignment requires destroying and verifying.
  skip_final_snapshot = true
  deletion_protection = false

  apply_immediately = true

  tags = {
    Name = "${var.project}-db"
  }
}
