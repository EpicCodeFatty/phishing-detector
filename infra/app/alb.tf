# The public entry point: an Application Load Balancer across both availability zones,
# forwarding to the instances on the application port.

resource "aws_lb" "main" {
  #checkov:skip=CKV_AWS_91:Access logs need an S3 bucket with an ELB delivery policy; ALB metrics and the app log answer the questions
  #checkov:skip=CKV_AWS_150:Deletion protection off on purpose; this stack is destroyed at the end of every working session
  #checkov:skip=CKV2_AWS_20:No domain, so no certificate and no HTTPS listener to redirect to; HTTPS is a planned bonus
  #checkov:skip=CKV2_AWS_28:No WAF; about $5 a month plus per rule, and uploads are already capped at 5 MB by the app
  name               = "${var.project}-alb"
  load_balancer_type = "application"
  internal           = false

  # Both zones. With subnets in only one, a zone failure takes the service down regardless
  # of where the instances are.
  subnets         = local.base.public_subnet_ids
  security_groups = [aws_security_group.alb.id]

  # Malformed HTTP headers are discarded at the edge instead of being passed on.
  drop_invalid_header_fields = true

  # Off deliberately: this stack is destroyed at the end of every working session.
  enable_deletion_protection = false
}

# name_prefix and create_before_destroy: changing the port or protocol replaces the group.
# With a fixed name the new one cannot be created while the old one exists, and the old one
# cannot be deleted while the listener uses it, so the apply deadlocks on itself.
resource "aws_lb_target_group" "app" {
  #checkov:skip=CKV_AWS_378:HTTP from the load balancer to the instances stays inside the VPC, admitted only from alb-sg
  name_prefix = "phish-" # six characters is the limit
  port        = local.app_port
  protocol    = "HTTP"
  vpc_id      = local.base.vpc_id
  target_type = "instance"

  # Short intervals for the demo: a new instance is in service about twenty seconds after
  # it starts answering, and a terminated one shows quickly. Production would use longer
  # values, and a longer deregistration delay.
  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  deregistration_delay = 30

  lifecycle {
    create_before_destroy = true
  }
}

# Plain HTTP, deliberately: there is no domain for this project, so there is no certificate
# to attach. With a domain this becomes an HTTPS listener, and this one a redirect to it.
resource "aws_lb_listener" "http" {
  #checkov:skip=CKV_AWS_2:No domain for this exercise, so no certificate; HTTPS is a planned bonus
  #checkov:skip=CKV_AWS_103:Same reason; a TLS policy applies only to HTTPS listeners
  load_balancer_arn = aws_lb.main.arn
  port              = local.http_port
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
