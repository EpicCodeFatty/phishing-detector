# The public entry point: an Application Load Balancer across both availability zones. It
# answers HTTPS on 443, where TLS ends, and forwards to the instances as plain HTTP on the
# application port; port 80 only redirects to 443.

locals {
  # TLS 1.3 and 1.2 only: nothing older is offered to a client.
  tls_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

resource "aws_lb" "main" {
  #checkov:skip=CKV_AWS_91:Access logs need an S3 bucket with an ELB delivery policy; ALB metrics and the app log answer the questions
  #checkov:skip=CKV_AWS_150:Deletion protection off on purpose; this stack is destroyed at the end of every working session
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

# Where TLS ends ("TLS termination"): the load balancer decrypts, and from here to the
# instances the traffic is HTTP on the application port inside the VPC, as it always was. One
# place holds the certificate, and the instances do not change. The health check is likewise
# unchanged: HTTP, straight to the application port.
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = local.https_port
  protocol          = "HTTPS"
  ssl_policy        = local.tls_policy
  certificate_arn   = aws_acm_certificate.alb.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# Port 80 stays open only to answer "use HTTPS instead": a 301 to the same host, path and
# query on 443. A client that follows a 301 repeats a POST as a GET, so an upload sent here
# uploads nothing: whatever posts (scripts/load.py, API callers) must be given the https://
# address.
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = local.http_port
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = tostring(local.https_port)
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
