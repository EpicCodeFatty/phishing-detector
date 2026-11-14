# What is needed to test the stack, a deployment and a teardown from a terminal, and to
# find the dashboard and the logs.

output "alb_dns_name" {
  description = "DNS name of the load balancer. It changes with every apply; read it from here each time."
  value       = aws_lb.main.dns_name
}

output "alb_url" {
  description = "Address of the service, over HTTPS. The certificate is self-signed: a browser warns first, and curl needs -k."
  value       = "https://${aws_lb.main.dns_name}"
}

output "alb_http_url" {
  description = "The same address over plain HTTP, for testing that port 80 answers with a redirect to HTTPS."
  value       = "http://${aws_lb.main.dns_name}"
}

output "asg_name" {
  description = "The Auto Scaling Group, for starting an instance refresh by hand."
  value       = aws_autoscaling_group.app.name
}

output "target_group_arn" {
  description = "The target group, for `aws elbv2 describe-target-health`."
  value       = aws_lb_target_group.app.arn
}

output "app_security_group_id" {
  description = "Security group of the application instances."
  value       = aws_security_group.app.id
}

output "instance_role_name" {
  description = "The role the instances run as."
  value       = aws_iam_role.app.name
}

output "nat_public_ips" {
  description = "Availability zone -> the address the instances in that zone appear from on the internet, for reading third-party logs."
  value       = { for zone, address in aws_eip.nat : zone => address.public_ip }
}

output "artifact_bucket" {
  description = "The private bucket holding the release zips."
  value       = aws_s3_bucket.artifacts.id
}

output "artifact_key" {
  description = "Key of the current release in the bucket: releases/app-<release>.zip."
  value       = aws_s3_object.release.key
}

output "release" {
  description = "The current release: the first 12 hex characters of the zip's SHA-256. /health reports the same value once the instances run it."
  value       = local.release
}

output "dashboard_url" {
  description = "The CloudWatch dashboard, ready to paste into a browser signed in to the account."
  value       = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards/dashboard/${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "app_log_group" {
  description = "Log group holding the application's JSON log lines, one stream per instance."
  value       = aws_cloudwatch_log_group.app.name
}

output "boot_log_group" {
  description = "Log group holding each instance's boot log (cloud-init-output.log). The first place to look when an instance never becomes healthy."
  value       = aws_cloudwatch_log_group.boot.name
}
