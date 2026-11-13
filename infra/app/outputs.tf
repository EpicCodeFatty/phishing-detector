# What is needed to test the stack from a terminal, and what phase 5 builds on.

output "alb_dns_name" {
  description = "DNS name of the load balancer. It changes with every apply; read it from here each time."
  value       = aws_lb.main.dns_name
}

output "alb_url" {
  description = "Address of the service, ready to paste into curl or a browser."
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
  description = "The instance role, for phase 5 to attach its inline policies to."
  value       = aws_iam_role.app.name
}

output "nat_public_ip" {
  description = "The address the instances appear from on the internet, for reading third-party logs."
  value       = aws_eip.nat.public_ip
}
