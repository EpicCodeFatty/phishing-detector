# Every value that might change. All have defaults, so a plain `terraform apply` works
# without a .tfvars file. project, region and aws_profile must match infra/base.

variable "project" {
  type        = string
  description = "Name prefix for every resource, and the value of the Project tag."
  default     = "phishing-detector"
}

variable "region" {
  type        = string
  description = "AWS region. Fixed to eu-north-1 by the account's project-based sign-up."
  default     = "eu-north-1"
}

variable "aws_profile" {
  type        = string
  description = "AWS CLI profile holding the temporary credentials from `aws login`."
  default     = "phishing"
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type. Must be x86_64 to match the AMI, and burstable (t3) for the credit setting."
  default     = "t3.micro"
}

variable "asg_size" {
  type        = number
  description = "Number of instances. Minimum, maximum and desired are all this value: the group heals, it does not scale."
  default     = 2
}

variable "health_check_type" {
  type        = string
  description = "What the Auto Scaling Group goes by when replacing an instance: ELB (the load balancer's health check as well, the normal mode) or EC2 (status checks only, for debugging a boot: instances stay up however broken)."
  default     = "ELB"

  validation {
    condition     = contains(["EC2", "ELB"], var.health_check_type)
    error_message = "health_check_type must be \"EC2\" or \"ELB\"."
  }
}

variable "health_check_grace_seconds" {
  type        = number
  description = "How long a new instance is protected from being replaced for failing the load balancer's health check. Keep it at least 60 seconds longer than a measured boot."

  # A measured boot takes 118 seconds (cloud-init: "Up 118.51 seconds"); 118 + 60, rounded up.
  default = 180
}

variable "instance_warmup_seconds" {
  type        = number
  description = "How long an instance refresh waits after launching a replacement before moving on to the next instance. Keep it at least 60 seconds longer than the grace period."

  # The grace period plus 60.
  default = 240

  # Inside the grace period the group treats every instance as healthy. A refresh that moved
  # on within it would take a release that cannot boot for healthy and replace the last
  # working instance too: a full outage caused by a deploy.
  validation {
    condition     = var.instance_warmup_seconds > var.health_check_grace_seconds
    error_message = "instance_warmup_seconds must be greater than health_check_grace_seconds."
  }
}

variable "allowed_ingress_cidrs" {
  type        = list(string)
  description = "IPv4 ranges allowed to reach the load balancer, on port 443 and on port 80, which only redirects. One security group rule per entry and port."
  default     = ["0.0.0.0/0"]
}

variable "enable_error_simulation" {
  type        = bool
  description = "Whether /simulate-error raises a deliberate 500. It exists for the demo, to fire the 5XX alarm on demand, and is on for the review. The application's own default is off, and a production deployment would not have the route at all."
  default     = true
}
