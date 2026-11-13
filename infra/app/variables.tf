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
  description = "What the Auto Scaling Group goes by when replacing an instance: EC2 (status checks only) or ELB (the load balancer's health check as well)."
  default     = "EC2"

  validation {
    condition     = contains(["EC2", "ELB"], var.health_check_type)
    error_message = "health_check_type must be \"EC2\" or \"ELB\"."
  }
}

variable "allowed_ingress_cidrs" {
  type        = list(string)
  description = "IPv4 ranges allowed to reach the load balancer on port 80. One security group rule per entry."
  default     = ["0.0.0.0/0"]
}
