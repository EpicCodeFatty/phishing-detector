# Every value that might change. All have defaults except alert_email, so a plain
# `terraform apply -var alert_email=...` works without a .tfvars file. Never commit one:
# .gitignore excludes *.tfvars.

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

variable "vpc_cidr" {
  type        = string
  description = "Address range of the VPC. Every subnet is carved out of it in locals."
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrsubnet(var.vpc_cidr, 8, 0)) && endswith(var.vpc_cidr, "/16")
    error_message = "vpc_cidr must be a /16, so that each subnet is a /24 with the planned numbering."
  }
}

variable "db_name" {
  type        = string
  description = "Name of the database the application uses."
  default     = "phishing"
}

variable "db_username" {
  type        = string
  description = "Master user of the database. Its password is generated and kept by AWS."
  default     = "phishing"
}

variable "db_instance_class" {
  type        = string
  description = "RDS instance class. Check the plan shows this, and nothing larger."
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  type        = number
  description = "Database storage in GiB. 20 is the minimum for PostgreSQL on gp2."
  default     = 20
}

variable "alert_email" {
  type        = string
  description = "Address that receives alarm notifications. The subscription must be confirmed from the inbox once."

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be an email address."
  }
}
