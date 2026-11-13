# The role the instances run as. Its credentials reach the instance through the metadata
# service; no access key exists anywhere.
#
# Two AWS-managed policies, deliberately: they are the documented requirements of the SSM
# agent and the CloudWatch agent, and rewriting them by hand means guessing at a list of
# actions that AWS maintains and changes. The permissions whose scope matters, one S3 object
# and one database secret, are added in phase 5 as inline policies against exact ARNs.

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    sid     = "InstancesAssumeTheRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "${var.project}-app"
  description        = "Application instances: Session Manager and the CloudWatch agent."
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

# Session Manager: shell access with no key pair, no bastion host and no port 22.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cloudwatch" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# The wrapper that attaches a role to an instance. Without it the role exists and the
# instance has no credentials.
resource "aws_iam_instance_profile" "app" {
  name = "${var.project}-app"
  role = aws_iam_role.app.name
}
