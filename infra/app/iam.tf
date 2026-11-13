# The role the instances run as. Its credentials reach the instance through the metadata
# service; no access key exists anywhere.
#
# Two AWS-managed policies, deliberately: they are the documented requirements of the SSM
# agent and the CloudWatch agent, and rewriting them by hand means guessing at a list of
# actions that AWS maintains and changes. The permissions whose scope matters, the releases
# in one bucket and one database secret, are the two inline policies at the end of this
# file, each written against exactly what the instance reads.

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
  description        = "Application instances: Session Manager, the CloudWatch agent, the release and the database secret."
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

# ---------------------------------------------------------------------- Inline policies

# The releases/ prefix rather than one key: during an instance refresh old and new instances
# coexist, and a policy pinned to one key would be rewritten on every release. Still
# read-only, one bucket, one folder. No s3:ListBucket, because the instance is told the
# exact key; the cost is that S3 answers 403 for a missing object, never 404.
data "aws_iam_policy_document" "read_release" {
  statement {
    sid       = "ReadReleases"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/${local.release_prefix}*"]
  }
}

resource "aws_iam_role_policy" "read_release" {
  name   = "read-release"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.read_release.json
}

# One secret, read-only: no DescribeSecret and no wildcard. No KMS permission either. The
# RDS-managed secret is encrypted with the AWS-managed aws/secretsmanager key, whose policy
# already lets any principal that may read the secret decrypt it through Secrets Manager.
data "aws_iam_policy_document" "read_db_secret" {
  statement {
    sid       = "ReadDatabaseSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [local.base.db_secret_arn]
  }
}

resource "aws_iam_role_policy" "read_db_secret" {
  name   = "read-db-secret"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.read_db_secret.json
}
