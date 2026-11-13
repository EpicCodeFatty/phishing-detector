# The release: app/ zipped, named after its own hash, in a private bucket the instances
# download from at boot.
#
# The hash drives the whole deployment. A code change gives a new key, which changes
# user_data, which makes a new launch template version, which starts an instance refresh.
# Nothing is bumped by hand, and unchanged code plans as no change.

locals {
  # The one folder of the bucket the instances may read; see iam.tf.
  release_prefix = "releases/"

  # The first 12 hex characters of the zip's SHA-256: the release ID that /health reports.
  release      = substr(data.archive_file.app.output_sha256, 0, 12)
  artifact_key = "${local.release_prefix}app-${local.release}.zip"
}

# The zip holds the contents of app/ at its root (web.py, detector/, ...), not an app/
# folder. The boot script extracts it into /opt/phishing/app, which restores the package name.
data "archive_file" "app" {
  type        = "zip"
  source_dir  = "${path.module}/../../app"
  output_path = "${path.module}/.build/app.zip"

  # The same mode for every file, so the zip, and with it the hash, is identical on Windows
  # and Linux. Without it a plan on another machine shows a new release for unchanged code.
  output_file_mode = "0644"

  # Everything the application needs at runtime stays in: the code, templates/, static/
  # and requirements.txt. Tests and development requirements are not under app/ at all.
  # What is excluded is build noise, so that running the tests locally does not make a
  # "new release", and .env, which should never be under app/ and must never reach S3 if
  # it ever is.
  excludes = [
    "**/__pycache__/**",
    "**/*.pyc",
    "**/.pytest_cache/**",
    "**/.ruff_cache/**",
    "**/.gitkeep",
    "**/.env",
    "**/.env.*",
  ]
}

# ------------------------------------------------------------------------------- Bucket
#
# Public access block, enforced ownership, encryption and a TLS-only policy. Several are
# already AWS's defaults for a new bucket; they are written out because a scanner reads the
# code, not the defaults, and so that the intent is visible in review.
#
# No versioning, deliberately: every release has its own key, so versioning would only keep
# copies of objects that never change. No access logging and no customer-managed key either:
# each adds resources and cost to protect zips that are rebuilt from git in seconds.

resource "aws_s3_bucket" "artifacts" {
  #checkov:skip=CKV_AWS_18:Access logs need a second bucket; it holds only zips rebuilt from git, read by one role
  #checkov:skip=CKV_AWS_21:Every release has its own key and is never overwritten, so versions would only copy it
  #checkov:skip=CKV_AWS_144:Replication protects data that cannot be rebuilt; these zips are rebuilt from git in seconds
  #checkov:skip=CKV_AWS_145:SSE-S3 rather than KMS; a customer-managed key adds cost to protect rebuildable zips
  #checkov:skip=CKV2_AWS_61:No lifecycle rule needed; Terraform deletes each superseded release and the bucket daily
  #checkov:skip=CKV2_AWS_62:No event notifications; nothing consumes them, the instances are told the exact key
  # A prefix, not a fixed name: bucket names are global across all AWS accounts, so a fixed
  # one can collide with someone else's, and re-creating the same name can briefly fail.
  bucket_prefix = "${var.project}-artifacts-"

  # Lets `terraform destroy` remove a bucket that still holds objects. Right here, where the
  # stack is destroyed daily and the bucket holds only rebuildable zips; wrong for a bucket
  # holding anything that cannot be rebuilt.
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "artifacts_tls_only" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.artifacts.arn,
      "${aws_s3_bucket.artifacts.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifacts_tls_only.json

  # Changing the bucket's policy and its public access block at the same moment can fail.
  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

# ------------------------------------------------------------------------------ Release

resource "aws_s3_object" "release" {
  bucket = aws_s3_bucket.artifacts.id
  key    = local.artifact_key
  source = data.archive_file.app.output_path

  # source_hash, not etag: an etag equals the file's MD5 only under some encryption
  # settings and is a permanent diff under the others. source_hash is compared by
  # Terraform alone.
  source_hash = data.archive_file.app.output_base64sha256

  # A new release creates its object before the old one is removed, so there is never a
  # moment when the launch template points at a key that is gone.
  lifecycle {
    create_before_destroy = true
  }
}
