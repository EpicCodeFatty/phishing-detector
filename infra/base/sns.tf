# The alarm notification channel. It lives here rather than beside the alarms in infra/app
# because an email subscription must be confirmed by clicking a link, which Terraform cannot
# do. Recreated with every app apply, it would sit unconfirmed and deliver nothing, which
# would be discovered during the demo. Created once here, it is confirmed once.
#
# After the first apply: open the confirmation email and click the link. The console must
# then show the subscription as Confirmed, not PendingConfirmation.

# Not encrypted, deliberately. CloudWatch alarms cannot publish to a topic encrypted with the
# AWS-managed alias/aws/sns key, because its key policy cannot be edited to admit them, and a
# customer-managed key costs a monthly fee to protect alarm text that contains no secrets.
resource "aws_sns_topic" "alerts" {
  name = "${var.project}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
