# The load balancer's certificate: self-signed, generated here and imported into ACM.
#
# There is no domain for this project, so no authority will sign a certificate for it. A
# self-signed one gives the same encryption without the proof of identity, which is why the
# browser warns before showing the site. With a domain, ACM would issue a trusted certificate
# and this file would go.
#
# The private key is stored in Terraform state, twice: as the key resource and as an
# argument of the ACM certificate. State is local and gitignored, so it never reaches git,
# but it is a demo trade-off: the key of a certificate that ACM issues never leaves AWS.

locals {
  # Thirty days. The stack is rebuilt daily, and the certificate is regenerated with it.
  certificate_validity_hours = 30 * 24
}

# RSA 2048 rather than an elliptic-curve key: accepted everywhere ACM and load balancers are.
resource "tls_private_key" "alb" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "alb" {
  private_key_pem = tls_private_key.alb.private_key_pem

  # A short fixed common name: it is limited to 64 characters, and the load balancer's
  # generated DNS name comes within a few characters of that. Browsers read the name from
  # dns_names (the subject alternative names) and ignore the common name.
  subject {
    common_name  = var.project
    organization = "${var.project} (self-signed, demo)"
  }

  # Naming the load balancer removes one of the browser's two complaints, the wrong name.
  # "Not trusted" remains: that is what self-signed means.
  dns_names = [aws_lb.main.dns_name]

  validity_period_hours = local.certificate_validity_hours
  allowed_uses          = ["digital_signature", "key_encipherment", "server_auth"]
}

# create_before_destroy: a new load balancer has a new DNS name, so a new certificate. The
# new one is imported and attached to the listener before the old one is deleted; the other
# way round, ACM refuses to delete a certificate that a listener still uses.
resource "aws_acm_certificate" "alb" {
  private_key      = tls_private_key.alb.private_key_pem
  certificate_body = tls_self_signed_cert.alb.cert_pem

  lifecycle {
    create_before_destroy = true
  }
}
