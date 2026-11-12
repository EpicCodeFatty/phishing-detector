# Build log

Running notes while building the project. Every problem gets an entry, however small.
This file is the raw material for the troubleshooting runbook in the README.

Format: what happened, why, how it was resolved.

---

## 2026-11-12 — Environment setup

**Account.** AWS account created through the new project-based sign-up. Free plan, $100 in credits.
Signup required a card for identity verification; the account was not upgraded to a paid plan.

**Region is fixed.** The new sign-up assigns the project a single region based on the contact address,
so this account is `eu-north-1` (Stockholm) and there is no region selector in the console. Choosing a
different region would require activating advanced features, which was deliberately not done. All
provider blocks, the CLI profile and the console therefore use `eu-north-1`.

**Local tooling.** Python 3.12, Git 2.56, Terraform 1.17.1, AWS CLI 2.40.0, Docker 29.9.3, plus the
Python, Pylance, Terraform and Docker extensions for VS Code.
Note: the machine also has Python 3.11 and 3.13, and `python` resolves to 3.13, so the project
virtualenv is created explicitly with `py -3.12 -m venv .venv`.

**Credentials — resolved an open question.** The new account manages IAM Identity Center itself, so
there is no IAM user to create and no access key to store. `aws login --profile phishing` opens a
browser and issues temporary credentials valid for 12 hours, assuming `AccountFullAccessRole`.
The open question was whether Terraform would read that session. Verified directly with a throwaway
configuration containing only a provider block and an `aws_caller_identity` data source:
`terraform plan` returned the correct account ID with the AWS provider v6.73.0.
No access keys are needed anywhere in this project.

**Budget.** A monthly cost budget with email alerts was created by hand in the console rather than in
Terraform, so that it keeps working after `terraform destroy`.

**Repository.** Private repository, folder skeleton, and a `.gitignore` covering `.venv/`, `.env`,
`.terraform/`, `*.tfstate*` and `*.tfvars`. `.terraform.lock.hcl` is intentionally *not* ignored, so
the provider version stays pinned across machines.

---

## Template for new entries

### YYYY-MM-DD — short title

**Symptom.** What was observed, including the exact error message.

**Cause.** What was actually wrong.

**Fix.** What resolved it, and where the change lives.

**Lesson.** Anything worth remembering, or that belongs in the runbook.
