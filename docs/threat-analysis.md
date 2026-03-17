# Threat Analysis & Design Decisions

## Overview

This document covers the threat model, tool rationale, security vs developer-experience trade-offs, and residual risks for Yuno's secrets management solution for VortexPay payment provider credentials.

---

## 1. Threat Model

### 1.1 Threat Actors

| Actor | Motivation | Access Level |
|-------|-----------|-------------|
| **External attacker** | Financial fraud, credential resale | No initial access; targets public surfaces |
| **Malicious insider** | Financial gain, sabotage | Varies by role; can have legitimate system access |
| **Compromised service** | Lateral movement, data exfiltration | Service-level IAM role access |
| **Developer (accidental)** | Unintentional exposure | Dev/sandbox environment access |

### 1.2 Attack Vectors & Blast Radius

#### Vector 1: Git Repository Leak
**Scenario:** A developer commits a VortexPay API key (`vp_live_...`) to a public or private GitHub repository.

**Blast radius:** If undetected, attacker gains API access for one merchant's VortexPay account. Could initiate fraudulent transactions, extract transaction history, or disrupt payment flow.

**Mitigations implemented:**
- Gitleaks in CI blocks any commit containing key patterns (`vp_live_*`, `AKIA*`)
- `terraform.tfvars` excluded via `.gitignore`
- Secrets Manager stores all credentials — Terraform `ignore_changes` prevents values from ever being managed (and thus tracked) in state
- `lifecycle { ignore_changes = [secret_string] }` on all secret versions

**Residual risk:** Pre-commit hooks are developer opt-in and can be bypassed. Gitleaks only runs on push — a leaked key is already in Git history by the time CI catches it. Mitigation: GitHub Advanced Security secret scanning with push protection enabled at the repo level.

---

#### Vector 2: Compromised Microservice (Service Account Takeover)
**Scenario:** An attacker exploits a vulnerability in `payment-gateway` (e.g., RCE via dependency) and steals its IAM role credentials via the EC2 metadata endpoint.

**Blast radius:** With the `yuno-payment-gateway-production` role, the attacker can call `GetSecretValue` on any `vortexpay/*` secret — up to 847 merchant API keys. They cannot access database credentials (explicit Deny in policy).

**Mitigations implemented:**
- IAM role scoped to `vortexpay/*` only — denies `database/*`
- `reconciliation-service` scoped to only 3 specific merchant IDs
- CloudTrail logs all `GetSecretValue` calls with IAM principal, timestamp, and source IP
- CloudWatch alarm fires on >0 `AccessDenied` events from Secrets Manager

**Residual risk:** If the service itself is compromised, the attacker has legitimate access to the credentials that service uses — IAM can't distinguish the real service from an attacker running inside it. Mitigation: IMDSv2 enforcement, VPC endpoint for Secrets Manager (traffic never leaves AWS network), and anomaly detection on access patterns (e.g., accessing all 847 merchants in rapid succession).

---

#### Vector 3: Insider Threat (Privileged Engineer)
**Scenario:** An engineer with production AWS console access exports VortexPay credentials and sells them or uses them for personal gain.

**Blast radius:** Potentially all merchant credentials if the engineer has broad IAM access.

**Mitigations implemented:**
- Developer IAM role restricted to `sandbox/*` only — cannot read `production/*`
- MFA required to assume developer role (`aws:MultiFactorAuthPresent: true`)
- CloudTrail logs all access with IAM ARN and username
- Separation of duties: rotation is automated (Lambda) — engineers don't need to see plaintext secrets to rotate them

**Residual risk:** This solution does not defend against a compromised AWS administrator (`arn:aws:iam::ACCOUNT:root` or an admin with KMS key access). Mitigation: Break-glass procedures for root, AWS Organizations SCPs to restrict root usage, quarterly access reviews.

---

#### Vector 4: Laptop Theft / Local Credential Exposure
**Scenario:** A developer's laptop is stolen. It contains `~/.aws/credentials` or a local `.env` file with sandbox credentials.

**Blast radius:** Access to sandbox environment only (developer role is scoped to `sandbox/*`). No production impact.

**Mitigations implemented:**
- Developer role only accesses `sandbox/*` — production is explicitly denied
- Short-lived credentials via `sts:AssumeRole` + MFA (not long-lived access keys)
- 5-minute cache TTL on SecretsClient — stolen tokens expire relatively quickly

**Residual risk:** A stolen long-lived `~/.aws/credentials` file with access key + secret key can be used indefinitely until manually revoked. Mitigation: Enforce AWS SSO (IAM Identity Center) for all developer access — eliminates long-lived credentials entirely.

---

#### Vector 5: Rotation Failure During the 48-Hour Window
**Scenario:** The rotation Lambda fails mid-rotation. `AWSPENDING` exists with a key that VortexPay has already invalidated, but `AWSCURRENT` still holds the old (now invalid) key.

**Blast radius:** Payments fail for all merchants whose keys were rotated before the failure. No data breach, but financial impact from downtime.

**Mitigations implemented:**
- 4-step rotation protocol: Lambda only promotes `AWSPENDING → AWSCURRENT` after `testSecret` passes
- If `testSecret` fails, rotation is aborted and `AWSCURRENT` is unchanged — old key remains valid
- CloudWatch alarm fires immediately on Lambda errors
- SNS notification sent on both success and failure
- `AWSPREVIOUS` retained for emergency rollback (one rotation cycle)

---

## 2. Tool Choices & Trade-offs

### 2.1 Why AWS Secrets Manager over HashiCorp Vault?

| Criterion | AWS Secrets Manager | HashiCorp Vault (self-hosted) |
|-----------|-------------------|------------------------------|
| **Operational burden** | Zero — fully managed | High — HA cluster, unsealing, upgrades |
| **Time to production** | Minutes (Terraform) | Days (cluster setup, Raft storage, tuning) |
| **Native AWS integration** | First-class (IAM, Lambda, CloudTrail) | Requires AWS auth method setup |
| **Cost (847 merchants × 3 secrets)** | ~$7.60/month (2,541 secrets × $0.40/10k API calls) | EC2 cost for 3-node cluster (~$150-300/month) |
| **Compliance audit trail** | CloudTrail automatic | Vault audit log requires separate storage pipeline |
| **Rotation automation** | Built-in Lambda trigger | Requires custom agent + Vault policies |
| **Vendor lock-in** | Higher | Lower |
| **Fine-grained dynamic secrets** | Limited | Excellent |

**Decision:** AWS Secrets Manager for this challenge. Yuno already operates on AWS, and the managed service eliminates operational overhead while providing native IAM integration and automatic CloudTrail coverage. The trade-off is vendor lock-in — if Yuno were to multi-cloud or needed database dynamic secrets at scale, Vault would be preferable.

### 2.2 Why KMS Customer-Managed Keys (CMK)?

AWS Secrets Manager uses KMS for encryption by default, but with AWS-managed keys you lose the ability to:
- Restrict which IAM roles can decrypt
- Rotate the KMS key material independently
- Audit KMS key usage separately from secret access

With a CMK, we get explicit `kms:Decrypt` grants per role — an attacker who steals IAM credentials but not KMS permissions cannot decrypt secrets even if they call `GetSecretValue`. Defense in depth (PCI-DSS 3.5).

---

## 3. Developer Experience vs. Security Tension

### The Problem
Developers building VortexPay integrations need real credentials to test payment flows. Fake keys return fake responses that don't match production behavior. But giving developers production credentials violates least privilege and PCI-DSS.

### Our Resolution

**Separate secret namespaces by environment:**

```
yuno/sandbox/vortexpay/merchant-{id}/api-key      ← developers can read
yuno/staging/vortexpay/merchant-{id}/api-key      ← CI/CD only
yuno/production/vortexpay/merchant-{id}/api-key   ← services only, never humans
```

**Developer access model:**
1. Developers assume `yuno-developer-sandbox` role via AWS SSO (MFA required)
2. Role has `Allow` on `sandbox/*` and explicit `Deny` on `production/*` and `staging/*`
3. Sandbox credentials are real VortexPay sandbox keys (not production) — actual API calls work, but no real money moves
4. All developer access is logged in CloudTrail with their IAM identity

**What this means for developers:**
- `aws secretsmanager get-secret-value --secret-id yuno/sandbox/vortexpay/merchant-123/api-key` — works ✅
- `aws secretsmanager get-secret-value --secret-id yuno/production/vortexpay/merchant-123/api-key` — explicit Deny ❌
- No `.env` files, no Slack-shared keys, no spreadsheets

**Remaining tension:** Developers cannot reproduce production-specific bugs (e.g., a credential that works in sandbox but fails in production due to merchant configuration). Resolution: a break-glass procedure allows a senior engineer to pull a production credential with multi-approval and full audit trail (see Stretch Goal: Break-Glass Access).

---

## 4. PCI-DSS Requirement Mapping

| Requirement | Implementation |
|------------|----------------|
| **8.3.2** — Rotate keys at least annually | Secrets Manager rotation set to 90 days; `aws_secretsmanager_secret_rotation` resource configured for all production secrets |
| **10.2.1** — Log all access to secrets | CloudTrail captures every `GetSecretValue`, `PutSecretValue`, `RotateSecret` API call with actor, timestamp, and source IP |
| **10.3.2** — Log file integrity | CloudTrail log file validation enabled (`enable_log_file_validation = true`); logs stored in S3 with versioning and `DenyDelete` bucket policy |
| **3.5** — Protect secrets with strong cryptography | AWS KMS CMK with AES-256 encryption; `enable_key_rotation = true` rotates KMS key material annually |
| **3.6** — Restrict secret access | IAM roles with explicit resource-level `Allow` and `Deny` policies; `payment-gateway` cannot read `database/*`, `reconciliation-service` scoped to 3 merchant IDs |

---

## 5. Residual Risks & Next Steps

| Risk | Likelihood | Impact | Next Step |
|------|-----------|--------|-----------|
| Compromised Vault/AWS admin | Low | Critical | AWS Organizations SCPs; quarterly privileged access review |
| Supply chain attack on Lambda dependencies | Low | High | Pin dependency versions; Dependabot + pip-audit in CI |
| Secrets Manager service outage | Very Low | High | SecretsClient falls back to `AWSPREVIOUS`; add local encrypted cache with 15-min TTL as last resort |
| Rotation succeeds but service cache not invalidated | Medium | Medium | Publish SNS event on `finishSecret`; services subscribe and call `invalidate_cache()` |
| 847 merchants rotated concurrently overwhelm Lambda concurrency | Medium | Medium | Implement batch rotation with exponential backoff; set Lambda reserved concurrency limit |
| Developer accidentally commits sandbox key | Medium | Low | Pre-commit hook + GitHub push protection for secret scanning |

### What this solution does NOT defend against:
- **Compromised AWS root account** — requires out-of-band controls (hardware MFA on root, CloudTrail alerts on root login)
- **VortexPay-side breach** — if VortexPay's systems are compromised, rotating our credentials alone isn't sufficient; requires coordination with VortexPay incident response
- **Memory scraping of running services** — once a secret is fetched into a service's memory, it's decrypted plaintext; requires runtime security tooling (e.g., Falco, AWS GuardDuty)
