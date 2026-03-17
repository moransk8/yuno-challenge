# Yuno — VortexPay Secrets Management

Automated, zero-downtime secrets management for Yuno's payment provider credentials.  
Built in response to the VortexPay 48-hour emergency credential rotation incident.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          AWS Account (us-east-1)                     │
│                                                                       │
│   ┌──────────────┐   schedule    ┌─────────────────────────────┐    │
│   │  EventBridge │──────────────▶│   Lambda: rotate-secret     │    │
│   │  (daily)     │               │                             │    │
│   └──────────────┘               │  1. createSecret (PENDING)  │    │
│                                  │  2. setSecret  (VortexPay)  │    │
│   ┌──────────────┐   triggers    │  3. testSecret (verify)     │    │
│   │ Secrets Mgr  │◀─────────────▶  4. finishSecret (promote)  │    │
│   │  (KMS enc.)  │               └──────────┬──────────────────┘    │
│   │              │                          │                        │
│   │ vortexpay/   │                          │ publish                │
│   │  merchant-*/ │               ┌──────────▼──────────────────┐    │
│   │   api-key    │               │         SNS Topic            │    │
│   │   webhook-   │               │   rotation-alerts            │    │
│   │   oauth      │               └──────────┬──────────────────┘    │
│   └──────┬───────┘                          │ email/webhook          │
│          │ GetSecretValue                    ▼                        │
│   ┌──────▼───────────────────────────────────────┐                  │
│   │              Microservices                    │                  │
│   │                                               │                  │
│   │  payment-gateway    reconciliation-service    │                  │
│   │  (vortexpay/* IAM)  (merchant-123,456,789)   │                  │
│   │                                               │                  │
│   │  SecretsClient — in-memory cache (5min TTL)  │                  │
│   │  Auto-fallback: AWSCURRENT → AWSPREVIOUS      │                  │
│   └───────────────────────────────────────────────┘                  │
│                                                                       │
│   ┌───────────────────────────────────────────────────────────────┐  │
│   │                    Audit Trail (PCI-DSS Req. 10)              │  │
│   │                                                               │  │
│   │   CloudTrail ──▶ S3 (versioned, delete-protected, encrypted)  │  │
│   │        └──────▶ CloudWatch Logs (/yuno/secrets-audit/)        │  │
│   │                      └──▶ Logs Insights (audit queries)       │  │
│   └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Zero-Downtime Rotation Flow

```
t=0   AWS Secrets Manager triggers Lambda (4-step rotation protocol)
t=1   Lambda generates new key, stores as AWSPENDING
        → AWSCURRENT (old key) still served to all services ✅
t=2   Lambda calls VortexPay API — registers new key
        → VortexPay now accepts BOTH old and new keys
t=3   Lambda tests new key against VortexPay — verifies it works
t=4   Lambda promotes AWSPENDING → AWSCURRENT
        → Services with cached credentials continue using old key
        → On next cache TTL (5 min), services fetch AWSCURRENT (new key)
        → Old key retained as AWSPREVIOUS for 1 rotation cycle
        
Result: ZERO payment downtime, ZERO service restarts
```

---

## Repository Structure

```
yuno-challenge/
├── .github/
│   └── workflows/
│       ├── ci.yml                  # Secret scanning, SAST, IaC scanning
│       └── rotate-secrets.yml      # Emergency rotation with approval gates
├── terraform/
│   ├── main.tf                     # Root module — wires all modules together
│   ├── variables.tf                # Input variables
│   ├── outputs.tf                  # Output values
│   ├── terraform.tfvars.example    # Config template (NEVER commit .tfvars)
│   └── modules/
│       ├── iam/                    # KMS key, service roles, least-privilege policies
│       ├── secrets/                # Secrets Manager secrets + rotation config
│       ├── lambda/                 # Rotation Lambda + EventBridge schedule
│       └── monitoring/             # CloudTrail, CloudWatch, SNS alerts
├── lambda/
│   └── rotate_secret/
│       ├── handler.py              # 4-step rotation logic (zero-downtime)
│       └── requirements.txt
├── client-lib/
│   ├── secrets_client.py           # Reusable secrets client for all microservices
│   └── example_payment_gateway.py  # Usage demo
├── scripts/
│   ├── emergency_rotation.py       # Bulk rotation script for 847 merchants
│   └── audit_queries.py            # PCI-DSS audit log queries
└── docs/
    └── threat-analysis.md          # Threat model, tool choices, residual risks
```

---

## Quick Start

### Prerequisites

- AWS CLI configured with appropriate permissions
- Terraform >= 1.5.0
- Python 3.11+

### 1. Deploy Infrastructure

```bash
cd terraform/

# Configure variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values (do NOT commit this file)

# Deploy
terraform init
terraform plan
terraform apply
```

### 2. Set Real Secret Values (out-of-band — never in Terraform)

```bash
# Set real VortexPay API key for merchant 123
aws secretsmanager put-secret-value \
  --secret-id "yuno/production/vortexpay/merchant-123/api-key" \
  --secret-string "vp_live_YOUR_REAL_KEY_HERE" \
  --region us-east-1

# Set OAuth credentials (JSON)
aws secretsmanager put-secret-value \
  --secret-id "yuno/production/vortexpay/merchant-123/oauth-credentials" \
  --secret-string '{"client_id":"real_id","client_secret":"real_secret","token_url":"https://auth.vortexpay.com/oauth/token","scope":"payments:read payments:write"}'
```

### 3. Test the Client Library

```bash
cd client-lib/
pip install boto3

# Assumes your IAM role has sandbox access
ENVIRONMENT=sandbox python example_payment_gateway.py
```

### 4. Trigger Emergency Rotation (for the VortexPay 48h incident)

```bash
# Via GitHub Actions (recommended — approval gate + audit trail)
# Go to Actions → Emergency Secret Rotation → Run workflow
# Fill in: provider=vortexpay, merchant_id=all, environment=production

# Or directly via script (requires AWS credentials)
ENVIRONMENT=production \
PROVIDER=vortexpay \
MERCHANT_ID=all \
TRIGGERED_BY=your-name \
ROTATION_REASON="VortexPay 48h emergency rotation - incident #1234" \
python scripts/emergency_rotation.py
```

### 5. Query Audit Logs (PCI-DSS)

```bash
# Who accessed VortexPay production secrets in the last 24 hours?
python scripts/audit_queries.py --query accesses --hours 24

# All rotation events in the last 30 days
python scripts/audit_queries.py --query rotations --days 30

# Any unauthorized access attempts?
python scripts/audit_queries.py --query denied

# Full export for PCI auditor
python scripts/audit_queries.py --query export --days 365 --output pci_audit_export.json
```

---

## Access Control Model

| Role | Can Read | Cannot Read |
|------|---------|-------------|
| `payment-gateway` | `vortexpay/*` | `database/*`, `staging/*`, `production/other-provider/*` |
| `reconciliation-service` | `vortexpay/merchant-{123,456,789}` | All other merchants |
| `developer` | `sandbox/*` | `production/*`, `staging/*` |
| `rotation-lambda` | `vortexpay/*` (AWSPENDING/AWSCURRENT) | `database/*` |

All roles require MFA for humans. All machine roles use short-lived credentials via IAM role assumption (no long-lived access keys).

---

## PCI-DSS Compliance Mapping

| Requirement | Control |
|------------|---------|
| **8.3.2** — Annual key rotation | `aws_secretsmanager_secret_rotation` — 90-day schedule |
| **10.2.1** — Log all secret access | CloudTrail captures every `GetSecretValue` API call |
| **10.3.2** — Tamper-evident logs | CloudTrail log file validation; S3 `DenyDelete` policy |
| **3.5** — Encrypt secrets at rest | AWS KMS CMK (AES-256); `enable_key_rotation = true` |
| **3.6** — Restrict secret access | IAM resource-level policies with explicit `Deny` |

---

## Security Controls Summary

- ✅ **Encryption at rest** — All secrets encrypted with KMS CMK
- ✅ **Encryption in transit** — TLS enforced by AWS SDK
- ✅ **Least privilege** — Each service role scoped to minimum required secrets
- ✅ **Zero plaintext** — No credentials in code, Git, environment variables, or Terraform state
- ✅ **Audit trail** — CloudTrail logs every access, tamper-protected in S3
- ✅ **Automated rotation** — 90-day schedule, zero-downtime 4-step protocol
- ✅ **Secret leak detection** — Gitleaks + Semgrep in CI pipeline
- ✅ **Alerting** — SNS notifications on rotation failure and unauthorized access

---

## Threat Analysis

See [`docs/threat-analysis.md`](docs/threat-analysis.md) for full threat model, tool choices, trade-offs, and residual risks.
