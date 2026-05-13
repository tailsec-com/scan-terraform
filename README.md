# @tailsec/scan-terraform

Security scanner for Terraform (AWS, Azure, GCP). Detects public S3 buckets, open security groups, overly permissive IAM policies, unencrypted databases, and other IaC misconfigurations.

[![npm](https://img.shields.io/npm/v/@tailsec/scan-terraform)](https://www.npmjs.com/package/@tailsec/scan-terraform)
[![CI](https://github.com/tailsec-com/scan-terraform/actions/workflows/ci.yml/badge.svg)](https://github.com/tailsec-com/scan-terraform)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

## Features

- Scans Terraform (.tf) files for security misconfigurations
- Multi-provider: AWS, Azure, and GCP
- Pattern-based detection with regex rules
- JSON output for CI/CD integration
- No external dependencies — parses Terraform HCL syntactically

## Installation

```bash
npm install -g @tailsec/scan-terraform
```

## Usage

```bash
# Scan a directory of Terraform files
npx @tailsec/scan-terraform ./infrastructure

# Output as JSON (for CI/CD pipelines)
npx @tailsec/scan-terraform ./infrastructure --format json

# Scan specific files
npx @tailsec/scan-terraform main.tf vpc.tf
```

### Programmatic

```typescript
import { scanTerraform, formatTerraformOutput } from '@tailsec/scan-terraform';

const findings = scanTerraform(tfContent);
console.log(formatTerraformOutput(findings, 'text'));
console.log(formatTerraformOutput(findings, 'json'));
```

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `text` | Output format: `text` or `json` |

## Supported Providers

| Provider | Resource Types |
|----------|----------------|
| AWS | s3, db_instance, rds_cluster, elb, security_group, iam, ec2, sqs, elasticache, redshift, mq |
| Azure | storage_account, sql_server, virtual_machine, aks, key_vault |
| GCP | storage_bucket, sql_instance, container_cluster |

## Detection Rules

| Rule ID | Severity | Title |
|---------|----------|-------|
| tf-aws-s3-public-read-write | Critical | S3 bucket is public read-write |
| tf-aws-db-public | Critical | RDS/DB is publicly accessible |
| tf-aws-security-group-allow-all | Critical | Security group allows all traffic from 0.0.0.0/0 |
| tf-aws-iam-admin | Critical | IAM policy grants AdminAccess (*:*) |
| tf-aws-iam-user-admin-access | Critical | IAM user has AdministratorAccess policy |
| tf-aws-elasticache-public | Critical | ElastiCache cluster is publicly accessible |
| tf-aws-redshift-public | Critical | Redshift cluster is publicly accessible |
| tf-aws-mq-public | Critical | MQ broker is publicly accessible |
| tf-secret-hardcoded | Critical | Hardcoded secret (password/api_key/secret) detected |
| tf-gcp-sa-full | Critical | Service account has full cloud-platform access |
| tf-gcp-sql-public | Critical | Cloud SQL instance has public IP |
| tf-aws-s3-public-read | High | S3 bucket is public read |
| tf-aws-s3-no-encryption | High | S3 bucket does not have encryption enabled |
| tf-aws-db-no-encryption | High | Database storage is not encrypted |
| tf-aws-rds-storage-encrypted | High | RDS storage encrypted set to false |
| tf-aws-security-group-ssh-all | High | Security group opens SSH to 0.0.0.0/0 |
| tf-aws-elb-no-ssl | High | ELB/ALB does not enforce SSL |
| tf-aws-iam-* | High | IAM policy grants service:* |
| tf-aws-ami-public | High | Using public AMI |
| tf-gcp-bucket-public | High | GCS bucket has public access |
| tf-gcp-container-no-client-certs | High | GKE cluster without client certificates |
| tf-az-sa-public | High | Azure storage account has public blob access |
| tf-az-sql-no-firewall | High | Azure SQL server allows all IPs (0.0.0.0) |
| tf-az-aks-no-ip-ranges | High | AKS cluster has no authorized IP ranges |
| tf-az-storage-https-only | High | Azure storage has HTTPS disabled |
| tf-aws-s3-no-versioning | Medium | S3 bucket versioning is disabled |
| tf-aws-db-no-backup | Medium | RDS has no backup retention |
| tf-aws-sqs-dlq | Medium | SQS queue has no dead-letter queue |
| tf-gcp-node-pool-default-sa | Medium | GKE node pool uses default service account |
| tf-az-vm-no-password | Medium | Azure VM has password authentication enabled |
| tf-secret-variable | Medium | Terraform variable block detected (check for secrets) |
| tf-aws-ec2-key-pair | Low | EC2 key pair declared (key material in state) |
| tf-aws-s3-logging-missing | Low | S3 bucket is missing logging configuration |

## Exit Codes

- `0` — Scan completed, no issues found
- `1` — Scan completed, issues found
- `2` — Scan failed (file errors, parse errors)

## Contributing

Rules are defined in `src/terraform.ts` in the `RULE_PATTERNS`, `AZURE_PATTERNS`, `GCP_PATTERNS`, and `SECRETS_PATTERNS` arrays. Each rule is a tuple of `[ruleId, pattern, severity]`.

To add a new rule:

1. Determine the correct provider array for your rule
2. Append a tuple: `[<rule-id>, /<regex-pattern>/, '<severity>']`
3. Rule IDs should follow: `tf-<provider>-<descriptive-name>` (e.g., `tf-aws-my-new-rule`)

Example:

```typescript
['tf-aws-my-new-rule', /pattern/, 'high'],
```

Also add a corresponding entry in the `scanExpression` function's rules map if needed.

## License

MIT