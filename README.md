# @tailsec/scan-terraform

Security scanner for Terraform (AWS, Azure, GCP). Detects insecure configurations including public S3 buckets, open security groups, overly permissive IAM policies, and more.

## Usage

```bash
npx @tailsec/scan-terraform ./infrastructure
npx @tailsec/scan-terraform ./infrastructure --format json
```

## Checks

- S3 public access and encryption
- RDS public access and encryption
- Security group overly permissive rules
- IAM wildcard policies
- Azure Storage public access
- GCP Storage public access
- And more...