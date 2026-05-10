import { readFileSync } from 'fs';

export interface TerraformFinding {
  ruleId: string;
  type: string;
  severity: string;
  resource: string;
  line?: number;
  advice: string[];
}

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

function scanExpression(expr: string, rules: Map<string, { severity: Severity; title: string; advice: string[]; pattern: RegExp }>): Array<{ ruleId: string; severity: Severity; title: string; advice: string[] }> {
  const matches: Array<{ ruleId: string; severity: Severity; title: string; advice: string[] }> = [];
  for (const [ruleId, rule] of rules) {
    if (rule.pattern.test(expr)) {
      matches.push({ ruleId, severity: rule.severity, title: rule.title, advice: rule.advice });
    }
  }
  return matches;
}

const PROVIDER_RULES = new Map([
  ['tf-aws-s3-public-read', {
    severity: 'high', title: 'S3 bucket allows public read access',
    advice: ['Block public access with acl = "private"', 'Use bucket policies to restrict access'],
    pattern: /acl\s*=\s*["']public-read["']/,
  }],
  ['tf-aws-s3-no-versioning', {
    severity: 'medium', title: 'S3 bucket has versioning disabled',
    advice: ['Enable versioning for data recovery', 'Consider lifecycle policies'],
    pattern: /versioning\s*\{\s*enabled\s*=\s*false?\s*\}/,
  }],
  ['tf-aws-s3-no-encryption', {
    severity: 'high', title: 'S3 bucket has encryption disabled',
    advice: ['Enable server-side encryption: server_side_encryption_configuration'],
    pattern: /server_side_encryption_configuration\s*=\s*null|sse\s*=\s*false/,
  }],
  ['tf-aws-s3-logging-missing', {
    severity: 'low', title: 'S3 bucket has no access logging',
    advice: ['Enable access logging for audit trail'],
    pattern: /logging\s*\{\s*target_bucket\s*=\s*["']?[^"']+["']?\s*\}/,
  }],
  ['tf-aws-db-public', {
    severity: 'critical', title: 'RDS database publicly accessible',
    advice: ['Set publicly_accessible = false', 'Use private subnets in VPC'],
    pattern: /publicly_accessible\s*=\s*true/,
  }],
  ['tf-aws-db-no-encryption', {
    severity: 'high', title: 'RDS database has storage encryption disabled',
    advice: ['Enable storage encryption: storage_encrypted = true'],
    pattern: /storage_encrypted\s*=\s*false/,
  }],
  ['tf-aws-db-no-backup', {
    severity: 'medium', title: 'RDS database has automated backups disabled',
    advice: ['Enable backups: backup_retention_period > 0'],
    pattern: /backup_retention_period\s*=\s*0/,
  }],
  ['tf-aws-elb-no-ssl', {
    severity: 'high', title: 'ALB/NLB does not enforce SSL',
    advice: ['Set ssl_policy and certificate on listener', 'Use TLS 1.2+ policy'],
    pattern: /ssl\s*=\s*false|protocol\s*=\s*["']HTTP["']/,
  }],
  ['tf-aws-security-group-allow-all', {
    severity: 'critical', title: 'Security group allows 0.0.0.0/0 for all ports',
    advice: ['Restrict to specific ports and sources', 'Never open all ports to 0.0.0.0/0'],
    pattern: /cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']\s*\].*from_port\s*=\s*0|from_port\s*=\s*0.*cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']/s,
  }],
  ['tf-aws-security-group-ssh-all', {
    severity: 'high', title: 'Security group allows SSH from 0.0.0.0/0',
    advice: ['Restrict SSH access to known IP ranges only'],
    pattern: /from_port\s*=\s*22.*cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']/s,
  }],
  ['tf-aws-iam-admin', {
    severity: 'critical', title: 'IAM policy grants full admin access (*)',
    advice: ['Use least-privilege principle', 'Specify exact actions and resources'],
    pattern: /Action\s*=\s*"\*"[\s\S]*Resource\s*=\s*"\*"|"Action"\s*:\s*"\*"[\s\S]*"Resource"\s*:\s*"\*"/,
  }],
  ['tf-aws-iam-*', {
    severity: 'high', title: 'IAM policy grants all actions on a service',
    advice: ['Use specific actions instead of *'],
    pattern: /"Action"\s*:\s*"service:\*"/,
  }],
  ['tf-aws-ec2-key-pair', {
    severity: 'low', title: 'EC2 instance has a key pair assigned — ensure it\'s rotated',
    advice: ['Use AWS SSM Session Manager instead of SSH', 'Rotate keys regularly'],
    pattern: /key_name\s*=\s*["'][^"']+["']/,
  }],
  ['tf-aws-ami-public', {
    severity: 'high', title: 'EC2 instance launched from public AMI',
    advice: ['Verify AMI source and ownership', 'Use private AMIs for production'],
    pattern: /ami\s*=\s*["']ami-[0-9a-f]{17}["']/,
  }],
  ['tf-aws-sqs-dlq', {
    severity: 'medium', title: 'SQS queue has no dead letter queue',
    advice: ['Configure redrive_policy with maxReceiveCount'],
    pattern: /redrive_policy\s*=\s*null/,
  }],
]);

const AZURE_RULES = new Map([
  ['tf-az-sa-public', {
    severity: 'high', title: 'Azure Storage account allows public access',
    advice: ['Disable anonymous access', 'Use Azure AD authentication'],
    pattern: /allow_blob_public_access\s*=\s*true/,
  }],
  ['tf-az-sql-no-firewall', {
    severity: 'high', title: 'Azure SQL has no firewall rules (allows Azure services)',
    advice: ['Configure specific IP ranges', 'Enable Azure Defender for SQL'],
    pattern: /start_ip_address\s*=\s*["']0\.0\.0\.0["'].*end_ip_address\s*=\s*["']0\.0\.0\.0["']/s,
  }],
  ['tf-az-vm-no-password', {
    severity: 'medium', title: 'Azure VM has password authentication enabled',
    advice: ['Disable password authentication', 'Use SSH keys or Azure AD'],
    pattern: /disable_password_authentication\s*=\s*false/,
  }],
]);

const GCP_RULES = new Map([
  ['tf-gcp-sa-full', {
    severity: 'critical', title: 'Service account has full Cloud API access',
    advice: ['Scope permissions to specific resources', 'Use least-privilege service accounts'],
    pattern: /access_token_scopes\s*=\s*\[\s*"https:\/\/www\.googleapis\.com\/auth\/cloud-platform"\s*\]/,
  }],
  ['tf-gcp-bucket-public', {
    severity: 'high', title: 'GCP Storage bucket allows public access',
    advice: ['Use uniform bucket-level access', 'Remove allUsers and allAuthenticatedUsers'],
    pattern: /uniform_bucket_level_access\s*=\s*false|acl\s*=\s*\[/,
  }],
  ['tf-gcp-sql-public', {
    severity: 'critical', title: 'Cloud SQL instance has public IP',
    advice: ['Use private IP only', 'Configure VPC peering'],
    pattern: /ip_configuration\.ipv4_enabled\s*=\s*true/,
  }],
]);

const SECRETS_RULES = new Map([
  ['tf-secret-hardcoded', {
    severity: 'critical', title: 'Hardcoded secret in Terraform',
    advice: ['Use environment variables or secrets manager', 'Never commit secrets to version control'],
    pattern: /password\s*=\s*["'][^'"]{4,}["']|secret\s*=\s*["'][^'"]{4,}["']|api_key\s*=\s*["'][^'"]{4,}["']/,
  }],
  ['tf-secret-variable', {
    severity: 'medium', title: 'Sensitive variable without sensitive attribute',
    advice: ['Mark as sensitive in variable definition: sensitive = true'],
    pattern: /variable\s+"[^"]+"\s*\{[^}]*\}/,
  }],
]);

function parseSimpleTerraform(content: string): Array<{ resource: string; type: string; name: string; body: string }> {
  const resources: Array<{ resource: string; type: string; name: string; body: string }> = [];

  const resourceBlocks = content.matchAll(/resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)\n\}/g);
  for (const match of resourceBlocks) {
    resources.push({ resource: match[0], type: match[1], name: match[2], body: match[3] });
  }

  const dataBlocks = content.matchAll(/data\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)\n\}/g);
  for (const match of dataBlocks) {
    resources.push({ resource: match[0], type: `data.${match[1]}`, name: match[2], body: match[3] });
  }

  return resources;
}

export function scanTerraform(content: string): TerraformFinding[] {
  const findings: TerraformFinding[] = [];
  const resources = parseSimpleTerraform(content);

  for (const res of resources) {
    const rules = res.type.startsWith('aws_') ? PROVIDER_RULES
      : res.type.startsWith('azurerm') ? AZURE_RULES
      : res.type.startsWith('google') ? GCP_RULES
      : new Map();

    for (const [ruleId, rule] of rules) {
      if (rule.pattern.test(res.body) || rule.pattern.test(res.resource)) {
        findings.push({
          ruleId,
          type: 'terraform',
          severity: rule.severity,
          title: rule.title,
          resource: `${res.type}.${res.name}`,
          advice: rule.advice,
        });
      }
    }
  }

  for (const [ruleId, rule] of SECRETS_RULES) {
    if (rule.pattern.test(content)) {
      const lineMatch = content.slice(0, content.indexOf(rule.pattern.source)).split('\n');
      findings.push({
        ruleId,
        type: 'terraform',
        severity: rule.severity,
        title: rule.title,
        resource: 'variables',
        line: lineMatch.length,
        advice: rule.advice,
      });
    }
  }

  return findings;
}

export function formatTerraformOutput(findings: TerraformFinding[], format: 'text' | 'json' = 'text'): string {
  if (format === 'json') {
    return JSON.stringify({ terraform: findings, total: findings.length }, null, 2);
  }

  const lines: string[] = ['\n=== Terraform Findings ===\n'];
  lines.push(`Total: ${findings.length} issues\n`);
  lines.push('─'.repeat(60));

  for (const f of findings) {
    lines.push(`\n[${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`  Resource: ${f.resource}`);
    if (f.advice.length > 0) lines.push(`  Fix: ${f.advice.join(' | ')}`);
  }

  return lines.join('\n');
}