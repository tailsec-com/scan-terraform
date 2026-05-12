import { readFileSync } from 'fs';

export interface TerraformFinding {
  ruleId: string;
  type: string;
  severity: string;
  title: string;
  resource: string;
  line?: number;
  advice: string[];
}

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

const RESOURCE_BLOCK_RE = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)\n\}/g;
const DATA_BLOCK_RE = /data\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)\n\}/g;

const RULE_PATTERNS: Array<[string, RegExp, Severity]> = [
  ['tf-aws-s3-public-read', /acl\s*=\s*["']public-read["']/, 'high'],
  ['tf-aws-s3-public-read-write', /acl\s*=\s*["']public-read-write["']/, 'critical'],
  ['tf-aws-s3-no-versioning', /versioning\s*\{\s*enabled\s*=\s*false?\s*\}/, 'medium'],
  ['tf-aws-s3-no-encryption', /server_side_encryption_configuration\s*=\s*null|sse\s*=\s*false/, 'high'],
  ['tf-aws-s3-logging-missing', /logging\s*\{\s*target_bucket\s*=\s*["']?[^"']+["']?\s*\}/, 'low'],
  ['tf-aws-db-public', /publicly_accessible\s*=\s*true/, 'critical'],
  ['tf-aws-db-no-encryption', /storage_encrypted\s*=\s*false/, 'high'],
  ['tf-aws-rds-storage-encrypted', /resource\s+"aws_db_instance"[^}]*storage_encrypted\s*=\s*false/, 'high'],
  ['tf-aws-db-no-backup', /backup_retention_period\s*=\s*0/, 'medium'],
  ['tf-aws-elb-no-ssl', /ssl\s*=\s*false|protocol\s*=\s*["']HTTP["']/, 'high'],
  ['tf-aws-security-group-allow-all', /cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']\s*\][^}]*from_port\s*=\s*0|from_port\s*=\s*0[^}]*cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']/, 'critical'],
  ['tf-aws-security-group-ssh-all', /from_port\s*=\s*22[^}]*cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']/, 'high'],
  ['tf-aws-iam-admin', /Action\s*=\s*"\*"[^}]*Resource\s*=\s*"\*"|"Action"\s*:\s*"\*"[^}]*"Resource"\s*:\s*"\*"/, 'critical'],
  ['tf-aws-iam-*', /"Action"\s*:\s*"service:\*"/, 'high'],
  ['tf-aws-iam-user-admin-access', /resource\s+"aws_iam_user_policy"[^}]*"AdministratorAccess"/, 'critical'],
  ['tf-aws-ec2-key-pair', /key_name\s*=\s*["'][^"']+["']/, 'low'],
  ['tf-aws-ami-public', /ami\s*=\s*["']ami-[0-9a-f]{17}["']/, 'high'],
  ['tf-aws-sqs-dlq', /redrive_policy\s*=\s*null/, 'medium'],
  ['tf-aws-elasticache-public', /resource\s+"aws_elasticache_cluster"[^}]*publicly_accessible\s*=\s*true/, 'critical'],
  ['tf-aws-redshift-public', /resource\s+"aws_redshift_cluster"[^}]*publicly_accessible\s*=\s*true/, 'critical'],
  ['tf-aws-mq-public', /resource\s+"aws_mq_broker"[^}]*publicly_accessible\s*=\s*true/, 'critical'],
];

const AZURE_PATTERNS: Array<[string, RegExp, Severity]> = [
  ['tf-az-sa-public', /allow_blob_public_access\s*=\s*true/, 'high'],
  ['tf-az-sql-no-firewall', /start_ip_address\s*=\s*["']0\.0\.0\.0["'][^}]*end_ip_address\s*=\s*["']0\.0\.0\.0["']/, 'high'],
  ['tf-az-vm-no-password', /disable_password_authentication\s*=\s*false/, 'medium'],
  ['tf-az-aks-no-ip-ranges', /api_server_authorized_ip_ranges\s*=\s*\[\s*\]/, 'high'],
  ['tf-az-storage-https-only', /enable_https_traffic_only\s*=\s*false/, 'high'],
];

const GCP_PATTERNS: Array<[string, RegExp, Severity]> = [
  ['tf-gcp-sa-full', /access_token_scopes\s*=\s*\[\s*"https:\/\/www\.googleapis\.com\/auth\/cloud-platform"\s*\]/, 'critical'],
  ['tf-gcp-bucket-public', /uniform_bucket_level_access\s*=\s*false|acl\s*=\s*\[/, 'high'],
  ['tf-gcp-sql-public', /ip_configuration\.ipv4_enabled\s*=\s*true/, 'critical'],
  ['tf-gcp-container-no-client-certs', /issue_client_certificate\s*=\s*false/, 'high'],
  ['tf-gcp-node-pool-default-sa', /service_account\s*=\s*"default"/, 'medium'],
];

const SECRETS_PATTERNS: Array<[string, RegExp, Severity]> = [
  ['tf-secret-hardcoded', /password\s*=\s*["'][^'"]{4,}["']|secret\s*=\s*["'][^'"]{4,}["']|api_key\s*=\s*["'][^'"]{4,}["']/, 'critical'],
  ['tf-secret-variable', /variable\s+"[^"]+"\s*\{[^}]*\}/, 'medium'],
];

const PROVIDER_RULES = new Map<string, { severity: Severity; pattern: RegExp }>(
  RULE_PATTERNS.map(([k, r, s]) => [k, { severity: s, pattern: r }])
);
const AZURE_RULES = new Map<string, { severity: Severity; pattern: RegExp }>(
  AZURE_PATTERNS.map(([k, r, s]) => [k, { severity: s, pattern: r }])
);
const GCP_RULES = new Map<string, { severity: Severity; pattern: RegExp }>(
  GCP_PATTERNS.map(([k, r, s]) => [k, { severity: s, pattern: r }])
);
const SECRETS_RULES = new Map<string, { severity: Severity; pattern: RegExp }>(
  SECRETS_PATTERNS.map(([k, r, s]) => [k, { severity: s, pattern: r }])
);

function scanExpression(expr: string, rules: Map<string, { severity: Severity; title: string; advice: string[]; pattern: RegExp }>): Array<{ ruleId: string; severity: Severity; title: string; advice: string[] }> {
  const matches: Array<{ ruleId: string; severity: Severity; title: string; advice: string[] }> = [];
  for (const [ruleId, rule] of rules) {
    if (rule.pattern.test(expr)) {
      matches.push({ ruleId, severity: rule.severity, title: rule.title, advice: rule.advice });
    }
  }
  return matches;
}

function parseSimpleTerraform(content: string): Array<{ resource: string; type: string; name: string; body: string }> {
  const resources: Array<{ resource: string; type: string; name: string; body: string }> = [];

  let match;
  while ((match = RESOURCE_BLOCK_RE.exec(content)) !== null) {
    resources.push({ resource: match[0], type: match[1], name: match[2], body: match[3] });
  }

  while ((match = DATA_BLOCK_RE.exec(content)) !== null) {
    resources.push({ resource: match[0], type: `data.${match[1]}`, name: match[2], body: match[3] });
  }

  RESOURCE_BLOCK_RE.lastIndex = 0;
  DATA_BLOCK_RE.lastIndex = 0;

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
          title: ruleId.replace(/-/g, ' ').replace(/tf [a-z]+ /i, ''),
          resource: `${res.type}.${res.name}`,
          advice: [`Review and fix ${ruleId} security issue`],
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
        title: ruleId.replace(/-/g, ' ').replace(/tf [a-z]+ /i, ''),
        resource: 'variables',
        line: lineMatch.length,
        advice: [`Review and fix ${ruleId} security issue`],
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