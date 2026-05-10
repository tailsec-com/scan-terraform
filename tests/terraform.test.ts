import { scanTerraform, formatTerraformOutput } from '../src/terraform';

describe('scanTerraform', () => {
  describe('empty terraform', () => {
    it('returns 0 findings', () => {
      const findings = scanTerraform('');
      expect(findings.length).toBe(0);
    });
  });

  describe('AWS S3', () => {
    it('finds tf-aws-s3-public-read', () => {
      const tf = `
resource "aws_s3_bucket" "example" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-aws-s3-public-read' }));
    });
  });

  describe('AWS RDS', () => {
    it('finds tf-aws-db-public', () => {
      const tf = `
resource "aws_db_instance" "example" {
  identifier           = "my-db"
  publicly_accessible  = true
  storage_encrypted    = false
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-aws-db-public' }));
    });
  });

  describe('AWS Security Group', () => {
    it('finds tf-aws-security-group-allow-all', () => {
      const tf = `
resource "aws_security_group" "example" {
  name = "open-all"
  ingress {
    from_port  = 0
    to_port    = 0
    protocol   = "all"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-aws-security-group-allow-all' }));
    });
  });

  describe('AWS IAM', () => {
    it('finds tf-aws-iam-admin', () => {
      const tf = `
resource "aws_iam_policy" "example" {
  name = "admin-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Resource = "*"
        Effect   = "Allow"
      }
    ]
  })
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-aws-iam-admin' }));
    });
  });

  describe('Azure Storage', () => {
    it('finds tf-az-sa-public', () => {
      const tf = `
resource "azurerm_storage_account" "example" {
  name                     = "examplestorage"
  resource_group_name       = "example-rg"
  location                  = "eastus"
  allow_blob_public_access  = true
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-az-sa-public' }));
    });
  });

  describe('GCP Storage', () => {
    it('finds tf-gcp-bucket-public', () => {
      const tf = `
resource "google_storage_bucket" "example" {
  name          = "example-bucket"
  location      = "US"
  acl           = []
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-gcp-bucket-public' }));
    });
  });
});

describe('formatTerraformOutput', () => {
  describe('text format', () => {
    it('contains "Terraform Findings"', () => {
      const output = formatTerraformOutput([], 'text');
      expect(output).toContain('Terraform Findings');
    });
  });

  describe('json format', () => {
    it('returns valid JSON with terraform array', () => {
      const findings = scanTerraform('');
      const output = formatTerraformOutput(findings, 'json');
      const parsed = JSON.parse(output);
      expect(parsed).toHaveProperty('terraform');
      expect(Array.isArray(parsed.terraform)).toBe(true);
      expect(parsed).toHaveProperty('total');
    });
  });
});