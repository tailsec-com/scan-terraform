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

  describe('AWS ElastiCache', () => {
    it('finds tf-aws-elasticache-public', () => {
      const tf = `
resource "aws_elasticache_cluster" "example" {
  cluster_id           = "example-cluster"
  engine              = "memcached"
  node_type           = "cache.t2.micro"
  num_cache_nodes     = 1
  publicly_accessible = true
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-aws-elasticache-public' }));
    });
  });

  describe('AWS Redshift', () => {
    it('finds tf-aws-redshift-public', () => {
      const tf = `
resource "aws_redshift_cluster" "example" {
  cluster_identifier = "example-cluster"
  database_name      = "mydb"
  master_username    = "admin"
  master_password    = "password123"
  node_type          = "dc1.large"
  publicly_accessible = true
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-aws-redshift-public' }));
    });
  });

  describe('AWS MQ Broker', () => {
    it('finds tf-aws-mq-public', () => {
      const tf = `
resource "aws_mq_broker" "example" {
  broker_name        = "example-broker"
  engine_type        = "ActiveMQ"
  engine_version     = "5.16.0"
  host_instance_type  = "mq.t3.micro"
  publicly_accessible = true
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-aws-mq-public' }));
    });
  });

  describe('AWS S3 ACL', () => {
    it('finds tf-aws-s3-public-read-write', () => {
      const tf = `
resource "aws_s3_bucket" "example" {
  bucket = "my-public-bucket"
  acl    = "public-read-write"
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-aws-s3-public-read-write' }));
    });
  });

  describe('AWS IAM User Policy', () => {
    it('finds tf-aws-iam-user-admin-access', () => {
      const tf = `
resource "aws_iam_user_policy" "example" {
  name = "admin-policy"
  user = "my-user"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
`;
      const findings = scanTerraform(tf);
      expect(findings.some(f => f.ruleId === 'tf-aws-iam-user-admin-access' || f.ruleId === 'tf-aws-iam-admin')).toBe(true);
    });
  });

  describe('Azure AKS', () => {
    it('finds tf-az-aks-no-ip-ranges', () => {
      const tf = `
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-cluster"
  location            = "eastus"
  resource_group_name  = "example-rg"
  dns_profile_prefix   = "example"
  api_server_authorized_ip_ranges = []
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-az-aks-no-ip-ranges' }));
    });
  });

  describe('Azure Storage HTTPS', () => {
    it('finds tf-az-storage-https-only', () => {
      const tf = `
resource "azurerm_storage_account" "example" {
  name                     = "examplestorage"
  resource_group_name       = "example-rg"
  location                  = "eastus"
  enable_https_traffic_only = false
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-az-storage-https-only' }));
    });
  });

  describe('GCP GKE', () => {
    it('finds tf-gcp-container-no-client-certs', () => {
      const tf = `
resource "google_container_cluster" "example" {
  name               = "example-cluster"
  location           = "us-central1"
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-gcp-container-no-client-certs' }));
    });
  });

  describe('GCP Node Pool', () => {
    it('finds tf-gcp-node-pool-default-sa', () => {
      const tf = `
resource "google_container_node_pool" "example" {
  name           = "example-pool"
  location       = "us-central1"
  cluster        = google_container_cluster.example.name
  node_count     = 1
  node_config {
    service_account = "default"
  }
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-gcp-node-pool-default-sa' }));
    });
  });

  describe('AWS S3 encryption', () => {
    it('finds tf-aws-s3-no-encryption when server_side_encryption_configuration is null', () => {
      const tf = `
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration = null
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-aws-s3-no-encryption' }));
    });
  });

  describe('AWS RDS backup', () => {
    it('finds tf-aws-db-no-backup when backup_retention_period = 0', () => {
      const tf = `
resource "aws_db_instance" "example" {
  identifier              = "my-db"
  backup_retention_period = 0
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-aws-db-no-backup' }));
    });
  });

  describe('AWS SQS', () => {
    it('finds tf-aws-sqs-dlq when redrive_policy is null', () => {
      const tf = `
resource "aws_sqs_queue" "example" {
  name = "my-queue"
  redrive_policy = null
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-aws-sqs-dlq' }));
    });
  });

  describe('Azure SQL', () => {
    it('finds tf-az-sql-no-firewall when firewall allows 0.0.0.0/0', () => {
      const tf = `
resource "azurerm_mssql_firewall_rule" "example" {
  name             = "example-firewall"
  server_id        = azurerm_mssql_server.example.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-az-sql-no-firewall' }));
    });
  });

  describe('Azure VM', () => {
    it('finds tf-az-vm-no-password when password_auth_enabled = true', () => {
      const tf = `
resource "azurerm_linux_virtual_machine" "example" {
  name                  = "example-vm"
  resource_group_name   = "example-rg"
  admin_ssh_key {
    public_key = "ssh-rsa AAAAB"
  }
  disable_password_authentication = false
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-az-vm-no-password' }));
    });
  });

  describe('AWS EC2', () => {
    it('finds tf-aws-ec2-key-pair when key_name is assigned', () => {
      const tf = `
resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  key_name      = "my-keypair"
}
`;
      const findings = scanTerraform(tf);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'tf-aws-ec2-key-pair' }));
    });
  });

  describe('AWS EMR', () => {
    it('finds tf-aws-emr-local-inbound', () => {
      const tf = `
resource "aws_emr_cluster" "example" {
  name               = "example-cluster"
  release_label      = "emr-6.0.0"
  service_role       = aws_iam_role.example.name
  local_outbound_security_group = aws_security_group.example.id
}
`;
      const findings = scanTerraform(tf);
      expect(findings.some(f => f.ruleId === 'tf-aws-emr-local-inbound')).toBe(true);
    });
  });

  describe('AWS Redshift encryption', () => {
    it('finds tf-aws-redshift-unencrypted', () => {
      const tf = `
resource "aws_redshift_cluster" "example" {
  cluster_identifier = "example-cluster"
  database_name      = "mydb"
  master_username    = "admin"
  master_password    = "password123"
  node_type          = "dc1.large"
  encrypted          = false
}
`;
      const findings = scanTerraform(tf);
      expect(findings.some(f => f.ruleId === 'tf-aws-redshift-unencrypted')).toBe(true);
    });
  });

  describe('AWS DocumentDB encryption', () => {
    it('finds tf-aws-documentdb-unencrypted', () => {
      const tf = `
resource "aws_docdb_cluster" "example" {
  cluster_identifier        = "example-cluster"
  engine                  = "docdb"
  master_username         = "admin"
  master_password         = "password123"
  storage_encrypted       = false
}
`;
      const findings = scanTerraform(tf);
      expect(findings.some(f => f.ruleId === 'tf-aws-documentdb-unencrypted')).toBe(true);
    });
  });

  describe('AWS MSK encryption', () => {
    it('finds tf-aws-msk-unencrypted', () => {
      const tf = `
resource "aws_msk_cluster" "example" {
  cluster_name           = "example-cluster"
  kafka_version          = "2.8.0"
  number_of_broker_nodes = 3
  encryption_at_rest_kms_key_id = null
}
`;
      const findings = scanTerraform(tf);
      expect(findings.some(f => f.ruleId === 'tf-aws-msk-unencrypted')).toBe(true);
    });
  });

  describe('AWS AppMesh TLS', () => {
    it('finds tf-aws-appmesh-missing-tls', () => {
      const tf = `
resource "aws_appmesh_mesh" "example" {
  name = "example-mesh"
  spec {
    tls {
      enforced = false
    }
  }
}
`;
      const findings = scanTerraform(tf);
      expect(findings.some(f => f.ruleId === 'tf-aws-appmesh-missing-tls')).toBe(true);
    });
  });

  describe('Multiple findings', () => {
    it('finds multiple findings of different severity', () => {
      const tf = `
resource "aws_db_instance" "example" {
  identifier           = "my-db"
  publicly_accessible  = true
  storage_encrypted    = false
}
`;
      const findings = scanTerraform(tf);
      const severities = findings.map(f => f.severity);
      expect(findings.length).toBeGreaterThan(1);
      expect(severities).toContain('critical');
      expect(severities).toContain('high');
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
