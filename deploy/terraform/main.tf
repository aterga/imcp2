terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Latest Amazon Linux 2023 arm64 AMI, resolved from the canonical public SSM parameter.
data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-al2023-latest/al2023-ami-kernel-default-arm64"
}

# Use the account's default VPC and one of its subnets — no NAT/extra networking cost.
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Inbound 80/443 only; the app's port 8000 is never exposed (Caddy fronts it).
resource "aws_security_group" "mcp" {
  name_prefix = "mcp-poc-"
  description = "mcp-poc: HTTP/HTTPS in, all out"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description      = "HTTP (ACME challenge + redirect)"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description      = "HTTPS"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

# IAM role so we can shell in via SSM Session Manager (no SSH port, no key pair).
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "mcp" {
  name_prefix        = "mcp-poc-"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.mcp.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "mcp" {
  name_prefix = "mcp-poc-"
  role        = aws_iam_role.mcp.name
}

resource "aws_instance" "mcp" {
  ami                    = data.aws_ssm_parameter.al2023_arm64.value
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.mcp.id]
  iam_instance_profile   = aws_iam_instance_profile.mcp.name

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_gb
    encrypted   = true
  }

  # Require IMDSv2.
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  user_data = templatefile("${path.module}/cloud-init.sh.tftpl", {
    domain     = local.domain
    image      = var.image
    acme_email = var.acme_email
    ghcr_user  = var.ghcr_user
    ghcr_token = var.ghcr_token
  })
  # Re-create the instance if the bootstrap config changes.
  user_data_replace_on_change = true

  tags = { Name = "mcp-poc" }
}

# Stable public IP. Allocated standalone (not via the instance) so its address is
# known before the instance boots — that lets us feed it into the sslip.io hostname
# and the cloud-init without a dependency cycle. Associated to the instance below.
resource "aws_eip" "mcp" {
  domain = "vpc"
  tags   = { Name = "mcp-poc" }
}

resource "aws_eip_association" "mcp" {
  instance_id   = aws_instance.mcp.id
  allocation_id = aws_eip.mcp.id
}

# Use the provided FQDN, or fall back to a free <ip>.sslip.io hostname that
# resolves to the Elastic IP (no domain purchase, no DNS records to manage).
locals {
  domain = var.domain != "" ? var.domain : "${aws_eip.mcp.public_ip}.sslip.io"
}
