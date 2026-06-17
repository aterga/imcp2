variable "region" {
  description = "AWS region to deploy into. us-east-1 is typically cheapest."
  type        = string
  default     = "us-east-1"
}

variable "domain" {
  description = "Public FQDN for the server. Leave empty (default) to auto-derive a free <ip>.sslip.io hostname from the Elastic IP — no domain to buy, no DNS to set up. Set a real FQDN for a stable name, then point an A record at the eip output after apply."
  type        = string
  default     = ""
}

variable "image" {
  description = "Container image to run (arm64). Built by the repo's GitHub Actions workflow."
  type        = string
  default     = "ghcr.io/aterga/imcp2:latest"
}

variable "acme_email" {
  description = "Email for Let's Encrypt expiry notices (used by Caddy). Optional but recommended."
  type        = string
  default     = ""
}

variable "instance_type" {
  description = "EC2 instance type (ARM/Graviton). t4g.micro (1 GB) is the safe default; drop to t4g.nano (0.5 GB) to save ~$3/mo if RAM headroom allows."
  type        = string
  default     = "t4g.micro"
}

variable "root_volume_gb" {
  description = "Root EBS volume size in GiB (gp3)."
  type        = number
  default     = 8
}

# Only needed if the GHCR package is private. Leave empty if you made it public.
variable "ghcr_user" {
  description = "GitHub username for pulling a private GHCR image."
  type        = string
  default     = ""
}

variable "ghcr_token" {
  description = "GitHub PAT with read:packages for pulling a private GHCR image."
  type        = string
  default     = ""
  sensitive   = true
}
