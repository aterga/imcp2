# Deploy mcp-poc to a single t4g.micro (low cost)

Stands up one ARM/Graviton `t4g.micro` running the `mcp-poc` container behind
Caddy (automatic HTTPS). A single always-on instance is used deliberately because
the server keeps modest in-memory state.

## What it creates

- 1× `t4g.micro` EC2 instance (Amazon Linux 2023, arm64) + 8 GB gp3 root volume
- An Elastic IP (stable public address) + association
- A security group allowing only inbound 80/443
- An IAM role for **SSM Session Manager** (shell access with no SSH port / key pair)
- Bootstrap (cloud-init) that installs Docker, adds 1 GB swap, runs the app, and
  runs Caddy for Let's Encrypt TLS

## Hostname / TLS — no domain required

By default you **don't need a domain**. If `domain` is left unset, the deployment
uses a free `<elastic-ip>.sslip.io` hostname (sslip.io resolves any `1.2.3.4.sslip.io`
to `1.2.3.4`), and Caddy gets a real Let's Encrypt cert for it. Zero DNS setup.

Want a stable, memorable name instead? Set `domain = "mcp.example.com"` and, after
apply, point an A record at the `public_ip` output.

## Rough cost (us-east-1; eu-central-1 ~10% more)

| Item | ~Monthly |
|---|---|
| t4g.micro on-demand | ~$6.13 |
| 8 GB gp3 | ~$0.65 |
| Public IPv4 (EIP) | ~$3.60 |
| **Total** | **~$10.38** |

To trim ~$3/mo, set `instance_type = "t4g.nano"` (0.5 GB) — fine if RAM stays low.
`terraform destroy` removes everything and stops the billing.

## Prerequisites

- Terraform >= 1.5 and AWS credentials (`aws configure`, `AWS_PROFILE`, env vars,
  or an AWS CloudShell session)
- The arm64 image published by this repo's GitHub Actions
  (`ghcr.io/<owner>/imcp2:latest`). If you kept the package private, set
  `ghcr_user`/`ghcr_token`; otherwise make the package public.

## Apply

```sh
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # set region (domain optional)
terraform init
terraform apply
```

When it finishes, check the `server_url` output — that's your endpoint. With the
default sslip.io hostname there's nothing else to do; Caddy issues the cert within
a minute or two. (If you set a custom `domain`, first create the A record shown in
the `dns_note` output, then the cert issues.)

## Operate

```sh
# Shell in (needs the Session Manager plugin for the AWS CLI):
aws ssm start-session --target <instance_id>

# On the box:
sudo docker logs -f mcp
sudo docker logs -f caddy
```

## Update the image

```sh
sudo docker pull ghcr.io/<owner>/imcp2:latest && sudo docker restart mcp
```

## Notes

- **Spot is intentionally not used**: an interruption would wipe the in-memory
  state. This is plain on-demand.
- Default is `t4g.micro` (1 GB). Swap covers spikes; if you drop to `t4g.nano`
  (0.5 GB) and see OOM kills in `dmesg`/`docker logs`, go back to micro.
- Changing the bootstrap script recreates the instance
  (`user_data_replace_on_change = true`).
