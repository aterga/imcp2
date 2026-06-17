# Native (Docker-free) deploy of mcp-poc

Run `mcp-poc` directly on an **existing** Amazon Linux 2023 (arm64) host as native
`systemd` services — no Docker on the box. Useful when the instance already exists
(e.g. in a managed VPC) and you just want to put the app on it. The repo's
[`Dockerfile`](../../Dockerfile) remains the container-based alternative.

```
   build.sh  ─────►  build-out/mcp-poc        (cross-built linux/arm64 binary)
   deploy.sh ─────►  /opt/imcp2/{mcp-poc,static}   + systemd: mcp-poc.service
                     /usr/local/bin/caddy          + systemd: caddy.service (TLS)
```

`mcp-poc` listens on `127.0.0.1:8000`/`0.0.0.0:8000`; **Caddy** terminates HTTPS for
your domain and reverse-proxies to it, obtaining a Let's Encrypt cert automatically.

## Quick start

```sh
# 1. Cross-build the arm64 binary (needs Docker locally; compiles in a container).
deploy/native/build.sh

# 2. Ship it and stand up the services.
HOST=ec2-user@<host> DOMAIN=mcp.example.com ACME_EMAIL=you@example.com \
  deploy/native/deploy.sh
```

`deploy.sh` is idempotent — re-run it to push a new build (it restarts `mcp-poc`).

## Why cross-build against bullseye

`build.sh` compiles in a `rust:1-slim-bullseye` container (glibc **2.31**). A binary
linked against an older glibc runs on newer ones, so it works on AL2023 (glibc 2.34).
Building against bookworm (glibc 2.36) would fail at runtime on AL2023. The build is
native arm64 (no QEMU) and handles the heavy deps (`aws-lc-sys`, `ring`, `rustls`).

## Host prerequisites

- **Inbound 80 + 443 from the internet** in the security group. Port 80 and 443 are
  both used for ACME (Caddy prefers TLS-ALPN-01 on 443, falls back to HTTP-01 on 80)
  and 443 serves traffic; 80 also does the HTTP→HTTPS redirect.
- **DNS**: an `A` (and/or `AAAA`) record for `$DOMAIN` pointing at the host's public
  address. Let's Encrypt validates over whichever the record resolves to.
- A sudo-capable SSH user (the units run the app as `ec2-user`).

### Networking note for private-subnet / managed VPCs

If the instance's primary interface is in a **private subnet** (default IPv4 route via
a NAT gateway), its IPv4 is outbound-only and **not reachable from the internet** — only
IPv6 (if the subnet routes `::/0` to an Internet Gateway) is publicly reachable. To get
public IPv4, attach a **second ENI in a public subnet** (route table `0.0.0.0/0 → IGW`)
and associate an Elastic IP; AL2023's `amazon-ec2-net-utils` auto-configures the
source-based policy routing for the secondary interface. Point `$DOMAIN` at that EIP.

## Operating

```sh
ssh <host>
sudo systemctl status mcp-poc caddy
sudo journalctl -u mcp-poc -f      # app logs
sudo journalctl -u caddy -f        # TLS / cert logs
```

## Files

| File | Purpose |
|---|---|
| `build.sh` | Cross-build `build-out/mcp-poc` (linux/arm64, bullseye glibc) |
| `deploy.sh` | Ship binary + `static/`, render & install units/Caddyfile, (re)start services |
| `mcp-poc.service` | systemd unit for the app (`__PUBLIC_URL__` substituted at deploy) |
| `caddy.service` | systemd unit for Caddy |
| `Caddyfile` | Caddy config (`__DOMAIN__`, `__ACME_EMAIL__` substituted at deploy) |
