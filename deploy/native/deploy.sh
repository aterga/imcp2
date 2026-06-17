#!/usr/bin/env bash
# Deploy mcp-poc to an existing Amazon Linux 2023 (arm64) host WITHOUT Docker on the
# box: ships the prebuilt binary + static assets, then runs the app and Caddy as
# native systemd services. Re-runnable (idempotent) — also use it to push updates.
#
# Prereqs:
#   - deploy/native/build.sh has produced build-out/mcp-poc
#   - SSH access to the host as a sudo-capable user
#   - DNS A/AAAA for $DOMAIN points at the host's public address(es)
#   - Security group allows inbound 80 + 443 from the internet (ACME + HTTPS)
#
# Usage:
#   HOST=ec2-user@1.2.3.4 DOMAIN=mcp.example.com ACME_EMAIL=you@example.com \
#     deploy/native/deploy.sh
set -euo pipefail

: "${HOST:?set HOST=user@host}"
: "${DOMAIN:?set DOMAIN=fqdn}"
: "${ACME_EMAIL:?set ACME_EMAIL=email}"
REMOTE_DIR="${REMOTE_DIR:-/opt/imcp2}"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=20 $HOST"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"

[ -x "$repo_root/build-out/mcp-poc" ] || { echo "build-out/mcp-poc missing — run deploy/native/build.sh first"; exit 1; }

echo ">> staging $REMOTE_DIR"
$SSH "sudo install -d -o \$(id -un) -g \$(id -gn) $REMOTE_DIR"

echo ">> shipping binary + static assets"
tar -C "$repo_root/build-out" -cf - mcp-poc | $SSH "tar -C $REMOTE_DIR -xf - && chmod +x $REMOTE_DIR/mcp-poc"
tar -C "$repo_root" -cf - static | $SSH "tar -C $REMOTE_DIR -xf -"

echo ">> rendering + installing units and Caddyfile, then (re)starting services"
unit_mcp="$(sed "s#__PUBLIC_URL__#https://$DOMAIN#g" "$here/mcp-poc.service")"
caddyfile="$(sed -e "s#__DOMAIN__#$DOMAIN#g" -e "s#__ACME_EMAIL__#$ACME_EMAIL#g" "$here/Caddyfile")"
caddy_unit="$(cat "$here/caddy.service")"

$SSH "sudo bash -s" <<EOF
set -e
# ca-certificates: rustls platform verifier reads the system trust store
command -v update-ca-trust >/dev/null && dnf install -y -q ca-certificates >/dev/null 2>&1 || true

# --- app service ---
cat > /etc/systemd/system/mcp-poc.service <<'UNIT'
$unit_mcp
UNIT

# --- caddy: install static binary if missing, create user/dirs ---
if [ ! -x /usr/local/bin/caddy ]; then
  curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=arm64" -o /usr/local/bin/caddy
  chmod +x /usr/local/bin/caddy
fi
id caddy >/dev/null 2>&1 || useradd --system --home-dir /var/lib/caddy --shell /sbin/nologin caddy
mkdir -p /etc/caddy /var/lib/caddy && chown -R caddy:caddy /var/lib/caddy

cat > /etc/caddy/Caddyfile <<'CADDY'
$caddyfile
CADDY

cat > /etc/systemd/system/caddy.service <<'UNIT'
$caddy_unit
UNIT

systemctl daemon-reload
systemctl enable mcp-poc caddy
systemctl restart mcp-poc
systemctl restart caddy
EOF

echo ">> deployed. Verifying..."
sleep 6
$SSH "systemctl is-active mcp-poc caddy; ss -tlnp 2>/dev/null | grep -E ':(80|443|8000)\b' || true"
echo ">> external check:"
curl -sS -o /dev/null -w "https://$DOMAIN -> HTTP %{http_code} (TLS verify %{ssl_verify_result})\n" "https://$DOMAIN/" || true
