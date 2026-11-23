#!/usr/bin/env bash
# skwod — one-command VPS install.
#
# Stands up a public, HTTPS self-hosted skwod server on a fresh Linux box: installs Docker if
# needed, gets a real TLS certificate for your domain automatically (Caddy + Let's Encrypt), starts
# the ciphertext-only server, and prints your URL + one-time owner setup code.
#
# Usage (run as root, from a clone of this repo):
#   sudo ./deploy/vps-install.sh chat.example.com you@example.com
#   # or:  sudo DOMAIN=chat.example.com ACME_EMAIL=you@example.com ./deploy/vps-install.sh
#
# Prereqs: a Linux VPS with a public IP, and a DNS A record pointing your domain at it. 1 GB RAM is
# enough to run; building from source comfortably wants ~2 GB (or set SKWOD_IMAGE to a prebuilt image).
set -euo pipefail

DOMAIN="${1:-${DOMAIN:-}}"
ACME_EMAIL="${2:-${ACME_EMAIL:-}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!  %s\033[0m\n' "$*"; }
die()  { printf '\033[31mx  %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "Please run as root (sudo) — installing Docker and binding ports 80/443 need it."

if [ -z "$DOMAIN" ]; then
  read -rp "Domain for this server (e.g. chat.example.com): " DOMAIN
fi
[ -n "$DOMAIN" ] || die "A domain is required (it's what your friends and the mobile app connect to)."
case "$DOMAIN" in
  http*|*/*) die "Give a bare hostname, not a URL — e.g. chat.example.com" ;;
esac
if [ -z "$ACME_EMAIL" ]; then
  read -rp "Email for Let's Encrypt renewal notices (optional, press Enter to skip): " ACME_EMAIL || true
fi

# --- Docker -----------------------------------------------------------------------------------
if ! docker info >/dev/null 2>&1; then
  say "Installing Docker…"
  curl -fsSL https://get.docker.com | sh || die "Docker install failed."
  systemctl enable --now docker >/dev/null 2>&1 || true
fi
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (comes with modern Docker; try updating Docker)."

# --- DNS sanity check (best effort) -----------------------------------------------------------
MYIP="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
DNSIP="$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1 || true)"
if [ -n "$MYIP" ] && [ -n "$DNSIP" ] && [ "$MYIP" != "$DNSIP" ]; then
  warn "$DOMAIN currently resolves to $DNSIP but this box is $MYIP."
  warn "TLS issuance will fail until the DNS A record points here. Continuing anyway…"
fi

# --- Caddyfile (auto-HTTPS reverse proxy) -----------------------------------------------------
say "Writing Caddy config for https://$DOMAIN"
{
  [ -n "$ACME_EMAIL" ] && printf '{\n\temail %s\n}\n\n' "$ACME_EMAIL"
  printf '%s {\n\treverse_proxy skwod:3000\n}\n' "$DOMAIN"
} > "$SCRIPT_DIR/Caddyfile"

cd "$SCRIPT_DIR"
COMPOSE=(docker compose -f docker-compose.vps.yml -p skwod)

# --- First-run bootstrap: generate the one-time owner setup code ------------------------------
STATE="$SCRIPT_DIR/.skwod-vps-initialized"
if [ ! -f "$STATE" ]; then
  say "Building the server image (first run — this can take a few minutes)…"
  "${COMPOSE[@]}" build skwod
  say "Bootstrapping your instance…"
  # One-shot: migrate + set the one-time owner setup code; prints the code once.
  INIT_OUT="$("${COMPOSE[@]}" run --rm --no-deps skwod \
    skwod init --no-livekit --yes --data /data --domain "$DOMAIN" 2>&1)" || { echo "$INIT_OUT"; die "Bootstrap failed."; }
  echo "$INIT_OUT"
  JOIN_CODE="$(printf '%s\n' "$INIT_OUT" | grep -oE 'SKWD-[A-Z0-9]{4}-[A-Z0-9]{4}' | head -1 || true)"
  touch "$STATE"
else
  say "Existing instance detected — updating in place (owner setup code unchanged)."
  "${COMPOSE[@]}" build skwod
fi

# --- Start (or restart) the server + proxy ----------------------------------------------------
say "Starting skwod + Caddy…"
"${COMPOSE[@]}" up -d

cat <<EOF

────────────────────────────────────────────────────────────
  ✓ skwod is live at  https://$DOMAIN
EOF
if [ -n "${JOIN_CODE:-}" ]; then
cat <<EOF

  Owner setup code (one-time, for YOU):  $JOIN_CODE

  Open the skwod app, "Connect to a server", and sign up with:
      Server address:  https://$DOMAIN
      Join code:       $JOIN_CODE
  You become the owner. Then invite friends from inside the app
  (Invite → private code, expires in 7 days, revocable). This
  setup code stops working once you've claimed the server.
EOF
else
cat <<EOF

  (No setup code printed — this instance was already bootstrapped.
   Invite people from inside the app; the owner code is one-time.)
EOF
fi
cat <<EOF

  Manage:   cd $(pwd) && docker compose -f docker-compose.vps.yml -p skwod <logs|ps|restart|down>
  Data:     Docker volume 'skwod_skwod-data'  (SQLite + encrypted blobs — back this up)
────────────────────────────────────────────────────────────
EOF
