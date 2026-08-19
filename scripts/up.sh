#!/bin/bash
# Bring up the Kali attack box on the lab LAN.
# Usage:
#   IP_RANGE=192.168.56 LAB_PARENT=vboxnet0 ./up.sh
#   ./up.sh vpn          # host network (HTB / tun0)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/docker"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "[*] wrote docker/.env from .env.example — edit LAB_PARENT if needed"
fi

mkdir -p "$ROOT/loot"

if [ "${1:-}" = "vpn" ]; then
  docker compose -f docker-compose.vpn.yml up -d
else
  docker compose up -d
fi

echo "[+] gotad-kali is up"
echo "    docker exec -it gotad-kali bash"
echo "    /opt/gotad/bootstrap.sh    # once on the vanilla image"
echo "    python3 /opt/gotad/ad-auto.py --help"
