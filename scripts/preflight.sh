#!/bin/bash
# VPN preflight — run once per box and again after any VPN reconnect.
# Fixes the two most common time-sinks on tun0 / HTB / THM labs:
#   1. Path-MTU black-hole: tun0 negotiates ~1300 but the real path MTU is
#      lower (~1230), so full-MSS Kerberos TGS-REQs are silently dropped
#      ("Connection reset by peer"). We clamp tun0 to 1200.
#   2. Clock skew breaks Kerberos (KRB_AP_ERR_SKEW). We ntpdate the DC.
# Then it verifies the rack and probes null/guest so the first real command
# isn't the thing that discovers the box is unreachable.
#
#   /opt/adtk/preflight.sh <DC_IP> [IFACE] [MTU]
#   IFACE default tun0, MTU default 1200
set -uo pipefail

DC="${1:-}"
IFACE="${2:-tun0}"
MTU="${3:-1200}"

# passwordless sudo may be absent on a plain Kali VM — fall back to `sudo -S`.
run_priv() {
  if [ "$(id -u)" = "0" ]; then
    "$@"
  elif sudo -n true 2>/dev/null; then
    sudo -p '' "$@"
  else
    # KALI_SUDO_PASS lets MCP/non-interactive callers pipe the password in.
    echo "${ADTK_SUDO_PASS:-${KALI_SUDO_PASS:-kali}}" | sudo -S -p '' "$@" 2>/dev/null
  fi
}

echo "== preflight =="

# 1. MTU clamp (only if the iface exists) ---------------------------------
if ip link show "$IFACE" >/dev/null 2>&1; then
  cur=$(ip link show "$IFACE" | sed -n 's/.* mtu \([0-9]*\).*/\1/p' | head -1)
  run_priv ip link set dev "$IFACE" mtu "$MTU"
  now=$(ip link show "$IFACE" | sed -n 's/.* mtu \([0-9]*\).*/\1/p' | head -1)
  echo "  mtu $IFACE: ${cur:-?} -> ${now:-?}  (target $MTU)"
  [ "${now:-0}" = "$MTU" ] || echo "  WARN mtu not applied — Kerberos may RST; check sudo"
else
  echo "  iface $IFACE absent (LAN/macvlan lab? skip MTU clamp)"
fi

# 2. Clock sync (Kerberos) ------------------------------------------------
if [ -n "$DC" ]; then
  ntp_bin=""
  command -v ntpdate >/dev/null 2>&1 && ntp_bin=ntpdate
  command -v ntpsec-ntpdate >/dev/null 2>&1 && ntp_bin=ntpsec-ntpdate
  if [ -n "$ntp_bin" ]; then
    run_priv "$ntp_bin" -u "$DC" >/dev/null 2>&1 && echo "  clock: $ntp_bin $DC ok" \
      || echo "  clock: $ntp_bin $DC failed (try 'rdate' / check skew manually)"
  else
    echo "  clock: ntpdate/ntpsec-ntpdate missing — bootstrap installs it"
  fi
  # Optional PMTU sanity: DF-set ping ladder (1200 payload passes, 1400 fails
  # means the path MTU is below full-MSS — the 1200 clamp above handles it).
  if ping -M do -s 1400 -c1 -W2 "$DC" >/dev/null 2>&1; then
    echo "  pmtu: 1400B DF passes"
  else
    echo "  pmtu: 1400B DF blocked -> path MTU < full segment (1200 clamp is why we set it)"
  fi
else
  echo "  clock: no DC arg — pass the DC IP to sync (KRB_AP_ERR_SKEW otherwise)"
fi

# 3. Rack verify (same list as bootstrap step 6) --------------------------
echo "  rack:"
miss=0
have() { local b; for b in "$@"; do command -v "$b" >/dev/null 2>&1 && return 0; done; return 1; }
check() { local label="$1"; shift; have "$@" && echo "    ok  $label" || { echo "    MISSING $label"; miss=1; }; }
check nxc nxc netexec
check nmap nmap
check john john
check certipy certipy certipy-ad
check bloodyAD bloodyAD
check secretsdump secretsdump.py impacket-secretsdump
check getST getST.py impacket-getST
check getTGT getTGT.py impacket-getTGT
check rbcd rbcd.py impacket-rbcd
check dacledit dacledit.py impacket-dacledit
check GetUserSPNs GetUserSPNs.py impacket-GetUserSPNs
[ "$miss" -eq 0 ] || echo "  -> MISSING tools: fix scripts/bootstrap.sh + docker/Dockerfile, re-bootstrap. No ad-hoc apt/pip."

# 4. Null / guest probe ---------------------------------------------------
if [ -n "$DC" ] && command -v nxc >/dev/null 2>&1; then
  echo "  smb null : $(nxc smb "$DC" -u '' -p '' --shares 2>/dev/null | grep -c '[+]') +hits"
  echo "  smb guest: $(nxc smb "$DC" -u guest -p '' --shares 2>/dev/null | grep -c '[+]') +hits (empty pw is first-class)"
fi

echo "== preflight done =="
