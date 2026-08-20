#!/bin/bash
# Install the public AD tool rack inside Kali. Run once.
#   docker exec -it adtk-kali /opt/adtk/bootstrap.sh
#
# Do NOT install kali-linux-headless on an SSH-transport box — the metapackage
# restarts networking mid-apt and can hang the VM. Opt in on Docker with
# ADTK_FULL_METAPACKAGE=1. Package names drift (freerdp2-x11/ntpdate gone);
# we try current names first and fall back so one missing pkg cannot abort
# the whole transaction (set -e + a dead pkg = EXIT 100).
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive

# Docker runs as root. SSH Kali is usually `kali` with no NOPASSWD —
# ADTK_SUDO_PASS (alias KALI_SUDO_PASS) is piped to sudo -S.
run_priv() {
  if [ "$(id -u)" = "0" ]; then
    "$@"
  elif sudo -n true 2>/dev/null; then
    sudo -p '' "$@"
  else
    echo "${ADTK_SUDO_PASS:-${KALI_SUDO_PASS:-kali}}" | sudo -S -p '' "$@"
  fi
}

apt_try() {
  run_priv apt-get install -y --no-install-recommends "$@"
}

apt_first() {
  local pkg
  for pkg in "$@"; do
    apt_try "$pkg" && return 0
  done
  echo "[!] none of: $*  (continuing)"
  return 0
}

have() {
  local b
  for b in "$@"; do
    command -v "$b" >/dev/null 2>&1 && return 0
  done
  return 1
}

run_priv apt-get update
apt_try \
  netexec impacket-scripts bloodhound.py responder \
  nmap ncat ldap-utils smbclient krb5-user enum4linux-ng \
  hashcat john seclists proxychains4 evil-winrm \
  python3-pip python3-venv git curl wget \
  iproute2 iputils-ping dnsutils \
  rlwrap tmux vim

# Renamed in current Kali repos (2025/2026). Try new, then old.
apt_first freerdp-x11 freerdp2-x11
apt_first ntpsec-ntpdate ntpdate

if [ "${ADTK_FULL_METAPACKAGE:-}" = "1" ]; then
  echo "[*] ADTK_FULL_METAPACKAGE=1 — installing kali-linux-headless (Docker only)"
  apt_try kali-linux-headless || true
fi

run_priv pip3 install --break-system-packages \
  certipy-ad bloodhound bloodyAD ldeep ldapdomaindump coercer mitm6 pygpoabuse || true

# optional collectors / helpers (best-effort)
run_priv pip3 install --break-system-packages bloodhound-ce || true
# rusthound-ce: fast BH-CE collector; some rooms (Operation Endgame) expect it.
# apt first, cargo fallback if the crate/binary is available.
if ! command -v rusthound-ce >/dev/null 2>&1; then
  apt_try rusthound-ce \
    || cargo install rusthound-ce 2>/dev/null || true
fi
TOOLS_DIR=/root/tools
if ! mkdir -p "$TOOLS_DIR" 2>/dev/null || [ ! -w "$TOOLS_DIR" ]; then
  TOOLS_DIR="${HOME}/tools"
  mkdir -p "$TOOLS_DIR"
fi
if [ ! -d "$TOOLS_DIR/targetedKerberoast" ]; then
  git clone --depth 1 https://github.com/ShutdownRepo/targetedKerberoast.git "$TOOLS_DIR/targetedKerberoast" || true
fi
if [ ! -d "$TOOLS_DIR/krbrelayx" ]; then
  git clone --depth 1 https://github.com/dirkjanm/krbrelayx.git "$TOOLS_DIR/krbrelayx" || true
fi

# Base log root. /logs is the Docker bind; an SSH Kali usually cannot write it.
if mkdir -p /logs 2>/dev/null && [ -w /logs ]; then
  :
else
  mkdir -p "${HOME}/logs"
  echo "[*] /logs not writable — using ${HOME}/logs (set ADTK_LOGS there)"
fi

# conf/ ships *.example templates. Prefer a live file if the operator wrote one,
# else fall back to the .example so a vanilla checkout still tools the box.
if [ -d /opt/adtk/conf ]; then
  hosts_src="/opt/adtk/conf/hosts.goad"; [ -f "$hosts_src" ] || hosts_src="/opt/adtk/conf/hosts.goad.example"
  if [ -f "$hosts_src" ] && [ ! -f /etc/hosts.adtk.bak ]; then
    run_priv cp /etc/hosts /etc/hosts.adtk.bak
    run_priv bash -c "cat '$hosts_src' >> /etc/hosts"
  fi
  krb_src="/opt/adtk/conf/krb5.conf"; [ -f "$krb_src" ] || krb_src="/opt/adtk/conf/krb5.conf.example"
  if [ -f "$krb_src" ] && [ ! -f /etc/krb5.conf.adtk.bak ]; then
    run_priv cp /etc/krb5.conf /etc/krb5.conf.adtk.bak 2>/dev/null || true
    run_priv cp "$krb_src" /etc/krb5.conf
  fi
fi

run_priv chmod +x /opt/adtk/ad-auto.py 2>/dev/null || chmod +x /opt/adtk/ad-auto.py 2>/dev/null || true

# Verify the rack. Same check the MCP loop runs (SKILL.md step 6 / mcp.md).
# Debian/Kali ships Impacket as impacket-secretsdump, not secretsdump.py.
echo "[*] verifying tool rack..."
miss=0
check() {
  local label="$1"; shift
  if have "$@"; then echo "    ok  $label"; else echo "    MISSING $label"; miss=1; fi
}
check nxc nxc netexec
check nmap nmap
check hashcat hashcat
check certipy certipy certipy-ad
check bloodyAD bloodyAD
check secretsdump secretsdump.py impacket-secretsdump
check getST getST.py impacket-getST
check GetUserSPNs GetUserSPNs.py impacket-GetUserSPNs
if [ -f /opt/adtk/ad-auto.py ]; then echo "    ok  ad-auto.py"; else echo "    MISSING ad-auto.py"; miss=1; fi

if [ "$miss" -ne 0 ]; then
  echo "[!] Some tools are MISSING. Add them to scripts/bootstrap.sh AND docker/Dockerfile,"
  echo "    then re-run this script. Do NOT apt/pip ad-hoc during the kill chain."
else
  echo "[+] Kali tooled and verified."
fi
echo "    python3 /opt/adtk/ad-auto.py --i-am-authorized --dc <DC> --domain <DOM> --cidr <CIDR>"
