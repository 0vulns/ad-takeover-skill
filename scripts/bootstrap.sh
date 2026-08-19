#!/bin/bash
# Install the public AD tool rack inside Kali. Run once.
#   docker exec -it gotad-kali /opt/gotad/bootstrap.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  kali-linux-headless \
  netexec impacket-scripts bloodhound.py responder \
  nmap ncat ldap-utils smbclient krb5-user enum4linux-ng \
  hashcat john seclists proxychains4 evil-winrm \
  python3-pip python3-venv git curl wget \
  iproute2 iputils-ping dnsutils \
  rlwrap tmux vim freerdp2-x11 ntpdate

pip3 install --break-system-packages \
  certipy-ad bloodhound bloodyAD ldeep ldapdomaindump coercer mitm6 pygpoabuse || true

# optional collectors / helpers (best-effort)
pip3 install --break-system-packages bloodhound-ce || true
# rusthound-ce: fast BH-CE collector; some rooms (Operation Endgame) expect it.
# apt first, cargo fallback if the crate/binary is available.
if ! command -v rusthound-ce >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends rusthound-ce 2>/dev/null \
    || cargo install rusthound-ce 2>/dev/null || true
fi
if [ ! -d /root/tools/targetedKerberoast ]; then
  git clone --depth 1 https://github.com/ShutdownRepo/targetedKerberoast.git /root/tools/targetedKerberoast || true
fi
if [ ! -d /root/tools/krbrelayx ]; then
  git clone --depth 1 https://github.com/dirkjanm/krbrelayx.git /root/tools/krbrelayx || true
fi

mkdir -p /loot/{nmap,hashes,bloodhound,tickets,adcs,enum,auto} /root/tools

if [ -d /opt/gotad/conf ]; then
  if [ ! -f /etc/hosts.gotad.bak ]; then
    cp /etc/hosts /etc/hosts.gotad.bak
    cat /opt/gotad/conf/hosts.goad >> /etc/hosts
  fi
  if [ ! -f /etc/krb5.conf.gotad.bak ] && [ -f /opt/gotad/conf/krb5.conf ]; then
    cp /etc/krb5.conf /etc/krb5.conf.gotad.bak 2>/dev/null || true
    cp /opt/gotad/conf/krb5.conf /etc/krb5.conf
  fi
fi

chmod +x /opt/gotad/ad-auto.py 2>/dev/null || true

# Verify the rack. Same check the MCP loop runs (SKILL.md step 6 / mcp.md).
echo "[*] verifying tool rack..."
miss=0
for b in nxc netexec nmap hashcat secretsdump.py getST.py certipy bloodyAD; do
  if command -v "$b" >/dev/null 2>&1; then echo "    ok  $b"; else echo "    MISSING $b"; miss=1; fi
done
if command -v GetUserSPNs.py >/dev/null 2>&1 || command -v impacket-GetUserSPNs >/dev/null 2>&1; then
  echo "    ok  GetUserSPNs"; else echo "    MISSING GetUserSPNs"; miss=1; fi
if [ -f /opt/gotad/ad-auto.py ]; then echo "    ok  ad-auto.py"; else echo "    MISSING ad-auto.py"; miss=1; fi

if [ "$miss" -ne 0 ]; then
  echo "[!] Some tools are MISSING. Add them to scripts/bootstrap.sh AND docker/Dockerfile,"
  echo "    then re-run this script. Do NOT apt/pip ad-hoc during the kill chain."
else
  echo "[+] Kali tooled and verified."
fi
echo "    python3 /opt/gotad/ad-auto.py --i-am-authorized --dc <DC> --domain <DOM> --cidr <CIDR>"
