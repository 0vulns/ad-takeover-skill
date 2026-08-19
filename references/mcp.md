# Kali MCP (Docker or SSH)

Stdio MCP server. **No extra pip deps.** Talks to `adtk-kali` via `docker exec`
or to any Kali over SSH. Lab / RoE only.

```
python3 mcp/server.py --self-test
ADTK_TRANSPORT=docker python3 mcp/server.py
ADTK_TRANSPORT=ssh ADTK_SSH=root@192.168.56.200 python3 mcp/server.py
```

## Wire it

Replace `/ABSOLUTE/PATH` in `mcp/claude_desktop.example.json` or
`mcp/cursor.example.json`.

Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json`.

Cursor: `.cursor/mcp.json` in the project, or Settings → MCP.

One server at a time. Leave `ADTK_TRANSPORT` unset for auto (Docker if the
container is up, else SSH when `ADTK_SSH` is set), or force `docker` / `ssh`.

## Env

| Var | Default | Meaning |
| --- | --- | --- |
| `ADTK_TRANSPORT` | auto | `docker` / `ssh`; unset = auto (Docker if container up, else SSH) |
| `ADTK_CONTAINER` | `adtk-kali` | compose service name |
| `ADTK_COMPOSE` | `<pack>/docker` | compose directory (`kali_up`) |
| `ADTK_SSH` | `root@127.0.0.1` | `user@host` |
| `ADTK_SSH_PORT` | `22` | |
| `ADTK_SSH_KEY` | empty | identity file |
| `ADTK_LOGS` | `/logs` | base log dir; each DC gets `logs/<dc-ip>/` under it (SSH VM with no `/logs` bind → e.g. `/home/kali/logs`) |

## Per-target log tree

The DC IP passed to `ad_plan` / `ad_auto` / `kali_preflight` selects the
current target. After that, `logs_read`, `logs_ls`, `logs_write`, `bh_next`, the
digest, and `kali_exec background:true` logs all resolve under `logs/<dc-ip>/`
(`auto/`, `hashes/`, `bloodhound/`, `nmap/`, …). Runs against different DCs
never overwrite each other. Absolute paths under `/logs` are still accepted.

SSH uses `BatchMode` + `IdentitiesOnly`. Get a key login working first:

```
ssh -i ~/.ssh/id_ed25519 root@192.168.56.200 hostname
```

If SSH cannot write `/opt/adtk`, copy the pack scripts there once, then bootstrap:

```
scp -r scripts conf root@HOST:/opt/adtk/         # or rsync
ssh root@HOST 'ls /opt/adtk/bootstrap.sh /opt/adtk/ad-auto.py'
```

## Tools

| Tool | Auth | Does |
| --- | --- | --- |
| `kali_status` | no | container / ssh alive? |
| `kali_up` | yes | `compose up -d` (`lan` or `vpn`) |
| `kali_bootstrap` | yes | `/opt/adtk/bootstrap.sh` |
| `kali_preflight` | yes | VPN: clamp tun0 mtu 1200 + ntpdate + verify + null/guest probe |
| `kali_exec` | yes | arbitrary bash on Kali (`background:true` for long scans) |
| `kali_logs` | no | tail a background job logfile in the target `logs/<dc>/` tree |
| `ad_auto` | yes | decision engine (returns a parsed digest); `dc` sets the target |
| `ad_plan` | no | next action only (+ digest); `dc` sets the target |
| `bh_next` | no | BloodHound zip → edges |
| `mssql_hop` | yes | impersonate / links |
| `logs_ls` / `logs_read` | no | current target `logs/<dc>/` only |
| `logs_write` | yes | current target `logs/<dc>/` only |

`ad_auto` / `ad_plan` append a `== digest ==` block (owned creds, done steps, the
printed next edge) parsed from `auto/state.json` — the model still decides; the
server just trims raw logs. No LLM runs inside the server.

Mutating tools refuse unless `i_am_authorized: true`.

## Agent loop (MCP first, tools second, attacks last)

This is the same loop as `SKILL.md` — mirror it exactly. Preinstall the rack
and verify binaries **before** recon / roast / BloodHound / `ad_auto`.

1. Restate lab / RoE.
2. Transport: leave `ADTK_TRANSPORT` unset (auto) or force `=docker` / `=ssh`.
3. `kali_status`.
4. Docker + down → `kali_up` (`vpn` on tun0 / HTB, else `lan`).
   SSH: key login already works; copy pack scripts to `/opt/adtk` if missing (above).
   VPN labs: `kali_preflight` (clamp tun0 mtu 1200 + clock) — re-run after any reconnect.
5. `kali_bootstrap` **once per box**. Wait for it. `i_am_authorized: true`.
6. **Verify binaries** — one `kali_exec`, same on Docker and SSH:

```
for b in nxc netexec nmap hashcat secretsdump.py getST.py certipy bloodyAD; do \
  command -v $b >/dev/null && echo "ok  $b" || echo "MISSING $b"; done; \
( command -v GetUserSPNs.py >/dev/null || command -v impacket-GetUserSPNs >/dev/null ) \
  && echo "ok  GetUserSPNs" || echo "MISSING GetUserSPNs"; \
test -f /opt/adtk/ad-auto.py && echo "ok  ad-auto.py" || echo "MISSING ad-auto.py"
```

7. Only now: `ad_plan` / `ad_auto` / `kali_exec` for the current step.
8. `logs_read` `auto/state.json` and `auto/report.txt`.
9. After a BloodHound collect: `bh_next`, then **one** `kali_exec` for the printed edge.

Any `MISSING` line → fix `scripts/bootstrap.sh` **and** `docker/Dockerfile`, then
re-`kali_bootstrap`. Never `apt`/`pip` ad-hoc inside the kill chain.

Do not open a Relayer / Responder / mitm6 via MCP — those hang. Point the
operator at an interactive `docker exec -it` / SSH tty. Long scans (nmap `-p-`):
use `kali_exec` with `background: true`, then poll with `kali_logs`, so a slow
scan isn't lost to a tool timeout.

SSH Kali VM without passwordless sudo: privileged commands (`ip link … mtu`,
`openvpn`) need `echo <pass> | sudo -S …`. `kali_preflight` / `preflight.sh`
handle this via `KALI_SUDO_PASS` (defaults to `kali`).

## Fail → next

| Symptom | Next |
| --- | --- |
| `docker: command not found` / not on PATH | MCP host must see Docker Desktop / colima; or switch `ADTK_TRANSPORT=ssh` |
| `kali_status` down / inspect empty | `kali_up` (right `mode`), or wrong `ADTK_CONTAINER` |
| SSH `Permission denied (publickey)` | fix key + `ADTK_SSH_KEY`; `ssh … hostname` must pass with `BatchMode=yes` first |
| `bootstrap.sh: No such file` | pack not at `/opt/adtk` — Docker: compose mounts `scripts/:/opt/adtk`; SSH: copy scripts there, then `kali_bootstrap` |
| `ad-auto.py` missing | same mount / copy issue — re-`kali_bootstrap` / re-compose |
| binary `MISSING` after bootstrap | add pkg to `scripts/bootstrap.sh` + `docker/Dockerfile`; re-bootstrap. Do not apt/pip in the chain |
| tool hangs | timeout 120s. poison / relay / responder is not an MCP job — interactive tty |
