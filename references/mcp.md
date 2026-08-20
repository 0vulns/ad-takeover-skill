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
| `ADTK_LOGS` | `/logs` | base log dir; each DC gets `logs/<dc-ip>/` under it (SSH VM with no `/logs` bind → e.g. `/home/kali/logs`). MCP exports this into every remote command. |
| `ADTK_SUDO_PASS` | `kali` | SSH Kali without NOPASSWD — piped to `sudo -S` by `preflight.sh` (alias of `KALI_SUDO_PASS`) |

## Per-target log tree

The DC IP passed to `ad_plan` / `ad_auto` / `kali_preflight` selects the
current target. After that, `logs_read`, `logs_ls`, `logs_write`, `bh_next`, the
digest, and `kali_exec background:true` logs all resolve under `logs/<dc-ip>/`
(`auto/`, `hashes/`, `bloodhound/`, `nmap/`, …). Runs against different DCs
never overwrite each other. Absolute paths under `ADTK_LOGS` (default `/logs`)
are still accepted.

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

| Tool | Mutates | Does |
| --- | --- | --- |
| `kali_status` | no | container / ssh alive? |
| `kali_up` | yes | `compose up -d` (`lan` or `vpn`) |
| `kali_bootstrap` | yes | `/opt/adtk/bootstrap.sh` (**always detaches** — poll `kali_logs`) |
| `kali_preflight` | yes | VPN: clamp tun0 mtu 1200 + ntpdate + verify + null/guest probe |
| `kali_exec` | yes | bash on Kali. nmap / bloodhound / secretsdump / hashcat / apt **auto-detach**; poll `kali_logs`. `background: false` forces foreground. |
| `kali_logs` | no | tail a background job logfile in the target `logs/<dc>/` tree |
| `ad_auto` | yes | decision engine (**always detaches**); `dc` sets the target. Poll the log, then `logs_read auto/state.json` |
| `ad_plan` | no | next action only (+ digest); `dc` sets the target |
| `bh_next` | no | BloodHound zip → edges |
| `mssql_hop` | yes | impersonate / links |
| `logs_ls` / `logs_read` | no | current target `logs/<dc>/` only |
| `logs_write` | yes | current target `logs/<dc>/` only |

`ad_auto` / `ad_plan` append a `== digest ==` block (owned creds, done steps, the
printed next edge) parsed from `auto/state.json` — the model still decides; the
server just trims raw logs. No LLM runs inside the server.

Tools run with no per-call authorization gate — point the server at a lab you own
or have written RoE for. `ad_auto` / `mssql_hop` still pass `--i-am-authorized`
to the underlying scripts automatically.

## Agent loop (MCP first, tools second, attacks last)

This is the same loop as `SKILL.md` — mirror it exactly. Preinstall the rack
and verify binaries **before** recon / roast / BloodHound / `ad_auto`.

1. Restate lab / RoE.
2. Transport: leave `ADTK_TRANSPORT` unset (auto) or force `=docker` / `=ssh`.
3. `kali_status`.
4. Docker + down → `kali_up` (`vpn` on tun0 / HTB, else `lan`).
   SSH: key login already works; copy pack scripts to `/opt/adtk` if missing (above).
   VPN labs: `kali_preflight` (clamp tun0 mtu 1200 + clock) — re-run after any reconnect.
5. `kali_bootstrap` **once per box**. It detaches — poll `kali_logs`, do not wait on the tool call.
6. **Verify binaries** — one `kali_exec`, same on Docker and SSH:

```
for b in nxc netexec nmap hashcat certipy bloodyAD; do \
  command -v $b >/dev/null && echo "ok  $b" || echo "MISSING $b"; done
for pair in "secretsdump.py impacket-secretsdump" "getST.py impacket-getST" "GetUserSPNs.py impacket-GetUserSPNs"; do
  set -- $pair
  ( command -v $1 >/dev/null || command -v $2 >/dev/null ) && echo "ok  $1" || echo "MISSING $1"
done
test -f /opt/adtk/ad-auto.py && echo "ok  ad-auto.py" || echo "MISSING ad-auto.py"
```

7. Only now: `ad_plan` / `ad_auto` / `kali_exec` for the current step.
8. `logs_read` `auto/state.json` and `auto/report.txt`.
9. After a BloodHound collect: `bh_next`, then **one** `kali_exec` for the printed edge.

Any `MISSING` line → fix `scripts/bootstrap.sh` **and** `docker/Dockerfile`, then
re-`kali_bootstrap`. Never `apt`/`pip` ad-hoc inside the kill chain.

Do not open a Relayer / Responder / mitm6 via MCP — those hang. Point the
operator at an interactive `docker exec -it` / SSH tty.

**Host MCP timeouts (~30s) kill foreground calls.** `ad_auto` and `kali_bootstrap`
always detach. `kali_exec` auto-detaches nmap / bloodhound / secretsdump /
hashcat / john / apt / bootstrap. Poll with `kali_logs`; never sit on the
tool call. `background: false` is the only way to force a short foreground job.

SSH Kali VM without passwordless sudo: privileged commands (`ip link … mtu`,
`openvpn`) need `echo <pass> | sudo -S -p '' …`. `kali_preflight` /
`preflight.sh` read `ADTK_SUDO_PASS` (falls back to `KALI_SUDO_PASS`, then `kali`).

## Fail → next

| Symptom | Next |
| --- | --- |
| `docker: command not found` / not on PATH | MCP host must see Docker Desktop / colima; or switch `ADTK_TRANSPORT=ssh` |
| `kali_status` down / inspect empty | `kali_up` (right `mode`), or wrong `ADTK_CONTAINER` |
| SSH `Permission denied (publickey)` | fix key + `ADTK_SSH_KEY`; `ssh … hostname` must pass with `BatchMode=yes` first |
| `bootstrap.sh: No such file` | pack not at `/opt/adtk` — Docker: compose mounts `scripts/:/opt/adtk`; SSH: copy scripts there, then `kali_bootstrap` |
| `ad-auto.py` missing | same mount / copy issue — re-`kali_bootstrap` / re-compose |
| binary `MISSING` after bootstrap | Debian names are `impacket-secretsdump` / `impacket-getST` — the check accepts both. If truly missing: add pkg to `scripts/bootstrap.sh` + `docker/Dockerfile`; re-bootstrap. Do not apt/pip in the chain |
| `PermissionError: '/logs'` | SSH box, no `/logs` bind. Set `ADTK_LOGS=/home/kali/logs` on the MCP server (it is exported into remote commands). `ad-auto.py` now falls back to `~/logs` on its own. |
| tool call dies at ~30s | host harness cap — do not raise timeout, detach. `ad_auto` / bootstrap already detach; `kali_exec` auto-detaches long cmds. Poll `kali_logs`. |
| SSH `Permission denied (publickey)` | the agent must use `ADTK_SSH_KEY` from the MCP config, not a default `~/.ssh/id_*` |
| `sudo: a password is required` | stock Kali has no NOPASSWD. Set `ADTK_SUDO_PASS` on the MCP server (exported into remote commands). `echo "$ADTK_SUDO_PASS" \| sudo -S -p '' …` |
| tool hangs | poison / relay / responder is not an MCP job — interactive tty |
