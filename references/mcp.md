# Kali MCP (Docker or SSH)

Stdio MCP server. **No extra pip deps.** Talks to `gotad-kali` via `docker exec`
or to any Kali over SSH. Lab / RoE only.

```
python3 mcp/server.py --self-test
GOTAD_TRANSPORT=docker python3 mcp/server.py
GOTAD_TRANSPORT=ssh GOTAD_SSH=root@192.168.56.200 python3 mcp/server.py
```

## Wire it

Replace `/ABSOLUTE/PATH` in `mcp/claude_desktop.example.json` or
`mcp/cursor.example.json`.

Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json`.

Cursor: `.cursor/mcp.json` in the project, or Settings → MCP.

One server at a time. Docker **or** SSH — set `GOTAD_TRANSPORT`.

## Env

| Var | Default | Meaning |
| --- | --- | --- |
| `GOTAD_TRANSPORT` | `docker` | `docker` or `ssh` |
| `GOTAD_CONTAINER` | `gotad-kali` | compose service name |
| `GOTAD_COMPOSE` | `<pack>/docker` | compose directory (`kali_up`) |
| `GOTAD_SSH` | `root@127.0.0.1` | `user@host` |
| `GOTAD_SSH_PORT` | `22` | |
| `GOTAD_SSH_KEY` | empty | identity file |

SSH uses `BatchMode` + `IdentitiesOnly`. Get a key login working first:

```
ssh -i ~/.ssh/id_ed25519 root@192.168.56.200 hostname
```

If SSH cannot write `/opt/gotad`, copy the pack scripts there once, then bootstrap:

```
scp -r scripts conf root@HOST:/opt/gotad/         # or rsync
ssh root@HOST 'ls /opt/gotad/bootstrap.sh /opt/gotad/ad-auto.py'
```

## Tools

| Tool | Auth | Does |
| --- | --- | --- |
| `kali_status` | no | container / ssh alive? |
| `kali_up` | yes | `compose up -d` (`lan` or `vpn`) |
| `kali_bootstrap` | yes | `/opt/gotad/bootstrap.sh` |
| `kali_exec` | yes | arbitrary bash on Kali |
| `ad_auto` | yes | decision engine |
| `ad_plan` | no | next action only |
| `bh_next` | no | BloodHound zip → edges |
| `mssql_hop` | yes | impersonate / links |
| `loot_ls` / `loot_read` | no | `/loot` only |
| `loot_write` | yes | `/loot` only |

Mutating tools refuse unless `i_am_authorized: true`.

## Agent loop (MCP first, tools second, attacks last)

This is the same loop as `SKILL.md` — mirror it exactly. Preinstall the rack
and verify binaries **before** recon / roast / BloodHound / `ad_auto`.

1. Restate lab / RoE.
2. Choose transport: `GOTAD_TRANSPORT=docker` or `=ssh`.
3. `kali_status`.
4. Docker + down → `kali_up` (`vpn` on tun0 / HTB, else `lan`).
   SSH: key login already works; copy pack scripts to `/opt/gotad` if missing (above).
5. `kali_bootstrap` **once per box**. Wait for it. `i_am_authorized: true`.
6. **Verify binaries** — one `kali_exec`, same on Docker and SSH:

```
for b in nxc netexec nmap hashcat secretsdump.py getST.py certipy bloodyAD; do \
  command -v $b >/dev/null && echo "ok  $b" || echo "MISSING $b"; done; \
( command -v GetUserSPNs.py >/dev/null || command -v impacket-GetUserSPNs >/dev/null ) \
  && echo "ok  GetUserSPNs" || echo "MISSING GetUserSPNs"; \
test -f /opt/gotad/ad-auto.py && echo "ok  ad-auto.py" || echo "MISSING ad-auto.py"
```

7. Only now: `ad_plan` / `ad_auto` / `kali_exec` for the current step.
8. `loot_read` `auto/state.json` and `auto/report.txt`.
9. After a BloodHound collect: `bh_next`, then **one** `kali_exec` for the printed edge.

Any `MISSING` line → fix `scripts/bootstrap.sh` **and** `docker/Dockerfile`, then
re-`kali_bootstrap`. Never `apt`/`pip` ad-hoc inside the kill chain.

Do not open a Relayer / Responder / mitm6 via MCP — those hang. Point the
operator at an interactive `docker exec -it` / SSH tty.

## Fail → next

| Symptom | Next |
| --- | --- |
| `docker: command not found` / not on PATH | MCP host must see Docker Desktop / colima; or switch `GOTAD_TRANSPORT=ssh` |
| `kali_status` down / inspect empty | `kali_up` (right `mode`), or wrong `GOTAD_CONTAINER` |
| SSH `Permission denied (publickey)` | fix key + `GOTAD_SSH_KEY`; `ssh … hostname` must pass with `BatchMode=yes` first |
| `bootstrap.sh: No such file` | pack not at `/opt/gotad` — Docker: compose mounts `scripts/:/opt/gotad`; SSH: copy scripts there, then `kali_bootstrap` |
| `ad-auto.py` missing | same mount / copy issue — re-`kali_bootstrap` / re-compose |
| binary `MISSING` after bootstrap | add pkg to `scripts/bootstrap.sh` + `docker/Dockerfile`; re-bootstrap. Do not apt/pip in the chain |
| tool hangs | timeout 120s. poison / relay / responder is not an MCP job — interactive tty |
