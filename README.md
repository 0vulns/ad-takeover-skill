# AD takeover skill

An agent skill + Kali toolbox for taking over an Active Directory domain on
**authorized labs and CTFs** — GOAD, HackTheBox, TryHackMe, OSCP-style rooms,
and your own homelab. It ships a disposable Kali (Docker or SSH), a 01–16 kill
chain, senior tool cards, a decision-engine runner, and an MCP server so an AI
agent (Cursor / Claude / any MCP host) can drive the box safely.

It is **not** a website or a framework — it's a self-contained skill folder.

> ### Authorized use only
> Operate **only** against environments you own or are explicitly authorized to
> attack (homelab, GOAD, HTB/THM, or an engagement with a signed Rules of
> Engagement). Public tools only — no malware, 0-days, ransomware, or mass
> resets. Redact flags, cracked passwords, and hashes from any notes. Using
> this against systems you don't have permission to test is illegal. See
> [LICENSE](LICENSE).

## Why

Most AD lab time is lost to plumbing, not tradecraft: VPN MTU black-holes,
chatty enumeration that times out, GPU-less cracking, and remembering the exact
flag for the empty-password guest → RBCD → DCSync path. This skill encodes those
lessons so the run is the attack path, not an environment fight.

## Features

- **Disposable Kali** via Docker (LAN macvlan for GOAD, or host/`tun0` for VPN
  labs) or over SSH to any Kali box.
- **One-shot bootstrap** that installs and self-verifies the public rack: nxc /
  NetExec, Impacket, Certipy, bloodyAD, BloodHound collectors, hashcat/john,
  nmap, krb5, ldap-utils.
- **`ad-auto.py`** — a decision engine that parses loot, skips dead ends, and
  prints the next action (`--plan` / `--resume` / `--from`).
- **MCP server** — drive Kali from an AI agent with a compact, parsed tool set
  (status, exec, decision engine, per-target logs).
- **Senior tool cards** (`references/tools/`) — one card per tool, each with a
  `Fail → next` table and interpolated commands.
- **Write-up library** (`ad-writeups/`) — structured path notes for classic AD
  boxes + a technique → challenge map, so you can fingerprint a target fast.

## Requirements

- Docker (Desktop / colima / engine) **or** SSH access to a Kali box.
- `python3` on the host (for the runner and MCP server; no extra pip deps).
- A lab you are authorized to attack.

## Quick start (Docker)

```bash
cd docker && cp .env.example .env      # set IP_RANGE + LAB_PARENT for LAN labs
../scripts/up.sh                       # or: ../scripts/up.sh vpn   (HTB/THM tun0)
docker exec -it adtk-kali bash

/opt/adtk/bootstrap.sh                # installs the rack, then self-verifies
/opt/adtk/preflight.sh <DC_IP> tun0 1200   # VPN labs: clamp MTU + sync clock

python3 /opt/adtk/ad-auto.py --i-am-authorized --dc 192.168.56.11 --profile goad
python3 /opt/adtk/ad-auto.py --plan --dc 10.10.11.47 --iface tun0
```

## Quick start (SSH to your own Kali)

```bash
# get a key login working first:
ssh -i ~/.ssh/id_ed25519 kali@KALI_IP hostname
# copy the pack if /opt/adtk is empty, then bootstrap over SSH via MCP or:
scp -r scripts conf kali@KALI_IP:/opt/adtk/ && ssh kali@KALI_IP /opt/adtk/bootstrap.sh
```

## Drive it from an AI agent (MCP)

The MCP server talks to Kali over Docker or SSH — no extra pip deps.

```bash
python3 mcp/server.py --self-test
ADTK_TRANSPORT=docker python3 mcp/server.py
ADTK_TRANSPORT=ssh ADTK_SSH=kali@192.168.56.200 python3 mcp/server.py
```

Wire it into your host by editing the absolute path in the example configs:

- Cursor: `mcp/cursor.example.json` → `.cursor/mcp.json`
- Claude Desktop: `mcp/claude_desktop.example.json` → `claude_desktop_config.json`

| Env | Default | Meaning |
| --- | --- | --- |
| `ADTK_TRANSPORT` | auto | `docker` or `ssh`; unset = auto (Docker if the container is up, else SSH) |
| `ADTK_CONTAINER` | `adtk-kali` | compose service name |
| `ADTK_COMPOSE` | `docker/` | compose dir (for `kali_up`) |
| `ADTK_SSH` | `root@127.0.0.1` | `user@host` |
| `ADTK_SSH_PORT` | `22` | SSH port |
| `ADTK_SSH_KEY` | empty | identity file |
| `ADTK_LOGS` | `/logs` | base log dir; each target gets `logs/<dc-ip>/` under it (set for an SSH VM with no `/logs` bind) |

You usually don't set `ADTK_TRANSPORT` — leave it unset and the server picks
Docker when the container is running, otherwise SSH if `ADTK_SSH` is set. The
DC IP you pass to `ad_plan` / `ad_auto` / `kali_preflight` also selects the
per-target log tree, so `logs_read`, `bh_next`, and background jobs all land in
`logs/<dc-ip>/`.

### MCP-first loop (safety model)

Agents preinstall the rack and verify tools **before** any recon — never
`apt`/`pip` inside the kill chain. Full loop + `Fail → next`: `references/mcp.md`
(mirrors `SKILL.md`).

```
1. Restate lab / RoE.
2. Transport: ADTK_TRANSPORT=docker or =ssh
3. kali_status
4. Docker + down → kali_up (vpn on tun0/HTB, else lan)
   VPN → kali_preflight (clamp tun0 mtu 1200 + clock)
5. kali_bootstrap (once per box)
6. Verify: nxc|netexec, nmap, hashcat, GetUserSPNs, secretsdump,
   getST, certipy, bloodyAD, /opt/adtk/ad-auto.py
7. Only then: ad_plan / ad_auto / kali_exec
8. logs_read auto/state.json + auto/report.txt
9. After a BloodHound collect: bh_next → ONE kali_exec for the printed edge
```

Relayer / Responder / mitm6 hang under MCP — run those in an interactive tty.

## How it works

`ad-auto.py` is not a linear script; it asks "what is the most useful next
action given what we've collected?" and stops when another cycle wouldn't help.
Each target keeps its own tree at `logs/<dc-ip>/` (state `auto/state.json` +
`report.txt`, plus `hashes/`, `bloodhound/`, `nmap/`, …), so runs against
different DCs never mix. The 01–16 kill chain (`references/steps.md`) is the
manual checklist behind it:

```
box → recon → unauth → poison → asrep → spray → kerberoast → bloodhound →
lateral → acl → delegation → adcs → sysvol/laps → mssql → trusts → dcsync
```

Stop condition: DCSync `KRBTGT` in every in-scope domain and act as DA/EA in the
forest root.

## Layout

```
SKILL.md            agent playbook (thin): RoE, MCP-first loop, 01–16, stop condition
README.md           this file
HISTORY.md          changelog
CONTRIBUTING.md     conventions + safety rules
LICENSE             MIT + authorized-use notice
docker/             compose (LAN + VPN), Dockerfile, .env.example
scripts/            up.sh, bootstrap.sh, preflight.sh, ad-auto.py, bh-next.py, mssql-hop.py
conf/               *.example templates (hosts, krb5, lab wordlist) — copy + edit per lab
mcp/                stdio MCP server + example configs (Cursor / Claude)
evals/              skill regression cases (evals.json)
references/
  steps.md          01–16 checklist
  automation.md     runner decision loop
  commands.md       interpolated command book
  kali-docker.md    networking / VPN / MTU notes
  mcp.md            MCP + bootstrap loop (mirrors SKILL.md)
  tools.md          index → open ONE card
  tools/            senior tool cards (nxc, Impacket, Certipy, bloodyAD, LPE, …)
  labs/             goad-topology.md, kill-chain.md
ad-writeups/        HTB / THM / GOAD path notes + technique map
logs/               per-target run artifacts logs/<dc-ip>/ (bind-mount, git-ignored)
```

## Where to start reading

`SKILL.md` first, then `references/mcp.md`, `references/automation.md`, and
`references/steps.md`. Practice targets and path notes are in `ad-writeups/`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep `ad-auto.py --self-test` and
`mcp/server.py --self-test` green, and never commit secrets.

## License

[MIT](LICENSE), with an authorized-use notice. Educational tooling for
authorized security testing only.
