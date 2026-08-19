# AD takeover skill

Authorized-lab Active Directory takeover: **Kali Docker + 01–16 automator +
the public tool rack**. Not a website.

Lab / RoE only. Public tools. No malware, no 0-days.

```
ad-takeover/
  SKILL.md                 agent playbook (thin): RoE, MCP-first loop, 01–16, stop
  HISTORY.md               product changelog
  README.md                how to run (Docker, SSH, MCP)
  docker/
    docker-compose.yml     Kali on the lab LAN (macvlan)
    docker-compose.vpn.yml host network (HTB / tun0)
    Dockerfile             pre-tooled image (installs the rack)
    .env.example
  scripts/
    up.sh                  bring the box up
    bootstrap.sh           install + verify nxc / impacket / certipy / bloodyAD / …
    ad-auto.py             decision engine (parse, skip, resume)
    bh-next.py             BloodHound zip → next edge
    mssql-hop.py           impersonate / linked servers
  conf/                    hosts, krb5, lab wordlist
  mcp/                     stdio MCP server + example configs (Docker or SSH into Kali)
  evals/                   skill regression cases (evals.json)
  references/
    steps.md               01–16 checklist
    automation.md          runner decision loop
    commands.md            interpolated command book
    kali-docker.md         networking notes
    mcp.md                 MCP + bootstrap loop (mirrors SKILL.md)
    tools.md               index → open ONE card
    tools/                 senior tool cards
    labs/                  goad-topology.md, kill-chain.md
  ad-writeups/             HTB / THM / GOAD path notes + technique map (KEEP name)
  loot/                    bind-mount target (created on up; git-ignored)
```

## MCP first, tools second, attacks last

Agents drive Kali through MCP and preinstall the rack **before** any recon.
Full loop + fail→next: `references/mcp.md` (mirrors `SKILL.md`).

```
1. Restate lab / RoE.
2. Transport: GOTAD_TRANSPORT=docker  or  =ssh
3. kali_status
4. Docker + down → kali_up (vpn on tun0/HTB, else lan)   SSH: copy scripts to /opt/gotad if missing
5. kali_bootstrap  (once per box; i_am_authorized: true)
6. Verify binaries: nxc|netexec, nmap, hashcat, GetUserSPNs, secretsdump,
   getST, certipy, bloodyAD, /opt/gotad/ad-auto.py
7. Only then: ad_plan / ad_auto / kali_exec
8. loot_read auto/state.json + auto/report.txt
9. After BloodHound collect: bh_next → ONE kali_exec for the printed edge
```

A missing binary after bootstrap is a bug in `scripts/bootstrap.sh` +
`docker/Dockerfile`, not a reason to `apt`/`pip` inside the chain.

## Run

```bash
cd docker && cp .env.example .env && ../scripts/up.sh
docker exec -it gotad-kali bash
/opt/gotad/bootstrap.sh                 # installs the rack, then self-verifies
python3 /opt/gotad/ad-auto.py --i-am-authorized --dc 192.168.56.11 --profile goad
python3 /opt/gotad/ad-auto.py --plan --dc 10.10.11.47 --iface tun0
python3 /opt/gotad/ad-auto.py --self-test
python3 ../mcp/server.py --self-test   # from pack root: python3 mcp/server.py --self-test

# drive Kali from Claude / Cursor (MCP)
GOTAD_TRANSPORT=docker python3 mcp/server.py
GOTAD_TRANSPORT=ssh GOTAD_SSH=root@192.168.56.200 python3 mcp/server.py
```

VPN labs: `../scripts/up.sh vpn` then `--iface tun0`.

`--plan` prints the next action. `--resume` / `--from acl` continues.
State: `/loot/auto/state.json` + `report.txt`. See `references/automation.md`.

Read `SKILL.md` first. Then `references/mcp.md`, `references/automation.md`, and
`references/steps.md`. Practice targets and path notes: `ad-writeups/`. Skill
regression cases: `evals/evals.json`.
