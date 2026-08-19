---
name: ad-takeover
description: >
  Full authorized Active Directory takeover skill for ANY lab or CTF —
  GOAD, HackTheBox, TryHackMe, CRTO, OSCP-style, and upcoming AD challenges.
  Ships Kali Docker, the 01–16 kill chain, the public tool rack,
  scripts/ad-auto.py, and an MCP server (Docker or SSH) to drive Kali. Use whenever the user mentions
  AD, Active Directory, domain takeover, DCSync, Kerberoast, AS-REP, BloodHound,
  ADCS, ESC1, RBCD, golden ticket, NetExec, Impacket, Certipy, bloodyAD,
  GOAD, GotAd, sevenkingdoms, Kali Docker, MCP Kali, SSH Kali, or a numbered 1-n AD kill chain.
  Always load this skill for AD lab work — do not improvise a thinner guide.
compatibility: docker, kali-rolling, python3, authorized lab or CTF network only
metadata:
  short-description: "Authorized AD takeover: Kali Docker + 01–16 automator"
---

# AD takeover (authorized labs only)

Operate **only** against an environment the operator owns or is explicitly
authorized to attack (homelab, GOAD, HTB/THM, employer pentest with a signed
RoE). Refuse production tenants, customer forests, and “my company’s DC”.

This skill is the product. There is no website. Docker, automator, and
command references live in this folder.

| Path | What |
| --- | --- |
| `docker/docker-compose.yml` | Kali on the lab LAN (macvlan) |
| `docker/docker-compose.vpn.yml` | HTB-style host/VPN network |
| `docker/Dockerfile` | Optional pre-tooled image |
| `scripts/bh-next.py` | BloodHound zip → next edges |
| `scripts/mssql-hop.py` | Impersonate / linked servers |
| `scripts/bootstrap.sh` | Tool install inside Kali |
| `mcp/server.py` | MCP stdio — Kali via Docker or SSH |
| `references/mcp.md` | Wire Claude / Cursor |
| `conf/` | hosts, krb5, lab wordlist |
| `references/steps.md` | Step 01–16 checklist |
| `references/tools.md` | Tool index — then **one** card in `references/tools/` |
| `references/kali-docker.md` | Networking notes |
| `references/automation.md` | How the runner decides |
| `references/commands.md` | Interpolated command book |
| `references/labs/goad-topology.md` | GOAD hosts / public lab creds |
| `references/labs/kill-chain.md` | GOAD worked example |
| `ad-writeups/` | HTB / THM / GOAD path notes + technique map |
| `evals/evals.json` | Skill regression cases |

## Hard rules

1. Lab / RoE only. First reply restates that.
2. Public tools only. No malware, no 0-days, no ransomware, no mass resets.
3. **MCP first, tools second, attacks last.** Go through the MCP loop below and
   preinstall the rack (`kali_bootstrap`) + verify binaries **before** any
   recon, roast, BloodHound, or `ad_auto`. Never apt/pip ad-hoc in the kill chain.
4. After any domain cred, collect BloodHound before guessing the next ACE. Open `tools/bloodhound.md`.
5. “DA on one domain” is not a takeover if trusts remain.
6. GOAD ansible passwords are public lab defaults — never treat as real-world.
7. Tool questions: open **one** card under `references/tools/`. Do not paste the whole rack.

## MCP-first loop (before any recon)

Any agent using this skill MUST drive Kali through MCP and preinstall the tool
rack before recon/roast/BloodHound/`ad_auto`. Full detail + fail→next:
`references/mcp.md`.

```
1. Restate lab / RoE.
2. Choose transport: GOTAD_TRANSPORT=docker  or  GOTAD_TRANSPORT=ssh
3. kali_status
4. Docker + down → kali_up  (mode vpn if tun0 / HTB, else lan)
     SSH: key login already works; copy pack scripts to /opt/gotad if missing
5. kali_bootstrap  (once per box; wait for it; i_am_authorized: true)
6. Verify binaries (same check, Docker or SSH):
     nxc|netexec · nmap · hashcat
     GetUserSPNs.py|impacket-GetUserSPNs · secretsdump · getST · certipy · bloodyAD
     /opt/gotad/ad-auto.py
7. Only now: ad_plan / ad_auto / kali_exec for the current step
8. loot_read auto/state.json and auto/report.txt
9. After a BloodHound collect: bh_next, then ONE kali_exec for the printed edge
```

Transport env: `GOTAD_TRANSPORT` · `GOTAD_CONTAINER` · `GOTAD_COMPOSE` ·
`GOTAD_SSH` · `GOTAD_SSH_PORT` · `GOTAD_SSH_KEY`.

`kali_bootstrap` = `/opt/gotad/bootstrap.sh`. Rack: nxc/netexec, Impacket
(GetUserSPNs, secretsdump, getST, smbclient.py, atexec, wmiexec), Certipy,
bloodyAD, BloodHound collector (bloodhound.py / rusthound-ce), nmap, hashcat,
ldap-utils, smbclient, krb5-user. Missing after bootstrap → add it to
`scripts/bootstrap.sh` **and** `docker/Dockerfile`, not ad-hoc.

Do **not** start Relayer / Responder / mitm6 via MCP — they hang. Interactive
`docker exec -it` / SSH tty only. Mutating MCP tools require `i_am_authorized: true`.

## Quick start

```bash
cd docker
cp .env.example .env          # set IP_RANGE + LAB_PARENT
../scripts/up.sh
docker exec -it gotad-kali bash
/opt/gotad/bootstrap.sh       # once, if you used the vanilla image
python3 /opt/gotad/ad-auto.py --i-am-authorized --dc 192.168.56.11 --profile goad
# or: --plan / --resume / --from acl / --abuse (lab only)

# drive Kali from Claude / Cursor (MCP)
# GOTAD_TRANSPORT=docker python3 mcp/server.py
# GOTAD_TRANSPORT=ssh GOTAD_SSH=root@192.168.56.200 python3 mcp/server.py
```

HTB / tun0: use `docker-compose.vpn.yml` and `--iface tun0`. Skip poison.

Walk **steps 1–16 in order** unless they already have a foothold.
Fill `{{DC}} {{DOMAIN}} {{USER}} {{PASS}}` from the current target.
Do not dump this whole file — open the matching reference.

| Step | Id | Goal | Ref |
| --- | --- | --- | --- |
| 01 | `box` | Kali on the LAN, DNS, clock | `references/kali-docker.md` |
| 02 | `recon` | Ports / roles | `references/steps.md` §02 · `tools/netexec.md` |
| 03 | `unauth` | Null, guest, RID, zone | `references/steps.md` §03 · `tools/enum.md` |
| 04 | `poison` | LLMNR / relay / IPv6 / coerce | `references/steps.md` §04 · `tools/relay.md` |
| 05 | `asrep` | DONT_REQ_PREAUTH | `references/steps.md` §05 · `tools/crack.md` |
| 06 | `spray` | Policy, spray, descriptions | `references/steps.md` §06 · `tools/netexec.md` |
| 07 | `kerberoast` | User SPNs | `references/steps.md` §07 · `tools/impacket.md` |
| 08 | `bloodhound` | Collect + **bh-next** | `tools/bloodhound.md` |
| 09 | `lateral` | PTH, tickets, WinRM, LSASS | `tools/shells.md` |
| 10 | `acl` | GenericAll / WriteDACL / … | `tools/bloodyad.md` |
| 10b | `maq` `shadow` `rbcd` | MAQ + PKINIT + getST | `tools/tickets.md` · `tools/shadow.md` |
| 11 | `delegation` | UC / CC / RBCD | `tools/impacket.md` |
| 12 | `adcs` | ESC1–ESC15 | `tools/certipy.md` |
| 13 | `sysvol` `laps` | GPP, GPO, LAPS, gMSA | `tools/gpo.md` |
| 14 | `mssql` | Impersonate, links, xp_cmdshell | `tools/mssql.md` |
| 15 | `trusts` `trusthop` | Child → parent, forests | `tools/trusts.md` |
| 16 | `dcsync` | NTDS, KRBTGT, golden, EA | `references/steps.md` §16 |

## Output shape (every manual step)

```
## Step NN — name
Objective: …
Success: …

### Commands
# already interpolated for THEIR dc/domain/user

### If it fails
- cause → next probe
```

## Stop condition

1. DCSync `KRBTGT` in every domain in scope
2. Act as DA / EA in the forest root (ticket or hash)
3. One-line path: foothold → DA → forest

## Upcoming challenges

Do not wait for a GOAD-shaped lab. Ask for: domain, DC IP/FQDN, CIDR, VPN iface
(`tun0` vs `eth0`), and any cred they already have. Then either run
`scripts/ad-auto.py` or walk `references/steps.md` from the first unfinished step.
