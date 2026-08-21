# adtk

A Kali toolbox for taking over an Active Directory domain in a lab you own or a
CTF you are allowed to attack: GOAD, HackTheBox, TryHackMe, CRTO, OSCP-style
rooms, or a homelab.

Clone the repo, bring up Kali (in Docker on the lab LAN or `tun0`, or over SSH
to a Kali VM you already run), and bootstrap the public tool rack. From there,
let `scripts/ad-auto.py` pick the next move or walk the 01–16 chain yourself. An
optional MCP server lets Cursor or Claude run commands on that same box.

```bash
git clone https://github.com/0vulns/ad-takeover-skill.git
cd ad-takeover-skill
```

> ### Authorized use only
>
> Operate only against environments you own or are explicitly authorized to
> attack (homelab, GOAD, HTB/THM, or an engagement with a signed Rules of
> Engagement). Public tools only: no malware, 0-days, ransomware, or mass
> resets. Redact flags, cracked passwords, and hashes from notes. Attacking
> systems you do not have permission to test is illegal. See [LICENSE](LICENSE).

## Features

- **Disposable Kali.** Docker macvlan on the lab LAN (GOAD / homelab), host/`tun0`
  for VPN labs (HTB / THM), or SSH to any Kali you already have.
- **Self-verifying rack.** `bootstrap.sh` installs nxc/NetExec, Impacket,
  Certipy, bloodyAD, BloodHound collectors, hashcat/john, nmap, krb5, ldap-utils,
  then checks the binaries. Missing a tool? Add it to `bootstrap.sh` and the
  Dockerfile, then re-bootstrap.
- **01–16 kill chain.** box → recon → unauth → poison → asrep → spray →
  kerberoast → bloodhound → lateral → acl → delegation → adcs → sysvol/laps →
  mssql → trusts → dcsync. Skip rules and a Fail → next table on every tool card.
- **Decision engine.** `ad-auto.py` reads your loot, skips dead ends, and prints
  or runs the next action (`--plan` / `--resume` / `--from` / `--only` / `--abuse`).
- **MCP (optional).** Cursor / Claude / any MCP host talks to Kali over Docker
  or SSH. Bootstrap and verify before recon. Long jobs detach; `logs_read` +
  `kali_logs` poll the per-target tree.
- **Tool cards.** One card per tool under `references/tools/` (nxc, Impacket,
  Certipy, bloodyAD, BloodHound, tickets, LPE, MSSQL, …), each with interpolated
  `{{DC}} {{DOMAIN}} {{USER}} {{PASS}}` and a Fail → next table.
- **VPN preflight.** `preflight.sh` clamps `tun0` MTU to 1200 and ntpdates the
  DC so Kerberos TGS-REQs do not black-hole.
- **Go-fast helpers.** Parallel stock-cred check (`spray-stock.sh`), bounded
  fan-out (`fan.sh`), host GPU crack (`host-crack.sh`), one-shot DC flag sweep
  (`revshell.sh flags`).
- **Write-up library.** HTB / THM / GOAD path notes plus a technique →
  challenge map, so you can fingerprint a known box from its domain name.
- **Per-target logs.** `logs/<dc-ip>/` (`auto/`, `hashes/`, `bloodhound/`,
  `nmap/`). Two DCs never overwrite each other.

## Proven on

Two authorized live runs (whose failures became repo fixes), ten regression
cases, and a coverage matrix against classic AD labs back this up. Flags,
cracked passwords, and hashes are redacted in the trails.

| Lab | Outcome | Wall clock | Trail |
| --- | --- | --- | --- |
| [THM Operation Endgame](ad-writeups/thm/operation-endgame.md) (`thm.local`) | DA + full NTDS + flag. Path: guest/empty-pw → Kerberoast → GenericWrite on `AD$` → existing-SPN RBCD → `getST ldap/` → DCSync → atexec (no WinRM) | 47m 54s | [`.refinements/1.md`](.refinements/1.md) |
| [GOAD-on-Ludus](ad-writeups/goad/goad-ludus.md) (3 domains / 2 forests, WS2022, SSH Kali over OpenVPN) | DA/EA in the forest root, DA in all three domains, `krbtgt` DCSync ×3, NTDS ×3, `ad-auto` rerun `takeover True`. Stock ansible creds 21/23 valid in ~1 min before recon | ~2h 35m over three sessions, including ~35 min Kali VM crash recovery | [`.refinements/2.md`](.refinements/2.md) |

Refinement #1 lost most of its 48 minutes to the environment (tun0 MTU
black-hole, RID-brute timeout at ~250 ms RTT, hashcat with no GPU). The repo now
preempts all three: `preflight.sh`, bulk LDAP, john-by-default in GPU-less VMs,
and `host-crack.sh`. Refinement #2 is why SSH Kali ships Impacket `impacket-*`
aliases, an `ADTK_LOGS` fallback, `ADTK_SUDO_PASS`, and detached
`ad_auto` / `kali_bootstrap`.

### Regression cases

[`evals/evals.json`](evals/evals.json) holds ten cases an operator or agent
should never skip:

| Id | What it checks |
| --- | --- |
| `mcp-first` | `kali_status` → bootstrap → verify binaries **before** recon; no ad-hoc apt/pip |
| `blank-htb` | tun0 / skip poison / guest empty password / unauth → asrep → spray |
| `endgame-guest-rbcd` | guest → roast `-no-pass` → existing-SPN RBCD → `getST ldap/` → atexec (no WinRM) |
| `forest-htb` | AS-REP → Account Operators → WriteDACL → DCSync |
| `active-htb` | SYSVOL GPP cpassword **before** Kerberoast |
| `blackfield-htb` | ForceChangePassword → SeBackupPrivilege → offline NTDS |
| `mid-foothold` | `bh-next` one edge; raiseChild only after child DA; no extra-SID on a forest trust |
| `goad-still-works` | `--profile goad` through MSSQL (`CASTELBLACK`) into `essos.local` |
| `bh-next-shadow` | GenericWrite → Certipy shadow, not a password reset |
| `trust-filter` | forest trust keeps SID filtering; hop via MSSQL / cert / foreign group |

```bash
python3 scripts/ad-auto.py --self-test
python3 mcp/server.py --self-test
```

### Lab coverage

[ad-writeups/coverage-matrix.md](ad-writeups/coverage-matrix.md) scores the 01–16
chain against HTB classic AD, GOAD, and THM. Boxes with a clear path: Forest,
Sauna, GOAD, Attacktive Directory, Certified / Certificate / Mirage (ADCS), and
Escape* (MSSQL). Order traps to watch: GPP before roast on Active, guest roast
before spray on Endgame. Known gaps: Azure AD Connect DB cred hunt (Monteverde),
printer LDAP-config capture (Return), and dMSA / Bad Successor on Server 2025
(Eighteen).

## Layout

```
README.md           this file
LICENSE             MIT + authorized-use notice
HISTORY.md          changelog
CONTRIBUTING.md     conventions + safety rules
SKILL.md            optional agent playbook (RoE, MCP loop, 01–16)
docker/             compose (LAN + VPN), Dockerfile, .env.example
scripts/            up.sh, bootstrap.sh, preflight.sh, ad-auto.py, bh-next.py,
                    mssql-hop.py, fan.sh, spray-stock.sh, host-crack.sh, revshell.sh
conf/               *.example templates — copy + edit per lab
mcp/                stdio MCP server + Cursor / Claude example configs
evals/              regression cases (evals.json)
references/
  steps.md          01–16 checklist
  automation.md     runner decision loop
  commands.md       interpolated command book
  kali-docker.md    networking / VPN / MTU
  mcp.md            MCP + bootstrap loop
  tools.md          index → open ONE card
  tools/            tool cards
  labs/             goad-topology.md, kill-chain.md
ad-writeups/        HTB / THM / GOAD path notes + technique map
logs/               per-target artifacts logs/<dc-ip>/ (bind-mount, git-ignored)
```

You are done when you DCSync `KRBTGT` in every in-scope domain and can act as
DA/EA in the forest root. Write down the one-line path: foothold → DA → forest.

## Requirements

- Docker (Desktop / Colima / engine) **or** SSH access to a Kali box
- `python3` on the host (runner and MCP server; stdlib only, no pip installs)
- A lab you are authorized to attack

## Quick start

### Docker on a lab LAN (GOAD / homelab)

Kali lands on the same L2 as the DCs via macvlan. Set `IP_RANGE` and
`LAB_PARENT` (`vboxnet0`, `vmnet1`, or your KVM bridge):

```bash
cd docker && cp .env.example .env
../scripts/up.sh
docker exec -it adtk-kali bash

/opt/adtk/bootstrap.sh
python3 /opt/adtk/ad-auto.py --i-am-authorized --dc 192.168.56.11 --profile goad
```

Optional fat image (rack baked in, so runtime bootstrap only verifies):

```bash
docker build -t adtk-kali -f docker/Dockerfile .
```

Do not set `ADTK_FULL_METAPACKAGE=1` on an SSH Kali. `kali-linux-headless`
restarts networking mid-apt and can hang the VM.

### Docker on a VPN lab (HTB / THM / `tun0`)

Share the host network and skip poison/relay (most PWN VPNs have no L2
broadcast):

```bash
../scripts/up.sh vpn
docker exec -it adtk-kali bash

/opt/adtk/bootstrap.sh
/opt/adtk/preflight.sh 10.10.11.47 tun0 1200
python3 /opt/adtk/ad-auto.py --i-am-authorized --dc 10.10.11.47 --iface tun0
```

`preflight.sh` clamps the `tun0` MTU to 1200 (otherwise full-MSS Kerberos
TGS-REQs black-hole) and ntpdates the DC. Re-run it after every VPN reconnect.

### SSH to an existing Kali

Get a key login working first, copy the scripts if `/opt/adtk` is empty, then
bootstrap:

```bash
ssh -i ~/.ssh/id_ed25519 kali@KALI_IP hostname
scp -r scripts conf kali@KALI_IP:/opt/adtk/
ssh kali@KALI_IP /opt/adtk/bootstrap.sh
```

Point MCP at that box (`ADTK_TRANSPORT=ssh`, `ADTK_SSH`, `ADTK_SSH_KEY`). Stock
Kali has no NOPASSWD, so set `ADTK_SUDO_PASS` (default `kali`) to let
`preflight.sh` pipe `sudo -S`. Use `ADTK_LOGS=/home/kali/logs` when the VM has
no `/logs` bind.

## Decision engine

Each `ad-auto.py` cycle picks the most useful next action from what sits in
`logs/<dc-ip>/`, then stops once another cycle would not help. Poison/relay stays
manual (listeners hang). `--i-am-authorized` is required to execute; `--plan` and
`--self-test` skip it.

```bash
# discover domain / CIDR from the DC banner
python3 /opt/adtk/ad-auto.py --i-am-authorized --dc 192.168.56.11 --profile goad

# HTB-style, known user
python3 /opt/adtk/ad-auto.py --i-am-authorized \
  --dc 10.10.11.47 --iface tun0 --user j.smith --password 'Welcome1'

# print the next action, do not run
python3 /opt/adtk/ad-auto.py --plan --dc 10.10.11.47 --iface tun0

# resume the newest target tree, jump, or cap the action set
python3 /opt/adtk/ad-auto.py --i-am-authorized --resume --from acl
python3 /opt/adtk/ad-auto.py --i-am-authorized --dc $DC --only asrep,spray

# lab only: act on the first ForceChangePassword / ESC1
python3 /opt/adtk/ad-auto.py --i-am-authorized --resume --abuse
```

| Flag | Meaning |
| --- | --- |
| `--dc` | DC IP; also selects `logs/<dc-ip>/`. Required unless `--resume` / `--self-test` |
| `--profile` | `auto` / `goad` / `generic`. `auto` becomes `goad` when the domain looks like sevenkingdoms/essos |
| `--iface` | Default `eth0`. VPN labs: `tun0` |
| `--from` | Force this action first |
| `--only` | Comma list of actions, then stop |
| `--resume` | Load `auto/state.json` (newest tree if `--dc` is omitted) |
| `--plan` | Print the next action |
| `--abuse` | Lab only: act on first ForceChangePassword / ESC1 |
| `--rounds` | Max decide() cycles (default 24) |

`--domain` and `--cidr` are optional; the banner parse fills them in. Each target
keeps its own tree under `ADTK_LOGS` (default `/logs`): `auto/state.json`,
`report.txt`, `hashes/`, `bloodhound/`, `nmap/`. Runs against different DCs never
mix.

`--profile goad` sprays documented stock creds before AS-REP. On-box cracking is
time-boxed (`ADTK_CRACK_BUDGET`, 90s); the runner then prints a `host-crack.sh`
offload, since the Kali VM has no GPU.

For how it decides, what it parses, and what it skips, see
[references/automation.md](references/automation.md).

## MCP (optional)

`mcp/server.py` talks to Kali over Docker or SSH, using the standard library
only. Skip this section if you are driving the box yourself with `docker exec` /
SSH.

```bash
python3 mcp/server.py --self-test
ADTK_TRANSPORT=docker python3 mcp/server.py
ADTK_TRANSPORT=ssh ADTK_SSH=kali@192.168.56.200 python3 mcp/server.py
```

Copy an example config and replace `/ABSOLUTE/PATH`:

| Host | Example → live |
| --- | --- |
| Cursor | `mcp/cursor.example.json` → `.cursor/mcp.json` |
| Claude Desktop | `mcp/claude_desktop.example.json` → `claude_desktop_config.json` |

Leave `ADTK_TRANSPORT` unset to auto-pick (Docker if the container is up, else
SSH when `ADTK_SSH` is set), or force `docker` / `ssh`. The DC IP you pass to
`ad_plan` / `ad_auto` / `kali_preflight` selects the per-target log tree, so
`logs_read`, `bh_next`, and background jobs all land in `logs/<dc-ip>/`.

| Env | Default | Meaning |
| --- | --- | --- |
| `ADTK_TRANSPORT` | auto | `docker` or `ssh`; unset = auto |
| `ADTK_CONTAINER` | `adtk-kali` | Compose service name |
| `ADTK_COMPOSE` | `docker/` | Compose dir (for `kali_up`) |
| `ADTK_SSH` | `root@127.0.0.1` | `user@host` |
| `ADTK_SSH_PORT` | `22` | SSH port |
| `ADTK_SSH_KEY` | empty | Identity file |
| `ADTK_LOGS` | `/logs` | Base log dir; each target is `logs/<dc-ip>/` under it. SSH VM with no `/logs` bind: `/home/kali/logs`. MCP exports this into every remote command |
| `ADTK_SUDO_PASS` | `kali` | SSH Kali without NOPASSWD: `preflight.sh` pipes it to `sudo -S` |

| Tool | Mutates | Does |
| --- | --- | --- |
| `kali_status` | no | Container / SSH alive? |
| `kali_up` | yes | `compose up -d` (`lan` or `vpn`) |
| `kali_bootstrap` | yes | `/opt/adtk/bootstrap.sh` (always detaches; poll `kali_logs`) |
| `kali_preflight` | yes | VPN: clamp tun0 MTU 1200 + ntpdate + verify + null/guest probe |
| `kali_exec` | yes | Bash on Kali. nmap / bloodhound / secretsdump / hashcat / apt auto-detach |
| `kali_logs` | no | Tail a background job in the target `logs/<dc>/` tree |
| `ad_auto` | yes | Decision engine (always detaches). `dc` sets the target |
| `ad_plan` | no | Next action only (+ digest). `dc` sets the target |
| `bh_next` | no | BloodHound zip → edges |
| `mssql_hop` | yes | Impersonate / linked servers |
| `logs_ls` / `logs_read` | no | Current target `logs/<dc>/` only |
| `logs_write` | yes | Current target `logs/<dc>/` only |

MCP tools carry no per-call authorization flag, so point the server only at a lab
you own or have written RoE for. `ad_auto` / `mssql_hop` still pass
`--i-am-authorized` to the underlying scripts.

Relayer / Responder / mitm6 hang under MCP. Run those in an interactive
`docker exec -it` or SSH tty instead.

For the full loop and Fail → next, see [references/mcp.md](references/mcp.md).
Agents also read [SKILL.md](SKILL.md).

### MCP-first loop (safety model)

Preinstall the rack and verify the binaries **before** any recon. Never `apt` or
`pip` inside the kill chain.

```
1. Restate lab / RoE.
2. Transport: leave ADTK_TRANSPORT unset to auto-pick (Docker if the container
   is up, else SSH when ADTK_SSH is set), or force =docker / =ssh
3. kali_status
4. Docker + down → kali_up  (mode vpn if tun0 / HTB, else lan)
     SSH: key login already works; copy pack scripts to /opt/adtk if missing
     VPN labs → kali_preflight (clamp tun0 mtu 1200 + clock); re-run after reconnect
5. kali_bootstrap  (once per box; it detaches — poll kali_logs, do not wait on the tool call)
6. Verify binaries (same check, Docker or SSH):
     nxc|netexec · nmap · hashcat · certipy · bloodyAD
     GetUserSPNs.py|impacket-GetUserSPNs · secretsdump.py|impacket-secretsdump
     getST.py|impacket-getST · /opt/adtk/ad-auto.py
7. Only now: ad_plan / ad_auto / kali_exec for the current step
     (the --dc you pass selects the per-target tree logs/<dc-ip>/)
     ad_auto and nmap/bloodhound/secretsdump auto-detach — poll kali_logs
8. logs_read auto/state.json and auto/report.txt
9. After a BloodHound collect: bh_next, then ONE kali_exec for the printed edge
```

Any `MISSING` binary: add it to `scripts/bootstrap.sh` **and**
`docker/Dockerfile`, then re-bootstrap.

## Kill chain (01–16)

Walk in order unless you already have a foothold. Fill
`{{DC}} {{DOMAIN}} {{USER}} {{PASS}}` from the current target, and open the
matching reference rather than dumping the whole repo.

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
| 09 | `lateral` | PTH, tickets, WinRM, LSASS, LPE | `tools/shells.md` · `tools/lpe.md` |
| 10 | `acl` | GenericAll / WriteDACL / … | `tools/bloodyad.md` |
| 10b | `maq` `shadow` `rbcd` | MAQ + PKINIT + getST | `tools/tickets.md` · `tools/shadow.md` |
| 11 | `delegation` | UC / CC / RBCD | `tools/impacket.md` |
| 12 | `adcs` | ESC1–ESC15 | `tools/certipy.md` |
| 13 | `sysvol` `laps` | GPP, GPO, LAPS, gMSA | `tools/gpo.md` |
| 14 | `mssql` | Impersonate, links, xp_cmdshell | `tools/mssql.md` |
| 15 | `trusts` `trusthop` | Child → parent, forests | `tools/trusts.md` |
| 16 | `dcsync` | NTDS, KRBTGT, golden, EA | `references/steps.md` §16 |

Core four: nxc + Impacket + Certipy + bloodyAD. Collect BloodHound the moment you
have a domain user, then run `bh-next.py` instead of guessing the next ACE. DA on
one domain is not a takeover while trusts remain.

Checklist, skip rules, and phase budgets: [references/steps.md](references/steps.md).

## Go fast

Live runs spent most of their wall clock on serial work and CPU john. Three
helpers sit outside the decide() loop:

```bash
# known labs: documented stock creds in parallel, before recon
/opt/adtk/spray-stock.sh 192.168.56.10 192.168.56.11 192.168.56.12

# per-domain BloodHound / DCSync in parallel (default 5-wide)
printf '%s\n' \
  "bloodhound-python -c All -d sevenkingdoms.local -u u -p p -ns 192.168.56.10 -o /logs/bh/sk" \
  "bloodhound-python -c All -d north.sevenkingdoms.local -u u -p p -ns 192.168.56.11 -o /logs/bh/north" \
  | /opt/adtk/fan.sh

# crack roast hashes on the HOST (Metal/GPU). Kali has none
ADTK_WORDLIST=~/wordlists/rockyou.txt \
  scripts/host-crack.sh --mode 13100 --hash ./kerb.txt --background
```

`spray-stock.sh` is a known-answer check: one guess per documented pair. Copy
`conf/creds.goad.example` → `conf/creds.goad` for GOAD-family labs.

To grab a CTF flag off the DC, run one sweep instead of N `atexec 'type
flag.txt'` calls:

```bash
export ADTK_DC=10.10.11.47
/opt/adtk/revshell.sh flags -u Administrator -H <NT> -d megabank.htb
```

`flags` refuses a non-DC host unless you pass `--any`. Interactive reverse shells
(`payload` / `listen`) belong in a tty; MCP's ~30s cap kills them. Card:
`references/tools/revshell.md`.

## Docs

1. This README — clone, Docker/SSH, `ad-auto.py`, MCP
2. [references/steps.md](references/steps.md) — 01–16 + "Go fast"
3. [references/automation.md](references/automation.md) — how `ad-auto.py` decides
4. [references/mcp.md](references/mcp.md) — wire Cursor / Claude
5. [ad-writeups/INDEX.md](ad-writeups/INDEX.md) — fingerprint a known box
6. [ad-writeups/coverage-matrix.md](ad-writeups/coverage-matrix.md) — coverage vs gaps

For a tool question, open **one** card under `references/tools/`. Index:
[references/tools.md](references/tools.md).

AI agents: load [SKILL.md](SKILL.md) (RoE, MCP-first loop, stop condition).

## Tests

```bash
python3 scripts/ad-auto.py --self-test
python3 mcp/server.py --self-test
bash -n scripts/*.sh
```

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first, keep
the self-tests green, and never commit secrets. The MCP-first loop must stay in
sync across `SKILL.md`, `references/mcp.md`, and this README. New labs, tool
cards, and write-ups are all fair game as long as they stay authorized-use only.

## License

[MIT](LICENSE), with an authorized-use notice. Educational tooling for
authorized security testing only.
