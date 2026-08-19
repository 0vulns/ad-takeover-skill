# Automation (decision engine)

`scripts/ad-auto.py` is **not** a linear 01–16 script. It asks “what is the
most useful next action given loot?” and stops when another cycle would not
help.

Requires `--i-am-authorized` to run. Public tools only. Poison/relay is
never auto-run (listeners hang).

## Invoke

```bash
# discover domain / CIDR from the DC banner
python3 /opt/gotad/ad-auto.py --i-am-authorized --dc 192.168.56.11 --profile goad

# HTB-style
python3 /opt/gotad/ad-auto.py --i-am-authorized \
  --dc 10.10.11.47 --iface tun0 --user j.smith --password 'Welcome1'

# print the next action only
python3 /opt/gotad/ad-auto.py --plan --resume
python3 /opt/gotad/ad-auto.py --plan --dc 10.10.11.47 --domain megabank.htb

# resume / jump
python3 /opt/gotad/ad-auto.py --i-am-authorized --resume --from acl
python3 /opt/gotad/ad-auto.py --i-am-authorized --dc $DC --only asrep,spray

# lab-only: act on first ForceChangePassword / ESC1
python3 /opt/gotad/ad-auto.py --i-am-authorized --resume --abuse
```

`--domain` and `--cidr` are optional. Banner parse fills them
(`(domain:foo.local)` → domain, `10.10.11.47` → `10.10.11.0/24`).
`--profile auto` becomes `goad` if the domain looks like sevenkingdoms/essos.

State: `/loot/auto/state.json` + `/loot/auto/report.txt` (`GOTAD_LOOT`).

## How it decides

```
no DC          → box
no hosts       → recon
no users       → unauth (null, guest, RID cycle)
no cred        → asrep, then spray (user=pass, LDAP descriptions, seasons)
have cred      → BloodHound FIRST, then bh-next.py
then           → kerberoast → SYSVOL/GPP → LAPS/gMSA → lateral → ACL
               → MAQ → shadow → RBCD → ADCS → delegation → MSSQL → trusts → trusthop
DA / admin     → DCSync
--abuse        → FCP + ESC1 + first shadow + addcomputer FAKE$
```

Each action is marked `done` so the loop does not repeat it. `--rounds`
caps cycles (default 16).

Skips with a reason:

| Condition | Skip |
| --- | --- |
| `tun0` / `tun1` | poison (noted as next-manual) |
| no users.txt | spray |
| no cleartext cred | BloodHound / ACL / ADCS / delegation |
| no 1433 in recon | MSSQL |
| certipy “no CA” | ADCS |
| no writable / no ESC | abuse |
| lockout N | spray cap = 2 |

## What it parses

- nxc banners → host, domain, signing, Pwn3d, DC vs SQL
- `[+] DOMAIN\user:secret` → cred or NT hash
- `--users` + lookupsid RIDs → `users.txt`
- `description:` fields → extra spray candidates
- lockout threshold
- `$krb5asrep$23$user` / `$krb5tgs$23$*user` paired with hashcat/john
- bloodyAD `writable` → edges
- certipy `ESC1–8`, template, CA
- GPP / lsassy / secretsdump NTDS lines
- `--trusts`

Cracking: `--profile goad` uses `conf/wordlist-lab.txt` first, then rockyou.
Usernames are taken from the hash itself (outfile-format 3), not “first name
in the file”.

## Agent behaviour

1. Restate lab/RoE.
2. If they only have a DC IP, run with just `--dc`. Do not invent a domain.
3. Prefer `--plan` after a failed run — read `state.json` / `report.txt`.
4. Do not restart from box if `done` already has a foothold — `--resume`.
5. Anything in `next_manual` is the operator’s job (relay, getST, linked
   SQL, extra-SID). Interpolate `commands.md` for those.
6. `--abuse` is lab-only password reset / ESC1. Never suggest it on a
   customer forest.

`python3 ad-auto.py --self-test` must stay green when you change parsers.
