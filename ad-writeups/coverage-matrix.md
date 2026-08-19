# Coverage matrix (writeups → skill)

Does the 01–16 kill chain + tool cards actually cover each authorized lab in
`INDEX.md`? Challenge list = `INDEX.md` + `techniques/technique-map.md`.

**Verdict legend**

- **(a)** skill covers it clearly
- **(b)** skill covers it, but an agent commonly misses / misapplies it
- **(c)** skill gap (technique not carded / not in a step)
- **(d)** skill *default* that would fail this room (wrong first move)

"Note" = has a path-notes file here. "INDEX-only" = techniques + `SOURCES.md`.

## HackTheBox

| Challenge | One-line path | Skill steps / cards | Verdict | Patch file |
| --- | --- | --- | --- | --- |
| Active (note) | GPP cpassword → Kerberoast → PTH | `unauth`/`sysvol` → `kerberoast` → `crack` → `lateral` · gpo.md, impacket.md | (b) SYSVOL/GPP before roast is easy to skip | steps.md §13, gpo.md |
| Forest (note) | AS-REP → Account Ops → WriteDACL → DCSync | `asrep` → `bloodhound` → `acl` → `dcsync` · bloodyad.md, impacket.md | (a) | — |
| Sauna (note) | AS-REP → autologon → Kerberoast → DCSync | `asrep` → `lateral` → `kerberoast` → `dcsync` · onhost.md | (a) | — |
| Blackfield (note) | AS-REP → ForceChangePassword → SeBackup → offline NTDS | `asrep` → `acl` → `shells` → `dcsync` (offline) | (b) SeBackup/offline NTDS variant | shells.md, impacket.md |
| Cascade (note) | LDAP desc / stored AES key → WinRM → DA | `unauth` (description) → `lateral` → `acl` | (b) look at description/stored keys, not only roast | enum.md |
| Monteverde (INDEX-only) | guest enum → Azure AD Connect creds → DA | `unauth` → `lateral` → on-host cred hunt · onhost.md | (c) Azure AD Connect DB cred hunt not carded | onhost.md (thin note) |
| Timelapse (INDEX-only) | PFX / LAPS-ish → PTH → DA | `unauth` → certipy.md (`auth`) → gpo.md (LAPS) | (b) PFX auth + LAPS read | certipy.md, gpo.md |
| Return (INDEX-only) | printer LDAP creds → Server Operators → DA | `unauth` → `lateral` → onhost.md | (c) printer LDAP-config credential capture | onhost.md (thin note) |
| Intelligence (INDEX-only) | doc/DNS enum → Kerberoast → RBCD/gMSA → DA | `recon` → `kerberoast` → `delegation`/gpo.md (gMSA) | (a) | — |
| Object (INDEX-only) | ACL / GPO write → DA | `acl` → gpo.md | (a) | — |
| Cicada (INDEX-only) | guest share → creds → AS-REP/ACL → DA | `unauth` (guest) → `asrep` → `acl` | (b) guest/empty-pw first-class | enum.md, netexec.md |
| Escape (INDEX-only) | MSSQL → AD hop → ADCS | `mssql` → mssql.md → certipy.md | (a) | — |
| EscapeTwo (INDEX-only) | MSSQL linked / cert path | `mssql` → `trusts`/certipy.md | (a) | — |
| Administrator (INDEX-only) | BloodHound ACL chain → DA | `bloodhound` → `acl` → `dcsync` | (a) | — |
| Certified (INDEX-only) | ADCS ESC → DA | `adcs` → certipy.md | (a) | — |
| Certificate (INDEX-only) | ADCS templates → DA | `adcs` → certipy.md | (a) | — |
| Mirage (INDEX-only) | ADCS + shadow creds | `adcs`/`shadow` → certipy.md, shadow.md | (a) | — |
| Vintage (INDEX-only) | pure AD: pre2k, Kerberoast, gMSA, RBCD | `unauth` → `kerberoast` → `delegation` · tickets.md | (b) pre2k + chained delegation | enum.md, tickets.md |
| DarkZero (INDEX-only) | cross-forest trust abuse | `trusts` → trusts.md | (b) forest trust: no extra-SID | trusts.md |
| Pirate (INDEX-only) | Pre2k, gMSA, PetitPotam, RBCD | `unauth` → `delegation`/`adcs` · relay.md, tickets.md | (b) coerce+relay is interactive, not MCP | relay.md, tickets.md |
| PingPong (INDEX-only) | MSSQL delegation, ADCS, multi-forest | `mssql` → `delegation` → `adcs` | (b) chained MSSQL+delegation | mssql.md |
| Eighteen (INDEX-only) | Server 2025 MSSQL, Bad Successor / dMSA | `mssql` → `delegation` | (c) dMSA / BadSuccessor (2025) not carded | steps.md (thin note) |

## GOAD

| Challenge | One-line path | Skill steps / cards | Verdict | Patch file |
| --- | --- | --- | --- | --- |
| GOAD (note) | AS-REP → spray → Kerberoast → ACL ladder → ADCS → MSSQL links → trusts | full 01–16, profile `goad` | (a) reference lab | labs/kill-chain.md |
| GOAD-Light / Mini | same primitives, fewer hosts | full 01–16 | (a) | — |

## TryHackMe

| Challenge | One-line path | Skill steps / cards | Session | Verdict | Patch file |
| --- | --- | --- | --- | --- | --- |
| Attacktive Directory (note) | enum → Kerberoast → DCSync | `unauth` → `kerberoast` → `dcsync` | — | (a) | — |
| Operation Endgame (note) | guest/empty-pw → Kerberoast → GenericWrite on `AD$` → RBCD (existing SPN) → getST `ldap/` → DCSync → atexec | `unauth` → `bloodhound` → `kerberoast` → `acl` → `rbcd` → `dcsync` | **yes** — see postmortem | (b)+(d): agent skipped MCP/bootstrap, sprayed before roast; `bloodyAD -p ''` + no-WinRM defaults | enum.md, netexec.md, impacket.md, bloodyad.md, tickets.md, shells.md, mcp.md |

## Session postmortem — Operation Endgame

Three tracks: **write-up path** vs **skill 01–16** vs **observed session behavior**
(`model-io-sess_c1d2c278`). The session never used the MCP tools
(`kali_status`/`kali_up`/`kali_bootstrap`/`ad_auto` = 0 calls); it drove Kali with
raw `docker exec` and `apt`/`pip`-installed tools ad-hoc mid-chain, and even
invoked a wrong bootstrap path (`/opt/gotad/scripts/bootstrap.sh`). It then burned
rounds on RID-brute (8000), AS-REP, and password spraying before finding the
Kerberoastable `CODY_ROY` that guest could roast immediately.

| Write-up step | Verdict | Why | Fix |
| --- | --- | --- | --- |
| Drive box via MCP + bootstrap first | (b) missed | session used raw docker, apt/pip ad-hoc, wrong bootstrap path | MCP-first loop is now hard-rule #3 in SKILL.md + mcp.md; bootstrap self-verifies |
| guest with empty password | (a) | guest binds, null denied | reinforced first-class in enum.md/netexec.md |
| Kerberoast `-no-pass` from guest | (b) missed order | agent sprayed / RID-brute before roasting | "roast before spray when guest works" in impacket.md + steps.md §07 |
| GenericWrite on DC computer `AD$` | (a) | carded in bloodyad.md | — |
| `bloodyAD -p ''` refuses | (d) default fails | stock bloodyAD rejects empty pw | empty-password path documented (Impacket `rbcd.py -no-pass`) in bloodyad.md |
| RBCD via existing user SPN | (c) gap | cards only taught MAQ+`FAKE$` | tickets.md now: existing-SPN user is a valid RBCD principal |
| getST `ldap/` for DCSync | (b) | tickets.md showed `cifs/` only | tickets.md/impacket.md: `ldap/` for DCSync, `cifs/` for C$ |
| No WinRM → smbclient/atexec | (d) default fails | shells.md defaulted to evil-winrm | shells.md/impacket.md: check `nxc winrm`; fall to smbclient.py/atexec |
