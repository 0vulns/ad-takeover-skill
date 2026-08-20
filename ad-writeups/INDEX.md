# AD Challenges Index

Difficulty is community/HTB rating at retirement or release. Techniques are
the dominant path, not the only one.

## HackTheBox (classic / retired AD)

| Machine | Diff | Domain / theme | Core techniques |
| --- | --- | --- | --- |
| Active | Easy | active.htb | GPP cpassword → Kerberoast → PTH |
| Forest | Easy | htb.local | AS-REP → Account Operators → WriteDACL → DCSync |
| Sauna | Easy | egotistical-bank.local | AS-REP → Autologon → Kerberoast → DCSync |
| Blackfield | Hard | BLACKFIELD.local | AS-REP → ForceChangePassword → SeBackupPrivilege → NTDS |
| Cascade | Medium | cascade.local | LDAP desc → AES key decrypt → WinRM → VNC → DA |
| Monteverde | Medium | MEGABANK.local | User enum → Azure AD Connect creds → DA |
| Timelapse | Medium | trust.htb | LAPS-ish / certs → PTH → DA |
| Return | Easy | return.local | Printer / relay-adjacent → DA |
| Intelligence | Medium | intelligence.htb | DNS / scripts → Kerberoast → DA |
| Object | Medium | object.htb | ACL / GPO-style paths |
| Cicada | Easy | cicada.htb | Guest / share → AS-REP / ACL → DA |
| Escape | Medium | sequel.htb | MSSQL → AD hop |
| EscapeTwo | Easy | sequel.htb | MSSQL linked / cert path |
| Administrator | Medium | administrator.htb | BloodHound ACL → DA |
| Certified | Medium | certified.htb | ADCS ESC |
| Certificate | Hard | certificate.htb | ADCS templates |
| Mirage | Hard | mirage.htb | ADCS + shadow |
| Vintage | Hard | vintage.htb | Pure AD / Kerberoast |
| DarkZero | Hard | multi-forest | Cross-forest trust |
| Pirate | Hard | pirate.htb | Pre2k, gMSA, PetitPotam, RBCD |
| PingPong | Hard | multi-forest | MSSQL delegation, ADCS |
| Eighteen | Hard | Server 2025 | MSSQL, Bad Successor / dMSA |

Full machine list (community):  
https://github.com/seriotonctf/HackTheBox-AD-Machines

## GOAD (Orange Cyberdefense)

| Lab | Scope | Core techniques |
| --- | --- | --- |
| GOAD | 3 domains, 2 forests | AS-REP, spray, Kerberoast, ACL ladder, ADCS ESC, MSSQL links, trusts, LAPS, gMSA |
| GOAD-on-Ludus (WS2022) | same topology | stock ansible 21/23; lord.varys GenericAll → EA; daenerys pre-seeded essos DA; CASTELBLACK→BRAAVOS link stale — own both MSSQL directly · [notes](goad/goad-ludus.md) |
| GOAD-Light | Smaller subset | Same primitives, fewer hosts |
| GOAD-Mini | Minimal | Condensed |

Domains: `sevenkingdoms.local` (root), `north.sevenkingdoms.local` (child),
`essos.local` (second forest).

Official lab: https://github.com/Orange-Cyberdefense/GOAD  
Scenarios: https://mayfly277.github.io/categories/ad/

## TryHackMe

| Room | Core techniques |
| --- | --- |
| Attacktive Directory | Enum → Kerberoast → DCSync (intro) |
| Operation Endgame | guest/empty-pw → Kerberoast → GenericWrite on DC$ → RBCD (existing SPN) → getST ldap/ → DCSync → atexec (no WinRM) · [notes](thm/operation-endgame.md) |
| Advent of Cyber / AD tracks | Mixed intro paths |
| Wreath / Ignite (network) | AD lateral in multi-host |

## Technique coverage (quick)

| Technique | Example boxes |
| --- | --- |
| AS-REP Roast | Forest, Sauna, Blackfield, GOAD (brandon.stark) |
| Kerberoast | Active, Sauna, GOAD (jon.snow) |
| GPP / SYSVOL | Active |
| BloodHound ACL | Forest, Blackfield, Administrator, GOAD |
| WriteDACL → DCSync | Forest |
| SeBackupPrivilege | Blackfield |
| ADCS ESC1–8 | Certified, Certificate, Mirage, GOAD |
| Shadow credentials | Mirage, GOAD ACL chains |
| RBCD / delegation | Pirate, GOAD unconstrained, Operation Endgame (existing-SPN RBCD) |
| guest / empty password | Operation Endgame, Cicada |
| MSSQL linked servers | Escape*, GOAD NORTH→ESSOS |
| Cross-forest / raiseChild | DarkZero, GOAD child→root |
| LAPS / gMSA | Timelapse-adjacent, GOAD, Pirate |
