# Technique → challenge map

Use this to practice one technique across multiple authorized labs.

| Technique | HTB examples | GOAD | THM |
| --- | --- | --- | --- |
| AS-REP Roast | Forest, Sauna, Blackfield, Cicada | brandon.stark, essos users | Attacktive |
| Kerberoast | Active, Sauna, Intelligence | jon.snow | Attacktive, Endgame (guest `-no-pass`) |
| guest / null / empty password | Cicada | — | Endgame (guest, empty pw) |
| Password spray / user=pass | — | hodor, rickon | — |
| LDAP description passwords | Cascade | samwell.tarly | — |
| GPP cpassword | Active | SYSVOL paths | — |
| BloodHound ACL | Forest, Administrator, Blackfield | Full forest | Endgame (guest ACL) |
| GenericWrite on DC computer | — | — | Endgame (`AD$`) |
| ForceChangePassword | Blackfield | Lannister ladder | — |
| WriteDACL / DCSync rights | Forest | ACL chains | Endgame (grant after S4U) |
| SeBackupPrivilege / offline NTDS (`tools/lpe.md`) | Blackfield | — | — |
| Local privesc: SeImpersonate / potato | service-account boxes (IIS/MSSQL) | CASTELBLACK-style | — |
| ADCS ESC1–8 | Certified, Certificate, Mirage | essos CA / templates | — |
| Shadow credentials | Mirage | ACL GenericWrite users | — |
| RBCD (MAQ + FAKE$) | Pirate | MAQ + computer write | — |
| RBCD via existing user SPN | — | — | Endgame (CODY_ROY) |
| S4U getST `ldap/` for DCSync | — | — | Endgame |
| No WinRM → smbclient/atexec | — | — | Endgame |
| Unconstrained delegation | — | CASTELBLACK-style | — |
| MSSQL impersonate / links | Escape, EscapeTwo | CASTELBLACK → BRAAVOS | — |
| Cross-forest trust | DarkZero, PingPong | NORTH → SEVENKINGDOMS → ESSOS | — |
| LAPS / gMSA | Timelapse-adjacent, Pirate | jorah / gMSA reads | — |
| Pre2k computer accounts | Pirate | — | — |

## Practice order (suggested)

1. Active + Forest + Sauna (classic easy AD)
2. Blackfield (backup + AS-REP)
3. GOAD NORTH only
4. GOAD full forest + ADCS
5. Certified / Certificate / Mirage (ADCS focus)
6. DarkZero / Pirate (modern hard)
