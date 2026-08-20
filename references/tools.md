# Tool rack (senior)

Install: `scripts/bootstrap.sh`. Cookbook: `commands.md`. Decision loop: `automation.md`.

Open **one** card. Do not dump this folder.

| Reach for | Card | Instead of |
| --- | --- | --- |
| Every protocol, every host | `tools/netexec.md` | one-off smbclient/rpcclient |
| Tickets, dumps, relay, SQL, exec | `tools/impacket.md` | living off nxc only |
| Shortest path / next edge | `tools/bloodhound.md` | guessing the next user |
| Read/write directory | `tools/bloodyad.md` | raw ldapmodify |
| Shadow / PKINIT | `tools/shadow.md` | resetting the password |
| Tickets / MAQ / RBCD | `tools/tickets.md` | golden-first |
| Trust hop | `tools/trusts.md` | extra-SID on a forest trust |
| ESC1–ESC15 / PKINIT | `tools/certipy.md` | certutil on a jumphost |
| GPO / LAPS / gMSA | `tools/gpo.md` | another roast |
| MSSQL links | `tools/mssql.md` | stopping at login |
| SCCM (if present) | `tools/sccm.md` | inventing a site server |
| LLMNR / relay / coerce / IPv6 | `tools/relay.md` | waiting for a roast |
| 18200 / 13100 / 5600 / 1000 | `tools/crack.md` | john-the-long-way first |
| Landed shells | `tools/shells.md` | dropping a beacon |
| Reverse shell / grab the flag | `tools/revshell.md` | N one-off `atexec 'type flag'` calls |
| SYSTEM on the box (SeImpersonate / SeBackup) | `tools/lpe.md` | assuming you need DA first |
| Null / RID / offline LDAP | `tools/enum.md` | BloodHound with no cred |
| On-host after a shell | `tools/onhost.md` | more nxc from Kali |

Core four: **nxc + Impacket + Certipy + bloodyAD**. BloodHound the moment you have a user. Responder only on the same L2. Rubeus/Mimikatz only after a shell.

Hashcat modes: `18200` AS-REP · `13100` TGS-RC4 · `19600/19700` TGS-AES · `5600` NetNTLMv2 · `1000` NTLM.

Agent rule: interpolate `{{DC}} {{DOMAIN}} {{USER}} {{PASS}}` from the current target. Name the card you used.
