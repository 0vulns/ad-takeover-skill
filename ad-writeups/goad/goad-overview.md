# GOAD — overview path notes

**Lab:** Game Of Active Directory (Orange Cyberdefense)  
**Authorized homelab only.** Never expose to the internet.

Official: https://github.com/Orange-Cyberdefense/GOAD  
Docs: https://orange-cyberdefense.github.io/GOAD/

## Topology (classic GOAD)

| Host | Role | Domain |
| --- | --- | --- |
| kingslanding | DC | sevenkingdoms.local (forest root) |
| winterfell | DC | north.sevenkingdoms.local (child) |
| meereen | DC | essos.local (second forest) |
| castelblack | MSSQL / IIS | north |
| braavos | MSSQL | essos |

Default LAN often `192.168.56.0/24` (check your Vagrant IP range).

## Public lab defaults (ansible seeds — not real-world secrets)

Examples documented publicly in GOAD materials (verify on your build):

- `hodor` / `hodor` (spray)
- `brandon.stark` — AS-REP
- `jon.snow` — Kerberoast / MSSQL
- `samwell.tarly` — password in LDAP description; GPO edit
- `rickon.stark` — season spray `WinterYYYY`
- North DA / forest paths via ACL ladder and trusts
- ESSOS: AS-REP, ADCS ESC, LAPS readers, MSSQL links from NORTH

## One-line forest story

NORTH foothold (AS-REP/spray/Kerberoast) → BloodHound ACL / MSSQL →
child DA → **raiseChild / extra-SID** to sevenkingdoms EA → ESSOS via
forest trust, SQL link, or ADCS — not extra-SID if SID filtering is on.

## ADTK skill mapping

Full 01–16 chain. Prefer:

`box` → `recon` → `unauth` → `asrep` → `spray` → `kerberoast` →
`bloodhound` + `bh-next` → `acl` / `maq` / `shadow` / `rbcd` →
`adcs` → `mssql` → `trusts` / `trusthop` → `dcsync`

Profile: `--profile goad`
