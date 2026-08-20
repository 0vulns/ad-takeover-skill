# GOAD-on-Ludus (WS2022) — path notes

**Lab:** Ludus-built GOAD variant (e.g. `AD-CVE-OpenVPN-1-15`). Authorized
homelab only. Topology matches classic GOAD; OS is Server 2022.

Live trail: `.refinements/2.md`.

## What this build keeps from stock GOAD

- Same 5 hosts on `192.168.56.0/24`: KINGSLANDING `.10` (sevenkingdoms.local
  root), WINTERFELL `.11` (north child), MEEREEN `.12` (essos.local),
  CASTELBLACK `.22` + BRAAVOS `.23` (MSSQL).
- Stock ansible defaults are valid **21/23** in this build. Spray them first
  (`references/labs/goad-topology.md`) before roasting.
- `daenerys.targaryen` is **pre-seeded in essos Domain Admins** — BloodHound
  group expansion is the tell, not a roast.
- `lord.varys` GenericAll → DOMAIN ADMINS / ENTERPRISE ADMINS. One
  `bloodyAD add groupMember` (nxc `--add-member` is gone) is forest EA.

## What this build breaks

- CASTELBLACK → BRAAVOS linked-server is present but the `data_source` is
  stale (ping works, `EXEC (…) AT [BRAAVOS]` times out / Named Pipes 53).
  **Own both engines directly**: jon.snow is sysadmin on `.22`, khal.drogo
  is admin on `.23`. Do not wait on the hop.
- `krbtgt` is not unique across the three domains.
  `secretsdump -just-dc-user krbtgt` → `ERROR_DS_NAME_ERROR_NOT_UNIQUE`.
  Use NetBIOS form: `-just-dc-user SEVENKINGDOMS/krbtgt`.
- OpenVPN path MTU: clamp `tun0` to 1200 before Kerberos/LDAP.
- Reach the lab from an SSH Kali whose own IP is **outside** the pushed
  routes, or the VPN will black-hole your SSH session.

## One-line forest story

Stock GOAD creds → BloodHound → lord.varys GenericAll → add to DA+EA →
WinRM Pwn3d on the root → DCSync krbtgt ×3 (NetBIOS-prefixed) → own both
MSSQL members directly. raiseChild is optional once you are already EA.

## ADTK skill mapping

`box` (preflight MTU) → `recon` → `spray` (topology creds) → `bloodhound` →
`acl` (bloodyAD add groupMember) → `dcsync` → `mssql` (direct, not the link).
