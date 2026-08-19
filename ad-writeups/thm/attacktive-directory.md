# TryHackMe — Attacktive Directory (path notes)

**Type:** Intro AD room · Lab only.

## One-line path

Enum users (Kerberos) → AS-REP / Kerberoast → service user → DCSync /
Administrator.

## Steps (high level)

1. Enumerate Kerberos users (`kerbrute` / Impacket).
2. AS-REP roast users without preauth; crack.
3. Kerberoast SPNs; crack.
4. Use valid domain cred for further LDAP / SMB.
5. Privilege path to DCSync or local admin on DC.
6. Dump hashes / submit flags per room tasks.

## ADTK skill mapping

`unauth` → `asrep` → `kerberoast` → `bloodhound` → `dcsync`
