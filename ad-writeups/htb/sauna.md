# HTB Sauna — path notes

**Type:** Easy Windows DC · Domain: `EGOTISTICAL-BANK.local`  
**Lab only.**

## One-line path

User enum → **AS-REP** → Autologon registry creds → **Kerberoast** svc →
BloodHound / ACL → **DCSync**.

## Steps (high level)

1. **Recon** — DC ports; domain name from LDAP/SMB banner.
2. **User list** — kerbrute / RID / LDAP.
3. **AS-REP Roast** — user without preauth; crack 18200.
4. **WinRM / lateral** — valid user shell.
5. **Autologon** — registry `Winlogon` DefaultUserName/Password (common on this box).
6. **Kerberoast** — service account with SPN; crack 13100.
7. **Privilege path** — BloodHound shortest path / DCSync rights group.
8. **DCSync** — dump KRBTGT / Administrator.

## Techniques to card

AS-REP · Autologon / registry · Kerberoast · DCSync

## ADTK skill mapping

`asrep` → `lateral` → `kerberoast` → `bloodhound` → `dcsync`
