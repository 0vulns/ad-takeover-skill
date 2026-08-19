# HTB Forest — path notes

**Type:** Easy Windows DC · Domain: `htb.local` · DC: Forest  
**Lab only.** Sources: public retired-box writeups (Kyuu-Ji, roughiz, community).

## One-line path

Null/LDAP user enum → **AS-REP** `svc-alfresco` → crack → Account Operators
chain → **WriteDACL** on domain (via Exchange Windows Permissions) → grant
**DCSync** → secretsdump Administrator.

## Steps (high level)

1. **Recon** — 88/389/445/5985. Domain `htb.local`.
2. **Unauth enum** — ldapsearch / enum4linux / RID cycle → user list.
3. **AS-REP Roast** — `GetNPUsers` / `nxc ldap --asreproast` on users with
   DONT_REQ_PREAUTH. Target often `svc-alfresco`.
4. **Crack** — hashcat `-m 18200` (lab wordlists / rockyou).
5. **BloodHound** — collect as the cracked user. Mark owned.
6. **ACL** — Account Operators → Exchange Windows Permissions (GenericAll /
   AddMember). Add self to that group.
7. **WriteDACL on domain** — grant yourself DS-Replication-Get-Changes +
   Get-Changes-All (DCSync rights).
8. **DCSync** — `secretsdump` / `nxc smb --ntds` as the privileged principal.
9. **PTH** — Administrator NT hash → wmiexec / evil-winrm / psexec.

## Techniques to card

AS-REP · BloodHound · ACL AddMember/WriteDACL · DCSync · PTH

## GOTAD skill mapping

`asrep` → `bloodhound` → `bh-next` → `acl` → `dcsync`
