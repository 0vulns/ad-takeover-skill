# HTB Blackfield — path notes

**Type:** Hard Windows DC · Domain: `BLACKFIELD.local`  
**Lab only.**

## One-line path

Share / user list → **AS-REP** `support` → ForceChangePassword on audit user
→ LSASS / SeBackupPrivilege → **NTDS.dit offline** → Administrator hash.

## Steps (high level)

1. **Recon** — SMB shares; possible forensics/share with usernames.
2. **AS-REP** — `support` (or similar) without preauth; crack.
3. **BloodHound** — ForceChangePassword (or similar) on a higher-value user.
4. **Password reset** (lab) — take over audit/backup-capable account.
5. **WinRM** — shell as that user.
6. **SeBackupPrivilege** — copy `NTDS.dit` + SYSTEM hive (diskshadow /
   robocopy backup tricks).
7. **Offline secretsdump** — `secretsdump -ntds NTDS.dit -system SYSTEM LOCAL`.
8. **PTH Administrator**.

## Techniques to card

AS-REP · ForceChangePassword · SeBackupPrivilege · offline NTDS · PTH

## GOTAD skill mapping

`asrep` → `bloodhound` / `acl` → `shells` → `dcsync` (offline variant)
