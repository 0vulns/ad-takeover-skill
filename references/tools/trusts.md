# Trusts (senior)

DA on one domain is not a forest takeover. Read the trust object before forging.

## When / not

Use after you have DA (or DCSync) in **one** domain, or a cred that can
`nxc ldap --trusts`. Skip if a single-domain box (`--trusts` empty).

## Flags

```
nxc ldap {{DC}} -u {{USER}} -p '{{PASS}}' --trusts
impacket-lookupsid {{DOMAIN}}/{{USER}}:'{{PASS}}'@{{DC}}
bloodhound-python … -c All     # Trusts + Foreign groups
```

## Decision

| Trust | SID filtering | Move |
| --- | --- | --- |
| Parent / child (same forest) | usually **off** | extra-SID `PARENT-519` or `raiseChild` |
| Tree-root / shortcut (same forest) | off | same — EA is forest-wide |
| Forest (two-way) | **on** by default | no extra-SID. Need a foreign group, ADCS, or MSSQL link |
| External | on | treat as a new foothold. Roast / spray the other side |
| SID history enabled | check BH | may already have a 519 in PAC |

`raiseChild` automates child DA → parent EA when filtering is off:

```
impacket-raiseChild north.sevenkingdoms.local/eddard.stark:'FightP3aceAndHonor!'
```

## Read this

- Direction: **outbound** from the domain you own is what you can walk.
- `TrustAttributes` `TREAT_AS_EXTERNAL` / `FILTER_SIDS` → extra-SID dies.
- Forest root EA (`S-1-5-21-PARENT-519`) is the stop condition, not child DA.
- GOAD: NORTH and SEVENKINGDOMS are the same forest; ESSOS is a **forest**
  trust — MSSQL / ADCS / foreign group, not extra-SID.

## Fail → next

| Symptom | Next |
| --- | --- |
| extra-SID TGT works, EA denied | filtering on. stop forging |
| no trust objects | single domain. you are done after KRBTGT |
| other forest, no cred | AS-REP / guest / MSSQL link / ESC on their CA |
| `lookupsid` stops at 1000 | `-max-rid 4000` for foreign groups |

## Chain

Child DA → raiseChild / extra-SID 519 → parent KRBTGT.
Forest trust → `mssql.md` / `certipy.md` / BH foreign members. Re-collect BH
**in the other domain** (`-d` / `-dc` swapped).
