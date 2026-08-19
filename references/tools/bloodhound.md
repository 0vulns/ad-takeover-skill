# BloodHound.py / RustHound / CE (senior)

Mandatory the moment you have any domain user. Re-collect after every hop.

## When / not

Use for: shortest path to DA, outbound control from owned, AS-REP, Kerberoast, sessions, UC, trusts, ADCS edges (CE).
Do not use as a substitute for a cred — collectors need a bind.
Do not re-collect every five minutes. Collect, mark owned, query, act, then collect again.

## Collectors

```
# legacy (Neo4j BloodHound ≤4)
bloodhound-python -u {{USER}} -p '{{PASS}}' -d {{DOMAIN}} \
  -dc {{DC_FQDN}} -ns {{NS}} -c All --zip -o /loot/bloodhound

bloodhound-python -u {{USER}} --hashes :{{HASH}} -d {{DOMAIN}} \
  -dc {{DC_FQDN}} -ns {{NS}} -c All --zip

# BloodHound CE / rusthound-ce (preferred on current labs)
rusthound-ce -d {{DOMAIN}} -u {{USER}}@{{DOMAIN}} -p '{{PASS}}' \
  -z -o /loot/bloodhound -f {{DC}}
bloodhound-ce-python -u {{USER}} -p '{{PASS}}' -d {{DOMAIN}} \
  -dc {{DC_FQDN}} -ns {{NS}} -c All --zip
```

`-ns {{NS}}` is not optional. If Kali uses 8.8.8.8 the zip is empty.

## Next edge (no GUI)

```
python3 /opt/gotad/bh-next.py /loot/bloodhound \
  --owned {{USER}} --state /loot/auto/state.json
```

That is what `ad-auto.py` runs after collect. Read the first HV edge and
open the matching card (`shadow.md` / `tickets.md` / `gpo.md` / `bloodyad.md`).

## Queries (in the GUI, in order)

1. Shortest path to Domain Admins from owned
2. Outbound Object Control from owned
3. Kerberoastable / AS-REP / unconstrained
4. Sessions on owned computers
5. Same-forest trusts / Foreign groups / Enterprise Admins
6. ADCS principals (CE)

Mark every cracked user **owned** before you query. An unmarked graph lies.

## Fail → next

| Symptom | Next |
| --- | --- |
| DNS / KDC errors | `/etc/hosts` + `-ns {{NS}}` |
| empty zip | wrong `-d` or collector. Confirm with nxc |
| `bh-next` “none of … found” | SAM in the zip is `USER@DOMAIN`. pass the SAM only |
| no path to DA | ACL/ADCS/session/GPO/MAQ — not more spray |
| path is GenericWrite on a user | `shadow.md` |
| path is GenericWrite on a computer | `tickets.md` RBCD |
| path is GPO | `gpo.md` |

## Chain

Any cred → collect → `bh-next` → **one** edge → abuse → re-collect.
Do not run Certipy, bloodyAD, and getST in parallel “just in case”.
