# GOAD — attack path catalog (lab)

Structured paths commonly documented for GOAD. Confirm edges on **your**
instance with BloodHound; ansible seeds can shift slightly by version.

## NORTH footholds

| Path | Flow |
| --- | --- |
| AS-REP | `brandon.stark` → crack → domain user |
| Spray | `hodor:hodor`, `rickon` + `Winter2022`-style |
| Description | `samwell.tarly` password in LDAP description |
| Kerberoast | `jon.snow` (HTTP/thewall) → crack |

## NORTH → privilege

| Path | Flow |
| --- | --- |
| GPO | samwell edit STARKWALLPAPER-style GPO → SYSTEM / local admin |
| MSSQL | jon.snow on CASTELBLACK → impersonate / link → BRAAVOS (ESSOS) |
| Unconstrained | Coerce + extract TGT (lab) |
| ACL | BloodHound outbound from owned Starks / Night Watch |

## SEVENKINGDOMS ACL ladder (example chain)

Documented style of chain (names are public lab characters):

1. ForceChangePassword (e.g. tywin → jaime)
2. GenericWrite (targeted SPN / shadow)
3. WriteDACL / AddMember toward high-value groups
4. GenericAll on DA or DC computer → RBCD / DCSync

Prefer `bh-next` + bloodyAD over memorizing a fixed ladder.

## ESSOS / ADCS

| Path | Flow |
| --- | --- |
| AS-REP | e.g. missandei-style users |
| ESC4 / ESC1 | Template write → enrollee SAN → DA cert → `certipy auth` |
| LAPS | ReadLAPSPassword on OU → local admin |
| Shadow | GenericWrite on user → PKINIT |

## Trusts

| Trust | Move |
| --- | --- |
| Parent/child (NORTH ↔ SEVENKINGDOMS) | SID filtering usually off → raiseChild / extra-SID 519 |
| Forest (↔ ESSOS) | Filtering usually on → SQL / ADCS / foreign group, not blind extra-SID |

## Stop condition

KRBTGT (or full NTDS) for **each** in-scope domain + EA-equivalent on forest root.
