# HTB Active — path notes

**Type:** Easy Windows DC · Domain: `active.htb`  
**Lab only.** Classic GPP + Kerberoast intro box.

## One-line path

SMB null / Groups.xml **GPP cpassword** → `SVC_TGS` → **Kerberoast**
Administrator SPN → crack → PTH / psexec as DA.

## Steps (high level)

1. **Recon** — SMB shares readable without creds (or with guest).
2. **SYSVOL / GPP** — `Groups.xml` (or similar) contains encrypted `cpassword`.
3. **Decrypt GPP** — offline decrypt (public algorithm; Impacket
   `Get-GPPPassword` / gpp-decrypt).
4. **Auth as SVC_TGS** — valid domain user.
5. **Kerberoast** — `GetUserSPNs -request` for Administrator (or other SPN).
6. **Crack TGS** — hashcat `-m 13100`.
7. **DA** — psexec / wmiexec / evil-winrm with cracked cleartext or hash.

## Techniques to card

GPP / SYSVOL · Kerberoast · PTH / exec

## GOTAD skill mapping

`unauth` / `sysvol` → `kerberoast` → `crack` → `lateral` / `dcsync`
