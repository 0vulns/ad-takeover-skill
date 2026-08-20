# Steps 01–16 (generic)

Tokens: `{{DC}} {{DOMAIN}} {{DC_FQDN}} {{USER}} {{PASS}} {{HASH}} {{CIDR}} {{NS}} {{IFACE}} {{ATTACK}}`.

`scripts/ad-auto.py` is the automated source of truth. This file is the
agent checklist — when to skip, what “done” means. Commands: `commands.md`.

## Go fast (both live runs were >45 min — most of it avoidable)

Three habits cut the wall clock; the setup ladders (MTU, VM recovery, package
drift) are already handled by the preflight and bootstrap.

- **Fast path first on known labs.** On GOAD family, spray the documented stock
  creds in parallel *before* recon/AS-REP — `spray-stock.sh {{DC}} <dc2> <dc3>`.
  `.refinements/2.md` got 21/23 valid (incl. DA-grade) in ~1 min this way.
  `ad-auto --profile goad` now sprays stock creds before roasting for you.
- **Fan out per-domain / per-host work, don't serialize it.** BloodHound ×N,
  DCSync ×N, spray ×N all run concurrently with `fan.sh` (`commands.md`).
  Serial per-domain work was the biggest sink on the 3-domain lab.
- **Crack on the HOST, never block the chain.** The Kali VM has no GPU
  (`.refinements/1.md` dead-ended on CPU john). Capture the hash on Kali, pull
  it down, run `host-crack.sh --background` on the host, and keep enumerating
  (BloodHound / ACL / ADCS) while it runs. `ad-auto` time-boxes its on-box crack
  to `ADTK_CRACK_BUDGET` (90s) and then hands you the offload command.

Rough budget per phase (VPN lab): box+preflight ≤5 min, recon ≤3, foothold
(stock spray / roast) ≤5, BloodHound + bh-next ≤5, the winning edge ≤10.
**Stop at proof:** DCSync of every in-scope KRBTGT + acting DA/EA is the
takeover. Post-takeover tooling/persistence is a separate, optional task — do
not let it pad the takeover clock.

## 01 Attack box
Done: `nxc smb {{DC}}` and `nxc ldap {{DC}}` respond. Clock within 5 minutes.
Skip macvlan on HTB VPN — you already have `tun0`. Use `docker-compose.vpn.yml`.
**VPN labs: run the preflight before any Kerberos.** `tun0` often negotiates an
MTU (1300) above the real path MTU (~1230), so full-MSS TGS-REQs are silently
black-holed (`Connection reset by peer`) even though AS-REQs succeed. Clamp it
and sync the clock — re-run after any VPN reconnect:
```
/opt/adtk/preflight.sh {{DC}} tun0 1200
# manual: ip link set dev tun0 mtu 1200 ; ntpdate -u {{DC}}   # or ntpsec-ntpdate
# PMTU probe: ping -M do -s 1400 -c1 {{DC}}  (fails => path MTU below full segment)
```

## 02 Recon
Done: host list with roles (DC vs member vs SQL vs HTTP vs CA).
If only 88/389/445 on one IP, it is a single-DC box. Still run the chain.

## 03 Unauth enum
Done: `users.txt` or a hard no on null/guest.
RID cycle (`lookupsid`) often works when LDAP anonymous does not — **but on a
slow/VPN link RID-brute times out (`NetBIOSTimeout`); use bulk anonymous LDAP
instead** (`enum.md` "High latency"): one query each for all users+descriptions,
AS-REP roastable, and SPNs.
Try `guest` with an **empty password** — null is often denied while guest binds.
guest is first-class: LDAP + BloodHound + Kerberoast `-no-pass` all work from it.
**Fingerprint early:** match the domain / DC name / open ports against
`ad-writeups/INDEX.md` — a known box (e.g. `thm.local` → Operation Endgame) hands
you the intended path and saves brute-forcing.

## 04 Poison + relay
Skip on most HTB PWN networks (no L2 broadcast). Do it on GOAD / local labs.
Prefer LDAP/ADCS relay when SMB signing is required.
The automator **skips** this step (listeners hang).

## 05 AS-REP
Hash mode 18200. No users → not a failure, continue.

## 06 Spray
Read lockout first (`--pass-pol`). Cap attempts. kerbrute over Kerberos is quieter.

## 07 Kerberoast
Mode 13100 (RC4) then 19700/19600 (AES). gMSA is step 13, not this.
If guest/null binds, roast **here with `-no-pass` before §06 spray** — don't
burn rounds on RID-brute + AS-REP + spray when guest already yields an SPN hash
(Operation Endgame: guest → GetUserSPNs `-no-pass` → CODY_ROY).

## 08 BloodHound
Mandatory once you have any domain user. Re-collect after every domain hop.
Then `bh-next.py` — do not guess the next ACE.

## 09 Lateral
Spray the new cred/hash across the CIDR. No local admin → stay in LDAP (10–12).
Landed a low-priv shell? `tools/lpe.md`: `whoami /priv` first — SeImpersonate
(potato) or SeBackupPrivilege (offline NTDS/SAM) is the usual SYSTEM path. LPE is
for a cred, not the goal — the goal is DCSync (16).

**Deploy an operator payload as DA** (lab only, after takeover): triage on Kali
first (`unzip -l`, `file`, `objdump -p | grep "DLL Name"`, `strings`) — never
copy a zip you have not listed. Upload over SMB (`printf 'lcd …\nuse C$\nput f\nexit\n' | impacket-smbclient 'DOM/user:pw@dc'` — no `-windows-auth` in
impacket 0.14). `Expand-Archive` over WinRM. Launch with an explicit working
directory (license files resolve against CWD). GUI-subsystem binaries on a
headless DC live in session 0: detached `Start-Process` / `start /b` die at
channel teardown; the surviving pattern is `nohup` on Kali + synchronous
`cmd /c cd /d C:\Ad && agent.exe` over WinRM. Runner `exit 124` usually means
the payload is **alive** — confirm with a fresh-session `tasklist` before
retrying. Never truncate a first attempt's output with `tail -N`.

## 10 ACL + MAQ + shadow + RBCD
GenericAll / GenericWrite / WriteDACL / WriteOwner / ForceChangePassword /
AddSelf / AddMember. `bh-next` + bloodyAD `get writable`.
MAQ default 10 → addcomputer. GenericWrite user → shadow. Computer → RBCD.

## 11 Delegation
findDelegation. RBCD via a computer you can write. Unconstrained = coerce + extract.

## 12 ADCS
`certipy find -vulnerable`. ESC1–ESC15. No CA → skip.

## 13 GPO / SYSVOL / LAPS / gMSA
GPP cpassword, writable GPO → SYSTEM task, ReadLAPSPassword, msDS-ManagedPassword.

## 14 MSSQL
`mssql-hop.py`. Impersonate, linked servers, xp_cmdshell. Cross-domain hop on
GOAD. If `EXEC AT [BRAAVOS]` times out on a Ludus/WS2022 build, the
`data_source` is stale — own CASTELBLACK and BRAAVOS directly.

## 15 Trusts
`--trusts`, then `trusthop`: raiseChild / extra-SID only if SID filtering is off.
Forest trusts → SQL / ADCS / foreign group.

## 16 DCSync + EA
`secretsdump -just-dc-ntlm` / `krbtgt`. Golden only in the lab. Stop when every
in-scope domain’s KRBTGT is dumped and you can act in the forest root.
