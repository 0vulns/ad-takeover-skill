# GOAD topology (full lab, 5 VMs / 2 forests / 3 domains)

IPs assume `ip_range = 192.168.56`. Last octet is fixed by the lab.

## Domains

| DNS | NetBIOS | DC | IP | OS | Notes |
| --- | --- | --- | --- | --- | --- |
| sevenkingdoms.local | SEVENKINGDOMS | kingslanding | .10 | WS2019 | Forest root. Defender on. |
| north.sevenkingdoms.local | NORTH | winterfell | .11 | WS2019 | Child of sevenkingdoms. Defender on. |
| essos.local | ESSOS | meereen | .12 | WS2016 | Separate forest. Bidirectional trust with sevenkingdoms. Defender on. |

## Members

| Host | FQDN | IP | OS | Role |
| --- | --- | --- | --- | --- |
| castelblack | castelblack.north.sevenkingdoms.local | .22 | WS2019 | IIS (asp upload as NETWORK SERVICE), MSSQL, SMB. Defender **off**. Local admin: jeor.mormont |
| braavos | braavos.essos.local | .23 | WS2016 | MSSQL, SMB. Defender on. |

MSSQL:

- CASTELBLACK `sa` = `Sup1_sa_P@ssw0rd!` — admin: `NORTH\jon.snow`
  - `EXECUTE AS USER` arya.stark → dbo
  - `EXECUTE AS LOGIN` samwell.tarly → sa, brandon.stark → jon.snow
  - Linked server to BRAAVOS as sa (`jon.snow`)
- BRAAVOS `sa` = `sa_P@ssw0rd!Ess0s` — admin: `ESSOS\khal.drogo`
  - Link back toward CASTELBLACK (`jorah.mormont` → sa)

## Trusts

- Parent/child: `sevenkingdoms.local` → `north.sevenkingdoms.local`
- External / forest: `sevenkingdoms.local` ↔ `essos.local`
- Cross-forest groups: AcrossTheSea, AcrossTheNarrowSea, DragonsFriends, Spys

## Users (ansible defaults — public lab)

### north.sevenkingdoms.local

| User | Password | Hook |
| --- | --- | --- |
| brandon.stark | iseedealpeople | AS-REP (preauth off). Writeups often try `iseedeadpeople` too. |
| rickon.stark | Winter2022 | Spray `WinterYYYY` |
| hodor | hodor | User = password spray |
| jon.snow | iknownothing | Kerberoastable (HTTP/thewall). MSSQL admin on CASTELBLACK. Night Watch + Stark |
| samwell.tarly | Heartsbane | Password in LDAP `description`. GPO Edit on STARKWALLPAPER. execute as login sa |
| arya.stark | Needle | MSSQL impersonate → dbo. Shares |
| eddard.stark | FightP3aceAndHonor! | NORTH Domain Admin. LLMNR bot ~5 min — Relaying target |
| catelyn.stark | robbsansabradonaryarickon | Stark |
| robb.stark | sexywolfy | LLMNR bot ~3 min / LSASS |
| sansa.stark | 345ertdfg | Keywalk. Unconstrained-delegation flavour / HTTP SPN |
| jeor.mormont | _L0ngCl@w_ | Local admin CASTELBLACK. Password in SYSVOL script |
| sql_svc | YouWillNotKerboroast1ngMeeeeee | Kerberoast bait (hard) |

### sevenkingdoms.local

| User | Password | Hook |
| --- | --- | --- |
| tywin.lannister | powerkingftw135 | ForceChangePassword on jaime. GPP / SYSVOL |
| jaime.lannister | cersei | GenericWrite on joffrey |
| tyron.lannister | Alc00L&S3x | Self-membership Small Council |
| joffrey.baratheon | 1killerlion | WriteDACL on tyron |
| renly.baratheon | lorastyrell | WriteDACL on container. Sensitive |
| stannis.baratheon | Drag0nst0ne | GenericAll on kingslanding computer |
| lord.varys | _W1sper_$ | GenericAll on Domain Admins + SD holder |
| robert.baratheon | iamthekingoftheworld | SEVENKINGDOMS DA. Protected Users |
| cersei.lannister | il0vejaime | Lannister |
| petyer.baelish | @littlefinger@ | Write property paths |
| maester.pycelle | MaesterOfMaesters | — |

### essos.local

| User | Password | Hook |
| --- | --- | --- |
| missandei | fr3edom | AS-REP. GenericAll on khal. GenericWrite viserys |
| khal.drogo | horse | MSSQL admin BRAAVOS. GenericAll viserys (shadow creds). GenericAll ESC4 |
| viserys.targaryen | GoldCrown | Write property on jorah |
| jorah.mormont | H0nnor! | MSSQL execute as / link. Read LAPS |
| daenerys.targaryen | BurnThemAll! | Targaryen / DA-adjacent |
| drogon | Dracarys | gMSA / dragon path |
| sql_svc | YouWillNotKerboroast1ngMeeeeee | Kerberoast bait |

## Groups / RDP

- Small Council → RDP kingslanding
- Stark / Starks → RDP winterfell + castelblack
- Night Watch, Mormont → RDP castelblack
- Targaryen → RDP meereen
- Dothraki → RDP braavos

## ACL chains worth memorizing

SEVENKINGDOMS:

`tywin --ForceChangePassword--> jaime --GenericWrite--> joffrey --WriteDACL--> tyron --self-add--> Small Council`

`lord.varys --GenericAll--> Domain Admins` (and SD holder)

`stannis --GenericAll--> kingslanding$`

ESSOS:

`missandei --GenericAll--> khal --GenericAll--> ESC4 / viserys (shadow creds)`

`jorah --ReadLAPSPassword--> member local admin`

## Local / domain bootstrap secrets (lab)

Do **not** lead with these. They exist so a broken lab can be repaired.

- kingslanding local admin: `8dCT-DJjgScp`
- winterfell / castelblack local admin: `NgtI75cKV+Pu`
- meereen local admin: `Ufe-bVXSx9rk`
- braavos local admin: `978i2pF43UJ-`
