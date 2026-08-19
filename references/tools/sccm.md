# SCCM / MECM (senior)

Present on CRTO and some GOAD-like labs. Skip if recon has no 445/80/443
site server and no `SMS` / `SCCM` SPN.

## When / not

Use after any domain user if BH / nxc shows an SCCM site, `SMS Admins`,
or `http://siteserver/CMApplicationCatalog`.
Do not invent SCCM on a single-DC HTB box.

## Flags

```
nxc ldap {{DC}} -u {{USER}} -p '{{PASS}}' --query \
  "(&(objectclass=*))" "" | rg -i 'sccm|sms|mecm' || true
nxc mssql {{CIDR}} -u {{USER}} -p '{{PASS}}'     # site DB is often MSSQL
# sccmhunter / SharpSCCM if the lab brief names SCCM
```

Usual primitives (public tools, lab only):

- Site admin / `SMS Admins` → NAA credentials (network access account) = domain user
- Client push → SYSTEM on a member (coerce + relay to site, or PXE)
- PXE media → domain creds in the boot image

## Chain

Site server admin → dump NAA → BloodHound as NAA → DA.
If nothing SCCM-shaped after recon, **mark done and leave**.
