# HTB Cascade — path notes

**Type:** Medium · Domain: `cascade.local`  
**Lab only.**

## One-line path

LDAP **description** password → user hop → encrypted AES blob (Cascading
riddles) → WinRM → VNC / desktop creds → DA.

## Steps (high level)

1. **LDAP enum** with null or low user — passwords in `description` / comments.
2. **Auth hop** between cascaded accounts.
3. **Decrypt** application-specific encrypted password material (box theme).
4. **WinRM** as higher user.
5. **VNC / local artifacts** — recover Administrator-equivalent.
6. **Domain Admin**.

## Techniques to card

LDAP description spray · multi-user cascade · WinRM · local secret recovery

## ADTK skill mapping

`unauth` / `spray` (descriptions) → `lateral` → local dump → `dcsync`
