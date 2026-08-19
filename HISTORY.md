# Pack history (this conversation)

Authorized-lab AD takeover skill. No website. Lab / RoE only.

1. **Skill + Kali Docker** — GOAD-capable 01–16 kill chain, compose (macvlan + VPN), bootstrap, public tool rack.
2. **Not GOAD-only** — generic steps, profiles `goad` / `generic` / `auto`.
3. **Fully automated** — `scripts/ad-auto.py` decision engine (parse loot, skip dead ends, `--plan` / `--resume`).
4. **No website** — skill + docker + scripts + references only.
5. **Smarter runner** — discover domain/CIDR, lockout-aware spray, description harvest, next-manual.
6. **Senior tool cards** — nxc, Impacket, BloodHound, bloodyAD, Certipy, relay, crack, shells, enum, on-host.
7. **Abuse layer** — `bh-next.py` (zip → next edge), shadow / RBCD / MAQ, LAPS/gMSA, trust hop, `mssql-hop.py`, ESC9–15, GPO/SCCM cards.
8. **MCP** — `mcp/server.py` drives Kali via **Docker** or **SSH**. Mutating tools need `i_am_authorized`.
9. **MCP-first, repo cleanup, CTF hardening** — hard rule *MCP → bootstrap → verify → attack* at
   the top of SKILL.md, mirrored in `references/mcp.md` + README (transport env, SSH copy-to-`/opt/gotad`,
   fail→next). `bootstrap.sh` now self-verifies the rack (adds rusthound-ce). Reorg paths fixed
   (`references/labs/`). Added `ad-writeups/thm/operation-endgame.md` + coverage matrix +
   Endgame session postmortem; carded the guest/empty-password path, Kerberoast-before-spray,
   RBCD via an existing-SPN user, getST `ldap/` vs `cifs/`, and no-WinRM → smbclient/atexec.
   Evals: `mcp-first`, `endgame-guest-rbcd`, `forest-htb`, `active-htb`, `blackfield-htb`
   (goad-still-works kept). `git init` + `.gitignore` + initial commit.
10. **Refinement #1 (live Endgame run)** — turned a real 48-min run into fixes:
    `scripts/preflight.sh` (tun0 mtu 1200 + clock + verify + null/guest) and MCP
    `kali_preflight`; VPN path-MTU carded across steps.md/kali-docker.md and
    impacket/tickets/netexec Fail→next; latency-aware bulk-LDAP recon (enum.md,
    commands.md); `john`-default in GPU-less VMs (crack.md + ad-auto hashcat-backend
    probe); the real empty-password guest→RBCD path (`getTGT` + `-k -no-pass`, quote
    `'AD$'`); DCSync-grant fallback (`dacledit -rights DCSync -dc-host`, not `-dc-ip`);
    atexec one-command-per-call. New `references/tools/lpe.md` (Local Privilege
    Escalation: SeImpersonate/potato, SeBackup→NTDS) wired into tools/onhost/steps/
    technique-map. MCP: `ad_auto`/`ad_plan` return parsed digests, `kali_exec`
    background + `kali_logs`, `GOTAD_LOOT` env (no LLM in the server). `.refinements/`
    tracked with flag/password/hashes redacted.
