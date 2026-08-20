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
   the top of SKILL.md, mirrored in `references/mcp.md` + README (transport env, SSH copy-to-`/opt/adtk`,
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
    background + `kali_logs`, `ADTK_LOGS` env (no LLM in the server). `.refinements/`
    tracked with flag/password/hashes redacted.
11. **De-brand + open-source polish** — MIT `LICENSE` (authorized-use notice) and
    `CONTRIBUTING.md`; rewrote README for newcomers (disclaimer, features, Docker/SSH
    quickstart, MCP + env table, how-it-works, layout). Renamed the `gotad` brand to
    **`adtk`** everywhere (env `ADTK_*`, `/opt/adtk`, container/compose `adtk-kali`).
12. **Per-target logs + config templates + better MCP** — `loot/` → `logs/<dc-ip>/`
    so runs against different DCs never mix (`ad-auto.py` rebinds its tree from `--dc`;
    `--resume` reuses the newest). `conf/*` are now `*.example` templates (live copies
    the agent writes per lab are git-ignored). MCP transport **auto-detects** (Docker if
    the container is up, else SSH) and tracks the current target from the DC IP, so
    `logs_ls`/`logs_read`/`logs_write` (renamed from `loot_*`), `bh_next`, digests, and
    background logs all resolve under `logs/<dc-ip>/`.
13. **Dropped the MCP `i_am_authorized` gate** — tools run without a per-call
    authorization flag (point the server at a lab you own / have RoE for). The
    underlying `ad-auto.py` / `mssql-hop.py` still receive `--i-am-authorized`
    automatically. Docs + self-test updated; the mcp.md tool table now marks which
    tools mutate rather than which need auth.
14. **Refinement #2 (GOAD-on-Ludus live run)** — SSH Kali over OpenVPN, ~2h35m
    to DA/EA + krbtgt ×3. Turned every failure into a pack fix: current Kali
    package names (`freerdp-x11` / `ntpsec-ntpdate`); no `kali-linux-headless`
    on SSH boxes (it restarts networking); Impacket `impacket-*` aliases in
    verify; `ADTK_LOGS=~/logs` fallback + MCP export; MCP host ~30s cap →
    `ad_auto` / `kali_bootstrap` always detach, `kali_exec` auto-detaches
    nmap/bloodhound/secretsdump and mkdir's `-oN` parents; empty BH zips fall
    back to loose JSON; nxc `--add-member` / `group-mem` / `--timeroasting`
    gone → bloodyAD / `--groups` / skip; DCSync `NOT_UNIQUE` → NetBIOS
    `SEVENKINGDOMS/krbtgt`; quoted-heredoc for `$`/`!` passwords; impacket 0.14
    dropped `-windows-auth`; WinRM + GUI-subsystem session-0 Fail→next;
    `ADTK_SUDO_PASS` for stock Kali; VMware Fusion recovery (stale `*.vmx.lck`,
    never `vmrun start` under a short timeout). New `ad-writeups/goad/goad-ludus.md`.
    Trail: `.refinements/2.md`.
15. **Time optimization** — both live runs ran >45 min, most of it avoidable.
    Three levers, kept out of the serial decision loop: (a) parallel fan-out
    helpers — `scripts/fan.sh` (bounded `xargs -P` executor) plus
    `scripts/spray-stock.sh` + `conf/creds.goad.example` for a stock-cred fast
    path (`.refinements/2.md` got 21/23 valid in ~1 min before recon); (b)
    host-offloaded cracking — `scripts/host-crack.sh` (hashcat Metal/GPU, john
    fallback, time-boxed, `--background`) because the Kali VM has no GPU, and
    `ad-auto.py` `crack()` now caps its on-box rockyou pass at
    `ADTK_CRACK_BUDGET` (90s) and prints the host-offload in `next_manual`
    instead of blocking; (c) stock-first ordering — `decide()` sprays before
    AS-REP on `--profile goad`, and `act_spray` runs the documented stock creds
    up front. Doctrine added to `steps.md` ("Go fast" + per-phase budget +
    stop-at-proof), `commands.md`, `mcp.md`, `crack.md`, `SKILL.md`, `README.md`.
