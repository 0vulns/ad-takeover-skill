# Prompt — generate a refinement report

Paste this to the agent at the end of an authorized-lab run to produce the next
`.refinements/<N>.md`. It documents what actually happened (the real trail, not
the write-up's ideal path) and feeds the skill's improvement loop.

---

Write a refinement report for the run we just finished, as a new file
`.refinements/<N>.md` where `<N>` is the next integer after the highest existing
`.refinements/<n>.md` (start at 1 if none). Do **not** edit older reports.

**Sources — reconstruct from what actually happened, don't re-solve:**
- This chat/session transcript (every command, its output, each retry).
- MCP tool results if the box was driven over MCP (`kali_status`, `kali_exec`,
  `ad_auto`/`ad_plan` digests, `logs_read`).
- On the Kali box: `logs/<dc-ip>/auto/state.json` + `report.txt`, and the
  `hashes/` / `bloodhound/` / `tickets/` artifacts.
- Shell history for the exact invocations.

**Rules of engagement (hard):**
- Authorized lab / CTF / signed RoE only. Public tools only.
- **Redact** the flag, any cracked passwords, and full NT/AES hashes — write
  `REDACTED` / `<REDACTED-NT>`. Never commit secrets. Keep commands, the trail,
  timings, and lessons verbatim otherwise.
- Report the truth, including dead ends and wasted time. The failures are the
  point — they become skill fixes.

**Structure (mirror `.refinements/1.md`):**
1. **Title + briefing** — `# Engagement Briefing — <CHALLENGE> (<domain> / <dc-ip>)`.
   One line of scope (platform, forest/domain, DC, OS), the outcome (what you
   ended with — e.g. DA + NTDS + flag), and **wall-clock time taken**.
2. **Phases** — one `## Phase N — <name> (Step NN)` per stage, tagged with the
   matching kill-chain step id from `references/steps.md`
   (box, recon, unauth, poison, asrep, spray, kerberoast, bloodhound, lateral,
   acl, delegation, adcs, sysvol, laps, mssql, trusts, dcsync, …). For each:
   - the commands run, in ```bash fences, verbatim (with secrets redacted);
   - the results (what you learned, counts, which ports/paths mattered);
   - a **`**Failures here.**`** list using `✗` for what broke and `✓` for what
     worked, each with the one-line cause and the fix/pivot.
3. **Failure ledger** — a table `| Failure | Root cause | Fix |` collecting every
   `✗` across the run.
4. **Leftover state / loot** — mutations left on the DC and how to revert them
   (e.g. `rbcd -action remove`, the `dacledit` `.bak`), where loot/ccaches live,
   and whether the stop condition (DCSync KRBTGT / DA in every in-scope domain)
   was met.
5. **Redaction note** — one line stating flag/password/hashes were redacted per
   RoE.

**Then, a final `## Proposed skill patches` section** — for each `✗`, name the
concrete file to change and the one-line fix, so the report is actionable:
- which tool card (`references/tools/*.md`) needs a `Fail → next` row,
- which step (`references/steps.md`) or `references/commands.md` template,
- whether `scripts/bootstrap.sh` + `docker/Dockerfile` are missing a tool,
- whether `scripts/ad-auto.py` / `mcp/server.py` behavior should change,
- whether `ad-writeups/` needs a new/updated path note.
Skip anything already covered — only list real gaps.

Keep it tight and factual. Save the file and print its path.
