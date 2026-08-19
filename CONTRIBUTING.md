# Contributing

Thanks for helping improve the AD takeover skill. A few conventions keep it
tight and safe.

## Scope and safety (non-negotiable)

- **Authorized labs / CTFs / signed RoE only.** No content that targets
  production or non-consenting systems.
- **Public tools only.** No malware, 0-days, ransomware, mass password resets,
  or bundled C2/crypters. Everything must be reproducible with public,
  documented tooling.
- **No secrets in the repo.** Redact flags, cracked passwords, and full hashes
  in any notes or write-ups. `loot/`, `.env`, ccaches, and hashes are
  git-ignored — keep it that way.
- Write-ups are **structured path notes + source links**, not pasted
  third-party blogs.

## Tool cards (`references/tools/*.md`)

Cards are for a senior operator. Keep them scannable:

- Sections: **When / not**, **Flags that matter**, **Read this**,
  **Fail → next**, **Chain**.
- Prefer a `Fail → next` row and one interpolated command
  (`{{DC}} {{DOMAIN}} {{USER}} {{PASS}}`) over prose.
- Open **one** card per question; don't dump the whole rack.

## Adding a tool

If a binary is missing after bootstrap, add it to **both**
`scripts/bootstrap.sh` **and** `docker/Dockerfile`. Never `apt`/`pip` ad-hoc
inside the kill chain.

## Tests

Keep these green before opening a PR:

```bash
python3 scripts/ad-auto.py --self-test
python3 mcp/server.py --self-test
bash -n scripts/*.sh
```

If you touch a parser in `ad-auto.py`, extend the self-test fixtures. If you
change behavior the agent relies on, add or update a case in
`evals/evals.json`.

## Docs stay in sync

`SKILL.md` is the entrypoint. The MCP-first loop must match across
`SKILL.md`, `references/mcp.md`, and `README.md`. Update `HISTORY.md` with a
one-line summary of the change.
