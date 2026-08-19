# AD Challenge Writeups Pack

**Authorized labs / CTF only.** Public educational material for:
HackTheBox AD machines, TryHackMe AD rooms, GOAD (Orange Cyberdefense).

This pack contains **structured attack-path notes and technique maps**, not
verbatim copies of third-party blogs. Follow the linked sources for full
narratives. Practice only on labs you own or are explicitly authorized to
attack (HTB, THM, GOAD homelab, signed RoE).

## Contents

| Path | What |
| --- | --- |
| `INDEX.md` | Master list of machines + techniques |
| `coverage-matrix.md` | Writeups → skill coverage + Endgame postmortem |
| `htb/` | Classic HTB AD box path notes |
| `goad/` | GOAD forest path notes |
| `thm/` | TryHackMe AD room notes |
| `techniques/` | Technique → which boxes use it |
| `SOURCES.md` | Public writeup / repo links |

## How to use with the GOTAD skill

1. Pick a box from `INDEX.md`.
2. Match techniques to cards in the ad-takeover skill (`tools/*.md`).
3. Run `ad-auto.py` / `bh-next.py` against **your** lab, not production.

## Stop condition (every box)

Domain Admin (or Enterprise Admin across trusts) + KRBTGT / NTDS for the
in-scope domain(s). Document the one-line path: foothold → DA → forest.
