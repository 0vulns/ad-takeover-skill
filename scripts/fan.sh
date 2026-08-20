#!/bin/bash
# Bounded parallel executor. Lab / RoE only.
#
# Runs one shell command per input line, ADTK_FANOUT at a time (default 5).
# This is the codified form of the hand-rolled `t(){...} & wait` fan-out from
# the live runs: per-domain BloodHound, per-domain DCSync, stock-cred spray all
# run concurrently instead of serially — the single biggest wall-clock win on
# multi-domain (GOAD-family) labs.
#
#   printf '%s\n' \
#     "bloodhound-python -c All -d sevenkingdoms.local -u u -p p -ns 192.168.56.10 -o /logs/bh/sk" \
#     "bloodhound-python -c All -d north.sevenkingdoms.local -u u -p p -ns 192.168.56.11 -o /logs/bh/north" \
#     | /opt/adtk/fan.sh
#
#   /opt/adtk/fan.sh cmds.txt              # read commands from a file
#   ADTK_FANOUT=3 /opt/adtk/fan.sh cmds.txt
#
# Each line is run with `bash -lc`. Do NOT fan out lockout-sensitive sprays
# (one bad guess per account across N parallel jobs still counts) — cap first.
set -uo pipefail

N="${ADTK_FANOUT:-5}"
SRC="${1:-/dev/stdin}"

if ! [ "$N" -gt 0 ] 2>/dev/null; then
  echo "[!] ADTK_FANOUT must be a positive integer (got '$N')" >&2
  exit 2
fi

# Skip blank lines and #comments; run the rest N-wide, preserving each line
# verbatim (xargs -I keeps embedded quoting intact for `bash -lc`). The replstr
# @@CMD@@ is deliberately obscure so it never collides with the command text.
grep -vE '^\s*(#|$)' "$SRC" \
  | xargs -I @@CMD@@ -P "$N" bash -lc '@@CMD@@'
