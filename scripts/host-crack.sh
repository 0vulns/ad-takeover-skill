#!/bin/bash
# Crack roast hashes on the HOST, not on the Kali VM. Lab / RoE only.
#
# Why: a headless Kali VM/container has no GPU runtime, so hashcat dies and john
# grinds rockyou at CPU speed (.refinements/1.md burned a whole dead-end on it).
# The host (an Apple-Silicon Mac with hashcat's Metal backend, or any box with a
# real GPU) cracks the same hashes far faster. Capture the hash on Kali, pull it
# down (MCP `logs_read` / scp), then run this here while the chain keeps moving.
#
#   # 1. on Kali the hash was written to logs/<dc>/hashes/kerb.txt
#   # 2. pull it to the host (MCP logs_read, or scp), then:
#   ADTK_WORDLIST=~/wordlists/rockyou.txt \
#     scripts/host-crack.sh --mode 13100 --hash ./kerb.txt
#
#   scripts/host-crack.sh --mode 18200 --hash ./asrep.txt --budget 300 --background
#   scripts/host-crack.sh --self-test
#
# Prints `user:pass` for each crack and writes <hash>.cracked (hash:pass).
# Time-boxed by design — hand it back to the chain rather than blocking on a
# hopeless wordlist. It does NOT download rockyou; point --wordlist / ADTK_WORDLIST
# at one (Kali: /usr/share/wordlists/rockyou.txt; brew: after `gunzip` the .gz).
set -uo pipefail

MODE=""
HASHF=""
WORDLIST="${ADTK_WORDLIST:-}"
BUDGET="${ADTK_CRACK_BUDGET:-600}"
BACKGROUND=0
SELFTEST=0

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-2}"
}

john_format() {
  case "$1" in
    18200) echo krb5asrep ;;
    13100) echo krb5tgs ;;
    19600) echo krb5tgs-aes128 ;;
    19700) echo krb5tgs-aes256 ;;
    5600)  echo netntlmv2 ;;
    5500)  echo netntlmv1 ;;
    1000)  echo nt ;;
    *)     echo "" ;;
  esac
}

# Pull the account name out of a roast hash so we print user:pass, not hash:pass.
extract_user() {
  local h="$1"
  case "$h" in
    *'$krb5asrep$'*) sed -E 's/.*\$krb5asrep\$(23\$)?//; s/@.*//' <<<"$h" ;;
    *'$krb5tgs$'*)   sed -E 's/.*\$krb5tgs\$[0-9]+\$\*//; s/\$.*//' <<<"$h" ;;
    *)               cut -d: -f1 <<<"$h" ;;
  esac
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --hash) HASHF="$2"; shift 2 ;;
    --wordlist) WORDLIST="$2"; shift 2 ;;
    --budget) BUDGET="$2"; shift 2 ;;
    --background) BACKGROUND=1; shift ;;
    --self-test) SELFTEST=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "[!] unknown arg: $1" >&2; usage 2 ;;
  esac
done

if [ "$SELFTEST" = "1" ]; then
  fail=0
  [ "$(john_format 18200)" = "krb5asrep" ] || { echo "[!] mode map 18200"; fail=1; }
  [ "$(john_format 13100)" = "krb5tgs" ] || { echo "[!] mode map 13100"; fail=1; }
  u="$(extract_user '$krb5asrep$23$VICTIM@THM.LOCAL:aaaa')"
  [ "$u" = "VICTIM" ] || { echo "[!] asrep user extract got '$u'"; fail=1; }
  u="$(extract_user '$krb5tgs$23$*CODY_ROY$THM.LOCAL$http~server*aaaa')"
  [ "$u" = "CODY_ROY" ] || { echo "[!] tgs user extract got '$u'"; fail=1; }
  [ "$fail" = "0" ] && echo "[self-test] host-crack ok" || exit 1
  exit 0
fi

[ -n "$MODE" ] || { echo "[!] --mode required" >&2; usage 2; }
[ -n "$HASHF" ] || { echo "[!] --hash required" >&2; usage 2; }
[ -f "$HASHF" ] || { echo "[!] hash file not found: $HASHF" >&2; exit 2; }
if ! [ "$BUDGET" -gt 0 ] 2>/dev/null; then echo "[!] --budget must be a positive integer" >&2; exit 2; fi

if [ -z "$WORDLIST" ] || [ ! -f "$WORDLIST" ]; then
  echo "[!] no wordlist. Set --wordlist / ADTK_WORDLIST to a real file." >&2
  echo "    Kali ships /usr/share/wordlists/rockyou.txt (gunzip the .gz once)." >&2
  echo "    macOS: copy rockyou.txt from Kali, or download it once — this" >&2
  echo "    script will not fetch it for you." >&2
  exit 3
fi

# --background: re-exec detached so the agent keeps working the chain.
if [ "$BACKGROUND" = "1" ]; then
  log="${HASHF}.crack.log"
  nohup "$0" --mode "$MODE" --hash "$HASHF" --wordlist "$WORDLIST" --budget "$BUDGET" \
    >"$log" 2>&1 &
  echo "started pid $!"
  echo "log $log"
  echo "[poll] tail -f $log ; results in ${HASHF}.cracked"
  exit 0
fi

OUT="${HASHF}.cracked"
POT="${HASHF}.pot"
: >"$OUT"

emit() {
  # take hash:plain lines, print user:pass, append to $OUT
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    local plain="${line##*:}"
    local hh="${line%:*}"
    local user; user="$(extract_user "$hh")"
    echo "${user}:${plain}"
    echo "${hh}:${plain}" >>"$OUT"
  done
}

cracked_any=0

HC="$(command -v hashcat || true)"
if [ -n "$HC" ]; then
  echo "[*] hashcat ($HC) mode $MODE, budget ${BUDGET}s (Metal/OpenCL if present)"
  "$HC" -m "$MODE" "$HASHF" "$WORDLIST" \
    --potfile-path "$POT" --runtime "$BUDGET" --quiet 2>/dev/null || true
  # Read the potfile directly (hash:plain). `--show --outfile-format` numbering
  # drifts between hashcat builds; the potfile format is stable, and splitting on
  # the LAST colon is correct even for krb hashes (whose hash field has a colon).
  if [ -s "$POT" ]; then
    emit <"$POT"
    cracked_any=1
  fi
fi

if [ "$cracked_any" = "0" ]; then
  JOHN="$(command -v john || true)"
  fmt="$(john_format "$MODE")"
  if [ -n "$JOHN" ] && [ -n "$fmt" ]; then
    echo "[*] john --format=$fmt, --max-run-time=${BUDGET}s (CPU fallback)"
    "$JOHN" "--format=$fmt" "--wordlist=$WORDLIST" "--max-run-time=$BUDGET" "$HASHF" 2>/dev/null || true
    "$JOHN" --show "--format=$fmt" "$HASHF" 2>/dev/null | while IFS= read -r line; do
      case "$line" in
        *:*) plain="$(cut -d: -f2 <<<"$line")"; left="$(cut -d: -f1 <<<"$line")"
             [ -n "$plain" ] || continue
             user="${left##*\$}"; user="${user%%@*}"
             echo "${user}:${plain}"
             echo "${line}" >>"$OUT" ;;
      esac
    done
  elif [ -z "$HC" ]; then
    echo "[!] neither hashcat nor john on the host — install one (brew install hashcat john-jumbo)" >&2
    exit 4
  fi
fi

if [ -s "$OUT" ]; then
  echo "[+] results in $OUT"
else
  echo "[*] nothing cracked in ${BUDGET}s — keep the hash, move on (BloodHound / ACL / ADCS)"
fi
