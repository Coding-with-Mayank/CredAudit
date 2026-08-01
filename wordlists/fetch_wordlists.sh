#!/usr/bin/env bash
# Pulls real, professional-grade wordlists from SecLists
# (https://github.com/danielmiessler/SecLists) -- maintained under OWASP,
# this is the wordlist collection actually used by working pentesters and
# bug bounty hunters. We don't bundle these in the repo (some tiers run
# tens of megabytes); this script fetches only the tier you ask for.
# Every path below was verified against the live repo before being
# hardcoded here.
#
# Usage:
#   ./fetch_wordlists.sh quick       # ~200 passwords -- fast smoke test
#   ./fetch_wordlists.sh standard    # 10k passwords -- good default
#   ./fetch_wordlists.sh thorough    # 100k passwords
#   ./fetch_wordlists.sh deep        # 1,000,000 passwords (~8.7 MB)
#   ./fetch_wordlists.sh ncsc        # 100k passwords, UK NCSC breach list
#   ./fetch_wordlists.sh usernames   # common username shortlist
#   ./fetch_wordlists.sh all         # fetch every tier above

set -euo pipefail
BASE="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fetch() {
  local path="$1" out="$2"
  echo "Fetching $path ..."
  curl -fsSL "$BASE/$path" -o "$OUT_DIR/$out"
  echo "  -> $OUT_DIR/$out ($(wc -l < "$OUT_DIR/$out") lines)"
}

tier="${1:-standard}"

case "$tier" in
  quick)
    fetch "Passwords/Common-Credentials/2025-199_most_used_passwords.txt" "passwords-quick.txt"
    ;;
  standard)
    fetch "Passwords/Common-Credentials/10k-most-common.txt" "passwords-standard.txt"
    ;;
  thorough)
    fetch "Passwords/Common-Credentials/Pwdb_top-100000.txt" "passwords-thorough.txt"
    ;;
  deep)
    fetch "Passwords/Common-Credentials/Pwdb_top-1000000.txt" "passwords-deep.txt"
    ;;
  ncsc)
    fetch "Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt" "passwords-ncsc.txt"
    ;;
  usernames)
    fetch "Usernames/top-usernames-shortlist.txt" "usernames-common.txt"
    ;;
  all)
    "${BASH_SOURCE[0]}" quick
    "${BASH_SOURCE[0]}" standard
    "${BASH_SOURCE[0]}" thorough
    "${BASH_SOURCE[0]}" ncsc
    "${BASH_SOURCE[0]}" usernames
    ;;
  *)
    echo "Unknown tier: $tier"
    echo "Choices: quick, standard, thorough, deep, ncsc, usernames, all"
    exit 1
    ;;
esac
