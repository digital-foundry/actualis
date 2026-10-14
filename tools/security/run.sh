#!/bin/sh
# Runs inside the image from tools/security/Dockerfile. /src is the checkout,
# mounted read-only; /out is the only writable mount and receives the reports.
set -eu
OUT=/out
export HOME=/tmp/home
mkdir -p "$HOME" "$OUT"

echo "== bandit (static analysis)"
# B404/B603/B607: actualis shells out only to fixed argv lists (git, open,
# xdg-open), never through a shell. The findings that matter are anything else.
bandit -q -r -f txt -o "$OUT/bandit.txt" -s B404,B603,B607 \
       /src/actualis.py /src/tools /src/tray-go/icons || true
# bandit exits 1 on findings, so its rc says nothing; a missing report does.
cat "$OUT/bandit.txt" 2>/dev/null || echo "bandit FAILED: no report written; not a clean result"

echo "== secrets in git history (trufflehog, gitleaks)"
git config --global --add safe.directory /src
# A scanner that failed to run must not read as a clean result.
# The container has no network, so trufflehog cannot verify anything against a
# provider: a verified-only scan would always print 0 and read as clean. Report the
# unverified candidates instead, outside the same fixture allowlist gitleaks
# uses (trufflehog-exclude.txt mirrors the root .gitleaks.toml's paths).
rc=0
trufflehog git file:///src --no-update --no-verification --json \
  --exclude-paths /src/tools/security/trufflehog-exclude.txt \
  > "$OUT/trufflehog.json" 2> "$OUT/trufflehog.err" || rc=$?
if [ "$rc" -eq 0 ] || [ "$rc" -eq 183 ]; then   # 183: results found (with --fail)
  n=$(grep -c . "$OUT/trufflehog.json" || true)
  if [ "${n:-0}" -gt 0 ]; then
    echo "trufflehog: $n unverified candidates outside fixtures (not verified: no network), see trufflehog.json"
  else
    echo "trufflehog: no candidates outside fixtures (unverified scan: no network)"
  fi
else
  echo "trufflehog FAILED (rc=$rc); not a clean result. stderr:"
  tail -n 20 "$OUT/trufflehog.err" || true
fi
rc=0
gitleaks git /src --config /src/.gitleaks.toml --no-banner --redact --report-path "$OUT/gitleaks.json" \
  > /dev/null 2> "$OUT/gitleaks.err" || rc=$?
case "$rc" in
  0) echo "gitleaks: no leaks" ;;
  1) echo "gitleaks: FINDINGS outside the fixture allowlist, see gitleaks.json" ;;
  *) echo "gitleaks FAILED (rc=$rc); not a clean result. stderr:"
     tail -n 20 "$OUT/gitleaks.err" || true ;;
esac

echo "== transcript fuzzer"
python3 /src/tools/security/fuzz_transcripts.py \
        --iterations "${FUZZ_ITERATIONS:-300}" --out "$OUT/fuzz"
