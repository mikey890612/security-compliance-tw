#!/usr/bin/env bash
# Task 1 harness: --list and --dry-run with fake HOME.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAIL=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAIL=1; }

FAKE_HOME="$(mktemp -d "${TMPDIR:-/tmp}/a2-install-test.XXXXXX")"
cleanup() { rm -rf "$FAKE_HOME"; }
trap cleanup EXIT

export HOME="$FAKE_HOME"

echo "== Task 1: --list / --dry-run (HOME=${HOME}) =="

# Capture full output first: bash 3.2 + pipefail + grep -q can SIGPIPE the producer.
list_out="$(./install.sh --list)"
if printf '%s\n' "$list_out" | grep -q claude; then
  pass "--list mentions claude"
else
  fail "--list should mention claude"
fi

dry_out="$(./install.sh --dry-run)"
if printf '%s\n' "$dry_out" | grep -q plugin; then
  pass "--dry-run mentions plugin"
else
  fail "--dry-run should mention plugin"
fi

# Dry-run must not write under fake HOME
if [[ -e "${HOME}/.security-compliance-tw" ]]; then
  fail "--dry-run wrote under HOME/.security-compliance-tw"
else
  pass "--dry-run left HOME clean"
fi

if [[ "$FAIL" -ne 0 ]]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
exit 0
