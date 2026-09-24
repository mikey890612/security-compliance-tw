#!/usr/bin/env bash
# Task 1+2 harness: --list/--dry-run plus plugin sync, root, skills, backup.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAIL=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAIL=1; }

FAKE_HOME="$(mktemp -d "${TMPDIR:-/tmp}/a2-install-test.XXXXXX")"
ONLY_HOME=""
MISS_HOME=""
cleanup() { rm -rf "$FAKE_HOME" ${ONLY_HOME:+"$ONLY_HOME"} ${MISS_HOME:+"$MISS_HOME"}; }
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

echo "== Task 2: full install =="

if ./install.sh; then
  pass "full install exit 0"
else
  fail "full install should exit 0"
fi

root_file="${HOME}/.security-compliance-tw/root"
plugin_profile="${HOME}/.security-compliance-tw/plugin/references/profile.md"

if [[ -f "$root_file" ]]; then
  root_val="$(tr -d '\n' <"$root_file")"
  if [[ -d "$root_val" ]]; then
    pass "root pointer exists and targets a directory"
  else
    fail "root pointer does not target a directory: ${root_val}"
  fi
else
  fail "missing root file"
fi

if [[ -f "$plugin_profile" ]]; then
  pass "plugin/references/profile.md present"
else
  fail "missing plugin/references/profile.md"
fi

for agent_base in .claude/skills .cursor/skills .agents/skills; do
  for skill in sec-audit sec-harden sec-deliverables; do
    skill_md="${HOME}/${agent_base}/${skill}/SKILL.md"
    if [[ -f "$skill_md" ]]; then
      pass "skill present: ${agent_base}/${skill}"
    else
      fail "missing skill: ${agent_base}/${skill}/SKILL.md"
    fi
  done
done

echo "== Task 2: second install creates backup =="

before_backups=0
if [[ -d "${HOME}/.security-compliance-tw/backups" ]]; then
  before_backups="$(find "${HOME}/.security-compliance-tw/backups" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
fi

if ./install.sh; then
  pass "second install exit 0"
else
  fail "second install should exit 0"
fi

after_backups=0
if [[ -d "${HOME}/.security-compliance-tw/backups" ]]; then
  after_backups="$(find "${HOME}/.security-compliance-tw/backups" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
fi

if [[ "$after_backups" -gt "$before_backups" ]]; then
  pass "second install created backups/ entry (${before_backups} -> ${after_backups})"
else
  fail "second install should create a new backups/ entry (${before_backups} -> ${after_backups})"
fi

echo "== Task 2: --no-backup does not add backup dir =="

before_nb="$after_backups"
if ./install.sh --no-backup; then
  pass "--no-backup install exit 0"
else
  fail "--no-backup install should exit 0"
fi

after_nb=0
if [[ -d "${HOME}/.security-compliance-tw/backups" ]]; then
  after_nb="$(find "${HOME}/.security-compliance-tw/backups" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
fi

if [[ "$after_nb" -eq "$before_nb" ]]; then
  pass "--no-backup created no new backup dir (${before_nb})"
else
  fail "--no-backup should not add backup dir (${before_nb} -> ${after_nb})"
fi

echo "== Task 2: --only cursor still syncs plugin+root; only cursor skills =="

ONLY_HOME="$(mktemp -d "${TMPDIR:-/tmp}/a2-install-only.XXXXXX")"
if HOME="$ONLY_HOME" ./install.sh --only cursor; then
  pass "--only cursor exit 0"
else
  fail "--only cursor should exit 0"
fi

if [[ -f "${ONLY_HOME}/.security-compliance-tw/root" && -f "${ONLY_HOME}/.security-compliance-tw/plugin/references/profile.md" ]]; then
  pass "--only cursor synced plugin+root"
else
  fail "--only cursor must still sync plugin+root"
fi

for skill in sec-audit sec-harden sec-deliverables; do
  if [[ -f "${ONLY_HOME}/.cursor/skills/${skill}/SKILL.md" ]]; then
    pass "--only cursor installed ${skill}"
  else
    fail "--only cursor missing .cursor/skills/${skill}"
  fi
  if [[ -e "${ONLY_HOME}/.claude/skills/${skill}" ]]; then
    fail "--only cursor should not install .claude/skills/${skill}"
  else
    pass "--only cursor skipped claude ${skill}"
  fi
  if [[ -e "${ONLY_HOME}/.agents/skills/${skill}" ]]; then
    fail "--only cursor should not install .agents/skills/${skill}"
  else
    pass "--only cursor skipped agents-hub ${skill}"
  fi
done

echo "== Task 2: missing source skill -> non-zero =="

MISS_HOME="$(mktemp -d "${TMPDIR:-/tmp}/a2-install-miss.XXXXXX")"
skill_src="${REPO_ROOT}/security-compliance-tw/skills/sec-audit"
skill_bak="${skill_src}.__test_missing__"
mv "$skill_src" "$skill_bak"
set +e
HOME="$MISS_HOME" ./install.sh >/tmp/a2-miss-out.txt 2>&1
miss_rc=$?
set -e
mv "$skill_bak" "$skill_src"

if [[ "$miss_rc" -ne 0 ]]; then
  pass "missing source skill exits non-zero (rc=${miss_rc})"
else
  fail "missing source skill should exit non-zero"
fi

echo "== Update check: install record and --check =="

record="${HOME}/.security-compliance-tw/installed.json"
clone_version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
  "${REPO_ROOT}/security-compliance-tw/.claude-plugin/plugin.json" | head -n 1)"

if [[ -f "$record" ]] && grep -q "\"version\": \"${clone_version}\"" "$record" \
   && grep -q '"checked_at"' "$record"; then
  pass "install wrote installed.json with version ${clone_version}"
else
  fail "installed.json missing or without version/checked_at"
fi

check_out="$(./install.sh --check --offline)"
if printf '%s\n' "$check_out" | grep -q "已是最新（${clone_version}）"; then
  pass "--check reports up to date right after install"
else
  fail "--check should report up to date after install"
fi

# 模擬舊版安裝：快照版本退回 0.0.1、上次檢查是很久以前
sed "s/\"version\": \"${clone_version}\"/\"version\": \"0.0.1\"/" \
  "${HOME}/.security-compliance-tw/plugin/.claude-plugin/plugin.json" >"${record}.plugin.tmp"
mv "${record}.plugin.tmp" "${HOME}/.security-compliance-tw/plugin/.claude-plugin/plugin.json"
sed 's/"checked_at": "[^"]*"/"checked_at": "2000-01-01"/' "$record" >"${record}.tmp"
mv "${record}.tmp" "$record"

PROJ_DIR="$(mktemp -d "${TMPDIR:-/tmp}/a2-install-proj.XXXXXX")"
printf '# own notes\n<!-- BEGIN sec-harden v0.0.1 — x -->\nrules\n<!-- END sec-harden -->\n' >"${PROJ_DIR}/AGENTS.md"

stale_out="$(./install.sh --check --offline "$PROJ_DIR")"
if printf '%s\n' "$stale_out" | grep -q "有新版 ${clone_version}（已安裝 0.0.1）" \
   && printf '%s\n' "$stale_out" | grep -q "## ${clone_version}"; then
  pass "--check reports the newer version and its CHANGELOG section"
else
  fail "--check should list the newer version with its CHANGELOG section"
fi
if printf '%s\n' "$stale_out" | grep -q "AGENTS.md：v0.0.1 → 可更新到 v${clone_version}"; then
  pass "--check flags stale project rule files"
else
  fail "--check should flag the project's stale AGENTS.md"
fi
if grep -q '"checked_at": "2000-01-01"' "$record"; then
  fail "--check should refresh checked_at"
else
  pass "--check refreshed checked_at"
fi
rm -rf "$PROJ_DIR"

set +e
./install.sh /tmp >/dev/null 2>&1
dir_rc=$?
set -e
if [[ "$dir_rc" -ne 0 ]]; then
  pass "directory argument without --check is rejected"
else
  fail "directory argument without --check should be rejected"
fi

if [[ "$FAIL" -ne 0 ]]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
exit 0
