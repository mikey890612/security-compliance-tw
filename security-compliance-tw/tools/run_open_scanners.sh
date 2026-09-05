#!/usr/bin/env bash
# Run open-source scanners (gosec / bandit / semgrep) against fixture trees.
# Findings are success for this workflow — always exit 0 unless the script itself errors.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="testdata/scan-artifacts/open-source/${RUN_ID}"
mkdir -p "$OUT_DIR"
OUT_ABS="${ROOT}/${OUT_DIR}"

echo "Artifact directory: $OUT_DIR"

count_json_findings() {
  local tool="$1"
  local file="$2"
  python3 -c '
import json,sys
tool,path=sys.argv[1],sys.argv[2]
data=json.load(open(path,encoding="utf-8"))
n=0
if tool=="gosec":
  issues=data.get("Issues") or data.get("issues") or []
  n=len(issues) if isinstance(issues,list) else 0
elif tool=="bandit":
  results=data.get("results") or []
  n=len(results) if isinstance(results,list) else 0
elif tool=="semgrep":
  results=data.get("results") or []
  n=len(results) if isinstance(results,list) else 0
print(f"  {tool}: {n} finding(s) -> {path}")
' "$tool" "$file"
}

# --- gosec (Go): must run with cwd=module root; package path from plugin root yields 0 files ---
if command -v gosec >/dev/null 2>&1; then
  echo "Running gosec on testdata/sample-go ..."
  set +e
  ( cd testdata/sample-go && gosec -fmt=json -out="${OUT_ABS}/gosec.json" . )
  set -e
  if [[ -f "$OUT_DIR/gosec.json" ]]; then
    count_json_findings gosec "$OUT_DIR/gosec.json"
  else
    echo "  gosec: ran but no JSON written"
  fi
else
  echo "skip gosec (not on PATH)"
fi

# --- bandit (Python under sample-multi) ---
if command -v bandit >/dev/null 2>&1; then
  echo "Running bandit on testdata/sample-multi ..."
  set +e
  bandit -r -f json -o "$OUT_DIR/bandit.json" testdata/sample-multi
  set -e
  if [[ -f "$OUT_DIR/bandit.json" ]]; then
    count_json_findings bandit "$OUT_DIR/bandit.json"
  else
    echo "  bandit: ran but no JSON written"
  fi
else
  echo "skip bandit (not on PATH)"
fi

# --- semgrep (multi) ---
if command -v semgrep >/dev/null 2>&1; then
  echo "Running semgrep on testdata/sample-go and testdata/sample-multi ..."
  set +e
  semgrep --config=auto --json --output "$OUT_DIR/semgrep.json" \
    testdata/sample-go testdata/sample-multi
  set -e
  if [[ -f "$OUT_DIR/semgrep.json" ]]; then
    count_json_findings semgrep "$OUT_DIR/semgrep.json"
  else
    echo "  semgrep: ran but no JSON written"
  fi
else
  echo "skip semgrep (not on PATH)"
fi

echo "Done. Artifacts under: $OUT_DIR"
exit 0
