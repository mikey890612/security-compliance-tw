#!/usr/bin/env bash
# Manifest-driven local agent skills installer (Task 1 skeleton).
# Full plugin sync / skill copy lands in Task 2; dry-run is log-only.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_TSV="${REPO_ROOT}/install/targets.tsv"
SKILLS=(sec-audit sec-harden sec-deliverables)

DRY_RUN=0
NO_BACKUP=0
LIST_ONLY=0
ONLY_FILTER=""

usage() {
  cat <<'USAGE'
Usage: ./install.sh [options]

Options:
  --dry-run      Print planned actions; do not write files
  --no-backup    Skip backups before overwrite (Task 2)
  --only a,b     Only process listed target ids (Task 2)
  --list         Print manifest rows and exit
  -h, --help     Show this help

Skills: sec-audit, sec-harden, sec-deliverables
Manifest: install/targets.tsv
USAGE
}

expand_path() {
  # Expand leading ~ to $HOME and optional {skill} placeholder.
  local path="$1"
  local skill="${2:-}"
  if [[ "$path" == "~"* ]]; then
    path="${HOME}${path:1}"
  fi
  if [[ -n "$skill" ]]; then
    path="${path//\{skill\}/${skill}}"
  fi
  printf '%s\n' "$path"
}

# Populate global arrays TARGET_IDS / TARGET_ENABLED / TARGET_MODE / TARGET_DEST
load_targets() {
  TARGET_IDS=()
  TARGET_ENABLED=()
  TARGET_MODE=()
  TARGET_DEST=()

  if [[ ! -f "$TARGETS_TSV" ]]; then
    echo "error: missing manifest: $TARGETS_TSV" >&2
    return 1
  fi

  local line id enabled mode dest
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    IFS=$'\t' read -r id enabled mode dest <<<"$line"
    [[ -z "${id:-}" ]] && continue
    TARGET_IDS+=("$id")
    TARGET_ENABLED+=("${enabled:-0}")
    TARGET_MODE+=("${mode:-}")
    TARGET_DEST+=("${dest:-}")
  done <"$TARGETS_TSV"
}

list_targets() {
  load_targets
  printf '%s\t%s\t%s\t%s\n' "id" "enabled" "mode" "dest_template"
  local i
  for i in "${!TARGET_IDS[@]}"; do
    printf '%s\t%s\t%s\t%s\n' \
      "${TARGET_IDS[$i]}" \
      "${TARGET_ENABLED[$i]}" \
      "${TARGET_MODE[$i]}" \
      "${TARGET_DEST[$i]}"
  done
}

should_process_target() {
  local id="$1"
  if [[ -z "$ONLY_FILTER" ]]; then
    return 0
  fi
  local part
  IFS=',' read -ra parts <<<"$ONLY_FILTER"
  for part in "${parts[@]}"; do
    [[ "$part" == "$id" ]] && return 0
  done
  return 1
}

dry_run_plan() {
  load_targets

  local plugin_src="${REPO_ROOT}/security-compliance-tw"
  local plugin_dest="${HOME}/.security-compliance-tw/plugin"
  local root_file="${HOME}/.security-compliance-tw/root"

  echo "[dry-run] would sync plugin: ${plugin_src}/ -> ${plugin_dest}/"
  if [[ "$NO_BACKUP" -eq 0 ]]; then
    echo "[dry-run] would backup existing plugin (if any) under ${HOME}/.security-compliance-tw/backups/<UTC>/"
  else
    echo "[dry-run] --no-backup: skip plugin backup"
  fi
  echo "[dry-run] would write root pointer: ${root_file} -> ${plugin_dest}"

  local i id enabled mode dest skill expanded
  for i in "${!TARGET_IDS[@]}"; do
    id="${TARGET_IDS[$i]}"
    enabled="${TARGET_ENABLED[$i]}"
    mode="${TARGET_MODE[$i]}"
    dest="${TARGET_DEST[$i]}"

    if [[ "$enabled" != "1" ]]; then
      echo "[dry-run] skip disabled target: ${id}"
      continue
    fi
    if ! should_process_target "$id"; then
      echo "[dry-run] skip (not in --only): ${id}"
      continue
    fi

    if [[ "$mode" == "doc-only" ]]; then
      echo "[dry-run] doc-only target ${id}: no copy; see docs/usage/install.md"
      continue
    fi

    if [[ "$mode" != "skill-dir" ]]; then
      echo "[dry-run] unknown mode for ${id}: ${mode}" >&2
      continue
    fi

    for skill in "${SKILLS[@]}"; do
      expanded="$(expand_path "$dest" "$skill")"
      echo "[dry-run] would copy skill ${skill} -> ${expanded}"
    done
  done
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --no-backup)
        NO_BACKUP=1
        shift
        ;;
      --only)
        if [[ $# -lt 2 ]]; then
          echo "error: --only requires a comma-separated list" >&2
          usage >&2
          exit 2
        fi
        ONLY_FILTER="$2"
        shift 2
        ;;
      --only=*)
        ONLY_FILTER="${1#--only=}"
        shift
        ;;
      --list)
        LIST_ONLY=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "error: unknown option: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
  done
}

main() {
  parse_args "$@"

  if [[ "$LIST_ONLY" -eq 1 ]]; then
    list_targets
    exit 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    dry_run_plan
    exit 0
  fi

  # Task 2 will implement real sync/copy. Skeleton refuses real writes.
  echo "error: real install not implemented yet (Task 2). Use --dry-run or --list." >&2
  exit 1
}

main "$@"
