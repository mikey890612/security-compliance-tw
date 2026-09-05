#!/usr/bin/env bash
# Manifest-driven local agent skills installer.
# Syncs plugin snapshot, writes root pointer, copies skills to agent dirs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_TSV="${REPO_ROOT}/install/targets.tsv"
SKILLS=(sec-audit sec-harden sec-deliverables)

DRY_RUN=0
NO_BACKUP=0
LIST_ONLY=0
ONLY_FILTER=""
BACKUP_TS=""
BACKUP_ROOT=""

usage() {
  cat <<'USAGE'
Usage: ./install.sh [options]

Options:
  --dry-run      Print planned actions; do not write files
  --no-backup    Skip backups before overwrite
  --only a,b     Only process listed target ids (plugin sync always runs)
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
  local IFS=','
  # shellcheck disable=SC2086
  set -- $ONLY_FILTER
  for part in "$@"; do
    [[ -z "$part" ]] && continue
    [[ "$part" == "$id" ]] && return 0
  done
  return 1
}

ensure_backup_root() {
  if [[ -z "$BACKUP_TS" ]]; then
    BACKUP_TS="$(date -u +%Y%m%dT%H%M%SZ)"
    BACKUP_ROOT="${HOME}/.security-compliance-tw/backups/${BACKUP_TS}"
  fi
}

abspath() {
  # Portable absolute path (macOS/Linux); requires path to exist.
  local target="$1"
  if [[ -d "$target" ]]; then
    (cd "$target" && pwd -P)
  elif [[ -e "$target" ]]; then
    local dir base
    dir="$(cd "$(dirname "$target")" && pwd -P)"
    base="$(basename "$target")"
    printf '%s/%s\n' "$dir" "$base"
  else
    echo "error: path does not exist for abspath: $target" >&2
    return 1
  fi
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

    if [[ -z "$dest" ]]; then
      echo "error: skill-dir target ${id} has empty dest_template" >&2
      return 1
    fi

    for skill in "${SKILLS[@]}"; do
      expanded="$(expand_path "$dest" "$skill")"
      if [[ -z "$expanded" ]]; then
        echo "error: skill-dir target ${id} expanded to empty path for ${skill}" >&2
        return 1
      fi
      echo "[dry-run] would copy skill ${skill} -> ${expanded}"
    done
  done
}

sync_plugin() {
  local plugin_src="${REPO_ROOT}/security-compliance-tw"
  local plugin_dest="${HOME}/.security-compliance-tw/plugin"
  local state_dir="${HOME}/.security-compliance-tw"

  if [[ ! -d "$plugin_src" ]]; then
    echo "error: missing plugin source: $plugin_src" >&2
    return 1
  fi

  mkdir -p "$state_dir"

  if [[ -e "$plugin_dest" ]]; then
    if [[ "$NO_BACKUP" -eq 0 ]]; then
      ensure_backup_root
      mkdir -p "$BACKUP_ROOT"
      if [[ -e "${BACKUP_ROOT}/plugin" ]]; then
        rm -rf "${BACKUP_ROOT}/plugin"
      fi
      mv "$plugin_dest" "${BACKUP_ROOT}/plugin"
      echo "backed up plugin -> ${BACKUP_ROOT}/plugin"
    else
      rm -rf "$plugin_dest"
    fi
  fi

  cp -R "$plugin_src" "$plugin_dest"
  echo "synced plugin: ${plugin_src}/ -> ${plugin_dest}/"
}

write_root_pointer() {
  local plugin_dest="${HOME}/.security-compliance-tw/plugin"
  local root_file="${HOME}/.security-compliance-tw/root"
  local plugin_abs

  plugin_abs="$(abspath "$plugin_dest")"
  printf '%s\n' "$plugin_abs" >"$root_file"
  echo "wrote root pointer: ${root_file} -> ${plugin_abs}"
}

backup_path_if_needed() {
  local src="$1"
  local rel_under_backup="$2"

  if [[ ! -e "$src" ]]; then
    return 0
  fi
  if [[ "$NO_BACKUP" -eq 1 ]]; then
    return 0
  fi

  ensure_backup_root
  local dest="${BACKUP_ROOT}/${rel_under_backup}"
  mkdir -p "$(dirname "$dest")"
  if [[ -e "$dest" ]]; then
    rm -rf "$dest"
  fi
  mv "$src" "$dest"
  echo "backed up ${src} -> ${dest}"
}

install_skills() {
  load_targets

  local plugin_src="${REPO_ROOT}/security-compliance-tw"
  local i id enabled mode dest skill expanded skill_src parent
  local -a doc_only_ids=()
  local -a written_skills=()

  for skill in "${SKILLS[@]}"; do
    skill_src="${plugin_src}/skills/${skill}"
    if [[ ! -d "$skill_src" ]]; then
      echo "error: missing source skill directory: $skill_src" >&2
      return 1
    fi
    if [[ ! -f "${skill_src}/SKILL.md" ]]; then
      echo "error: missing source SKILL.md: ${skill_src}/SKILL.md" >&2
      return 1
    fi
  done

  for i in "${!TARGET_IDS[@]}"; do
    id="${TARGET_IDS[$i]}"
    enabled="${TARGET_ENABLED[$i]}"
    mode="${TARGET_MODE[$i]}"
    dest="${TARGET_DEST[$i]}"

    if [[ "$enabled" != "1" ]]; then
      echo "skip disabled target: ${id}"
      continue
    fi

    if [[ "$mode" == "doc-only" ]]; then
      if should_process_target "$id"; then
        doc_only_ids+=("$id")
      fi
      continue
    fi

    if ! should_process_target "$id"; then
      echo "skip (not in --only): ${id}"
      continue
    fi

    if [[ "$mode" != "skill-dir" ]]; then
      echo "error: unknown mode for ${id}: ${mode}" >&2
      return 1
    fi

    if [[ -z "$dest" ]]; then
      echo "error: skill-dir target ${id} has empty dest_template" >&2
      return 1
    fi

    for skill in "${SKILLS[@]}"; do
      expanded="$(expand_path "$dest" "$skill")"
      if [[ -z "$expanded" ]]; then
        echo "error: skill-dir target ${id} expanded to empty path for ${skill}" >&2
        return 1
      fi

      skill_src="${plugin_src}/skills/${skill}"
      backup_path_if_needed "$expanded" "${id}/${skill}"

      if [[ -e "$expanded" ]]; then
        rm -rf "$expanded"
      fi

      parent="$(dirname "$expanded")"
      mkdir -p "$parent"
      cp -R "$skill_src" "$expanded"
      echo "copied skill ${skill} -> ${expanded}"
      written_skills+=("${expanded}/SKILL.md")
    done
  done

  if [[ ${#doc_only_ids[@]} -gt 0 ]]; then
    echo "doc-only targets (no copy): ${doc_only_ids[*]}"
    echo "  see docs/usage/install.md for Cline / Windsurf / Copilot guidance"
  fi

  echo "--- verify ---"
  local root_file="${HOME}/.security-compliance-tw/root"
  if [[ -f "$root_file" ]]; then
    echo "root: $(tr -d '\n' <"$root_file")"
  fi

  local skill_md
  for skill_md in "${written_skills[@]+"${written_skills[@]}"}"; do
    if [[ -f "$skill_md" ]]; then
      echo "ok: ${skill_md}"
    else
      echo "error: expected SKILL.md missing after copy: ${skill_md}" >&2
      return 1
    fi
  done
}

run_validate_kb() {
  local script="${REPO_ROOT}/security-compliance-tw/tools/validate_kb.py"
  if ! command -v python3 >/dev/null 2>&1; then
    echo "warning: python3 not found; skipping validate_kb.py" >&2
    return 0
  fi
  if [[ ! -f "$script" ]]; then
    echo "warning: validate_kb.py not found; skipping" >&2
    return 0
  fi
  if python3 "$script"; then
    echo "validate_kb.py: ok"
  else
    echo "warning: validate_kb.py reported issues (install still considered successful)" >&2
  fi
}

do_install() {
  sync_plugin
  write_root_pointer
  install_skills
  run_validate_kb
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

  do_install
}

main "$@"
