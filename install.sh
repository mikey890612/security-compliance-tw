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
CHECK_ONLY=0
OFFLINE=0
CHECK_PROJECT=""
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
  --check [dir]  Compare installed / local clone / GitHub versions and print
                 what changed; with dir, also check that project's sec-harden
                 rule files. Does not install anything.
  --offline      With --check: skip the GitHub comparison
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

# ── 版本與更新檢查 ────────────────────────────────────────────────
# 版本號只有一個來源：plugin.json 的 "version"。不依賴 python／jq。

read_version() {
  # 從 plugin.json 取出 version；參數省略時讀 stdin
  sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' \
    "${1:-/dev/stdin}" | head -n 1
}

version_gt() {
  # $1 是否比 $2 新（X.Y.Z）
  local IFS=.
  local -a a=($1) b=($2)
  local i
  for i in 0 1 2; do
    if (( ${a[i]:-0} > ${b[i]:-0} )); then return 0; fi
    if (( ${a[i]:-0} < ${b[i]:-0} )); then return 1; fi
  done
  return 1
}

json_escape() {
  local s="${1//\\/\\\\}"
  printf '%s' "${s//\"/\\\"}"
}

write_install_record() {
  # checked_at：最後一次安裝或 --check 的日期；skill 用它決定要不要提醒檢查更新
  local state_dir="${HOME}/.security-compliance-tw"
  local version commit="" today
  version="$(read_version "${REPO_ROOT}/security-compliance-tw/.claude-plugin/plugin.json")"
  today="$(date -u +%Y-%m-%d)"
  if command -v git >/dev/null 2>&1; then
    commit="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || true)"
  fi
  cat >"${state_dir}/installed.json" <<EOF
{
  "version": "${version}",
  "installed_at": "${today}",
  "checked_at": "${today}",
  "source": "$(json_escape "$(abspath "$REPO_ROOT")")",
  "commit": "${commit}"
}
EOF
  echo "installed version ${version}${commit:+ (${commit})} — run ./install.sh --check later to see if a newer version exists"
}

touch_checked_at() {
  local record="${HOME}/.security-compliance-tw/installed.json"
  [[ -f "$record" ]] || return 0
  local today tmp
  today="$(date -u +%Y-%m-%d)"
  tmp="${record}.tmp"
  sed "s/\"checked_at\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"checked_at\": \"${today}\"/" "$record" >"$tmp"
  mv "$tmp" "$record"
}

print_changelog_between() {
  # 印出 CHANGELOG 中 (lo, hi] 之間各版的段落
  local lo="$1" hi="$2"
  awk -v lo="$lo" -v hi="$hi" '
    function key(v,  p) { split(v, p, "."); return p[1] * 1000000 + p[2] * 1000 + p[3] }
    /^## [0-9]+\.[0-9]+\.[0-9]+/ {
      match($2, /^[0-9]+\.[0-9]+\.[0-9]+/)
      v = substr($2, RSTART, RLENGTH)
      show = (key(v) > key(lo) && key(v) <= key(hi))
    }
    /^## / && !/^## [0-9]/ { show = 0 }
    show { print "  " $0 }
  '
}

check_project() {
  local dir="$1" target="$2"
  local f found=0 v
  if [[ ! -d "$dir" ]]; then
    echo "error: project directory not found: $dir" >&2
    return 1
  fi
  echo
  echo "專案規則檔（${dir}）："
  for f in "$dir"/AGENTS.md "$dir"/.clinerules "$dir"/.windsurfrules \
           "$dir"/.github/copilot-instructions.md "$dir"/.cursor/rules/sec-harden-*.mdc; do
    [[ -f "$f" ]] || continue
    v="$(grep -o 'sec-harden v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*' "$f" | head -n 1 | sed 's/sec-harden v//' || true)"
    [[ -n "$v" ]] || continue
    found=1
    if [[ -n "$target" ]] && version_gt "$target" "$v"; then
      echo "  ${f#"$dir"/}：v${v} → 可更新到 v${target}（plugin 更新後，在專案裡重跑 sec-harden 安裝）"
    else
      echo "  ${f#"$dir"/}：v${v}"
    fi
  done
  if [[ "$found" -eq 0 ]]; then
    echo "  沒有找到 sec-harden 產生的規則檔"
  fi
}

check_updates() {
  local state_dir="${HOME}/.security-compliance-tw"
  local plugin_rel="security-compliance-tw"
  local installed="" installed_at="" clone latest ref="" remote="" changelog
  clone="$(read_version "${REPO_ROOT}/${plugin_rel}/.claude-plugin/plugin.json")"
  changelog="${REPO_ROOT}/${plugin_rel}/CHANGELOG.md"
  if [[ -f "${state_dir}/plugin/.claude-plugin/plugin.json" ]]; then
    installed="$(read_version "${state_dir}/plugin/.claude-plugin/plugin.json")"
  fi
  if [[ -f "${state_dir}/installed.json" ]]; then
    installed_at="$(sed -n 's/.*"installed_at"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${state_dir}/installed.json" | head -n 1)"
  fi

  echo "已安裝：${installed:-（尚未安裝）}${installed_at:+（${installed_at} 安裝）}"
  echo "本機 clone：${clone}"

  latest="$clone"
  local changelog_text
  changelog_text="$(cat "$changelog" 2>/dev/null || true)"
  if [[ "$OFFLINE" -eq 1 ]]; then
    echo "GitHub：略過（--offline）"
  elif command -v git >/dev/null 2>&1 && GIT_TERMINAL_PROMPT=0 git -C "$REPO_ROOT" fetch --quiet origin 2>/dev/null; then
    ref="$(git -C "$REPO_ROOT" symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || echo origin/main)"
    remote="$(git -C "$REPO_ROOT" show "${ref}:${plugin_rel}/.claude-plugin/plugin.json" 2>/dev/null | read_version || true)"
    echo "GitHub（${ref}）：${remote:-（讀不到版本）}"
    if [[ -n "$remote" ]] && version_gt "$remote" "$latest"; then
      latest="$remote"
      changelog_text="$(git -C "$REPO_ROOT" show "${ref}:${plugin_rel}/CHANGELOG.md" 2>/dev/null || printf '%s' "$changelog_text")"
    fi
  else
    echo "GitHub：無法連線，略過（本機 clone 可能不是最新）"
  fi

  echo
  if [[ -z "$installed" ]]; then
    echo "尚未安裝：執行 ./install.sh"
  elif version_gt "$latest" "$installed"; then
    echo "有新版 ${latest}（已安裝 ${installed}）。各版變更："
    printf '%s\n' "$changelog_text" | print_changelog_between "$installed" "$latest"
    echo
    if version_gt "$latest" "$clone"; then
      echo "更新：git pull && ./install.sh"
    else
      echo "更新：./install.sh"
    fi
  else
    echo "已是最新（${installed}）"
  fi

  if [[ -n "$CHECK_PROJECT" ]]; then
    check_project "$CHECK_PROJECT" "$latest"
  fi
  touch_checked_at
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
  write_install_record
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
      --check)
        CHECK_ONLY=1
        shift
        ;;
      --offline)
        OFFLINE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      -*)
        echo "error: unknown option: $1" >&2
        usage >&2
        exit 2
        ;;
      *)
        if [[ -n "$CHECK_PROJECT" ]]; then
          echo "error: only one project directory is allowed" >&2
          exit 2
        fi
        CHECK_PROJECT="$1"
        shift
        ;;
    esac
  done
  if [[ -n "$CHECK_PROJECT" && "$CHECK_ONLY" -eq 0 ]]; then
    echo "error: a directory argument is only valid with --check" >&2
    usage >&2
    exit 2
  fi
}

main() {
  parse_args "$@"

  if [[ "$LIST_ONLY" -eq 1 ]]; then
    list_targets
    exit 0
  fi

  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    check_updates
    exit 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    dry_run_plan
    exit 0
  fi

  do_install
}

main "$@"
