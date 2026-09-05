# 安裝說明

**clone 後執行 `./install.sh`，一次把三支 skill 與知識庫快照裝到本機。**

```bash
git clone https://github.com/mikey890612/security-compliance-tw.git
cd security-compliance-tw
./install.sh
```

腳本會：同步 plugin 快照 → 寫入 root 指標 → 依 `install/targets.tsv` 複製 skill 到各 agent 全域目錄 → 印出驗證結果（並嘗試跑 `validate_kb.py`）。

macOS／Linux，需要 `bash`。`python3` 建議有（缺則跳過知識庫驗證，安裝仍算成功）。

---

## Flags

| Flag | 行為 |
|---|---|
| `--dry-run` | 只印將執行的動作，不寫檔、不備份 |
| `--no-backup` | 覆蓋前不備份既有 plugin／skill |
| `--only a,b` | 只處理列出的 target id（**不**略過 plugin 同步與 root 寫入） |
| `--list` | 印出 manifest（id／enabled／mode／dest）後退出 |
| `-h`, `--help` | 顯示用法 |

範例：

```bash
./install.sh --dry-run
./install.sh --list
./install.sh --only claude,cursor
./install.sh --no-backup
```

---

## 安裝路徑

| 用途 | 路徑 |
|---|---|
| Plugin 快照 | `~/.security-compliance-tw/plugin/` |
| Root 指標檔 | `~/.security-compliance-tw/root`（單行：plugin 絕對路徑） |
| Claude Code skills | `~/.claude/skills/{sec-audit,sec-harden,sec-deliverables}/` |
| Cursor skills | `~/.cursor/skills/{sec-audit,sec-harden,sec-deliverables}/` |
| Agents hub skills | `~/.agents/skills/{sec-audit,sec-harden,sec-deliverables}/` |
| 備份 | `~/.security-compliance-tw/backups/<UTC-timestamp>/` |

Target 清單由 `install/targets.tsv` 驅動；維護者加列見 [`install/README.md`](../../install/README.md)。

---

## 備份

預設在覆蓋前備份：

- 既有 `plugin/` → `~/.security-compliance-tw/backups/<UTC>/plugin/`
- 既有各 agent skill 目錄 → `~/.security-compliance-tw/backups/<UTC>/<target>/<skill>/`

時間戳為 UTC（`YYYYMMDDTHHMMSSZ`）。加上 `--no-backup` 則直接覆蓋、不建立備份目錄。

---

## 知識庫根目錄（ROOT）

三支 skill 讀 `references/` 前會解析 **ROOT**（plugin 根目錄）：

1. 環境變數 `SECURITY_COMPLIANCE_TW_ROOT`（若已設定，**優先**）
2. 否則讀 `~/.security-compliance-tw/root`（install 寫入的單行絕對路徑）
3. 否則 fallback：相對於該 `SKILL.md` 的 `../..`（仍在 clone／plugin 樹內開發時）

CI 或暫時覆寫範例：

```bash
export SECURITY_COMPLIANCE_TW_ROOT="/path/to/security-compliance-tw"
```

知識庫路徑一律為 `{ROOT}/references/…`（例如 `{ROOT}/references/profile.md`）。

---

## Doc-only 代理（不安裝假路徑）

下列 target 在 manifest 中為 `doc-only`：**`install.sh` 不會複製 skill**。

| id | 說明 |
|---|---|
| `cline` | 無穩定全域 skill 對等路徑 |
| `windsurf` | 同上 |
| `copilot` | 同上 |

建議：

- 需要全域 skill（稽核／交付流程）→ 用 **Claude Code** 或 **Cursor**（已由 install 複製）
- 寫程式當下的規則 → 在專案根對 Claude／Cursor 跑 **`sec-harden` 安裝模式**，產出 `.clinerules`、`.windsurfrules`、`.github/copilot-instructions.md` 等；詳見 [sec-harden 使用說明](sec-harden.md)

---

## 驗證 skill 是否可見

安裝結束後腳本會印 `root:` 與各寫入的 `SKILL.md` 路徑。也可手動確認：

```bash
cat ~/.security-compliance-tw/root
ls ~/.claude/skills/sec-audit/SKILL.md \
   ~/.cursor/skills/sec-audit/SKILL.md \
   ~/.agents/skills/sec-audit/SKILL.md
test -f "$(cat ~/.security-compliance-tw/root)/references/profile.md" && echo "ROOT ok"
```

**Claude Code：** 重開 session（或新開專案目錄），確認可觸發 `/sec-audit`、`/sec-harden`、`/sec-deliverables`，或自然语言提到「源碼掃描／附表十」時會載入對應 skill。

**Cursor：** 重開 Cursor（或 Agent／skills 相關面板），確認 `~/.cursor/skills/` 下三支 skill 出現且可被選用。若介面有 Skills 列表，應看到 `sec-audit`、`sec-harden`、`sec-deliverables`。

知識庫完整性（可選）：

```bash
python3 security-compliance-tw/tools/validate_kb.py
```

---

## 疑難排解：plugin 快照過期

Skill 已更新但 agent 仍讀到舊知識庫／舊 SKILL 內容時：

1. 在最新 clone 上重跑 `./install.sh`（預設會覆蓋 `plugin/` 與各 skill 目錄；需要保留舊版時不要加 `--no-backup`）
2. 確認 `cat ~/.security-compliance-tw/root` 指向目前的 `…/.security-compliance-tw/plugin`
3. 若設過 `SECURITY_COMPLIANCE_TW_ROOT`，檢查是否仍指向舊路徑；清掉或改到新 plugin 後重開 agent
4. 重開 Claude Code／Cursor session，避免快取舊 skill 定義

只想更新單一 agent 時可用 `./install.sh --only cursor`（plugin 與 root 仍會同步）。

---

## 進階：手動 symlink（不建議作為主路徑）

一般請用 `./install.sh`。若僅本機開發、且接受相對路徑 fallback，可手動：

```bash
ln -sfn "$PWD/security-compliance-tw/skills/sec-audit"        ~/.claude/skills/sec-audit
ln -sfn "$PWD/security-compliance-tw/skills/sec-harden"       ~/.claude/skills/sec-harden
ln -sfn "$PWD/security-compliance-tw/skills/sec-deliverables" ~/.claude/skills/sec-deliverables
```

此方式**不會**寫入 `~/.security-compliance-tw/root`，也不會同步可攜 plugin 快照；離開 clone 樹或換機後知識庫路徑可能斷裂。正式／可攜安裝請用 `./install.sh`。
