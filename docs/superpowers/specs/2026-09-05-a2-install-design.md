# A2：本機 agent skills 一鍵安裝 — 設計規格

日期：2026-09-05
狀態：§1–§4 已核准；§5.3 references 路徑改採 Fix A（已核准）；待使用者 re-review 本檔後進入 writing-plans
專案：`security_skill_creator` / `security-compliance-tw`
相關 GitHub：https://github.com/mikey890612/security-compliance-tw

---

## 0. 子專案地圖（脈絡）

| ID | 內容 |
|---|---|
| A1 | 掃描器規則名可信度（已完成並併入 main） |
| **A2（本規格）** | 本機全域 agent skills 一鍵安裝 |
| A3 | validate_kb CI、CHANGELOG、release tag |
| A4 | 搜尋 regex／golden test 等（可選） |
| B1–B4 | 行動裝置資安指引模組（獨立） |

建議順序：A1 → **A2** → A3，再進 B1。

---

## 1. 背景與問題

目前 README「安裝」只有三條 Claude Code `ln -sfn`，沒有腳本；Cursor／其他工具的安裝體驗不一致。使用者要的是：**clone 後一條指令**，把 `sec-audit`／`sec-harden`／`sec-deliverables` **複製**到本機各 agent 的**全域** skill 目錄（可攜、可離線），重跑可整包覆蓋並可選備份。

不安裝掃描器；不對業務 repo 跑 sec-harden。

---

## 2. 目標與非目標

### 目標

- 提供 repo 根目錄 `install.sh` + 可維護的 targets manifest
- 將三支 skill **整夾複製**到 Claude／Cursor／agents-hub 全域目錄
- 重跑預設覆蓋；預設先備份既有目錄
- 文件清楚列出路徑、flags、限制與驗收方式
- Cline／Windsurf／Copilot：誠實標為無穩定全域 skill 對等路徑（doc-only）

### 非目標

- 不安裝 gosec／bandit／semgrep（屬驗證工具，非本輪）
- 不對目標業務專案執行 sec-harden 規則寫入
- Windows 非一等公民（文件可提及；腳本以 macOS／Linux 為準）
- 不做 A3（CI／CHANGELOG／自動更新）
- 不改知識庫 check 內容或 A1 狀態模型

### 成功標準

1. 新 clone 後執行一條 `./install.sh`（或文件指定的等價指令）
2. 三個 `skill-dir` target 下各出現三支 skill 的 `SKILL.md`
3. `validate_kb.py` 仍通過
4. `--dry-run`／`--list`／`--only`／`--no-backup` 行為符合 §4
5. 重跑產生 backup（除非 `--no-backup`）

---

## 3. 架構總覽

```
repo root
├── install.sh                 # 同步 plugin 快照、寫 root、讀 manifest、備份、複製 skill、驗證
├── install/
│   ├── README.md              # 維護者：如何加 target
│   └── targets.tsv            # 無 yq 依賴的簡單 manifest
├── security-compliance-tw/    # 來源 plugin（skills + references + tools …）
└── docs/usage/install.md

~/.security-compliance-tw/
├── root                       # 一行：plugin 絕對路徑
├── plugin/                    # security-compliance-tw/ 的可攜快照
└── backups/<timestamp>/…
```

`install.sh` **不**把 agent dest 寫死在業務邏輯中（來自 manifest）。  
Skill 來源：`security-compliance-tw/skills/<name>/`。  
知識庫來源：`SECURITY_COMPLIANCE_TW_ROOT` 或 `~/.security-compliance-tw/root` 指向的 plugin 樹。

---

## 4. §1 已確認摘要

- 成功定義：本機一鍵裝 agent skills（非掃描器）
- 涵蓋意圖：Claude、Cursor、Cline／Windsurf／Copilot（後三者以文件誠實說明）
- 落點：本機全域，非業務 repo
- 機制：複製（非 symlink）
- 重跑：整包覆蓋 + 可選備份（預設有備份）

---

## 5. §2 Manifest 與路徑（已確認）

### 5.1 格式

使用 **TSV**（避免 yq／jq 依賴），檔案：`install/targets.tsv`。

欄位（建議）：

| 欄 | 說明 |
|---|---|
| `id` | 如 `claude`、`cursor`、`agents-hub`、`cline` |
| `enabled` | `1`／`0` |
| `mode` | `skill-dir` 或 `doc-only` |
| `dest_template` | 含 `~` 與可選 `{skill}` 佔位；`skill-dir` 必填 |

註解行以 `#` 開頭。

### 5.2 預設 targets

| id | enabled | mode | dest |
|---|---|---|---|
| `claude` | 1 | skill-dir | `~/.claude/skills/{skill}` |
| `cursor` | 1 | skill-dir | `~/.cursor/skills/{skill}` |
| `agents-hub` | 1 | skill-dir | `~/.agents/skills/{skill}` |
| `cline` | 1 | doc-only | （空） |
| `windsurf` | 1 | doc-only | （空） |
| `copilot` | 1 | doc-only | （空） |

技能名稱固定集合：`sec-audit`、`sec-harden`、`sec-deliverables`。

### 5.3 複製範圍與知識庫根解析（Fix A，已核准）

現況：三支 SKILL 以 `../../references/…` 相對路徑讀知識庫。若只把 skill 夾複製到 `~/.claude/skills/<skill>/`，相對路徑會斷裂。

**採用 Fix A：**

1. **`install.sh` 同步 plugin 快照**  
   將 repo 內 `security-compliance-tw/` **整樹複製／同步**到  
   `~/.security-compliance-tw/plugin/`  
   （內容含 `skills/`、`references/`、`tools/` 等；重跑覆蓋，遵守 §3 備份策略時可先備份既有 `plugin/`）。

2. **寫入 root 指標**  
   檔案：`~/.security-compliance-tw/root`（單行、無尾隨空白以外的內容：plugin 目錄的絕對路徑，即上述 `…/plugin` 的 realpath）。  
   環境變數 `SECURITY_COMPLIANCE_TW_ROOT` 若已設定，**優先於**該檔（方便 CI／開發覆寫）。

3. **改 repo 內三支 SKILL 的讀取約定**（實作必做，屬 A2 範圍）  
   - 廢止「僅靠 `../../references`」作為已安裝環境的唯一方式。  
   - 新約定（Traditional Chinese 說明寫進各 SKILL）：  
     1. 若存在 env `SECURITY_COMPLIANCE_TW_ROOT` → 用它  
     2. 否則若存在 `~/.security-compliance-tw/root` → 讀取該路徑  
     3. 否則 fallback：相對於本 `SKILL.md` 的 `../..`（即仍在 clone／plugin 樹的 `skills/<name>/` 下開發時可用）  
   - 知識庫路徑改表述為 `{ROOT}/references/…`（Read 工具用解析後的絕對或明確相對路徑）。  
   - 保留「不要用 shell `cd ../..` 導航」的既有警告，改為「先解析 ROOT 再 Read」。

4. **再複製 skill 夾到各 agent target**  
   從來源 `security-compliance-tw/skills/<name>/`（或已同步的 plugin 內同路徑）`cp -R` 到 Claude／Cursor／agents-hub。  
   拷貝**不需要**再改寫檔案內容（約定已在來源 SKILL 內）。

5. **開發／未安裝**  
   未跑 install、無 root 檔時，fallback `../..` 讓 clone 內直接用技能仍可用。

### 5.4 doc-only 政策

Cline／Windsurf／Copilot：**不安裝假路徑**。`install.sh` 結尾提示見 `docs/usage/install.md`：建議用 Claude／Cursor 全域 skill，或對專案使用 sec-harden。

---

## 6. §3 `install.sh` 行為（已確認）

### 6.1 位置與相容

- 路徑：repo 根目錄 `./install.sh`
- OS：macOS／Linux；`bash`
- 依賴：標準 Unix（`cp`、`mkdir`、`date`）；**不**依賴 yq／jq
- `python3`：安裝結束後嘗試跑 `validate_kb.py`；缺失則警告，**不**使安裝失敗

### 6.2 預設流程

1. 解析 flags；定位 repo root（腳本所在目錄）
2. **同步 plugin 快照**：將 `security-compliance-tw/` 複製到 `~/.security-compliance-tw/plugin/`  
   （若目錄已存在且未 `--no-backup`，先備份整個 `plugin/` 到 backups）  
   `--dry-run` 時只列印。`--only` **不略過**此步（知識庫根必須存在；若未來要略過需另開 flag，本規格不做）。
3. 寫入／覆寫 `~/.security-compliance-tw/root` 為該 plugin 的絕對路徑
4. 讀 `install/targets.tsv`
5. 對每個 `enabled=1` 且 `mode=skill-dir` 的 target（可被 `--only` 過濾）：
   - 對每個 skill：若 dest 已存在且未 `--no-backup`，移到  
     `~/.security-compliance-tw/backups/<UTC-timestamp>/<target>/<skill>/`
   - `mkdir -p` parent；`cp -R` 來源 skill → dest（覆蓋）
6. 對 `doc-only`：不複製；彙總提示
7. 印出 root 檔內容、每個寫入的 `SKILL.md` 是否存在
8. 嘗試 `python3 security-compliance-tw/tools/validate_kb.py`（對 **repo 內** 來源樹；可另對 plugin 快照再跑一次作可選加強，非必須）

### 6.3 Flags

| Flag | 行為 |
|---|---|
| `--dry-run` | 只印將執行的動作，不寫檔、不備份 |
| `--no-backup` | 覆蓋前不備份 |
| `--only a,b` | 只處理列出的 target id |
| `--list` | 印出 manifest（含 enabled／mode／dest）後退出 |

### 6.4 退出碼

- `0`：複製步驟成功（即使 validate_kb 警告跳過）
- 非 `0`：manifest 讀取失敗、來源 skill 缺失、複製失敗等硬錯誤

---

## 7. §4 文件與驗收（已確認）

### 7.1 文件

- `docs/usage/install.md`：一鍵指令、flags、路徑表、backup 位置、doc-only 限制、如何在 Claude／Cursor 確認 skill 可見
- README「安裝」改為主推 `./install.sh`；手動 `ln -s` 改為進階附錄（連結到 install.md）
- `install/README.md`：如何新增 target 列

### 7.2 驗收清單

1. `--dry-run` 可跑通且無副作用
2. 真實安裝後：`~/.security-compliance-tw/root` 存在且指向有效 plugin；三個 skill-dir target × 三 skill 皆有 `SKILL.md`
3. 依 ROOT 可解析到 `references/profile.md`（抽樣）；`validate_kb.py` 對 repo 來源通過
4. `--only`／`--no-backup`／`--list` 符合 §3
5. 重跑產生 backup（除非 `--no-backup`）

### 7.3 交付物

- `install.sh`（含 plugin 同步 + root 寫入）
- `install/targets.tsv`
- `install/README.md`
- `docs/usage/install.md`（含 ROOT 解析約定與除錯）
- README 安裝區更新
- 三支 `skills/*/SKILL.md`：改為 ROOT 解析約定（廢止僅依賴 `../../references` 的已安裝假設）

---

## 8. 測試策略（實作計畫層）

- 用臨時 `HOME`（或 `TMPDIR` 下假 home）跑 install，避免污染開發者真實 `~/.claude`
- 覆蓋：list、dry-run、only、backup、no-backup、缺來源目錄失敗

---

## 9. 風險與後續

| 風險 | 緩解 |
|---|---|
| Skill 忘記改 ROOT 約定 | A2 必改三支 SKILL；驗收抽樣 Read `references/profile.md` |
| plugin 快照過期 | 重跑 `install.sh` 覆蓋；文件說明 |
| Cursor／Claude 重複三份 skill 拷貝 | 接受（明確性優先）；可用 `--only` 減量 |
| doc-only 使用者期望落空 | 文件與腳本結尾明確提示 |

A2 完成後預設下一棒：**A3**（CI／CHANGELOG），除非使用者指定。

---

## 10. 核准紀錄

- §1 目標／非目標：已核准
- §2 Manifest／路徑：已核准
- §3 install.sh 行為：已核准
- §4 文件／驗收：已核准
- §5.3 references 路徑：Fix A（plugin 快照 + root 指標 + SKILL 解析約定）已核准
- 已核准；實作計畫見 docs/superpowers/plans/2026-09-05-a2-install.md
