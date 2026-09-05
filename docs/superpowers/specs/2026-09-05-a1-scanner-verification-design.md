# A1：掃描器規則名可信度校正 — 設計規格

日期：2026-09-05
狀態：已與使用者確認 §1–§4，待使用者 review 本檔後進入 writing-plans
專案：`security_skill_creator` / `security-compliance-tw`
相關 GitHub：https://github.com/mikey890612/security-compliance-tw

---

## 0. 子專案地圖（脈絡）

本規格只涵蓋 **A1**。完整路線圖（不在本規格實作範圍）：

| ID | 內容 |
|---|---|
| **A1（本規格）** | 開源規則名核對；商用標未驗證；補報告流程 |
| A2 | install.sh 與跨工具安裝說明 |
| A3 | validate_kb CI、CHANGELOG、release tag |
| A4 | 搜尋 regex／golden test、跨 agent 問答抽象（可選） |
| B1–B4 | 行動裝置資安指引模組（獨立子專案） |

建議順序：A1 → A2 → A3，再進 B1。

---

## 1. 背景與問題

`security-compliance-tw` 的 check「掃描器怎麼標」表格中，開源工具規則 id
多已人工對過官方文件；**Fortify／Checkmarx 等商用規則名來自模型知識**，
尚未以真實掃描報告驗證。`sec-audit` 模式 2 依規則名反查 check-id 時，
名稱不準會導致錯配或漏配。

使用者短期**拿不到商用報告**，但仍要求 A1 能推進，且完成時：

1. 開源規則名已核對（盡量 `verified`）
2. 商用列明確標成 `unverified`
3. 有之後補上真實報告的標準流程

採用做法：**開源對 fixture 實跑對表＋商用延後驗證流程**（非「只改文件」或「空等商用報告」）。

---

## 2. 目標與非目標

### 目標

- 為每則 check 的掃描器表建立可機器檢查的 **狀態模型**（`verified` / `unverified` / `partial`）
- 對現有 fixture 跑約定之開源掃描器，填入狀態與證據
- 文件化商用報告的取得、存放（gitignore）、對表與 PR checklist
- 調整 `sec-audit`：反查到 `unverified` 時必須在 findings 標示待確認
- 更新 README「已知限制」指向本狀態模型

### 非目標（明確不做）

- 不取得或不偽造 Fortify／Checkmarx 報告
- 不在本輪安裝 SonarQube／CodeQL 重型 CI
- 不上 GitHub Action（屬 A3）
- 不做行動裝置 checks（屬軌道 B）
- 不改動附表十控制項本文、不擴充新的 vulnerability 類別（除非對表發現表格欄位不足）

---

## 3. 架構總覽

```
checks/*.md  「掃描器怎麼標」表
      │
      ├─ validate_kb.py  強制欄位與狀態／商用 verified 規則
      │
      ├─ 開源實跑 → testdata/scan-artifacts/（可 gitignore 大檔）
      │            → references/scanner-verification-log.md（進 git）
      │
      └─ 商用延後 → docs/usage/scanner-verification.md
                   → testdata/scan-artifacts/commercial/（gitignore）
```

`mapping.md` 與 check 五小節結構不變；本規格只擴充掃描器表與驗證周邊。

---

## 4. §1 狀態模型（已確認）

「掃描器怎麼標」固定五欄：

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |

**狀態枚舉（僅允許）：**

| 值 | 意義 |
|---|---|
| `verified` | 已用 fixture 實跑或官方 rule id 文件／未來真實商用報告釘死 |
| `unverified` | 尚未用報告或實跑釘死（短期商用列預設） |
| `partial` | 規則家族可對上，但 id／名稱可能因版本飄 |

**硬規則：**

1. 商用工具列（Fortify、Checkmarx、AWVS、WebInspect、Nessus）無真實報告時 **不得** `verified`
2. `sec-audit` 模式 2 命中 `unverified` → findings 必須註明「規則名待真實報告確認」
3. README 已知限制改為描述本狀態模型並連結 verification 文件

---

## 5. §2 開源實跑對表（已確認）

### 輸入 fixture

- 必要：`testdata/sample-go`
- 有 Python 時：`testdata/sample-multi`（bandit）
- 可選回歸：`testdata/sample-go-fixed`（本輪不強制）

### 工具

| 工具 | 必要 | 備註 |
|---|---|---|
| gosec | 是 | Go |
| bandit | 條件式 | 有 Python fixture 時 |
| semgrep | 是（能裝則跑） | 規則集版本釘死寫進 log；裝不起來則相關列保持 unverified 並記 skip |
| SonarQube／CodeQL | 否 | 本輪不做；列可 `unverified` 或依官方文件 `partial`＋URL |

### 產物

- 操作說明：`tools/verify_scanners.md`；可選腳本 `tools/run_open_scanners.sh`（工具缺失不失敗）
- 原始輸出：`testdata/scan-artifacts/`（大檔可 gitignore）
- 對照總表（進 git）：`references/scanner-verification-log.md`  
  欄位：check-id、工具、規則、狀態、證據路徑、日期、備註

### 不做

- 不偽造商用報告格式
- 不要求本輪 CI 裝齊 scanner

---

## 6. §3 商用延後驗證流程（已確認）

文件：`docs/usage/scanner-verification.md`

1. 取得脫敏 csv／txt／json（優先）
2. 本機放 `testdata/scan-artifacts/commercial/`（**預設 gitignore**，禁止客戶報告進公開 GitHub）
3. 用模式 2 對表；對得上改 `verified`，公開證據寫 `internal-verified:YYYY-MM-DD`（不貼報告內容）
4. 對不上記入 log「未涵蓋」，禁止猜測規則名
5. PR checklist：報告未進 git；只改狀態／規則字串／log

取得路徑（計畫，非本輪執行）：公司授權跑 sample-go、外部脫敏樣本、公開教學報告（僅可作 `partial`）。

Skill：更新 `sec-audit/SKILL.md` 對 `unverified` 的 findings 註記；README 已知限制改寫。

---

## 7. §4 測試與 validator（已確認）

`validate_kb.py` 新增：

1. 掃描器表必須含五欄
2. 狀態 ∈ {verified, unverified, partial}
3. 商用列若 verified → 證據必填且不得為 `—`
4. 非商用 verified → 證據必填（**error**，非警告）

行為：

| 情況 | 處置 |
|---|---|
| 商用 verified 無證據 | validator fail |
| 開源工具未安裝 | skip＋log，不中止 A1 |
| 規則對不到 check | log 未涵蓋，禁止猜 |
| 證據指向 gitignore 商業報告 | 公開欄只寫內部已驗證＋日期 |

回歸：既有 `validate_kb.py` 必須通過。GitHub Action 留給 A3。

---

## 8. 檔案變更清單（實作時）

| 路徑 | 變更 |
|---|---|
| `references/checks/*.md` | 掃描器表加狀態／證據；開源填核對結果；商用→unverified |
| `references/scanner-verification-log.md` | 新建 |
| `tools/validate_kb.py` | 表頭與狀態規則 |
| `tools/verify_scanners.md` | 新建操作說明 |
| `tools/run_open_scanners.sh` | 可選 |
| `testdata/scan-artifacts/` | 新建＋gitignore 規則 |
| `docs/usage/scanner-verification.md` | 新建商用補報告流程 |
| `skills/sec-audit/SKILL.md` | unverified 註記 |
| `README.md` | 已知限制改寫 |
| `.gitignore` | commercial artifacts |

---

## 9. 成功標準（验收）

- [ ] 開源：gosec（＋可行的 bandit／semgrep）已對表；能 verified 的列已標且有證據
- [ ] 商用列皆為 `unverified`（或具真實證據的 verified——本輪預期前者）
- [ ] `validate_kb.py` 通過新規則
- [ ] `scanner-verification.md` 與 `scanner-verification-log.md` 存在且無 TBD 占位
- [ ] `sec-audit` 與 README 已反映狀態模型
- [ ] 公開 git 無客戶／商用原始報告

---

## 10. 風險與緩解

| 風險 | 緩解 |
|---|---|
| 本機裝不了 semgrep | skip＋列維持 unverified，不擋 A1 |
| fixture 覆蓋不到部分 check | partial／unverified＋log 原因，不捏造命中 |
| 日後誤把商用報告 commit | commercial 目錄 gitignore＋PR checklist |
| 狀態欄格式漂移 | validator 強制五欄與枚舉 |

---

## 11. 實作後下一步

本規格核准並完成實作後：進入 **A2（安裝體驗）** 或依使用者指定；軌道 B 行動裝置另開規格。
