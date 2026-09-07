# security-compliance-tw

讓程式碼通過**源碼掃描**與**弱點掃描**，不需要與稽核人員逐項協調。

依台灣「資通安全責任等級分級辦法**附表十** 資通系統防護基準」，
結合 OWASP Web Top 10（2021 / 2025）、API Security Top 10（2023）、
Top 10 for LLM Applications（2025），提供給 Claude Code、Cursor
及其他本機 agent 使用的資安知識庫與工作流程。

伺服器與 Web 端涵蓋 **Go、Python、JavaScript**；
行動端涵蓋 **Kotlin／Java（Android）與 Swift（iOS）**，
對標《行動應用 App 基本資安檢測基準 V4.0》、OWASP MASVS V2.0 與 Mobile Top 10。

---

## 這個專案在解決什麼

政府指引寫「應針對輸入資料進行驗證」——那是給人看的，人可以判斷你做到了。

但 Fortify 做的是**污點分析**：它追資料從 source 流到 sink 的路徑。
你的程式碼可能真的安全，但只要它追不出你在中間消毒過，照樣標 Critical。

**「安全的寫法」與「掃描器認得的寫法」不是同一個集合。**
兩者的差距就是大部分專案卡在驗收的地方。

本專案的知識庫因此不只寫「正確寫法」，而是寫**掃描器規則明確認得的那一種寫法**，
並針對每一則說明：哪些工具會標、標什麼名字、什麼情況是誤判、誤判怎麼處置。


## 三支 skill

| Skill | 時機 | 產出 | 使用說明 |
|---|---|---|---|
| **`sec-audit`** | 送掃之前 / 拿到掃描報告之後 | `security-audit/findings.md`、`false-positives.md` | [詳細用法](docs/usage/sec-audit.md) |
| **`sec-harden`** | 寫程式的當下 | 專案的 `AGENTS.md`、Cursor `.mdc`、Cline / Windsurf / Copilot 規則檔 | [詳細用法](docs/usage/sec-harden.md) |
| **`sec-deliverables`** | 要交文件時 | 附表十查檢表、源碼查檢表、**檢測基準勾稽表**、測試報告、威脅建模、RTM、委外 RFP | [詳細用法](docs/usage/sec-deliverables.md) |

**第一次用建議從 [`sec-audit`](docs/usage/sec-audit.md) 開始**——
它會告訴你這個專案現在的體質，另外兩支的產出都依賴它的結果。

### sec-audit 的兩個模式

- **模式 1（送掃之前）**——樣式比對，預判會被標什麼，先修掉
- **模式 2（拿到報告之後）**——讀你手上的 Fortify / Checkmarx / AWVS 報告，
  逐項判定真漏洞或誤判、給修法、產出誤判佐證

**本專案不執行任何掃描工具。** 掃描由人執行。

### sec-harden 是跨工具的

它把規則安裝進你的專案，產出各家 agent 的格式：

```
你的專案/
├── AGENTS.md                        通用基底
├── .cursor/rules/sec-harden-*.mdc   依語言分檔，用 globs 自動附加
├── .clinerules
├── .windsurfrules
└── .github/copilot-instructions.md
```

裝完之後**不依賴 Claude Code 在場**，Cursor、Cline、Codex 都能用。
一律附加不覆蓋，重跑安裝只替換標記區塊內容。

---

## 安裝

```bash
git clone https://github.com/mikey890612/security-compliance-tw.git
cd security-compliance-tw
./install.sh
```

一鍵安裝會同步 plugin 快照、寫入 root 指標，並把三支 skill 複製到 Claude／Cursor／agents-hub 的全域目錄。完整 flags、路徑、備份、doc-only 代理與驗證步驟見 **[安裝說明](docs/usage/install.md)**。

可選：驗證知識庫完整性（需要 Python 3，無外部相依；`install.sh` 結束時也會嘗試執行）：

```bash
python3 security-compliance-tw/tools/validate_kb.py
```

> **進階：** 僅本機開發、不跑 installer 時，仍可用手動 `ln -sfn` 把 skill 鏈到 `~/.claude/skills/`；此方式不寫 root、不同步可攜快照，細節見 [安裝說明 · 進階](docs/usage/install.md#進階手動-symlink不建議作為主路徑)。

---

## 知識庫結構

核心設計是**偵測與對照分離**：

```
references/
├── checks/              90 則：怎麼偵測、怎麼修（不含任何法規或 OWASP 編號）
├── mapping.md           唯一對照表：check-id → 附表十 / OWASP / CWE
├── controls-appendix10.md   附表十查檢表全文與分級
├── controls-mas-v4.md   檢測基準 V4.0 的 65 條條號與標題
├── quick-patterns.md    寫程式當下的速查（sec-harden 的內容來源）
├── templates/           各類交付文件的產出規則
├── profile.md           分級問答與 check 選取規則
└── scanners.md          各工具的行為特性與誤判處置慣例
```

同一個壞味道會同時對映四張清單（例：字串拼接 SQL = 附表十 4.5.3.1 +
Web21 A03 + Web25 A05 + LLM05 + CWE-89）。若在每則 check 內嵌編號，
清單改版時要修改全部檔案；集中對照則只需改一個檔。

每則 check 固定五個小節：**掃描器怎麼標 / 壞味道 / 過關寫法 /
常見誤判與處置 / 判定準則**。`SAST-` 類必須含 Go、Python、JavaScript 三種範例；
`MAST-` 類依平台要求 Kotlin／Swift；設定檔屬性必須以可複製的 xml／plist 圍籬呈現。
以上由 `tools/validate_kb.py` 自動驗證，同時檢查 `checks/` 與 `mapping.md`
的雙向對應。

### 涵蓋範圍（90 則）

注入（含 XSS）· 存取控制 · 身分鑑別與 Session · 密碼學 · 日誌與稽核 ·
錯誤與例外 · **請求濫用**（`sast-request-abuse.md`：CSRF／SSRF／UPLOAD）·
API 授權 · LLM / Agent · HTTP 安全標頭 · TLS 與 Cookie · 資訊外洩 ·
**行動端 MAST**（`mast-storage.md`、`mast-crypto.md`、`mast-network.md`、`mast-auth.md`、`mast-platform.md`、`mast-code.md`、`mast-resilience.md`）·
**MDM／EMM／MAM**（`mdm-controls.md`）

**伺服器與 Web 46 則**（含請求濫用 3 則）·**行動端 36 則**（七檔，依 MASVS 類別命名）·
**MDM 8 則**（規格外的延伸，見下）。依 profile 勾選「有行動 App」「有 EMM／MDM／MAM」載入。

行動端對照《行動應用 App 基本資安檢測基準》的條號與 L1／L2／L3 分級、
OWASP MASVS 控制項編號與 Mobile Top 10。

**16 列掃描器對照已對 `testdata/sample-android` 與 `sample-ios` 實跑 mobsfscan 驗證**
（狀態 `verified`，附檔名行號）；其餘仍為 `unverified`。
**商用工具的行動端對照本專案不收錄**——無從查證，寫進來只是假的安全感。

⚠ **`MDM-*` 8 則不在本專案原始規格的範圍內**——原始規格限定「行動應用程式本身的
用戶端程式碼與設定檔」，MDM 是機關端的裝置管理政策，其佐證來自主控台報表
而非掃描器規則命中。保留是因為對實際稽核有用，但在 `mapping.md` 中**獨立一張表**，
且不計入行動端則數。

**未涵蓋**：備份備援、稽核儲存容量、時戳校時、系統文件、委外管理、
供應鏈完整性、基礎設施加固（GCB / 防火牆 / OS）。

---

## 範例產出

`security-compliance-tw/examples/` 收錄對測試 fixture 實際跑出來的成果：

| 檔案 | 內容 |
|---|---|
| `audit-findings.md` | sec-audit 的逐項判定 |
| `checklist-appendix10.md` | 附表十勾稽表（44 項，分級中） |
| `checklist-source.md` | 源碼安全查檢表（23 項） |
| `threat-model.md` | DFD + STRIDE + DREAD（含驗算） |
| `rtm.md` | 需求追溯矩陣 |
| `rfp-security-requirements.md` | 委外 RFP 資安需求（45 條） |
| `security-test-report.md` | 安全測試報告 |

⚠ 這些是對一個 **41 行的測試 fixture** 產出的示範，不是真實專案的稽核結果。

---

## 核心原則：不編造

交付文件會送到稽核人員手上。**編造比留白危險得多。**

- 看不到證據的項目**不可標「符合」**，一律標「非程式碼可判定，需人工確認」
- 推導不出來的欄位填「（待填）」
- 自動判斷處標示信心度，低信心的寫明依據什麼假設
- 附表十查檢表未收錄的風險，標為「查檢表外」，不硬湊章節號

誤判標記須同時滿足三要件：資料實際不可控、路徑上確有消毒只是工具追不到、
有具體佐證。三者缺一即當真漏洞修。

不採用「遮蔽掃描結果讓紅字消失」的做法——附表十每項的查核方式
都同時要求**自動化工具檢測**與**人工審查**，遮蔽會在人工審查那關破功。

---

## 已知限制

誠實列出，請據此判斷可信度：

1. **掃描器對照的驗證狀態不一**——開源工具（gosec、bandit、Semgrep 等）
   可透過 fixture 實跑做到**部分** `verified`；商用掃描器（Fortify、Checkmarx、
   AWVS、WebInspect、Nessus 等）對照在提供redacted 報告前一律維持 `unverified`
   （宣稱對照、尚未校準）。不得捏造商用規則 ID。
   詳見 [開源驗證操作](security-compliance-tw/tools/verify_scanners.md) 與
   [商用驗證流程](docs/usage/scanner-verification.md)。
2. **僅對測試 fixture 驗證過**，尚未在真實專案上跑過。
3. **OWASP Top 10:2025 的定稿狀態**需自行至 owasp.org/Top10 核對。
   `mapping.md` 的 Web25 欄依 2025 版排序。
4. **樣式比對無法取代污點分析**——不安全操作被包進多層 helper、
   動態組成的字串、二階注入等情形可能漏判。「未命中」不等於「無此問題」。
5. **行動端已對 fixture 實跑過，但仍非真實專案。**
   `testdata/sample-android` 與 `sample-ios` 是刻意寫成不安全的 fixture，
   已用 mobsfscan 的規則集實跑，**16 列掃描器對照因此標為 `verified` 並附
   檔名行號證據**。但那證明的是「規則會對這樣的程式碼命中」，
   不是「本知識庫在真實專案上完整」——真實專案的框架、SDK 與寫法遠更多樣。
   商用工具（Fortify／Checkmarx）的行動端對照仍未驗證，且本專案不收錄。
   重跑方式見 `references/scanner-verification-log.md`。

6. **`MDM-*` 是掃描器看不到的類別。**
   註冊狀態、組態描述檔、抹除紀錄都在主控台，不在程式碼裡；
   其佐證方式是主控台報表與裝置抽樣稽核，不是規則命中，
   因此整組維持 `unverified`。

7. **`MAS` 欄只對照到條號，不代表該條「符合」。**
   《行動應用 App 基本資安檢測基準》65 條中，目前有 39 條掛得上 check；
   其餘產出勾稽表時會落在「非程式碼可判定，需人工確認」或「尚未涵蓋」。
   **不要把 `MAS` 欄有值當成該項已通過。**

8. **指引內文與附件 1 查檢表的收錄範圍不完全相同**——例如 HTTP 安全標頭
   （4.5.3.4）收錄於內文，查檢表未收錄。產出勾稽表時這類項目會另立區段。
   詳見 `references/controls-appendix10.md` 的「內文與查檢表的收錄範圍」。

---

## 資料來源與著作權

### 法規本文（不受著作權保護）

`references/controls-appendix10.md` 收錄的控制措施與分級，出自：

- **《資通安全責任等級分級辦法》附表十「資通系統防護基準」**
  （依《資通安全管理法》授權訂定之法規命令）

依**著作權法第 9 條**，憲法、法律、命令或公文不得為著作權之標的。

### 檢測基準（不是法規命令，本專案只收條號與標題）

`references/controls-mas-v4.md` 收錄《行動應用 App 基本資安檢測基準》V4.0
（行動應用資安聯盟，民國 113 年 9 月）**全部 65 條的條號、條目標題與適用分類**，
由官方 PDF 抽取，並與該基準附錄二的 ★／－ 表格交叉驗證。

**它與附表十的法律地位不同。** 附表十是法規命令，第 9 條不保護，故可全文重製；
檢測基準是受委託編製的技術文件，第 9 條的排除**不適用**。
因此本專案只收條號與標題，**不收**其檢測方法、判定標準與條文內文。
完整條文請自行至 <https://www.mas.org.tw/download/app> 取得。詳見 [NOTICE.md](NOTICE.md)。

### 參考指引（著作權屬各機關，本專案不重製）

下列文件為前述法規的實作參考，本專案**僅參考其技術觀念**，
所有實作內容均另行以 Go / Python / JavaScript 撰寫，並補上掃描器規則對應、
API 層與 AI 層內容：

- 《Web 應用程式安全參考指引 V3.2》，數位發展部資通安全署，114.12.31
- 《安全軟體發展流程指引》《安全軟體設計參考指引》《安全軟體測試參考指引》，
  行政院資通安全辦公室，103 年

**這些文件的原始 PDF 及其實作建議、程式範例、編排，著作權分屬上述機關，
不隨本專案散布**，請自行至各機關網站取得。

---

## 授權

MIT（見 [LICENSE](LICENSE)）。

涉及外部來源的部分——法規本文、參考指引、OWASP 清單、掃描工具規則名稱——
的處理方式與界線，見 [NOTICE.md](NOTICE.md)。
