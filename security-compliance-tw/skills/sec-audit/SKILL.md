---
name: sec-audit
description: 依台灣附表十資通系統防護基準與 OWASP Web/API/LLM Top 10 檢視程式碼，讓專案通過源碼掃描（Fortify/Checkmarx/Semgrep/SonarQube/gosec/bandit）與弱點掃描（AWVS/Nessus/ZAP/WebInspect）。送掃之前用來預防被標紅字，拿到掃描報告之後用來逐項判定真漏洞或誤判並修補。Use when the user mentions 源碼掃描, 弱點掃描, 資安稽核, 附表十, 資通系統防護基準, OWASP, Fortify, Checkmarx, AWVS, 滲透測試, 驗收, or asks to make code pass a security scan.
---

# sec-audit

**目標：讓程式碼通過掃描，不需要與稽核人員逐項協調。**

本 skill 不執行任何掃描工具。掃描由人執行。

## 判定準則（最重要）

預設路徑是**真的修好，而且用掃描器追得到的方式修好**。

只有在同時滿足以下三點時，才走誤判標記：

1. 資料實際不可控（來源為常數、列舉，或已通過白名單驗證）
2. 路徑上確實有有效的消毒或參數化，只是工具追不到
3. 有具體佐證可寫入報告：檔案位置、資料來源、消毒點行號

三點無法同時滿足就當真漏洞修。不採用單純遮蔽結果讓紅字消失的做法——
附表十每項的查核方式都同時要求自動化工具檢測**與**人工審查，遮蔽會在人工審查破功。

## 兩個模式

**使用者提供了掃描報告檔案 → 模式 2。沒有 → 模式 1。情境不明就直接問。**

## 模式 1：送掃之前

1. **建立 profile**——讀 `{ROOT}/references/profile.md`，照其問答腳本**一次問完**。
   腳本用 multiSelect 把六個資料點壓成三題，**剛好在 AskUserQuestion 的四題上限內**。
   不要拆成兩輪問，拆輪等於逐題往返
2. **偵測技術棧**——讀 `go.mod` / `requirements.txt` / `pyproject.toml` / `package.json`
3. **選定 check 集合**——依 `profile.md` 的選取規則決定載入哪些 `checks/*.md`。
   **只載入需要的檔案**，這是控制 context 的關鍵。載入前先確認檔案存在。
   Profile 複選若勾「**有行動 App**」→ 載入 `checks/mast-storage.md`、`checks/mast-crypto.md`、`checks/mast-network.md`、`checks/mast-auth.md`、`checks/mast-platform.md`；
   勾「**有 EMM／MDM／MAM**」→ 載入 `mdm-controls.md`（含 LOCK／JAIL／PATCH／VPN／MTD；規則見 `profile.md`，勿複製 check 全文）
4. **樣式比對**——用 check 檔內「壞味道」區塊的樣式在 codebase 搜尋
5. **逐項判定**——每個命中歸為：真漏洞 / 誤判 / 不適用，各自記錄理由
6. **修補**——**先列出待修清單與影響檔案數，取得使用者確認後才動手**。
   依 check 檔的「過關寫法」修改。優先序見 `profile.md` 的優先序表
7. **產出**——見下方

## 模式 2：拿到掃描報告之後

1. 讀取使用者提供的報告檔（csv / txt 優先支援；html / pdf 盡力解析）
2. 取出每項發現的規則名稱、等級、檔案位置
3. 以各 check 的「掃描器怎麼標」表格反查 check-id。
   找不到對應的 check 時，明確標示「本知識庫尚未涵蓋」，**不要猜測**。
   若命中列的「狀態」為 `unverified`，在 findings 註明「規則名待真實報告確認」
4. 依該 check 的「判定準則」逐項判定
5. 真漏洞依「過關寫法」修補；誤判產出佐證。
   誤判的標記方式（`#nosec`、Not an Issue 等）查 `{ROOT}/references/scanners.md`
6. **產出**——見下方

## DAST 家族的處理方式

不對系統實際發動探測。改為檢查**決定執行期行為的程式碼與設定**：
middleware 註冊順序、安全標頭設定、Cookie flags、錯誤處理器、TLS 組態，
據以預判掃描器將觀察到的結果。

## 產出

寫入專案根目錄的 `security-audit/`：

- `findings.md`——逐項：check-id / 檔案位置 / 判定 / 處置
- `false-positives.md`——誤判清單與佐證，供複掃與人工審查使用

**本 skill 不產交付文件。** 使用者要附表十勾稽表、源碼安全查檢表、
安全測試報告、威脅建模、RTM 或委外 RFP 時，改用 `sec-deliverables`
——它會讀本 skill 產出的 `findings.md` 作為輸入。

## 知識庫根目錄（ROOT）

讀知識庫前，先解析 **ROOT**（plugin 根目錄，其下有 `references/`）：

1. 若環境變數 `SECURITY_COMPLIANCE_TW_ROOT` 已設定 → 用它
2. 否則若存在 `~/.security-compliance-tw/root` → 讀取該檔單行路徑（plugin 絕對路徑）
3. 否則 fallback：相對於本 `SKILL.md` 的 `../..`（仍在 clone／plugin 樹的 `skills/<name>/` 下開發時）

知識庫路徑一律表述為 `{ROOT}/references/…`。用 Read 工具讀**解析後的絕對路徑**（或開發時 fallback 的明確相對路徑）。

**不要用 shell 的 `cd ../..` 導航**——先解析 ROOT 再 Read。`cd` 是邏輯解析，在 symlink 或已安裝的 skill 目錄下會跑錯地方。

## 知識庫

全部位於 `{ROOT}/references/`：

| 檔案 | 何時讀 |
|---|---|
| `profile.md` | 步驟 1 與 3，一定要讀 |
| `checks/*.md` | 依 profile 選取，只讀需要的 |
| `scanners.md` | 判讀報告或處理誤判時 |
| `mapping.md` | 需要在報告中標註附表十、檢測基準（`MAS` 欄）或 OWASP 編號時才讀 |
| `scanner-verification-log.md` | 需要說明某條掃描器對照的驗證依據時 |

`controls-appendix10.md`、`controls-mas-v4.md` 與 `templates/` 屬 `sec-deliverables` 的範圍，本 skill 不讀。

**不要一次載入所有 check 檔。**


## 掃描器對照狀態（必讀）

各 check「掃描器怎麼標」表有「狀態」與「證據」欄。引用掃描器涵蓋時必須遵守：

1. **優先引用 `verified`**（必要時含 `partial`）列——這些才有 fixture／報告證據可追
2. **`unverified` = 宣稱對照、尚未校準**——可當提示用，不可當成已實測的規則 ID
3. **禁止捏造** Fortify、Checkmarx、AWVS、WebInspect、Nessus 等商用規則 ID；表上沒有就寫「知識庫尚無已驗證對照」
4. 模式 2 命中 `unverified` 列時，findings 必須註明「**規則名待真實報告確認**」

操作與回填流程：

- 開源 fixture 實跑：`{ROOT}/tools/verify_scanners.md`
- 商用遮蔽（redacted）報告路徑：`../../../docs/usage/scanner-verification.md`

## 目前涵蓋範圍

66 則 check，18 個檔：

| 類別 | 檔案 | 載入條件（見 `profile.md`） |
|---|---|---|
| 注入 | `sast-injection.md` | 一律 |
| 存取控制 | `sast-authz.md` | 分級 ≥ 中 |
| 身分鑑別與 Session | `sast-session-auth.md` | 有登入功能 |
| 密碼學 | `sast-crypto.md` | 分級 ≥ 中／有個資或金流 |
| 日誌與稽核 | `sast-logging.md` | 有個資或金流 |
| 錯誤與例外 | `sast-errors.md` | 一律 |
| 請求濫用（CSRF／SSRF／上傳） | `sast-request-abuse.md` | 一律 |
| API 授權 | `sast-api-authz.md` | 有 API 端點 |
| LLM / Agent | `sast-llm.md` | 有 LLM／RAG／Agent |
| HTTP 安全標頭 | `dast-headers.md` | 對外服務 |
| TLS 與 Cookie | `dast-tls-cookie.md` | 對外服務 |
| 資訊外洩 | `dast-info-leak.md` | 對外服務 |
| MAST 本機儲存／日誌／備份 | `mast-storage.md` | **有行動 App** |
| MAST 密碼學 | `mast-crypto.md` | **有行動 App** |
| MAST 網路與憑證釘選 | `mast-network.md` | **有行動 App** |
| MAST 身分鑑別與生物辨識 | `mast-auth.md` | **有行動 App** |
| MAST 平台介面（IPC／WebView／剪貼簿／螢幕） | `mast-platform.md` | **有行動 App** |
| MDM／EMM／MAM 控制 | `mdm-controls.md` | **有 EMM／MDM／MAM** |

行動端 12 則分於五個依 MASVS 類別命名的檔案；MDM 8 則獨立一檔（規格外的延伸）。W1 新增 `sast-request-abuse.md`（`SAST-CSRF-001`／`SAST-SSRF-001`／`SAST-UPLOAD-001`，一律；+3 則至 66）。掃描器對照多為 `unverified`／`—`，**勿宣稱 Fortify／MobSF 已驗證**。

**未涵蓋**：備份備援、稽核儲存容量、時戳校時、系統文件、委外管理、
供應鏈完整性、基礎設施加固（GCB / 防火牆 / OS）。

遇到超出範圍的項目時，明確告知使用者「此類別本知識庫尚未涵蓋」，
**不要憑印象生成建議**——本 skill 的價值在於答案來自經過驗證的知識庫。
