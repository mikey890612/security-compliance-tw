---
name: sec-audit
description: 依台灣附表十資通系統防護基準與 OWASP Web/API/LLM Top 10 檢視程式碼，讓專案通過源碼掃描（Fortify/Checkmarx/Semgrep/SonarQube/gosec/bandit）與弱點掃描（AWVS/Nessus/ZAP/WebInspect）；Android／iOS App 另對照 OWASP MASVS 與《行動應用 App 基本資安檢測基準》（MobSF/mobsfscan）。送掃之前用來預防被標紅字，拿到掃描報告之後用來逐項判定真漏洞或誤判並修補。Use when the user mentions 源碼掃描, 弱點掃描, 資安稽核, 附表十, 資通系統防護基準, OWASP, MASVS, Fortify, Checkmarx, AWVS, MobSF, 滲透測試, 驗收, or asks to make code or a mobile app pass a security scan.
---

# sec-audit

**目標：讓程式碼通過掃描，不需要與稽核人員逐項協調。**

本 skill 不執行任何掃描工具。掃描由人執行。

## 判定準則（最重要）

預設路徑是**真的修好，而且用掃描器追得到的方式修好**。

只有在同時滿足以下兩點時，才走誤判標記：

1. **風險實際已被消除，只是掃描器看不出來**——以下任一成立：
   - 來源不可控：常數、列舉，或已通過允許清單驗證
   - 路徑上有有效的消毒或參數化（含框架的自動跳脫，例如 `html/template`）
   - 要求的控制確實存在，只是在工具看不到的地方：中介層、接收端 handler、框架設定
2. **有具體佐證**可寫入報告：檔案位置與行號——資料來源、消毒點或控制所在

兩點缺一就當真漏洞修。「應該沒事」「只在內網」不是佐證。
不採用單純遮蔽結果讓紅字消失的做法——
附表十每項的查核方式都同時要求自動化工具檢測**與**人工審查，遮蔽會在人工審查破功。

## 判定分類與優先序

每個發現歸入下列一類，**不要自創分類**。check 檔裡的「通過」代表合格、不構成發現。

| 判定 | 意思 | 優先序 |
|---|---|---|
| **真漏洞** | 風險存在。灰色地帶一律歸此 | P0／P1，見 `profile.md` |
| **改寫即過** | 實質安全，但寫法會被標，且**換成掃描器認得的寫法後就不再被標**。check 的處置寫了改寫方式（「改寫比寫誤判說明省事」）的情況一律歸此，**不要判誤判**。改完仍會被標的（例如自訂的消毒函式），判誤判 | P2 |
| **誤判** | 符合上方兩點，且不需要改程式碼 | 不排序，列為送掃前要備妥的佐證 |
| **不適用** | 該 check 的前提不成立（例如沒有對外 TLS） | 不列 |

第三方套件（`vendor/` 等）的發現同樣歸入這四類：風險已被接收端或伺服器端的控制消除的，判誤判；
風險真實存在的，判真漏洞，修法依 `{ROOT}/references/scanners.md` 的「第三方程式碼的發現」（升級或設定覆寫，不改套件檔）。

優先序排的是**不修會不會被驗收退件**，不是掃描器等級——規則見 `{ROOT}/references/profile.md` 的「優先序」。
**人工審查才抓得到的真漏洞（例如完全沒有授權檢查）照樣排 P0**，它們最容易被忽略。

## 兩個模式

**使用者提供了掃描報告檔案 → 模式 2。沒有 → 模式 1。情境不明就直接問。**

## 模式 1：送掃之前

1. **建立 profile**——讀 `{ROOT}/references/profile.md`，照其問答腳本**一次問完**。
   腳本用 multiSelect 把六個資料點壓成三題，**剛好在 AskUserQuestion 的四題上限內**。
   不要拆成兩輪問，拆輪等於逐題往返
2. **偵測技術棧**——依 `profile.md` 的「語言對應」：manifest 檔之外，也看實際存在的原始檔
   （例如有 `.js`／`.html` 但沒有 `package.json`）
3. **選定 check 集合**——依 `profile.md` 的選取規則決定載入哪些 `checks/*.md`。
   **只載入需要的檔案**，這是控制 context 的關鍵。載入前先確認檔案存在。
   載入的檔裡**逐則**依 `profile.md` 的「逐則決定要不要查」判斷：本分級沒要求、
   使用者將面對的掃描器也不會標的，歸不適用。
   Profile 複選若勾「**有行動 App**」→ 載入 `checks/mast-storage.md`、`checks/mast-crypto.md`、`checks/mast-network.md`、`checks/mast-auth.md`、`checks/mast-platform.md`、`checks/mast-code.md`；
   另勾「**將送 F 類加測**」才載入 `checks/mast-resilience.md`；
   勾「**有 EMM／MDM／MAM**」→ 載入 `checks/mdm-controls.md`（含 LOCK／JAIL／PATCH／VPN／MTD；規則見 `profile.md`，勿複製 check 全文）
4. **樣式比對**——用 check 檔內「壞味道」區塊的樣式在 codebase 搜尋
5. **逐項判定**——每個命中歸入上方四類之一，記錄理由；依 `profile.md` 的「優先序」排序，
   需要讀 `{ROOT}/references/mapping.md` 的分級欄
6. **修補**——**先列出待修清單與影響檔案數，取得使用者確認後才動手**。
   依 check 檔的「過關寫法」修改。修補若會新增機制（例如補上登入），
   修完後要重跑模式 1——新機制會讓其他 check（例如 `sast-session-auth.md`）開始適用
7. **產出**——見下方

## 模式 2：拿到掃描報告之後

1. 讀取使用者提供的報告檔（csv / txt 優先支援；html / pdf 盡力解析）
2. 取出每項發現的規則名稱、等級、檔案位置。**先依規則名稱分組**——
   同一規則常一次報幾十項（例如每個檔案上傳欄位各一項），逐組判讀、逐項佐證
3. 以各 check 的「掃描器怎麼標」表格反查 check-id，**用規則全名比對，含冒號後的子類別**
   （`Weak Cryptographic Hash: Insecure PBE Iteration Count` 不等於 `Weak Cryptographic Hash`）。
   找不到對應的 check 時，明確標示「本知識庫尚未涵蓋」，**不要猜測**。
   若命中列的「狀態」為 `unverified`，在 findings 註明「規則名待真實報告確認」
4. **優先序依 `profile.md` 的「優先序」**；其中「掃描器等級」一律用**報告上的等級**，
   不用表上的「預設等級」——Fortify 的等級是逐項計算的，同一規則在不同位置等級可以不同
   （見 `{ROOT}/references/scanners.md`）
5. 依該 check 的「判定準則」逐項判定。發生在第三方套件（`vendor/` 等）的項目，
   依 `scanners.md` 的「第三方程式碼的發現」處置，**不要直接改套件檔**
6. 真漏洞依「過關寫法」修補；誤判產出佐證。
   誤判的標記方式（`#nosec`、Not an Issue 等）查 `{ROOT}/references/scanners.md`
7. **產出**——見下方

## DAST 家族的處理方式

不對系統實際發動探測。改為檢查**決定執行期行為的程式碼與設定**：
middleware 註冊順序、安全標頭設定、Cookie flags、錯誤處理器、TLS 組態，
據以預判掃描器將觀察到的結果。

## 產出

寫入專案根目錄的 `security-audit/`：

- `findings.md`——逐項：check-id / 檔案位置 / 判定（四類之一）/ 優先序 / 預期或實際的掃描器規則 / 處置。
  依 P0、P1、P2 排列；人工審查項也排進去，不另立「表外」。
  需要使用者先執行工具才能判定的（例如 `SAST-DEP-001` 的元件比對），不歸入四類，
  列在開頭的「**待使用者執行**」，附要跑的指令；使用者提供輸出後再判定
- `false-positives.md`——供複掃與人工審查使用，分兩段：
  - **誤判**：判定為誤判的項目與佐證。對照為 `unverified` 的規則也要預先列出「可能被標」的項目，註明規則名待確認
  - **已知風險接受**：判定仍是真漏洞、但受外部限制無法修的項目（例如對方系統只收 MD5），附限制的出處。
    這不是第五類判定，findings 裡照樣列為真漏洞

**本 skill 不產交付文件。** 使用者要附表十勾稽表、源碼安全查檢表、
安全測試報告、威脅建模、RTM 或委外 RFP 時，改用 `sec-deliverables`
——它會讀本 skill 產出的 `findings.md` 作為輸入。

## 知識庫根目錄（ROOT）

讀知識庫前，先解析 **ROOT**（plugin 根目錄，其下有 `references/`）：

1. 若環境變數 `SECURITY_COMPLIANCE_TW_ROOT` 已設定 → 用它
2. 否則若存在 `~/.security-compliance-tw/root` → 讀取該檔單行路徑（plugin 絕對路徑）
3. 否則 fallback：本 `SKILL.md` **所在目錄**往上兩層（`skills/<name>/../..`；仍在 clone 裡開發時才成立）

三者都找不到 `references/` 時，停下來請使用者執行 repo 的 `install.sh`——
**不要憑印象作答**，本 skill 的價值在於答案來自知識庫。

解析出 ROOT 後，讀 `~/.security-compliance-tw/installed.json`；不存在就略過（例如直接在 clone 裡開發）。
其中 `checked_at`（最後一次安裝或檢查更新的日期）距今超過 30 天時，在回覆開頭提醒一句：
「知識庫是 v{version}，上次檢查更新是 {checked_at}；可在 repo 執行 `./install.sh --check` 看看有沒有新版。」
只提醒這一句，接著照常做事。

知識庫路徑一律表述為 `{ROOT}/references/…`。用 Read 工具讀**解析後的絕對路徑**（或開發時 fallback 的明確相對路徑）。

**不要用 shell 的 `cd ../..` 導航**——先解析 ROOT 再 Read。`cd` 是邏輯解析，在 symlink 或已安裝的 skill 目錄下會跑錯地方。

要在 shell 操作時，先解析 ROOT 取得絕對路徑，再用絕對路徑操作。

## 知識庫

全部位於 `{ROOT}/references/`：

| 檔案 | 何時讀 |
|---|---|
| `profile.md` | 步驟 1 與 3，一定要讀 |
| `checks/*.md` | 依 profile 選取，只讀需要的 |
| `scanners.md` | 判讀報告或處理誤判時 |
| `mapping.md` | 排優先序時（看分級欄與附表十欄）；需要標註附表十、檢測基準（`MAS` 欄）或 OWASP 編號時 |
| `scanner-verification-log.md` | 需要說明某條掃描器對照的驗證依據時 |

`controls-appendix10.md`、`controls-mas-v4.md` 與 `templates/` 屬 `sec-deliverables` 的範圍，本 skill 不讀。

**不要一次載入所有 check 檔。**


## 掃描器對照狀態（必讀）

各 check「掃描器怎麼標」表有「狀態」與「證據」欄。引用掃描器涵蓋時必須遵守：

1. **優先引用 `verified`**（必要時含 `partial`）列——這些才有 fixture／報告證據可追
2. **`unverified` = 宣稱對照、尚未校準**——可當提示用，不可當成已實測的規則 ID
3. **禁止捏造** Fortify、Checkmarx、AWVS、WebInspect、Nessus 等商用規則 ID；表上沒有就寫「知識庫尚無已驗證對照」
4. 模式 2 命中 `unverified` 列時，findings 必須註明「**規則名待真實報告確認**」
5. **`unverified` 列的等級不參與優先序**——寫成「可能被標，等級待確認」

操作與回填流程：

- 開源 fixture 實跑：`{ROOT}/tools/verify_scanners.md`
- 商用遮蔽（redacted）報告路徑：`{ROOT}/tools/verify_commercial.md`

回填改的是知識庫本身，要在 repo 的 clone 裡做；**不要改已安裝的快照**——重裝即被覆寫。

## 目前涵蓋範圍

95 則 check，21 個檔：

| 類別 | 檔案 | 載入條件（見 `profile.md`） |
|---|---|---|
| 注入（含 XXE、反序列化、標頭注入） | `sast-injection.md` | 一律 |
| 存取控制 | `sast-authz.md` | 一律 |
| 身分鑑別與 Session | `sast-session-auth.md` | 有登入功能 |
| 密碼學 | `sast-crypto.md` | 分級 ≥ 中／有個資或金流／將面對 SAST |
| 日誌與稽核 | `sast-logging.md` | 一律 |
| 錯誤與例外 | `sast-errors.md` | 一律 |
| 請求濫用（CSRF／SSRF／上傳／Open Redirect） | `sast-request-abuse.md` | 一律 |
| 第三方元件（已知漏洞） | `sast-dependencies.md` | 一律 |
| API 授權 | `sast-api-authz.md` | 有 API 端點 |
| LLM / Agent | `sast-llm.md` | 有 LLM／RAG／Agent |
| HTTP 安全標頭 | `dast-headers.md` | 分級 ≥ 中／對外服務／將面對 DAST |
| TLS 與 Cookie | `dast-tls-cookie.md` | 一律 |
| 資訊外洩 | `dast-info-leak.md` | 一律 |
| MAST 本機儲存／日誌／備份 | `mast-storage.md` | **有行動 App** |
| MAST 密碼學 | `mast-crypto.md` | **有行動 App** |
| MAST 網路與憑證釘選 | `mast-network.md` | **有行動 App** |
| MAST 身分鑑別與生物辨識 | `mast-auth.md` | **有行動 App** |
| MAST 平台介面（IPC／WebView／剪貼簿／螢幕） | `mast-platform.md` | **有行動 App** |
| MAST 輸入驗證與注入防護 | `mast-code.md` | **有行動 App** |
| MAST 抗逆向與竄改（F 類） | `mast-resilience.md` | **有行動 App 且勾選 F 類加測** |
| MDM／EMM／MAM 控制 | `mdm-controls.md` | **有 EMM／MDM／MAM** |

行動端 36 則分於七個依 MASVS 類別命名的檔案；MDM 8 則獨立一檔（規格外的延伸）。
`mast-resilience.md` 全部屬 F 類加測或參考項目，**未勾選 F 類時不要載入**。

行動端有 16 列掃描器對照已對 fixture 實跑驗證（狀態 `verified`，附檔名行號）；
其餘仍為 `unverified`。**商用工具（Fortify／Checkmarx）的行動端對照本知識庫不收錄**，
報告反查時若命中商用規則，直接寫「知識庫尚無已驗證對照」。

**未涵蓋**：備份備援、稽核儲存容量、時戳校時、系統文件、委外管理、
供應鏈完整性、基礎設施加固（GCB / 防火牆 / OS）。

遇到超出範圍的項目時，明確告知使用者「此類別本知識庫尚未涵蓋」，
**不要憑印象生成建議**——本 skill 的價值在於答案來自經過驗證的知識庫。
