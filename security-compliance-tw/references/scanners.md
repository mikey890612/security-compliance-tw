# 掃描工具行為特性

本檔說明各類掃描器的判定方式與誤判習性，供判讀掃描報告時參考。
**本 plugin 不執行任何掃描工具**——掃描由人執行。

## 商用 SAST

### Fortify SCA
- 判定方式：污點分析（taint analysis），追蹤資料從 source 流向 sink 的路徑。
  另有**不追資料流的結構規則**：`Often Misused: File Upload` 看到 HTML 檔案欄位就報、
  `Weak Cryptographic Hash` 看到弱雜湊呼叫就報，都不看用途
- 等級：Critical / High / Medium / Low，是**逐項計算**的 Fortify Priority
  （衝擊 × 可能性），不是每條規則固定一個等級。結構規則的等級通常穩定；
  污點規則依資料來源可信度浮動——實測 `SQL Injection` 也可以只有 Low。
  各 check 表上的「預設等級」是典型值，**判讀報告時一律以報告上的等級為準**
- 報告欄位：每項有 Category（規則名，例如 `System Information Leak: External`）與
  Kingdom（例如 API Abuse、Encapsulation、Security Features）。
  **反查 check 用 Category 全名，含冒號後的子類別**——
  `Weak Cryptographic Hash: Insecure PBE Iteration Count` 屬金鑰推導，
  只比對冒號前的主類別會錯對到弱雜湊那則
- 掃描範圍：HTML 模板與前端 JS 都會掃，含 `vendor/` 下的第三方套件
- 習性：偏保守，寧可多報。自訂的消毒函式（custom sanitizer）追不出來，
  除非在 Fortify 的 rulepack 中註冊為 cleanse rule——這要能改掃描設定，
  見下方「需要改掃描器設定的處置」
- 誤判處置：在 Audit Workbench 中標記為 Not an Issue 並填寫理由，
  該判定會寫入 `.fpr`，複掃時保留。分析標籤另有 Reliability Issue、
  Bad Practice、Suspicious、Exploitable

### Checkmarx
- 判定方式：以 CxQL 查詢語言對程式碼圖譜（AST + DFG）比對
- 等級：High / Medium / Low / Information
- 習性：對框架的內建防護辨識度較 Fortify 好，但對動態語言誤判偏多
- 誤判處置：於結果介面標記 Not Exploitable，可設定為跨掃描持續
- **LLM preset**：Engine Pack 9.8.0.1001（2026-11-01）新增「OWASP Top 10 for LLM」preset 與 compliance category，
  既有 preset 不變——要看 LLM 類發現須**另選此 preset**。release note 未註明對應 LLM Top 10 的 2025 或 2026 版，
  判讀時以報告上的類別名稱用 `mapping.md` 換算。preset 只涵蓋能用資料流表達的項目（如模型輸出流入注入 sink），
  `checks/sast-llm.md` 標「需人工審查」的項目與代理式 AI 補充檢查仍不會被掃出

## 開源 SAST

| 工具 | 語言 | 判定方式 | 等級 |
|---|---|---|---|
| Semgrep | 多語 | 語法樣式比對（部分規則支援 taint mode） | ERROR / WARNING / INFO |
| SonarQube | 多語 | 規則引擎 + 部分資料流分析 | Blocker / Critical / Major / Minor |
| CodeQL | 多語 | 對程式碼資料庫下 QL 查詢，資料流分析完整 | error / warning / note |
| gosec | Go | AST 規則比對，無跨函式資料流 | HIGH / MEDIUM / LOW |
| bandit | Python | AST 規則比對，無跨函式資料流 | HIGH / MEDIUM / LOW |

gosec 與 bandit 只看單一函式內的樣式，把不安全操作包進 helper 函式就會漏報——
**這代表「gosec 沒報」不等於「Fortify 不會報」**。判讀時以資料流分析工具為準。

CodeQL 2.27.4（2026-11-02）起，`js/redos`、`java/redos`、`cs/redos`、`*/regex-injection` 等查詢移除
`external/cwe/cwe-730` 標籤（MITRE 已禁止以 CWE-730 做弱點對應），其他 CWE 標籤保留。
以 CWE-730 篩選 SARIF 的流程會漏掉 ReDoS 結果——**改用查詢 id 或 CWE-1333 對照**。
來源：https://codeql.github.com/docs/codeql-overview/codeql-changelog/codeql-cli-2.27.4/

CodeQL 2.27.5（2026-11-19）影響判讀的變更（升版後同一份程式碼的結果可能增減，比對前後兩次掃描時要先確認版本）：

- **可能新增結果**：`js/command-line-injection` 開始回報在 `shell` 選項開啟時流入參數陣列（`spawn`／`execFile`）的遠端輸入；
  `isNaN(parseInt(x))`／`isNaN(parseFloat(x))` 不再被當成數字檢查；帶 `m` 或未知旗標、只靠 `^…$` 錨定的正規表示式不再被當成通用消毒——
  過去靠這類檢查「過關」的命令注入、反射型 XSS 會重新被標
- **大小寫不敏感比對**：`java/weak-cryptographic-algorithm`、`java/potentially-weak-cryptographic-algorithm`、`java/rsa-without-oaep`
  改為不分大小寫比對演算法與模式名稱（如 `AES/cbc/Pkcs5Padding`），改大小寫無法再躲過
- **可能減少結果**：Java 污點查詢把「與固定字串常數做（不分大小寫的）相等比較」視為消毒；`java/ssrf`、`java/unvalidated-url-redirection`
  也認得 `URI.getHost()` 對固定字串集合的允許清單比對（含先轉大小寫）——這是被認可的過關寫法
- **MCP／LLM 來源**：JS／TS（`@modelcontextprotocol/sdk`、`@modelcontextprotocol/server`、`fastmcp`）與 Python（`mcp`、`fastmcp`）
  的 MCP tool／resource／prompt handler 參數成為選用 `ai` threat model 的來源；SDK 傳入的 HTTP 標頭與 bearer token 屬 `remote` 來源。
  要讓 CodeQL 追蹤 LLM 產生的參數流向 sink，需在分析設定啟用 `ai` threat model（預設不啟用）
- 新增 `rust/unsafe-deserialization`；`py/tarslip` 修正 `extract`／`extractall` 參數位置（減少誤判）

來源：https://codeql.github.com/docs/codeql-overview/codeql-changelog/codeql-cli-2.27.5/

## DAST / 弱點掃描

| 工具 | 觀察對象 |
|---|---|
| Acunetix WVS | HTTP 回應標頭、錯誤頁內容、表單注入回應、Cookie 屬性 |
| Nessus | 服務版本指紋、TLS 組態、已知 CVE |
| OWASP ZAP | 同 AWVS，另含被動掃描規則 |
| HP WebInspect | 同 AWVS |

DAST 完全看不到源碼，只看執行期表現。因此 DAST 家族的 check
偵測的是**決定執行期行為的程式碼與設定**：middleware 註冊順序、
標頭設定、Cookie flags、錯誤處理器、TLS 組態。

## 誤判處置的共同原則

標記誤判前必須確認兩件事，缺一不可：

1. **風險實際已被消除，只是掃描器看不出來**——以下任一成立：
   來源不可控（常數、列舉、已通過允許清單）；路徑上有有效的消毒或參數化
   （含框架的自動跳脫）；要求的控制確實存在於工具看不到的地方（中介層、接收端
   handler、框架設定）
2. **有具體佐證**可寫入 `false-positives.md`：檔案位置與行號——資料來源、消毒點或控制所在

缺一即視為真漏洞處理。「應該沒事」「只在內網」不是佐證。

## 需要改掃描器設定的處置

本知識庫**預設掃描由第三方執行**（政府驗收常見），開發團隊碰不到規則庫與掃描設定。
因此註冊 cleanse rule、調整規則等級、排除路徑這類處置一律標「選配」，只在你們自己執行掃描時適用。

主路徑一律是程式碼做得到的事：照各 check 的過關寫法改；改完仍會被標的，判誤判，
佐證（含實際輸出樣本）寫進 `false-positives.md`，交給掃描方或審查者判讀。

## 第三方程式碼的發現

SAST 會掃到專案內附的第三方套件（`vendor/`、`assets/vendor/`、`static/lib/` 等）。
這些發現**不要直接改套件檔**——下次升級就被覆蓋，改過的地方也無從追蹤。

風險已被接收端或伺服器端的控制消除的（例如接收端已驗 CSRF token、伺服器錯誤回應皆為常數——
含前端代理或 LB 的錯誤頁；代理錯誤頁在 repo 以外看不到時，先列「待使用者執行」請使用者提供設定），
**直接判誤判**，佐證寫套件名稱、版本、觸發的預設行為與替代控制的位置。
風險確實存在的，依下列順序處置：

1. **升級套件**——新版可能已修，或提供設定關掉有問題的預設行為
2. **用設定覆寫**——例如以自訂的上傳 handler 取代套件預設的 `XMLHttpRequest`，
   sink 移進自己的程式碼，再照對應 check 的過關寫法寫
3. 以上都不行，就在自己的程式碼補上替代控制（例如接收端驗證），補完後依上一段判誤判

**不要自行把 vendor 目錄排除在掃描範圍外。** 掃描範圍由驗收方決定；
自行排除等同遮蔽結果，人工審查時會被追問。

## 各工具的誤判標記方式

| 工具 | 標記方式 | 是否跨掃描保留 |
|---|---|---|
| Fortify | Audit Workbench 標記 Not an Issue | 是，存於 `.fpr` |
| Checkmarx | 結果介面標記 Not Exploitable | 是，可設定 |
| Semgrep | 程式碼加 `# nosemgrep` 註解，或 `.semgrepignore` | 是 |
| SonarQube | 介面標記 Won't Fix / False Positive | 是 |
| gosec | 程式碼加 `#nosec G201` 註解 | 是 |
| bandit | 程式碼加 `# nosec` 註解，或 `.bandit` 設定 | 是 |
| AWVS / ZAP | 掃描設定中排除該規則或路徑 | 視設定 |

**在程式碼中加抑制註解時，一律附上理由**，例如：

```go
// #nosec G201 -- col 來自 allowedSort 白名單的 value，非使用者輸入
rows, err := db.Query("SELECT * FROM users ORDER BY " + col)
```

```python
# nosec B608 - 欄位名來自 ALLOWED_SORT 常數字典，已驗證
cur.execute(f"SELECT * FROM users ORDER BY {col}")
```

沒有理由的抑制註解，在人工審查時會被要求說明，等於沒省到事。
