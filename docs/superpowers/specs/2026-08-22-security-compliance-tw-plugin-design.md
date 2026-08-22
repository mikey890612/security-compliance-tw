# security-compliance-tw Plugin 設計規格

日期：2026-08-22
狀態：已與使用者確認，待實作

**本規格的詳細程度**：第 4、5 節（共用知識庫）與 6.1–6.3（skill A）為完整規格，
可直接據以實作。6.4（skill B）與 6.5（skill C）僅為輪廓描述，用以確認架構相容性，
兩者於各自實作前另行撰寫規格。

---

## 1. 背景

台灣政府資訊系統的驗收流程要求通過**源碼掃描（SAST）**與**弱點掃描（DAST）**，
並依「資通安全責任等級分級辦法附表十 資通系統防護基準」逐項查核。

現有的官方指引（7 份 PDF，收錄於本專案根目錄）提供了控制措施與實作建議，但存在三個落差：

1. **語言落差**——指引的程式範例只有 ASP.NET / Java / PHP，本團隊使用 Go / Python / JS。
2. **層級落差**——指引以 Web 應用程式為主，完全未涵蓋 API 層（BOLA / BOPLA / BFLA）
   與 AI 層（Prompt Injection / 過度代理權等）。
3. **工具落差**——指引描述「應如何實作」（給人審查用），但掃描器判定的是
   **污點分析追不追得出來**。程式碼可能實際安全，卻仍被標為 Critical。

## 2. 目的

**讓程式碼通過源碼掃描與弱點掃描，不需要與稽核人員逐項協調。**

這是本 plugin 的唯一北極星。所有設計決策以此為準。

### 2.1 「通過掃描」的定義與界線

「通過」的預設路徑是**真的修好，而且用掃描器追得到的方式修好**。

只有在確認程式碼實際安全、純粹是工具的分析能力追不出來時，才走誤判標記路徑，
並產出佐證供複掃與人工審查使用。

不採用「單純遮蔽掃描結果讓紅字消失」的做法——附表十每一項控制措施的查核方式
都同時要求**自動化工具檢測**與**人工審查**兩項，遮蔽會在人工審查該關破功。
此判定準則需明文寫入每則 check 的「判定準則」欄位。

## 3. 範圍

### 3.1 涵蓋的風險清單

| 清單 | 版本 | 用途 |
|---|---|---|
| 附表十 資通系統防護基準 | 7 大類 29 項 | 法遵基準，決定查核範圍與分級 |
| OWASP Top 10（Web） | 2021 | 現行指引 V3.2 的對應版本 |
| OWASP Top 10（Web） | 2025 | 前瞻補強（新增供應鏈、例外處理；SSRF 併入 A01） |
| OWASP API Security Top 10 | 2023 | 附表十完全未涵蓋的物件級授權缺口 |
| OWASP Top 10 for LLM Apps | 2025 | AI 功能專屬風險 |

> OWASP Top 10:2025 的最終定稿狀態需於實作時至 owasp.org/Top10 核對。

### 3.2 涵蓋的技術棧

Go、Python、JavaScript、CSS、HTML。

每則 check 的「壞味道」與「過關寫法」至少涵蓋 Go / Python / JS 三種；
CSS / HTML 出現在輸出編碼與安全標頭相關的 check 中。

### 3.3 涵蓋的掃描工具

| 類別 | 工具 |
|---|---|
| 商用 SAST | Fortify SCA、Checkmarx |
| 開源 SAST | Semgrep、SonarQube、CodeQL、gosec、bandit |
| DAST / 弱點掃描 | Acunetix WVS、Nessus、OWASP ZAP、HP WebInspect |

每則 check 需記錄各工具的規則名稱與預設風險等級。

### 3.4 非目標

- **不執行任何外部掃描工具。** 掃描由人執行；本 plugin 只做送掃前的預防與送掃後的判讀。
- 不對線上系統實際發動 DAST 探測（指引明定滲透測試須先取得書面授權）。
- 不產生工具專有格式報告（`.fpr`、`.cxsast` 等）。
- 不涵蓋基礎設施層（GCB、防火牆、OS 加固、網路架構）。
- 不做威脅建模自動化——歸 skill C，本期不實作。

## 4. 架構

```
security-compliance-tw/                    ← plugin 根目錄
├── .claude-plugin/plugin.json
├── skills/
│   ├── sec-audit/SKILL.md                 A：掃描前自檢與掃描後判讀
│   ├── sec-harden/SKILL.md                B：開發時直接套用過關寫法
│   └── sec-deliverables/SKILL.md          C：SSDLC 交付文件（最後實作）
└── references/                            ← 三支 skill 共用知識庫
    ├── README.md                          導覽：要查什麼看哪個檔
    ├── profile.md                          分級問答腳本 + 各級適用的 check 集合
    ├── scanners.md                         各工具行為特性與誤判處置慣例
    ├── mapping.md                          check-id → 各清單編號的唯一對照表
    ├── quick-patterns.md                   給 skill B 用的濃縮速查
    ├── controls-appendix10.md              附表十 29 項全文（僅產報告時讀）
    └── checks/
        ├── sast-injection.md               SQLi / OS Command / XSS / 路徑尋訪 / 反序列化
        ├── sast-authz.md                   存取控制、最小權限、越權
        ├── sast-session-auth.md            密碼強度、Session、帳號鎖定、MFA
        ├── sast-crypto.md                  雜湊、加密、金鑰管理、硬編碼憑證
        ├── sast-logging.md                 日誌欄位、敏感資訊、日誌注入
        ├── sast-errors.md                  例外處理、資源釋放、錯誤訊息外洩
        ├── sast-api-authz.md               BOLA / BOPLA / BFLA / 資源耗用無限制
        ├── sast-llm.md                     Prompt injection / 輸出處理 / 過度代理權
        ├── dast-headers.md                 六大 HTTP 安全標頭 + CSP 取捨
        ├── dast-tls-cookie.md              TLS 組態、Cookie 屬性
        └── dast-info-leak.md               錯誤頁、目錄列表、版本標示、備份檔殘留
```

### 4.1 設計原則：偵測與對照分離

`checks/` 內**完全不出現法規編號或 OWASP 編號**，只描述「怎麼偵測、怎麼修」。
所有編號對照集中在 `mapping.md` 一個檔案。

理由：同一個壞味道會同時對映四張清單（例：字串拼接 SQL = 附表十 4.5.3.1 +
Web21 A03 + Web25 A05 + LLM05 + CWE-89）。若在每則 check 內嵌編號，
清單改版時需修改全部 check 檔；集中對照則只需修改一個檔案。

### 4.2 待驗證的實作細節

skill 讀取 plugin 根目錄下的 `references/` 需使用相對路徑（`../../references/…`）。
**實作第一步必須先驗證此路徑在目標環境可讀取。** 若不可行，改為將 `references/`
置於 `skills/sec-audit/` 之下，另外兩支 skill 以相對路徑指向該處。

## 5. 知識庫資料結構

### 5.1 check 檔案格式

每則 check 以穩定的 id 標識，格式為 `{SAST|DAST}-{主題}-{序號}`，例如 `SAST-INJ-001`。

````markdown
## SAST-INJ-001 · SQL 指令注入

### 掃描器怎麼標
| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | SQL Injection | Critical |
| Checkmarx | SQL_Injection | High |
| Semgrep | (規則 id) | ERROR |
| gosec | G201 / G202 | HIGH |
| bandit | B608 | MEDIUM |
| SonarQube | S3649 | Blocker |
| AWVS / ZAP | SQL Injection | High |

### 壞味道
Go / Python / JS 各一段最小可辨識片段，需可直接用於 Grep 樣式比對。

### 過關寫法
Go / Python / JS 各一段，且必須是掃描器規則明確認得的形式。
（例：Go 使用 `db.Query(q, args...)` 而非自製 escape helper——自製 helper
即使實際安全，Fortify 的污點分析也追不出消毒動作。）

### 常見誤判與處置
安全但仍被標記的情境；如何改寫使工具不再標記；何時應正式標記為誤判。

### 判定準則
真漏洞與誤判的分界線，需具體到可據以判斷。
````

### 5.2 mapping.md 格式

單一大表，欄位如下：

| check-id | 附表十 | 普 | 中 | 高 | Web21 | Web25 | API23 | LLM25 | CWE |
|---|---|---|---|---|---|---|---|---|---|
| SAST-INJ-001 | 4.5.3.1 | ◎ | ◎ | ◎ | A03 | A05 | — | LLM05 | CWE-89 |
| SAST-API-001 | —（查檢表外） | | ◎ | ◎ | A01 | A01 | API1 | — | CWE-639 |

附表十無對應項者，明確標記為「缺口」，不得硬湊章節號。
此欄位使使用者得以辨識「掃描器會抓、但驗收查檢表上找不到」的項目。

### 5.3 profile.md 格式

定義分級問答腳本，以及「分級 × 專案特徵 × 語言 → 適用 check 集合」的選取規則。

分級差異範例（高等級才要求）：多重因素身分鑑別、高可用性架構、滲透測試、
機敏資料靜態加密、重要資料雜湊值完整性、自動化流量監控。

## 6. Skill 行為規格

### 6.1 sec-audit（A）

具備兩個模式。判定規則：**使用者提供了掃描報告檔案即為模式 2，否則為模式 1。**
若使用者未明示而情境不明，直接詢問「手上是否已有掃描報告」。

#### 模式 1：送掃之前（預防）

1. **建立 profile**——一次問完，不逐題騷擾：
   - 安全分級：普 / 中 / 高（**每次都問，不推測、不寫設定檔**）
   - 是否對外服務
   - 有無 API 端點（REST / GraphQL / gRPC）
   - 有無 LLM / RAG / Agent 功能
   - 有無個資或金流
   - 已知將面對哪些掃描器（若使用者知道）

2. **偵測技術棧**——讀取 `go.mod` / `requirements.txt` / `package.json`，
   決定語言與框架，選用對應的壞味道樣式。

3. **選定 check 集合**——依 `profile.md` 的規則決定載入哪些 check 檔。
   此步驟為漸進式載入的生效點：普等級純前端專案可能僅載入 3 個檔，
   高等級含 AI 的後端服務可能載入全部 11 個。

4. **樣式比對**——載入 check 檔後，以其中的壞味道樣式在 codebase 中搜尋。
   **不執行任何外部掃描工具。**

5. **逐項判定**——每個命中歸為三類：真漏洞 / 誤判（記錄理由與佐證）/
   不適用（記錄理由）。

6. **修補**——真漏洞依「過關寫法」修改。
   **修改前先列出清單供使用者確認範圍**，不一次變更大量檔案。
   優先序 = 掃描器預設等級 × 專案安全分級。

7. **產出**——見 6.3。

#### 模式 2：拿到掃描報告之後（判讀）

使用者提供已執行的掃描報告（Fortify / Checkmarx / AWVS 等匯出的
csv / html / txt / pdf）。skill 讀取該檔案，不執行任何掃描工具。

1. 解析報告，取得各項發現的規則名稱、等級、檔案位置
2. 以 `checks/` 內的「掃描器怎麼標」欄位反查對應的 check-id
3. 依該 check 的「判定準則」逐項判定真漏洞或誤判
4. 真漏洞依「過關寫法」修補；誤判產出佐證說明
5. 產出——見 6.3

模式 2 預期使用頻率高於模式 1，因為卡驗收時使用者手上必定已有該報告。

### 6.2 DAST 家族的特殊處理

不對系統實際發動探測。改為檢查**決定執行期行為的程式碼與設定**：
middleware 註冊、安全標頭設定、Cookie flags、錯誤處理器、TLS 組態，
據以預判掃描器將觀察到的結果。

### 6.3 產出物

```
security-audit/
├── findings.md          逐項：check-id / 檔案位置 / 判定 / 處置
├── false-positives.md   誤判清單與佐證（供複掃與人工審查使用）
└── checklist.md         附表十勾稽表（選配，經 mapping.md 回貼產生）
```

### 6.4 sec-harden（B）

不掃描整個 codebase。僅在使用者撰寫或修改程式碼時，將該情境適用的
過關寫法套用上去。

讀取 `references/quick-patterns.md`（由 A 的知識庫萃取的濃縮速查），
而非完整 check 檔——寫程式時無法承受載入 29 項全文的 context 成本。

`quick-patterns.md` 的內容應於 A 實作完成後萃取，屆時已知哪些控制措施最常被違反。

### 6.5 sec-deliverables（C）

產出 SSDLC 交付文件：威脅建模結果、需求追溯矩陣（RTM）、安全查檢表、
源碼安全查檢表、委外 RFP 資安需求、安全測試計畫與報告。

本期不實作。實作時可直接消費 A 的產出（findings.md 可轉為查檢表與測試報告）。

## 7. 建置順序

| 順序 | 項目 | 理由 |
|---|---|---|
| 1 | `references/` 知識庫 | 最費工，且三支 skill 全部依賴。價值集中於此 |
| 2 | skill A（sec-audit） | 會逼使知識庫的每一條都寫到可判斷、可定位、可修補的程度；知識庫的含糊處會在此暴露 |
| 3 | skill B（sec-harden） | 需要 A 完成後才知道該萃取哪些內容進速查 |
| 4 | skill C（sec-deliverables） | 不影響掃描結果，優先度最低 |

## 8. 風險與待確認事項

1. **OWASP Top 10:2025 的定稿狀態**——需於實作時核對 owasp.org/Top10。
   若仍為 RC，`mapping.md` 的 Web25 欄位需標註版本狀態。
2. **references 相對路徑可讀性**——見 4.2，實作第一步驗證。
3. **掃描器規則名稱的準確性**——商用工具（Fortify / Checkmarx）的規則名稱
   無公開完整清單，需依實際報告樣本補正。初版可先填寫已確認者，
   未確認者標記為待補。
4. **知識庫規模**——11 個 check 檔 × 每檔數則 × 三語言範例，總量可觀。
   須嚴格遵守漸進式載入，SKILL.md 本身不得內嵌 check 內容。
5. **模式 2 的報告格式多樣性**——各工具匯出格式差異大。初版先支援
   純文字與 CSV，HTML / PDF 視實際樣本再擴充。
