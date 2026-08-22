# AGENTS.md

本專案的 agent 工作規範。

<!-- BEGIN sec-harden v0.1.0 — 由 security-compliance-tw 的 quick-patterns.md 產生。
     請勿直接編輯本區塊內容，重跑安裝器即可更新。 -->

## 安全撰寫規範（Go）

原則：**不只是寫得安全，還要寫成掃描器追得出來的形式。**
污點分析對標準函式庫的消毒有內建規則，對自製 helper 沒有。

### 資料庫查詢
- ✅ `db.Query("... WHERE name = ?", name)`
- ❌ 字串拼接或 `fmt.Sprintf` 組 SQL — placeholder 才有 cleanse 規則（gosec G201/G202）
- ✅ 欄位名用白名單 map 轉換，查不到回錯
- ❌ 使用者傳的欄位名直接拼進 `ORDER BY`

### HTTP handler
- ✅ 安全標頭集中在一層 middleware 包住整個 mux，六個標頭一次設完
- ❌ 各 handler 分別設定 — DAST 掃到一條沒標頭的路徑就標記，分散必漏
- ✅ CSP 至少定義 `default-src` `object-src` `frame-ancestors` `base-uri`
- ❌ 只設 `default-src *` 或只設 `report-uri` — 半套會被判成高風險，比沒設更糟
- ✅ Cookie 三屬性齊備：`Secure` `HttpOnly` `SameSite`
- ❌ 用 `SameSiteDefaultMode` — 不會輸出屬性，等於沒設
- ✅ 擁有者條件寫進同一句 WHERE：`WHERE id = ? AND owner_id = ?`
- ❌ 先查出資料再另外比對擁有者 — 分兩步工具追不到關聯
- ✅ 回應用明確列舉欄位的 DTO
- ❌ 直接序列化 ORM 實體 — 過度暴露，且請求端可寫入不該寫的欄位
- ✅ 輸出 HTML 用 `html/template`（會依上下文自動跳脫）
- ❌ `text/template`、`template.HTML()`、`fmt.Fprintf(w, "<div>%s</div>", x)` — 掃描器認的是樣板引擎，黑名單過濾特殊字元不被承認
- ✅ 回傳非 HTML 內容時設對 `Content-Type` 並加 `X-Content-Type-Options: nosniff`
- ❌ 回傳檔案位元組卻不設 `Content-Type` — 瀏覽器會猜型別，上傳的 HTML 會被當網頁渲染成儲存型 XSS

### 檔案路徑
- ✅ 三步固定順序：`filepath.Clean` → `strings.HasPrefix` 比對根目錄 → 才開檔
- ❌ `os.ReadFile(root + userInput)` — **`filepath.Join` 不擋 `../`**，只做正規化
- ✅ 更穩：使用者傳識別碼，程式查表得檔名 — 污點路徑斷開，多數工具不報

### 外部命令
- ✅ `exec.Command("convert", userFile, "out.png")`
- ❌ `exec.Command("sh", "-c", ...)` — 經 shell 才有 metacharacter 可逃逸（gosec G204）
- ❌ 讓外部輸入決定執行哪個程式（argv[0]）— 不經 shell 也一樣危險

### 密碼與金鑰
- ✅ `bcrypt.GenerateFromPassword` / `argon2.IDKey` / `scrypt.Key`
- ❌ `sha256` 直接雜湊密碼，即使加 salt — 掃描器認的是函式名稱
- ✅ 比對用 `subtle.ConstantTimeCompare` 或 `bcrypt.CompareHashAndPassword`
- ❌ 用 `==` 比對雜湊 — 會被另外標為時序側通道
- ✅ 亂數用 `crypto/rand`
- ❌ 用 `math/rand` 產生 token / salt / session id（gosec G404）
- ✅ 憑證金鑰從環境變數或密鑰管理服務讀取
- ❌ 寫在程式碼、設定檔、測試檔、註解裡（gosec G101，最不可能誤判的一類）
- ❌ `InsecureSkipVerify: true`，即使只在測試環境 — gosec G402 不看環境

### 日誌
- ✅ 寫入前轉義 `\n` `\r` `\x1b` 並截長
- ❌ 使用者輸入直接串進日誌 — 可偽造日誌行（Fortify Log Forging、SonarQube S5145）
- ❌ 記錄密碼、token、身分證號、信用卡號 — Privacy Violation 依欄位名比對
- ✅ 四類事件必記：身分鑑別失敗、存取資源失敗、重要資料異動、管理者行為
- ⚠ 這四類**沒有任何掃描器會報**，但人工複核會要求補件

### 錯誤處理
- ✅ `if err != nil { log; http.Error(w, "internal server error", 500); return }`
- ❌ `rows, _ := db.Query(q)` 後接 `defer rows.Close()` — err 非 nil 時 rows 為 nil 會 panic
- ❌ 改寫成 `_ =` 不是解法 — errcheck `-blank` 與 Fortify 照樣標
- ✅ 回應只給簡短訊息與代碼，詳細寫進日誌
- ❌ 把 `err.Error()` 或堆疊回給使用者 — DAST 會主動觸發錯誤比對回應
- ✅ 資源 `defer Close()` 且放在 err 檢查**之後**

### 伺服器設定
- ✅ `MinVersion: tls.VersionTLS12`，明列 AEAD cipher suites
- ❌ 用 `ALL` / `HIGH` 集合名稱 — 內容隨版本變動，今天過關明天被標
- ⚠ 不要加 `PreferServerCipherSuites` — Go 1.17 棄用、1.18 起被完全忽略

完整版（含掃描器規則名稱、誤判處置、判定準則）見
security-compliance-tw plugin 的 `references/checks/`。

<!-- END sec-harden -->

## 專案自訂規則（使用者手寫，重裝不應被動到）
- 一律使用 tabs 縮排
