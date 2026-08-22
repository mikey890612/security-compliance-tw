# 過關寫法速查

寫程式當下用的濃縮版。**依情境排序，不依 check-id 排序。**

收錄原則：只收「寫的當下就能預防」的項目。備份備援、稽核容量、
目錄列表、敏感檔案殘留等部署期議題不在此，那些查 `checks/`。

每則格式固定：`✅ 這樣寫` / `❌ 不要這樣寫` / 一句話理由。
理由一律是**為什麼掃描器認得或不認得**，不是「因為比較安全」。

本檔是 `sec-harden` 產出各家 agent 規則檔的唯一內容來源。
新增或修改後需重跑安裝，各專案的規則檔才會更新。

---

## 寫資料庫查詢時

**✅** 用驅動層 placeholder：Go `db.Query(q, args...)`、
Python `cur.execute(q, (a,))`、JS `db.query(q, [a])`
**❌** 字串拼接或格式化組 SQL，包含 `fmt.Sprintf` / f-string / 樣板字面值
**理由** 污點分析對標準函式庫的 placeholder 有內建 cleanse 規則，對自製 escape helper 沒有

**✅** 欄位名或排序方向用白名單 map 轉換，查不到就回錯
**❌** 把使用者傳來的欄位名直接拼進 `ORDER BY`
**理由** 拼接的是 map 的 value（程式內常數），工具可回溯來源

## 寫 HTTP handler 時

**✅** 安全標頭集中在一層 middleware 設定，包住整個 mux
**❌** 在各別 handler 裡分別設定
**理由** DAST 只要掃到一個沒標頭的路徑就標記，分散設定必漏

**✅** 至少設六個標頭：`Content-Security-Policy`、`Strict-Transport-Security`、
`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、
`Referrer-Policy: strict-origin-when-cross-origin`、`Permissions-Policy`
**❌** 只設一兩個，或 CSP 只設 `report-uri`
**理由** CSP 半套會讓工具基於保守假設判成高風險，比沒設更糟

**✅** CSP 至少定義四項：`default-src` `object-src` `frame-ancestors` `base-uri`
**❌** 只寫 `default-src *` 或 `script-src 'unsafe-inline' *`
**理由** 未定義 `default-src` 等同允許任意來源

**✅** Cookie 三個屬性齊備：`Secure` + `HttpOnly` + `SameSite`
**❌** 任一缺漏；`SameSite=None` 卻沒配 `Secure`
**理由** 三者各有獨立掃描規則，缺一報一條

**✅** 查詢或更新資料時，把擁有者條件寫進同一句 WHERE
**❌** 先用 path param 的 id 查出資料，再另外比對擁有者
**理由** 分兩步時工具追不到關聯；同句 WHERE 才能被辨識為授權判斷

**✅** 回應明確列舉欄位（DTO / select 指定欄位）
**❌** 直接序列化整個 model 或 ORM 實體
**理由** 過度暴露；同時避免請求端大量賦值寫入 `isAdmin` 這類欄位

**✅** 輸出 HTML 用會自動跳脫的樣板引擎：Go `html/template`、
Jinja2 開啟 autoescape、React 直接放進 JSX
**❌** Go 的 `text/template`、`|safe`、`mark_safe`、`template.HTML()`、
`innerHTML`、`dangerouslySetInnerHTML`、字串拼 HTML
**理由** 掃描器認的是樣板引擎與跳脫函式；黑名單過濾特殊字元幾乎所有工具都不承認

**✅** 回傳非 HTML 內容時設對 `Content-Type` 並加 `X-Content-Type-Options: nosniff`
**❌** 回傳檔案位元組卻不設 `Content-Type`
**理由** 瀏覽器會猜型別，使用者上傳的 HTML 會被當網頁渲染成儲存型 XSS；
只設 `nosniff` 不設 `Content-Type` 沒有用

## 處理檔案路徑時

**✅** 三步固定樣式：正規化 → 比對根目錄前綴 → 才開檔
**❌** 直接把使用者輸入接在根目錄後面就開檔
**理由** `filepath.Join` 與 `os.path.join` **不擋** `../`，它們只做路徑正規化

**✅** 更穩的做法：使用者傳識別碼，程式查表得到實際檔名
**❌** 讓使用者傳任何形式的路徑
**理由** 污點路徑徹底斷開，多數工具直接不報

## 執行外部命令時

**✅** 參數以 argv 陣列傳入：`exec.Command("convert", f)`、
`subprocess.run([...], shell=False)`、`execFile("convert", [f])`
**❌** 經過 shell：`sh -c`、`shell=True`、`exec()`
**理由** 不經 shell 就沒有 metacharacter 可逃逸，sink 從「shell 命令」降級為「程式參數」

**✅** 外部輸入只能當參數
**❌** 讓外部輸入決定要執行哪個程式（argv[0]）
**理由** 那等於允許執行任意執行檔，不經 shell 也一樣危險

## 處理密碼與金鑰時

**✅** 密碼用 KDF：`bcrypt.GenerateFromPassword`、`argon2.PasswordHasher`、
`scrypt`、`pbkdf2_hmac`（迭代數 600,000 以上）
**❌** MD5 / SHA1 / SHA256 直接雜湊密碼，即使加了 salt
**理由** 掃描器認的是**函式名稱**，sink 換成已知 KDF 呼叫規則就不再命中

**✅** 比對雜湊用常數時間函式：`subtle.ConstantTimeCompare`、
`hmac.compare_digest`、`crypto.timingSafeEqual`
**❌** 用 `==` 比對
**理由** `==` 會被另外標為時序側通道

**✅** 亂數用 `crypto/rand`、`secrets`、`crypto.randomBytes`
**❌** 用 `math/rand`、`random`、`Math.random()` 產生 token 或 salt
**理由** 只要落在安全相關的 sink 就會被標，與實際可預測性無關

**✅** 憑證與金鑰一律從環境變數或密鑰管理服務讀取
**❌** 寫在程式碼、設定檔、測試檔、註解裡
**理由** 硬編碼憑證是規則最單純、最不可能誤判的一類，一定會被抓

**✅** TLS 保持預設驗證
**❌** `InsecureSkipVerify: true`、`verify=False`、`rejectUnauthorized: false`
**理由** 即使只在測試環境，規則不看環境只看程式碼

## 寫日誌時

**✅** 寫入前剝除或轉義換行與控制字元
**❌** 把使用者輸入直接串進日誌訊息
**理由** 可偽造日誌行；這是獨立的 Log Forging 規則

**✅** 記錄使用者識別用內部 ID
**❌** 記錄密碼、token、身分證號、信用卡號、完整個資
**理由** Privacy Violation 規則會依欄位名比對，`password` / `token` 這類命名必中

**✅** 這些事件一定要記：身分鑑別失敗、存取資源失敗、重要資料異動、管理者行為
**❌** 只記錯誤不記安全事件
**理由** 缺少稽核事件是查檢表明列項目，人工審查會抓

## 錯誤處理時

**✅** 回應只給簡短訊息與錯誤代碼，詳細內容寫進日誌
**❌** 把例外訊息、堆疊追蹤、SQL 錯誤原文回給使用者
**理由** DAST 會主動觸發錯誤並比對回應內容

**✅** 檢查每個錯誤回傳值
**❌** Go 的 `_ =` 吞錯、Python 的 `except: pass`
**理由** gosec G104、bandit B110 是規則最單純的一類

**✅** 資源用 `defer Close()` / `with` / `finally` 釋放
**❌** 開了不關，或只在正常路徑關
**理由** Unreleased Resource 是 Fortify 的高頻項目

**✅** 只捕捉預期的例外類型
**❌** `except Exception` / `catch Throwable` / `recover()` 全吞
**理由** 過廣的捕捉會遮蔽真實錯誤，同時被標為 Poor Error Handling

## 設定伺服器時

**✅** `MinVersion: tls.VersionTLS12` 以上，明列允許的 cipher suites
**❌** 用 `ALL`、`HIGH` 這類集合名稱
**理由** 集合內容隨函式庫版本變動，今天過關的組態明天被標

**✅** 關閉 debug 模式、移除 `Server` 與 `X-Powered-By` 標頭
**❌** 上線仍開 `debug=True`、保留預設錯誤頁
**理由** 版本指紋與除錯頁都是 DAST 的被動掃描項目

## 呼叫 LLM 時

**✅** 指令只放 system，資料只放 user 訊息，外部內容包在明確標籤內
**❌** 把使用者輸入或抓來的網頁內容直接串進 prompt 字串
**理由** 指令與資料分離是目前唯一有效的結構性防護

**✅** 包裝外部內容前先剝除結束標籤
**❌** 直接包起來就送
**理由** 否則內容可自行閉合標籤逃逸

**✅** 模型輸出當成不可信輸入處理，經過與使用者輸入相同的驗證
**❌** 把模型輸出直接丟進 SQL / shell / `eval` / `innerHTML` / 檔案路徑
**理由** 這是最會被傳統 SAST 抓到的一類——sink 是標準注入 sink

**✅** 系統提示只放行為指示
**❌** 在系統提示裡放金鑰、內部網址、授權規則
**理由** 系統提示會洩漏；授權判斷必須在模型外部做
