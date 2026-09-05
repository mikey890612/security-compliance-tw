# DAST：資訊外洩

DAST 掃描器看不到源碼，只看執行期的回應內容、狀態碼與可存取的路徑。
因此本檔的偵測對象是**決定執行期行為的那段程式碼或設定**，據以預判掃描器會看到什麼。
這一類幾乎都是「部署與設定」的問題，而不是程式邏輯的問題——
同一份程式碼，換個環境變數或換個 Dockerfile 就會從乾淨變成一片紅字。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## DAST-LEAK-001 · 詳細錯誤頁與堆疊追蹤外洩

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| AWVS | Application error message | Medium | unverified | — |
| AWVS | Possible server path disclosure | Low | unverified | — |
| ZAP | Application Error Disclosure | Medium | unverified | — |
| ZAP | Information Disclosure - Debug Error Messages | Low | unverified | — |
| WebInspect | Web Server Misconfiguration: Server Error Message | Medium | unverified | — |
| Nessus | —（一般 Web 掃描少涵蓋，主要靠 AWVS / ZAP 觸發） | — | unverified | — |

掃描器的觸發方式是**主動送壞資料**：型別錯誤的參數、超長字串、單引號、
不存在的路由、畸形 JSON。只要有一條路徑回應含堆疊或框架除錯頁就成立。

### 壞味道

除錯模式在生產環境開啟：

```python
# Flask：debug=True 會回傳 Werkzeug 互動式除錯頁，
# 含完整堆疊、原始碼片段，甚至可執行的 console
app.run(host="0.0.0.0", port=8080, debug=True)

# Django 同理
DEBUG = True
```

```javascript
// Express：未掛自訂錯誤處理，預設 error handler 在
// NODE_ENV !== "production" 時會把 err.stack 寫進回應主體
app.get("/item", (req, res) => {
  throw new Error(db.lookup(req.query.id));
});

// 更糟的是自己回傳堆疊
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});
```

```go
// 直接把 error 內容回給客戶端——error 常含 SQL 語句、
// 連線字串、絕對檔案路徑
if err != nil {
	http.Error(w, err.Error(), http.StatusInternalServerError)
	return
}

// 自製 recover 把堆疊寫進回應
defer func() {
	if r := recover(); r != nil {
		fmt.Fprintf(w, "panic: %v\n%s", r, debug.Stack())
	}
}()
```

被判定為外洩的內容包含：函式名與行號、絕對檔案路徑、SQL 語句、
框架與語言版本、環境變數、內部 IP 與主機名稱。

### 過關寫法

原則是**堆疊只進日誌，回應只給關聯 ID**。使用者拿到的是一組 ID，
需要追查時拿 ID 去查日誌——掃描器看不到任何內部資訊，維運能力也沒有損失。

```go
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				id := uuid.NewString()
				log.Printf("trace_id=%s panic=%v\n%s", id, rec, debug.Stack())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "internal error", "trace_id": id,
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// 一般錯誤同樣不要外傳 err.Error()
if err != nil {
	id := uuid.NewString()
	log.Printf("trace_id=%s err=%v", id, err)
	writeJSONError(w, http.StatusInternalServerError, "internal error", id)
	return
}
```

```python
import logging, uuid
from flask import jsonify

# 生產環境一律由環境變數決定，且預設為關閉
app.run(host="0.0.0.0", port=8080, debug=os.getenv("APP_DEBUG") == "1")

@app.errorhandler(Exception)
def handle_error(e):
    trace_id = str(uuid.uuid4())
    logging.exception("trace_id=%s", trace_id)
    return jsonify(error="internal error", trace_id=trace_id), 500
```

```javascript
// 必須是四個參數，Express 才認得這是 error handler
app.use((err, req, res, next) => {
  const traceId = crypto.randomUUID();
  console.error(traceId, err);
  res.status(500).json({ error: "internal error", traceId });
});

// 同時確認容器啟動時 NODE_ENV=production
```

錯誤處理 middleware 要掛在**所有路由之後**，且 404 也要走自訂頁面——
框架預設的 404 頁常帶版本字串，會另外觸發 DAST-LEAK-003。

### 常見誤判與處置

- **回應含欄位名稱的驗證錯誤被標記**——例如
  `{"error":"field 'email' must be a valid address"}`。
  這是給呼叫端看的正常合約，但關鍵字比對會命中 "error"。
  處置：確認回應不含堆疊框、檔案路徑、SQL 片段後標記誤判，
  佐證附上實際回應主體全文。

- **錯誤頁由上游反向代理產生**——應用程式回 502，Nginx / ALB 送出
  預設錯誤頁並帶 `Server: nginx/1.24.0`。
  處置：這不是應用程式的問題，但也不是誤判。在代理層設定
  `error_page` 指向自訂靜態頁，並關閉 `server_tokens`。

- **測試環境掃描結果被拿來要求生產環境改**——測試機刻意開 debug。
  處置：不要當誤判處理。把 debug 開關改成讀環境變數且**預設關閉**，
  重掃生產環境；只要開關寫死在程式碼裡，遲早會誤上生產。

- **框架回傳的 405 / 415 預設頁**——含框架名稱但無堆疊。
  處置：屬 DAST-LEAK-003 範疇，改由自訂錯誤處理接管即可一併解決。

### 判定準則

真問題：任一回應主體含以下任一項——堆疊框（含函式名或行號）、
伺服器絕對檔案路徑、SQL 語句、連線字串、環境變數內容、內部 IP。

真問題：生產環境回應中出現框架互動式除錯介面（Werkzeug debugger、
Django 黃色錯誤頁、Rails 錯誤頁）——這類介面本身即可被利用。

可接受：回應僅含通用訊息與關聯 ID，且詳細內容僅寫入伺服器日誌。

---

## DAST-LEAK-002 · 目錄列表開啟

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| AWVS | Directory listing | Low | unverified | — |
| ZAP | Directory Browsing | Medium | unverified | — |
| Nessus | Browsable Web Directories | Medium | unverified | — |
| WebInspect | Directory Listing | Medium | unverified | — |

### 壞味道

Go 標準函式庫的 `http.FileServer` **預設就會列出目錄內容**，
這是最容易踩到的一個：

```go
// 存取 /static/ 會列出整個目錄，含檔名與時間
http.Handle("/static/", http.StripPrefix("/static/",
	http.FileServer(http.Dir("./static"))))
```

```python
# SimpleHTTPRequestHandler 的 list_directory 會產生完整清單
handler = http.server.SimpleHTTPRequestHandler
http.server.HTTPServer(("0.0.0.0", 8080), handler).serve_forever()
```

```javascript
// serve-index 就是專門做目錄列表的 middleware，
// 掛上去等於明確開啟
const serveIndex = require("serve-index");
app.use("/files", express.static("public"), serveIndex("public"));
```

伺服器設定層面的等價寫法：Nginx 的 `autoindex on;`、
Apache 的 `Options +Indexes`、IIS 的 Directory Browsing 功能啟用。

### 過關寫法

Go 沒有現成開關，要包一層檔案系統把「開啟目錄」這個動作擋掉：

```go
type noDirFS struct{ fs http.FileSystem }

func (n noDirFS) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st.IsDir() {
		// 若該目錄有 index.html 才放行，否則等同 404
		if _, err := n.fs.Open(filepath.Join(name, "index.html")); err != nil {
			f.Close()
			return nil, os.ErrNotExist
		}
	}
	return f, nil
}

http.Handle("/static/", http.StripPrefix("/static/",
	http.FileServer(noDirFS{http.Dir("./static")})))
```

```python
# 不要用 SimpleHTTPRequestHandler 對外服務。
# 改由 WSGI 應用只提供明確的檔案路由
@app.route("/files/<name>")
def download(name):
    if name not in ALLOWED_FILES:
        abort(404)
    return send_from_directory(FILES_DIR, name)
```

```javascript
// express.static 本身不列目錄；不要加 serve-index。
// 目錄請求沒有 index 檔時直接落到 404
app.use("/files", express.static("public", {
  index: false,
  dotfiles: "deny",
  fallthrough: true,
}));
```

設定層一併關閉：Nginx `autoindex off;`（預設即為 off，重點是別開）、
Apache `Options -Indexes`。應用層與伺服器層兩邊都要確認，
因為 DAST 打到的是最終效果，只要有一層開著就會被標。

### 常見誤判與處置

- **自製的檔案清單頁被當成目錄列表**——業務上刻意提供的下載索引頁，
  由程式產生 HTML 清單。工具依「以 `/` 結尾 + 頁面含多個檔案連結」判定。
  處置：確認清單內容經權限過濾（不同使用者看到不同結果）後標記誤判，
  佐證寫明產生清單的 handler 位置與權限檢查行號。
  若清單未經權限過濾就不是誤判。

- **回應 403 但工具仍標記**——關掉列表後改回 403 Forbidden，
  部分工具把 403 視為「目錄存在」而降級保留告警。
  處置：改回 404，讓目錄存在與否無法區分，告警通常會消失。

- **只有部分路徑被關掉**——`/static/` 已處理，但 `/uploads/`
  由另一段程式碼掛載仍會列表。
  處置：不是誤判。逐一列出所有靜態檔案掛載點確認，
  DAST 只要掃到一個就成立。

### 判定準則

真問題：任一 URL 以 `/` 結尾，回應為伺服器或框架**自動產生**的檔案清單
（典型特徵：Parent Directory 連結、Name / Last modified / Size 欄位、
`Index of /...` 標題）。

真問題：目錄列表雖然只含無敏感內容的靜態圖檔，但仍完整揭露檔名結構——
這仍是真問題，因為檔名本身即為攻擊面資訊。

誤判：清單由應用程式產生且已依使用者權限過濾內容。

---

## DAST-LEAK-003 · 版本與技術指紋外洩

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| AWVS | Version disclosure | Informational | unverified | — |
| ZAP | Server Leaks Version Information via 'Server' HTTP Response Header Field | Low | unverified | — |
| ZAP | Server Leaks Information via 'X-Powered-By' HTTP Response Header Field(s) | Low | unverified | — |
| Nessus | HTTP Server Type and Version | Info | unverified | — |
| WebInspect | — | — | unverified | — |

這一類本身等級低，真正的麻煩在於**Nessus 會拿橫幅版本去比對已知漏洞資料庫**，
把一個 Info 等級的指紋放大成一串 High / Critical 的版本漏洞告警。
移除版本字串不只是消一條 Info，是消掉一整批衍生告警。

### 壞味道

```javascript
// Express 預設就會送 X-Powered-By: Express
const app = express();
app.get("/", (req, res) => res.send("ok"));
```

```python
# Flask / Werkzeug 預設 Server: Werkzeug/3.0.1 Python/3.11.6
# 直接用內建開發伺服器對外服務，版本全都露
app.run(host="0.0.0.0", port=8080)
```

```go
// Go 標準函式庫預設不送 Server 標頭，但手動加上版本就是自找麻煩
w.Header().Set("Server", "myapp/1.4.2 (go1.21.3)")
w.Header().Set("X-Api-Version", "1.4.2-build9271")
```

其他常見指紋來源：Nginx / Apache 的 `Server` 完整版本、
PHP 的 `X-Powered-By: PHP/8.1.2`、ASP.NET 的 `X-AspNet-Version`
與 `X-AspNetMvc-Version`、框架預設 404 / 500 頁面上的版本字樣、
`/favicon.ico` 與預設歡迎頁的雜湊指紋。

### 過關寫法

```javascript
app.disable("x-powered-by");
// 或 helmet 內含此項
app.use(helmet());
```

```python
# 不要用開發伺服器對外。用 gunicorn / uvicorn 並覆寫 Server 標頭
@app.after_request
def strip_fingerprint(resp):
    resp.headers["Server"] = "server"
    resp.headers.pop("X-Powered-By", None)
    return resp
```

```go
func stripFingerprint(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "server")
		w.Header().Del("X-Powered-By")
		next.ServeHTTP(w, r)
		// 注意：標頭必須在 WriteHeader 之前設定才會生效
	})
}
```

反向代理層一併處理，因為多數情況下最終的 `Server` 標頭是由代理送出的：
Nginx `server_tokens off;`（只會縮成 `nginx`，要完全移除需
`headers_more` 模組的 `more_clear_headers Server;`）、
Apache `ServerTokens Prod` + `ServerSignature Off`。

自訂 404 / 500 頁也要一併換掉，否則版本會從錯誤頁的頁尾漏出去。

### 常見誤判與處置

- **`Server: server` 或 `Server: nginx` 仍被標記**——部分工具只要
  存在 `Server` 標頭就報 Info，不論有無版本號。
  處置：確認標頭值不含任何版本數字後標記誤判；
  若稽核方仍要求清空，用 `headers_more` 完全移除該標頭。

- **版本漏洞告警其實是誤判，但橫幅讓它成立**——發行版套件常
  backport 安全修補而不改版本號，Nessus 依橫幅判定為易受攻擊。
  處置：這是**兩件事**。版本漏洞告警可依套件變更紀錄標記誤判；
  但橫幅外洩本身要修，否則每次重掃都要重寫一次誤判說明。

- **API 回應的 `X-Api-Version` 是客戶端相依的合約**——移除會壞掉前端。
  處置：改為只回主版本號（`v1`）而非完整建置編號，
  合約仍在但指紋價值歸零。

### 判定準則

真問題：任一回應標頭含產品名稱**加上**版本號
（`Server`、`X-Powered-By`、`X-AspNet-Version`、自訂版本標頭皆算）。

真問題：預設錯誤頁或歡迎頁上出現框架名稱與版本字樣。

可接受：`Server` 標頭存在但值為不含版本的通用字串，
且錯誤頁已全數自訂。

---

## DAST-LEAK-004 · 敏感檔案殘留可被存取

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| AWVS | Possible sensitive files / Possible sensitive directories | Medium | unverified | — |
| AWVS | Possible backup file | Medium–High | unverified | — |
| ZAP | `.env` Information Leak | High | unverified | — |
| ZAP | Hidden File Finder | Medium | unverified | — |
| ZAP | Backup File Disclosure | Medium–High | unverified | — |
| ZAP | Source Code Disclosure | High | unverified | — |
| Nessus | Backup Files Disclosure | Medium | unverified | — |
| WebInspect | — | — | unverified | — |

Swagger / OpenAPI 文件未授權公開通常沒有專屬規則，
而是被檔案與路徑列舉規則（Hidden File Finder、Possible sensitive files）
以 `/swagger.json`、`/v2/api-docs`、`/openapi.json` 等常見路徑掃出。

### 壞味道

根源幾乎都在「把整個專案目錄當成靜態根目錄」或「把整個 repo 包進映像檔」：

```javascript
// 專案根目錄整個對外——.git、.env、package.json、原始碼全都拿得到
app.use(express.static(__dirname));

// Swagger 無條件掛載，生產環境也開著、也沒有認證
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDoc));
```

```python
# static_folder 指到專案根
app = Flask(__name__, static_folder=".", static_url_path="")
```

```go
// 服務目前工作目錄——等同把整個部署目錄公開
r.PathPrefix("/").Handler(http.FileServer(http.Dir("./")))
```

```dockerfile
# 沒有 .dockerignore 的情況下，.git/ 與 .env 會一起進映像檔
COPY . .
```

其他常見殘留：`config.php.bak`、`web.config.old`、`index.jsp~`、
`db_dump.sql`、`backup.zip`、`src.tar.gz`、`.DS_Store`、
`.svn/`、`.idea/`、`composer.lock` 與 `yarn.lock` 之外的內部設定檔。
`.git/` 尤其嚴重——只要 `/.git/config` 與 `/.git/HEAD` 可取得，
就能還原整份原始碼與歷史提交中的憑證。

### 過關寫法

```javascript
// 只服務建置產物，不服務專案根；並明確拒絕 dotfiles
app.use(express.static(path.join(__dirname, "dist"), {
  dotfiles: "deny",
  index: ["index.html"],
}));

// Swagger 依環境開關，且加上認證
if (process.env.ENABLE_API_DOCS === "1") {
  app.use("/api-docs", requireAuth, swaggerUi.serve, swaggerUi.setup(doc));
}
```

```python
app = Flask(__name__, static_folder="dist", static_url_path="/static")

# 文件端點同樣受控
if os.getenv("ENABLE_API_DOCS") == "1":
    app.register_blueprint(docs_bp, url_prefix="/api-docs")
```

```go
// 只掛建置產物目錄，並沿用 DAST-LEAK-002 的 noDirFS
http.Handle("/", http.FileServer(noDirFS{http.Dir("./dist")}))
```

部署管線一併處理，這比程式碼層更關鍵：

```
# .dockerignore
.git
.env
*.bak
*.old
*~
*.sql
*.zip
node_modules
```

反向代理再補一道，攔掉所有 dotfile 與備份副檔名：

```
location ~ /\.(?!well-known) { return 404; }
location ~* \.(bak|old|orig|save|swp|sql|tar|gz|zip)$ { return 404; }
```

三層都做——應用程式只服務 `dist`、映像檔不含敏感檔、代理層再擋一次。
任何一層單獨都有繞過的可能。

### 常見誤判與處置

- **soft 404 造成的大量誤報**——SPA 的 catch-all 路由對
  `/.env`、`/backup.zip` 都回傳 200 加 `index.html`。
  掃描器看到 200 就判定檔案存在，一次報出數十筆。
  處置：這是**設定問題不是誤判**。讓不存在的靜態資源回傳真正的 404，
  catch-all 只套用在應用程式路由前綴上。修好之後告警整批消失。

- **`.env.example` 被當成 `.env`**——範本檔內容全是佔位字串。
  處置：確認檔案內無真實憑證後標記誤判，佐證附上檔案完整內容；
  但仍建議移出可存取目錄，避免每次掃描都要重寫一次說明。

- **Swagger 為刻意公開的開發者文件**——對外 API 的公開文件站。
  處置：先確認文件中**未列出內部管理端點、未含測試金鑰、
  未含內網位址**，符合才標記誤判。只要文件同時描述了內部端點，
  就不是誤判，要拆成公開版與內部版兩份規格。

- **備份檔在 web root 外但工具仍報**——工具依路徑猜測回報，
  實際請求回 404。
  處置：確認回應狀態碼與主體後標記誤判，佐證附上原始 HTTP 回應。

### 判定準則

真問題：未經認證即可取得且回應為 200 並含**實際內容**的以下任一項——
`/.git/HEAD`、`/.git/config`、`/.env`、`*.bak`、`*.old`、`*~`、
`*.sql`、`*.zip`、`*.tar.gz`、`/.svn/entries`。

真問題：API 規格文件未經認證可取得，且其中列出僅供內部使用的端點、
內網位址或任何憑證樣本。

誤判：請求實際回傳 404，或取得的是內容僅含佔位字串的範本檔。

灰色地帶——**一律當真問題修**：檔案存在但需要猜測完整檔名才能取得
（如 `backup_20260318.zip`）。檔名不是存取控制。
