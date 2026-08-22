# DAST：HTTP 安全標頭

DAST 掃描器看不到源碼，只看回應標頭。因此本檔的偵測對象是
**設定標頭的那段程式碼或設定檔**，據以預判掃描器會看到什麼。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## DAST-HDR-001 · 缺少 Content-Security-Policy

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| AWVS | Content Security Policy not implemented | Medium |
| ZAP | Content Security Policy (CSP) Header Not Set | Medium |
| WebInspect | Missing Content-Security-Policy Header | Medium |
| Nessus | Missing or Permissive CSP | Medium |
| SecurityHeaders.com | 評分扣分（無 CSP 難以達 A） | — |

### 壞味道

回應中完全沒有 `Content-Security-Policy`，或設成過寬的值：

```go
// 沒有任何 CSP 設定的 handler
func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<html>..."))
}
```

```python
# Flask 未掛任何 after_request 標頭處理
@app.route("/")
def index():
    return render_template("index.html")
```

```javascript
// Express 未使用 helmet 或手動設定標頭
app.get("/", (req, res) => res.send("<html>..."));
```

以下設定值等同沒設，掃描器仍會標記：
`default-src *`、`script-src 'unsafe-inline' 'unsafe-eval' *`、只設 `report-uri`

### 過關寫法

集中在 middleware 一次設定，不要散在各 handler——散開設定會漏，
DAST 只要掃到一個沒有標頭的路徑就會標記。

```go
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'")
		next.ServeHTTP(w, r)
	})
}

// 掛載：mux 外層包一次，涵蓋所有路由
srv := &http.Server{Handler: securityHeaders(mux)}
```

```python
@app.after_request
def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; object-src 'none'; "
        "frame-ancestors 'none'; base-uri 'self'"
    )
    return resp
```

```javascript
const helmet = require("helmet");
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    objectSrc: ["'none'"],
    frameAncestors: ["'none'"],
    baseUri: ["'self'"],
  },
}));
```

### 常見誤判與處置

- **前後端分離、CSP 由前端 CDN 或 Nginx 設定**——掃描器打的是 API 網域，
  該網域回傳 JSON 不需要 CSP，但工具照樣標記。
  處置：對純 API 網域仍設 `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
  ——一行解決，比寫誤判說明省事。

- **CSP 半套被判高風險**——只設部分指令（如未定義 `default-src`）
  會讓工具基於保守假設放大風險。
  處置：**補完而非移除**。至少定義 `default-src`、`object-src`、
  `frame-ancestors`、`base-uri` 四項。

- **必須保留 `'unsafe-inline'`**——舊架構把腳本內嵌在 HTML 中。
  處置：這是真實的架構限制，不是誤判。若無法改為外部腳本，
  在 `false-positives.md` 記錄為「已知風險接受」並註明架構原因，
  同時把其他指令收緊到最嚴，降低整體評分衝擊。

### 判定準則

真問題：任何會回傳 HTML 的路徑，其回應缺少 `Content-Security-Policy`。

真問題：CSP 存在但 `default-src` 未定義，或 `script-src` 含 `*` 萬用來源。

可接受：CSP 完整定義四項核心指令，`'unsafe-inline'` 僅出現在
`style-src` 且有架構原因記錄在案。

---

## DAST-HDR-002 · 缺少 Strict-Transport-Security

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| AWVS | HSTS not enabled | Medium |
| ZAP | Strict-Transport-Security Header Not Set | Low–Medium |
| WebInspect | Missing HSTS Header | Medium |
| Nessus | Missing HSTS | Medium |

### 壞味道

HTTPS 回應中沒有 `Strict-Transport-Security`，或 `max-age` 過短
（低於 31536000 常被標為 weak configuration）。

```go
// 只設了其他標頭，漏掉 HSTS
w.Header().Set("X-Frame-Options", "DENY")
```

```python
resp.headers["X-Frame-Options"] = "DENY"  # 缺 HSTS
```

```javascript
app.use(helmet({ hsts: false }));  // 明確關閉
```

### 過關寫法

```go
w.Header().Set("Strict-Transport-Security",
	"max-age=31536000; includeSubDomains")
```

```python
resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
```

```javascript
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
```

`preload` 視情況加。加了之後要提交到 hstspreload.org，且**很難撤銷**——
子網域全部必須支援 HTTPS，否則會全站無法存取。建議先不鎖太久，
驗證穩定後再拉長。

### 常見誤判與處置

- **服務只在內網以 HTTP 提供**——HSTS 在 HTTP 回應中無效，瀏覽器會忽略。
  掃描器仍可能標記。
  處置：若確實不對外，標記誤判並註明部署範圍；
  但若有任何對外可能，直接改用 HTTPS 並設 HSTS。

- **TLS 由前端負載平衡器終結**——應用程式看到的是 HTTP。
  處置：在 LB 或反向代理層設定標頭，並在佐證中註明設定位置。

### 判定準則

真問題：對外提供 HTTPS 服務，但回應缺少 HSTS 或 `max-age` 小於 31536000。

誤判：純內網 HTTP 服務，且無對外路徑。

---

## DAST-HDR-003 · 缺少 X-Frame-Options 或 frame-ancestors

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| AWVS | Clickjacking: X-Frame-Options header missing | Medium |
| ZAP | Missing Anti-clickjacking Header | Medium |
| WebInspect | Missing X-Frame-Options Header | Medium |
| Nessus | Web Application Potentially Vulnerable to Clickjacking | Medium |

### 壞味道

回應缺少 `X-Frame-Options`，且 CSP 中也沒有 `frame-ancestors`。

```go
w.Header().Set("Content-Security-Policy", "default-src 'self'")  // 缺 frame-ancestors
```

```python
resp.headers["Content-Security-Policy"] = "default-src 'self'"  # 缺 frame-ancestors
```

```javascript
app.use(helmet({ frameguard: false }));
```

`X-Frame-Options: ALLOW-FROM` 已被現代瀏覽器廢棄，設了等於沒設。

### 過關寫法

兩者都設——舊掃描器只認 `X-Frame-Options`，新的認 `frame-ancestors`。

```go
w.Header().Set("X-Frame-Options", "DENY")
w.Header().Set("Content-Security-Policy",
	"default-src 'self'; frame-ancestors 'none'")
```

```python
resp.headers["X-Frame-Options"] = "DENY"
resp.headers["Content-Security-Policy"] = (
    "default-src 'self'; frame-ancestors 'none'"
)
```

```javascript
app.use(helmet.frameguard({ action: "deny" }));
app.use(helmet.contentSecurityPolicy({
  directives: { defaultSrc: ["'self'"], frameAncestors: ["'none'"] },
}));
```

需要允許同源嵌入時用 `SAMEORIGIN` + `frame-ancestors 'self'`；
需要允許特定網域時**只能**用 `frame-ancestors https://partner.example.com`。

### 常見誤判與處置

- **已用 CSP frame-ancestors，但工具只找 X-Frame-Options**——
  舊版 AWVS / Nessus 常見。
  處置：兩個都設，比寫誤判說明省事。

- **該頁面本來就設計為被 iframe 嵌入**（如金流元件、地圖嵌入）。
  處置：設 `frame-ancestors` 明列允許的網域，不要留空。
  留空會被標記，明列則多數工具接受。

### 判定準則

真問題：回傳 HTML 的路徑同時缺少 `X-Frame-Options` 與 CSP `frame-ancestors`。

真問題：使用 `X-Frame-Options: ALLOW-FROM`（已廢棄，無效）。

誤判：已設 `frame-ancestors` 且明列允許來源，僅因工具版本舊而被標記。
