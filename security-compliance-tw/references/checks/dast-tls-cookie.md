# DAST：TLS 與 Cookie 屬性

DAST 掃描器看不到源碼，只看 `Set-Cookie` 的字面內容與 TLS 交握的結果。
因此本檔的偵測對象是**決定執行期行為的那段程式碼或組態**——
發 Cookie 的那行、session 中介層的設定、`tls.Config` 或反向代理的
TLS 區塊——據以預判掃描器會看到什麼。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## DAST-COOKIE-001 · Cookie 缺少 Secure 屬性

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| AWVS | Session Cookie without Secure flag set | Medium |
| ZAP | Cookie Without Secure Flag（pscan 10011） | Low |
| Nessus | Web Application Cookies Are Not Marked Secure | Medium |
| WebInspect | Cookie Security: Cookie Not Sent Over SSL | Medium |

### 壞味道

`Set-Cookie` 中沒有 `Secure`。掃描器是逐條解析 `Set-Cookie` 字串，
**每一條**都會被個別檢查，漏一條就標一條。

```go
// 手動組 Cookie，只給了名稱與值
http.SetCookie(w, &http.Cookie{
	Name:  "session_id",
	Value: sid,
	Path:  "/",
})
```

```python
# Flask：預設 SESSION_COOKIE_SECURE 為 False
app.config["SESSION_COOKIE_SECURE"] = False

# 手動 set_cookie 未帶 secure
resp.set_cookie("session_id", sid)
```

```javascript
// express-session：cookie 區塊未設 secure
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { maxAge: 3600000 },
}));
```

以下情形等同沒設，掃描器照樣標記：
`Secure` 只加在登入那條 Cookie、其餘（語系、追蹤、CSRF token）沒加；
或在程式碼裡用 `if isProd` 之類的旗標控制，而掃描環境剛好走到 false 分支。

### 過關寫法

在**發 Cookie 的唯一出口**設定，不要每個 handler 各寫一次。
散開寫必漏，DAST 只要抓到一條沒有 `Secure` 的 `Set-Cookie` 就標記。

```go
// 統一的 Cookie 產生函式，全站只走這裡
func setSessionCookie(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sid,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
```

```python
# Flask：設定檔一次到位，涵蓋 session cookie
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Django settings.py
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

```javascript
app.set("trust proxy", 1);  // 位於反向代理後方時必加，否則 secure cookie 不會送出
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: "lax", maxAge: 3600000 },
}));
```

不要用環境變數決定 `Secure` 開關。本機開發要測 HTTPS 就給本機一張
自簽憑證，比留一個「非正式環境不設 Secure」的分支安全——那個分支
會被掃描器踩到，也遲早會被誤帶上正式環境。

### 常見誤判與處置

- **TLS 由負載平衡器終結，應用程式收到的是 HTTP**——框架看到
  `request.is_secure == False`，於是自動略過 `Secure` 屬性
  （Flask 與 express-session 都有這個行為）。
  這不是誤判，是**真的沒送出**，掃描器抓得到。
  處置：Go 直接寫死 `Secure: true`；Express 加 `app.set("trust proxy", 1)`；
  Django 設定 `SECURE_PROXY_SSL_HEADER`，並確認 LB 有帶
  `X-Forwarded-Proto`。

- **純內網、只走 HTTP 的服務**——加了 `Secure` 之後瀏覽器不會送 Cookie，
  登入直接壞掉。
  處置：這是架構問題不是誤判。有對外可能就改上 HTTPS 再設 `Secure`；
  確實封閉才在 `false-positives.md` 記錄部署範圍與網段限制。

- **非敏感 Cookie 也被標記**（語系偏好、UI 摺疊狀態）。
  處置：照樣加 `Secure`。這類 Cookie 加了完全無副作用，
  比寫一份「這條不敏感」的說明省事。

### 判定準則

真問題：任何以 HTTPS 提供的路徑，其 `Set-Cookie` 缺少 `Secure`。

真問題：`Secure` 由執行期旗標或環境變數決定，存在會產生無 `Secure`
回應的分支。

可接受：服務僅在封閉內網以 HTTP 提供，且無任何對外路徑，
部署範圍已記錄在案。

---

## DAST-COOKIE-002 · Cookie 缺少 HttpOnly 屬性

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| AWVS | Session Cookie without HttpOnly flag set | Medium |
| ZAP | Cookie No HttpOnly Flag（pscan 10010） | Low |
| Nessus | Web Application Cookies Are Not Marked HttpOnly | Medium |
| WebInspect | Cookie Security: HTTPOnly not Set | Medium |

### 壞味道

`Set-Cookie` 中沒有 `HttpOnly`，代表該 Cookie 可被 `document.cookie` 讀到。
掃描器不判斷 Cookie 的用途，看到就標。

```go
http.SetCookie(w, &http.Cookie{
	Name:   "session_id",
	Value:  sid,
	Secure: true,  // 有 Secure 但漏了 HttpOnly
})
```

```python
resp.set_cookie("session_id", sid, secure=True)  # httponly 預設 False
app.config["SESSION_COOKIE_HTTPONLY"] = False    # 明確關閉，最糟
```

```javascript
// cookie-session：httpOnly 預設為 true，但被明確關掉
app.use(cookieSession({
  keys: [process.env.SESSION_SECRET],
  httpOnly: false,
}));
```

最常見的成因是「前端要拿 session id 塞進 API 的 Authorization 標頭」。
這個設計本身就是問題來源，不是設定疏漏。

### 過關寫法

```go
http.SetCookie(w, &http.Cookie{
	Name:     "session_id",
	Value:    sid,
	Path:     "/",
	Secure:   true,
	HttpOnly: true,
	SameSite: http.SameSiteLaxMode,
})
```

```python
# Flask
app.config["SESSION_COOKIE_HTTPONLY"] = True
resp.set_cookie("session_id", sid, secure=True, httponly=True, samesite="Lax")

# Django（預設即為 True，但要確認沒有被覆寫）
SESSION_COOKIE_HTTPONLY = True
```

```javascript
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: "lax" },
}));
```

前端需要辨識登入狀態時，不要讓它讀 session Cookie。
改為提供一支 `/api/me` 由後端讀 Cookie 後回傳使用者資訊——
Cookie 保持 `HttpOnly`，前端拿到的是資料而非憑證。

### 常見誤判與處置

- **CSRF token 採 double-submit 模式，前端必須用 JS 讀取**——
  這條 Cookie 依設計就不能設 `HttpOnly`。
  處置：這是真實限制。把 CSRF Cookie 與 session Cookie **分開兩條**，
  session 那條設滿 `HttpOnly`，CSRF 那條在 `false-positives.md` 記錄
  用途與其不含身分憑證的事實。Django 的 `CSRF_COOKIE_HTTPONLY`
  官方預設就是 `False`，屬同一情形。

- **前端分析或 A/B 測試 SDK 自行寫入的 Cookie**——由第三方腳本
  在瀏覽器端 `document.cookie` 產生，後端根本沒發這條。
  處置：後端改不了。評估該 SDK 是否必要；保留的話記錄來源腳本與
  Cookie 名稱，並確認其中不含身分或個資。

### 判定準則

真問題：承載身分或工作階段狀態的 Cookie（session id、認證 token、
記住我）缺少 `HttpOnly`。

真問題：框架設定中出現明確的 `HttpOnly = False` / `httpOnly: false`。

可接受：該 Cookie 依設計需由前端 JS 讀取（CSRF double-submit token），
且不含身分憑證，用途已記錄在案。

---

## DAST-COOKIE-003 · Cookie 缺少 SameSite 屬性（或 None 未配 Secure）

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| ZAP | Cookie without SameSite Attribute（pscan 10054） | Low |
| AWVS | —（隨版本併入 Cookie 屬性檢查） | — |
| Nessus | — | — |
| WebInspect | — | — |

這條的工具覆蓋率比 Secure / HttpOnly 低，但 ZAP 幾乎必報，
且 `SameSite=None` 沒配 `Secure` 時瀏覽器會直接丟棄該 Cookie，
會變成功能性缺陷而不只是掃描紅字。

### 壞味道

`Set-Cookie` 完全沒有 `SameSite`，或設了 `None` 卻沒有 `Secure`。

```go
http.SetCookie(w, &http.Cookie{
	Name:     "session_id",
	Value:    sid,
	Secure:   true,
	HttpOnly: true,
	// SameSite 未設，Go 會輸出 SameSiteDefaultMode（不寫出屬性）
})

// 更糟：None 沒配 Secure，瀏覽器直接丟棄
http.SetCookie(w, &http.Cookie{
	Name:     "session_id",
	Value:    sid,
	SameSite: http.SameSiteNoneMode,
})
```

```python
resp.set_cookie("session_id", sid, secure=True, httponly=True)  # 缺 samesite
app.config["SESSION_COOKIE_SAMESITE"] = None  # Flask 的 None 代表「不輸出屬性」
```

```javascript
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true },  // 缺 sameSite
}));

// None 字串沒配 secure
app.use(session({ cookie: { sameSite: "none" } }));
```

Go 的 `http.SameSiteDefaultMode` **不會**輸出 `SameSite` 屬性——
這是常見誤解，以為「Default」等於瀏覽器的 Lax 預設。
Flask 的 `SESSION_COOKIE_SAMESITE = None`（Python 的 `None`）同理，
它代表不輸出屬性，不是字串 `"None"`。

### 過關寫法

`Lax` 是預設選擇，涵蓋絕大多數表單與導覽情境。

```go
http.SetCookie(w, &http.Cookie{
	Name:     "session_id",
	Value:    sid,
	Path:     "/",
	Secure:   true,
	HttpOnly: true,
	SameSite: http.SameSiteLaxMode,
})

// 確實需要跨站帶送時，None 與 Secure 必須成對出現
http.SetCookie(w, &http.Cookie{
	Name:     "embed_session",
	Value:    sid,
	Path:     "/",
	Secure:   true,  // 缺這行整條 Cookie 會被瀏覽器丟棄
	HttpOnly: true,
	SameSite: http.SameSiteNoneMode,
})
```

```python
# Flask
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"   # 字串，不是 None

# Django
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

# 跨站情境
resp.set_cookie("embed_session", sid, secure=True, httponly=True, samesite="None")
```

```javascript
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: "lax" },
}));

// cookie-session 的跨站設定
app.use(cookieSession({
  keys: [process.env.SESSION_SECRET],
  secure: true,
  httpOnly: true,
  sameSite: "none",
}));
```

`Strict` 會讓「從外部連結點進來的使用者看起來像未登入」，
在有外部入口的系統會造成明顯體感問題。除非是純後台或高風險操作專用的
Cookie，否則選 `Lax`。

### 常見誤判與處置

- **Cookie 必須跨站帶送，所以不能設 `Strict`**——單一登入的回跳、
  金流服務的 callback、被第三方網站以 iframe 嵌入的元件。
  處置：這不是誤判，也不需要留空。設 `SameSite=None; Secure`
  是明確且工具接受的答案；留空才會被標記。同時把該 Cookie 的
  跨站來源限制在必要範圍，不要整站的 session Cookie 都開 `None`。

- **舊版瀏覽器不認得 `SameSite=None`**——特定版本的 Safari 與
  iOS 內建瀏覽器會把 `None` 誤解為 `Strict`，導致跨站流程壞掉。
  處置：若使用者端仍有這些版本，依 User-Agent 對該群組不輸出
  `SameSite` 屬性，其餘一律輸出。在 `false-positives.md` 記錄
  分支條件與影響的瀏覽器版本範圍。

- **掃描器只看到未設屬性，但瀏覽器實際套用 Lax 預設**——
  現代瀏覽器對沒有 `SameSite` 的 Cookie 會當作 `Lax`。
  處置：仍要明寫。掃描器看的是 `Set-Cookie` 字面，不模擬瀏覽器預設；
  明寫一個字比爭論省事，且不同瀏覽器的預設並不一致。

### 判定準則

真問題：承載工作階段狀態的 Cookie，其 `Set-Cookie` 未輸出 `SameSite` 屬性。

真問題：`SameSite=None` 但同一條 Cookie 沒有 `Secure`——
此時瀏覽器會丟棄，屬於必修的功能性兼安全性缺陷。

可接受：明確輸出 `SameSite=Lax` 或 `Strict`；或輸出 `None` 且同時有
`Secure`，且跨站需求已記錄在案。

---

## DAST-TLS-001 · 不安全的 TLS 版本或加密套件

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Nessus | SSL Version 2 and 3 Protocol Detection | High |
| Nessus | TLS Version 1.0 Protocol Detection | Medium |
| Nessus | TLS Version 1.1 Protocol Deprecated | Medium |
| Nessus | SSL RC4 Cipher Suites Supported (Bar Mitzvah) | Medium |
| Nessus | SSL Medium Strength Cipher Suites Supported (SWEET32) | Medium–High |
| Nessus | SSL NULL Cipher Suites Supported | High |
| WebInspect | Insecure Transport: Weak SSL Protocol | Medium–High |
| WebInspect | Insecure Transport: Weak SSL Cipher | Medium–High |
| AWVS | TLS 1.0 enabled | Medium |
| ZAP | —（無原生 TLS 套件檢測，靠 testssl.sh / sslyze 補） | — |

TLS 這一類的主力是 Nessus，不是應用層掃描器。AWVS 與 ZAP 的覆蓋零散，
但 Nessus 的網路掃描一定會打到，且**任何一個對外開放的 TLS 埠都算數**——
包含管理介面、metrics 埠、資料庫的 TLS 埠。

### 壞味道

允許 TLS 1.0 / 1.1，或加密套件清單中含 RC4、3DES、NULL、EXPORT、匿名交握。

```go
// MinVersion 未設：Go 舊版預設可接受 TLS 1.0
srv := &http.Server{
	Addr:      ":443",
	TLSConfig: &tls.Config{},
}

// 明確指定了不該用的版本與套件
cfg := &tls.Config{
	MinVersion: tls.VersionTLS10,
	CipherSuites: []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	},
}

// 連外時關掉驗證，同一類問題的近親
client := &http.Client{Transport: &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}}
```

```python
# 指定過時協定
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

# gunicorn 組態允許舊版與弱套件
ssl_version = ssl.PROTOCOL_TLSv1
ciphers = "ALL:!aNULL"   # ALL 會帶進 3DES 與 RC4
```

```javascript
const https = require("https");
https.createServer({
  key, cert,
  secureProtocol: "TLSv1_method",           // 鎖死在 TLS 1.0
  ciphers: "ALL:!aNULL",
}, app);
```

反向代理層同樣要看。以下是常見的 Nginx 壞組態：

```
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers HIGH:!aNULL:!MD5;
```

`HIGH` 與 `ALL` 都會把 3DES 帶進來，這正是 SWEET32 的來源。

### 過關寫法

原則是**明列允許值**，不要用 `ALL`、`HIGH` 這類集合名稱——
集合的內容隨函式庫版本變動，今天過關的組態明天會被新規則標記。

```go
srv := &http.Server{
	Addr: ":443",
	TLSConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	},
}
```

`CipherSuites` 對 TLS 1.3 無效——1.3 的套件由 Go 自行決定且皆為安全選項。

**不要加 `PreferServerCipherSuites: true`。** 該欄位 Go 1.17 起標記棄用、
1.18 起被 `crypto/tls` 完全忽略，套件優先順序改由執行期依硬體特性自行決定。
寫了不會報錯也不會生效，只會讓人誤以為已經設定過——舊教學與舊掃描報告的
修補建議仍常出現這一行，照抄會留下無效組態。
設 `MinVersion: tls.VersionTLS13` 是最省事的選擇，前提是用戶端撐得住。

```python
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
ctx.options |= ssl.OP_NO_COMPRESSION
```

```javascript
const https = require("https");
const tls = require("tls");

https.createServer({
  key, cert,
  minVersion: "TLSv1.2",
  ciphers: [
    "TLS_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
  ].join(":"),
  honorCipherOrder: true,
}, app);
```

Nginx 對應寫法：

```
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
```

改完務必用 `testssl.sh` 或 `sslyze` 自行驗一次再送掃描。
組態檔改對但沒有 reload、或有多個 `server` 區塊只改到其中一個，
是複掃仍然紅字的最常見原因。

### 常見誤判與處置

- **TLS 由負載平衡器或 CDN 終結，應用程式的 `tls.Config` 根本沒生效**——
  改了 Go 或 Node 的組態，複掃結果完全沒變。
  處置：這不是誤判，是改錯地方。掃描器打的是 LB 對外的那個埠，
  組態要改在 LB / CDN 的 TLS 政策上（多數雲端供應商以「安全政策」
  或「最低 TLS 版本」的形式提供）。佐證中註明實際生效的設定位置，
  並附上該處的組態截圖或匯出值。

- **舊型用戶端只支援 TLS 1.0 或 3DES**——POS 終端、工控設備、
  嵌入式讀卡機、無法更新的舊版行動裝置。停用後這些裝置直接連不上。
  處置：這是真實的相容性限制，不是誤判。把舊協定限縮到**專用的
  獨立埠或獨立主機名稱**，主要服務端點維持 TLS 1.2 以上；
  在 `false-positives.md` 記錄受影響裝置清單、暫存期限與汰換計畫。
  不要為了少數裝置讓全站降級。

- **掃描器報的是非對外的管理埠或內部服務埠**——例如
  只綁在內網介面的 metrics 埠、資料庫複寫埠。
  處置：先確認該埠真的沒有對外路徑（用外部視角自行掃一次確認）。
  確認後標記誤判並註明繫結位址與防火牆規則；若其實對外，照樣要修。

- **憑證鏈或自簽憑證的告警混在同一批結果裡**——`InsecureSkipVerify`、
  過期憑證、主機名稱不符會被歸在鄰近的規則名稱下，容易被當成同一件事。
  處置：分開處理。協定與套件是組態問題，憑證是簽發與輪替問題，
  兩者的修復途徑不同，混在一起會漏掉其中一邊。

### 判定準則

真問題：任何對外可達的 TLS 埠接受 SSL 3.0、TLS 1.0 或 TLS 1.1 交握。

真問題：可協商出含 RC4、3DES、NULL、EXPORT 或匿名（aNULL / ADH）
的加密套件。

真問題：加密套件以 `ALL`、`HIGH`、`DEFAULT` 等集合名稱設定，
未明列允許值——即使當下掃描結果乾淨，也視為未通過。

真問題：程式碼中出現 `InsecureSkipVerify: true` 或等效的憑證驗證關閉，
且該路徑會用於正式環境的對外連線。

可接受：僅開放 TLS 1.2 與 1.3、加密套件為明列的 AEAD 套件；
舊協定若因裝置相容性保留，已限縮在獨立端點且有汰換期限記錄在案。
