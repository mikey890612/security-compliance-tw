# SAST：請求濫用（CSRF／SSRF／不安全上傳）

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

這三則的共同點是：**伺服端代使用者發出或接受「有副作用的請求／資源」**，
卻沒有把來源或內容限制在可驗證的範圍內。Cookie 的 `SameSite`、路徑尋訪讀檔、
儲存型 XSS 輸出跳脫，分別見 `dast-tls-cookie.md`、`sast-injection.md`，
不在本檔重複。

## SAST-CSRF-001 · 跨站請求偽造未防護

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Cross-Site Request Forgery | High | unverified | — |
| Checkmarx | CSRF | Medium | unverified | — |
| Semgrep | `*.security.*.csrf*` / framework CSRF middleware 缺失規則 | ERROR | unverified | — |
| SonarQube | S4502（Spring CSRF 關閉）等框架規則 | Blocker | unverified | — |
| CodeQL | `js/missing-token-validation` 等（覆蓋率因框架而異） | High | unverified | — |
| gosec | —（無專屬 CSRF 規則，需人工／框架設定審查） | — | unverified | — |
| bandit | —（無專屬 CSRF 規則，需人工／框架設定審查） | — | unverified | — |
| AWVS / ZAP | Absence of Anti-CSRF Tokens | Medium | unverified | — |

靜態工具對「有沒有 token 驗證」的偵測高度依賴框架慣例；自幹的 handler
幾乎一定要人工對照下方樣式。

### 壞味道

狀態變更（POST／PUT／PATCH／DELETE）只靠 Cookie 身分、沒有同步 CSRF token，
也沒有核對 `Origin`／`Referer`：

```go
func updateEmail(w http.ResponseWriter, r *http.Request) {
	// 只靠 session cookie，跨站表單一送就會帶上
	sess := sessionFromCookie(r)
	email := r.FormValue("email")
	db.Exec("UPDATE users SET email=? WHERE id=?", email, sess.UserID)
}
```

```python
@app.route("/profile/email", methods=["POST"])
def update_email():
    # Flask 未啟用 CSRFProtect；只靠登入 cookie
    email = request.form["email"]
    g.user.email = email
    db.session.commit()
    return "ok"
```

```javascript
app.post("/profile/email", requireLogin, (req, res) => {
  // express-session cookie 自動帶上，無 csrf 中介層
  db.users.update({ id: req.session.userId }, { email: req.body.email });
  res.send("ok");
});
```

只設 Cookie `SameSite` **不算**本則過關——那是 `DAST-COOKIE-003` 的範圍；
本則要的是伺服端對狀態變更請求的明確防護。

### 過關寫法

核心是**伺服端驗證**：同步 CSRF token（double-submit 或 session 綁定），
或嚴格核對 `Origin`／`Referer` 與預期站台一致。框架內建中介層優先。

```go
func updateEmail(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCookie(r)
	token := r.Header.Get("X-CSRF-Token")
	if token == "" || !hmacEqual(token, sess.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" && origin != expectedOrigin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	email := r.FormValue("email")
	db.Exec("UPDATE users SET email=? WHERE id=?", email, sess.UserID)
}
```

```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)  # 所有非豁免的狀態變更路由自動驗證

@app.route("/profile/email", methods=["POST"])
def update_email():
    email = request.form["email"]
    g.user.email = email
    db.session.commit()
    return "ok"
```

```javascript
const csrf = require("csurf");
const csrfProtection = csrf({ cookie: false }); // token 綁在 server session

app.post("/profile/email", requireLogin, csrfProtection, (req, res) => {
  db.users.update({ id: req.session.userId }, { email: req.body.email });
  res.send("ok");
});
```

API 若全面改用自訂 header 承載的 bearer token（且不以 Cookie 當唯一憑證），
跨站表單帶不走該 header，可作為等價防護——但混合「Cookie session + 無 token」
的頁面仍屬本則範圍。

### 常見誤判與處置

- **唯讀 GET／安全方法**——掃描器對所有表單報缺 token。
  處置：確認該端點無狀態變更副作用後標記誤判。

- **已用框架 CSRF 中介層但工具追不到**——例如 Django middleware、
  Spring Security CSRF、`flask_wtf.CSRFProtect`。
  處置：佐證寫明中介層註冊位置與豁免清單，確認狀態變更路由未在豁免內。

- **只設了 `SameSite=Lax`／`Strict`**——瀏覽器輔助，不是伺服端驗證。
  處置：**不當本則過關**；Cookie 屬性另見 `DAST-COOKIE-003`。
  本則仍要求 token 或 Origin／Referer 核對（或非 Cookie 的 bearer 方案）。

- **WebSocket／純 JSON API 被標**——部分工具對非表單 POST 也報。
  處置：若已驗證自訂 CSRF header 或非 Cookie 憑證，標記誤判並註明驗證位置。

### 判定準則

真漏洞：狀態變更請求僅依賴 Cookie（或自動帶上的瀏覽器憑證）辨識身分，
且伺服端**未**驗證 CSRF token，也**未**核對 `Origin`／`Referer`。

誤判：框架或自訂邏輯已對該路由做 token／Origin 驗證；或該方法確定無副作用。

灰色地帶——**一律當真漏洞修**：豁免清單過寬（整棵 `/api/*` 關掉 CSRF），
或前端把 token 寫進可被跨站讀取的位置。

---

## SAST-SSRF-001 · 伺服器端請求偽造

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Server-Side Request Forgery | Critical | unverified | — |
| Checkmarx | SSRF | High | unverified | — |
| Semgrep | `*.security.*.ssrf*` / `*.http-request*` 污點規則 | ERROR | unverified | — |
| SonarQube | S5144 等 | Blocker | unverified | — |
| CodeQL | `go/request-forgery`、`py/request-forgery`、`js/request-forgery` | High | unverified | — |
| gosec | —（無穩定專屬 SSRF 規則，靠 Semgrep／CodeQL 補） | — | unverified | — |
| bandit | B113（請求無逾時；非完整 SSRF） | MEDIUM | unverified | — |
| AWVS / ZAP | Server Side Request Forgery | High | unverified | — |

模型輸出被拿去發 HTTP 請求也是 SSRF sink，交叉可見 `sast-llm.md`；
**本則涵蓋所有使用者可控 URL**，不限 LLM 場景。

### 壞味道

使用者傳入的 URL／主機名被伺服端直接拿去請求：

```go
func fetchPreview(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target) // 可打內網、metadata、file://
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
```

```python
@app.route("/preview")
def preview():
    url = request.args["url"]
    r = requests.get(url, timeout=5)  # 未限制 host／IP
    return r.content
```

```javascript
app.get("/preview", async (req, res) => {
  const target = req.query.url;
  const r = await fetch(target); // 使用者決定要打哪裡
  res.send(await r.text());
});
```

### 過關寫法

樣式固定：解析 URL → 只允許 `http`／`https` → 主機名過**允許清單**
（或解析後的 IP 拒絕私網／迴環／link-local／雲端 metadata）→ 再發請求，
並設逾時與回應大小上限。

```go
var allowedHosts = map[string]struct{}{
	"cdn.example.com": {},
	"img.example.com": {},
}

func fetchPreview(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "bad url", http.StatusBadRequest)
		return
	}
	if _, ok := allowedHosts[strings.ToLower(u.Hostname())]; !ok {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, io.LimitReader(resp.Body, 1<<20))
}
```

```python
from urllib.parse import urlparse
import ipaddress
import socket
import requests

ALLOWED_HOSTS = {"cdn.example.com", "img.example.com"}

def _is_public_ip(host: str) -> bool:
    infos = socket.getaddrinfo(host, None)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return False
    return True

@app.route("/preview")
def preview():
    u = urlparse(request.args["url"])
    if u.scheme not in ("http", "https"):
        return "bad url", 400
    host = (u.hostname or "").lower()
    if host not in ALLOWED_HOSTS or not _is_public_ip(host):
        return "host not allowed", 403
    r = requests.get(u.geturl(), timeout=5, allow_redirects=False)
    return r.content[: 1 << 20]
```

```javascript
const { URL } = require("url");
const ALLOWED_HOSTS = new Set(["cdn.example.com", "img.example.com"]);

app.get("/preview", async (req, res) => {
  let u;
  try {
    u = new URL(req.query.url);
  } catch {
    return res.status(400).send("bad url");
  }
  if (!["http:", "https:"].includes(u.protocol)) {
    return res.status(400).send("bad url");
  }
  if (!ALLOWED_HOSTS.has(u.hostname.toLowerCase())) {
    return res.status(403).send("host not allowed");
  }
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5000);
  const r = await fetch(u.toString(), { signal: ctrl.signal, redirect: "manual" });
  clearTimeout(t);
  const buf = Buffer.from(await r.arrayBuffer()).subarray(0, 1 << 20);
  res.send(buf);
});
```

允許重新導向時，**每一跳**都要重做同一套檢查，否則允許清單形同虛設。

### 常見誤判與處置

- **URL 完全來自設定檔常數**——工具看到 `http.Get(variable)` 就報。
  處置：佐證寫明常數定義位置後標記誤判。

- **已允許清單但工具追不到守衛**——如上方過關寫法。
  處置：標記誤判，註明白名單與拒絕分支行號。

- **僅封鎖字串 `localhost`／`127.0.0.1`**——可用十進位 IP、DNS rebinding、
  短網址、重新導向繞過。
  處置：**不當過關**；改為解析後 IP 屬性檢查或嚴格允許清單。

- **LLM／Agent 把模型輸出當 URL**——仍是本則真漏洞，可與
  `SAST-LLM-*` 交叉引用，但不改以本則為主敘事。

### 判定準則

真漏洞：外部可控的 URL／主機進入伺服端 HTTP／TCP 客戶端，且發請求前
未做允許清單或等價的解析後 IP 限制。

誤判：目標主機可回溯到程式內常數／設定，或已通過允許清單且拒絕分支存在。

灰色地帶——**一律當真漏洞修**：允許重新導向但未對 Location 重檢；
或黑名單只擋少數字面值。

---

## SAST-UPLOAD-001 · 不安全檔案上傳

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Unrestricted File Upload / Path Manipulation（寫入） | Critical | unverified | — |
| Checkmarx | Unrestricted_File_Upload | High | unverified | — |
| Semgrep | `*.security.*.file-upload*` / `*.arbitrary-file-write*` | ERROR | unverified | — |
| SonarQube | S5679 等（覆蓋率因語言而異） | Blocker | unverified | — |
| CodeQL | `py/path-injection`、`js/file-system-race` 等相關寫入規則 | High | unverified | — |
| gosec | G304（以變數開／寫檔；非上傳專屬） | MEDIUM | unverified | — |
| bandit | B202（`tarfile` extractall 等）／通用寫檔污點 | MEDIUM–HIGH | unverified | — |
| AWVS / ZAP | Unrestricted File Upload | High | unverified | — |

本則管**寫入側**：類型／內容／副檔名／大小／存放路徑。純讀檔路徑尋訪見
`SAST-INJ-003`；上傳後當 HTML 渲染的儲存型 XSS 見 `SAST-INJ-004`。

### 壞味道

信任用戶端給的檔名與 Content-Type，原樣寫入可被執行或下載的位置，
且無大小上限：

```go
func upload(w http.ResponseWriter, r *http.Request) {
	f, hdr, _ := r.FormFile("file")
	defer f.Close()
	// 直接用用戶檔名；可上傳 .php / .html / 含 ../ 的名稱
	out, _ := os.Create("/var/www/uploads/" + hdr.Filename)
	io.Copy(out, f) // 無大小上限、不驗內容
}
```

```python
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    # 信任 Content-Type 與原檔名
    f.save("/var/www/uploads/" + f.filename)
    return f.filename
```

```javascript
const multer = require("multer");
const upload = multer({ dest: "uploads/" }); // 未限副檔名／MIME／大小

app.post("/upload", upload.single("file"), (req, res) => {
  // 若再把 req.file.originalname 拼進公開目錄更糟
  fs.renameSync(req.file.path, "public/uploads/" + req.file.originalname);
  res.send(req.file.originalname);
});
```

### 過關寫法

固定四步：大小上限 → 副檔名／MIME **允許清單** → 內容魔術位元驗證 →
以伺服端產生的隨機名寫入**非執行**目錄（必要時再掃毒）。不要用用戶檔名當路徑。

```go
var allowedExt = map[string]string{
	".png": "image/png",
	".jpg": "image/jpeg",
}

func upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 5<<20)
	f, hdr, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "too large or missing", http.StatusBadRequest)
		return
	}
	defer f.Close()
	ext := strings.ToLower(filepath.Ext(hdr.Filename))
	want, ok := allowedExt[ext]
	if !ok {
		http.Error(w, "type not allowed", http.StatusBadRequest)
		return
	}
	head := make([]byte, 512)
	n, _ := f.Read(head)
	mime := http.DetectContentType(head[:n])
	if mime != want {
		http.Error(w, "content mismatch", http.StatusBadRequest)
		return
	}
	name := uuid.NewString() + ext
	out, err := os.Create(filepath.Join("/var/data/uploads", name))
	if err != nil {
		http.Error(w, "store error", 500)
		return
	}
	defer out.Close()
	out.Write(head[:n])
	io.Copy(out, io.LimitReader(f, 5<<20))
}
```

```python
import os, uuid
from werkzeug.utils import secure_filename

ALLOWED = {".png": "image/png", ".jpg": "image/jpeg"}
UPLOAD_ROOT = "/var/data/uploads"

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return "missing", 400
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED:
        return "type not allowed", 400
    head = f.stream.read(512)
    # 實際專案應以 Pillow／python-magic 等驗證影像頭
    if not head.startswith(b"\x89PNG\r\n\x1a\n") and ext == ".png":
        return "content mismatch", 400
    if f.content_length and f.content_length > 5 * 1024 * 1024:
        return "too large", 400
    name = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(UPLOAD_ROOT, name)
    with open(path, "wb") as out:
        out.write(head)
        remaining = (5 * 1024 * 1024) - len(head)
        out.write(f.stream.read(remaining))
    return name
```

```javascript
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");

const ALLOWED = new Map([
  [".png", "image/png"],
  [".jpg", "image/jpeg"],
]);

const upload = multer({
  storage: multer.diskStorage({
    destination: "/var/data/uploads",
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, crypto.randomUUID() + ext);
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED.has(ext)) return cb(new Error("type not allowed"));
    cb(null, true);
  },
});

app.post("/upload", upload.single("file"), (req, res) => {
  // 另以 file-type／影像庫驗證內容；勿把 originalname 拼進公開路徑
  res.send({ stored: req.file.filename });
});
```

### 常見誤判與處置

- **內部匯入工具、檔名由系統產生**——無使用者可控路徑與類型。
  處置：佐證寫明檔名產生方式後標記誤判。

- **只檢查擴充名被標「不足」**——若另有內容驗證與大小上限，屬過關寫法。
  處置：佐證寫明魔術位元／解析庫與 limits；若**只有**擴充名則仍為真漏洞。

- **與路徑尋訪讀檔混淆**——工具對 `os.Create(userPath)` 報 Path Traversal。
  處置：讀檔題歸 `SAST-INJ-003`；本則聚焦上傳寫入的類型與存放策略。
  若上傳檔名仍含 `../` 寫出根目錄，兩則可並列，但修復以隨機名＋固定根為主。

- **與儲存型 XSS 混淆**——上傳 HTML／SVG 後又當網頁輸出。
  處置：輸出跳脫與 `Content-Type`／`nosniff` 歸 `SAST-INJ-004`；
  本則仍要求根本不收可執行／可當文件渲染的危險類型（或隔離網域下載）。

### 判定準則

真漏洞：上傳路徑接受外部檔名或未限制類型／內容／大小，或寫入可執行／
公開可解析的目錄。

誤判：檔名與類型完全由系統決定，或已通過允許清單＋內容驗證＋大小上限＋
安全存放路徑。

灰色地帶——**一律當真漏洞修**：只信 `Content-Type` 標頭；或允許清單含
`.html`／`.svg`／腳本副檔名卻仍從同源靜態目錄提供下載。
