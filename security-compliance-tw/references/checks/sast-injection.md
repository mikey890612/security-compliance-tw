# SAST：注入類

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## SAST-INJ-001 · SQL 指令注入

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | SQL Injection | Critical | unverified | — |
| Checkmarx | SQL_Injection | High | unverified | — |
| Semgrep | `*.security.*.string-formatted-query` / `*.sql-injection*` | ERROR | unverified | — |
| SonarQube | S3649 | Blocker | unverified | — |
| gosec | G201（SQL 字串格式化）/ G202（SQL 字串串接） | HIGH | unverified | — |
| bandit | B608 | MEDIUM | unverified | — |
| AWVS / ZAP | SQL Injection | High | unverified | — |

### 壞味道

```go
q := "SELECT * FROM users WHERE name = '" + name + "'"
rows, _ := db.Query(q)

q2 := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
rows2, _ := db.Query(q2)
```

```python
cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
cur.execute("SELECT * FROM users WHERE id = " + str(user_id))
```

```javascript
db.query("SELECT * FROM users WHERE name = '" + name + "'");
db.query(`SELECT * FROM users WHERE id = ${userId}`);
```

### 過關寫法

關鍵不是「有沒有消毒」，而是**驅動層的參數化**——污點分析引擎對標準函式庫的
placeholder 有內建 cleanse 規則，對自製 escape helper 沒有。

```go
rows, err := db.Query("SELECT * FROM users WHERE name = ?", name)

// 動態欄位名無法參數化時，用白名單映射，不要拼接使用者輸入
var allowedSort = map[string]string{"name": "name", "created": "created_at"}
col, ok := allowedSort[req.SortBy]
if !ok {
	return ErrInvalidSort
}
rows, err = db.Query("SELECT * FROM users ORDER BY " + col)
```

```python
cur.execute("SELECT * FROM users WHERE name = %s", (name,))
cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))

ALLOWED_SORT = {"name": "name", "created": "created_at"}
col = ALLOWED_SORT.get(req.sort_by)
if col is None:
    raise ValueError("invalid sort")
cur.execute(f"SELECT * FROM users ORDER BY {col}")
```

```javascript
await db.query("SELECT * FROM users WHERE name = ?", [name]);
await client.query("SELECT * FROM users WHERE id = $1", [userId]);
```

### 常見誤判與處置

- **常數或列舉組成的查詢**——SQL 完全由程式內常數組成，無外部輸入。
  gosec 的 G201 只看是否用了 `fmt.Sprintf`，不看參數來源，必然誤報。
  處置：改用常數字串直接傳入，消除格式化動作。

- **ORM 的 raw 查詢已參數化**——`gorm.Raw("... WHERE id = ?", id)`
  部分工具版本辨識不出 gorm 的 placeholder。
  處置：確認 placeholder 語法正確後標記誤判，佐證寫明 ORM 版本與參數繫結位置。

- **白名單映射後的欄位名拼接**——如上方過關寫法的排序範例。
  拼接的是 map 的 **value**（程式內常數），非使用者輸入。
  處置：標記誤判，佐證寫明白名單定義位置與 `ok` 檢查行號。
  **前提是白名單查不到時必須回傳錯誤**，若查不到時 fallback 用原輸入，就是真漏洞。

### 判定準則

真漏洞：SQL 字串中存在任何來自 HTTP 請求、檔案、資料庫、環境變數的值，
且該值未經白名單映射或未走驅動層 placeholder。

誤判：拼接進 SQL 的值可回溯到程式內常數（含白名單 map 的 value），
或已由驅動層 placeholder 承載。

灰色地帶——**一律當真漏洞修**：值來自其他內部服務的回應，
或來自資料庫但該欄位曾由使用者寫入（二階注入）。

---

## SAST-INJ-002 · 作業系統命令注入

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Command Injection | Critical | unverified | — |
| Checkmarx | Command_Injection | High | unverified | — |
| Semgrep | `*.security.*.command-injection*` | ERROR | unverified | — |
| SonarQube | S2076 | Blocker | unverified | — |
| gosec | G204 | HIGH | unverified | — |
| bandit | B602（shell=True）/ B605 | HIGH | unverified | — |
| AWVS / ZAP | OS Command Injection | High | unverified | — |

### 壞味道

```go
exec.Command("sh", "-c", "convert "+userFile+" out.png").Run()
exec.Command("/bin/bash", "-c", cmdFromRequest).Run()
```

```python
os.system("convert " + user_file + " out.png")
subprocess.run(f"convert {user_file} out.png", shell=True)
subprocess.Popen("ls " + path, shell=True)
```

```javascript
const { exec } = require("child_process");
exec("convert " + userFile + " out.png");
```

### 過關寫法

核心是**不要經過 shell**。把參數當成 argv 陣列傳入，shell 不介入就沒有
metacharacter 可以逃逸，資料流分析也會把 sink 從「shell 命令」降級為「程式參數」。

```go
// 不經 shell，參數逐一傳入
cmd := exec.Command("convert", userFile, "out.png")
if err := cmd.Run(); err != nil {
	return err
}
```

```python
subprocess.run(["convert", user_file, "out.png"], shell=False, check=True)
```

```javascript
const { execFile } = require("child_process");
execFile("convert", [userFile, "out.png"], (err, stdout) => { /* ... */ });
```

若參數是檔案路徑，另外加上路徑正規化與根目錄限制（見 SAST-INJ-003）。

### 常見誤判與處置

- **命令與參數全為常數**——gosec G204 只要看到 `exec.Command` 的參數
  不是字面常數就報，即使該變數來自設定檔常數。
  處置：若確為程式內常數，標記誤判並註明變數定義位置。

- **參數已通過嚴格白名單**——例如只允許 `["png", "jpg"]` 之一。
  處置：標記誤判，佐證寫明白名單與拒絕分支。

### 判定準則

真漏洞：命令字串或參數含外部輸入，**且**透過 `sh -c` / `shell=True` /
`exec()` 執行。

真漏洞（即使不經 shell）：外部輸入被當成**命令本身**（argv[0]），
而非參數——此時攻擊者可指定任意執行檔。

誤判：不經 shell，且外部輸入僅作為參數傳入，且已限制其取值範圍。

---

## SAST-INJ-003 · 路徑尋訪

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Path Manipulation | Critical | unverified | — |
| Checkmarx | Path_Traversal | High | unverified | — |
| Semgrep | `*.security.*.path-traversal*` | ERROR | unverified | — |
| SonarQube | S2083 | Blocker | unverified | — |
| gosec | G304（以變數開檔） | MEDIUM | unverified | — |
| bandit | —（無專屬規則，靠 Semgrep / CodeQL 補） | — | unverified | — |
| AWVS / ZAP | Directory Traversal | High | unverified | — |

### 壞味道

```go
data, _ := os.ReadFile("/var/data/" + r.URL.Query().Get("file"))
http.ServeFile(w, r, filepath.Join("/var/data", r.URL.Path))
```

```python
with open("/var/data/" + request.args["file"]) as f:
    data = f.read()
path = os.path.join("/var/data", user_input)
```

```javascript
fs.readFile("/var/data/" + req.query.file, cb);
res.sendFile(path.join("/var/data", req.params.name));
```

`filepath.Join` 與 `os.path.join` **不會**擋 `../`——這是最常見的誤解。
`Join` 只做路徑正規化，`/var/data` + `../../etc/passwd` 會正規化成 `/etc/passwd`。

### 過關寫法

樣式是固定的三步：正規化 → 確認仍在根目錄內 → 才開檔。
資料流分析引擎認得「比對後才使用」這個結構。

```go
root := "/var/data"
target := filepath.Join(root, filepath.Clean("/"+userInput))
if !strings.HasPrefix(target, filepath.Clean(root)+string(os.PathSeparator)) {
	return ErrForbidden
}
data, err := os.ReadFile(target)
```

```python
import os

root = os.path.realpath("/var/data")
target = os.path.realpath(os.path.join(root, user_input))
if not (target == root or target.startswith(root + os.sep)):
    raise PermissionError("path escapes root")
with open(target) as f:
    data = f.read()
```

```javascript
const path = require("path");
const root = path.resolve("/var/data");
const target = path.resolve(root, userInput);
if (target !== root && !target.startsWith(root + path.sep)) {
  throw new Error("path escapes root");
}
fs.readFile(target, cb);
```

更穩的做法是完全不接受路徑：讓使用者傳識別碼，由程式查表得到實際檔名。
這會讓污點路徑徹底斷開，多數工具直接不報。

### 常見誤判與處置

- **路徑來自資料庫且由系統產生**——例如上傳時以 UUID 命名、資料庫只存 UUID。
  gosec G304 看到變數開檔就報。
  處置：標記誤判，佐證寫明檔名產生位置與格式限制。

- **已做前綴檢查但工具追不到**——如上方過關寫法。
  部分 Fortify 版本認不得 `strings.HasPrefix` 的守衛。
  處置：標記誤判，佐證寫明守衛的行號與拒絕分支。

### 判定準則

真漏洞：開檔或送檔的路徑含外部輸入，且**沒有**在開檔前做根目錄前綴比對。

真漏洞：有做比對但比對的是**正規化前**的字串（先檢查再 `Join`，順序錯了）。

誤判：路徑完全由系統產生，或已在正規化**之後**做前綴比對且不符時中止。

---

## SAST-INJ-004 · 跨站腳本攻擊

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Cross-Site Scripting: Reflected / Persistent / DOM | Critical | unverified | — |
| Checkmarx | Reflected_XSS_All_Clients / Stored_XSS / Client_DOM_XSS | High | unverified | — |
| Semgrep | `*.security.*.xss*` / `*.dangerously-set-inner-html*` / `go.lang.security.audit.xss.*` | ERROR | unverified | — |
| SonarQube | S5131（端點不應存在反射型 XSS）/ S6299（DOM XSS） | Blocker | unverified | — |
| gosec | G203（HTML 樣板中使用未跳脫資料） | MEDIUM | unverified | — |
| bandit | B308（`mark_safe`）/ B703（Django `mark_safe`） | MEDIUM | unverified | — |
| AWVS / ZAP | Cross Site Scripting (Reflected / Persistent / DOM Based) | High | unverified | — |

### 壞味道

**Go——關鍵在 `text/template` 與 `html/template` 的差別**：

```go
import "text/template" // ← 不會自動跳脫，任何使用者輸入都直接輸出
t, _ := template.New("p").Parse("<div>{{.}}</div>")
t.Execute(w, r.URL.Query().Get("q"))

// 即使用了 html/template，這樣寫也會繞過跳脫
import "html/template"
template.HTML(userInput)          // 明示「這是安全的 HTML」
template.JS(userInput)
template.URL(userInput)

// 完全不經樣板直接拼字串
fmt.Fprintf(w, "<div>%s</div>", userInput)
w.Write([]byte("<p>" + userInput + "</p>"))
```

```python
# Jinja2 關閉自動跳脫，或對使用者輸入用 |safe
Environment(autoescape=False)
render_template_string("<div>" + user_input + "</div>")
# 樣板中：{{ user_input|safe }}

from markupsafe import Markup
Markup(user_input)              # 明示為安全 HTML

from django.utils.safestring import mark_safe
mark_safe(user_input)
```

```javascript
el.innerHTML = userInput;
el.outerHTML = "<div>" + userInput + "</div>";
document.write(userInput);
el.insertAdjacentHTML("beforeend", userInput);

// React
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// jQuery：這些方法會執行傳入的 HTML
$("#x").html(userInput);
$(userInput).appendTo("body");
```

### 過關寫法

核心是**讓輸出經過工具認得的跳脫函式**，而不是自己過濾字元。
黑名單過濾（把 `<script>` 換掉）幾乎所有工具都不承認，因為繞過方式太多。

```go
import "html/template" // ← 用這個，不要用 text/template

// 樣板中的 {{.}} 會依上下文自動選擇跳脫方式
t := template.Must(template.New("p").Parse(`<div>{{.}}</div>`))
t.Execute(w, userInput)

// 不用樣板時，明確跳脫
w.Write([]byte("<p>" + template.HTMLEscapeString(userInput) + "</p>"))

// 回傳 JSON 時設對 Content-Type，不要讓瀏覽器猜
w.Header().Set("Content-Type", "application/json; charset=utf-8")
```

```python
# Flask 預設對 .html 樣板開啟 autoescape，保持開啟即可
return render_template("page.html", q=user_input)   # 樣板中寫 {{ q }}，不加 |safe

# 手動跳脫
from markupsafe import escape
return f"<div>{escape(user_input)}</div>"

# 明確指定 autoescape
env = Environment(autoescape=select_autoescape(["html", "xml"]))
```

```javascript
el.textContent = userInput;                    // 不會解析 HTML
el.setAttribute("data-name", userInput);

// React 預設跳脫，直接放進 JSX 即可
<div>{userInput}</div>

// 必須插入 HTML 時，先過消毒函式庫
import DOMPurify from "dompurify";
el.innerHTML = DOMPurify.sanitize(userInput);
```

**回傳任意檔案內容時另需設 `Content-Type` 與 `X-Content-Type-Options: nosniff`**，
否則使用者上傳的 HTML 會被瀏覽器當網頁渲染，形成儲存型 XSS。
只設 `nosniff` 不設 `Content-Type` 沒有用。

### 常見誤判與處置

- **樣板已用 `html/template` 但工具仍標**——部分 Fortify 版本對
  Go 樣板的上下文感知跳脫辨識不完整。
  處置：確認匯入的確實是 `html/template`（不是 `text/template`），
  且沒有任何 `template.HTML` 包裝，再標記誤判並註明匯入行號。

- **內容來自資料庫且為系統產生**——例如商品分類名稱由管理端固定維護。
  處置：確認該欄位無使用者可寫入路徑後標記誤判。
  **但若管理端也是網頁表單，那是儲存型 XSS，不是誤判。**

- **API 回傳 JSON 被標為 XSS**——工具看到使用者輸入流向 HTTP 回應就報。
  處置：確認 `Content-Type` 為 `application/json` 且有 `nosniff` 後標記誤判，
  佐證寫明標頭設定位置。

- **前後端分離，跳脫在前端框架做**——後端只回 JSON。
  處置：這是真的分工，但要確認前端沒有 `dangerouslySetInnerHTML` 或
  `v-html` 接同一份資料。**兩邊都要查才能標誤判。**

### 判定準則

真漏洞：使用者可控的值進入 HTML、JS、CSS 或 URL 上下文，
且該值未經對應上下文的跳脫函式處理。

真漏洞：使用 `text/template` 產生 HTML 輸出（無論資料來源）。

真漏洞：用黑名單過濾特殊字元或標籤名稱來「防範」XSS——
繞過方式過多，且工具不承認。

誤判：值可回溯到程式內常數，或已經過框架的自動跳脫且未被
`template.HTML` / `|safe` / `mark_safe` / `dangerouslySetInnerHTML` 繞過。

灰色地帶——**一律當真漏洞修**：值來自資料庫但該欄位有任何使用者可寫入的路徑
（儲存型 XSS）；或前後端分離但無法確認前端是否安全渲染。
