# SAST：注入類

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## SAST-INJ-001 · SQL 指令注入

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | SQL Injection（等級依資料來源浮動，實測一例為 Low） | Critical | partial | internal-verified:2026-04-24（C#） |
| Checkmarx | SQL_Injection | High | unverified | — |
| Semgrep | `*.security.*.string-formatted-query` / `*.sql-injection*` | ERROR | verified | testdata/scan-artifacts/open-source/20260905T084457Z/semgrep.json#rule=go.lang.security.audit.database.string-formatted-query.string-formatted-query（見 `references/scanner-verification-log.md`） |
| SonarQube | S3649 | Blocker | unverified | — |
| gosec | G201（SQL 字串格式化）/ G202（SQL 字串串接） | HIGH | verified | testdata/scan-artifacts/open-source/20260905T084457Z/gosec.json#rule=G202（見 `references/scanner-verification-log.md`） |
| bandit | B608 | MEDIUM | verified | testdata/scan-artifacts/open-source/20260905T084457Z/bandit.json#rule=B608（見 `references/scanner-verification-log.md`） |
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
| Semgrep | `*.security.*.command-injection*` | ERROR | verified | testdata/scan-artifacts/open-source/20260905T084457Z/semgrep.json#rule=go.lang.security.audit.dangerous-exec-command.dangerous-exec-command（見 `references/scanner-verification-log.md`） |
| SonarQube | S2076 | Blocker | unverified | — |
| gosec | G204 | HIGH | verified | testdata/scan-artifacts/open-source/20260905T084457Z/gosec.json#rule=G204（見 `references/scanner-verification-log.md`） |
| bandit | B602（shell=True）/ B605 | HIGH | verified | testdata/scan-artifacts/open-source/20260905T084457Z/bandit.json#rule=B602（見 `references/scanner-verification-log.md`） |
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
| Semgrep | `*.security.*.xss*` / `*.dangerously-set-inner-html*` / `go.lang.security.audit.xss.*` | ERROR | verified | testdata/scan-artifacts/open-source/20260905T084457Z/semgrep.json#rule=go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter（見 `references/scanner-verification-log.md`） |
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

---

## SAST-INJ-005 · XML 外部實體（XXE）

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | XML External Entity Injection | High | unverified | — |
| Semgrep | `python.lang.security.use-defused-xml`（只看有沒有 `import xml`，不看用法） | ERROR | verified | testdata/scan-artifacts/open-source/20260924T115741Z/semgrep.json#rule=python.lang.security.use-defused-xml（見 `references/scanner-verification-log.md`） |
| Semgrep | `javascript.express.security.audit.express-libxml-noent` / `express-libxml-vm-noent`（libxmljs 開 `noent`） | ERROR | verified | testdata/scan-artifacts/open-source/20260924T115741Z/semgrep.json#rule=javascript.express.security.audit.express-libxml-noent（見 `references/scanner-verification-log.md`） |
| Semgrep | `go.lang.security.audit.xxe.parsing-external-entities-enabled`（libxml2 綁定的 `XMLParseNoEnt`） | WARNING | unverified | — |
| SonarQube | S2755 | Blocker | unverified | — |
| CodeQL | `py/xxe`、`js/xxe` | — | unverified | — |
| bandit | B314（`xml.etree.ElementTree.fromstring` 等，B313–B319）/ B405（匯入 `xml.etree`，B405–B409） | MEDIUM / LOW | verified | testdata/scan-artifacts/open-source/20260924T115741Z/bandit.json#rule=B314、B405（見 `references/scanner-verification-log.md`） |
| AWVS / ZAP | XML External Entity Injection / XML External Entity Attack | High | unverified | — |

**開源工具的盲點（實測）：** bandit 1.9 已移除 lxml 的兩條規則（B320、B410），
semgrep 的 Python 規則只看 `import xml`。lxml 開 `resolve_entities=True`——**真正會解析外部實體**的寫法——
兩者都不會標。相反地，它們會標 Python 標準函式庫的 `xml.etree`，而那在新版 Python 並不解析外部實體。
開源工具的命中與實際風險在這一則幾乎是反的，**一律照下方判定準則逐處看解析器設定**。

### 壞味道

```go
// 標準函式庫 encoding/xml 不解析外部實體；風險來自 cgo 的 libxml2 綁定
p := parser.New(parser.XMLParseNoEnt) // 開啟實體替換
doc, err := p.ParseReader(r.Body)
```

```python
from lxml import etree

# 真正會解析外部實體；lxml 5.0 之前，不寫 resolve_entities 也是這個預設
parser = etree.XMLParser(resolve_entities=True)
root = etree.fromstring(request.get_data(), parser)
```

```javascript
const libxmljs = require("libxmljs");
const doc = libxmljs.parseXml(req.body, { noent: true }); // 開啟實體替換
```

### 過關寫法

原則：**解析器不替換外部實體、不抓外部 DTD**，並限制輸入大小。

```go
// 用標準函式庫 encoding/xml：不支援外部實體，也不會抓 DTD
var inv Invoice
dec := xml.NewDecoder(io.LimitReader(r.Body, 1<<20))
if err := dec.Decode(&inv); err != nil {
	http.Error(w, "bad request", http.StatusBadRequest)
	return
}
```

```python
import defusedxml.ElementTree as DET

# 預設拒絕實體與 DTD；bandit、semgrep 都不標
root = DET.fromstring(request.get_data())

# 一定要用 lxml 時，明確關掉實體、網路與 DTD
from lxml import etree

parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
root = etree.fromstring(request.get_data(), parser)
```

```javascript
// 不開 noent：libxmljs 預設不替換實體
const doc = libxmljs.parseXml(req.body);
```

### 常見誤判與處置

- **Python 標準函式庫的 `xml.etree`／`minidom`**——bandit B314／B405、semgrep `use-defused-xml`
  看到匯入就報。Python 3.7.1 起這些解析器預設不解析外部實體，搭配 Expat 2.4.1 以上也擋住實體倍增。
  處置：**改寫即過**——換成 `defusedxml` 的同名函式，API 幾乎相同，工具就不再標；
  改寫比寫誤判說明省事。

- **Go 的 `encoding/xml`**——不支援外部實體與 DTD 抓取。商用 SAST 若仍標，
  處置：判誤判，佐證寫明使用 `encoding/xml`（附匯入行號），且專案沒有引入 libxml2 綁定。

- **lxml 已關閉實體解析**——如上方過關寫法。處置：工具若仍標，判誤判，
  佐證附建立 parser 的行號與三個參數。

- **XML 來源是程式內常數或自家產生、使用者無法影響的檔案**——
  處置：判誤判，佐證寫明來源。**檔案可由使用者上傳或替換時，不是誤判。**

### 判定準則

真漏洞：外部可控的 XML 進入會替換外部實體或抓外部 DTD 的解析器——
lxml 設 `resolve_entities=True`（或 5.0 之前未明設——實測 4.9.4 預設會讀本機檔，5.0.0 起不會）、libxmljs 的 `noent: true`、
libxml2 綁定的 `XMLParseNoEnt`。

改寫即過：Python 標準函式庫的 XML 解析器被標——換成 `defusedxml`。

誤判：解析器本身不支援外部實體（Go `encoding/xml`），或已明確關閉，且有設定所在行號為證。

灰色地帶——**一律當真漏洞修**：用了 lxml 但版本沒有鎖定、也沒有明設 `resolve_entities`；
或解析器設定在他處組裝，無法確認最後生效的參數。

---

## SAST-INJ-006 · 不安全的反序列化

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Dynamic Code Evaluation: Unsafe Deserialization（子類別依語言與函式庫不同，以報告全名為準） | High | unverified | — |
| Checkmarx | Deserialization_of_Untrusted_Data | High | unverified | — |
| Semgrep | `python.lang.security.deserialization.avoid-pickle` / `avoid-pyyaml-load`；`python.flask.security.insecure-deserialization` | WARNING / ERROR | verified | testdata/scan-artifacts/open-source/20260924T115741Z/semgrep.json#rule=python.lang.security.deserialization.avoid-pickle（見 `references/scanner-verification-log.md`） |
| Semgrep | `javascript.express.security.audit.express-third-party-object-deserialization`（`node-serialize` 等） | WARNING | verified | testdata/scan-artifacts/open-source/20260924T115741Z/semgrep.json#rule=javascript.express.security.audit.express-third-party-object-deserialization（見 `references/scanner-verification-log.md`） |
| Semgrep | `go.lang.security.deserialization.go-unsafe-deserialization-interface`（解到 `interface{}`，見下方「改寫即過」） | WARNING | verified | testdata/scan-artifacts/open-source/20260924T115741Z/semgrep.json#rule=go.lang.security.deserialization.go-unsafe-deserialization-interface（見 `references/scanner-verification-log.md`） |
| SonarQube | S5135 | — | unverified | — |
| CodeQL | `py/unsafe-deserialization`、`js/unsafe-deserialization` | — | unverified | — |
| bandit | B301（`pickle.loads` 等）/ B403（匯入 `pickle`）/ B506（`yaml.load`） | MEDIUM / LOW | verified | testdata/scan-artifacts/open-source/20260924T115741Z/bandit.json#rule=B301、B403、B506（見 `references/scanner-verification-log.md`） |

### 壞味道

```go
// Go 的 encoding/json 不會執行程式碼，但解到 interface{} 會被 semgrep 標，
// 後續還得靠型別斷言猜內容——見「常見誤判與處置」
var v interface{}
if err := json.Unmarshal(body, &v); err != nil {
	return err
}
```

```python
state = pickle.loads(request.get_data())                  # 反序列化即可執行任意程式碼
cfg = yaml.load(request.get_data(), Loader=yaml.Loader)   # 可建構任意 Python 物件
```

```javascript
const serialize = require("node-serialize");
const state = serialize.unserialize(req.body); // 可夾帶立即執行的函式
```

js-yaml 3.x 的 `yaml.load` 也屬此類（預設 schema 支援 `!!js/function`）；4.x 起移除。

### 過關寫法

原則：**跨越信任邊界的資料只用純資料格式**（JSON、安全模式的 YAML），並解到明確的型別。

```go
type settings struct {
	Theme    string `json:"theme"`
	PageSize int    `json:"page_size"`
}

dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
dec.DisallowUnknownFields()
var s settings
if err := dec.Decode(&s); err != nil {
	http.Error(w, "bad request", http.StatusBadRequest)
	return
}
```

```python
state = json.loads(request.get_data())
cfg = yaml.safe_load(request.get_data())
```

```javascript
const state = JSON.parse(req.body);
// js-yaml 4.x 的 load 預設即安全 schema
const cfg = yaml.load(req.body);
```

### 常見誤判與處置

- **Go 解到 `interface{}`**——semgrep 的 `go-unsafe-deserialization-interface` 看到就報，
  但 Go 的 JSON／YAML／XML 解碼不會執行程式碼。
  處置：**改寫即過**——解到具體 struct（上方過關寫法），工具就不再標，也順便擋掉多餘欄位。

- **pickle 讀的是本程式自己寫入的本機檔**——例如快取。
  處置：判誤判，佐證寫明檔案路徑、唯一的寫入者，以及檔案權限。
  **路徑或內容只要有任何使用者可影響的途徑，就是真漏洞。**

- **`yaml.load` 已指定 `SafeLoader`**——bandit B506 與 semgrep 都不標這種寫法，不構成發現。
  改成 `yaml.safe_load` 更好讀，但不是必要。

### 判定準則

真漏洞：外部可控的資料進入會依內容建構任意物件或執行程式碼的反序列化器——
`pickle`／`dill`／`shelve`、PyYAML 的 `Loader`／`UnsafeLoader`／`unsafe_load`、`node-serialize`、
js-yaml 3.x 的 `load`；其他語言如 Java `ObjectInputStream`、.NET `BinaryFormatter`。

改寫即過：Go 解到 `interface{}` 被標——改解到具體 struct。

誤判：資料只可能由本程式寫入，且有路徑、寫入者與權限為證。

灰色地帶——**一律當真漏洞修**：以簽章保護的 pickle（例如 cookie 或 session 的序列化器）——
金鑰一旦外洩就是遠端執行；資料經其他內部服務轉手、無法確認源頭。

---

## SAST-INJ-007 · HTTP 標頭注入（CRLF／Cookie 屬性）

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Header Manipulation / Header Manipulation: Cookies | High | unverified | — |
| Checkmarx | HTTP_Response_Splitting | Medium | unverified | — |
| SonarQube | S5167 | — | unverified | — |
| AWVS / ZAP | CRLF injection/HTTP response splitting / CRLF Injection | Medium | unverified | — |

**開源工具（實測）：** semgrep 與 bandit 對 fixture 裡三種語言的標頭與 `Set-Cookie` 寫法都沒有規則命中
（見 `references/scanner-verification-log.md`）。本則主要面對商用 SAST 與 DAST。

### 壞味道

標頭值直接放入使用者輸入，或用字串自組 `Set-Cookie`：

```go
theme := r.URL.Query().Get("theme")
w.Header().Add("Set-Cookie", "theme="+theme+"; Path=/")
w.Header().Set("X-Theme", theme)
```

```python
resp = app.make_response(("", 204))
resp.headers["Set-Cookie"] = "theme=" + request.args.get("theme", "") + "; Path=/"
```

```javascript
res.setHeader("Set-Cookie", "theme=" + req.query.theme + "; Path=/");
```

三種框架都**擋得住 CR/LF**，但**擋不住 Cookie 屬性注入**。實測（Go 1.24、Werkzeug 3.1、Node 22）：

| 輸入 | Go `net/http` | Werkzeug（Flask） | Node `http`（Express） |
|---|---|---|---|
| `x\r\nInjected: 1` | CR、LF 換成空白後送出 | 丟 `ValueError` | 丟 `ERR_INVALID_CHAR` |
| `x; Domain=evil.example`（自組 `Set-Cookie`） | 原樣送出 | 原樣送出 | 原樣送出 |

屬性注入讓攻擊者改寫 cookie 的 `Domain`、`Path`、`Expires`，可用於 session 固定或蓋掉其他 cookie。

### 過關寫法

Cookie 一律走框架的 cookie API——它們會跳脫或丟棄非法字元；標頭值先過允許清單。

```go
var allowedThemes = map[string]bool{"light": true, "dark": true}

theme := r.URL.Query().Get("theme")
if !allowedThemes[theme] {
	theme = "light"
}
http.SetCookie(w, &http.Cookie{
	Name: "theme", Value: theme, Path: "/",
	Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
})
```

```python
theme = request.args.get("theme", "")
if theme not in ALLOWED_THEMES:
    theme = "light"
resp.set_cookie("theme", theme, path="/", secure=True, httponly=True, samesite="Lax")
```

```javascript
const theme = ALLOWED_THEMES.has(req.query.theme) ? req.query.theme : "light";
res.cookie("theme", theme, { path: "/", secure: true, httpOnly: true, sameSite: "lax" });
```

`Content-Disposition` 的檔名同理：用 `mime.FormatMediaType`（Go）、Flask 的 `send_file(download_name=…)`、
Express 的 `res.attachment()` 產生，不要自己拼引號。

### 常見誤判與處置

- **標頭值含使用者輸入，但框架已擋 CR/LF**——如上表。Fortify 的 Header Manipulation
  追的是資料流，不知道框架會擋。
  處置：值不是 `Set-Cookie`、也不會被下游當成結構化欄位解析時，判誤判；
  佐證寫明框架與版本、上表對應的行為，以及寫入標頭的行號。
  **Node 與 Werkzeug 是丟例外**——確認例外不會把堆疊回給使用者（見 `sast-errors.md`）。

- **值已過允許清單**——如上方過關寫法。處置：工具若仍標，判誤判，佐證附允許清單位置。

### 判定準則

真漏洞：用字串自組 `Set-Cookie`，且值含外部可控的內容——CR/LF 擋得住，`;` 擋不住。

真漏洞：框架或執行環境不擋 CR/LF（自行寫原始 HTTP 回應、舊版框架、反向代理的自訂模組），
且標頭值含外部可控的內容。

誤判：值經允許清單或框架 cookie API，或框架會擋 CR/LF 且該標頭不承載結構化屬性。

灰色地帶——**一律當真漏洞修**：無法確認執行時的框架版本；或標頭值會被下游服務再解析。
