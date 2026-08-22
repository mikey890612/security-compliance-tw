# SAST：工作階段與身分驗證

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

這類缺失有一個共同特徵：**靜態工具的偵測能力落差極大**。硬編碼憑證幾乎每套工具
都有專屬規則且必報；Session 固定只有部分工具追得到；帳號鎖定與密碼強度則多半
沒有通用規則，卻是人工複核與 DAST 一定會問的項目。因此本檔的「過關寫法」除了
讓掃描器不標紅字，也刻意採用**規則辨識得出、且人工複核一眼看得到**的固定樣式。

## SAST-AUTH-001 · 硬編碼帳號密碼與金鑰

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | Password Management: Hardcoded Password | High |
| Fortify | Key Management: Hardcoded Encryption Key | Critical |
| Checkmarx | Use_Of_Hardcoded_Password / Hardcoded_Password_in_Connection_String | High |
| Semgrep | `*.secrets.*.detected-*` / `*.security.*.hardcoded-*` | ERROR |
| SonarQube | S2068（硬編碼憑證）/ S6418（硬編碼機密） | Blocker |
| CodeQL | `go/hardcoded-credentials`、`py/hardcoded-credentials`、`js/hardcoded-credentials` | High |
| gosec | G101 | HIGH |
| bandit | B105 / B106 / B107 | LOW–MEDIUM |
| gitleaks / trufflehog | 高熵字串與供應商金鑰樣式 | High |

這是**唯一一類靜態工具偵測率接近 100% 的認證缺失**：規則靠變數名關鍵字
（`password`、`secret`、`token`、`apikey`）加字串熵值判斷，不需要污點分析，
所以躲不掉，也因此誤報率相對高。

### 壞味道

```go
const dbPassword = "P@ssw0rd1234"
var jwtSecret = []byte("my-super-secret-key")

db, _ := sql.Open("mysql", "root:P@ssw0rd1234@tcp(10.0.0.5:3306)/app")

if user == "admin" && pass == "admin123" {  // 後門帳號
	return true
}
```

```python
DB_PASSWORD = "P@ssw0rd1234"
SECRET_KEY = "django-insecure-8f3k2j4h5g6f7d8s9a0"

conn = pymysql.connect(host="10.0.0.5", user="root", password="P@ssw0rd1234")

def login(u, p):
    return u == "admin" and p == "admin123"
```

```javascript
const JWT_SECRET = "my-super-secret-key";
const dbUrl = "postgres://root:P@ssw0rd1234@10.0.0.5:5432/app";

app.use(session({ secret: "keyboard cat" }));
```

連線字串內嵌密碼是最常被漏掉的一種——變數名叫 `dsn` 或 `connStr`，
但工具會解析字串中的 `user:pass@` 樣式照樣標記。

### 過關寫法

秘密必須來自**執行期環境**，而且取值動作要讓工具看得出來。
關鍵是「字串字面值不進原始碼」——規則比對的是 AST 上的字串常數節點，
只要該節點換成函式呼叫的回傳值，規則就不會觸發。

另一半同樣重要：**啟動時缺值就中止**。若寫成 `os.Getenv("X")` 取不到時
fallback 成預設字串，那個預設字串一樣是硬編碼，工具照樣標。

```go
func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required secret %s not set", key)  // 缺值即中止，不 fallback
	}
	return v
}

var (
	dbPassword = mustEnv("DB_PASSWORD")
	jwtSecret  = []byte(mustEnv("JWT_SECRET"))
)

// 連線字串也要組出來，不要寫成字面值
dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s",
	mustEnv("DB_USER"), dbPassword, mustEnv("DB_HOST"), mustEnv("DB_NAME"))
```

```python
import os

def must_env(key: str) -> str:
    v = os.environ.get(key)
    if not v:
        raise RuntimeError(f"required secret {key} not set")
    return v

DB_PASSWORD = must_env("DB_PASSWORD")
SECRET_KEY = must_env("DJANGO_SECRET_KEY")

conn = pymysql.connect(
    host=must_env("DB_HOST"), user=must_env("DB_USER"), password=DB_PASSWORD
)
```

```javascript
function mustEnv(key) {
  const v = process.env[key];
  if (!v) throw new Error(`required secret ${key} not set`);
  return v;
}

const JWT_SECRET = mustEnv("JWT_SECRET");
app.use(session({ secret: mustEnv("SESSION_SECRET") }));
```

更高的層級是接秘密管理服務（Vault、雲端 Secret Manager、KMS），
程式碼中連環境變數名稱都只是識別碼。無論哪種方式，
**`.env`、`config.yaml`、`application.properties` 等含真實值的檔案不得進版本控制**——
秘密掃描工具會掃整個 git 歷史，即使後來刪掉，歷史紀錄中的值仍會被標記，
而且**必須視為已外洩並輪換**，刪 commit 不算修好。

### 常見誤判與處置

- **測試碼與 fixture 中的假密碼**——`user_test.go` 裡的 `"testpass123"`、
  pytest fixture 中的假 token。gosec G101 與 bandit B105 只比對變數名與字串熵，
  不看檔案是否為測試檔，必然誤報。
  處置：優先讓測試資料在執行期產生（隨機字串或測試專用環境變數）。
  無法改時用 `//nosec G101` / `# nosec B105` 行內抑制並註明原因，
  **不要在設定檔整條停用規則**——那會連正式碼的真問題一起放掉。

- **變數名含關鍵字但值不是秘密**——如 `passwordPolicyURL = "https://.../policy"`、
  `tokenEndpoint = "https://idp.example.gov.tw/token"`、
  `secretHeaderName = "X-Auth-Token"`。
  處置：改名（`policyURL`、`authEndpoint`、`authHeaderName`）比寫誤判說明省事，
  且能一併避免下次掃描重複出現。

- **內嵌的是公開金鑰或憑證**——PEM 格式的 public key 或 CA 憑證被當成高熵字串。
  公鑰本來就該公開，不是秘密。
  處置：標記誤判，佐證寫明該區塊為 `-----BEGIN PUBLIC KEY-----` 或
  `-----BEGIN CERTIFICATE-----`。若出現 `-----BEGIN * PRIVATE KEY-----`，
  **一律是真漏洞，且該金鑰必須立即作廢重簽**。

- **預設值只在開發模式生效**——`if os.Getenv("ENV") == "dev" { secret = "devkey" }`。
  這**不是誤判**。分支條件靠環境變數決定，部署設定錯誤就會用到弱金鑰。
  處置：當真漏洞修，開發環境也走同一條取值路徑。

### 判定準則

真漏洞：原始碼或版本控制歷史中存在可直接用於驗證的字串——資料庫密碼、
API 金鑰、簽章金鑰、私鑰、連線字串中的 `user:pass@`。

真漏洞：取秘密時有 fallback 預設字串（`os.Getenv("X")` 取不到時用寫死的值），
無論該分支「實務上不會走到」。

真漏洞：帳號密碼比對直接對字面常數（後門帳號），無論是否只在特定環境啟用。

誤判：字串為公開金鑰、憑證、URL、標頭名稱、或非秘密的識別碼，僅因變數名
含關鍵字或熵值高而被標記。

誤判：測試專用假值，且該值不對應任何真實系統的憑證。

---

## SAST-AUTH-002 · Session 固定：登入後未重新產生 Session ID

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | Session Fixation | High |
| Checkmarx | Session_Fixation | Medium–High |
| SonarQube | S5876（驗證時應建立新的工作階段） | Blocker |
| Semgrep | —（無通用規則，多需自訂 rule 比對登入 handler） | — |
| CodeQL | `java/session-fixation`（Go / Python / JS 無對應通用查詢） | High |
| gosec | — | — |
| bandit | — | — |
| AWVS | Session fixation | Medium |
| ZAP | Session Fixation | Medium |

靜態端只有 Fortify、Checkmarx、SonarQube 有專屬規則，且判斷方式相同：
**在被辨識為登入的 handler 中，找不到「作廢舊工作階段」或「換發新識別碼」的呼叫**。
規則認的是特定 API 名稱（`regenerate`、`cycle_key`、`invalidate`、`store.New`），
自己寫的 `resetSession()` 包裝函式常常認不出來。

### 壞味道

登入成功後直接把身分寫進登入前就存在的工作階段：

```go
sess, _ := store.Get(r, "sid")        // 取到的是登入前的 session
sess.Values["uid"] = user.ID          // 沿用同一個 session id
sess.Values["authenticated"] = true
_ = sess.Save(r, w)
```

```python
def login_view(request):
    user = authenticate(request, username=u, password=p)
    if user:
        request.session["uid"] = user.id   # 未換發 session id
        request.session["is_auth"] = True
```

```javascript
app.post("/login", (req, res) => {
  const user = authenticate(req.body.account, req.body.password);
  if (user) {
    req.session.uid = user.id;       // 沒有 regenerate
    res.redirect("/dashboard");
  }
});
```

另外兩種同類壞味道：

- 由 URL 或使用者可控參數帶入 session id（`/app;jsessionid=...`、`?sid=...`），
  等於讓攻擊者直接指定受害者的工作階段識別碼。
- 提權操作（改密碼、切換角色、由一般使用者升為管理者）後未換發識別碼。

### 過關寫法

固定樣式：**驗證成功 → 作廢舊工作階段 → 換發新識別碼 → 才寫入身分**。
順序不能顛倒，先寫身分再換發的話，舊識別碼在短暫時間內是已驗證狀態。

用框架內建的換發函式，不要自己包一層——規則比對的就是這些函式名。

```go
func login(w http.ResponseWriter, r *http.Request) {
	user, err := authenticate(r.FormValue("account"), r.FormValue("password"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// 1. 作廢登入前的工作階段（含伺服器端記錄）
	old, _ := store.Get(r, "sid")
	old.Options.MaxAge = -1
	_ = old.Save(r, w)

	// 2. 換發全新的 session id
	sess, _ := store.New(r, "sid")
	sess.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 60, // 閒置上限 30 分鐘
	}

	// 3. 最後才寫入身分
	sess.Values["uid"] = user.ID
	_ = sess.Save(r, w)
}
```

```python
from django.contrib.auth import authenticate, login

def login_view(request):
    user = authenticate(request, username=request.POST["account"],
                        password=request.POST["password"])
    if user is None:
        return HttpResponse(status=401)

    # login() 內部會呼叫 session.cycle_key()（同一使用者）
    # 或 session.flush()（不同使用者），兩者都會換發新的 session id
    login(request, user)
    request.session.set_expiry(30 * 60)
    return redirect("/dashboard")

# Flask 沒有等價函式，需自行作廢後重建：
#   session.clear()
#   session["_sid"] = secrets.token_urlsafe(32)   # 伺服器端 store 一併換 key
#   session.permanent = True
#   app.permanent_session_lifetime = timedelta(minutes=30)
```

```javascript
app.post("/login", (req, res) => {
  const user = authenticate(req.body.account, req.body.password);
  if (!user) return res.sendStatus(401);

  req.session.regenerate((err) => {          // 換發新的 session id
    if (err) return res.sendStatus(500);
    req.session.uid = user.id;               // 換發後才寫入身分
    req.session.cookie.maxAge = 30 * 60 * 1000;
    req.session.save(() => res.redirect("/dashboard"));
  });
});
```

同一段樣式要套用在**所有改變權限等級的地方**：登入、二階段驗證通過、
角色切換、以管理者身分模擬他人（impersonation）。

工作階段識別碼本身也要能通過檢查：至少 128 bits 的密碼學亂數
（`crypto/rand`、`secrets.token_urlsafe`、`crypto.randomBytes`），
**不可**用時間戳、遞增序號、使用者 ID 雜湊、或 `math/rand` / `random` 模組產生。
只放在 Cookie，不放 URL、不放 localStorage。

### 常見誤判與處置

- **登入交由外部身分提供者（OIDC / SAML / 單一簽入）**——本地只有 callback handler，
  換發動作在框架的 `login()` 或 SDK 內部。Fortify 與 Checkmarx 看不到 callback
  裡的字串比對，會把 callback 當成登入 handler 而標記缺少換發。
  處置：標記誤判，佐證寫明 callback 中呼叫框架登入函式的行號，
  並附該函式確實換發識別碼的依據。**若 callback 只是自己 `session["uid"] = ...`
  就結束，那不是誤判，是真漏洞。**

- **無狀態 JWT 架構、沒有伺服器端工作階段**——登入後簽發全新 token，
  本來就不存在「沿用舊識別碼」的問題，但工具看到有寫 Cookie 仍可能標記。
  處置：標記誤判，佐證寫明登入時簽發新 token、且舊 token 已加入撤銷清單。
  **若登入前後是同一個 token（只更新 claims 而未重簽），那是真漏洞。**

- **自訂的 `resetSession()` 包裝函式**——內部確實做了作廢與換發，
  但規則只認框架原生函式名。
  處置：兩種做法都可以——標記誤判並註明包裝函式實作位置，
  或直接把換發那兩行攤平寫在登入 handler 裡。後者往往更省事，
  而且下次換掃描器版本也不會重新冒出來。

- **測試用的登入輔助函式被當成正式登入流程**——`testutil.LoginAs(t, uid)`。
  處置：標記誤判並註明檔案為測試用途、不參與部署。

### 判定準則

真漏洞：登入 handler 中，寫入身分資訊使用的是與登入前相同的工作階段識別碼——
無論後續是否設了逾時、Secure、HttpOnly。

真漏洞：工作階段識別碼可由 URL 查詢字串、路徑參數或請求主體帶入並被接受。

真漏洞：識別碼由非密碼學亂數產生（時間戳、序號、可預測雜湊），
或長度不足 128 bits——此時即使有換發，攻擊者仍可預測新識別碼。

真漏洞：換發動作發生在寫入身分之後。

誤判：換發由框架登入函式或身分提供者 SDK 內部完成，且可指出實際呼叫位置。

灰色地帶——**一律當真漏洞修**：提權操作（改密碼、角色變更、模擬他人）
未換發識別碼。攻擊面比登入更小，但利用後果更嚴重。

---

## SAST-AUTH-003 · 工作階段逾時與登出未確實失效

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | J2EE Misconfiguration: Excessive Session Timeout（其他語言多無對應規則） | Low |
| Checkmarx | —（無通用規則，多靠組態檢查與人工複核） | — |
| SonarQube | —（無逾時規則；相鄰的 S2092 Secure、S3330 HttpOnly 會標 Cookie 屬性） | — |
| Semgrep | —（可自訂 rule 檢查 session 設定的 maxAge / lifetime） | — |
| CodeQL | — | — |
| gosec | — | — |
| bandit | — | — |
| WebInspect | Insufficient Session Expiration | Medium |
| AWVS / ZAP | —（工作階段逾時多為手動測試項目，自動掃描不穩定） | — |

**這是靜態工具的盲區**：逾時值通常在設定檔或框架初始化，不在資料流上，
污點分析追不到。實務上這一項幾乎都是靠**人工複核與組態檢查**發現的，
而複核者看的就是「設定值是多少」與「登出後舊識別碼還能不能用」兩件事。
因此過關寫法要把數值寫成**顯眼的具名常數**，而不是埋在框架預設值裡。

### 壞味道

```go
// 完全沒設 MaxAge：瀏覽器 Cookie 隨關閉消失，
// 但伺服器端記錄永久有效，複製 Cookie 即可無限期使用
sess.Options = &sessions.Options{HttpOnly: true}

// 登出只清客戶端 Cookie，伺服器端 session 記錄還在
func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}
```

```python
SESSION_COOKIE_AGE = 1209600          # 兩週，遠超上限
SESSION_SAVE_EVERY_REQUEST = False    # 只有絕對逾時，沒有閒置逾時

def logout_view(request):
    del request.session["uid"]        # 只刪一個 key，session 本體仍有效
    return redirect("/")
```

```javascript
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { maxAge: 7 * 24 * 3600 * 1000 },  // 七天
  // 缺 rolling，且無 store：預設 MemoryStore 重啟才清，無法主動作廢
}));

app.post("/logout", (req, res) => {
  res.clearCookie("sid");             // 沒有 destroy，伺服器端 session 還活著
  res.sendStatus(204);
});
```

無狀態 JWT 的對應壞味道：token 沒有 `exp`、有效期以天為單位、
或有 `exp` 但登出時沒有任何撤銷機制——「登出」只是前端把 token 丟掉。

### 過關寫法

三件事要同時成立，缺一項複核就會退件：

1. **閒置逾時最長 30 分鐘**，且每次請求續期（rolling），不是只有絕對逾時。
2. **登出必須刪除伺服器端記錄**，不能只清 Cookie。
3. 逾時後或登出後，舊識別碼再次出現一律拒絕並要求重新驗證。

```go
const idleTimeout = 30 * time.Minute  // 閒置上限，具名常數方便複核

func sessionOptions() *sessions.Options {
	return &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(idleTimeout.Seconds()),
	}
}

// 每次請求檢查閒置時間並續期
func requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := store.Get(r, "sid")
		if err != nil || sess.IsNew {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		last, _ := sess.Values["last_seen"].(int64)
		if time.Since(time.Unix(last, 0)) > idleTimeout {
			_ = store.Delete(r, w, sess) // 逾時即刪伺服器端記錄
			http.Error(w, "session expired", http.StatusUnauthorized)
			return
		}
		sess.Values["last_seen"] = time.Now().Unix()
		sess.Options = sessionOptions() // 續期
		_ = sess.Save(r, w)
		next.ServeHTTP(w, r)
	})
}

func logout(w http.ResponseWriter, r *http.Request) {
	sess, _ := store.Get(r, "sid")
	_ = store.Delete(r, w, sess) // 伺服器端刪除，這行才是真正的登出
	sess.Options = sessionOptions()
	sess.Options.MaxAge = -1
	_ = sess.Save(r, w) // 一併清客戶端 Cookie
	http.Redirect(w, r, "/", http.StatusFound)
}
```

```python
from django.contrib.auth import logout

IDLE_TIMEOUT_SECONDS = 30 * 60        # 閒置上限

SESSION_COOKIE_AGE = IDLE_TIMEOUT_SECONDS
SESSION_SAVE_EVERY_REQUEST = True     # 每次請求續期 => 閒置逾時而非絕對逾時
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_ENGINE = "django.contrib.sessions.backends.cached_db"  # 伺服器端可主動刪除

def logout_view(request):
    logout(request)   # 刪除伺服器端 session 記錄並清除 Cookie
    return redirect("/")
```

```javascript
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;   // 閒置上限

app.use(session({
  name: "sid",
  secret: mustEnv("SESSION_SECRET"),
  store: redisStore,          // 伺服器端可主動作廢，不用 MemoryStore
  resave: false,
  rolling: true,              // 每次回應重設到期時間 => 閒置逾時
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: IDLE_TIMEOUT_MS,
  },
}));

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {   // 刪除 store 中的記錄
    if (err) return res.sendStatus(500);
    res.clearCookie("sid");
    res.sendStatus(204);
  });
});
```

**無狀態 JWT 沒辦法只靠 token 本身做到登出**。可行的組合是：
存取 token 有效期壓到分鐘級（配合 30 分鐘閒置上限）、更新 token 存在伺服器端可撤銷、
登出時把該使用者的 token 版本號遞增使既有 token 全數失效。
若架構上做不到撤銷，就不要用長效 token 承載已驗證身分。

除了閒置逾時，另設**絕對逾時**（例如 8 小時或 12 小時）——
無論使用者多活躍，超過就必須重新驗證。複核時常一併問到。

### 常見誤判與處置

- **逾時由反向代理、API 閘道或身分提供者控制**——應用程式碼中確實沒有數值，
  框架維持預設值。
  處置：標記誤判，佐證寫明實際設定位置（Nginx / 閘道設定檔 / IdP 主控台）
  與具體數值。**同時要驗證應用程式無法被繞過閘道直接存取**，
  否則逾時等於沒設，是真漏洞。

- **機器對機器（M2M）端點使用長效憑證**——批次作業、服務帳號、
  排程呼叫，沒有互動式使用者，30 分鐘閒置逾時不適用。
  處置：標記誤判，但必須說明該端點不接受互動式使用者登入，
  且憑證改用短效 token 搭配用戶端憑證驗證。
  **若同一組端點同時服務人類使用者，就不能主張誤判。**

- **`SESSION_EXPIRE_AT_BROWSER_CLOSE = True` 被誤讀為沒設逾時**——
  設為 `True` 時 Django 會忽略 `SESSION_COOKIE_AGE` 對 Cookie 的效果，
  複核者可能認為缺少逾時值。
  處置：兩項都設，並在中介層自行檢查閒置時間（如上方過關寫法），
  伺服器端有明確的逾時判斷就沒有爭議。

- **「記住我」功能造成長效 Cookie**——這是真實的功能需求，不是誤判。
  處置：記住我 Cookie 只能用於**重新識別身分**，不能直接授予已驗證工作階段；
  使用者回站時仍須重新輸入密碼或第二因素，且該 Cookie 需可由伺服器端撤銷。

### 判定準則

真漏洞：工作階段閒置超過 30 分鐘後，舊識別碼仍可存取受保護資源。

真漏洞：只有絕對逾時而無閒置逾時（使用者離開後識別碼仍在有效期內可用）。

真漏洞：登出後以原識別碼重送請求仍可通過驗證——常見於只清 Cookie
未刪伺服器端記錄，或無狀態 token 無撤銷機制。

真漏洞：登出僅刪除工作階段中的部分欄位（如只 `del session["uid"]`），
工作階段本體未作廢。

誤判：逾時實作在應用程式外層（代理、閘道、IdP），且已確認無法繞過該層存取。

誤判：純 M2M 端點，不接受互動式使用者登入。

---

## SAST-AUTH-004 · 登入失敗未鎖定與密碼強度未驗證

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | —（無通用的「缺少帳號鎖定」規則） | — |
| Checkmarx | —（無通用規則，多靠人工複核） | — |
| Semgrep | —（可自訂 rule 檢查登入路由是否掛上限流中介層） | — |
| SonarQube | —（無密碼政策規則） | — |
| CodeQL | `js/missing-rate-limiting`（登入等驗證路由缺少限流） | Medium–High |
| gosec | — | — |
| bandit | — | — |
| AWVS | Login page password-guessing attack | Medium |
| ZAP / WebInspect | —（暴力破解多為手動或需設定的測試項目） | — |

**靜態工具幾乎完全抓不到這一類**——「缺少某個東西」不在資料流上，
沒有 sink 可以標。唯一穩定會報的是 CodeQL 的限流規則，且僅限它認得的
Node.js 路由樣式。實務上這兩項是**人工複核與滲透測試的必問題目**，
而複核者要看的是：門檻數字、鎖定時長、鎖定對象、以及密碼規則的實際實作。

因此過關寫法的重點在於**把數字寫成具名常數並集中在一處**，
讓複核者一眼找得到，而不是散在各處的魔術數字。

### 壞味道

登入端點沒有任何失敗計數，密碼只檢查非空或長度過短：

```go
func Login(account, password string) (*User, error) {
	u, err := repo.FindByAccount(account)
	if err != nil {
		return nil, errors.New("account not found")   // 洩漏帳號是否存在
	}
	if u.Password != md5Hex(password) {               // 弱雜湊，且無失敗計數
		return nil, errors.New("wrong password")      // 錯誤訊息可區分
	}
	return u, nil
}

func SetPassword(pw string) error {
	if len(pw) < 6 {                                  // 長度不足，且無複雜度
		return errors.New("too short")
	}
	...
}
```

```python
@app.post("/login")
def login():
    u = User.query.filter_by(account=request.form["account"]).first()
    if not u or u.password != hashlib.md5(request.form["password"].encode()).hexdigest():
        return "invalid", 401          # 無失敗計數，可無限次嘗試
    ...

def set_password(pw):
    if len(pw) < 8:                    # 僅長度，無複雜度、無歷史比對
        raise ValueError("too short")
```

```javascript
app.post("/login", async (req, res) => {   // 路由未掛任何限流中介層
  const u = await findUser(req.body.account);
  if (!u || u.password !== md5(req.body.password)) return res.sendStatus(401);
  req.session.uid = u.id;
});
```

還有一種常見但更難發現的壞味道：**鎖定只針對帳號，不針對來源 IP**。
攻擊者改用「密碼噴灑」——同一個常見密碼試遍上千個帳號，
每個帳號都只失敗一次，帳號鎖定門檻永遠不會觸發。

### 過關寫法

**帳號鎖定**的樣式：門檻 5 次、鎖定至少 15 分鐘、
**帳號與來源 IP 兩個維度都要計數**、成功登入後歸零、
且無論帳號存不存在都回傳同一則錯誤訊息與相近的回應時間。

**密碼強度**的樣式：長度至少 12 字元、
同時含大寫、小寫、數字、特殊符號四類、
且不得與前 3 次使用過的密碼相同（比對歷史雜湊，不是存明文）。

```go
const (
	maxFailures     = 5
	lockDuration    = 15 * time.Minute
	minPasswordLen  = 12
	passwordHistory = 3
)

var ErrInvalidCredentials = errors.New("invalid account or password")

func Login(ctx context.Context, account, password, srcIP string) (*User, error) {
	// 帳號與來源 IP 兩個維度分別檢查
	for _, k := range []string{"acct:" + account, "ip:" + srcIP} {
		if locked, _ := limiter.IsLocked(ctx, k); locked {
			return nil, ErrAccountLocked
		}
	}

	u, err := repo.FindByAccount(ctx, account)
	if err != nil || bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)) != nil {
		_ = limiter.Fail(ctx, "acct:"+account, maxFailures, lockDuration)
		_ = limiter.Fail(ctx, "ip:"+srcIP, maxFailures, lockDuration)
		return nil, ErrInvalidCredentials // 帳號不存在與密碼錯誤回傳同一則訊息
	}

	_ = limiter.Reset(ctx, "acct:"+account)
	_ = limiter.Reset(ctx, "ip:"+srcIP)
	return u, nil
}

var (
	reUpper   = regexp.MustCompile(`[A-Z]`)
	reLower   = regexp.MustCompile(`[a-z]`)
	reDigit   = regexp.MustCompile(`[0-9]`)
	reSpecial = regexp.MustCompile(`[^A-Za-z0-9]`)
)

// prevHashes 傳入最近 passwordHistory 次的密碼雜湊
func ValidatePassword(pw string, prevHashes [][]byte) error {
	if utf8.RuneCountInString(pw) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	for _, re := range []*regexp.Regexp{reUpper, reLower, reDigit, reSpecial} {
		if !re.MatchString(pw) {
			return errors.New("password must contain upper, lower, digit and special characters")
		}
	}
	for _, h := range prevHashes { // 不得與前 3 次相同
		if bcrypt.CompareHashAndPassword(h, []byte(pw)) == nil {
			return errors.New("password was used recently")
		}
	}
	return nil
}
```

```python
MAX_FAILURES = 5
LOCK_SECONDS = 15 * 60
MIN_PASSWORD_LEN = 12
PASSWORD_HISTORY = 3

CLASSES = (
    re.compile(r"[A-Z]"), re.compile(r"[a-z]"),
    re.compile(r"[0-9]"), re.compile(r"[^A-Za-z0-9]"),
)

def login(account: str, password: str, src_ip: str):
    for key in (f"acct:{account}", f"ip:{src_ip}"):
        if limiter.is_locked(key):
            raise AccountLocked()

    u = repo.find_by_account(account)
    if u is None or not bcrypt.checkpw(password.encode(), u.password_hash):
        limiter.fail(f"acct:{account}", MAX_FAILURES, LOCK_SECONDS)
        limiter.fail(f"ip:{src_ip}", MAX_FAILURES, LOCK_SECONDS)
        raise InvalidCredentials()      # 統一錯誤訊息

    limiter.reset(f"acct:{account}")
    limiter.reset(f"ip:{src_ip}")
    return u

def validate_password(pw: str, prev_hashes: list[bytes]) -> None:
    if len(pw) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    if not all(c.search(pw) for c in CLASSES):
        raise ValueError("password must contain upper, lower, digit and special characters")
    for h in prev_hashes[:PASSWORD_HISTORY]:
        if bcrypt.checkpw(pw.encode(), h):
            raise ValueError("password was used recently")
```

```javascript
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60 * 1000;
const MIN_PASSWORD_LEN = 12;
const PASSWORD_HISTORY = 3;

// 先掛限流中介層：CodeQL 的限流規則認得掛在路由上的 rate limiter
const loginLimiter = rateLimit({
  windowMs: LOCK_MS,
  max: MAX_FAILURES,
  keyGenerator: (req) => req.ip,       // 來源 IP 維度
  standardHeaders: true,
});

app.post("/login", loginLimiter, async (req, res) => {
  const { account, password } = req.body;
  if (await limiter.isLocked(`acct:${account}`)) return res.sendStatus(423);

  const u = await findUser(account);
  const ok = u && (await bcrypt.compare(password, u.passwordHash));
  if (!ok) {
    await limiter.fail(`acct:${account}`, MAX_FAILURES, LOCK_MS);  // 帳號維度
    return res.status(401).json({ error: "invalid account or password" });
  }
  await limiter.reset(`acct:${account}`);
  req.session.regenerate(() => { req.session.uid = u.id; res.sendStatus(204); });
});

function validatePassword(pw, prevHashes) {
  if (pw.length < MIN_PASSWORD_LEN) throw new Error("too short");
  const classes = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/];
  if (!classes.every((re) => re.test(pw))) throw new Error("missing character class");
  return Promise.all(
    prevHashes.slice(0, PASSWORD_HISTORY).map((h) => bcrypt.compare(pw, h))
  ).then((hits) => { if (hits.some(Boolean)) throw new Error("password reused"); });
}
```

配套的三件事，複核時會一起問：

- 密碼雜湊必須用具備工作因子的演算法（bcrypt / scrypt / Argon2 / PBKDF2）。
  `md5`、`sha1`、`sha256` 單次雜湊會被獨立標記為弱雜湊，即使有加鹽。
- 驗證邏輯必須在**伺服器端**。只在前端 JavaScript 檢查密碼強度等於沒檢查，
  且掃描器看得出來——攻擊者直接打 API 就繞過了。
- 帳號被鎖定時，回應與錯誤訊息不應洩漏「該帳號存在」。
  真要提供解鎖倒數，用固定訊息加上通用的等待秒數。

### 常見誤判與處置

- **鎖定與限流在 WAF、API 閘道或 IdP 實作**——應用程式碼中確實沒有計數器，
  CodeQL 的限流規則只看得到 Express 路由，必然標記。
  處置：標記誤判，佐證寫明閘道規則名稱、門檻值與鎖定時長。
  **但必須同時證明應用程式無法繞過閘道直接存取**（例如僅監聽內網、
  或要求閘道簽發的用戶端憑證），否則是真漏洞。

- **密碼規則由網域目錄或身分提供者強制**——使用 AD / LDAP / 單一簽入，
  應用程式從不接觸密碼，程式碼裡當然沒有強度驗證。
  處置：標記誤判，佐證寫明密碼原則的來源系統與實際生效數值。
  **若應用程式另有本機管理者帳號可用密碼登入，該路徑仍須自行驗證。**

- **強度驗證寫在框架設定而非程式碼**——如 Django 的
  `AUTH_PASSWORD_VALIDATORS` 或表單層的 validator，複核者掃 view 看不到。
  處置：標記誤判並指出設定檔位置與各驗證器參數；
  若預設驗證器的長度低於 12 或缺少字元類別檢查，就補上自訂驗證器。

- **API 端點回傳 429 而非鎖定帳號**——限流只擋住請求速率，
  攻擊者放慢速度仍可持續嘗試。
  這**不是誤判**：限流與帳號鎖定是兩件事，兩者都要有。
  處置：當真漏洞修，補上跨越限流視窗的累計失敗計數與鎖定狀態。

### 判定準則

真漏洞：登入端點對同一帳號連續失敗 5 次以上，第 6 次仍正常處理驗證，
未進入鎖定狀態。

真漏洞：只鎖帳號不限來源 IP（或反之）——任一維度缺失都擋不住對應的攻擊手法
（暴力破解 vs 密碼噴灑）。

真漏洞：鎖定時間短於 15 分鐘，或鎖定計數在極短視窗內自動歸零，
使有效嘗試速率不受限。

真漏洞：密碼長度下限低於 12 字元，或未同時要求大寫、小寫、數字、特殊符號四類。

真漏洞：允許重複使用前 3 次內用過的密碼，或根本未保留歷史雜湊。

真漏洞：強度驗證只存在於前端，伺服器端 API 未重複驗證。

真漏洞：帳號不存在與密碼錯誤回傳可區分的訊息或狀態碼（帳號列舉）。

誤判：鎖定、限流或密碼原則由外部元件（閘道、WAF、目錄服務、IdP）強制執行，
且已證明該元件無法被繞過、並可提出實際生效的數值。

灰色地帶——**一律當真漏洞修**：有鎖定機制但門檻設為「登入失敗 10 次」
或鎖定 5 分鐘之類低於基準的值。數字不合規和沒有機制在複核上是同一個結論。
