# SAST：硬編碼憑證與金鑰

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

硬編碼憑證與登入功能無關——批次作業、公開資料 API、沒有登入畫面的後台服務，
一樣可能把資料庫密碼或 API 金鑰寫在原始碼裡，而幾乎每套掃描器都有專屬規則且必報。
所以本則獨立一檔、一律載入。check-id 沿用 `SAST-AUTH-001`（0.5.0 以前在 `sast-session-auth.md`），
舊的 `findings.md` 與勾稽表不必改。

## SAST-AUTH-001 · 硬編碼帳號密碼與金鑰

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Password Management: Hardcoded Password | High | unverified | — |
| Fortify | Key Management: Hardcoded Encryption Key | Critical | unverified | — |
| Checkmarx | Use_Of_Hardcoded_Password / Hardcoded_Password_in_Connection_String | High | unverified | — |
| Semgrep | `*.secrets.*.detected-*` / `*.security.*.hardcoded-*` | ERROR | unverified | — |
| SonarQube | S2068（硬編碼憑證）/ S6418（硬編碼機密） | Blocker | unverified | — |
| CodeQL | `go/hardcoded-credentials`、`py/hardcoded-credentials`、`js/hardcoded-credentials` | High | unverified | — |
| gosec | G101 | HIGH | unverified | — |
| bandit | B105 / B106 / B107 | LOW–MEDIUM | unverified | — |
| gitleaks / trufflehog | 高熵字串與供應商金鑰樣式 | High | unverified | — |

這是**唯一一類靜態工具偵測率接近 100% 的認證缺失**：規則靠變數名關鍵字
（`password`、`secret`、`token`、`apikey`）加字串熵值判斷，不需要污點分析，
所以躲不掉，也因此誤報率相對高。

### 壞味道

```go
const dbPassword = "EXAMPLE-PASSWORD-DO-NOT-USE"
var jwtSecret = []byte("my-super-secret-key")

db, _ := sql.Open("mysql", "root:EXAMPLE-PASSWORD-DO-NOT-USE@tcp(10.0.0.5:3306)/app")

if user == "admin" && pass == "admin123" {  // 後門帳號
	return true
}
```

```python
DB_PASSWORD = "EXAMPLE-PASSWORD-DO-NOT-USE"
SECRET_KEY = "django-insecure-8f3k2j4h5g6f7d8s9a0"

conn = pymysql.connect(host="10.0.0.5", user="root", password="EXAMPLE-PASSWORD-DO-NOT-USE")

def login(u, p):
    return u == "admin" and p == "admin123"
```

```javascript
const JWT_SECRET = "my-super-secret-key";
const dbUrl = "postgres://root:EXAMPLE-PASSWORD-DO-NOT-USE@10.0.0.5:5432/app";

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
  **不要在設定檔整條停用規則**——那會連正式碼的真漏洞一起放掉。

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
