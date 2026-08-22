# SAST：密碼學誤用

密碼學誤用是靜態掃描**最容易產生大量紅字、也最容易一次修完**的類別。
多數規則不做污點分析，只做 API 比對——看到 `md5.New()`、`DES`、`math/rand`、
`InsecureSkipVerify` 就報，不管你拿去做什麼。因此「用途無關安全」這種辯解
在工具面前無效，改寫比寫誤判說明快。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## SAST-CRYPTO-001 · 已破解的雜湊與加密演算法

涵蓋 MD5 / SHA-1 / MD4 / RIPEMD-160 雜湊，以及 DES / 3DES / RC4 / Blowfish
加密與 ECB 模式。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | Weak Cryptographic Hash / Weak Encryption / Weak Encryption: Insecure Mode of Operation | Critical–High |
| Checkmarx | Use_of_Broken_or_Risky_Cryptographic_Algorithm | High |
| Semgrep | `*.security.*.use-of-md5*` / `*.security.*.use-of-weak-crypto*` / `*.security.*.insecure-cipher-mode*` | ERROR–WARNING |
| SonarQube | S4790（弱雜湊）/ S5547（弱加密演算法）/ S5542（不安全模式與填充） | Critical–Major |
| gosec | G401（MD5/SHA1）/ G405（DES/RC4）/ G406（MD4/RIPEMD160）/ G501 / G502 / G503 / G505 / G506 / G507（封鎖匯入） | HIGH–MEDIUM |
| bandit | B303（不安全雜湊，舊版）/ B324（hashlib 弱雜湊）/ B304（弱加密）/ B305（ECB 模式） | HIGH–MEDIUM |
| CodeQL | Use of a broken or weak cryptographic algorithm | — |

gosec 的 G5xx 是**匯入層**規則：只要 `import "crypto/md5"` 出現在檔案裡就報，
即使那行 import 已經沒有任何呼叫。清理未使用的 import 是零成本的修法。

### 壞味道

```go
import (
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
)

sum := md5.Sum(data)                        // G401 + G501
h := sha1.New()                             // G401 + G505
block, _ := des.NewCipher(key)              // G405 + G502

// ECB：自己一塊一塊跑 block.Encrypt，就是 ECB
for i := 0; i < len(pt); i += block.BlockSize() {
	block.Encrypt(ct[i:], pt[i:])
}
```

```python
import hashlib
from Crypto.Cipher import DES, ARC4, AES

hashlib.md5(data).hexdigest()               # B303 / B324
hashlib.new("sha1", data).hexdigest()       # B324
DES.new(key, DES.MODE_ECB)                  # B304 + B305
ARC4.new(key)                               # B304
AES.new(key, AES.MODE_ECB)                  # B305
```

```javascript
const crypto = require("crypto");

crypto.createHash("md5").update(data).digest("hex");
crypto.createHash("sha1").update(data).digest("hex");
crypto.createCipheriv("des-ede3-cbc", key, iv);
crypto.createCipheriv("aes-256-ecb", key, null);
crypto.createCipheriv("rc4", key, null);
```

### 過關寫法

規則比對的是**演算法字串或套件符號本身**，所以唯一可靠的過關方式是
換掉演算法，而不是加註解或包一層 wrapper。包 wrapper 反而更糟——
Fortify 的 dataflow 仍會追到底層呼叫，但你的誤判說明會變得難以佐證。

雜湊改用 SHA-256 以上；對稱加密改用 AES-GCM（AEAD，同時給你完整性），
不要用 AES-CBC 手工拼 HMAC——`S5542` 對 CBC 加 PKCS#5 仍會標 padding oracle。

```go
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
)

sum := sha256.Sum256(data)

block, err := aes.NewCipher(key) // key 需為 32 bytes
if err != nil {
	return err
}
gcm, err := cipher.NewGCM(block)
if err != nil {
	return err
}
nonce := make([]byte, gcm.NonceSize())
if _, err := rand.Read(nonce); err != nil { // 每次加密都重新產生，勿寫死（G407）
	return err
}
ct := gcm.Seal(nonce, nonce, plaintext, nil)
```

```python
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

digest = hashlib.sha256(data).hexdigest()

aesgcm = AESGCM(key)            # key 為 32 bytes
nonce = os.urandom(12)          # 每次重新產生
ct = aesgcm.encrypt(nonce, plaintext, None)
```

```javascript
const crypto = require("crypto");

const digest = crypto.createHash("sha256").update(data).digest("hex");

const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const tag = cipher.getAuthTag();
```

Go 需要非加密用途的快速雜湊時，用 `hash/fnv` 或 `hash/maphash`；
Python 用 `hashlib.blake2b(digest_size=8)`；JavaScript 用 `crypto.createHash("sha256")`
截短。這些都不在任何弱雜湊規則的比對清單內，等於從源頭消除紅字。

### 常見誤判與處置

- **MD5 用於非安全用途**——快取鍵、檔案去重、ETag、分片雜湊、
  第三方 API 要求的簽章格式。gosec G401 與 bandit B303/B324 不看用途，一律報。
  處置：**優先改寫**。Go 換 `hash/fnv` 或 `maphash`，Python 換
  `hashlib.blake2b`，JavaScript 換 SHA-256 截短——換掉比申報誤判快。
  Python 若因相容性必須留 MD5，加 `hashlib.md5(data, usedforsecurity=False)`
  （3.9+），新版 bandit B324 認得這個參數並降級處理。

- **與外部系統的相容性需求**——對方只收 MD5 簽章或 3DES 加密（常見於
  舊金流、政府介接、傳真閘道）。
  處置：這是真實限制不是誤判。在 `false-positives.md` 記錄為已知風險接受，
  佐證附上對方介接規格的段落，並把該演算法**限縮在單一 adapter 檔案**內，
  避免掃描面擴散到整個程式庫。

- **SHA-1 出現在 Git 物件處理或既有資料格式解析**——讀取既有格式時必須
  用同樣的雜湊，無法選擇。
  處置：標記誤判，佐證寫明該雜湊是格式定義的一部分、非用於驗證安全屬性。

- **gosec G5xx 報未使用的 import**——重構後 `crypto/md5` 還留在 import 區塊。
  處置：直接刪除該 import，不需要任何說明。

### 判定準則

真漏洞：MD5 / SHA-1 / MD4 / RIPEMD-160 用於數位簽章驗證、憑證指紋比對、
訊息完整性檢查、密碼儲存、token 產生，或任何攻擊者有動機製造碰撞的場景。

真漏洞：DES / 3DES / RC4 / Blowfish 用於保護任何仍需保密的資料。

真漏洞：加密使用 ECB 模式（含未指定模式而套件預設為 ECB），無論演算法強度。

誤判：弱雜湊的輸出僅用於效能最佳化（快取鍵、分桶、去重），
且輸出不參與任何存取控制或完整性判斷。

灰色地帶——**一律當真漏洞修**：用途說不清楚、或雜湊值會離開行程邊界
（寫入資料庫、回傳給前端、送往其他服務）。

---

## SAST-CRYPTO-002 · 密碼儲存未使用金鑰推導函式

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | Weak Cryptographic Hash: Insecure PBKDF2 Iteration Count / Weak Cryptographic Hash: Hardcoded Salt | Critical–High |
| Checkmarx | Reversible_One_Way_Hash / Use_of_Hard_coded_Cryptographic_Key | High |
| Semgrep | `*.security.*.md5-used-as-password*` / `*.security.*.insecure-hash-function*` | ERROR |
| SonarQube | S5344（以快速雜湊儲存密碼）/ S2053（雜湊未使用不可預測的 salt） | Blocker–Critical |
| gosec | —（無專屬規則；只會由 G401 / G501 間接命中） | — |
| bandit | —（無專屬規則；靠 Semgrep / CodeQL 補） | — |
| CodeQL | Use of a broken or weak cryptographic hashing algorithm on sensitive data | — |

這一類是掃描器**覆蓋率最差**的項目：gosec 與 bandit 都沒有專屬規則，
但 Fortify / Checkmarx / SonarQube 會標 Blocker。不要因為本地跑 gosec 沒紅字
就以為過關。

### 壞味道

```go
// 直接雜湊，無 salt、無迭代成本
sum := sha256.Sum256([]byte(password))
stored := hex.EncodeToString(sum[:])

// 固定 salt 等於沒有 salt
const salt = "myapp-static-salt"
h := sha256.Sum256([]byte(salt + password))

// 用 == 比對雜湊字串（時序側通道）
if stored == hex.EncodeToString(sum[:]) { /* ... */ }
```

```python
import hashlib

stored = hashlib.sha256(password.encode()).hexdigest()
stored = hashlib.sha256(("mysalt" + password).encode()).hexdigest()

# 迭代次數過低，Fortify 會標 Insecure PBKDF2 Iteration Count
hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000)

if stored == submitted_hash:   # 非常數時間比對
    login()
```

```javascript
const crypto = require("crypto");

const stored = crypto.createHash("sha256").update(password).digest("hex");
const stored2 = crypto.createHash("sha256").update("mysalt" + password).digest("hex");

if (stored === submitted) { login(); }   // 非常數時間比對
```

### 過關寫法

掃描器認的是**函式名稱**：`bcrypt.GenerateFromPassword`、`argon2.IDKey`、
`scrypt.Key`、`pbkdf2_hmac`、`argon2.PasswordHasher`。只要 sink 換成這些
已知的 KDF 呼叫，規則就不再命中——這比調整任何雜湊參數都有效。

三個必要條件：**每筆密碼獨立隨機 salt**、**足夠的運算成本**、
**常數時間比對**。bcrypt 與 argon2 的函式庫會自己處理 salt 與比對，
所以優先選它們——少一個可以出錯的地方，也少一個掃描器會質疑的參數。

```go
import "golang.org/x/crypto/bcrypt"

// 註冊：salt 由函式庫產生並內嵌在輸出字串中
hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
if err != nil {
	return err
}

// 驗證：常數時間比對，不要自己用 == 比
if err := bcrypt.CompareHashAndPassword(hashed, []byte(password)); err != nil {
	return ErrInvalidCredentials
}
```

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()          # salt 與參數皆由函式庫管理

stored = ph.hash(password)     # 註冊

try:                           # 驗證
    ph.verify(stored, password)
except VerifyMismatchError:
    raise InvalidCredentials

# 若環境限制必須用標準庫，PBKDF2 迭代數需拉高並使用隨機 salt
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
```

```javascript
const argon2 = require("argon2");

const stored = await argon2.hash(password);        // 註冊
const ok = await argon2.verify(stored, password);  // 驗證，常數時間

// 或使用 Node 內建 scrypt
const crypto = require("crypto");
const salt = crypto.randomBytes(16);
const dk = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
```

自己比對雜湊字串時務必用常數時間函式：Go `subtle.ConstantTimeCompare`、
Python `hmac.compare_digest`、JavaScript `crypto.timingSafeEqual`。
`==` 會被 Fortify 與 SonarQube 另外標為時序側通道。

### 常見誤判與處置

- **雜湊的不是密碼，是 API token 或 session id**——這些是高熵隨機值，
  不需要 KDF，用 SHA-256 儲存是正確做法。但規則靠**變數名稱**判斷
  （`password`、`passwd`、`pwd`、`secret`），命名踩到就報。
  處置：把變數改名為 `tokenDigest`、`apiKeyHash` 之類，多數規則立刻不報。
  這是最省事的修法。

- **PBKDF2 迭代次數被判過低**——Fortify 有內建門檻，程式碼裡的常數低於門檻
  就標 Critical，即使該值是從設定檔讀入的預設值。
  處置：把預設值直接拉到門檻以上（PBKDF2-HMAC-SHA256 建議 600000 起），
  不要靠設定檔覆寫——掃描器只看程式碼裡的字面值。

- **密碼驗證委外給 OIDC / LDAP / SSO，本地不存密碼**——但程式碼中仍有
  `password` 欄位用於轉送。
  處置：標記誤判，佐證寫明本地無密碼持久化，並確認該欄位未寫入日誌
  （否則會變成另一類真漏洞）。

- **測試資料或種子資料中的雜湊**——fixture 裡寫死 SHA-256 密碼雜湊。
  處置：測試檔改用真正的 KDF 產生，或把 fixture 移出掃描範圍；
  留著會持續產生紅字且難以逐次說明。

### 判定準則

真漏洞：使用者密碼以 MD5 / SHA-1 / SHA-2 / SHA-3 家族**單次雜湊**儲存，
無論是否加 salt——快速雜湊本身就是問題。

真漏洞：使用 KDF 但 salt 為常數、為使用者可控值，或全體使用者共用同一 salt。

真漏洞：PBKDF2 迭代次數低於 600000（HMAC-SHA256），
或 bcrypt cost 低於 10，或 scrypt N 低於 16384。

誤判：被雜湊的值是系統產生的高熵隨機憑證（token、session id、API key），
且產生來源為密碼學安全亂數（見 SAST-CRYPTO-003）。

---

## SAST-CRYPTO-003 · 不安全的亂數來源

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | Insecure Randomness | Critical–High |
| Checkmarx | Use_of_Cryptographically_Weak_PRNG | High |
| Semgrep | `*.security.*.math-random-used*` / `*.security.*.insecure-random*` | ERROR–WARNING |
| SonarQube | S2245 | Critical |
| gosec | G404 | HIGH |
| bandit | B311 | LOW |
| CodeQL | Insecure randomness | — |

bandit 把 B311 標為 LOW，Fortify 標 Critical——**以嚴格的那一邊為準**。
稽核報告通常採用 Fortify 的等級。

### 壞味道

```go
import "math/rand"

token := fmt.Sprintf("%d", rand.Int63())          // G404
otp := rand.Intn(1000000)                          // G404
rand.Seed(time.Now().UnixNano())                   // 種子可預測，等於沒有熵

// math/rand/v2 同樣被 G404 命中，換版本不能過關
import mrand "math/rand/v2"
sessionID := mrand.Uint64()
```

```python
import random

token = "".join(random.choices(string.ascii_letters, k=32))   # B311
otp = random.randint(100000, 999999)                          # B311
reset_code = str(random.random())[2:10]                       # B311
random.seed(time.time())
```

```javascript
const token = Math.random().toString(36).slice(2);
const otp = Math.floor(Math.random() * 1000000);
const uuid = "id-" + Date.now() + Math.random();
```

### 過關寫法

規則比對的是**套件路徑**：`math/rand`、`random`、`Math.random`。
換成 `crypto/rand`、`secrets`、`crypto.randomBytes` 之後規則直接不命中，
不需要任何說明。三種語言的密碼學安全來源都在標準庫裡，沒有導入成本。

```go
import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

// 隨機 token
b := make([]byte, 32)
if _, err := rand.Read(b); err != nil {
	return "", err
}
token := base64.RawURLEncoding.EncodeToString(b)

// 範圍內隨機整數（六位數 OTP）
n, err := rand.Int(rand.Reader, big.NewInt(900000))
if err != nil {
	return 0, err
}
otp := int(n.Int64()) + 100000
```

```python
import secrets

token = secrets.token_urlsafe(32)
otp = secrets.randbelow(900000) + 100000
reset_code = secrets.token_hex(16)
```

```javascript
const crypto = require("crypto");

const token = crypto.randomBytes(32).toString("base64url");
const otp = crypto.randomInt(100000, 1000000);
const id = crypto.randomUUID();
```

`crypto/rand`、`secrets`、`crypto.randomBytes` 都不需要也不接受種子——
若程式碼中還留著 seeding 邏輯，代表換得不完整，掃描器會從 seed 那行
繼續標記。

### 常見誤判與處置

- **亂數用於非安全用途**——負載測試的抖動、退避重試的 jitter、
  UI 動畫、抽樣、洗牌展示資料。gosec G404 與 bandit B311 一律報。
  處置：這類場景改用 `crypto/rand` 的效能成本可以忽略，
  **直接換掉比申報誤判省事**。真的在熱路徑上（每秒數萬次）才走誤判流程，
  佐證需寫明該值不影響任何安全決策，且不會出現在對外回應中。

- **UUID 產生函式庫被連帶標記**——部分 Go UUID 套件內部使用 `math/rand`
  作為 fallback。工具會標在你的呼叫點。
  處置：確認套件版本使用 `crypto/rand`（如 `google/uuid` 的 `uuid.NewRandom`
  走 `crypto/rand`），標記誤判並註明套件版本；若確為 `math/rand` fallback，
  這是真漏洞，換套件。

- **測試碼中固定 seed 以求可重現**——測試需要決定性行為。
  處置：把測試檔排除在掃描範圍外，或標記誤判並註明檔案為 `_test.go` /
  `test_*.py`。多數工具支援依路徑排除，設定一次即可。

### 判定準則

真漏洞：非密碼學亂數的輸出用於 session id、CSRF token、密碼重設連結、
OTP、邀請碼、檔案上傳名稱、加密的 key / IV / nonce / salt，
或任何攻擊者猜中就能取得存取權的值。

真漏洞：使用 `crypto/rand` 但 IV / nonce 被寫死為常數（gosec G407 另外標記）。

誤判：亂數僅用於效能或體驗（jitter、動畫、抽樣），輸出不離開行程邊界，
且不參與任何存取控制判斷。

灰色地帶——**一律當真漏洞修**：亂數輸出會出現在 URL、回應內容或日誌中，
即使目前用途無關安全，日後被誤用的成本遠高於現在換掉。

---

## SAST-CRYPTO-004 · TLS 憑證驗證被關閉

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | Insecure SSL: Server Identity Verification Disabled | Critical |
| Checkmarx | Improper_Certificate_Validation / SSL_Verification_Bypass | High |
| Semgrep | `*.security.*.disabled-cert-validation*` / `*.security.*.request-with-verify-false*` / `*.security.*.insecure-skip-verify*` | ERROR |
| SonarQube | S4830（伺服器憑證應被驗證）/ S4423（弱 TLS 協定版本） | Blocker |
| gosec | G402（含 `InsecureSkipVerify: true`、`MinVersion` 過低） | HIGH |
| bandit | B501（`verify=False`）/ B502 / B503（不安全的 SSL 版本與預設值） | HIGH |
| CodeQL | Disabled TLS certificate check / Request without certificate validation | — |
| Nessus / AWVS | SSL Certificate Cannot Be Trusted / SSL Self-Signed Certificate | Medium–High |

DAST 端會從另一側看到同一個問題：伺服器若使用自簽或過期憑證，
Nessus 與 AWVS 會直接標記。源碼端關掉驗證，通常代表伺服器端也有憑證問題，
兩份報告會同時出現紅字。

### 壞味道

```go
tr := &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // G402
}
client := &http.Client{Transport: tr}

// 版本過低同樣被 G402 命中
cfg := &tls.Config{MinVersion: tls.VersionTLS10}

// 自訂 VerifyPeerCertificate 卻直接回 nil，等於沒驗
cfg2 := &tls.Config{
	InsecureSkipVerify: true,
	VerifyPeerCertificate: func(raw [][]byte, chains [][]*x509.Certificate) error {
		return nil
	},
}
```

```python
import requests, ssl, urllib3

requests.get(url, verify=False)                    # B501
urllib3.disable_warnings()                          # 常與上一行成對出現

ctx = ssl._create_unverified_context()              # B502/B503
ssl._create_default_https_context = ssl._create_unverified_context

ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLSv1)           # 版本過低
ctx2.check_hostname = False
ctx2.verify_mode = ssl.CERT_NONE
```

```javascript
const https = require("https");

const agent = new https.Agent({ rejectUnauthorized: false });
axios.get(url, { httpsAgent: agent });

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";     // 全域關閉，最嚴重
```

### 過關寫法

不要關驗證，而是**把該信任的 CA 加進信任鏈**。掃描器認得
`RootCAs` / `verify=<path>` / `ca` 這些欄位——它們的存在就是「有在驗證」的
明確訊號；相對地，任何形式的 `InsecureSkipVerify` / `verify=False` /
`rejectUnauthorized: false` 都是規則的直接比對目標，包成變數或讀設定檔
也躲不掉（Fortify 與 Checkmarx 會做常數傳播）。

```go
import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
)

pool, err := x509.SystemCertPool()
if err != nil {
	return err
}
pem, err := os.ReadFile("/etc/ssl/internal-ca.pem")
if err != nil {
	return err
}
pool.AppendCertsFromPEM(pem)

client := &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12, // 明確寫出來，G402 才不報
		},
	},
}
```

```python
import requests

# 指向內部 CA 憑證檔，而非 verify=False
resp = requests.get(url, verify="/etc/ssl/internal-ca.pem")

# 需要自建 context 時，維持預設的驗證行為
import ssl
ctx = ssl.create_default_context(cafile="/etc/ssl/internal-ca.pem")
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
```

```javascript
const fs = require("fs");
const https = require("https");

const agent = new https.Agent({
  ca: fs.readFileSync("/etc/ssl/internal-ca.pem"),
  minVersion: "TLSv1.2",
  rejectUnauthorized: true,   // 明確寫出來，比省略更好過關
});
axios.get(url, { httpsAgent: agent });
```

明確寫出 `MinVersion` / `minimum_version` / `minVersion` 有額外好處：
SonarQube S4423 與 gosec G402 都會檢查是否**未指定**版本下限，
省略等同接受舊協定。

### 常見誤判與處置

- **開發環境用自簽憑證**——本機或測試環境沒有正式憑證，開發時關掉驗證，
  程式碼卻一路帶進正式庫。這是掃描紅字最常見的來源。
  處置：**不是誤判，是真漏洞**。改為把自簽 CA 放進信任鏈
  （`RootCAs` / `verify=<path>` / `ca`），開發與正式用同一段程式碼、
  不同的 CA 檔路徑。用旗標或環境變數切換 `InsecureSkipVerify` 一樣會被標記，
  因為工具無法證明該旗標在正式環境為 false。

- **內部服務間呼叫，走私有網路**——認為不需要驗證憑證。
  處置：仍應驗證。內網不是信任邊界，且掃描器不接受這個論點。
  若確實無法佈署內部 CA，記錄為已知風險接受並限縮在單一 HTTP client
  建構函式內，不要散在各處。

- **憑證釘選（pinning）自行實作**——用 `InsecureSkipVerify: true` 搭配
  `VerifyPeerCertificate` 做指紋比對。這是 Go 的官方釘選寫法，
  但 gosec G402 只看 `InsecureSkipVerify` 欄位，必然誤報。
  處置：標記誤判，佐證需寫明 `VerifyPeerCertificate` 的實作行號、
  比對的指紋來源，以及**驗證失敗時回傳 error** 的分支。
  若該函式在任何路徑上回傳 `nil` 而未比對，就是真漏洞。

- **測試碼中的 mock HTTPS 伺服器**——`httptest.NewTLSServer` 的 client
  預設帶 `InsecureSkipVerify`。
  處置：使用 `server.Client()` 取得已配置好信任鏈的 client，
  或把測試檔排除在掃描範圍外。

### 判定準則

真漏洞：正式程式碼路徑上存在 `InsecureSkipVerify: true`、`verify=False`、
`rejectUnauthorized: false`、`CERT_NONE`、`check_hostname = False`，
或 `NODE_TLS_REJECT_UNAUTHORIZED=0`，且無指紋比對作為替代驗證。

真漏洞：關閉驗證由旗標或環境變數控制——工具無法證明正式環境的取值，
稽核也不會接受。

真漏洞：`VerifyPeerCertificate` 存在但在某條路徑上直接回傳 `nil`。

真漏洞：未指定 TLS 版本下限，或下限低於 TLS 1.2。

誤判：`InsecureSkipVerify: true` 僅作為憑證釘選的前置，
且 `VerifyPeerCertificate` 對所有輸入都執行指紋比對、不符時回傳 error。

誤判：僅出現在測試檔（`_test.go`、`test_*.py`、`*.spec.js`），
且該檔案不會被編譯進正式產出。
