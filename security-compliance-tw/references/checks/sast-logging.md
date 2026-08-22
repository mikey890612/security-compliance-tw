# SAST：日誌與稽核紀錄

日誌內容從外部觀測不到，因此本檔全部是源碼面的判定，
DAST 工具（AWVS / Nessus / ZAP / WebInspect）在這幾項不會有對應告警。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## SAST-LOG-001 · 日誌注入與日誌偽造

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | Log Forging / Log Forging (debug) | High（debug 變體多為 Low） |
| Checkmarx | Log_Forging | Medium |
| SonarQube | S5145 | Blocker |
| CodeQL | `go/log-injection` / `py/log-injection` / `js/log-injection` | High |
| Semgrep | —（社群規則庫覆蓋不完整，多數專案需自訂規則） | — |
| gosec | —（無專屬規則） | — |
| bandit | —（無專屬規則） | — |

### 壞味道

外部輸入未處理換行與控制字元，直接串接或格式化進日誌 API。
攻擊者送出 `alice\n2026-08-22T10:00:00Z INFO admin login success`
就能在日誌檔中偽造一整行看起來合法的紀錄。

```go
log.Printf("login failed for user: %s", r.FormValue("user"))
log.Println("request from " + r.Header.Get("User-Agent"))
slog.Info("payload received: " + string(body))
```

```python
logger.info("login failed for user: %s" % request.form["user"])
logger.warning(f"request from {request.headers.get('User-Agent')}")
logger.debug("payload received: " + raw_body)
```

```javascript
console.log("login failed for user: " + req.body.user);
logger.info(`request from ${req.headers["user-agent"]}`);
```

`%s` 與 f-string 沒有差別——污點分析看的是「外部值有沒有進入 sink」，
不是用什麼語法拼進去的。

### 過關寫法

兩層一起做：**結構化日誌**讓編碼器把換行轉義掉，
**具名的 sanitize 函式**讓引擎與人審都看得到消毒點。
只做結構化而不留具名函式，Fortify 常常仍會沿污點路徑報出來。

```go
var logUnsafe = strings.NewReplacer("\n", "\\n", "\r", "\\r", "\x1b", "")

func sanitizeForLog(s string) string {
	if len(s) > 256 {
		s = s[:256]
	}
	return logUnsafe.Replace(s)
}

slog.Info("auth failed",
	slog.String("event", "AUTH_FAIL"),
	slog.String("user_id", sanitizeForLog(userID)),
	slog.String("ua", sanitizeForLog(r.Header.Get("User-Agent"))))
```

```python
_LOG_UNSAFE = str.maketrans({"\n": "\\n", "\r": "\\r", "\x1b": ""})


def sanitize_for_log(v) -> str:
    return str(v)[:256].translate(_LOG_UNSAFE)


logger.info(
    "auth failed",
    extra={
        "event": "AUTH_FAIL",
        "user_id": sanitize_for_log(user_id),
        "ua": sanitize_for_log(request.headers.get("User-Agent")),
    },
)
```

```javascript
const sanitizeForLog = (v) =>
  String(v).slice(0, 256).replace(/\r/g, "\\r").replace(/\n/g, "\\n").replace(/\x1b/g, "");

logger.info({
  event: "AUTH_FAIL",
  userId: sanitizeForLog(req.body.user),
  ua: sanitizeForLog(req.headers["user-agent"]),
}, "auth failed");
```

若使用 Fortify 或 Checkmarx，把 `sanitizeForLog` 註冊為 cleanse rule / sanitizer，
之後所有經過它的路徑就會自動消音，不必逐筆寫誤判說明。

### 常見誤判與處置

- **已用 JSON 結構化編碼器，換行實際上已被轉義**——zap、slog 的 JSON handler、
  pino 都會把 `\n` 轉成 `\\n`，日誌行無法被撐開，但 Fortify 仍沿污點路徑報。
  處置：優先把 encoder 或 sanitize helper 註冊為 cleanse rule；
  來不及調規則就標記誤判，佐證附上實際輸出樣本，顯示換行已被轉義。

- **記錄的值不是字串型別**——例如 `int64` 主鍵、已驗證過的列舉常數、
  框架產生的 UUID。Checkmarx 型別推導不足時仍會標。
  處置：標記誤判，佐證寫明型別與驗證位置。
  但若是 `fmt.Sprintf("%v", obj)` 把整個 struct 印出，其中含字串欄位，
  就不是誤判。

- **值來自內部服務的回應**——常被開發者當成「內部資料所以安全」。
  處置：**不接受這個理由**。上游服務的欄位可能源自使用者輸入，
  照 sanitize 處理，成本遠低於爭論。

### 判定準則

真漏洞：外部輸入（HTTP 參數、標頭、路徑、檔案、資料庫欄位）未經
換行與控制字元處理，即以串接或格式化進入日誌 API。

真漏洞：以 `%v`、`%+v`、`repr()`、`JSON.stringify()` 直接輸出含外部輸入的整個物件。

誤判：值可回溯到程式內常數、為布林或數值型別、
或已由結構化編碼器轉義且能提出輸出佐證。

灰色地帶——**一律當真漏洞修**：值來自 `User-Agent`、`Referer`、
`X-Forwarded-For` 等標頭，或來自 URL path。這些是偽造日誌行最常用的入口。

---

## SAST-LOG-002 · 敏感資訊寫入日誌

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | Privacy Violation | High（密碼、金鑰類常判為 Critical） |
| Checkmarx | Privacy_Violation | Medium–High |
| SonarQube | S5757 | Security Hotspot |
| CodeQL | `go/clear-text-logging` / `py/clear-text-logging-sensitive-data` / `js/clear-text-logging` | High |
| Semgrep | —（需自訂 pattern，比對 password / token / secret / id_no 等欄位名） | — |
| gosec | —（G101 只看硬編憑證，不看日誌 sink） | — |
| bandit | —（無專屬規則） | — |

Fortify 的 Privacy Violation 主要靠**變數與欄位名稱**觸發：
`password`、`passwd`、`pwd`、`token`、`secret`、`ssn`、`creditCard` 等。
命名與 sink 的組合就會報，不需要真的追到值。

### 壞味道

```go
log.Printf("login attempt: user=%s password=%s", user, password)
slog.Info("request", slog.Any("body", reqBody))       // 整包請求含密碼
log.Printf("token=%s", authHeader)
log.Printf("member: %+v", member)                     // struct 內含身分證號
```

```python
logger.info("login attempt: user=%s password=%s", user, password)
logger.debug("headers: %s", dict(request.headers))    # 含 Authorization
logger.info("member data: %s", member.__dict__)       # 含身分證號、生日
```

```javascript
console.log("login attempt", { user, password });
logger.info({ headers: req.headers }, "incoming");     // 含 authorization / cookie
logger.debug("member: " + JSON.stringify(member));
```

需要當成敏感資訊處理的至少有：密碼、憑證與金鑰、Session ID 與 JWT、
身分證統一編號、護照號碼、信用卡號、金融帳號、健康與病歷資料、
以及「姓名＋生日」這類可直接指認個人的組合。

### 過關寫法

用**白名單欄位化**，不要用黑名單遮罩——黑名單一定會漏掉新加的欄位。
另外，日誌中的使用者識別欄位要用系統內部代碼，
不可直接使用身分證號、手機號碼或電子郵件這類個資型態的值。

日誌五要素固定為：使用者 ID（系統內部代碼，非個資）、
經校時的時間戳記、執行的功能或存取的資源、事件類型或等級、事件描述。

```go
func maskTail(s string, keep int) string {
	if len(s) <= keep {
		return "****"
	}
	return "****" + s[len(s)-keep:]
}

// 只記白名單欄位，憑證類完全不進日誌
slog.Info("member updated",
	slog.String("event", "DATA_CHANGE"),
	slog.String("user_id", actor.InternalID),         // 內部代碼
	slog.String("resource", "PUT /members/"+target.InternalID),
	slog.String("id_no", maskTail(target.NationalID, 3)))
```

```python
ALLOWED_FIELDS = ("event", "user_id", "resource", "level", "detail")


def mask_tail(s: str, keep: int = 3) -> str:
    s = str(s)
    return "****" if len(s) <= keep else "****" + s[-keep:]


logger.info(
    "member updated",
    extra={
        "event": "DATA_CHANGE",
        "user_id": actor.internal_id,
        "resource": f"PUT /members/{target.internal_id}",
        "level": "INFO",
        "detail": f"id_no={mask_tail(target.national_id)}",
    },
)
```

```javascript
// pino 的 redact：在序列化層就移除，污點路徑直接斷開
const logger = require("pino")({
  redact: {
    paths: ["req.headers.authorization", "req.headers.cookie", "*.password", "*.token", "*.nationalId"],
    censor: "[REDACTED]",
  },
});

logger.info({ event: "DATA_CHANGE", userId: actor.internalId, resource: "PUT /members" }, "member updated");
```

遮罩後要**指派給新變數**再送進日誌，不要把遮罩結果寫回原變數名。
`password = mask(password)` 之後再 log，多數引擎仍會認為 sink 收到了
名為 `password` 的值。

### 常見誤判與處置

- **變數名叫 token 但不是憑證**——分頁游標 `nextToken`、CSRF 的公開
  `formToken`、追蹤用 `traceToken`。Fortify 與 Checkmarx 靠名稱推斷，必然誤報。
  處置：**改名比寫誤判說明省事**，改成 `pageCursor`、`traceId`。
  若因相容性不能改名，標記誤判並佐證該值的產生位置與非機密性質。

- **只有 DEBUG 等級才印完整請求體**——開發者常主張「正式環境是 INFO，不會印」。
  掃描器不看日誌等級，照樣標記。
  處置：**這通常不是誤判**。日誌等級是可被組態改回去的執行期設定，
  不是程式碼保證。正解是在序列化層就把敏感欄位移除（如上方 pino redact），
  這樣即使等級調到 DEBUG 也不會外洩。

- **記的是雜湊或遮罩後的值，但引擎仍追到原始變數**——常見於
  `log.Printf("pwd hash=%s", sha256Hex(password))`。
  處置：把遮罩／雜湊函式註冊為 cleanse rule；或先指派新變數再記錄，
  佐證附上遮罩函式實作與輸出樣本。

### 判定準則

真漏洞：密碼、憑證、金鑰、Session ID、JWT、身分證統一編號、
信用卡號、金融帳號、健康或病歷資料，以明文出現在任何日誌敘述或欄位中。

真漏洞：以 `%+v`、`__dict__`、`JSON.stringify()` 輸出含上述欄位的整個物件，
即使當下那個欄位剛好是空值。

真漏洞：日誌的使用者識別欄位直接使用身分證號、手機號碼或電子郵件。

誤判：記錄的是不可逆遮罩後的值（僅保留末 3 至 4 碼），
或為系統內部代碼、無法反推個人身分的識別碼。

---

## SAST-LOG-003 · 缺少必要的稽核事件記錄

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | —（無現成規則；可用 Custom Rules 的 Structural Rule 檢查特定分支是否呼叫稽核 API） | — |
| Checkmarx | —（需自訂 query） | — |
| Semgrep | —（可自訂：比對錯誤回應分支中缺少稽核呼叫） | — |
| SonarQube | — | — |
| CodeQL | — | — |
| gosec | — | — |
| bandit | — | — |

這一項**沒有現成的污點分析規則會報**，屬於覆蓋率缺口。
它出現的場合是人工複核與稽核抽查，而不是掃描報告。
會被要求補件的時候通常已經來不及，因此要在開發期就用自訂規則或
程式碼審查清單擋下來。

### 壞味道

錯誤分支只回應狀態碼，沒有留下任何可追溯的紀錄。

```go
if !checkPassword(user, pw) {
	http.Error(w, "unauthorized", http.StatusUnauthorized) // 沒有稽核紀錄
	return
}
if !user.CanAccess(res) {
	http.Error(w, "forbidden", http.StatusForbidden)       // 沒有稽核紀錄
	return
}
db.Delete(&member)                                        // 重要資料刪除，沒有紀錄
```

```python
if not check_password(user, pw):
    return jsonify({"error": "unauthorized"}), 401        # 沒有稽核紀錄

if not user.can_access(res):
    abort(403)                                            # 沒有稽核紀錄

db.session.delete(member)                                 # 重要資料刪除，沒有紀錄
```

```javascript
if (!checkPassword(user, pw)) {
  return res.status(401).json({ error: "unauthorized" }); // 沒有稽核紀錄
}
if (!user.canAccess(resource)) {
  return res.status(403).end();                           // 沒有稽核紀錄
}
await Member.destroy({ where: { id } });                  // 重要資料刪除，沒有紀錄
```

### 過關寫法

必須留下稽核紀錄的四類事件：
**身分鑑別失敗**、**存取資源失敗（授權被拒）**、
**重要資料的新增修改刪除**、**管理者行為**（權限調整、組態變更、資料匯出）。

每一筆紀錄固定含五要素：
使用者 ID（系統內部代碼，不可為身分證號等個資型態）、
經校時的時間戳記（NTP 同步，含時區，建議 RFC3339 或 UTC）、
執行的功能或存取的資源、事件類型或等級、事件描述。

用一個集中的 `Audit` 進入點，不要讓各 handler 各寫各的——
分散寫的一定會漏欄位，也無法用自訂規則檢查覆蓋率。

```go
type AuditEvent struct {
	UserID    string    `json:"user_id"`   // 系統內部代碼，非個資
	At        time.Time `json:"at"`        // 經 NTP 校時，RFC3339 含時區
	Resource  string    `json:"resource"`  // 執行的功能或存取的資源
	Type      string    `json:"type"`      // AUTH_FAIL / ACCESS_DENIED / DATA_CHANGE / ADMIN_ACTION
	Level     string    `json:"level"`
	Detail    string    `json:"detail"`
}

func Audit(ctx context.Context, e AuditEvent) { /* 寫入稽核儲存 */ }

if !checkPassword(user, pw) {
	Audit(r.Context(), AuditEvent{
		UserID:   resolveInternalID(attemptedAccount),
		At:       time.Now().UTC(),
		Resource: "POST /login",
		Type:     "AUTH_FAIL",
		Level:    "WARN",
		Detail:   sanitizeForLog("password mismatch"),
	})
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return
}
```

```python
def audit(*, user_id, resource, type_, level, detail):
    logger.info(
        detail,
        extra={
            "user_id": user_id,                                  # 內部代碼
            "at": datetime.now(timezone.utc).isoformat(),        # 經校時，含時區
            "resource": resource,
            "type": type_,
            "level": level,
        },
    )


if not user.can_access(res):
    audit(
        user_id=user.internal_id,
        resource=f"GET /records/{res.id}",
        type_="ACCESS_DENIED",
        level="WARN",
        detail=sanitize_for_log("role lacks read permission"),
    )
    abort(403)
```

```javascript
function audit({ userId, resource, type, level, detail }) {
  logger.info({
    user_id: userId,                        // 內部代碼
    at: new Date().toISOString(),           // 經校時，含時區
    resource,
    type,
    level,
    detail: sanitizeForLog(detail),
  });
}

await Member.destroy({ where: { id } });
audit({
  userId: req.user.internalId,
  resource: `DELETE /members/${id}`,
  type: "DATA_CHANGE",
  level: "NOTICE",
  detail: "member record deleted",
});
```

### 常見誤判與處置

- **主張「已經有 Nginx access log」**——access log 只有 URL、狀態碼與來源 IP，
  沒有使用者 ID 與事件類型，授權被拒的 403 與一般 403 在其中無法區分，
  也看不出是哪一筆資料被異動。
  處置：**不是誤判**，必須補應用層稽核事件。access log 只能當輔助佐證。

- **主張「中介層已統一記錄」，但錯誤在中介層之前就回傳**——
  例如 JWT 驗證失敗由框架的認證中介層直接回 401，
  根本沒進入自訂的稽核 middleware，最該記的鑑別失敗事件反而全部漏掉。
  處置：在框架的錯誤處理 hook 補記（Gin 的錯誤處理中介層、
  Flask 的 `errorhandler(401)`、Express 的 error middleware），
  不能只在 handler 內部記錄。

- **稽核呼叫本身被 Fortify 標成 Log Forging**——因為稽核紀錄必然要記
  使用者輸入（如嘗試登入的帳號）。
  處置：套用 SAST-LOG-001 的 sanitize 後再送進稽核 API。
  **不可以因為掃描器標紅就把稽核紀錄拿掉**，那是拿一個缺失換另一個。

### 判定準則

真問題：身分鑑別失敗、授權被拒、重要資料新增修改刪除、管理者行為
這四類事件中，任一類在源碼中找不到對應的稽核寫入呼叫。

真問題：有紀錄但五要素缺一。最常見的兩種缺法是
「無法歸屬到特定使用者」與「時間戳記沒有時區或未經校時」。

真問題：只在成功路徑記錄，失敗路徑（`401` / `403` / 例外分支）沒有記錄。

可接受：四類事件都由集中的稽核 API 寫入，
且能拿出單一筆實際輸出，逐項對上五要素。

---

## SAST-LOG-004 · 稽核紀錄檔權限過寬或可被覆寫

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| gosec | G302（Chmod 權限過寬）/ G306（WriteFile 權限過寬） | MEDIUM |
| bandit | B103（set_bad_file_permissions） | HIGH／MEDIUM（依權限位元） |
| SonarQube | S2612 | Security Hotspot |
| Fortify | File Permission Manipulation（權限值或路徑來自外部輸入時） | High |
| Checkmarx | — | — |
| Semgrep | —（可自訂：比對建檔 mode 位元） | — |
| CodeQL | — | — |

### 壞味道

```go
os.WriteFile("/var/log/app/audit.log", data, 0666)
os.Chmod("/var/log/app/audit.log", 0777)
f, _ := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644) // 截斷，舊紀錄消失
```

```python
os.chmod("/var/log/app/audit.log", 0o777)
with open("/var/log/app/audit.log", "w") as f:   # "w" 會截斷既有紀錄
    f.write(line)
handler = logging.FileHandler("/var/log/app/audit.log", mode="w")
```

```javascript
fs.writeFileSync("/var/log/app/audit.log", data, { mode: 0o666 });
fs.createWriteStream(logPath, { flags: "w", mode: 0o666 });  // 截斷 + 全域可寫
```

`0664` 也算過寬——同群組的其他服務帳號可以改寫稽核紀錄，
稽核紀錄就失去證據力。

### 過關寫法

三件事：權限收到 `0600` 或 `0640`、一律用附加模式開啟、
路徑與權限值都是程式常數或組態常數，不接受外部輸入。

```go
const auditPath = "/var/log/app/audit.log" // 常數路徑

f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
if err != nil {
	return err
}
defer f.Close()
```

```python
import os
import logging

AUDIT_PATH = "/var/log/app/audit.log"       # 常數路徑

fd = os.open(AUDIT_PATH, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
os.close(fd)                                # 先以正確權限建檔
handler = logging.FileHandler(AUDIT_PATH, mode="a")   # 附加，不截斷
```

```javascript
const AUDIT_PATH = "/var/log/app/audit.log";  // 常數路徑

const stream = fs.createWriteStream(AUDIT_PATH, { flags: "a", mode: 0o600 });
```

更穩的做法是應用程式完全不落地，寫到標準輸出交由平台的日誌收集器
（journald、容器日誌驅動、集中式 log agent）處理，
權限由平台統一管理，程式碼中就沒有建檔的 sink 可以被標記。

### 常見誤判與處置

- **日誌不落地，交由平台收集**——程式只寫標準輸出，但同一個檔案中
  另有非日誌用途的 `os.WriteFile`，gosec G306 照樣報。
  處置：先確認被標記的那行是否真的是日誌；若不是，依該檔案的實際用途判定。
  日誌本身標記誤判，佐證寫明收集方式與平台端的權限設定。

- **主張「權限由部署時的 umask 或 logrotate 決定」**——
  程式寫 `0666`，但 umask 022 讓實際落地是 `0644`，
  或 logrotate 設定 `create 0640` 覆蓋掉。
  處置：**不要靠 umask**，它隨執行環境與服務管理器而變動，
  換一台機器就破功。直接把 mode 改成 `0600` 比寫誤判說明省事。

- **開發環境需要開放權限方便查看日誌**——
  處置：用群組授權（`0640` ＋ 專屬日誌群組）取代放寬權限位元，
  不要在程式碼中依環境分支給不同 mode，那會讓掃描器兩條路徑都報。

### 判定準則

真問題：日誌或稽核紀錄檔以 group 或 other 可寫的權限建立
（含 `0666`、`0777`、`0664`、`0620`）。

真問題：以截斷模式（`O_TRUNC`、`"w"`）開啟稽核紀錄檔，既有紀錄會被清空。

真問題：檔案路徑或權限位元由外部輸入決定（此時同時觸發路徑尋訪類的規則）。

可接受：權限為 `0600` 或 `0640`、以附加模式開啟、路徑為程式或組態常數。

可接受：應用程式不自行落地，日誌寫到標準輸出由平台收集，
且能提出平台端的權限與保存設定作為佐證。
