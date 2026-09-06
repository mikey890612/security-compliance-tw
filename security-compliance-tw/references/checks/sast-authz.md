# SAST：授權與存取控制

授權缺陷與注入類不同：注入是「污點從 source 流到 sink」，授權是
**「該有的檢查不存在」**。污點分析追不了「不存在的東西」，所以商用工具
對授權多半改用**結構規則**——找特定註解、找特定函式呼叫、找 route 註冊表。
這代表過關的關鍵是：把授權動作寫成**單一具名、可被規則辨識的呼叫或註解**，
而不是散在各處的 `if user.Role == "admin"`。

也因為結構規則的辨識能力有限，本類別的漏報（false negative）遠多於誤報。
掃描報告乾淨**不等於**授權沒問題，仍需人工複核路由清單。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## SAST-AUTHZ-001 · 存取資源前未執行授權檢查

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Access Control: Database | Critical | unverified | — |
| Fortify | Often Misused: Authentication（僅認證未授權時） | Medium | unverified | — |
| Checkmarx | —（需自訂查詢，內建無通用「缺少授權」查詢） | — | unverified | — |
| Semgrep | —（無通用規則；框架專屬如 `*.spring.security.*` 才有） | — | unverified | — |
| SonarQube | S4834（Controlling permissions is security-sensitive，Security Hotspot） | — | unverified | — |
| SonarQube | S5808（Authorizations should be based on strong decisions） | Blocker | unverified | — |
| CodeQL | —（無通用查詢） | — | unverified | — |
| gosec / bandit | —（不涵蓋授權語意） | — | unverified | — |

Fortify 的 `Access Control: Database` 是本類別**最常真的被觸發**的規則：
它的判準是「資料庫查詢的鍵值來自使用者輸入，而查詢條件中找不到任何
可回溯到 session／已驗證身分的值」。認得這條判準，就知道怎麼寫才會消掉。

### 壞味道

Handler 只確認「有登入」，沒確認「有權限」：

```go
func deleteOrder(w http.ResponseWriter, r *http.Request) {
	uid := session.Get(r, "uid") // 只取出身分，沒拿來判斷
	if uid == "" {
		http.Error(w, "unauthorized", 401)
		return
	}
	id := r.URL.Query().Get("id")
	db.Exec("DELETE FROM orders WHERE id = ?", id) // 少了權限條件
}
```

```python
@app.route("/api/orders/<order_id>", methods=["DELETE"])
@login_required          # 只有認證
def delete_order(order_id):
    db.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    return "", 204
```

```javascript
router.delete("/orders/:id", requireLogin, async (req, res) => {
  await db.query("DELETE FROM orders WHERE id = $1", [req.params.id]);
  res.sendStatus(204);
});
```

另一種典型：**路由註冊表裡有例外清單**，新增路由時忘了加進去。

```javascript
const PUBLIC_PATHS = ["/login", "/health"];
app.use((req, res, next) => {
  if (PUBLIC_PATHS.includes(req.path)) return next();
  return requireAuth(req, res, next);   // 預設放行的反向寫法
});
```

### 過關寫法

三個要點，缺一掃描器就追不到：

1. **授權寫成單一具名函式**（例如 `authz.Require`），全專案只有這一個入口。
   這樣才有辦法在 Fortify 註冊為 validation rule、在 Checkmarx 定義為
   sanitizer、在 Semgrep 寫成 `pattern-not-inside`。散寫的 `if role == ...`
   任何工具都認不出來。
2. **預設拒絕**。中介層對所有路由強制檢查，公開路由用**明列白名單**，
   且白名單是靜態常數。
3. **檢查與使用在同一個函式內、且檢查在前**。跨函式的守衛多數引擎追不動。

```go
// authz 套件：全專案唯一的授權入口
func Require(ctx context.Context, action string, resourceID string) error {
	sub, ok := SubjectFrom(ctx)
	if !ok {
		return ErrUnauthenticated
	}
	if !policy.Allow(sub, action, resourceID) {
		return ErrForbidden
	}
	return nil
}

func deleteOrder(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	// 守衛與 sink 同一函式、且在前面
	if err := authz.Require(r.Context(), "order:delete", id); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// 即使已授權，查詢仍帶入 session 身分——這一段才是消掉
	// Fortify "Access Control: Database" 的關鍵
	sub, _ := authz.SubjectFrom(r.Context())
	db.Exec("DELETE FROM orders WHERE id = ? AND owner_id = ?", id, sub.UserID)
}
```

```python
def require(action, resource_id):
    subject = current_subject()          # 由 session 取得，非請求參數
    if subject is None:
        abort(401)
    if not policy.allow(subject, action, resource_id):
        abort(403)
    return subject


@app.route("/api/orders/<order_id>", methods=["DELETE"])
def delete_order(order_id):
    subject = require("order:delete", order_id)
    db.execute(
        "DELETE FROM orders WHERE id = ? AND owner_id = ?",
        (order_id, subject.user_id),
    )
    return "", 204
```

```javascript
// 中介層預設拒絕；公開路由以靜態白名單明列
const PUBLIC = new Set(["/login", "/health"]);
app.use((req, res, next) => {
  if (PUBLIC.has(req.path)) return next();
  if (!req.session?.userId) return res.sendStatus(401);
  return next();
});

router.delete("/orders/:id", async (req, res) => {
  const subject = await authz.require(req, "order:delete", req.params.id);
  await db.query("DELETE FROM orders WHERE id = $1 AND owner_id = $2", [
    req.params.id,
    subject.userId,
  ]);
  res.sendStatus(204);
});
```

註解式框架（Spring、NestJS 的 Guard、Django 的 permission_classes）比
自訂函式更容易被工具辨識——若框架已提供，優先用框架的，不要自己造。

### 常見誤判與處置

- **授權在中介層做，handler 內看不到**——這是正確架構，但 Fortify 與
  Checkmarx 的資料流不會跨過框架的中介層註冊機制，會把每個 handler 都報一次。
  處置：標記誤判，佐證需列出「中介層掛載位置行號 + 路由註冊清單 +
  白名單常數定義」三項。只寫「已在 middleware 處理」不足以結案，
  因為無法證明該路由確實走過中介層。**更省事的做法**是在 handler 內
  補一行 `authz.Require`，重複檢查不會壞事，還能把工具與人工複核一起解決。

- **內部管理工具、僅限內網 IP**——常見主張是「這支 API 外面連不到」。
  處置：這通常**不是誤判**。網路層隔離不是授權，內網橫向移動後即可存取。
  若確實無法補授權（例如批次程式由排程器直接呼叫），
  處置是把它從 HTTP 介面移除，改為不對外開放的執行入口，而非標記誤判。

- **唯讀端點被標記**——例如公開的商品列表查詢。
  處置：若資料本來就公開，標記誤判，佐證註明該資源的公開性與
  回傳欄位清單（**必須確認回傳中不含任何非公開欄位**，如成本、內部備註）。

### 判定準則

真漏洞：路由可被已認證但無權限的使用者呼叫，並取得或變更該使用者
本不應存取的資料。判斷方式是找出「這支 API 的授權決策點」——
若找不到任何一行程式碼在做決策，就是真漏洞。

真漏洞：授權採**預設放行**（黑名單／例外清單）架構。即使目前清單正確，
下一支新路由就會漏，一律當真漏洞修。

真漏洞：授權決策的輸入來自請求本身（例如從 header、body 或 JWT 未驗簽的
payload 取出 `role` 就拿來判斷），而非來自伺服器端 session 或已驗簽的憑證。

誤判：授權確實在中介層執行，且能舉證該路由必然經過該中介層
（掛載於路由樹根節點，且無 bypass 分支）。

灰色地帶——**一律當真漏洞修**：授權檢查存在但在資源讀取**之後**才執行
（先查出資料再判斷能不能給）。這種寫法在錯誤訊息、時間差、
以及例外處理路徑上都會洩漏資訊。

---

## SAST-AUTHZ-002 · 不安全的直接物件參考與水平越權

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Access Control: Database | Critical | unverified | — |
| Checkmarx | —（需自訂查詢；部分版本以 `Improper_Access_Control` 呈現） | — | unverified | — |
| Semgrep | —（無通用規則） | — | unverified | — |
| SonarQube | S5808 | Blocker | unverified | — |
| CodeQL | —（無通用查詢） | — | unverified | — |
| gosec / bandit | —（不涵蓋授權語意） | — | unverified | — |
| AWVS | —（需設定多組登入情境才可偵測） | — | unverified | — |
| ZAP | Access Control Testing（附加元件，需設定使用者情境） | Medium–High | unverified | — |

DAST 工具在未設定「兩組不同權限的登入帳號」時，**完全掃不出水平越權**。
掃描報告沒有這一項不代表沒問題。

### 壞味道

主鍵直接來自請求，查詢條件中沒有任何身分相關值：

```go
id := r.URL.Query().Get("account_id")
row := db.QueryRow("SELECT balance FROM accounts WHERE id = ?", id)
```

```python
order_id = request.args["order_id"]
order = Order.query.get(order_id)          # 無 owner 條件
return jsonify(order.to_dict())
```

```javascript
const { invoiceId } = req.params;
const inv = await Invoice.findById(invoiceId);   // 無 owner 條件
res.json(inv);
```

另一種樣式：**身分取自請求參數而非 session**。

```javascript
// userId 由前端傳來，改成別人的就看到別人的資料
const rows = await db.query("SELECT * FROM orders WHERE user_id = $1", [
  req.query.userId,
]);
```

```python
user_id = request.form["user_id"]          # 應該來自 session
profile = Profile.query.filter_by(user_id=user_id).first()
```

```go
uid := r.FormValue("uid") // 同上，來自請求
db.QueryRow("SELECT * FROM profiles WHERE uid = ?", uid)
```

### 過關寫法

最有效的樣式是**把擁有者條件寫進同一個查詢**。這不只是「安全」，
更是掃描器**明確認得**的結構：Fortify 的 `Access Control: Database`
就是在檢查「WHERE 子句中有沒有可回溯到 session 的值」，把
`sub.UserID` 放進同一句 SQL，污點路徑上就出現了 session 來源的節點，
規則條件不成立，發現自然消失。

分兩步寫（先查資料、再比對 owner）在功能上也安全，但引擎追不到關聯，
照樣標 Critical，還得寫誤判說明——直接一步到位比較省事。

```go
sub, ok := authz.SubjectFrom(r.Context())
if !ok {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return
}

// 擁有者條件與主鍵在同一個查詢
row := db.QueryRow(
	"SELECT balance FROM accounts WHERE id = ? AND owner_id = ?",
	r.URL.Query().Get("account_id"), sub.UserID)

var balance int64
if err := row.Scan(&balance); err == sql.ErrNoRows {
	// 查無資料與無權限回傳相同結果，避免以錯誤訊息探測資源是否存在
	http.Error(w, "not found", http.StatusNotFound)
	return
}
```

```python
subject = current_subject()               # 來自 session，非請求參數
order = (
    Order.query
    .filter_by(id=request.view_args["order_id"], owner_id=subject.user_id)
    .first()
)
if order is None:
    abort(404)                            # 不區分「不存在」與「無權限」
return jsonify(order.to_dict())
```

```javascript
const subject = req.session.subject;      // 來自 session
const inv = await Invoice.findOne({
  _id: req.params.invoiceId,
  ownerId: subject.userId,                // 同一個查詢帶入擁有者
});
if (!inv) return res.sendStatus(404);
res.json(inv);
```

若識別碼必須對外曝露，另外加上**不可預測的識別碼**（UUIDv4 或
每個使用者不同的對外代號）。這是縱深防禦，**不能取代擁有者條件**——
只換識別碼而不加條件，Fortify 照報，而且確實仍可被列舉。

多租戶系統把 `tenant_id` 條件下沉到 ORM 的 global scope／
資料庫 row-level security，是更穩的做法，但要留意：下沉之後
handler 層看不到條件，工具會回到「查詢無身分值」的判定而重新報一次，
需要以誤判處置（見下）。

### 常見誤判與處置

- **租戶隔離由 ORM global scope 或資料庫 row-level security 強制**——
  程式碼裡看不到 `WHERE tenant_id = ?`，Fortify 必報。
  處置：標記誤判，佐證需包含 scope／policy 的定義位置、
  作用範圍（是否所有連線都套用）、以及**是否存在可繞過的分支**
  （如 `withoutGlobalScope()`、以管理者連線字串建立的 session）。
  若存在繞過分支且該分支可被一般請求路徑觸達，就不是誤判。

- **識別碼是使用者自己的 session 值，不是請求參數**——例如
  `db.Query("... WHERE id = ?", session.UserID)`。部分工具只看到「變數」
  就報，不追來源。
  處置：標記誤判，佐證寫明該變數的賦值行號與 session 取值函式。

- **管理者端點刻意可查所有人資料**——後台客服查詢功能。
  處置：這**不是誤判**，而是需要另一層檢查。正確作法是保留
  `authz.Require(ctx, "order:read:any", id)` 這類明確的高權限動作宣告，
  並確認該動作只授予管理角色。單純標記誤判會讓真正的垂直越權漏掉。

### 判定準則

真漏洞：查詢或更新的鍵值來自請求，且**同一次資料存取**中沒有任何
來自 session／已驗簽憑證的身分條件，亦無等效的等值授權呼叫。

真漏洞：授權所依據的身分來自請求可控處（query、body、header、cookie 中的
明文欄位、未驗簽的 token payload）。這是本類別最嚴重的樣式，
攻擊者只要改一個數字。

真漏洞：識別碼為連續整數且無擁有者條件——可被自動化列舉，
即使目前無已知外洩也一律修。

誤判：擁有者／租戶條件確實生效（同句查詢、ORM scope、
或資料庫 row-level security），且**不存在可由一般請求路徑觸達的繞過分支**。

誤判：鍵值本身即取自 session，未經請求參數。

---

## SAST-AUTHZ-003 · 前端隱藏選項但後端未檢查（垂直越權）

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Access Control: Database | Critical | unverified | — |
| Fortify | Mass Assignment: Insecure Binder Configuration | High | unverified | — |
| Checkmarx | —（需自訂查詢） | — | unverified | — |
| Semgrep | —（無通用規則；部分框架有 mass assignment 專屬規則） | — | unverified | — |
| SonarQube | S4834（Security Hotspot） | — | unverified | — |
| SonarQube | S5808 | Blocker | unverified | — |
| CodeQL | —（無通用查詢） | — | unverified | — |
| ZAP | Access Control Testing（附加元件，需設定多角色情境） | Medium–High | unverified | — |

**沒有任何工具能看出「前端藏了按鈕、後端沒檢查」**——前端與後端在
不同的掃描範圍內，資料流不相連。此類問題主要靠人工複核路由清單，
以及本節的 mass assignment 樣式間接發現。

### 壞味道

前端以條件渲染隱藏功能：

```javascript
// 前端：只有管理者看得到刪除鈕
{user.role === "admin" && <button onClick={deleteUser}>刪除</button>}

// 後端：完全沒有角色檢查，直接呼叫就能刪
router.post("/api/users/:id/delete", requireLogin, async (req, res) => {
  await db.query("DELETE FROM users WHERE id = $1", [req.params.id]);
  res.sendStatus(204);
});
```

以及與之高度相關的 mass assignment——把整包請求綁進模型，
使用者塞一個 `role` 欄位就自我提權：

```go
var u User
json.NewDecoder(r.Body).Decode(&u) // Body 含 {"role":"admin"} 也照收
db.Save(&u)
```

```python
user = User(**request.json)        # role 欄位一併寫入
db.session.add(user)

# 或
for k, v in request.json.items():
    setattr(user, k, v)
```

```javascript
await User.updateOne({ _id: req.session.userId }, { $set: req.body });
```

第三種樣式：**權限資訊放在使用者可改的地方**。

```javascript
// 角色從 cookie 或 localStorage 帶回來，後端直接信任
const role = req.cookies.role;
if (role === "admin") { /* ... */ }
```

```python
role = request.headers.get("X-User-Role")   # 前端可任意設定
if role == "admin":
    do_admin_thing()
```

```go
role := r.Header.Get("X-Role") // 同上
if role == "admin" {
	doAdminThing()
}
```

### 過關寫法

後端必須獨立完成三件事，且不得依賴前端傳來的任何權限資訊：

1. **角色／權限一律從伺服器端 session 或已驗簽憑證取得**，
   絕不從 header、cookie 明文、request body 讀取。
2. **寫入欄位採白名單**，逐欄指派，不整包綁定。白名單是程式內常數，
   這一點與注入類的欄位白名單相同——工具認得「常數 map 的 value」。
3. **敏感欄位（role、status、balance）走獨立端點**，有各自的授權動作。

```go
// 1. 角色來自 session，不來自請求
sub, ok := authz.SubjectFrom(r.Context())
if !ok || !sub.HasRole("admin") {
	http.Error(w, "forbidden", http.StatusForbidden)
	return
}

// 2. 白名單逐欄指派，不整包 Decode 進實體
var in struct {
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	// 刻意不含 Role / Status，多傳來的欄位被丟棄
}
dec := json.NewDecoder(r.Body)
dec.DisallowUnknownFields() // 明確拒絕未知欄位，工具與人工都看得懂
if err := dec.Decode(&in); err != nil {
	http.Error(w, "bad request", http.StatusBadRequest)
	return
}

db.Exec("UPDATE users SET display_name = ?, email = ? WHERE id = ?",
	in.DisplayName, in.Email, sub.UserID)
```

```python
ALLOWED_FIELDS = {"display_name", "email"}    # 程式內常數白名單

subject = current_subject()
if not subject.has_role("admin"):
    abort(403)

payload = {k: v for k, v in request.json.items() if k in ALLOWED_FIELDS}
for field, value in payload.items():
    setattr(user, field, value)
db.session.commit()
```

```javascript
// 前端隱藏只是體驗，後端必須各自再判一次
router.post("/api/users/:id/delete", async (req, res) => {
  const subject = req.session.subject;              // 來自 session
  if (!subject?.roles.includes("admin")) return res.sendStatus(403);
  await db.query("DELETE FROM users WHERE id = $1", [req.params.id]);
  res.sendStatus(204);
});

// 白名單逐欄指派
const ALLOWED = ["displayName", "email"];
const update = {};
for (const key of ALLOWED) {
  if (key in req.body) update[key] = req.body[key];
}
await User.updateOne({ _id: req.session.userId }, { $set: update });
```

前端的隱藏**保留**——那是使用體驗，不是安全機制。
不要因為後端補了檢查就把前端的條件渲染拿掉，兩邊都要有。

### 常見誤判與處置

- **DTO 已與實體分離，工具仍報 mass assignment**——請求綁到
  `UpdateUserRequest` 而非 `User` 實體，Fortify 的
  `Mass Assignment: Insecure Binder Configuration` 部分版本只看
  「有沒有整包 bind」，不看目標型別。
  處置：標記誤判，佐證需列出 DTO 的完整欄位定義，
  證明其中**不含任何權限或狀態欄位**。若 DTO 含 `status` 之類欄位，
  即使不是 `role`，仍可能構成越權，不能結案。

- **管理端點被報，但檢查寫在框架的 Guard／Filter 註解上**——
  例如 Spring 的方法註解、NestJS 的 `@UseGuards`。
  部分工具版本不解析註解。
  處置：標記誤判，佐證寫明註解位置與 Guard 實作中的角色比對行號，
  並確認該註解**未被類別層的較寬鬆設定覆寫**。

- **`X-User-Role` 之類的 header 由內部閘道注入**——微服務架構中
  API Gateway 驗證後注入身分 header 給下游。
  處置：這**不是誤判**，除非能同時舉證：下游服務不可由外部直接連線
  （網路策略），且閘道會**剝除**外部傳入的同名 header。
  兩項缺一，攻擊者只要自己帶這個 header 就取得管理權限。

### 判定準則

真漏洞：後端端點缺少角色／權限判斷，僅靠前端不顯示入口。
判斷方式：把該請求以一般使用者身分重放，若能成功即為真漏洞。

真漏洞：授權決策讀取請求可控的權限欄位（header、cookie 明文、
body 中的 role／is_admin、未驗簽的 token payload）。

真漏洞：請求整包綁定至持久化實體，且該實體含權限、狀態、金額等敏感欄位，
又未以白名單或未知欄位拒絕加以限制。

誤判：綁定目標為不含敏感欄位的 DTO，且 DTO 欄位清單可完整舉證。

誤判：角色檢查以框架註解實作，且註解確實生效、未被上層較寬鬆的設定覆寫。

---

## SAST-AUTHZ-004 · 未以最小權限執行程序

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Often Misused: Privilege Management | High | unverified | — |
| Fortify | Insecure Deployment: Overly Permissive Configuration | Medium | unverified | — |
| Checkmarx | —（需自訂查詢） | — | unverified | — |
| Semgrep | `dockerfile.security.missing-user.missing-user` | ERROR | unverified | — |
| SonarQube | S4834（Controlling permissions is security-sensitive，Security Hotspot） | — | unverified | — |
| gosec | G301（目錄權限過寬）/ G302（Chmod 權限過寬）/ G306（WriteFile 權限過寬） | MEDIUM | unverified | — |
| bandit | B103（set_bad_file_permissions） | HIGH | verified | testdata/scan-artifacts/open-source/20260905T084457Z/bandit.json#rule=B103（見 `references/scanner-verification-log.md`） |
| CodeQL | —（依語言而異，無跨語言通用查詢） | — | unverified | — |
| Nessus | 主機層權限與服務帳號相關檢查（依 plugin 而異） | Medium–High | unverified | — |

### 壞味道

檔案與目錄權限開到全域可寫：

```go
os.WriteFile("/var/app/config.yaml", data, 0777) // gosec G306
os.MkdirAll("/var/app/data", 0777)               // gosec G301
os.Chmod(path, 0666)                             // gosec G302
```

```python
os.chmod("/var/app/config.yaml", 0o777)   # bandit B103
os.makedirs("/var/app/data", mode=0o777)
```

```javascript
fs.chmodSync("/var/app/config.yaml", 0o777);
fs.writeFileSync("/var/app/data.json", data, { mode: 0o666 });
```

以 root 執行、或程序取得的權限遠超需求：

```javascript
// 容器未指定執行使用者 → 預設 root
// Dockerfile:
//   FROM node:20
//   COPY . /app
//   CMD ["node", "server.js"]      ← 缺 USER

// 監聽 443 而以 root 常駐
app.listen(443);
```

```python
# 資料庫連線使用具備 DDL 權限的超級使用者
DB_URL = "postgresql://postgres:pw@db/app"   # 應用程式不需要 superuser
```

```go
// 取得高權限後未降權
if os.Geteuid() == 0 {
	// 綁定低位埠後就一直以 root 跑下去
	ln, _ := net.Listen("tcp", ":443")
	http.Serve(ln, mux)
}
```

### 過關寫法

原則是**權限只在需要的那一刻存在、只涵蓋需要的範圍**。
掃描器認得的是具體的數值與宣告，不是「我們有做好權限管理」這種說法——
所以把權限收斂寫成字面常數，是最直接會讓規則消失的做法。

```go
// 檔案 0600、目錄 0700：owner 以外無任何權限
if err := os.MkdirAll("/var/app/data", 0o700); err != nil {
	return err
}
if err := os.WriteFile("/var/app/config.yaml", data, 0o600); err != nil {
	return err
}

// 低位埠交給前端反向代理或 systemd socket activation，
// 應用程式本身監聽高位埠，全程不需要 root
ln, err := net.Listen("tcp", "127.0.0.1:8443")
if err != nil {
	return err
}
return http.Serve(ln, mux)
```

```python
import os

os.makedirs("/var/app/data", mode=0o700, exist_ok=True)

fd = os.open("/var/app/config.yaml", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(data)

# 應用程式使用只有 DML 權限的帳號；migration 另用一組帳號、另一個執行入口
DB_URL = os.environ["APP_DB_URL"]   # 該帳號無 DDL、無 SUPERUSER
```

```javascript
fs.mkdirSync("/var/app/data", { recursive: true, mode: 0o700 });
fs.writeFileSync("/var/app/config.yaml", data, { mode: 0o600 });

// 容器明確指定非 root 使用者
// Dockerfile:
//   FROM node:20
//   RUN useradd --system --uid 10001 appuser
//   COPY --chown=appuser:appuser . /app
//   USER 10001
//   CMD ["node", "server.js"]

app.listen(8443, "127.0.0.1");
```

`umask` 不能取代明確的 mode 參數：`umask` 是行程層設定，
靜態分析看不到，工具照樣依 `0777` 字面值報。**要改的是字面值本身**。

雲端執行角色同理——附加的策略要逐項列出所需動作與資源範圍，
不要用萬用字元。萬用字元策略在設定檔掃描器（IaC 規則）中一律標記。

### 常見誤判與處置

- **0777 是給暫存目錄用的**——常見於需要多個容器共用的暫存路徑。
  處置：這通常**不是誤判**。正確作法是改用共同群組
  （目錄 `0770` + 明確 group owner），或改用具名 volume 與相同 uid。
  真的無法改時，需確認該目錄下不含任何可執行檔與設定檔，
  並在誤判說明中記錄清理機制與掛載選項（`noexec`）。

- **`0644` 被 gosec G306 標記**——G306 的預設門檻是 `0600`，
  一般設定檔用 `0644` 也會報。
  處置：若該檔案不含機密（如靜態資源、公開憑證），標記誤判並註明內容性質。
  **若含連線字串、金鑰、token，就不是誤判**，一律收到 `0600`。

- **基底映像檔已內建非 root 使用者，Dockerfile 未再寫 `USER`**——
  Semgrep 的 `missing-user` 只看當前 Dockerfile 有沒有 `USER` 指令。
  處置：**直接補上 `USER` 明寫**，比寫誤判說明省事，
  也避免日後換基底映像檔時默默變回 root。

- **程序啟動時需要 root（綁定低位埠、讀取憑證）**——
  處置：若啟動後有確實降權（`setuid` 至非特權帳號、
  或由 systemd 的 `User=` 與 `AmbientCapabilities` 承擔），標記誤判並
  註明降權位置。**若只是啟動需要 root、之後一直以 root 常駐，就是真問題。**

### 判定準則

真問題：檔案或目錄權限授予 owner 以外的寫入權（mode 含 group／other 的 `w`），
且該路徑存放設定檔、憑證、金鑰、可執行檔或應用程式資料。

真問題：服務常駐於 root（含容器未指定 `USER`），且無任何降權動作。
容器的隔離不算降權——逃逸後即為主機 root。

真問題：應用程式使用的資料庫帳號具備 DDL、SUPERUSER 或跨庫權限，
而其執行期功能僅需 DML。

真問題：雲端執行角色或存取策略使用萬用字元涵蓋動作或資源。

誤判：權限位元寬鬆但該路徑僅存放公開靜態資源，且掛載為 `noexec`。

誤判：啟動階段需要高權限，但在開始服務請求**之前**已完成降權，
且降權位置可指出具體行號或設定項。
