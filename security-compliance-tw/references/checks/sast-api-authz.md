# SAST：API 授權

本檔的問題有個共同特徵：**程式碼在語法上完全正確，掃描器多半不會標紅字**。
判斷「這筆資料該不該給這個人」需要理解業務語意，靜態分析引擎沒有這個資訊。
因此本檔的「掃描器怎麼標」有大量的「—」，那不是漏寫，是實況。

反過來說，這些問題在滲透測試與紅隊演練中命中率極高，
而且 Go / Python 後端的常見寫法（handler 直接吃 path param 查 DB、
回應直接序列化整個 model）幾乎必然中招。
SAST 工具靜悄悄不代表安全，**這幾則要靠人工審查與程式碼審查清單來擋**。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## SAST-API-001 · 物件層級授權失效

呼叫者提供的識別碼（path param、query string、request body 中的 ID）
被直接拿去查資料庫，程式沒有驗證那筆資料屬於呼叫者。
換一個 ID 就能讀到別人的訂單、病歷、發票。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Access Control: Database（需在 Rules Builder 標註授權函式，否則不觸發） | High | unverified | — |
| Checkmarx | Missing_Authorization / Improper_Access_Control（需自訂 query 指定 authz sink） | Medium | unverified | — |
| Semgrep | —（多數工具偵測不到，需人工審查；可自寫規則比對「查詢條件是否含擁有者欄位」） | — | unverified | — |
| SonarQube | —（多數工具偵測不到，需人工審查） | — | unverified | — |
| CodeQL | —（無通用查詢，需自寫 dataflow query 定義 authz barrier） | — | unverified | — |
| gosec | —（多數工具偵測不到，需人工審查） | — | unverified | — |
| bandit | —（多數工具偵測不到，需人工審查） | — | unverified | — |
| AWVS / WebInspect | —（被動掃描無法判斷資料歸屬，需以兩組帳號做橫向比對測試） | — | unverified | — |
| ZAP | Access Control Testing 附加元件（須人工建立角色矩陣後才會判定） | — | unverified | — |

### 壞味道

可做樣式比對的特徵：**handler 直接用 path param 或 query param 查 DB，
查詢條件只有主鍵，沒有比對擁有者**。

```go
// 樣式：mux.Vars / c.Param 取得 ID → 直接進 WHERE id = ?
func GetOrder(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var o Order
	db.QueryRow("SELECT id, user_id, total FROM orders WHERE id = ?", id).
		Scan(&o.ID, &o.UserID, &o.Total)
	json.NewEncoder(w).Encode(o) // 沒有比對 o.UserID 與登入者
}

// 同樣是壞味道：查回來才比，但比錯對象（比的是請求帶來的值）
if o.UserID != r.URL.Query().Get("user_id") {
	http.Error(w, "forbidden", 403)
}
```

```python
# 樣式：request 參數 → 直接 filter by pk / get_object_or_404
@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    order = Order.query.get(order_id)      # 沒有 owner 條件
    return jsonify(order.to_dict())

# Django 同一個樣式
def detail(request, pk):
    order = get_object_or_404(Order, pk=pk)  # 沒有 user=request.user
    return JsonResponse(model_to_dict(order))
```

```javascript
// 樣式：req.params.id → findById / findByPk
app.get("/api/orders/:id", async (req, res) => {
  const order = await Order.findByPk(req.params.id); // 沒有 ownerId 條件
  res.json(order);
});

// 也是壞味道：擁有者取自 request body，可被竄改
const order = await Order.findOne({ _id: req.params.id, userId: req.body.userId });
```

另一個高頻樣式：**批次端點**。單筆有比對擁有者，
但 `POST /api/orders/batch` 收一整包 ID 陣列時忘了逐筆比對。

### 過關寫法

原則只有一條：**擁有者條件要放進 WHERE，不要查回來再比**。
查回來再比容易漏（早退出的分支、批次迴圈、快取路徑），
而且會先把資料讀進記憶體，一旦有其他錯誤處理路徑就可能外洩。

擁有者身分**只能來自伺服器端的 session 或已驗簽的權杖**，
絕不能來自 query string、request body 或未驗簽的標頭。

```go
func GetOrder(w http.ResponseWriter, r *http.Request) {
	// 身分來自伺服器端 context，不是請求參數
	uid, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id := mux.Vars(r)["id"]
	var o Order
	// 擁有者條件寫進 WHERE
	err := db.QueryRow(
		"SELECT id, total, status FROM orders WHERE id = ? AND user_id = ?",
		id, uid,
	).Scan(&o.ID, &o.Total, &o.Status)

	// 查無資料一律回 404，不要回 403——403 會洩漏「這個 ID 存在」
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeOrderResponse(w, o)
}

// 批次端點：把擁有者條件放進同一句 SQL，不要在迴圈裡逐筆判斷
rows, err := db.Query(
	"SELECT id, total FROM orders WHERE user_id = ? AND id IN (?)",
	uid, ids,
)
```

```python
from flask import abort, g

@app.route("/api/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.filter_by(
        id=order_id,
        user_id=g.current_user.id,   # 擁有者條件進 WHERE
    ).first()
    if order is None:
        abort(404)                   # 一律 404，不區分「不存在」與「不是你的」
    return jsonify(order_response(order))


# Django：用 queryset 收斂範圍，讓所有後續查詢都繼承限制
def detail(request, pk):
    order = get_object_or_404(
        Order.objects.filter(user=request.user),  # 先收斂再取單筆
        pk=pk,
    )
    return JsonResponse(order_response(order))
```

```javascript
app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await Order.findOne({
    where: { id: req.params.id, userId: req.user.id }, // 身分來自 req.user
  });
  if (!order) return res.status(404).json({ error: "not found" });
  res.json(orderResponse(order));
});

// 批次：一次查詢帶上擁有者條件，再確認筆數相符
const orders = await Order.findAll({
  where: { id: req.body.ids, userId: req.user.id },
});
if (orders.length !== req.body.ids.length) {
  return res.status(404).json({ error: "not found" });
}
```

更省事的架構做法：在資料存取層包一個**必須帶 tenant / owner 的 repository**，
讓「不帶擁有者的查詢」在型別上就寫不出來。
這樣人工審查只要檢查有沒有繞過 repository，不必逐個 handler 看。

### 常見誤判與處置

- **授權已在 middleware 或路由層完成**——例如 `/api/me/orders/{id}` 這種
  路由前綴已由 middleware 綁定當前使用者，或 middleware 已載入資源並比對擁有者
  後放進 context。此時 handler 內看不到比對動作是正常的。
  處置：標記誤判，佐證寫明 middleware 的檔案與行號、掛載位置，
  **並確認該路由確實被掛在那組 middleware 底下**（最常見的真漏洞就是漏掛）。

- **刻意設計的跨帳號查詢**——後台客服、稽核報表端點本來就要查他人資料。
  處置：不是誤判也不是「不用管」。必須有明確的角色檢查
  （見 SAST-API-003）與存取紀錄，兩者齊備才標記為已處理，
  佐證寫明角色檢查位置與紀錄欄位。

- **識別碼是隨機 UUID，猜不到**——這**不是**誤判理由。
  UUID 會出現在網址列、Referer、日誌、分享連結、前端狀態中，
  取得後照樣可重放。
  處置：當真漏洞修，補上擁有者條件。

- **公開資料端點**——如公開文章、商品目錄，本來就人人可讀。
  處置：標記誤判，佐證寫明該資料表無擁有者概念、
  且回應欄位不含任何個資或內部欄位。

### 判定準則

真漏洞：查詢條件僅含由呼叫者提供的識別碼，
且在回應之前沒有任何地方比對該筆資料的擁有者與已驗證的呼叫者身分。

真漏洞：有比對擁有者，但比對的基準值取自請求本身
（query param、request body、未驗簽的標頭）而非伺服器端 session 或已驗簽權杖。

真漏洞：單筆端點有比對，批次 / 匯出 / 搜尋 / 關聯展開端點沒有。
這幾個是最常漏的位置，必須逐一檢查。

誤判：擁有者條件已寫進查詢，或由 middleware 在進入 handler 前完成比對
且該路由確實掛在該 middleware 之下。

灰色地帶——**一律當真漏洞修**：授權比對發生在「取得資料之後、回應之前」，
但函式中存在提早回傳的分支（錯誤處理、快取命中、日誌輸出）
可能繞過該比對。

---

## SAST-API-002 · 物件屬性層級授權失效

同一筆資料，呼叫者有權存取，但**不該看到所有欄位、也不該寫入所有欄位**。
兩個方向都算：

- **讀取方向（過度暴露）**：回應直接序列化整個 model，
  把密碼雜湊、內部備註、風險分數、其他人的識別碼一起吐出去。
- **寫入方向（大量賦值）**：request body 直接綁定到 model，
  攻擊者多送一個 `"is_admin": true` 或 `"balance": 999999` 就寫進去了。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Mass Assignment: Insecure Binder Configuration（主要涵蓋 Java / .NET binder，Go 不觸發） | High | unverified | — |
| Checkmarx | Mass_Assignment（框架相依，Go / FastAPI 覆蓋不完整） | Medium | unverified | — |
| Semgrep | Rails / Django 有大量賦值規則；Go 與 Node 手寫 binder **無對應規則** | WARNING | unverified | — |
| SonarQube | S4684（持久化實體不應直接作為請求繫結目標，僅 Java） | Major | unverified | — |
| CodeQL | —（無通用查詢，需自寫規則比對「序列化目標是否為 ORM 實體」） | — | unverified | — |
| gosec | —（多數工具偵測不到，需人工審查） | — | unverified | — |
| bandit | —（多數工具偵測不到，需人工審查） | — | unverified | — |
| AWVS / ZAP / WebInspect | —（過度暴露需人工比對回應欄位；大量賦值需主動猜測欄位名） | — | unverified | — |

過度暴露這一半，**幾乎所有 SAST 工具都偵測不到**——
`json.NewEncoder(w).Encode(user)` 在語法上與任何正常序列化沒有差別。

### 壞味道

```go
// 讀取方向：整個 ORM 實體直接序列化
type User struct {
	ID           int64  `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"` // 有 tag 就會被吐出去
	IsAdmin      bool   `json:"is_admin"`
	InternalNote string `json:"internal_note"`
	RiskScore    int    `json:"risk_score"`
}
json.NewEncoder(w).Encode(user) // 全部欄位都出去了

// 寫入方向：request body 直接綁到同一個實體
var u User
json.NewDecoder(r.Body).Decode(&u) // 攻擊者可送 is_admin: true
db.Save(&u)

// gin / echo 也是同一個樣式
c.ShouldBindJSON(&user)
c.BindJSON(&user)
```

```python
# 讀取方向
return jsonify(user.__dict__)            # 含 _sa_instance_state 與所有欄位
return JsonResponse(model_to_dict(user)) # Django：整個 model
return UserSchema().dump(user)           # schema 未列 fields 時等同全欄位

# 寫入方向
user = User(**request.json)              # 任意欄位都能塞
for k, v in request.json.items():
    setattr(user, k, v)                  # 更明顯的樣式
form = UserForm(request.POST, instance=user)  # ModelForm 未限定 fields
```

```javascript
// 讀取方向
res.json(user);                          // Mongoose document 全欄位
res.json(await User.findByPk(id));       // Sequelize 實體全欄位

// 寫入方向
Object.assign(user, req.body);
await User.update(req.body, { where: { id } });
const user = new User(req.body);
```

Go 特有的陷阱：`json:"-"` 只擋 JSON，**不擋** `fmt.Sprintf("%+v")`、
日誌輸出、以及其他序列化器（YAML / MessagePack / template）。
只靠 tag 不算完整防護。

### 過關寫法

兩個方向都用同一個原則：**明確列舉，不要靠排除**。
排除清單（黑名單）在新增欄位時必然會漏——
明天有人在 model 加一個 `two_factor_secret`，黑名單不會自己更新。

```go
// 讀取方向：獨立的回應 DTO，明確列舉要給出去的欄位
type UserResponse struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func toUserResponse(u User) UserResponse {
	return UserResponse{ID: u.ID, Email: u.Email, CreatedAt: u.CreatedAt}
}
json.NewEncoder(w).Encode(toUserResponse(user))

// 寫入方向：獨立的請求 DTO（白名單），再逐欄搬到實體
type UpdateUserRequest struct {
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
}

dec := json.NewDecoder(r.Body)
dec.DisallowUnknownFields() // 送了未知欄位直接報錯，而不是默默忽略
var req UpdateUserRequest
if err := dec.Decode(&req); err != nil {
	http.Error(w, "bad request", http.StatusBadRequest)
	return
}
user.Email = req.Email       // 只搬白名單內的欄位
user.Nickname = req.Nickname
db.Model(&user).Select("email", "nickname").Updates(user) // 更新也限定欄位
```

```python
from pydantic import BaseModel, ConfigDict

# 寫入方向：白名單 + 拒絕未知欄位
class UpdateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # 多送欄位直接 422
    email: str
    nickname: str

# 讀取方向：明確列舉回應欄位
class UserResponse(BaseModel):
    id: int
    email: str
    created_at: datetime

req = UpdateUserRequest.model_validate(request.json)
user.email = req.email
user.nickname = req.nickname
db.session.commit()
return UserResponse.model_validate(user, from_attributes=True).model_dump()


# Django：ModelForm / Serializer 一律用 fields 正面表列，不要用 exclude
class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["email", "nickname"]   # 不要寫 exclude = ["is_admin"]
```

```javascript
// 讀取方向：明確挑出欄位
const userResponse = (u) => ({
  id: u.id,
  email: u.email,
  createdAt: u.createdAt,
});
res.json(userResponse(user));

// 寫入方向：白名單解構 + 限定可更新欄位
const { email, nickname } = req.body;      // 其餘欄位直接丟棄
await User.update(
  { email, nickname },
  { where: { id: req.user.id }, fields: ["email", "nickname"] }
);

// Mongoose：schema 層再擋一次
const schema = new mongoose.Schema(
  { email: String, nickname: String, isAdmin: { type: Boolean, select: false } },
  { strict: "throw" }   // 未定義欄位寫入時丟錯
);
```

敏感欄位建議**在資料層就不要載入**（Go 的 `Select` 指定欄位、
Mongoose 的 `select: false`、SQLAlchemy 的 `deferred`）。
沒讀進記憶體的東西不會被任何序列化路徑意外吐出來。

### 常見誤判與處置

- **內部服務之間的完整序列化**——服務對服務的介面刻意傳整個實體。
  處置：確認該端點確實不對外（網路層隔離 + 服務間驗證），
  標記誤判並在佐證寫明呼叫方清單與網路限制。
  若只靠「內網不會有人打」，那是真漏洞。

- **敏感欄位已標 `json:"-"` 或 `select: false`**——工具仍可能因為
  「整個實體被序列化」的樣式而標記。
  處置：標記誤判，佐證列出所有敏感欄位及其排除設定；
  同時檢查是否有其他序列化路徑（日誌、錯誤訊息、範本渲染）繞過該設定。

- **框架的繫結白名單工具沒被辨識**——如 Rails 的 strong parameters、
  DRF Serializer 的 `fields`。工具版本舊時常誤報。
  處置：標記誤判，佐證寫明白名單定義位置。
  **前提是用正面表列**；若用 `exclude` 反面排除，維持真漏洞判定。

- **回應 DTO 由程式碼產生器自動生成**——欄位其實是明確列舉的，
  只是不在人寫的檔案裡。
  處置：標記誤判，佐證指向產生器的 schema 來源檔。

### 判定準則

真漏洞：回應序列化的對象是 ORM 實體或資料庫 row struct 本身，
且該型別含有任何不應對外的欄位（憑證、雜湊、權限旗標、
內部評分、他人識別碼、軟刪除標記）。

真漏洞：請求 body 反序列化的目標是 ORM 實體本身，
或存在 `setattr` / `Object.assign` / `Updates(struct)` 這類全欄位寫入，
且未限定可寫欄位清單。

真漏洞：使用反面排除（`exclude` / 黑名單）來控制欄位。
即使目前清單是完整的，仍判定為真漏洞——新增欄位時必然失效。

誤判：讀寫兩端都使用獨立的 DTO 型別，欄位為正面表列，
且未知欄位會被拒絕或丟棄。

灰色地帶——**一律當真漏洞修**：DTO 與實體是同一個型別，
僅靠序列化 tag 區分方向（例如同一個 struct 同時當請求與回應）。

---

## SAST-API-003 · 功能層級授權失效

端點本身就不該給一般使用者呼叫——刪除使用者、調整權限、匯出全站資料、
切換功能旗標——但伺服器端沒有檢查角色，只靠前端不顯示按鈕。
攻擊者不用瀏覽器，直接打 API。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Access Control: Missing Access Control（需自訂規則標註 authz 函式後才有意義） | High | unverified | — |
| Checkmarx | Missing_Authorization / Improper_Access_Control（需自訂 query） | Medium | unverified | — |
| Semgrep | —（多數工具偵測不到，需人工審查；可自寫規則比對「路由註冊是否套用 authz middleware」） | — | unverified | — |
| SonarQube | S4834（權限控管屬 Security Hotspot，需人工複核；不會自動判定缺漏） | Review | unverified | — |
| CodeQL | —（無通用查詢；需自寫規則列舉路由並檢查 authz barrier） | — | unverified | — |
| gosec | —（多數工具偵測不到，需人工審查） | — | unverified | — |
| bandit | —（多數工具偵測不到，需人工審查） | — | unverified | — |
| AWVS / WebInspect | —（需以低權限帳號重放高權限請求，屬人工測試範疇） | — | unverified | — |
| ZAP | Access Control Testing 附加元件（須人工設定角色矩陣） | — | unverified | — |

### 壞味道

可做樣式比對的特徵：**路由註冊在沒有授權 middleware 的群組裡，
且 handler 內沒有任何角色比對**。

```go
// 樣式一：管理端點註冊在公開群組
r := mux.NewRouter()
api := r.PathPrefix("/api").Subrouter()
api.Use(authMiddleware)                       // 只驗身分，沒驗角色
api.HandleFunc("/admin/users/{id}", DeleteUser).Methods("DELETE")

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	db.Delete(&User{}, mux.Vars(r)["id"])     // 沒有任何角色檢查
}

// 樣式二：角色取自請求，可竄改
role := r.Header.Get("X-User-Role")
if role == "admin" { /* ... */ }

// 樣式三：只有 GET 有檢查，其他動詞漏掉
```

```python
# 樣式：管理端點沒有任何權限裝飾器
@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@login_required                      # 只驗登入，沒驗角色
def delete_user(uid):
    db.session.delete(User.query.get(uid))
    db.session.commit()
    return "", 204

# 樣式：角色來自 client
if request.json.get("role") == "admin":
    ...

# Django：只在 template 隱藏按鈕，view 本身沒擋
```

```javascript
// 樣式：router 未套用角色檢查
router.delete("/admin/users/:id", requireAuth, async (req, res) => {
  await User.destroy({ where: { id: req.params.id } }); // 沒驗角色
  res.sendStatus(204);
});

// 樣式：授權只做在前端
if (currentUser.isAdmin) {
  showDeleteButton();   // 後端沒擋，按鈕藏起來也沒用
}
```

還有一個常被忽略的樣式：**框架自動註冊的端點**——
除錯路由、健康檢查、metrics、GraphQL introspection、
Swagger UI、管理後台的自動 CRUD，這些沒有人「寫」路由，
所以人工審查清單常常整組漏掉。

### 過關寫法

原則：**預設拒絕**。授權掛在路由群組上，新增端點時預設就受保護，
而不是「記得要加裝飾器」。角色一律取自伺服器端 session 或已驗簽權杖。

```go
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 角色來自已驗簽的 token 解析結果，不是請求標頭
			u, ok := auth.UserFromContext(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !slices.Contains(roles, u.Role) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// 管理端點獨立 subrouter，整組套用——新增路由自動受保護
admin := r.PathPrefix("/api/admin").Subrouter()
admin.Use(authMiddleware, RequireRole("admin"))
admin.HandleFunc("/users/{id}", DeleteUser).Methods("DELETE")
```

```python
from functools import wraps
from flask import abort, g

def require_role(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if g.current_user is None:
                abort(401)
            if g.current_user.role not in roles:   # 角色來自伺服器端
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco

# 用 Blueprint 整組套用，而不是逐個 route 加裝飾器
admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

@admin_bp.before_request
def guard():
    if g.current_user is None:
        abort(401)
    if g.current_user.role != "admin":
        abort(403)

@admin_bp.route("/users/<int:uid>", methods=["DELETE"])
def delete_user(uid):
    ...
```

```javascript
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "unauthorized" });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "forbidden" });
    }
    next();
  };
}

// 整個 admin router 掛一次，底下所有路由自動受保護
const adminRouter = express.Router();
adminRouter.use(requireAuth, requireRole("admin"));
adminRouter.delete("/users/:id", async (req, res) => { /* ... */ });
app.use("/api/admin", adminRouter);
```

驗收方式：把所有路由列出來（Go 用 `router.Walk`、
Flask 用 `app.url_map`、Express 走 `app._router.stack`），
逐一標註所需角色，產出一張路由授權矩陣。
沒有角色標註的路由必須明確標為「公開」，不能留空。
這張表比任何掃描器報告都有用，也是稽核時最好的佐證。

### 常見誤判與處置

- **授權在上游閘道完成**——API Gateway、Kong、Istio 或反向代理
  已依路徑做角色判斷，應用程式內看不到檢查。
  處置：標記誤判，佐證附上閘道規則設定與路徑對應表。
  **同時確認應用程式無法被繞過閘道直接連線**（內網直連、port-forward）；
  若可繞過，維持真漏洞判定。

- **端點對所有已登入使用者開放是刻意設計**——例如個人資料修改。
  處置：標記誤判，佐證寫明該端點的資料範圍已由物件層級授權收斂
  （見 SAST-API-001），不需額外角色。

- **角色檢查寫在 handler 呼叫的服務層**——工具只看 handler 因而誤報。
  處置：標記誤判，佐證寫明服務層檢查的函式與行號。
  但要確認**所有**呼叫路徑都會經過該服務層方法，
  不能有 handler 直接操作 repository 的旁路。

- **測試或開發專用端點**——工具標記 `/debug/*`、`/internal/*`。
  處置：這通常**不是**誤判。確認正式環境是否真的沒有註冊該路由
  （建構標籤、環境變數判斷），能證明才標記誤判；
  若只是「應該不會有人知道」，當真漏洞處理。

### 判定準則

真漏洞：端點會執行僅限特定角色的動作（刪除他人資料、變更權限、
全站匯出、設定變更），而從路由註冊到 handler 完成之間
沒有任何角色或權限比對。

真漏洞：角色來源為請求可控的值——標頭、query param、request body、
未驗簽的 cookie、或前端傳來的 JWT 但未驗證簽章。

真漏洞：授權僅實作於前端（隱藏按鈕、路由守衛），後端無對應檢查。

真漏洞：同一資源的部分動詞有檢查、部分沒有
（`GET` 有擋但 `PUT` / `DELETE` 沒擋）。

誤判：路由掛在具備角色檢查的群組或 middleware 之下，
且無法繞過該群組直接抵達 handler。

灰色地帶——**一律當真漏洞修**：授權檢查存在，但採「列舉禁止清單」
（只擋特定角色）而非「列舉允許清單」。新增角色時必然失效。

---

## SAST-API-004 · 資源消耗無限制

呼叫者可以指定「要多少」——每頁筆數、查詢範圍、上傳大小、
巢狀查詢深度、批次筆數——而伺服器照單全收。
一個 `?limit=99999999` 就能把資料庫與記憶體拖垮，
或是把整張使用者表分頁抓完（同時也是資料外洩）。
沒有速率限制時，登入端點還會變成免費的暴力破解平台。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Denial of Service（僅涵蓋部分模式，動態 limit 多半不觸發） | Medium | unverified | — |
| Checkmarx | —（多數工具偵測不到，需人工審查） | — | unverified | — |
| Semgrep | 部分框架有上傳大小 / 速率限制規則；動態 `limit` 參數**無通用規則** | WARNING | unverified | — |
| SonarQube | S5693（請求大小上限未設定，僅涵蓋部分框架的上傳設定） | Major | unverified | — |
| CodeQL | —（無通用查詢，需自寫規則追蹤 limit 參數至查詢） | — | unverified | — |
| gosec | G110（解壓縮炸彈：未限制大小的 `io.Copy`） | MEDIUM | unverified | — |
| bandit | —（多數工具偵測不到，需人工審查） | — | unverified | — |
| AWVS / WebInspect | —（主動掃描不會刻意送極端參數，除非自訂測試案例） | — | unverified | — |
| Nessus / ZAP | —（除非出現明顯逾時或錯誤，被動掃描不會報） | — | unverified | — |

### 壞味道

可做樣式比對的特徵：**請求參數直接進入 LIMIT / 陣列長度 / 讀取大小，
中間沒有夾擠（clamp）動作**。

```go
// 樣式：query param → Atoi → 直接進 LIMIT，無上限
limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
rows, _ := db.Query("SELECT * FROM users LIMIT ?", limit)

// 樣式：整包 body 讀進記憶體，無大小限制
body, _ := io.ReadAll(r.Body)

// 樣式：無限制的解壓縮
io.Copy(dst, gzipReader)   // gosec G110

// 樣式：登入端點沒有任何速率限制
mux.HandleFunc("/api/login", Login)
```

```python
# 樣式：直接吃 limit
limit = int(request.args.get("limit", 100))
users = User.query.limit(limit).all()

# 樣式：沒有分頁，一次全撈
users = User.query.all()

# 樣式：批次端點吃任意長度陣列
for item in request.json["items"]:   # 一百萬筆也照跑
    process(item)

# 樣式：登入端點無速率限制
@app.route("/api/login", methods=["POST"])
def login(): ...
```

```javascript
// 樣式：limit 直接進查詢
const limit = parseInt(req.query.limit) || 100;   // 傳 999999 照吃
const users = await User.findAll({ limit });

// 樣式：body 大小無上限
app.use(express.json());       // 預設 100kb，但被明確放寬時要注意
app.use(express.json({ limit: "500mb" }));

// 樣式：GraphQL 未限制查詢深度與複雜度
const server = new ApolloServer({ typeDefs, resolvers });
```

### 過關寫法

原則：**每個「數量」都要有預設值與硬上限，而且上限由伺服器決定**。
夾擠要寫成一個共用函式，不要每個 handler 各寫一次——散開寫必然有人漏。

```go
const (
	defaultPageSize = 50
	maxPageSize     = 200
	maxBodyBytes    = 1 << 20 // 1 MiB
)

func pageSize(raw string) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return defaultPageSize
	}
	if n > maxPageSize {
		return maxPageSize // 夾擠，不是回錯誤——避免掃描器與客戶端反覆重試
	}
	return n
}

func ListUsers(w http.ResponseWriter, r *http.Request) {
	// 請求大小上限：超過會在讀取時回錯，不會吃光記憶體
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	limit := pageSize(r.URL.Query().Get("limit"))
	rows, err := db.Query("SELECT id, email FROM users LIMIT ?", limit)
	// ...
}

// 解壓縮限制大小（對應 gosec G110）
if _, err := io.Copy(dst, io.LimitReader(gzipReader, maxBodyBytes)); err != nil {
	return err
}

// 伺服器層級逾時，避免慢速連線佔用
srv := &http.Server{
	ReadHeaderTimeout: 5 * time.Second,
	ReadTimeout:       15 * time.Second,
	WriteTimeout:      30 * time.Second,
}
```

```python
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

def page_size(raw):
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_PAGE_SIZE
    return max(1, min(n, MAX_PAGE_SIZE))   # 夾擠在合理區間

@app.route("/api/users")
def list_users():
    limit = page_size(request.args.get("limit"))
    users = User.query.limit(limit).all()
    return jsonify([user_response(u) for u in users])

# 請求大小上限（Flask）
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

# 批次筆數上限
items = request.json.get("items", [])
if len(items) > 100:
    abort(413)

# 速率限制：敏感端點加嚴
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per minute"])

@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    ...
```

```javascript
const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 200;

function pageSize(raw) {
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_PAGE_SIZE;
  return Math.min(n, MAX_PAGE_SIZE);
}

app.use(express.json({ limit: "1mb" }));   // 請求大小上限

const rateLimit = require("express-rate-limit");
app.use("/api/", rateLimit({ windowMs: 60_000, max: 200 }));
app.use("/api/login", rateLimit({ windowMs: 60_000, max: 5 }));

app.get("/api/users", requireAuth, async (req, res) => {
  const users = await User.findAll({ limit: pageSize(req.query.limit) });
  res.json(users.map(userResponse));
});
```

深層分頁（`offset=1000000`）與大範圍時間查詢也算數量問題：
改用游標分頁（以最後一筆的 ID 或時間戳往下取），
並限制查詢時間範圍的最大跨度。

### 常見誤判與處置

- **上限設在資料存取層或 ORM 預設**——handler 看不到夾擠動作，
  但 repository 統一套用了 `LIMIT`。
  處置：標記誤判，佐證寫明共用函式位置，
  並確認沒有 handler 繞過該層直接下 SQL。

- **速率限制在閘道 / WAF / 負載平衡器**——應用程式碼內沒有限流器。
  處置：標記誤判，佐證附上閘道限流設定與套用範圍。
  **要確認涵蓋所有對外路徑**，尤其是新加的網域或 WebSocket 端點。

- **內部批次作業端點刻意無上限**——資料遷移、報表產生。
  處置：確認該端點不對外、需高權限角色（見 SAST-API-003）
  且有非同步佇列承接，三者齊備才標記誤判。
  同步執行且對外可達的，維持真漏洞判定。

- **gosec G110 標記已知大小的解壓縮**——來源檔案由系統產生、大小可控。
  處置：標記誤判，佐證寫明來源與大小限制；
  但若來源可由使用者上傳，維持真漏洞判定。

### 判定準則

真漏洞：查詢筆數、批次筆數、上傳大小、巢狀深度中，
任何一項可由呼叫者指定且無伺服器端硬上限。

真漏洞：列表端點完全沒有分頁，一次回傳整張資料表。

真漏洞：認證相關端點（登入、忘記密碼、簡訊驗證碼、權杖換發）
沒有速率限制或鎖定機制。

真漏洞：外部輸入的資料被整包讀進記憶體或解壓縮，且無大小上限。

誤判：夾擠邏輯存在於共用函式、資料存取層或閘道設定中，
且所有對外路徑均涵蓋。

灰色地帶——**一律當真漏洞修**：有預設值但無上限
（`limit` 未給時用 50，給了 999999 就照吃）——
這是最常見的假性防護，預設值不是上限。
