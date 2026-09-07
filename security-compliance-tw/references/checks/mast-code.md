# MAST：輸入驗證、注入防護與函式庫漏洞

行動端常被誤以為「輸入驗證是伺服器的事」。伺服器端確實是主防線，
但**行動 App 自己也有 sink**：本機 SQLite、WebView 的 `javascript:`、
`Runtime.exec`、深層連結參數。這些不經過伺服器，伺服器擋不到。

檢測基準對這一類的要求也不只看伺服器——它明文要求
「行動應用程式應針對使用者於輸入階段之字串，進行安全檢查」，
檢測範圍是**行動應用程式本身**。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

**「掃描器怎麼標」只收可查證的工具**：MobSF／mobsfscan、Android Lint、
detekt、SwiftLint、Semgrep——規則 id 逐一與官方原始碼或規則清單核對過。

## MAST-CODE-001 · 使用者輸入未進行安全檢查

涵蓋輸入字串未經長度、字元集、格式驗證即進入本機處理或送往伺服器，
以及深層連結與 IPC 傳入的參數未經檢查。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | —（**無通用規則**。「有沒有做驗證」需要語意理解，樣式比對做不到；只有落到具體 sink 時才會被 `MAST-CODE-002` 的規則抓到） | — | unverified | — |
| mobsfscan | —（無通用規則） | — | unverified | — |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（無通用規則） | — | unverified | — |

**這一則沒有自動化涵蓋，只能人工審查。** 檢測實驗室的做法是
對每個輸入介面實際灌入邊界值與注入字串，觀察 App 行為。

本則與 `MAST-CODE-002` 的分界：本則管**入口有沒有守門**，
後者管**出口（sink）有沒有正確編碼**。兩者都要做——
只做入口過濾擋不住二階注入，只做出口編碼擋不住長度與格式問題。

### 壞味道

```kotlin
// 深層連結參數直接使用，未驗證格式與範圍
class OrderActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val orderId = intent.data?.getQueryParameter("id")   // 可能是任意字串
        loadOrder(orderId!!)                                  // 也可能是 null
    }
}

// 表單輸入未做任何檢查就送出
fun submit() {
    api.updateProfile(nameField.text.toString(), bioField.text.toString())
}
```

```swift
// URL Scheme 參數未驗證
func handle(_ url: URL) {
    let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
    let orderId = comps?.queryItems?.first { $0.name == "id" }?.value
    loadOrder(orderId!)     // 型別、長度、字元集皆未檢查
}
```

### 過關寫法

**白名單優於黑名單。** 定義「允許長什麼樣」而不是「不允許哪些字元」——
黑名單過濾在檢測時幾乎不被接受，因為總有沒想到的字元。

```kotlin
// 以正規表示式定義允許的格式，不符即拒絕
private val ORDER_ID = Regex("^[A-Z0-9]{8,16}$")

fun handleDeepLink(uri: Uri) {
    val id = uri.getQueryParameter("id")
    if (id == null || !ORDER_ID.matches(id)) {
        finish()          // 不符格式就不處理，不要試圖「修正」輸入
        return
    }
    loadOrder(id)
}

// 表單：長度與字元集都要限制，並在 UI 層就擋
nameField.filters = arrayOf(InputFilter.LengthFilter(50))

fun submit() {
    val name = nameField.text.toString().trim()
    if (name.isEmpty() || name.length > 50) {
        showError(R.string.invalid_name); return
    }
    api.updateProfile(name, bio)
}
```

```swift
private let orderIdPattern = try! NSRegularExpression(pattern: "^[A-Z0-9]{8,16}$")

func handle(_ url: URL) {
    guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
          let id = comps.queryItems?.first(where: { $0.name == "id" })?.value,
          orderIdPattern.firstMatch(
              in: id, range: NSRange(id.startIndex..., in: id)) != nil
    else { return }        // 不符即忽略
    loadOrder(id)
}

// 表單：即時限制長度
func textField(_ tf: UITextField,
               shouldChangeCharactersIn range: NSRange,
               replacementString string: String) -> Bool {
    let new = (tf.text as NSString?)?.replacingCharacters(in: range, with: string) ?? ""
    return new.count <= 50
}
```

三個準則：

- **用戶端驗證是體驗，伺服器端驗證是安全**——兩邊都要做，
  但不可只做用戶端（可被繞過）
- **不符格式就拒絕，不要「清理後繼續」**——清理邏輯本身常有漏洞
- **深層連結與 IPC 的輸入與使用者輸入同等對待**——它們來自其他 App

### 常見誤判與處置

- **驗證確實有做，但寫在共用的 validator 類別裡。**
  處置：這一則本來就沒有自動化規則，不存在工具誤判。人工審查時
  提供 validator 的位置與各輸入點的呼叫行號即可。

- **輸入僅用於本機顯示，不進入任何 sink。**
  處置：仍需長度限制（避免 UI 破版與記憶體問題），但格式驗證可放寬。
  佐證寫明該輸入的完整流向。

### 判定準則

真漏洞：外部輸入（表單、深層連結、IPC、掃碼結果）未經長度與格式驗證
即進入本機處理或持久化。

真漏洞：僅做黑名單字元過濾。

誤判：輸入僅用於本機顯示且有長度限制，流向經確認不含任何 sink。

## MAST-CODE-002 · 注入攻擊防護缺漏

涵蓋本機 SQLite 的字串拼接查詢、WebView 的 `javascript:` 拼接、
`Runtime.exec` 的字串命令，以及 IPC 傳入值直接進入上述 sink。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| mobsfscan | `android_kotlin_sql_raw_query`（Kotlin 的 `rawQuery`／`execSQL` 拼接）；`sqlite_injection`（Java） | ERROR | verified | `testdata/scan-artifacts/open-source/20260907T001858Z/semgrep-mobsfscan-android.json#rule=android_kotlin_sql_raw_query`（MainActivity.kt:43、:44）（另見 `references/scanner-verification-log.md`） |
| mobsfscan（WebView） | `webview_javascript_interface`／`android_kotlin_webview`（`addJavascriptInterface` 橋接） | ERROR | partial | 規則原始碼：`mobsfscan/rules/semgrep/{java/webview/webview_javascript_interface.yaml,kotlin/webview.yaml}` |
| MobSF | 靜態報告的 "App uses SQLite Database and execute raw SQL query" | High | partial | 同上 |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（官方規則庫的行動端 SQL 規則有限） | — | unverified | — |

規則比對的是 **`rawQuery` 加字串串接**這個樣式。改用參數化之後
規則直接不命中——這與伺服器端的 SQL 注入是同一個道理。

### 壞味道

```kotlin
// 本機 SQLite 字串拼接
fun search(keyword: String): Cursor =
    db.rawQuery("SELECT * FROM notes WHERE title LIKE '%$keyword%'", null)

// execSQL 同樣中招
db.execSQL("DELETE FROM notes WHERE id = $noteId")

// WebView 的 javascript: 拼接
webView.loadUrl("javascript:showUser('$userName')")

// 橋接物件暴露給任意載入的頁面
webView.addJavascriptInterface(BridgeObject(), "bridge")
webView.loadUrl(externalUrl)
```

```swift
// SQLite.swift 或 FMDB 的字串拼接
let sql = "SELECT * FROM notes WHERE title LIKE '%\(keyword)%'"
let rows = try db.prepare(sql)

// WKWebView 的 JS 拼接
webView.evaluateJavaScript("showUser('\(userName)')")
```

### 過關寫法

```kotlin
// 參數化查詢——? 佔位符，值另外傳
fun search(keyword: String): Cursor =
    db.rawQuery("SELECT * FROM notes WHERE title LIKE ?", arrayOf("%$keyword%"))

fun delete(noteId: Long) =
    db.delete("notes", "id = ?", arrayOf(noteId.toString()))

// 更好：用 Room，編譯期就檢查 SQL 且自動參數化
@Dao
interface NoteDao {
    @Query("SELECT * FROM notes WHERE title LIKE :pattern")
    suspend fun search(pattern: String): List<Note>
}

// WebView：不用 addJavascriptInterface，改用有來源驗證的訊息通道
webView.settings.javaScriptEnabled = true
webView.settings.allowFileAccess = false
webView.settings.allowFileAccessFromFileURLs = false
webView.settings.allowUniversalAccessFromFileURLs = false

// 傳值進 JS 時走 JSON 序列化，不要字串拼接
val payload = org.json.JSONObject().put("name", userName).toString()
webView.evaluateJavascript("showUser($payload);", null)
```

```swift
// 參數化綁定
let stmt = try db.prepare("SELECT * FROM notes WHERE title LIKE ?")
let rows = try stmt.run("%\(keyword)%")

// JS 傳值走 JSON 編碼
let data = try JSONEncoder().encode(["name": userName])
let json = String(data: data, encoding: .utf8)!
webView.evaluateJavaScript("showUser(\(json));")

// 訊息處理器要驗證來源
func userContentController(_ controller: WKUserContentController,
                           didReceive message: WKScriptMessage) {
    guard message.frameInfo.isMainFrame,
          message.frameInfo.securityOrigin.host == "app.example.com" else { return }
    handle(message.body)
}
```

### 常見誤判與處置

- **拼接的是程式內常數**——欄位名或排序方向來自寫死的 map。
  處置：標記誤判，佐證寫明該值的來源為程式內常數集合。
  **更省事的做法是改用白名單 map 轉換**，讓拼接的值明顯來自常數。

- **`addJavascriptInterface` 只載入內建的 asset 頁面。**
  處置：仍應標記為需注意——若該頁面載入任何外部資源（圖片、腳本、iframe），
  橋接就可能被觸及。佐證需附該頁面的 CSP 或資源清單。
  Android 4.2 以上需 `@JavascriptInterface` 註解，但那不改變暴露面。

- **測試碼中的拼接查詢。**
  處置：把測試檔排除在掃描範圍外。

### 判定準則

真漏洞：外部輸入經字串拼接進入 `rawQuery`／`execSQL`／`prepare`。

真漏洞：外部輸入經字串拼接進入 `loadUrl("javascript:...")`
或 `evaluateJavaScript`。

真漏洞：`addJavascriptInterface` 的橋接物件可被外部載入的頁面觸及。

誤判：拼接值來自程式內常數集合，有來源佐證。

## MAST-CODE-003 · 引用的函式庫含已知漏洞

涵蓋第三方相依套件停留在有公開 CVE 的版本，以及缺少相依更新的流程。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | 靜態報告會列出偵測到的第三方函式庫與版本，**但不比對 CVE 資料庫** | Info | unverified | — |
| mobsfscan | —（無對應規則；相依分析不在其範圍） | — | unverified | — |
| Android Lint | `GradleDependency`（有較新版本可用，**非** CVE 判定） | Warning | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（官方規則庫的行動端無相依規則） | — | unverified | — |

**一般的行動端掃描器不做相依漏洞比對。** 這一項要另外用相依掃描工具
（OWASP Dependency-Check、`gradle dependencies` 搭配 OSV、
GitHub Dependabot、`pod outdated`），或由檢測實驗室以 SBOM 比對。

### 壞味道

```gradle
// 版本寫死且長期未更新；動態版本更糟——建置結果不可重現
dependencies {
    implementation "com.squareup.okhttp3:okhttp:3.12.0"      // 2018 年版本
    implementation "com.google.code.gson:gson:2.8.0"
    implementation "androidx.appcompat:appcompat:1.+"        // 動態版本
}
```

### 過關寫法

```gradle
// 版本集中管理，明確固定，並納入相依漏洞掃描
dependencies {
    implementation platform("com.squareup.okhttp3:okhttp-bom:4.12.0")
    implementation "com.squareup.okhttp3:okhttp"
    implementation "com.google.code.gson:gson:2.11.0"
    implementation "androidx.appcompat:appcompat:1.7.0"
}

// 相依漏洞掃描納入建置流程
plugins {
    id "org.owasp.dependencycheck" version "10.0.4"
}

dependencyCheck {
    failBuildOnCVSS = 7.0      // High 以上直接讓建置失敗
    suppressionFile = "config/dependency-check-suppressions.xml"
}
```

iOS 側對應的是 `Podfile.lock` 與 `Package.resolved` 納入版控，
並定期以 `pod outdated` 或 SPM 的相依更新檢查比對。
**兩個平台都要把 lock 檔進版控**——否則建置結果不可重現，
送檢的版本與掃描的版本可能不同。

檢測基準這一條的原文是「**應備妥對應之更新版本**」——
它要的不只是「目前沒有漏洞」，而是**有更新的準備與流程**。
因此佐證要包含：相依清單（SBOM）、掃描週期、以及發現漏洞時的處置流程。

### 常見誤判與處置

- **CVE 存在但不影響實際用法**——漏洞在未使用的模組或功能路徑上。
  處置：這是相依掃描最常見的誤判。用 suppression 檔記錄，
  **佐證必須寫明為什麼不受影響**（哪個功能未使用、呼叫路徑不存在），
  不可只寫「不適用」。

- **無法升級，因為上游未修**。
  處置：記錄為已知風險接受，說明補償控制
  （例如在應用層阻擋觸發該漏洞的輸入），並列出追蹤的上游 issue。

- **傳遞相依（transitive）帶進舊版本。**
  處置：這是真問題。用 `resolutionStrategy.force` 或 `constraints`
  強制版本，並確認強制後的相容性。

### 判定準則

真漏洞：正式建置使用的相依存在 CVSS 7.0 以上且影響實際使用路徑的已知漏洞。

真漏洞：使用動態版本（`1.+`、`latest.release`），建置結果不可重現。

真漏洞：`Podfile.lock` / `Package.resolved` / `gradle.lockfile` 未進版控。

誤判：CVE 存在但經確認不影響實際呼叫路徑，且 suppression 檔記載了具體理由。
