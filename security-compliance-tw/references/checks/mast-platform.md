# MAST：平台介面（IPC、WebView、剪貼簿、螢幕擷取）

這一類的共同點是**資料透過作業系統的共享機制離開 App 邊界**：
匯出元件與 Deep Link、WebView 的橋接與檔案存取、剪貼簿、系統快照。
靜態規則比對的是 `exported="true"`、`addJavascriptInterface`、
`UIPasteboard`、`FLAG_SECURE` 這些字面樣式，
不保證能判斷「傳出去的是不是敏感資料」。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

**「掃描器怎麼標」只收可查證的工具**：MobSF／mobsfscan、Android Lint、
detekt、SwiftLint、Semgrep——規則 id 逐一與官方原始碼或規則清單核對過。

## MAST-PLATFORM-001 · 過度匯出元件／危險 Deep Link

涵蓋 Android `exported=true` 的 Activity／Service／Receiver／Provider
未加權限、ContentProvider 可被外部讀寫、以及 iOS／Android Deep Link／
URL Scheme／Intent 攜帶權杖或直接觸發敏感動作卻未驗證來源與參數。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | Exported Components／Deep Link／Content Provider 類 | High–Warning | unverified | — |
| mobsfscan | Android exported／deeplink／iOS URL scheme pattern | WARNING–ERROR | unverified | — |
| Semgrep | Manifest／Intent filter／URL handler 社群規則 | ERROR–WARNING | unverified | — |
| Android Lint | `ExportedService`／`ExportedReceiver`／`ExposedContentProvider` 等 | Error–Warning | unverified | — |
| Xcode | URL scheme／Universal Link 處理多依賴手動與自訂規則 | — | unverified | — |

Manifest 掃描幾乎是「看得到 `exported="true"` 或隱含匯出就報」。
把不需要跨 App 的元件改成不匯出、需要的加自訂 permission，
並在 Deep Link 入口做參數白名單，比爭論「誰會呼叫」快。

### 壞味道

```swift
// Info.plist 註冊 myapp:// 後，AppDelegate／SceneDelegate 直接信任 URL
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    // myapp://login?token=...
    if url.host == "login", let token = URLComponents(url: url, resolvingAgainstBaseURL: false)?
        .queryItems?.first(where: { $0.name == "token" })?.value {
        Session.shared.token = token // 任意 App 都可喚起並注入
        return true
    }
    return false
}
```

```xml
<!-- AndroidManifest.xml：任何 App 都能送 Intent 進來，且 Provider 開放授權 -->
<activity android:name=".TransferActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <data android:scheme="myapp" android:host="transfer" />
    </intent-filter>
</activity>

<provider
    android:name=".FileProvider"
    android:authorities="com.example.files"
    android:exported="true"
    android:grantUriPermissions="true" />
```

```kotlin
class TransferActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val amount = intent.getIntExtra("amount", 0)
        val to = intent.data?.getQueryParameter("to")
        api.transfer(to, amount) // 外部 Intent 直接觸發
    }
}
```

### 過關寫法

原則：**預設不匯出**；跨 App 入口最小化並加權限或 App Links／Universal Links 驗證；
Deep Link **只當導航**，敏感動作要進 App 內再認證，參數當不可信輸入。

```swift
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
          components.scheme == "myapp" else { return false }

    // 不接受 token／password 之類查詢參數
    switch components.host {
    case "orders":
        let id = components.queryItems?.first(where: { $0.name == "id" })?.value
        guard let id, id.allSatisfy(\.isNumber) else { return false }
        Router.openOrder(id: id) // 進畫面後用既有 session；缺 session 就導登入
        return true
    default:
        return false
    }
}

// 優先改 Universal Links（https 網域＋apple-app-site-association），減少自訂 scheme 搶註
```

```xml
<!-- AndroidManifest.xml：無跨 App 需求就關掉；必須開放時用 App Links + 自訂權限 -->
<activity android:name=".InternalActivity" android:exported="false" />

<activity android:name=".OrderDeepLinkActivity" android:exported="true">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="app.example.com" />
    </intent-filter>
</activity>

<provider
    android:name=".FileProvider"
    android:authorities="com.example.files"
    android:exported="false"
    android:grantUriPermissions="true" />
```

`autoVerify="true"` 的 App Links 需要網域端的 `assetlinks.json` 才會生效——
少了它會靜默退化成一般 scheme，任何 App 都能搶註。

```kotlin
class OrderDeepLinkActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent.data ?: return finish()
        if (uri.scheme != "https" || uri.host != "app.example.com") return finish()
        val id = uri.pathSegments.getOrNull(1) ?: return finish()
        if (!id.all { it.isDigit() }) return finish()
        // 只導航；轉帳等動作另頁並要求生物辨識／伺服器授權
        startActivity(OrderActivity.intent(this, id))
        finish()
    }
}

// ContentProvider：exported=false，或 android:permission="com.example.APP_READ"
// 並以 UriMatcher 白名單路徑；勿把內部資料庫路徑直接對外
```

Android 12+ 明確寫 `android:exported`；審查時對每個 `true` 列出來源與權限。
iOS 自訂 scheme 無法防止搶註——敏感流程改 Universal Links 或 App 內路由。

### 常見誤判與處置

- **匯出僅為了同開發者 App 共用，已設 signature 級 permission**——
  工具可能仍報 exported。
  處置：標記誤判並附 permission 名稱與 `protectionLevel`；確認無其它未加權限的 filter。

- **推播／分享套件要求匯出 receiver**——常見於 Firebase 等。
  處置：維持官方建議的 exported＋權限；誤判說明附 SDK 版與元件名。

- **Deep Link 只開「關於我們」靜態頁**——仍應驗證 path。
  處置：白名單 path；參數當不可信；可標誤判但先做驗證較省事。

- **「內部員工才裝得了呼叫端 App」**——不是控管。
  處置：**不當誤判**。裝置上任意 App 都可能發 Intent／搶 scheme。

### 判定準則

真漏洞：匯出元件可在無許可下讀寫敏感資料，或觸發轉帳／改密／注入工作階段。

真漏洞：Deep Link／URL Scheme／Intent 接受權杖或直接執行高風險動作，且未驗證來源與參數。

誤判：元件匯出但具 signature／自訂 permission，且可證明無敏感資料與危險 action；
Deep Link 僅導航且參數已白名單。

灰色地帶——**一律當真漏洞修**：`intent://`／過時的 `file://` 轉發、
或把整段外部 URL 丟進 WebView（併見 MAST-PLATFORM-002）。

---

## MAST-PLATFORM-002 · 不安全 WebView

涵蓋 JavaScript 與原生橋接（`addJavascriptInterface`／`WKScriptMessageHandler`）
未驗證來源、允許 `file://` 或通用檔案存取、混合內容、以及把使用者可控 URL
直接 `loadUrl`／`loadRequest` 導致的釣魚或任意程式碼執行。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | WebView／JavaScript Interface／File Access／Mixed Content 類 | High–Warning | unverified | — |
| mobsfscan | `android_kotlin_webview`／`ios_webview`／JS bridge pattern | WARNING–ERROR | unverified | — |
| Semgrep | WebView 設定與 bridge 社群規則 | ERROR–WARNING | unverified | — |
| Android Lint | `SetJavaScriptEnabled`／`AddJavascriptInterface` 等 | Warning–Error | unverified | — |
| Xcode | WKWebView 設定多依賴手動與自訂規則 | — | unverified | — |

規則常因「開了 JavaScript」就報，不論是否載入可信內容。
過關關鍵是**縮小 bridge 面、關掉檔案／混合內容、URL 白名單**，
而不是爭論「我們沒有敏感頁」。

### 壞味道

```swift
let webView = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())
// 任意 https／http 字串直接載入
if let url = URL(string: userSupplied) {
    webView.load(URLRequest(url: url))
}

let config = WKWebViewConfiguration()
config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
config.userContentController.add(self, name: "nativeBridge")
// 橋接直接執行：token、付款，未檢查 message 來源頁

func userContentController(
    _ userContentController: WKUserContentController,
    didReceive message: WKScriptMessage
) {
    if message.name == "nativeBridge", let token = message.body as? String {
        Session.shared.token = token
    }
}
```

```kotlin
val webView = WebView(context)
webView.settings.javaScriptEnabled = true
webView.settings.allowFileAccess = true
webView.settings.allowFileAccessFromFileURLs = true
webView.settings.allowUniversalAccessFromFileURLs = true
webView.settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW

webView.addJavascriptInterface(object {
    @JavascriptInterface
    fun postToken(token: String) {
        Session.token = token // 任意 JS 可呼叫
    }
}, "AndroidBridge")

webView.loadUrl(userSuppliedUrl) // 含 http:// 或 file://
```

### 過關寫法

原則：**能不用 WebView 就用系統瀏覽器或原生畫面**；必須用時只載入自有 HTTPS 來源、
關閉不必要的檔案存取與混合內容、bridge 方法最小化並驗證來源。

```swift
let config = WKWebViewConfiguration()
// 不開啟 allowFileAccessFromFileURLs；不載入 file://
let controller = WKUserContentController()
controller.add(self, name: "nativeBridge")
config.userContentController = controller

let webView = WKWebView(frame: .zero, configuration: config)
webView.navigationDelegate = self

func loadTrusted() {
    webView.load(URLRequest(url: URL(string: "https://app.example.com/help")!))
}

func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
             decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
    guard let host = navigationAction.request.url?.host,
          host == "app.example.com" || host.hasSuffix(".example.com") else {
        decisionHandler(.cancel)
        return
    }
    decisionHandler(.allow)
}

func userContentController(_ userContentController: WKUserContentController,
                           didReceive message: WKScriptMessage) {
    guard message.name == "nativeBridge",
          let host = message.webView?.url?.host,
          host == "app.example.com" else { return }
    // 只處理白名單動作；不要接收權杖字串當「登入」
}
```

```kotlin
val webView = WebView(context)
webView.settings.javaScriptEnabled = true // 僅當頁面需要；能關就關
webView.settings.allowFileAccess = false
webView.settings.allowContentAccess = false
webView.settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
// 不呼叫 allowFileAccessFromFileURLs／allowUniversalAccessFromFileURLs

// 若需 JS bridge：API 24+ 仍要注意；方法面最小化，參數驗證
webView.addJavascriptInterface(SafeBridge(), "AndroidBridge")

webView.webViewClient = object : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
        val host = request.url.host ?: return true
        if (host != "app.example.com" && !host.endsWith(".example.com")) {
            return true // 攔截；或改丟 Custom Tabs
        }
        return false
    }
}

webView.loadUrl("https://app.example.com/help")
```

本機 HTML 優先用 `WebViewAssetLoader`（https 虛擬來源）而非 `file://`。
OAuth／付款若可改用 Custom Tabs／ASWebAuthenticationSession，通常比自管 WebView 安全。

### 常見誤判與處置

- **規則只因 `javaScriptEnabled=true` 就報，頁面為自有靜態說明**——
  處置：保留白名單與無危險 bridge；標記誤判並附 URL 與設定清單。

- **舊版 Android 為了相容開了 file access**——掃描仍報。
  處置：升 minSdk 或改 AssetLoader；**不當長期誤判**。

- **第三方客服／聊天 SDK 內嵌 WebView**——MobSF 常報在依賴。
  處置：升級 SDK、關不必要 file／mixed；否則誤判說明附版本與殘餘風險。

- **「內容是我們 CDN，所以 URL 來自後端就可以」**——中間人改後端回應仍危險。
  處置：客戶端仍做 host 白名單；TLS 見 MAST-NETWORK-001。

### 判定準則

真漏洞：使用者或外部可控輸入流入 `loadUrl`／`loadRequest`，可載入任意來源。

真漏洞：JS bridge 可讀寫權杖、觸發付款／匯出資料，且未驗證來源頁。

真漏洞：啟用 `file://` 通用存取或混合內容，使本機檔或明文腳本可進 WebView 原始碼。

誤判：WebView 僅載入固定自有 HTTPS、JS 面最小、無危險 bridge／檔案存取，
且導覽已白名單。

灰色地帶——**一律當真漏洞修**：把 Deep Link 參數整段當 URL 載入，
或在 bridge 上傳入「任意要執行的 JS 字串」。

---

## MAST-PLATFORM-003 · 剪貼簿外洩敏感資料

涵蓋把權杖、密碼、OTP、完整卡片號或身分證字號寫進系統剪貼簿，
以及未設短命／本機限定就讓其他 App 或鍵盤讀取。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | Clipboard／Sensitive Information 類 | Warning–Info | unverified | — |
| mobsfscan | `UIPasteboard`／`ClipboardManager` 相關 pattern | WARNING–INFO | unverified | — |
| Semgrep | 剪貼簿 sink 與敏感欄位名合流的社群／自訂規則 | ERROR–WARNING | unverified | — |
| Android Lint | Clipboard 自訂規則（視專案組態） | — | unverified | — |
| Xcode | `UIPasteboard` 無預設安全規則；多依賴審查與自訂 | — | unverified | — |

規則幾乎只認 API 呼叫，分不清「複製邀請碼」與「複製 session token」。
預設：**敏感值不要進剪貼簿**；非敏感才允許，並設過期與本機限定。

### 壞味道

```swift
import UIKit

// 權杖／OTP 丟進一般剪貼簿，其他 App 可讀
UIPasteboard.general.string = accessToken
UIPasteboard.general.string = otpCode

// 密碼顯示頁「一鍵複製」且無過期
UIPasteboard.general.string = password

// 自訂 pasteboard 名稱但未設 localOnly／expirationDate
let board = UIPasteboard(name: UIPasteboard.Name("app.secrets"), create: true)!
board.string = refreshToken
```

```kotlin
import android.content.ClipData
import android.content.ClipboardManager

val clipboard = context.getSystemService(ClipboardManager::class.java)

// 權杖寫入主剪貼簿
clipboard.setPrimaryClip(ClipData.newPlainText("token", accessToken))

// OTP／密碼同樣長駐
clipboard.setPrimaryClip(ClipData.newPlainText("otp", otp))
clipboard.setPrimaryClip(ClipData.newPlainText("password", password))

// 複製後未清除，背景 App 輪詢仍讀得到
```

### 過關寫法

原則：**權杖、密碼、長期密鑰絕不進剪貼簿**；使用者明確要求複製的短碼才寫入，
並用本機限定、過期時間，離開畫面時清除。

```swift
import UIKit

func copyShortLivedInviteCode(_ code: String) {
    // 非憑證；仍縮短暴露窗
    let board = UIPasteboard.general
    board.setItems(
        [[UIPasteboard.typeAutomatic: code]],
        options: [
            .localOnly: true,
            .expirationDate: Date().addingTimeInterval(60),
        ],
    )
}

func clearPasteboardIfNeeded() {
    UIPasteboard.general.items = []
}

// 權杖／密碼：提供「顯示」與「手動輸入」，不要提供複製到系統剪貼簿
```

```kotlin
import android.content.ClipData
import android.content.ClipboardManager
import android.os.Build
import android.os.PersistableBundle

fun copyShortLivedInviteCode(context: Context, code: String) {
    val clipboard = context.getSystemService(ClipboardManager::class.java)
    val clip = ClipData.newPlainText("invite", code)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
        clip.description.extras = PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
    }
    clipboard.setPrimaryClip(clip)
    // 短暫後清除；權杖路徑根本不要呼叫這裡
    handler.postDelayed({ clipboard.clearPrimaryClip() }, 60_000)
}

fun neverCopySecrets() {
    // accessToken／password／refresh：UI 不提供「複製」動作
}
```

### 常見誤判與處置

- **複製公開邀請碼／訂單編號**——工具仍可能因 `setPrimaryClip` 報。
  處置：標記誤判並列出字串語意；必要時改用 App 內分享 Sheet，避免系統剪貼簿。

- **「使用者自己按複製」**——若複製的是 session token，仍是真問題。
  處置：**不當誤判**。改短時授權碼或深連結，不要讓長期權杖進剪貼簿。

- **第三方 SDK（客服、鍵盤）讀剪貼簿**——不在你的寫入 sink。
  處置：確認未寫入敏感值；文件化 SDK 行為與最小權限。

- **僅 Debug 複製權杖方便測試**——正式掃描仍命中。
  處置：測試工具走專用 debug 選單且正式建置剔除；不要留在共用程式碼。

### 判定準則

真漏洞：存取權杖、重新整理權杖、密碼、長期 API 金鑰、完整卡片號等
被寫入系統剪貼簿（含具名 pasteboard 但可被其他 App 讀取）。

真漏洞：OTP／驗證碼寫入後無過期、無清除，且可被背景 App 長時間讀取。

誤判：寫入內容可證明為非機密短碼，且已本機限定／短命，正式流程無憑證 sink。

灰色地帶——**一律當真漏洞修**：把「方便貼到網頁登入」當成複製 session token 的理由。

---

## MAST-PLATFORM-004 · 截圖／螢幕錄影／背景快照未擋

涵蓋轉帳、持卡、身分證、權杖顯示等敏感畫面未擋系統截圖／錄影，
以及進入背景時未遮罩，導致多工切換器／快照快取露出敏感 UI。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | Screen Recording／Screenshot／FLAG_SECURE 類 | Warning–Info | unverified | — |
| mobsfscan | `FLAG_SECURE`／截圖防護相關 pattern | INFO–WARNING | unverified | — |
| Semgrep | `FLAG_SECURE`／`isSecureTextEntry`／背景遮罩社群規則 | WARNING | unverified | — |
| Android Lint | Window flag 自訂規則（視專案組態） | — | unverified | — |
| Xcode | 背景快照遮罩多依賴審查；無預設強制規則 | — | unverified | — |

靜態工具常「找不到 `FLAG_SECURE` 就報」，不管畫面是否真的敏感。
過關以**敏感 Activity／頁面強制安全旗標＋背景遮罩**為準，不要只在根 Activity 設一次。

### 壞味道

```swift
import UIKit

// 敏感頁（持卡、轉帳確認）無任何防截圖／遮罩
class CardDetailViewController: UIViewController {
    @IBOutlet weak var panLabel: UILabel! // 完整卡號明文
    // 未在 viewWillDisappear／scene 生命週期蓋模糊層
}

// App 進背景仍保留完整敏感畫面上的視窗快照
func sceneWillResignActive(_ scene: UIScene) {
    // 空實作：系統多工快照直接露出餘額與卡號
}

// 密碼欄位未用安全輸入
passwordField.isSecureTextEntry = false
```

```kotlin
// 轉帳／卡片 Activity 未設 FLAG_SECURE
class TransferActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_transfer)
        // window 未加 WindowManager.LayoutParams.FLAG_SECURE
        amountView.text = balance.toString()
    }
}

// 錄影／螢幕分享時仍顯示完整個資
// 背景切換不做遮罩，Recent Apps 縮圖可見

// EditText 密碼未 inputType=textPassword
```

### 過關寫法

敏感頁：**Android 加 `FLAG_SECURE`**（同時抑制截圖與錄影進近期任務縮圖）；
**iOS 在 resign active 蓋遮罩**，並對密碼／CVV 用安全輸入元件。
遮罩要在回前景時再移除，避免閃爍露出。

```swift
import UIKit

final class PrivacyOverlay {
    static var view: UIView?

    static func show(on window: UIWindow?) {
        guard let window, view == nil else { return }
        let blur = UIVisualEffectView(effect: UIBlurEffect(style: .systemMaterial))
        blur.frame = window.bounds
        blur.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        window.addSubview(blur)
        view = blur
    }

    static func hide() {
        view?.removeFromSuperview()
        view = nil
    }
}

func sceneWillResignActive(_ scene: UIScene) {
    PrivacyOverlay.show(on: (scene as? UIWindowScene)?.windows.first)
}

func sceneDidBecomeActive(_ scene: UIScene) {
    PrivacyOverlay.hide()
}

// 密碼／CVV
passwordField.isSecureTextEntry = true
```

```kotlin
import android.view.WindowManager

class TransferActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        setContentView(R.layout.activity_transfer)
    }
}

// 非敏感頁不要全域亂設，以免誤傷合法截圖需求；
// 持卡、轉帳、身分證預覽、顯示一次性權杖的頁面必須設。
```

### 常見誤判與處置

- **行銷／說明頁被規則要求 FLAG_SECURE**——無敏感欄位。
  處置：標記誤判；規則改為只掃描標了 `sensitive` 的 Activity／路由。

- **「系統仍可能被 root／錄影硬體繞過」**——不是不設旗標的理由。
  處置：**不當誤判**。先做平台提供的防護，再談殘餘風險。

- **WebView 內嵌銀行頁**——原生旗標管得到視窗，管不到遠端頁自己的政策。
  處置：敏感流程改原生頁＋FLAG_SECURE；或確認 WebView 所在 Activity 已設。

- **截圖用於客服除錯**——正式版不應在敏感頁開後門。
  處置：除錯建置才關旗標，並用字串／Manifest 合併證明正式版仍開啟。

### 判定準則

真漏洞：顯示完整卡片號、餘額明細、身分證、權杖、密碼的畫面，
未設 `FLAG_SECURE`（Android）或等價防護，且可被系統截圖／錄影／近期任務縮圖取得。

真漏洞：進入背景時敏感 UI 仍清晰出現在多工切換器快照。

誤判：畫面可證明無敏感欄位，或已遮罩／安全旗標且僅在非敏感流程允許截圖。

灰色地帶——**一律當真漏洞修**：只遮 App 圖示層、實際內容層仍可被系統快照——改為蓋住整個視窗。

---

## MAST-PLATFORM-005 · 分享資料時未授權的應用程式可存取

涵蓋 `FileProvider` 授權過寬、`grantUriPermissions` 未限縮、
隱式 Intent 分享敏感檔案、以及 iOS 的 App Group 與分享擴充未限制對象。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | manifest 分析會標記 `exported="true"` 的 `provider` 與 `grantUriPermissions="true"`；另列出 `<grant-uri-permission>` 的 path 範圍 | High–Warning | partial | MobSF `manifest_analysis.py` 的元件檢查 |
| mobsfscan | —（無專屬規則；`android_kotlin_webview_*` 系列只管 WebView） | — | unverified | — |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（無對應規則） | — | unverified | — |

與 `MAST-PLATFORM-001`（IPC 洩漏）的分界：
前者管**元件被外部呼叫**，本則管**主動分享出去的資料被誰拿到**。

### 壞味道

```xml
<!-- AndroidManifest.xml：Provider 對外開放且授權整個根目錄 -->
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.files"
    android:exported="true"
    android:grantUriPermissions="true">
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/file_paths" />
</provider>
```

```xml
<!-- res/xml/file_paths.xml：把整個 files 目錄都開放出去 -->
<paths>
    <files-path name="all" path="." />
</paths>
```

```kotlin
// 隱式 Intent 分享——任何能處理該 MIME 的 App 都收得到
val intent = Intent(Intent.ACTION_SEND).apply {
    type = "application/pdf"
    putExtra(Intent.EXTRA_STREAM, statementUri)   // 對帳單流向不明
}
startActivity(intent)
```

```swift
// UIActivityViewController 未限制可用的活動類型
let vc = UIActivityViewController(activityItems: [statementURL], applicationActivities: nil)
present(vc, animated: true)
```

### 過關寫法

```xml
<!-- Provider 不對外開放，僅以逐次授權的方式分享 -->
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.files"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/file_paths" />
</provider>
```

```xml
<!-- 只開放專用的分享子目錄，不是整個 files -->
<paths>
    <files-path name="shared_exports" path="exports/" />
</paths>
```

```kotlin
// 逐次授予讀取權限，且用選擇器讓使用者明確決定接收方
val uri = FileProvider.getUriForFile(context, "com.example.files", exportFile)
val share = Intent(Intent.ACTION_SEND).apply {
    type = "application/pdf"
    putExtra(Intent.EXTRA_STREAM, uri)
    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)   // 只讀，且僅此次
}
startActivity(Intent.createChooser(share, "分享對帳單"))

// 分享結束後主動撤銷
context.revokeUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
```

```swift
// 排除不適合傳遞敏感檔案的活動類型
let vc = UIActivityViewController(activityItems: [statementURL], applicationActivities: nil)
vc.excludedActivityTypes = [
    .postToFacebook, .postToTwitter, .postToWeibo, .postToVimeo,
    .assignToContact, .addToReadingList,
]
present(vc, animated: true)
```

**分享前取得使用者同意是檢測基準另一條的要求**（同意流程屬人工查核）；
本則管的是同意之後，資料是否只流向使用者選定的對象。

### 常見誤判與處置

- **`exported="true"` 的 Provider 有 `android:permission` 保護。**
  處置：標記誤判，佐證附該權限的宣告與 `protectionLevel`——
  `normal` 等級等同沒有保護，必須是 `signature` 才算數。

- **分享的是使用者自己選的公開檔案。**
  處置：標記誤判，佐證寫明該路徑下只存放使用者主動匯出的內容，
  且不含權杖或個資。

### 判定準則

真漏洞：`FileProvider` 的 `exported="true"` 且無 `signature` 等級的權限保護。

真漏洞：`file_paths.xml` 授權範圍涵蓋存放敏感資料的目錄。

真漏洞：以隱式 Intent 傳遞敏感檔案且未使用 `createChooser`，
或未加 `FLAG_GRANT_READ_URI_PERMISSION` 而改用永久授權。

誤判：分享路徑經確認僅含使用者主動匯出的非敏感內容，有路徑設定佐證。

## MAST-PLATFORM-006 · Android 未防護螢幕覆蓋攻擊

涵蓋敏感操作的畫面未設定觸控過濾，惡意 App 可疊加透明視窗誘導點擊
（tapjacking／overlay attack）。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| mobsfscan | `android_tapjacking`（Kotlin）／`android_detect_tapjacking`（Java）——屬 **best_practices 類，比對防護程式碼的樣式，缺少時才報** | INFO | partial | 規則原始碼：`mobsfscan/rules/semgrep/best_practices/{kotlin/tapjacking.yaml,java/tapjacking.yaml}` |
| MobSF | 靜態報告的 "This app does not have tapjacking protection" | Info | partial | 同上（MobSF 內嵌 mobsfscan 規則） |
| Android Lint | —（無對應規則） | — | unverified | — |
| Semgrep | —（官方規則庫無對應規則） | — | unverified | — |
| SwiftLint | —（不適用；iOS 系統不允許跨 App 覆蓋） | — | unverified | — |

**這一則只適用 Android。** iOS 的視窗系統不允許第三方 App 疊加在其他 App 之上，
因此檢測基準的這一條在 iOS 上標「不適用」。

⚠ 規則方向與一般規則相反：**「未命中」代表缺少防護，是壞事。**

### 壞味道

```kotlin
// 轉帳確認畫面未設任何觸控過濾——透明覆蓋層可誘導使用者點下確認
class TransferConfirmActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_transfer_confirm)
        confirmButton.setOnClickListener { doTransfer() }
    }
}
```

### 過關寫法

```kotlin
class TransferConfirmActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_transfer_confirm)

        // 有其他視窗覆蓋時，本視窗不接受觸控事件
        window.decorView.filterTouchesWhenObscured = true

        // 個別關鍵控制項也可單獨設定
        confirmButton.filterTouchesWhenObscured = true

        // 進一步：覆蓋發生時主動中止操作
        confirmButton.setOnTouchListener { _, event ->
            if (event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED != 0 ||
                event.flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED != 0) {
                showOverlayWarning()
                true      // 吞掉此次觸控
            } else false
        }
    }
}
```

也可在版面 XML 上直接宣告，涵蓋整個畫面：

```xml
<!-- res/layout/activity_transfer_confirm.xml -->
<LinearLayout
    xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:filterTouchesWhenObscured="true">
    <!-- 敏感操作的控制項 -->
</LinearLayout>
```

**不需要每個畫面都設。** 套用在涉及金流、授權同意、權限授予的畫面即可——
全面套用反而可能在正常的分割畫面情境造成誤擋。

### 常見誤判與處置

- **防護寫在自訂的 base Activity 裡**——規則比對不到個別畫面的設定。
  處置：標記誤判，佐證寫明 base class 的行號與繼承該 base 的畫面清單。

- **App 完全沒有敏感操作畫面。**
  處置：標記不適用，佐證說明 App 的功能範圍。

### 判定準則

真漏洞：涉及金流、授權或權限授予的畫面未設 `filterTouchesWhenObscured`
且未在觸控事件中檢查 `FLAG_WINDOW_IS_OBSCURED`。

不適用：iOS 平台（系統不允許跨 App 覆蓋）。

誤判：防護在共用 base class 中實作，有行號與套用範圍佐證。

## MAST-PLATFORM-007 · 輸入敏感資料的欄位未關閉鍵盤快取

涵蓋密碼、身分證號、卡號等欄位允許系統鍵盤學習與自動填字，
輸入內容因此進入鍵盤字典並可能出現在其他 App 的建議列。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| mobsfscan | `android_kotlin_sensitive_input_keyboard_cache`（Kotlin）／`android_sensitive_input_keyboard_cache`（Java）；`ios_keyboard_cache`／`ios_custom_keyboard_disabled`（Swift） | WARNING–INFO | partial | 規則原始碼：`mobsfscan/rules/semgrep/{kotlin/android.yaml,java/android/sensitive_input.yaml,best_practices/swift/keyboard.yaml}` |
| MobSF | 靜態報告的 "sensitive input field with keyboard cache enabled" | Warning | partial | 同上 |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（無對應規則） | — | unverified | — |

### 壞味道

```kotlin
// EditText 未設 inputType，輸入內容會進入鍵盤學習字典
val idField = EditText(context).apply {
    hint = "身分證字號"
}
```

```xml
<!-- 版面上同樣未宣告 -->
<EditText
    android:id="@+id/id_number"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:hint="身分證字號" />
```

```swift
let idField = UITextField()
idField.placeholder = "身分證字號"
// 未關閉自動修正與自動填字，且未限制第三方鍵盤
```

### 過關寫法

```kotlin
// textNoSuggestions 關閉學習；密碼欄位用 textPassword（已隱含不快取）
val idField = EditText(context).apply {
    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
}

val pwdField = EditText(context).apply {
    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
}
```

```xml
<EditText
    android:id="@+id/id_number"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:inputType="textNoSuggestions"
    android:importantForAutofill="no" />

<EditText
    android:id="@+id/password"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:inputType="textPassword" />
```

```swift
let idField = UITextField()
idField.autocorrectionType = .no          // 不進入自動修正字典
idField.spellCheckingType = .no
idField.textContentType = .oneTimeCode    // 或設為 nil，避免被自動填入既有值

let pwdField = UITextField()
pwdField.isSecureTextEntry = true         // 隱含關閉快取與截圖
```

iOS 另可在 `AppDelegate` 拒絕第三方鍵盤，避免輸入內容離開裝置：

```swift
func application(_ application: UIApplication,
                 shouldAllowExtensionPointIdentifier id: UIApplication.ExtensionPointIdentifier) -> Bool {
    return id != .keyboard      // 僅允許系統鍵盤
}
```

### 常見誤判與處置

- **欄位收的是非敏感資料**——暱稱、搜尋關鍵字。
  處置：標記誤判，佐證列出該欄位的用途與收集的資料類型。

- **密碼欄位已用 `textPassword` / `isSecureTextEntry`**，但規則仍報。
  處置：這兩者已隱含關閉快取，屬誤判。佐證附設定行號。

- **拒絕第三方鍵盤影響使用者習慣。**
  處置：這是產品決策。金流類 App 通常接受此限制；一般 App 可只對敏感欄位
  關閉快取而不全面拒絕第三方鍵盤，並記錄該決策。

### 判定準則

真漏洞：收集密碼、身分證號、卡號、健康資料的欄位未關閉鍵盤快取。

誤判：欄位已使用密碼類型（隱含關閉快取），有設定行號佐證。

誤判：欄位收集的資料經確認非敏感，有用途說明佐證。

## MAST-PLATFORM-008 · 過度宣告權限或未說明用途

涵蓋 manifest／plist 宣告了功能用不到的權限，以及宣告了權限卻未提供
使用者可理解的用途說明。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | manifest 分析會逐一列出宣告的權限並標註其風險等級（"dangerous" 權限特別標示）；iOS 側列出 `Info.plist` 的 `NS*UsageDescription` | High–Info | partial | MobSF `manifest_analysis.py` 與 `permissions` 區段 |
| Android Lint | —（無「過度宣告」規則；Lint 只檢查缺少的權限，不檢查多餘的） | — | unverified | — |
| mobsfscan | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（無對應規則） | — | unverified | — |

**「多餘」需要對照功能才判得出來**，工具只能列出清單。
檢測時的做法是：把宣告的權限與調查表所述功能逐一比對，
問「哪個功能需要這個權限」——答不出來的就是多餘。

iOS 側有一個硬性條件：**宣告了會觸發權限請求的 API，卻沒有對應的
`NS*UsageDescription`，App 會直接閃退**。這是 App Store 審查會擋的項目。

### 壞味道

```xml
<!-- AndroidManifest.xml：一次要滿，之後再說 -->
<uses-permission android:name="android.permission.READ_CONTACTS" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.RECORD_AUDIO" />
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.READ_PHONE_STATE" />
```

```plist
<!-- Info.plist：用途說明寫得等於沒寫 -->
<key>NSLocationWhenInUseUsageDescription</key>
<string>需要位置權限</string>
<key>NSCameraUsageDescription</key>
<string>App 需要相機</string>
```

### 過關寫法

```xml
<!-- 只宣告功能實際需要的權限；可選功能用 uses-feature required="false" -->
<uses-permission android:name="android.permission.CAMERA" />

<!-- 相機僅用於掃描 QR Code，非核心功能 -->
<uses-feature android:name="android.hardware.camera" android:required="false" />

<!-- 儲存權限：Android 10 以上改用 scoped storage，不需要廣泛的讀寫權限 -->
<uses-permission
    android:name="android.permission.READ_EXTERNAL_STORAGE"
    android:maxSdkVersion="28" />
```

```plist
<!-- 用途說明要具體到使用者看得懂「為什麼」與「用來做什麼」 -->
<key>NSCameraUsageDescription</key>
<string>用於掃描帳單上的 QR Code 以自動帶入付款資訊，不會儲存或上傳影像。</string>
<key>NSLocationWhenInUseUsageDescription</key>
<string>用於顯示您附近的服務據點，僅在使用地圖功能時取用，不會於背景持續蒐集。</string>
```

iOS 17 以上另需 **Privacy Manifest**（`PrivacyInfo.xcprivacy`）
宣告蒐集的資料類型與必要理由 API 的使用原因：

```xml
<!-- PrivacyInfo.xcprivacy -->
<dict>
    <key>NSPrivacyCollectedDataTypes</key>
    <array>
        <dict>
            <key>NSPrivacyCollectedDataType</key>
            <string>NSPrivacyCollectedDataTypeEmailAddress</string>
            <key>NSPrivacyCollectedDataTypeLinkedToUser</key>
            <true/>
            <key>NSPrivacyCollectedDataTypeUsedForTracking</key>
            <false/>
        </dict>
    </array>
</dict>
```

**送檢前自己走一遍**：列出所有宣告的權限，逐一寫出「哪個功能用到、
在哪個畫面觸發」。寫不出來的就刪掉——這份對照表本身就是佐證。

### 常見誤判與處置

- **權限由第三方 SDK 帶進來**——manifest merger 合併後才出現。
  處置：這是真實情況但**仍需說明**。用 `tools:node="remove"` 移除不需要的，
  或在調查表列出該 SDK 與其所需權限。不要略過——檢測會看合併後的 manifest。

- **權限為未來功能預留。**
  處置：**刪掉。** 未上線的功能不該宣告權限，這在檢測時無法辯護。

### 判定準則

真漏洞：宣告的權限無法對應到任何已上線功能。

真漏洞：iOS 使用了需要授權的 API 但缺少對應的 `NS*UsageDescription`。

真漏洞：用途說明過於空泛，未說明取用時機與用途。

誤判：權限由第三方 SDK 帶入，且已於調查表列出該 SDK 與用途。
