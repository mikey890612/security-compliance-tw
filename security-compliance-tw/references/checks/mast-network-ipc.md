# MAST：網路傳輸、本機驗證、IPC 與 WebView

行動 App 的攻擊面常落在明文 HTTP、本機生物辨識／PIN 閘道、
匯出元件與 Deep Link，以及內嵌 WebView 的橋接與檔案存取。
靜態規則多半只做 Info.plist／AndroidManifest 與 API 名稱比對——
看到 `NSAllowsArbitraryLoads`、`cleartextTrafficPermitted`、
`exported="true"`、`addJavascriptInterface` 就報，
不保證能判斷「是否真的傳敏感資料」或「是否已在執行期再驗證」。
因此過關寫法要以**平台網路政策、系統驗證 API、最小匯出與安全 WebView 設定**為主，
比事後寫誤判說明省事。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## MAST-NET-001 · 明文傳輸／ATS／NSC

涵蓋以 HTTP 明文傳送憑證或個資、iOS App Transport Security（ATS）全域或網域例外放寬、
Android Network Security Config（NSC）允許 cleartext，以及自訂 TrustManager／
`URLSession` delegate 無條件信任所有憑證（等同關閉傳輸完整性與機密性）。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | Cleartext Traffic／ATS／Network Security Config／Trust All Certs 類 | High–Warning | unverified | — |
| mobsfscan | `ios_ats_arbitrary_loads`／Android cleartext／insecure SSL pattern | WARNING–ERROR | unverified | — |
| Semgrep | `swift.*`／`kotlin.*`／`java.lang.security.*` 明文傳輸與 SSL 繞過社群規則 | ERROR–WARNING | unverified | — |
| Android Lint | `CleartextTraffic`／`InsecureTrustManager` 等（視 AGP／Lint 組態） | Error–Warning | unverified | — |
| Xcode／Clang Static Analyzer | ATS／自訂 TLS 驗證多依賴 Info.plist 與手動／自訂規則 | — | unverified | — |

多數工具對 Info.plist／`network_security_config.xml` 是**有例外就報**，
不會讀你的「僅開發環境」註解。改成預設禁止明文、正式建置不含例外，
比爭論用途快。

### 壞味道

```swift
// Info.plist：全域關閉 ATS（掃描器必報）
// NSAppTransportSecurity → NSAllowsArbitraryLoads = true

// 執行期允許 http://
let url = URL(string: "http://api.example.com/login")!
var req = URLRequest(url: url)
req.httpBody = try JSONEncoder().encode(["password": password])

// 無條件信任憑證
func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
) {
    completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
}
```

```kotlin
// AndroidManifest：application 層允許 cleartext
// android:usesCleartextTraffic="true"
// 或 network_security_config.xml：
// <base-config cleartextTrafficPermitted="true" />

val client = OkHttpClient.Builder()
    .hostnameVerifier { _, _ -> true } // 接受任意主機名
    .build()

// 自訂 TrustManager 信任全部
val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
})
```

### 過關寫法

原則：**正式建置只走 HTTPS**；ATS／NSC 預設拒絕明文；
憑證驗證走系統預設鏈，不要寫「一律 trust」。
掃描器認得 `https://`、`NSAllowsArbitraryLoads=false`（或不出現）、
`cleartextTrafficPermitted="false"` 這類設定——改完之後，多數明文／ATS／NSC 規則就不再命中。

```swift
// Info.plist：不要設 NSAllowsArbitraryLoads；必要時僅對具名網域開例外並註明理由
let url = URL(string: "https://api.example.com/login")!
var req = URLRequest(url: url)
req.setValue("application/json", forHTTPHeaderField: "Content-Type")
// 使用系統 URLSession 預設 TLS；不實作「一律信任」的 delegate

// 若需釘選：在 didReceive challenge 內比對 SPKI／憑證雜湊後再 .useCredential
// 釘選失敗要取消挑戰，不可 fallback 成信任全部
```

```kotlin
// AndroidManifest：usesCleartextTraffic 省略或 false
// res/xml/network_security_config.xml：
// <base-config cleartextTrafficPermitted="false" />
// 開發用 debug-overrides 僅綁 debug 建置，勿進 release

val client = OkHttpClient.Builder()
    // 不覆寫 hostnameVerifier／TrustManager；必要時用 CertificatePinner
    .certificatePinner(
        CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .build(),
    )
    .build()

val request = Request.Builder()
    .url("https://api.example.com/login")
    .post(body)
    .build()
```

除錯代理（Charles／mitmproxy）需要的使用者安裝 CA，應僅在 debug 建置的
`debug-overrides`／開發描述檔出現；release 組態與正式 IPA／APK 抽樣都不該帶。

### 常見誤判與處置

- **僅對靜態資源網域開 ATS／NSC 例外，且該網域從不帶憑證**——
  工具仍可能因例外鍵存在而報。
  處置：能改 HTTPS 就改；不能則標記誤判並列出例外網域與流量內容證明。

- **「內網／VPN 才用 HTTP」**——裝置離開該網路或 DNS 被劫持時仍危險。
  處置：**不當誤判**。內網也走 TLS，或改用平台提供的安全通道 API。

- **測試／Debug 才關 ATS**——掃描器常掃正式產物，但也會掃原始碼裡的 plist。
  處置：例外只放 debug 專用 plist／`debug-overrides`；正式 pipeline 断言無全域放寬。

- **第三方 SDK 自己的 cleartext 或 TrustAll**——MobSF 可能報在依賴裡。
  處置：升級或更換 SDK；無法改則記錄風險接受並限縮該 SDK 可觸達的資料。

### 判定準則

真漏洞：登入、權杖交換、個資或交易 API 以 HTTP 明文傳送。

真漏洞：ATS 全域 `NSAllowsArbitraryLoads`、NSC／Manifest 允許 cleartext，
且 App 實際或可配置地對敏感端點使用明文。

真漏洞：自訂 TrustManager／`hostnameVerifier`／`URLSession` delegate
無條件接受任意憑證或主機名。

誤判：例外僅涵蓋可證明的非敏感靜態資源，正式建置無 TrustAll，
且敏感 API 一律 HTTPS。

灰色地帶——**一律當真漏洞修**：開發用 TrustAll 殘留在 release，
或「先連上再升級」的明文引導請求仍帶帳密。

---

## MAST-AUTH-001 · 本機驗證可繞過

涵蓋把生物辨識／裝置 PIN 的成功與否只當 UI 開關、
敏感操作僅靠客戶端布林旗標閘道、以及可被 Hook／修補繞過的「越獄／root 偵測當唯一防護」。
重點是：**本機驗證不能單獨當伺服器信任根**；繞過客戶端後仍應無法完成高風險動作。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | Insecure Authentication／Biometric Bypass／Root Detection 類 | High–Warning | unverified | — |
| mobsfscan | 生物辨識／本地認證／root 偵測相關 pattern | WARNING | unverified | — |
| Semgrep | `swift.*`／`kotlin.*` LocalAuthentication／BiometricPrompt 誤用社群規則 | ERROR–WARNING | unverified | — |
| Android Lint | 生物辨識／Credential 相關自訂規則（視專案組態） | — | unverified | — |
| Xcode | LocalAuthentication 誤用多依賴程式碼審查與自訂規則 | — | unverified | — |

靜態工具很難證明「可繞過」——多半只看到缺少伺服器二次驗證、
或 Keychain／Keystore 未綁 `accessControl`／`setUserAuthenticationRequired`。
過關寫法要讓**金鑰與高風險 API 都綁系統驗證**，而不只顯示 Face ID 動畫。

### 壞味道

```swift
import LocalAuthentication

var isUnlocked = false

func unlockWithBiometrics() {
    let ctx = LAContext()
    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "解鎖") { ok, _ in
        // 只改記憶體旗標；權杖早已在 UserDefaults／記憶體明文
        isUnlocked = ok
    }
}

func transfer(amount: Int) {
    guard isUnlocked else { return } // Hook 把旗標改 true 即可
    api.post("/transfer", body: ["amount": amount])
}
```

```kotlin
var unlocked = false

fun unlock(activity: FragmentActivity) {
    val prompt = BiometricPrompt(activity, executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                unlocked = true // 僅客戶端旗標
            }
        },
    )
    prompt.authenticate(BiometricPrompt.PromptInfo.Builder()
        .setTitle("解鎖")
        .setNegativeButtonText("取消")
        .build())
}

fun transfer(amount: Int) {
    if (!unlocked) return
    api.post("/transfer", mapOf("amount" to amount))
}
```

### 過關寫法

兩件事一起做：**敏感材料用系統驗證綁定取出**（Keychain access control／
Keystore `setUserAuthenticationRequired`），
**高風險操作一律帶可伺服器驗證的短時憑證或 step-up**，不要只靠 `isUnlocked`。

```swift
import LocalAuthentication
import Security

func readTokenBoundToBiometrics(account: String) throws -> Data {
    let ctx = LAContext()
    ctx.localizedReason = "授權讀取工作階段"
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecUseAuthenticationContext as String: ctx,
        // 寫入時應使用 AccessControl：biometryCurrentSet / userPresence
    ]
    var out: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &out)
    guard status == errSecSuccess, let data = out as? Data else {
        throw KeychainError.unhandled(status)
    }
    return data
}

func transfer(amount: Int) async throws {
    let token = try readTokenBoundToBiometrics(account: "session")
    // 伺服器端仍需授權／交易簽章；客戶端成功不等于放行
    try await api.postTransfer(amount: amount, bearer: token)
}
```

```kotlin
import androidx.biometric.BiometricPrompt
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.Cipher

fun buildBiometricCipher(alias: String): Cipher {
    // KeyGenParameterSpec：setUserAuthenticationRequired(true)
    // PURPOSE_ENCRYPT or PURPOSE_DECRYPT + BLOCK_MODE_GCM
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, loadKey(alias))
    return cipher
}

fun unlockAndTransfer(activity: FragmentActivity, amount: Int) {
    val cipher = buildBiometricCipher("auth.aes")
    val prompt = BiometricPrompt(activity, executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val crypto = result.cryptoObject?.cipher ?: return
                // 用通過驗證的 Cipher 解開本地包裹的 refresh／session 材料
                val token = unwrapToken(crypto)
                api.postTransfer(amount, token) // 伺服器再驗權
            }
        },
    )
    prompt.authenticate(
        BiometricPrompt.PromptInfo.Builder()
            .setTitle("確認轉帳")
            .setNegativeButtonText("取消")
            .build(),
        BiometricPrompt.CryptoObject(cipher),
    )
}
```

越獄／root 偵測可當**防禦深度與遙測**，不可當唯一閘道；
偵測失敗時應提高後端風控或拒絕高風險操作，而不是只藏一個按鈕。

### 常見誤判與處置

- **設定頁用生物辨識只為了顯示「已鎖定」動畫，無敏感資料**——
  工具仍可能因 `evaluatePolicy`／`BiometricPrompt` 用法報。
  處置：說明無金鑰／無高風險 API；若規則堅持，改成不對外暴露的內部設定流。

- **「已做 root 偵測」當本機驗證過關證據**——偵測可被 patch。
  處置：**不當誤判**。補 Keystore／Keychain 綁定與伺服器 step-up。

- **離線 App 無法每次打後端**——仍可用系統綁定的金鑰做本地解密，
  上線後再換發短時權杖。
  處置：文件化離線威脅模型；高風險動作（轉帳、改密）改為必須連線。

- **第三方錢包／SDK 自己的生物辨識**——不在你的 sink。
  處置：確認 SDK 是否使用 CryptoObject／AccessControl；否則記錄殘餘風險。

### 判定準則

真漏洞：高風險操作（轉帳、看完整個資、匯出金鑰）僅以客戶端布林／
未綁定密碼學物件的生物辨識結果閘道，且無伺服器二次驗證。

真漏洞：權杖或金鑰在「通過生物辨識前」即可自本機明文讀出。

誤判：生物辨識僅用於非敏感 UI，敏感材料始終需系統驗證才能取出，
且高風險 API 具伺服器授權。

灰色地帶——**一律當真漏洞修**：本機 PIN 自寫比對、或把「通過一次」快取成
長時間 `isUnlocked=true` 而不重新綁定金鑰使用。

---

## MAST-IPC-001 · 過度匯出元件／危險 Deep Link

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

```kotlin
// AndroidManifest：
// <activity android:name=".TransferActivity" android:exported="true">
//   <intent-filter>
//     <action android:name="android.intent.action.VIEW" />
//     <data android:scheme="myapp" android:host="transfer" />
//   </intent-filter>
// </activity>
// <provider ... android:exported="true" android:grantUriPermissions="true" /> 無權限

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

```kotlin
// Manifest：無跨 App 需求 → android:exported="false"
// 需要被外部開啟：exported=true + 自訂 permission，或僅 App Links（autoVerify）

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
或把整段外部 URL 丟進 WebView（併見 MAST-WEB-001）。

---

## MAST-WEB-001 · 不安全 WebView

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
  處置：客戶端仍做 host 白名單；TLS 見 MAST-NET-001。

### 判定準則

真漏洞：使用者或外部可控輸入流入 `loadUrl`／`loadRequest`，可載入任意來源。

真漏洞：JS bridge 可讀寫權杖、觸發付款／匯出資料，且未驗證來源頁。

真漏洞：啟用 `file://` 通用存取或混合內容，使本機檔或明文腳本可進 WebView 原始碼。

誤判：WebView 僅載入固定自有 HTTPS、JS 面最小、無危險 bridge／檔案存取，
且導覽已白名單。

灰色地帶——**一律當真漏洞修**：把 Deep Link 參數整段當 URL 載入，
或在 bridge 上傳入「任意要執行的 JS 字串」。
