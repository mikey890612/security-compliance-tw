# MAST：網路傳輸與憑證驗證

行動 App 的網路攻擊面常落在明文 HTTP 與平台網路政策（ATS／NSC），
以及「系統信任鏈過了就連」——那擋不住被信任 CA 簽出的假憑證。
靜態規則多半只做 Info.plist／AndroidManifest 與 API 名稱比對，
看到 `NSAllowsArbitraryLoads`、`cleartextTrafficPermitted` 就報。
因此過關寫法要以**平台網路政策設定**與**對高風險主機的明確釘選點**為主。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

**「掃描器怎麼標」只收可查證的工具**：MobSF／mobsfscan、Android Lint、
detekt、SwiftLint、Semgrep——規則 id 逐一與官方原始碼或規則清單核對過。

## MAST-NETWORK-001 · 明文傳輸／ATS／NSC

涵蓋以 HTTP 明文傳送憑證或個資、iOS App Transport Security（ATS）全域或網域例外放寬、
Android Network Security Config（NSC）允許 cleartext，以及自訂 TrustManager／
`URLSession` delegate 無條件信任所有憑證（等同關閉傳輸完整性與機密性）。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | Cleartext Traffic／ATS／Network Security Config／Trust All Certs 類 | High–Warning | unverified | — |
| mobsfscan | Android：`android_manifest_usescleartext`（`android:usesCleartextTraffic="true"`）／`android_manifest_base_config_cleartext`（NSC 的 `cleartextTrafficPermitted="true"`）。iOS：`ios_ats_arbitrary_loads`（`NSAllowsArbitraryLoads`） | ERROR | verified | `testdata/scan-artifacts/open-source/20260907T001858Z/mobsfscan-android.json#rule=android_manifest_usescleartext`、`#rule=android_manifest_base_config_cleartext`；`testdata/scan-artifacts/open-source/20260907T001858Z/mobsfscan-ios.json#rule=ios_ats_arbitrary_loads`（另見 `references/scanner-verification-log.md`） |
| Semgrep | `swift.*`／`kotlin.*`／`java.lang.security.*` 明文傳輸與 SSL 繞過社群規則 | ERROR–WARNING | unverified | — |
| Android Lint | `CleartextTraffic`／`InsecureTrustManager` 等（視 AGP／Lint 組態） | Error–Warning | unverified | — |
| Xcode／Clang Static Analyzer | ATS／自訂 TLS 驗證多依賴 Info.plist 與手動／自訂規則 | — | unverified | — |

多數工具對 Info.plist／`network_security_config.xml` 是**有例外就報**，
不會讀你的「僅開發環境」註解。改成預設禁止明文、正式建置不含例外，
比爭論用途快。

### 壞味道

```plist
<!-- Info.plist：全域關閉 ATS（掃描器必報） -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

```swift
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

```xml
<!-- AndroidManifest.xml：application 層允許明文 -->
<application android:usesCleartextTraffic="true">
</application>
```

```xml
<!-- 或 res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true" />
</network-security-config>
```

```kotlin
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

```plist
<!-- Info.plist：最乾淨的過關方式是整段不出現 NSAppTransportSecurity。
     必要時只對具名網域開例外，並保留 forward secrecy 與 TLS 下限 -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy.example.com</key>
        <dict>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
        </dict>
    </dict>
</dict>
```

```swift
let url = URL(string: "https://api.example.com/login")!
var req = URLRequest(url: url)
req.setValue("application/json", forHTTPHeaderField: "Content-Type")
// 使用系統 URLSession 預設 TLS；不實作「一律信任」的 delegate

// 若需釘選：在 didReceive challenge 內比對 SPKI／憑證雜湊後再 .useCredential
// 釘選失敗要取消挑戰，不可 fallback 成信任全部
```

```xml
<!-- AndroidManifest.xml：usesCleartextTraffic 省略或設 false，並指向 NSC -->
<application
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config">
</application>
```

```xml
<!-- res/xml/network_security_config.xml
     debug-overrides 只在 debug 建置生效，不會進 release -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

```kotlin
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

## MAST-NETWORK-002 · 無憑證釘選（僅 ATS／NSC 不夠）

涵蓋敏感 API 只靠系統 CA 信任鏈、未做 SPKI／公鑰釘選，以及「開了 ATS／NSC 就夠」的誤區。
ATS／NSC 擋的是明文與明顯的憑證繞過；**使用者安裝的 CA、企業代理或遭竄改的信任庫**仍可能對預設 TLS 成功中間人。
本則只談釘選：固定比對預期公鑰／憑證雜湊，失敗就中斷——不可 fallback 成信任全部（TrustAll 屬網路傳輸檢查，不在此重寫）。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | SSL Pinning／Certificate Pinning 缺失類 | High–Warning | unverified | — |
| mobsfscan | `android_ssl_pinning`／`android_certificate_transparency`（Android）、`ios_cert_pinning`（iOS）——**皆屬 best_practices 類，缺少時才報** | INFO | verified | `testdata/scan-artifacts/open-source/20260907T001858Z/mobsfscan-android.json#rule=android_ssl_pinning`、`#rule=android_certificate_transparency`；`testdata/scan-artifacts/open-source/20260907T001858Z/mobsfscan-ios.json#rule=ios_cert_pinning`（fixture 未實作釘選，三條均命中）（另見 `references/scanner-verification-log.md`） |
| Semgrep | `swift.*`／`kotlin.*` pinning／TrustKit／CertificatePinner 社群規則 | ERROR–WARNING | unverified | — |
| Android Lint | CertificatePinner／自訂 TrustManager 相關（視專案組態） | — | unverified | — |
| Xcode／Clang Static Analyzer | URLSession 釘選多依賴手動或 TrustKit 等自訂規則 | — | unverified | — |

靜態工具很難證明「有沒有釘對」——多半只看到缺少 `CertificatePinner`／TrustKit／
`SecTrust` 雜湊比對。過關寫法要讓**敏感主機有明確釘選點，且失敗路徑取消連線**。

### 壞味道

```plist
<!-- Info.plist 維持 ATS 預設（整段不出現 NSAllowsArbitraryLoads）。
     這只擋明文，不擋「被系統信任的 CA 簽出的假憑證」——以為就此足夠是本則的誤區 -->
```

```swift
let session = URLSession(configuration: .default)
// 無 URLSessionDelegate 釘選；任何系統信任的 CA 簽出的 api.example.com 都過

func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
) {
    // 「除錯方便」：釘選失敗就改信任全部——等於沒釘
    completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
}
```

```xml
<!-- res/xml/network_security_config.xml：只禁了明文，沒有任何 <pin-set>。
     系統信任鏈過得了就連得上——這正是釘選要擋的那一段 -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>
```

```kotlin
val client = OkHttpClient.Builder()
    // 未設定 CertificatePinner；系統信任鏈過了就連
    .build()

val request = Request.Builder()
    .url("https://api.example.com/login")
    .post(body)
    .build()
```

### 過關寫法

原則：**對登入、權杖、交易等敏感主機做 SPKI／公鑰釘選**；
正式建置至少釘葉憑證或中繼公鑰，並準備輪替用的備援 pin。
釘選失敗只能取消挑戰／拋錯，**不可**退回「信任系統鏈上任意憑證」。

```swift
import CryptoKit
import Foundation

// 亦可用 TrustKit：kTSKPublicKeyHashes 指向 api.example.com 的 SPKI SHA-256
let pinnedSPKIHashes: Set<String> = [
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 現行
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", // 輪替備援
]

func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let trust = challenge.protectionSpace.serverTrust,
          challenge.protectionSpace.host == "api.example.com" else {
        completionHandler(.performDefaultHandling, nil)
        return
    }
    guard let pin = spkiSHA256(of: trust), pinnedSPKIHashes.contains(pin) else {
        completionHandler(.cancelAuthenticationChallenge, nil) // 失敗不 fallback
        return
    }
    completionHandler(.useCredential, URLCredential(trust: trust))
}
```

```kotlin
val client = OkHttpClient.Builder()
    .certificatePinner(
        CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
            .build(),
    )
    .build()

```

```xml
<!-- res/xml/network_security_config.xml：對正式域名加 <pin-set>。
     與 OkHttp 的 CertificatePinner 擇一或並用；NSC 的 pin 對所有
     走系統堆疊的連線生效（含 WebView），CertificatePinner 只管 OkHttp -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <!-- 備援 pin 是必要的：只放一枚，憑證輪替當天全體使用者連不上 -->
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

`expiration` 到期後該 `pin-set` 會自動失效並退回一般驗證——
這是刻意的安全閥，但也表示**到期日必須進維運行事曆**，否則釘選會無聲消失。
`debug-overrides` 只在 debug 建置生效，release 抽樣仍須驗到 pin。

ATS／NSC 仍要維持關閉明文與 TrustAll；它們是底線，**不能替代**對高風險主機的釘選。

### 常見誤判與處置

- **「我們全站 HTTPS + ATS／NSC，掃描還報沒 pinning」**——
  工具在找釘選 API／設定，不是在否定 TLS。
  處置：對敏感主機補 SPKI pin；純靜態官網／CDN 可標範圍外並附流量分類。

- **只在 debug 為抓包關掉 pin，卻殘留在 release**——
  處置：**不當誤判**。用 product flavour／編譯旗標隔離；正式 pipeline 断言有 pin。

- **釘選葉憑證、憑證一換就全掛**——營運問題，不是省略理由。
  處置：同時釘中繼或備援 SPKI，並備輪替文件；勿因此改回 TrustAll。

- **第三方 SDK 自建連線未釘選**——MobSF 可能報在依賴。
  處置：升級／換 SDK，或把敏感呼叫收回自有客戶端；無法改則記錄殘餘風險。

### 判定準則

真漏洞：登入、權杖交換、個資或交易 API 的主機僅依賴系統 CA 鏈，
無 SPKI／公鑰釘選，且威脅模型含使用者 CA／企業代理中間人。

真漏洞：宣稱有釘選，但失敗路徑改 `.useCredential` 信任全部或關閉驗證。

誤判：非敏感靜態資源未釘選，敏感主機已釘選且失敗即中斷；
或產品明確不處理使用者 CA 威脅並以其他控管書面接受殘餘風險。

灰色地帶——**一律當真漏洞修**：pin 寫死過期雜湊後全面改走「略過驗證」後門，
或只在註解／文件寫「應釘選」而正式二進位無實作。

## MAST-NETWORK-003 · 自訂信任評估接受任意憑證

涵蓋自訂 `TrustManager`／`HostnameVerifier`／`URLSessionDelegate` 無條件回傳成功，
以及 WebView 的 SSL 錯誤處理直接 `proceed()`。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| mobsfscan | `accept_self_signed_certificate`（空的 `checkServerTrusted`／接受自簽）；`ignore_ssl_certificate_errors`（WebView 的 `onReceivedSslError` 直接 `proceed()`）；`android_kotlin_webview_ignore_ssl`（Kotlin 版） | ERROR | partial | 規則原始碼：`mobsfscan/rules/semgrep/{java/network/accept_self_signed.yaml,java/webview/webview_ignore_ssl_errors.yaml,kotlin/webview.yaml}` |
| MobSF | 靜態報告的 "Insecure TrustManager" / "WebView ignores SSL errors" | High | partial | 同上 |
| Android Lint | `TrustAllX509TrustManager`、`BadHostnameVerifier` | Warning | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（官方規則庫的行動端部分無對應規則） | — | unverified | — |

**這一則與 `MAST-NETWORK-002`（憑證釘選）的分界要講清楚：**
本則管的是「連基本的鏈驗證都放棄」，那是更嚴重、更常見的錯；
釘選是在鏈驗證之上再加一層。**沒做釘選是缺防護，接受任意憑證是沒有防護。**

### 壞味道

```kotlin
// 空的 TrustManager——任何憑證都通過
val trustAll = object : X509TrustManager {
    override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
    override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}   // 什麼都不做
    override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
}
val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustAll), SecureRandom()) }

// 主機名驗證形同虛設
val client = OkHttpClient.Builder()
    .sslSocketFactory(ctx.socketFactory, trustAll)
    .hostnameVerifier { _, _ -> true }
    .build()

// WebView 忽略 SSL 錯誤
webView.webViewClient = object : WebViewClient() {
    override fun onReceivedSslError(v: WebView, h: SslErrorHandler, e: SslError) {
        h.proceed()      // ignore_ssl_certificate_errors
    }
}
```

```swift
// URLSession delegate 無條件信任
func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
) {
    let trust = challenge.protectionSpace.serverTrust!
    completionHandler(.useCredential, URLCredential(trust: trust))   // 未做任何評估
}
```

### 過關寫法

**最好的過關寫法是完全不實作 delegate。** 系統預設的鏈驗證已經是對的——
自己寫只會寫錯。掃描器認的也是「沒有可疑的自訂實作」。

```kotlin
// 什麼都不覆寫：使用系統信任鏈
val client = OkHttpClient.Builder().build()

// 確實需要內部 CA 時，把它加進信任庫，而不是關掉驗證
fun clientWithInternalCa(context: Context): OkHttpClient {
    val cf = CertificateFactory.getInstance("X.509")
    val ca = context.resources.openRawResource(R.raw.internal_ca).use { cf.generateCertificate(it) }
    val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
        load(null, null); setCertificateEntry("internal", ca)
    }
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        .apply { init(ks) }
    val ctx = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
    return OkHttpClient.Builder()
        .sslSocketFactory(ctx.socketFactory, tmf.trustManagers[0] as X509TrustManager)
        .build()
}
```

```swift
// 不實作 didReceive challenge：系統會做完整的鏈驗證與主機名比對
let session = URLSession(configuration: .default)

// 必須自訂時，先跑系統評估，失敗就取消——不可 fallback 成信任
func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let trust = challenge.protectionSpace.serverTrust else {
        completionHandler(.performDefaultHandling, nil); return
    }
    var error: CFError?
    guard SecTrustEvaluateWithError(trust, &error) else {
        completionHandler(.cancelAuthenticationChallenge, nil)   // 失敗就斷線
        return
    }
    completionHandler(.useCredential, URLCredential(trust: trust))
}
```

Android 側更省事的做法是**用 `network_security_config.xml` 加內部 CA**，
完全不碰程式碼——見 `MAST-NETWORK-001` 的設定檔範例。

### 常見誤判與處置

- **開發環境用自簽憑證**——本機沒有正式憑證，開發時關掉驗證，
  程式碼一路帶進正式庫。**這是行動端紅字最常見的來源。**
  處置：**不是誤判，是真漏洞。** 改用 `network_security_config.xml` 的
  `debug-overrides`（只在 debug 建置生效），或把自簽 CA 加進信任庫。
  用旗標切換一樣會被標——工具無法證明該旗標在正式版為 false。

- **憑證釘選的自訂實作**——為了比對指紋而實作了 delegate。
  處置：標記誤判，佐證需寫明**失敗路徑會取消連線**的行號。
  若任一路徑會 fallback 成信任，就是真漏洞。

### 判定準則

真漏洞：正式程式碼路徑存在空的 `checkServerTrusted`、
永遠回 true 的 `HostnameVerifier`、或無條件 `.useCredential` 的 delegate。

真漏洞：WebView 的 `onReceivedSslError` 呼叫 `proceed()`。

真漏洞：上述行為由旗標或環境變數控制——工具無法證明正式環境的取值。

誤判：自訂實作僅為憑證釘選，且所有失敗路徑都取消連線，有行號佐證。

## MAST-NETWORK-004 · 連線網域未宣告或與宣告不符

涵蓋 App 實際連線的網域超出送檢時宣告的清單，以及未使用平台的網域設定機制
（`network_security_config.xml` 的 `domain-config`、ATS 的 `NSExceptionDomains`）
限縮連線範圍。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | 靜態報告會列出反編譯後找到的所有 URL 與網域（"URLs" 區段），**但不比對宣告清單** | Info | unverified | — |
| mobsfscan | —（無對應規則） | — | unverified | — |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（無對應規則） | — | unverified | — |

**這一則本質上是「比對兩份清單」**：MobSF 抽出的網域 vs 送檢調查表宣告的網域。
沒有工具會自動做這件事——檢測實驗室以動態流量側錄比對。
本知識庫能提供的是**讓清單可被驗證的寫法**。

### 壞味道

```xml
<!-- AndroidManifest.xml：未指定 networkSecurityConfig，連線範圍無任何限制 -->
<application android:name=".App">
</application>
```

```plist
<!-- Info.plist：未使用 NSExceptionDomains，無從得知預期連線範圍 -->
```

第三方 SDK 是這一則最常見的破口——分析、廣告、崩潰回報 SDK
會連到未宣告的網域，而那些連線不出現在自家程式碼裡。

### 過關寫法

把預期連線的網域**明確寫進設定檔**，讓宣告清單與實作一致且可被稽核：

```xml
<!-- res/xml/network_security_config.xml
     逐一列出正式網域；未列出者仍走 base-config 的預設規則 -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>

    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
        <domain includeSubdomains="false">cdn.example.com</domain>
    </domain-config>
</network-security-config>
```

```plist
<!-- Info.plist：僅在確有必要時列出例外網域，並保留 TLS 下限。
     整段不出現代表全面套用 ATS 預設，那是最乾淨的宣告 -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy.partner.com</key>
        <dict>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
        </dict>
    </dict>
</dict>
```

**送檢前自己先做一次比對**：用 MobSF 或 `strings` 抽出 APK／IPA 內的網域，
與調查表宣告的清單逐一核對。第三方 SDK 帶進來的網域也要列——
實驗室的動態測試會看到它們。

### 常見誤判與處置

- **CDN 或雲端服務使用大量子網域**——列不完。
  處置：用 `includeSubdomains="true"` 涵蓋，並在調查表宣告母網域與用途。

- **第三方 SDK 的網域無法事先窮舉。**
  處置：這是真實限制。處理方式是在調查表列出所使用的 SDK 及其官方文件所載的
  連線網域，並說明無法窮舉的原因——**不要略過不提**，動態測試一定會發現。

### 判定準則

真漏洞：實際連線的網域未出現在送檢宣告清單中。

真漏洞：完全未使用平台的網域設定機制，導致預期連線範圍無從驗證。

誤判：差異來自 CDN 的子網域，且母網域已宣告並使用 `includeSubdomains`。
