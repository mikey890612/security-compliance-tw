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
| mobsfscan | `ios_ats_arbitrary_loads`／Android cleartext／insecure SSL pattern | WARNING–ERROR | unverified | — |
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
| mobsfscan | certificate pin／TrustKit／CertificatePinner 相關 pattern | WARNING | unverified | — |
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
