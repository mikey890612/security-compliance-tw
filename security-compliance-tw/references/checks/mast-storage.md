# MAST：本機儲存、日誌與系統備份

行動 App 的敏感資料常落在本機偏好設定、檔案、Keychain／Keystore、除錯日誌，
以及**離開裝置的系統備份**。靜態規則多半只做 API 與字串比對——看到
`UserDefaults`、`SharedPreferences`、`NSLog`／`Log.d`、`android:allowBackup`
就報，不保證能判斷「值是否真的敏感」。
因此過關寫法要以**平台安全儲存 API**、**明確的遮罩／移除日誌**、
**明列排除清單的備份規則**為主，比事後寫誤判說明省事。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

**「掃描器怎麼標」只收可查證的工具**：MobSF／mobsfscan、Android Lint、
detekt、SwiftLint、Semgrep——規則 id 逐一與官方原始碼或規則清單核對過。

## MAST-STORAGE-001 · 不安全本機儲存

涵蓋把權杖、密碼、個資或金鑰寫進明文偏好設定、未加密檔案、
可被其他 App／備份讀取的外部儲存，以及未啟用資料保護的本機資料庫。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | Insecure Data Storage／Shared Preferences／External Storage 類 | High–Warning | unverified | — |
| mobsfscan | `android_kotlin_hardcoded`（儲存相關硬編碼常一併命中）／iOS 本機儲存 pattern | WARNING | unverified | — |
| Semgrep | `swift.*`／`kotlin.*`／`java.lang.security.*` 本機儲存相關社群規則 | ERROR–WARNING | unverified | — |
| Android Lint | `WorldReadableFiles`／`WorldWriteableFiles`／`ExportedPreferenceActivity` 等 | Error–Warning | unverified | — |
| Xcode／Clang Static Analyzer | 偏好設定與檔案 API 的手動／自訂規則為主 | — | unverified | — |

多數工具**不會**區分「暫存 UI 狀態」與「存 session token」——
變數名或字串內容踩到敏感關鍵字就報。改寫到 Keychain／Keystore／
EncryptedSharedPreferences 比爭論用途快。

### 壞味道

```swift
// 權杖寫進 UserDefaults（可被備份、越獄後易讀）
UserDefaults.standard.set(accessToken, forKey: "access_token")
UserDefaults.standard.set(password, forKey: "user_password")

// Documents 明文檔，未設完整資料保護
let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("profile.json")
try data.write(to: url) // 預設保護等級不足，且常進 iCloud／iTunes 備份

// SQLite／Core Data 未加密就放身分證號
try db.execute("INSERT INTO members (id_no) VALUES (?)", idNo)
```

```kotlin
// SharedPreferences 明文存放 session／refresh token
val prefs = context.getSharedPreferences("auth", Context.MODE_PRIVATE)
prefs.edit()
    .putString("access_token", token)
    .putString("refresh_token", refresh)
    .apply()

// 外部儲存／媒體目錄明文檔（可被其他 App 或 USB 讀取）
val file = File(context.getExternalFilesDir(null), "session.json")
file.writeText("""{"token":"$token"}""")

// 過時的全域可讀模式（舊版 API 仍可能出現在繼承碼）
@Suppress("DEPRECATION")
context.openFileOutput("creds.txt", Context.MODE_WORLD_READABLE).use {
    it.write(secret.toByteArray())
}
```

### 過關寫法

原則：**敏感值只進平台金鑰庫或加密容器**；一般設定才用偏好設定。
掃描器認得 Keychain／Keystore／`EncryptedSharedPreferences`／
`EncryptedFile` 這類 API 名稱——換成它們之後，多數本機儲存規則就不再命中。

```swift
import Security

func saveToken(_ token: String, account: String) throws {
    let data = Data(token.utf8)
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecValueData as String: data,
    ]
    SecItemDelete(query as CFDictionary)
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw KeychainError.unhandled(status)
    }
}

// 非敏感 UI 狀態才用 UserDefaults
UserDefaults.standard.set(lastTabIndex, forKey: "ui.last_tab")
```

```kotlin
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val prefs = EncryptedSharedPreferences.create(
    context,
    "auth_enc",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
)
prefs.edit()
    .putString("access_token", token)
    .apply()

// 檔案改走內部私有目錄 + EncryptedFile，或根本不要落地
```

iOS 另確認敏感檔啟用完整資料保護（`NSFileProtectionComplete`／
對應 `FileProtectionType.complete`），並在備份排除清單中標出含憑證的容器。
Android 避免 `getExternalStorage*`／媒體公開目錄放憑證；
需要跨行程共享時改用 ContentProvider＋明確權限，不要靠世界可讀檔。

### 常見誤判與處置

- **偏好設定只存布林或主題色**——工具仍可能因同一 `SharedPreferences` 檔名
  與其他敏感鍵一起被報。
  處置：敏感鍵與非敏感鍵**分檔**；非敏感檔標記誤判並列出實際鍵名。

- **「已 root／越獄才讀得到」**——不是可接受的控管。
  處置：**不當誤判**。改 Keychain／Keystore；並假設裝置可能被取證。

- **測試／Debug build 才寫明文**——掃描器不區分 build variant。
  處置：測試也走同一套加密 API，或以 `debug` 原始碼集排除；
  不要用 `if (BuildConfig.DEBUG)` 包一層明文寫入當藉口。

- **WebView／第三方 SDK 自己寫的 cookie 檔**——不在你的 sink 裡，但 MobSF 可能報。
  處置：確認 SDK 版本與設定；能關本地持久化就關，否則在誤判說明附 SDK 文件。

### 判定準則

真漏洞：存取權杖、重新整理權杖、密碼、API 金鑰、身分證字號、
金融帳號等，以明文寫入 UserDefaults／SharedPreferences、
外部儲存、世界可讀檔、或未加密資料庫。

真漏洞：敏感檔未啟用平台資料保護／加密，且會進入裝置備份。

誤判：寫入內容可證明為非機密（UI 狀態、公開設定），
且同一容器內沒有夾帶憑證欄位。

灰色地帶——**一律當真漏洞修**：欄位名稱像 `token`／`secret`／`session`，
但開發者聲稱「只是追蹤 ID」——先改名與分檔，再談誤判。

---

## MAST-STORAGE-002 · 敏感日誌外洩

涵蓋把權杖、密碼、個資、完整請求／回應本體寫進 `print`／`NSLog`／`os_log`、
`Log.*`、`System.out`，以及第三方崩潰／分析 SDK 的麵包屑日誌。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | Logging／Sensitive Information in Logs 類 | Warning–Info | unverified | — |
| mobsfscan | `android_kotlin_logging`（比對 `Log.$M(...)`／`System.out.print*`）；`ios_log`（比對 `print`／`NSLog`） | INFO | verified | `testdata/scan-artifacts/open-source/20260907T001858Z/semgrep-mobsfscan-android.json#rule=android_kotlin_logging`（AuthManager.kt:33、:61）；`testdata/scan-artifacts/open-source/20260907T001858Z/semgrep-mobsfscan-ios.json#rule=ios_log`（AuthManager.swift:19）（另見 `references/scanner-verification-log.md`） |
| Semgrep | 敏感欄位名流入 log sink 的社群／自訂規則 | ERROR–WARNING | unverified | — |
| Android Lint | `LogNotTimber`／自訂禁止 `Log.d` 規則（視組態） | Warning | unverified | — |
| Xcode | 對 `print`／`NSLog` 無預設安全規則；多依賴自訂與程式碼審查 | — | unverified | — |

mobsfscan 的 logging 規則常常是「有呼叫就報」，等級偏低，
但稽核仍會要求說明**正式建置是否仍編譯進這些呼叫**。
不要因為等級是 INFO 就忽略。

### 壞味道

```swift
print("login ok, token=\(accessToken)")
NSLog("password=%@", password)
os_log("auth header %{public}@", "\(authHeader)") // public 會完整落盤

#if DEBUG
Logger.auth.debug("body: \(responseBody, privacy: .public)")
#endif
// 若 DEBUG 旗標在正式 pipeline 被誤開，等於沒有保護
```

```kotlin
Log.d("Auth", "token=$accessToken")
Log.i("Login", "password=$password")
System.out.println("Authorization: $header")

// 整包物件／JSON 直接印
Log.e("API", response.toString()) // 含身分證、卡片末四碼以外欄位

Timber.d("member=%s", member) // 若未裝 redact tree，正式版照印
```

### 過關寫法

正式建置：**拿掉或編譯期剔除**含敏感欄位的日誌；
必須保留的稽核事件只記內部使用者代碼與事件類型，並對字串做遮罩。
iOS 用 `privacy: .private`／`redacted`；Android 用正式版無操作的 logger 或 ProGuard／R8 移除。

```swift
import os

private let logger = Logger(subsystem: "tw.example.app", category: "auth")

func onLoginSuccess(userId: String, token: String) {
    // 不記 token；userId 為內部代碼
    logger.info("login success user=\(userId, privacy: .private)")
}

func logIdNumber(_ idNo: String) {
    let masked = "****" + idNo.suffix(3)
    logger.info("id_no=\(masked, privacy: .private)")
}
```

```kotlin
object AppLog {
    // 正式建置改為 no-op，或接可 redact 的後端
    inline fun d(tag: String, message: () -> String) {
        if (BuildConfig.DEBUG) {
            Log.d(tag, message())
        }
    }
}

fun onLoginSuccess(internalUserId: String, token: String) {
    // 絕不把 token 傳進 lambda
    AppLog.d("Auth") { "login success user=$internalUserId" }
}

fun maskTail(value: String, keep: Int = 3): String =
    if (value.length <= keep) "****" else "****" + value.takeLast(keep)

// 崩潰／分析 SDK：關閉麵包屑附帶的網路本體，或自訂 before-send 過濾
```

另外確認 CI 的 release 組態：`BuildConfig.DEBUG == false`、
Swift 的 `-O`／無 `-D DEBUG`，避免「只有本機正式包才關日誌」。

### 常見誤判與處置

- **規則只因呼叫 `Log.d`／`print` 就報，訊息是常數**——
  處置：標記誤判並附上行內字串；同時考慮正式版改 no-op，減少雜訊。

- **「只在 DEBUG 印」但字面量仍在 release 二進位**——
  R8／編譯器不一定剝乾淨。
  處置：用 `BuildConfig`／自訂 logger 包一層，並用字串掃描抽樣正式 APK／IPA。

- **第三方 SDK 的 verbose log**——MobSF 常報在依賴碼。
  處置：調 SDK log level；文件允許就關閉；否則誤判說明附版本與設定項。

- **為了除錯暫時打開、打算之後刪**——掃描當下仍是真問題。
  處置：**不當誤判**，先刪或改遮罩再過門禁。

### 判定準則

真漏洞：密碼、權杖、Cookie、Authorization 標頭、身分證字號、
完整卡片號碼、健康資料等，以明文出現在裝置日誌、崩潰報告或分析麵包屑。

真漏洞：以 `toString()`／完整 JSON 印出含上述欄位的物件。

誤判：日誌內容為編譯期常數，或已不可逆遮罩且僅保留必要末碼，
且正式建置可證明無額外敏感 sink。

灰色地帶——**一律當真漏洞修**：`User-Agent`、推播 device token、
精確定位座標是否該記——預設不記，需要時再做最小化與遮罩。

## MAST-STORAGE-003 · 不安全備份／雲端同步外洩

涵蓋 Android `allowBackup`／Auto Backup 未排除憑證容器、iOS 未把敏感檔標為排除備份，
以及把權杖、金鑰材料無差別同步進 iCloud／雲端硬碟的寫法。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | 靜態報告的 "Application Data can be Backed up"（內嵌上列規則） | High–Warning | partial | 同上 |
| mobsfscan | `android_manifest_allow_backup`（比對 `android:allowBackup="true"`，走 manifest 分析非 semgrep）。iOS 側無對應規則 | WARNING | verified | `testdata/scan-artifacts/open-source/20260907T001858Z/mobsfscan-android.json#rule=android_manifest_allow_backup`（AndroidManifest.xml）（另見 `references/scanner-verification-log.md`） |
| Semgrep | `android.*allowBackup*`／iOS backup／CloudKit 社群規則 | ERROR–WARNING | unverified | — |
| Android Lint | Manifest／backup 相關自訂規則（視專案組態） | Warning | unverified | — |
| Xcode | 備份排除與 Keychain accessible 屬性多依賴程式碼審查 | — | unverified | — |

多數工具只看到 Manifest 旗標或 API 名稱，不會讀 `fullBackupContent`／
`dataExtractionRules` 的實際排除清單。過關要讓敏感容器**明確不進備份**，
而不是只把 `allowBackup` 關掉卻仍用可同步的 Keychain／Documents。

### 壞味道

```swift
// Documents 明文檔，預設會進 iCloud／裝置備份
let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("session.json")
try tokenData.write(to: url) // 未設 isExcludedFromBackup、亦無完整資料保護

// Keychain 可被同步／備份的 accessible（跨裝置外洩面）
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "refresh",
    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock, // 可進備份／同步路徑
    kSecValueData as String: refreshToken,
]
SecItemAdd(query as CFDictionary, nil)

// 敏感設定直接丟進 NSUbiquitousKeyValueStore
NSUbiquitousKeyValueStore.default.set(accessToken, forKey: "access_token")
```

```xml
<!-- AndroidManifest.xml：允許整包 Auto Backup（含 shared_prefs／內部檔） -->
<application
    android:allowBackup="true"
    android:fullBackupContent="true">
    <!-- 未提供 dataExtractionRules 排除清單，權杖與憑證一併上雲 -->
</application>
```

```kotlin
val prefs = context.getSharedPreferences("auth", Context.MODE_PRIVATE)
prefs.edit().putString("access_token", token).apply() // 會進雲端備份

// 未提供 fullBackupContent／dataExtractionRules 排除清單
// 或把權杖寫進可被備份的檔案
val file = File(context.filesDir, "creds.json")
file.writeText("{\"token\":\"$token\"}")

// 自行接到雲端硬碟／Drive API 上傳含憑證的匯出檔
drive.upload("backup.zip", zipWithSecrets)
```

### 過關寫法

原則：**憑證與金鑰只進不可備份／本機限定的容器**；一般設定才允許進系統備份。
Android 關掉不必要的 `allowBackup`，或用排除規則明確剔除 auth 檔；
iOS 對敏感檔設 `isExcludedFromBackup`，Keychain 用 `ThisDeviceOnly` 系屬性。

```swift
import Security

func saveRefreshToken(_ token: Data) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "refresh",
        // 本機限定，不進 iCloud Keychain／裝置備份同步
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecValueData as String: token,
    ]
    SecItemDelete(query as CFDictionary)
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainError.unhandled(status) }
}

func writeLocalOnlySecret(_ data: Data, name: String) throws {
    let url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent(name)
    try data.write(to: url, options: [.completeFileProtectionUntilFirstUserAuthentication])
    var resourceValues = URLResourceValues()
    resourceValues.isExcludedFromBackup = true
    var mutableURL = url
    try mutableURL.setResourceValues(resourceValues)
}
```

```xml
<!-- AndroidManifest.xml：預設關閉備份 -->
<application
    android:allowBackup="false"
    android:dataExtractionRules="@xml/data_extraction_rules">
</application>
```

```xml
<!-- res/xml/data_extraction_rules.xml（Android 12+）
     必須開備份時，明確排除憑證與權杖 -->
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="auth_enc.xml" />
        <exclude domain="file" path="creds.json" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="auth_enc.xml" />
        <exclude domain="file" path="creds.json" />
    </device-transfer>
</data-extraction-rules>
```

Android 11 以下另需 `android:fullBackupContent="@xml/backup_rules"`，
`backup_rules.xml` 用 `<exclude>` 列出同一組路徑——兩者要同時維護，
只設其中一個會在另一個 API 級別失效。

```kotlin
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()
val prefs = EncryptedSharedPreferences.create(
    context,
    "auth_enc", // 並在 backup_rules 中 exclude
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
)
prefs.edit().putString("access_token", token).apply()

// 不要把權杖打包進使用者可觸發的「雲端備份／匯出」流程
```

另確認第三方 SDK 的本地快取是否標了可備份路徑；能關本地持久化就關。

### 常見誤判與處置

- **`allowBackup=true` 但已用 EncryptedSharedPreferences**——加密降低風險，備份檔仍可能被同一使用者／取證環境還原。
  處置：敏感容器仍應列入排除；或關閉整包備份。

- **「只備份非敏感 UI 狀態」卻與 token 同檔**——規則仍報整檔。
  處置：敏感與非敏感**分檔**；排除清單寫明確路徑。

- **Debug／內部建置才開備份**——掃描器不區分 variant。
  處置：正式 Manifest 合併結果必須可證明關閉或已排除；不要靠口頭「內部才開」。

- **iCloud Drive 使用者手動上傳**——非 App 自動同步。
  處置：若 App 未提供匯出含密檔的按鈕，可標誤判；有「一鍵備份到雲端」就要修。

### 判定準則

真漏洞：存取權杖、重新整理權杖、密碼、金鑰材料會進入裝置 Auto Backup、
iTunes／Finder 備份、iCloud Keychain 同步，或 App 自動上傳的雲端備份包。

真漏洞：`allowBackup=true`（或等價）且未排除含憑證的 preferences／檔案容器。

誤判：備份範圍可證明僅含非機密 UI 狀態，且與憑證容器分檔並已排除。

灰色地帶——**一律當真漏洞修**：欄位名像 `token`／`secret` 卻聲稱「可進雲端」——先排除與改儲存，再談誤判。

---

## MAST-STORAGE-004 · 敏感性資料硬編碼於程式碼或資源檔

涵蓋 API 金鑰、密碼、對稱加密金鑰、憑證私鑰直接寫在原始碼、`strings.xml`、
`Info.plist`、`.xcconfig` 或 `gradle.properties` 內。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| mobsfscan | `android_kotlin_hardcoded`（Kotlin 常數）；`hardcoded_api_key`／`hardcoded_password`／`hardcoded_secret`／`hardcoded_username`（Java）；`ios_hardcoded_secret`（Swift）；`aes_hardcoded_key`／`android_kotlin_aes_hardcoded_key`（寫死的 AES 金鑰） | WARNING–ERROR | verified | `testdata/scan-artifacts/open-source/20260907T001858Z/semgrep-mobsfscan-android.json#rule=android_kotlin_hardcoded`（AuthManager.kt:19）；`testdata/scan-artifacts/open-source/20260907T001858Z/semgrep-mobsfscan-ios.json#rule=ios_hardcoded_secret`（AuthManager.swift:9）（另見 `references/scanner-verification-log.md`） |
| MobSF | 靜態報告的 "Hardcoded Secrets" 區段；另會列出 `strings.xml` 內疑似金鑰的字串 | High | partial | 同上（MobSF 內嵌 mobsfscan 規則） |
| Semgrep | `generic.secrets.security.detected-generic-secret.detected-generic-secret`（entropy 式，涵蓋任意檔案格式） | ERROR | unverified | — |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |

這一類是**規則最單純、最不可能誤判的一種**——比對的是變數名稱加字串字面值。
包進 `BuildConfig` 或 `Info.plist` 一樣會被抓到，因為那些值最終仍在 APK／IPA 裡。

### 壞味道

```kotlin
object ApiConfig {
    const val API_KEY = "sk-live-4f9a2b8c1d7e"          // android_kotlin_hardcoded
    const val AES_KEY = "0123456789abcdef"              // aes_hardcoded_key
}

// 從 BuildConfig 讀也一樣——值是在建置期塞進 APK 的
val key = BuildConfig.API_SECRET
```

```swift
struct ApiConfig {
    static let apiKey = "sk-live-4f9a2b8c1d7e"          // ios_hardcoded_secret
    static let aesKey = "0123456789abcdef"
}
```

```xml
<!-- res/values/strings.xml：反編譯後直接可讀 -->
<resources>
    <string name="api_key">sk-live-4f9a2b8c1d7e</string>
</resources>
```

### 過關寫法

**唯一可靠的做法是讓金鑰不進到用戶端。** 需要簽章或授權的動作由伺服器代理，
用戶端只拿短期、可撤銷的憑證。

```kotlin
// 用戶端只持有登入後取得的短期 token，存進受保護儲存
class TokenStore(context: Context) {
    private val prefs = EncryptedSharedPreferences.create(
        context, "auth",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
    fun save(token: String) = prefs.edit().putString("access_token", token).apply()
}

// 對稱金鑰由 Keystore 產生，永遠不離開硬體支援的金鑰庫
val spec = KeyGenParameterSpec.Builder(
    "data_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
 .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
 .build()
KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
    init(spec); generateKey()
}
```

```swift
import CryptoKit
import Security

// 金鑰由 Secure Enclave 產生；私鑰無法匯出
let access = SecAccessControlCreateWithFlags(
    nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil)!
let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)

// 短期 token 存 Keychain，不寫進程式碼
func store(token: Data) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "access",
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecValueData as String: token,
    ]
    SecItemDelete(query as CFDictionary)
    guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else {
        throw KeychainError.storeFailed
    }
}
```

### 常見誤判與處置

- **公開的識別碼被當成機密**——Firebase 的 `google-services.json`、
  Google Maps 的 API key、OAuth 的 client id。這些設計上就是公開的。
  處置：標記誤判，佐證寫明該值的公開性質，**並確認伺服器端有配額與來源限制**
  （Maps key 未設限制時仍是真問題，只是問題在配額不在保密）。

- **測試用的假金鑰**——fixture 或單元測試中的 `"test-key-1234"`。
  處置：把測試檔排除在掃描範圍外，或改用明顯是佔位符的值
  （`"REPLACE_ME"`）——規則多半依 entropy 判斷，低 entropy 的字串不會命中。

- **憑證釘選用的公鑰指紋**——那是公開資訊，不是機密。
  處置：標記誤判，佐證寫明該值為公鑰雜湊。

### 判定準則

真漏洞：任何可用於存取後端服務、解密資料或簽署請求的憑材出現在
程式碼、資源檔或建置設定中，無論是否經過編碼或拆分。

真漏洞：對稱加密金鑰為常數，即使拆成多段再組合——反編譯後一樣可還原。

誤判：該值設計上即為公開（公鑰、client id、公開 API 識別碼），
且伺服器端有對應的來源或配額限制作為佐證。

## MAST-STORAGE-005 · 敏感性資料殘留於快取、暫存與冗餘檔案

涵蓋登出或關閉後未清除的快取、WebView 快取、崩潰日誌、
以及自動產生的暫存檔中仍含權杖或個資。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | 靜態報告會列出 `getCacheDir`／`NSTemporaryDirectory` 等 API 的使用位置（`api_local_file_io`），但**不判斷是否清除** | Info | unverified | — |
| mobsfscan | —（無專屬規則） | — | unverified | — |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（官方規則庫無對應規則） | — | unverified | — |

**這一則靜態涵蓋率極低。** 檢測實驗室以「登出後拉取裝置檔案系統」的
動態方式驗證。本知識庫提供的是寫法與判定準則，不預判掃描器行為。

### 壞味道

```kotlin
// 登出只清了 token，快取與 WebView 資料原封不動
fun logout() {
    prefs.edit().remove("access_token").apply()
    startActivity(Intent(this, LoginActivity::class.java))
}

// 把回應整包寫進 cache，且從不清除
File(context.cacheDir, "profile.json").writeText(responseBody)
```

```swift
// URLCache 預設會把含個資的回應寫到磁碟
let session = URLSession(configuration: .default)

// 暫存檔寫完不刪
let tmp = NSTemporaryDirectory() + "export.csv"
try csv.write(toFile: tmp, atomically: true, encoding: .utf8)
```

### 過關寫法

```kotlin
fun logout(context: Context) {
    prefs.edit().clear().apply()

    // 應用程式快取與 WebView 快取一併清除
    context.cacheDir.deleteRecursively()
    android.webkit.WebStorage.getInstance().deleteAllData()
    android.webkit.WebView(context).apply {
        clearCache(true); clearHistory(); clearFormData()
    }
    android.webkit.CookieManager.getInstance().removeAllCookies(null)
}

// 敏感回應不進磁碟快取
val client = OkHttpClient.Builder()
    .cache(null)   // 或對敏感端點加 Cache-Control: no-store
    .build()
```

```swift
func logout() {
    // 記憶體與磁碟快取一併清除
    URLCache.shared.removeAllCachedResponses()
    HTTPCookieStorage.shared.cookies?.forEach {
        HTTPCookieStorage.shared.deleteCookie($0)
    }
    try? FileManager.default.contentsOfDirectory(atPath: NSTemporaryDirectory())
        .forEach { try? FileManager.default.removeItem(atPath: NSTemporaryDirectory() + $0) }
}

// 敏感請求走不快取的組態
let config = URLSessionConfiguration.ephemeral   // 不寫磁碟
let session = URLSession(configuration: config)
```

伺服器端對敏感回應加 `Cache-Control: no-store` 是最省事的做法——
兩個平台的 HTTP 快取都會遵守，不必逐處清除。

### 常見誤判與處置

- **快取中只有非敏感的清單資料**——商品列表、公告內容。
  處置：標記誤判，佐證寫明快取內容的欄位清單。注意**登入後的個人化清單通常含個資**，
  不要一律當成非敏感。

- **崩潰回報 SDK 蒐集的堆疊含變數值。**
  處置：這是真問題。設定 SDK 過濾敏感欄位，或關閉區域變數蒐集。

### 判定準則

真漏洞：登出後裝置上仍可讀到權杖、個資或交易內容。

真漏洞：WebView 快取或 Cookie 在登出後未清除。

誤判：殘留內容經逐欄位確認不含敏感性資料，且有欄位清單佐證。

## MAST-STORAGE-006 · 憑證與金鑰未存放於系統憑證儲存設施

涵蓋權杖、私鑰、加密金鑰存在一般檔案或偏好設定，而非 Android Keystore
或 iOS Keychain；以及 Keychain 屬性選得過寬（可同步、可備份）。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | `api_keystore`／`api_keychain_access` 屬 **API 使用清單**（Info 等級），**不判定違規**——它只告訴你有沒有用到，用不用得對要人工看 | Info | partial | 規則原始碼：`mobsfscan/rules/semgrep/{android_apis.yaml,ios_apis.yaml}` |
| mobsfscan | —（無「未使用 Keystore」的專屬規則；缺席無法被樣式比對偵測） | — | unverified | — |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（無對應規則） | — | unverified | — |

**「沒有使用某個 API」這種缺席，樣式比對工具偵測不到。**
掃描器只能看到缺席造成的**症狀**——金鑰出現在明文儲存位置，
那由 `MAST-STORAGE-001` 與 `MAST-STORAGE-004` 涵蓋。

### 壞味道

```kotlin
// 私鑰存成一般檔案
File(context.filesDir, "private.pem").writeText(privateKeyPem)

// 或存進未加密的偏好設定
prefs.edit().putString("signing_key", keyBase64).apply()
```

```swift
// 存進 UserDefaults，等同明文
UserDefaults.standard.set(privateKeyPem, forKey: "signingKey")

// Keychain 屬性過寬：可同步到 iCloud、可進備份
let query: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrAccessible as String: kSecAttrAccessibleAlways,   // 已棄用且過寬
    kSecAttrSynchronizable as String: true,                   // 會同步到其他裝置
    kSecValueData as String: keyData,
]
```

### 過關寫法

```kotlin
// 金鑰在 Keystore 內產生並使用，程式碼從頭到尾拿不到金鑰材料
val spec = KeyGenParameterSpec.Builder(
    "signing_key", KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
).setDigests(KeyProperties.DIGEST_SHA256)
 .setUserAuthenticationRequired(true)     // 綁定裝置解鎖或生物辨識
 .build()

KeyPairGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
).apply { initialize(spec) }.generateKeyPair()

// 使用時取 handle，不取金鑰本身
val entry = java.security.KeyStore.getInstance("AndroidKeyStore")
    .apply { load(null) }
    .getEntry("signing_key", null) as java.security.KeyStore.PrivateKeyEntry
```

```swift
import Security

// 存取控制限定本機、需解鎖；可用時再加生物辨識
let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,   // 不同步、不進備份
    [.privateKeyUsage, .biometryCurrentSet],
    nil
)!

let attrs: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,   // 私鑰不可匯出
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: "com.example.signing".data(using: .utf8)!,
        kSecAttrAccessControl as String: access,
    ],
]
var error: Unmanaged<CFError>?
let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error)
```

`kSecAttrAccessible` 的選擇是這一則最常出錯的地方：
`...ThisDeviceOnly` 系列不會同步到 iCloud Keychain、也不進裝置備份，
非 `ThisDeviceOnly` 的則會——**兩者的差別在檢測時會被實際驗證**。

### 常見誤判與處置

- **金鑰確實在 Keystore／Keychain，但存取的變數名含 `key`**——
  被硬編碼規則誤報。
  處置：標記誤判，佐證寫明金鑰產生與存取的行號，並確認該變數持有的是
  handle 或 alias 而非金鑰材料。

- **需要跨裝置同步的憑證**——例如使用者的加密備份金鑰。
  處置：這是產品決策不是誤判。若確實需要同步，記錄為已知風險接受，
  並說明同步路徑的保護方式。

### 判定準則

真漏洞：私鑰、對稱金鑰或長期權杖存放於一般檔案、`SharedPreferences`
或 `UserDefaults`。

真漏洞：Keychain 項目使用 `kSecAttrAccessibleAlways`
或未加 `ThisDeviceOnly` 而該資料不應離開本機。

誤判：金鑰在 Keystore／Secure Enclave 內產生且不可匯出，
變數僅持有 alias 或 handle，有行號佐證。
