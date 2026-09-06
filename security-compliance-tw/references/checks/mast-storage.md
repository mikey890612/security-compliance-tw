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
| mobsfscan | `android_kotlin_logging`／`ios_log` | INFO | partial | https://github.com/MobSF/mobsfscan |
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
| MobSF | Backup／`allowBackup`／Insecure Data Storage 類 | High–Warning | unverified | — |
| mobsfscan | Android backup／iOS 備份與 Keychain 可同步 pattern | WARNING | unverified | — |
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
