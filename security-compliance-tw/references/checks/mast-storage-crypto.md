# MAST：本機儲存、密碼學與日誌

行動 App 的敏感資料常落在本機偏好設定、檔案、Keychain／Keystore、以及除錯日誌。
靜態規則多半只做 API 與字串比對——看到 `UserDefaults`、`SharedPreferences`、
硬編碼金鑰、`NSLog`／`Log.d` 就報，不保證能判斷「值是否真的敏感」。
因此過關寫法要以**平台安全儲存 API** 與**明確的遮罩／移除日誌**為主，
比事後寫誤判說明省事。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## MAST-STORE-001 · 不安全本機儲存

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

## MAST-CRYPTO-001 · 弱密碼學／硬編碼密鑰

涵蓋 MD5／SHA-1、DES／3DES／RC4、AES-ECB、固定 IV／nonce，
以及把對稱金鑰、HMAC 密鑰、憑證私鑰寫死在原始碼或資源檔。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | Weak Cryptography／Hardcoded Secrets／Insecure Random 類 | High–Warning | unverified | — |
| mobsfscan | `ios_sha1_collision`／`ios_hardcoded_secret`／Android 弱雜湊與硬編碼 pattern | WARNING | partial | https://github.com/MobSF/mobsfscan |
| Semgrep | `*.security.*.use-of-md5*`／`*.security.audit.hardcoded-*`／mobile crypto 社群規則 | ERROR–WARNING | unverified | — |
| Android Lint | 密碼學相關自訂／Error Prone 規則（視專案組態） | — | unverified | — |
| Xcode／CryptoKit 診斷 | 過時 CommonCrypto API 與硬編碼字串的手動／自訂檢查 | — | unverified | — |

硬編碼金鑰規則幾乎全靠**字面字串＋變數名**（`key`、`secret`、`password`）。
把金鑰藏進 Base64 或拆成兩段常數**躲不過**字串掃描，也不要當成修法。

### 壞味道

```swift
import CommonCrypto
import CryptoKit

// 硬編碼對稱金鑰
let aesKey = "0123456789abcdef0123456789abcdef"

// MD5／SHA-1 當完整性或「加密」
var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
_ = data.withUnsafeBytes { CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }

// AES-ECB 或固定 IV
let iv = Data(repeating: 0, count: 16)
// ... CCCrypt(... kCCOptionECBMode ...)
```

```kotlin
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

const val AES_KEY = "0123456789abcdef" // 硬編碼

val md = MessageDigest.getInstance("MD5")
val digest = md.digest(payload)

val key = SecretKeySpec(AES_KEY.toByteArray(), "AES")
val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
cipher.init(Cipher.ENCRYPT_MODE, key)

// 固定 IV
val iv = ByteArray(16) // 全 0
```

### 過關寫法

兩件事一起做：**演算法換成平台推薦的 AEAD／雜湊**，
**金鑰由 Keychain／Android Keystore 產生或包裹**，不要出現在原始碼。

```swift
import CryptoKit
import Security

// 雜湊：SHA-256 以上；密碼用場景另走 KDF（見後端對應檢查）
let digest = SHA256.hash(data: data)

// 對稱加密：AES-GCM，nonce 每次隨機
let key = SymmetricKey(size: .bits256) // 實務上應由 Keychain 載入，勿每次新建後丟棄
let sealed = try AES.GCM.seal(plaintext, using: key)

// 金鑰材料進 Keychain，應用只持有 key tag
func loadOrCreateKey(tag: String) throws -> SecKey {
    // SecKeyCreateRandomKey + kSecAttrTokenIDSecureEnclave（可行時）
    // 或 SecItemCopyMatching 取出既有金鑰參照
    fatalError("wire to Keychain helper")
}
```

```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

fun getOrCreateAesKey(alias: String): SecretKey {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    ks.getKey(alias, null)?.let { return it as SecretKey }

    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    kg.init(
        KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build(),
    )
    return kg.generateKey()
}

val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, getOrCreateAesKey("app.aes"))
val iv = cipher.iv // 由系統產生，與密文一併保存
```

傳輸層 TLS、憑證釘選不在本則範圍；本則只看**應用自己做的密碼學與金鑰材料**。

### 常見誤判與處置

- **MD5／SHA-1 用於非安全快取鍵**——規則仍報。
  處置：換成 SHA-256 截短或平台非加密雜湊；比寫誤判快。

- **測試用假金鑰寫在 `androidTest`／單元測試**——字串掃描照樣命中正式規則集。
  處置：測試金鑰改由測試專用 Keystore／環境注入；或把測試原始碼排除掃描路徑。

- **金鑰來自遠端設定，但程式裡留了「預設值」字面常數**——這是真漏洞入口。
  處置：拿掉預設字面值；啟動時若無金鑰就失敗，不要靜默退回硬編碼。

- **第三方 SDK 內嵌金鑰**——MobSF 會報在依賴裡。
  處置：升級或更換 SDK；無法改則記錄風險接受並限縮該 SDK 權限與資料範圍。

### 判定準則

真漏洞：MD5／SHA-1／DES／3DES／RC4／AES-ECB（或等價弱模式）
用於保護仍需保密或防篡改的資料。

真漏洞：對稱金鑰、HMAC 密鑰、私鑰材料以字面字串、資源檔或可逆編碼
出現在 App 套件內。

真漏洞：IV／nonce 固定、可預測，或與金鑰一樣寫死在原始碼。

誤判：弱雜湊僅用於非安全快取且輸出不參與存取控制，
且能提出替代實作計畫或已排程替換。

灰色地帶——**一律當真漏洞修**：自製「混淆」當加密、或自寫密碼學協定。

---

## MAST-LOG-001 · 敏感日誌外洩

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
iOS 用 `privacy: .private`／紅acted；Android 用正式版無操作的 logger 或 ProGuard／R8 移除。

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
