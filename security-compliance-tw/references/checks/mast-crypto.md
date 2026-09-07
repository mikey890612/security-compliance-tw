# MAST：密碼學誤用

密碼學誤用是行動端掃描器**最容易大量產紅字、也最容易一次修完**的類別。
多數規則不做資料流分析，只做 API 比對——看到 `MessageDigest.getInstance("MD5")`、
`Insecure.MD5`、`"AES/ECB/PKCS5Padding"` 就報，不管你拿去做什麼。
「用途無關安全」這種辯解在工具面前無效，**改寫比寫誤判說明快**。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

**「掃描器怎麼標」只收可查證的工具**：MobSF／mobsfscan、Android Lint、
detekt、SwiftLint、Semgrep——規則 id 逐一與官方原始碼或規則清單核對過。

## MAST-CRYPTO-001 · 弱密碼學／硬編碼密鑰

涵蓋 MD5／SHA-1、DES／3DES／RC4、AES-ECB、固定 IV／nonce，
以及把對稱金鑰、HMAC 密鑰、憑證私鑰寫死在原始碼或資源檔。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | 靜態報告的 "Weak Hash"／"Insecure Encryption" 區段（內嵌上列 mobsfscan 規則） | High–Warning | partial | 同上（本次僅驗證 mobsfscan 規則本身，未跑完整 MobSF） |
| mobsfscan | Android：`android_kotlin_md5`（`MessageDigest.getInstance("MD5")`）／`cbc_kotlin_padding_oracle`（`AES/CBC/PKCS5Padding`）。iOS：`ios_weak_hash`（`CC_MD5`／`CC_SHA1`） | ERROR–WARNING | verified | `testdata/scan-artifacts/open-source/20260907T001858Z/semgrep-mobsfscan-android.json#rule=android_kotlin_md5`（AuthManager.kt:38、:49）；`testdata/scan-artifacts/open-source/20260907T001858Z/semgrep-mobsfscan-ios.json#rule=ios_weak_hash`（AuthManager.swift:27）（另見 `references/scanner-verification-log.md`） |
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

## MAST-CRYPTO-002 · 不安全的亂數來源

涵蓋交談識別碼、權杖、OTP、加密的 IV／nonce／salt 由非密碼學安全的
亂數產生器產出。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| mobsfscan | `android_kotlin_insecure_random`（Kotlin，比對 `Random()`／`java.util.Random(...)`）／`java_insecure_random`（Java）；`ios_insecure_random_no_generator`（Swift） | WARNING | verified | `testdata/scan-artifacts/open-source/20260907T001858Z/semgrep-mobsfscan-android.json#rule=android_kotlin_insecure_random`（AuthManager.kt:43、:45）；`testdata/scan-artifacts/open-source/20260907T001858Z/semgrep-mobsfscan-ios.json#rule=ios_insecure_random_no_generator`（AuthManager.swift:34、:38）（另見 `references/scanner-verification-log.md`） |
| MobSF | 靜態報告的 "App uses an insecure Random Number Generator" | Warning | partial | 同上（MobSF 內嵌 mobsfscan 規則） |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（官方規則庫的行動端部分無對應規則） | — | unverified | — |

規則比對的是**類別與函式名稱**（`java.util.Random`、`arc4random`），
不看輸出用途。因此「這個亂數不用於安全目的」的辯解在工具面前無效——
換掉比寫誤判說明快。

### 壞味道

```kotlin
import java.util.Random

// 交談識別碼可預測——種子空間小，且 Random 是線性同餘
val sessionId = Random().nextLong().toString()

// OTP 同樣可預測
val otp = Random().nextInt(900000) + 100000

// 用時間當種子等於沒有熵
val r = Random(System.currentTimeMillis())
```

```swift
// arc4random 系列雖然比 rand() 好，但 Apple 建議加密用途改用 SecRandomCopyBytes
let otp = Int(arc4random_uniform(900000)) + 100000

// Swift 的 Int.random(in:) 使用 SystemRandomNumberGenerator，
// 對一般用途足夠，但加密材料應明確走 SecRandomCopyBytes
let token = String((0..<32).map { _ in "abcdef0123456789".randomElement()! })
```

### 過關寫法

```kotlin
import java.security.SecureRandom
import android.util.Base64

private val rng = SecureRandom()

// 權杖：直接取足夠長度的隨機位元組
fun newToken(): String {
    val b = ByteArray(32)
    rng.nextBytes(b)
    return Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_WRAP)
}

// 範圍內整數：用 nextInt(bound)，不要自己取模（會有偏差）
fun newOtp(): Int = 100000 + rng.nextInt(900000)

// 加密用的 IV／nonce：每次重新產生，絕不重用
fun newNonce(): ByteArray = ByteArray(12).also { rng.nextBytes(it) }
```

```swift
import Security

// SecRandomCopyBytes 是 iOS 的密碼學安全來源
func randomBytes(_ count: Int) throws -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
        throw CryptoError.randomFailed
    }
    return Data(bytes)
}

func newToken() throws -> String {
    try randomBytes(32).base64EncodedString()
}

// 範圍內整數：用拒絕取樣避免取模偏差
func newOtp() throws -> Int {
    while true {
        let v = try randomBytes(4).withUnsafeBytes { $0.load(as: UInt32.self) }
        if v < 4_294_967_295 - (4_294_967_295 % 900_000) {
            return 100_000 + Int(v % 900_000)
        }
    }
}
```

**交談識別碼最好完全不由用戶端產生**——由伺服器發放，用戶端只負責保存。
那樣這一則自然不適用，也少一個可能出錯的地方。

### 常見誤判與處置

- **亂數用於非安全用途**——動畫抖動、退避重試的 jitter、抽樣、洗牌。
  處置：**改用安全來源比申報誤判省事**，效能差異在行動端可忽略。
  真的在熱路徑上才走誤判流程，佐證需寫明該值不影響任何安全決策、
  且不會出現在對外回應或持久化資料中。

- **UUID 產生函式庫**——`UUID.randomUUID()`（Java）內部使用 `SecureRandom`，
  是安全的；`UUID().uuidString`（Swift）同樣安全。
  處置：標記誤判，佐證註明所用 API 的內部實作。

- **測試碼固定種子以求可重現。**
  處置：把測試檔排除在掃描範圍外。

### 判定準則

真漏洞：非密碼學安全的亂數輸出用於交談識別碼、權杖、密碼重設碼、OTP、
邀請碼，或加密的金鑰／IV／nonce／salt。

真漏洞：使用安全來源但 IV 或 nonce 寫死為常數。

誤判：輸出僅用於效能或體驗，不離開行程邊界，且不參與任何存取控制判斷。

## MAST-CRYPTO-003 · 對稱金鑰或 IV 重複使用

涵蓋跨訊息重用同一組金鑰與 IV／nonce、或 IV 由計數器與時間戳推導。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| mobsfscan | `aes_hardcoded_key`／`android_kotlin_aes_hardcoded_key`（比對寫死的 AES 金鑰字面值） | ERROR | partial | 規則原始碼：`mobsfscan/rules/semgrep/{java/crypto/aes_encryption_keys.yaml,kotlin/crypto.yaml}` |
| MobSF | 靜態報告的 "The App uses hardcoded encryption key" | High | partial | 同上 |
| mobsfscan（IV 重用） | —（**無規則**。IV 是否重用需要跨呼叫的資料流分析，樣式比對做不到） | — | unverified | — |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |

⚠ **金鑰寫死抓得到，IV 重用抓不到。** 後者要看「同一個 IV 變數是否
在多次加密間重複傳入」，那是資料流問題不是樣式問題。
這一則的 IV 部分實務上靠人工審查發現。

### 壞味道

```kotlin
// IV 宣告成常數，每次加密都用同一個——AES-GCM 下這會直接洩漏明文差異
private val IV = ByteArray(12)   // 全零，且從不更換

fun encrypt(data: ByteArray, key: SecretKey): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, IV))
    return cipher.doFinal(data)
}

// 或以遞增計數器當 IV，同樣可預測
private var counter = 0L
fun nextIv(): ByteArray = ByteBuffer.allocate(12).putLong(counter++).array()
```

```swift
import CryptoKit

// 重用同一個 nonce 物件
let fixedNonce = try! AES.GCM.Nonce(data: Data(repeating: 0, count: 12))

func encrypt(_ data: Data, key: SymmetricKey) throws -> Data {
    try AES.GCM.seal(data, using: key, nonce: fixedNonce).combined!
}
```

### 過關寫法

```kotlin
// 每次加密都產生新的 IV，並與密文一起儲存
fun encrypt(data: ByteArray, key: SecretKey): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key)      // 不傳 IV，由 provider 產生
    val iv = cipher.iv                          // 取出後隨密文保存
    val ct = cipher.doFinal(data)
    return iv + ct                              // 前 12 bytes 是 IV
}

fun decrypt(blob: ByteArray, key: SecretKey): ByteArray {
    val iv = blob.copyOfRange(0, 12)
    val ct = blob.copyOfRange(12, blob.size)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
    return cipher.doFinal(ct)
}
```

```swift
import CryptoKit

// 省略 nonce 參數時 CryptoKit 會自動產生新的隨機 nonce
func encrypt(_ data: Data, key: SymmetricKey) throws -> Data {
    let sealed = try AES.GCM.seal(data, using: key)
    return sealed.combined!      // combined 已包含 nonce + 密文 + tag
}

func decrypt(_ blob: Data, key: SymmetricKey) throws -> Data {
    let box = try AES.GCM.SealedBox(combined: blob)
    return try AES.GCM.open(box, using: key)
}
```

**最省事的過關方式是不要自己傳 IV**——兩個平台的 API 在省略時
都會產生密碼學安全的隨機 IV，並提供取回的方法。

### 常見誤判與處置

- **金鑰常數其實是 Keystore 的 alias 字串**——變數名為 `AES_KEY` 但值是
  `"user_data_key"` 這種 alias。
  處置：標記誤判，佐證寫明該字串用於 `KeyStore.getEntry()` 的查詢，
  並附金鑰實際產生的行號。**改個變數名（`KEY_ALIAS`）更省事。**

- **測試向量**——加解密單元測試需要固定 IV 才能比對預期輸出。
  處置：把測試檔排除在掃描範圍外。

### 判定準則

真漏洞：同一組金鑰與 IV／nonce 用於加密多筆訊息。

真漏洞：IV 由計數器、時間戳或其他可預測來源推導。

真漏洞：對稱金鑰為程式碼中的字面常數。

誤判：疑似金鑰的常數實為 Keystore／Keychain 的 alias，有查詢行號佐證。
