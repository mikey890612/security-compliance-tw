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
