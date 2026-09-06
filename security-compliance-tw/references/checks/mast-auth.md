# MAST：身分鑑別與生物辨識閘道

行動端最常見的鑑別缺陷是**把授權判斷留在用戶端**：
本機布林閘道可被 hook 繞過，生物辨識回傳的成功旗標也一樣。
掃描器看得到 `BiometricPrompt`、`LAContext` 這些 API 名稱，
但看不出「失敗路徑有沒有放行」。
因此過關寫法要以**把驗證綁進金鑰存取**與**授權一律在伺服器端**為主。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

**「掃描器怎麼標」只收可查證的工具**：MobSF／mobsfscan、Android Lint、
detekt、SwiftLint、Semgrep——規則 id 逐一與官方原始碼或規則清單核對過。

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

## MAST-AUTH-002 · 生物辨識可略過／無後備閘道

涵蓋生物辨識對話可取消後仍放行、硬體不可用／鎖定時沒有後備政策（裝置密碼或拒絕）、
以及錯誤回呼被忽略導致「略過等於成功」。
本則**不是**重寫 `MAST-AUTH-001`：AUTH 管「只靠客戶端布林閘道」；
本則管**略過路徑、失敗處理與後備閘道是否存在且失敗即關閉**。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | Biometric Bypass／Insecure Authentication 類 | High–Warning | unverified | — |
| mobsfscan | BiometricPrompt／LocalAuthentication 錯誤處理相關 pattern | WARNING | unverified | — |
| Semgrep | 生物辨識 cancel／error 仍放行的社群／自訂規則 | ERROR–WARNING | unverified | — |
| Android Lint | Biometric 自訂規則（視專案組態） | — | unverified | — |
| Xcode | LocalAuthentication 錯誤路徑多依賴程式碼審查 | — | unverified | — |

工具很難區分「取消後回上一頁」與「取消後照樣解鎖」。
過關寫法要讓**成功才解鎖材料**，取消／錯誤／鎖定一律失敗關閉，並在政策上備妥裝置密碼後備或明確拒絕。

### 壞味道

```swift
import LocalAuthentication

func unlockOrSkip() {
    let ctx = LAContext()
    var error: NSError?
    // 裝置不支援或未登錄生物辨識時直接當成功
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
        openVault() // 略過
        return
    }
    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "解鎖") { ok, err in
        // 使用者取消、鎖定、失敗也都開庫
        openVault()
        _ = ok
        _ = err
    }
}
```

```kotlin
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricManager

fun unlockOrSkip(activity: FragmentActivity) {
    val manager = BiometricManager.from(activity)
    if (manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)
        != BiometricManager.BIOMETRIC_SUCCESS
    ) {
        openVault() // 不可用就略過
        return
    }
    val prompt = BiometricPrompt(activity, executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                openVault()
            }
            override fun onAuthenticationError(code: Int, errString: CharSequence) {
                openVault() // 取消／鎖定也當成功
            }
            override fun onAuthenticationFailed() {
                // 忽略連續失敗
            }
        },
    )
    // 無裝置密碼後備，也未綁 CryptoObject
    prompt.authenticate(
        BiometricPrompt.PromptInfo.Builder()
            .setTitle("解鎖")
            .setNegativeButtonText("略過")
            .build(),
    )
}
```

### 過關寫法

三件事：**失敗／取消失敗關閉**；**生物辨識不可用時走明確後備（裝置密碼）或拒絕進入**；
高風險解鎖仍應綁 Keychain access control／`CryptoObject`（與 AUTH 互補，不互相取代）。

```swift
import LocalAuthentication
import Security

enum BioGateError: Error { case canceled, lockedOut, unavailable, failed }

func unlockWithBiometricsOrDevicePasscode() async throws {
    let ctx = LAContext()
    // 允許生物辨識，必要時升級為裝置密碼；不要在 canEvaluate 失敗時直接放行
    let policy = LAPolicy.deviceOwnerAuthentication
    var error: NSError?
    guard ctx.canEvaluatePolicy(policy, error: &error) else {
        throw BioGateError.unavailable
    }
    try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
        ctx.evaluatePolicy(policy, localizedReason: "驗證身分以繼續") { ok, err in
            if ok {
                cont.resume()
            } else {
                cont.resume(throwing: mapLAError(err)) // cancel／lockout → 拋錯，不呼叫 openVault
            }
        }
    }
    // 成功後才讀取以 biometry／userPresence 綁定的 Keychain 項目
    _ = try readTokenBoundToBiometrics(account: "session")
}

func mapLAError(_ err: Error?) -> BioGateError {
    // LAError.userCancel / .biometryLockout / ... → 對應枚舉；預設 .failed
    .failed
}
```

```kotlin
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators

fun unlockWithFallback(activity: FragmentActivity, cipher: javax.crypto.Cipher) {
    val authenticators = Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL
    val can = BiometricManager.from(activity).canAuthenticate(authenticators)
    if (can != BiometricManager.BIOMETRIC_SUCCESS) {
        showBlocked("無法驗證裝置持有者") // 失敗關閉，不略過
        return
    }
    val prompt = BiometricPrompt(activity, executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val crypto = result.cryptoObject?.cipher ?: run {
                    showBlocked("缺少密碼學綁定")
                    return
                }
                openVault(unwrapToken(crypto))
            }
            override fun onAuthenticationError(code: Int, errString: CharSequence) {
                showBlocked(errString.toString()) // 取消／鎖定／錯誤：不放行
            }
            override fun onAuthenticationFailed() {
                // 可提示再試；達上限交由 onAuthenticationError 處理
            }
        },
    )
    prompt.authenticate(
        BiometricPrompt.PromptInfo.Builder()
            .setTitle("確認本人")
            .setAllowedAuthenticators(authenticators) // 系統後備裝置密碼；勿設「略過」負按鈕偷跑
            .build(),
        BiometricPrompt.CryptoObject(cipher),
    )
}
```

後備政策要寫進產品規則：生物辨識鎖定後改裝置密碼；兩者皆不可用就拒絕高風險功能，
而不是靜默進入。

### 常見誤判與處置

- **設定頁預覽 Face ID 動畫，無解鎖資料**——工具仍可能報。
  處置：說明無金鑰、無高風險導航；取消路徑不會進入受保護區。

- **「已做 AUTH-001 的 CryptoObject」但取消仍開頁**——AUTH 過關不等于 BIO 過關。
  處置：**不當誤判**。補失敗關閉與後備政策。

- **無障礙改用裝置 PIN 當唯一因素**——可接受為後備，不可當「按取消繼續」。
  處置：文件化後備是 `DEVICE_CREDENTIAL`／`deviceOwnerAuthentication`，並保留失敗關閉。

- **第三方 SDK 自帶生物辨識**——核對其錯誤回呼是否放行。
  處置：SDK 無法證明失敗關閉就換掉或外包一層閘道。

### 判定準則

真漏洞：生物辨識取消、錯誤、鎖定或硬體不可用時，仍進入受保護功能或視為驗證成功。

真漏洞：政策上無裝置密碼／等效後備，也無「不可用即拒絕」，導致攻擊者可略過生物辨識提示。

真漏洞：高風險解鎖未綁 `CryptoObject`／Keychain access control，且錯誤路徑可放行（與 AUTH 交集時兩則都記，修復要同時滿足）。

誤判：生物辨識僅裝飾 UI，受保護資料與導航在取消／錯誤時不可達，且有文件化後備或拒絕策略。

灰色地帶——**一律當真漏洞修**：負按鈕文案寫「略過／稍後」並在回呼裡呼叫與成功相同的 `openVault`。

## MAST-AUTH-003 · 授權判斷由用戶端執行

涵蓋以本機旗標、回應欄位或畫面顯示與否作為權限控制，
伺服器端未對每個請求重新驗證權限。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | —（**無規則**。授權邏輯正確與否無法由樣式比對判定） | — | unverified | — |
| mobsfscan | —（無對應規則） | — | unverified | — |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（無對應規則） | — | unverified | — |

**這一則沒有任何自動化涵蓋。** 它是行動端最常見的越權來源，
卻完全靠人工審查與動態測試發現——攔截 API 回應、改掉 `isAdmin` 欄位，
看功能是否解鎖。

伺服器端的對應檢查在 `sast-api-authz.md`（`SAST-API-001`～`003`）。
**兩邊要一起看**：用戶端藏起按鈕不是防護，伺服器端擋下請求才是。

### 壞味道

```kotlin
// 用回應欄位決定顯示什麼，且後續操作不再驗證
data class Profile(val userId: String, val role: String)

fun render(profile: Profile) {
    adminPanel.isVisible = profile.role == "admin"   // 改掉回應就解鎖
}

// 更糟：把權限存在本機，之後都讀本機
prefs.edit().putBoolean("is_admin", profile.role == "admin").apply()

fun onDeleteUserClicked(targetId: String) {
    if (prefs.getBoolean("is_admin", false)) {
        api.deleteUser(targetId)     // 伺服器端若不再驗證，任何人都刪得掉
    }
}
```

```swift
// 以本機旗標控制功能入口
final class Session {
    static var isAdmin = false
}

func onDeleteTapped(_ targetId: String) {
    guard Session.isAdmin else { return }
    api.deleteUser(targetId)          // 同樣依賴用戶端判斷
}
```

### 過關寫法

**用戶端的顯示控制是體驗，不是安全。** 兩件事要同時做：

```kotlin
// 1. 用戶端仍可依回應調整畫面——這是體驗，不是防護
adminPanel.isVisible = profile.role == "admin"

// 2. 但每個敏感操作都由伺服器重新驗證，用戶端不做最終裁決
suspend fun deleteUser(targetId: String): Result<Unit> {
    // 不夾帶任何「我是 admin」的參數——權限由伺服器依 token 判定
    val resp = api.deleteUser(targetId)
    return when (resp.code()) {
        204 -> Result.success(Unit)
        403 -> Result.failure(NotAuthorized())   // 伺服器擋下才是真的擋下
        else -> Result.failure(ApiError(resp.code()))
    }
}
```

```swift
// 同樣：畫面依回應調整，操作由伺服器裁決
func deleteUser(_ targetId: String) async throws {
    let (_, response) = try await api.delete("/users/\(targetId)")
    guard let http = response as? HTTPURLResponse else { throw ApiError.malformed }
    switch http.statusCode {
    case 204: return
    case 403: throw ApiError.notAuthorized      // 伺服器端的判定才算數
    default:  throw ApiError.status(http.statusCode)
    }
}
```

三個具體準則：

- **請求中不夾帶權限宣告**——不要送 `role=admin` 或 `isAdmin=true`
  這類參數，權限一律由伺服器依 token 判定
- **物件識別碼不可直接信任**——請求 `/orders/{id}` 時，
  伺服器要驗證該訂單屬於 token 的擁有者（見 `sast-api-authz.md`）
- **用戶端不快取權限決定**——每次操作都以伺服器回應為準

### 常見誤判與處置

- **伺服器端確實有驗證，用戶端只是先過濾以減少無效請求。**
  處置：這是正確設計。標記誤判，佐證需附**伺服器端的授權檢查位置**——
  只說「伺服器有做」而拿不出程式碼位置，稽核不會接受。

- **離線模式必須在本機判斷權限。**
  處置：這是真實限制。記錄為已知風險接受，說明離線可用的功能範圍
  （應限縮為唯讀或本機資料），並確認**恢復連線後會重新驗證**。

### 判定準則

真漏洞：敏感操作僅由用戶端旗標控制，伺服器端未對該請求重新驗證權限。

真漏洞：請求中夾帶權限宣告參數，且伺服器採信該參數。

真漏洞：權限決定被快取於本機，後續操作不再向伺服器確認。

誤判：用戶端過濾僅為體驗優化，伺服器端有對應的授權檢查且有程式碼位置佐證。

## MAST-AUTH-004 · 使用交易資源前未進行身分鑑別

涵蓋付款、轉帳、預授權等交易動作在執行前未要求重新驗證身分，
或僅以既有的登入狀態放行。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | —（**無規則**。交易流程的鑑別時機無法由樣式比對判定） | — | unverified | — |
| mobsfscan | —（無對應規則） | — | unverified | — |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（無對應規則） | — | unverified | — |

同 `MAST-AUTH-003`，這一則靠人工審查與動態測試發現。

### 壞味道

```kotlin
// 登入後就一路放行，轉帳不再確認身分
fun onTransferConfirmed(amount: Long, to: String) {
    api.transfer(amount, to)          // 手機被短暫取用即可轉帳
}
```

```swift
func confirmTransfer(amount: Decimal, to account: String) async throws {
    try await api.transfer(amount: amount, to: account)   // 無二次驗證
}
```

### 過關寫法

交易前的再驗證要**綁定到伺服器可驗證的憑據**，而不是本機的布林值——
這一點與 `MAST-AUTH-002`（生物辨識綁定金鑰）是同一個道理。

```kotlin
// 用 Keystore 中「需使用者驗證才可用」的金鑰對交易內容簽章
val spec = KeyGenParameterSpec.Builder(
    "txn_key", KeyProperties.PURPOSE_SIGN
).setDigests(KeyProperties.DIGEST_SHA256)
 .setUserAuthenticationRequired(true)
 .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
 .build()

// 簽章成功即代表使用者剛通過驗證——伺服器驗簽後才執行交易
suspend fun transfer(amount: Long, to: String, signature: ByteArray) {
    api.transfer(amount, to, signature)   // 伺服器驗章，用戶端不做裁決
}
```

```swift
import LocalAuthentication

// 存取受保護金鑰時系統會要求驗證；取得簽章才代表驗證通過
func signTransaction(_ payload: Data) throws -> Data {
    let context = LAContext()
    context.localizedReason = "確認轉帳"
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: "com.example.txn".data(using: .utf8)!,
        kSecUseAuthenticationContext as String: context,
        kSecReturnRef as String: true,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
          let key = item else { throw TxnError.authFailed }
    // 以該金鑰簽章 payload，送交伺服器驗證
    return try sign(payload, with: key as! SecKey)
}
```

**「驗證通過」不可只是一個布林值。** 布林值可被 hook 改寫；
簽章不行——伺服器驗不過就不執行交易。

### 常見誤判與處置

- **小額交易免驗證是產品設計。**
  處置：這是業務決策不是缺陷。記錄免驗證的金額上限與其依據，
  並確認上限判斷在**伺服器端**執行——放在用戶端等於沒有上限。

- **已在登入時做過多因素驗證。**
  處置：檢測基準要求的是「使用交易資源時」進行鑑別。
  登入時的驗證不等於交易時的驗證——手機在登入後被取用是常見情境。
  除非有 session 短時效等補償控制並附佐證，否則當真漏洞修。

### 判定準則

真漏洞：交易動作僅依既有登入狀態放行，無任何再驗證。

真漏洞：有再驗證但結果為本機布林值，未綁定伺服器可驗證的憑據。

真漏洞：免驗證的金額上限由用戶端判斷。

誤判：免驗證範圍經業務核可、上限在伺服器端強制，且有設定佐證。

## MAST-AUTH-005 · 未提示使用者設定足夠複雜的密碼

涵蓋 App 自建密碼認證但未於設定或變更密碼時檢查強度、
未給出具體提示，以及僅在伺服器端檢查而用戶端無任何回饋。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | —（**無規則**。密碼強度邏輯需語意理解） | — | unverified | — |
| mobsfscan | —（無對應規則） | — | unverified | — |
| Android Lint | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則） | — | unverified | — |
| Semgrep | —（無對應規則） | — | unverified | — |

無自動化涵蓋，靠人工審查與實際操作驗證。

**若 App 的身分鑑別完全委外**（OIDC／SSO／平台登入），本則標不適用——
密碼策略由身分提供者負責。

### 壞味道

```kotlin
// 只檢查非空
fun onRegisterClicked() {
    if (passwordField.text.isEmpty()) { showError("請輸入密碼"); return }
    api.register(email, passwordField.text.toString())
}
```

```swift
func register() {
    guard !password.isEmpty else { return }   // 無強度要求、無提示
    api.register(email: email, password: password)
}
```

### 過關寫法

用戶端給即時回饋，伺服器端做最終強制——**兩邊都要**，
用戶端的檢查可被繞過，但沒有它使用者不知道要改什麼。

```kotlin
data class PasswordCheck(val ok: Boolean, val hints: List<String>)

fun check(pw: String): PasswordCheck {
    val hints = buildList {
        if (pw.length < 12) add("至少 12 個字元")
        if (!pw.any { it.isUpperCase() }) add("需包含大寫英文字母")
        if (!pw.any { it.isLowerCase() }) add("需包含小寫英文字母")
        if (!pw.any { it.isDigit() }) add("需包含數字")
        if (pw.none { !it.isLetterOrDigit() }) add("需包含特殊符號")
    }
    return PasswordCheck(hints.isEmpty(), hints)
}

// 輸入時即時顯示還差什麼，不要等按下送出才報錯
passwordField.doAfterTextChanged {
    val r = check(it.toString())
    hintView.text = r.hints.joinToString("、")
    registerButton.isEnabled = r.ok
}
```

```swift
struct PasswordCheck { let ok: Bool; let hints: [String] }

func check(_ pw: String) -> PasswordCheck {
    var hints: [String] = []
    if pw.count < 12 { hints.append("至少 12 個字元") }
    if pw.rangeOfCharacter(from: .uppercaseLetters) == nil { hints.append("需包含大寫英文字母") }
    if pw.rangeOfCharacter(from: .lowercaseLetters) == nil { hints.append("需包含小寫英文字母") }
    if pw.rangeOfCharacter(from: .decimalDigits) == nil { hints.append("需包含數字") }
    if pw.rangeOfCharacter(from: .punctuationCharacters) == nil,
       pw.rangeOfCharacter(from: .symbols) == nil { hints.append("需包含特殊符號") }
    return PasswordCheck(ok: hints.isEmpty, hints: hints)
}
```

**提示要說「還差什麼」，不要只說「密碼太弱」。** 後者使用者不知道怎麼改，
實務上會導致他們用最低限度的變形（`Password1!`）通過檢查。

更好的做法是**支援密碼管理器**——Android 的 autofill hint、
iOS 的 `textContentType = .newPassword`，讓系統建議強密碼：

```swift
passwordField.textContentType = .newPassword    // 觸發系統的強密碼建議
```

### 常見誤判與處置

- **身分鑑別完全委外**（OIDC／SSO／Sign in with Apple）。
  處置：標不適用，佐證寫明本地無密碼建立流程。

- **密碼規則在伺服器端，用戶端只顯示伺服器回傳的錯誤。**
  處置：這符合安全要求，但**不符合本條「主動提醒」的要求**——
  使用者要送出後才知道。建議補上用戶端即時回饋；
  若不補，記錄為已知差異並說明理由。

### 判定準則

真漏洞：App 自建密碼流程但未檢查長度與字元組合。

真漏洞：有檢查但無任何提示，使用者不知道要求為何。

不適用：身分鑑別完全委外，本地無密碼建立或變更流程。
