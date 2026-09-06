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
