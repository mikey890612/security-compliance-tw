# MAST：裝置隱私、備份與生物辨識閘道

行動 App 的敏感畫面與憑證，常經備份、剪貼簿、系統快照、以及「可略過的生物辨識」離開受控範圍。
靜態規則多半只看到 `allowBackup`、`UIPasteboard`、`FLAG_SECURE`、`BiometricPrompt` 這類 API 名稱，
不保證能判斷「值是否敏感」或「失敗路徑是否放行」。
因此過關寫法要以**排除備份／短命剪貼簿／遮罩快照／失敗即關閉並備妥後備政策**為主，
比事後寫誤判說明省事。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。
與 `MAST-AUTH-001` 的邊界：AUTH 管本機布林閘道可繞過；本檔 BIO 管生物辨識可略過、無後備與錯誤處理。

## MAST-BACKUP-001 · 不安全備份／雲端同步外洩

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

```kotlin
// AndroidManifest：允許整包 Auto Backup（含 shared_prefs／內部檔）
// <application android:allowBackup="true" ...>

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

```kotlin
// Manifest：android:allowBackup="false"
// 若必須開備份：android:fullBackupContent="@xml/backup_rules"
// 與 dataExtractionRules 明確 exclude sharedpref/auth、files/creds.json

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

## MAST-CLIP-001 · 剪貼簿外洩敏感資料

涵蓋把權杖、密碼、OTP、完整卡片號或身分證字號寫進系統剪貼簿，
以及未設短命／本機限定就讓其他 App 或鍵盤讀取。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | Clipboard／Sensitive Information 類 | Warning–Info | unverified | — |
| mobsfscan | `UIPasteboard`／`ClipboardManager` 相關 pattern | WARNING–INFO | unverified | — |
| Semgrep | 剪貼簿 sink 與敏感欄位名合流的社群／自訂規則 | ERROR–WARNING | unverified | — |
| Android Lint | Clipboard 自訂規則（視專案組態） | — | unverified | — |
| Xcode | `UIPasteboard` 無預設安全規則；多依賴審查與自訂 | — | unverified | — |

規則幾乎只認 API 呼叫，分不清「複製邀請碼」與「複製 session token」。
預設：**敏感值不要進剪貼簿**；非敏感才允許，並設過期與本機限定。

### 壞味道

```swift
import UIKit

// 權杖／OTP 丟進一般剪貼簿，其他 App 可讀
UIPasteboard.general.string = accessToken
UIPasteboard.general.string = otpCode

// 密碼顯示頁「一鍵複製」且無過期
UIPasteboard.general.string = password

// 自訂 pasteboard 名稱但未設 localOnly／expirationDate
let board = UIPasteboard(name: UIPasteboard.Name("app.secrets"), create: true)!
board.string = refreshToken
```

```kotlin
import android.content.ClipData
import android.content.ClipboardManager

val clipboard = context.getSystemService(ClipboardManager::class.java)

// 權杖寫入主剪貼簿
clipboard.setPrimaryClip(ClipData.newPlainText("token", accessToken))

// OTP／密碼同樣長駐
clipboard.setPrimaryClip(ClipData.newPlainText("otp", otp))
clipboard.setPrimaryClip(ClipData.newPlainText("password", password))

// 複製後未清除，背景 App 輪詢仍讀得到
```

### 過關寫法

原則：**權杖、密碼、長期密鑰絕不進剪貼簿**；使用者明確要求複製的短碼才寫入，
並用本機限定、過期時間，離開畫面時清除。

```swift
import UIKit

func copyShortLivedInviteCode(_ code: String) {
    // 非憑證；仍縮短暴露窗
    let board = UIPasteboard.general
    board.setItems(
        [[UIPasteboard.typeAutomatic: code]],
        options: [
            .localOnly: true,
            .expirationDate: Date().addingTimeInterval(60),
        ],
    )
}

func clearPasteboardIfNeeded() {
    UIPasteboard.general.items = []
}

// 權杖／密碼：提供「顯示」與「手動輸入」，不要提供複製到系統剪貼簿
```

```kotlin
import android.content.ClipData
import android.content.ClipboardManager
import android.os.Build
import android.os.PersistableBundle

fun copyShortLivedInviteCode(context: Context, code: String) {
    val clipboard = context.getSystemService(ClipboardManager::class.java)
    val clip = ClipData.newPlainText("invite", code)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
        clip.description.extras = PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
    }
    clipboard.setPrimaryClip(clip)
    // 短暫後清除；權杖路徑根本不要呼叫這裡
    handler.postDelayed({ clipboard.clearPrimaryClip() }, 60_000)
}

fun neverCopySecrets() {
    // accessToken／password／refresh：UI 不提供「複製」動作
}
```

### 常見誤判與處置

- **複製公開邀請碼／訂單編號**——工具仍可能因 `setPrimaryClip` 報。
  處置：標記誤判並列出字串語意；必要時改用 App 內分享 Sheet，避免系統剪貼簿。

- **「使用者自己按複製」**——若複製的是 session token，仍是真問題。
  處置：**不當誤判**。改短時授權碼或深連結，不要讓長期權杖進剪貼簿。

- **第三方 SDK（客服、鍵盤）讀剪貼簿**——不在你的寫入 sink。
  處置：確認未寫入敏感值；文件化 SDK 行為與最小權限。

- **僅 Debug 複製權杖方便測試**——正式掃描仍命中。
  處置：測試工具走專用 debug 選單且正式建置剔除；不要留在共用程式碼。

### 判定準則

真漏洞：存取權杖、重新整理權杖、密碼、長期 API 金鑰、完整卡片號等
被寫入系統剪貼簿（含具名 pasteboard 但可被其他 App 讀取）。

真漏洞：OTP／驗證碼寫入後無過期、無清除，且可被背景 App 長時間讀取。

誤判：寫入內容可證明為非機密短碼，且已本機限定／短命，正式流程無憑證 sink。

灰色地帶——**一律當真漏洞修**：把「方便貼到網頁登入」當成複製 session token 的理由。

---

## MAST-SCREEN-001 · 截圖／螢幕錄影／背景快照未擋

涵蓋轉帳、持卡、身分證、權杖顯示等敏感畫面未擋系統截圖／錄影，
以及進入背景時未遮罩，導致多工切換器／快照快取露出敏感 UI。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | Screen Recording／Screenshot／FLAG_SECURE 類 | Warning–Info | unverified | — |
| mobsfscan | `FLAG_SECURE`／截圖防護相關 pattern | INFO–WARNING | unverified | — |
| Semgrep | `FLAG_SECURE`／`isSecureTextEntry`／背景遮罩社群規則 | WARNING | unverified | — |
| Android Lint | Window flag 自訂規則（視專案組態） | — | unverified | — |
| Xcode | 背景快照遮罩多依賴審查；無預設強制規則 | — | unverified | — |

靜態工具常「找不到 `FLAG_SECURE` 就報」，不管畫面是否真的敏感。
過關以**敏感 Activity／頁面強制安全旗標＋背景遮罩**為準，不要只在根 Activity 設一次。

### 壞味道

```swift
import UIKit

// 敏感頁（持卡、轉帳確認）無任何防截圖／遮罩
class CardDetailViewController: UIViewController {
    @IBOutlet weak var panLabel: UILabel! // 完整卡號明文
    // 未在 viewWillDisappear／scene 生命週期蓋模糊層
}

// App 進背景仍保留完整敏感畫面上的視窗快照
func sceneWillResignActive(_ scene: UIScene) {
    // 空實作：系統多工快照直接露出餘額與卡號
}

// 密碼欄位未用安全輸入
passwordField.isSecureTextEntry = false
```

```kotlin
// 轉帳／卡片 Activity 未設 FLAG_SECURE
class TransferActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_transfer)
        // window 未加 WindowManager.LayoutParams.FLAG_SECURE
        amountView.text = balance.toString()
    }
}

// 錄影／螢幕分享時仍顯示完整個資
// 背景切換不做遮罩，Recent Apps 縮圖可見

// EditText 密碼未 inputType=textPassword
```

### 過關寫法

敏感頁：**Android 加 `FLAG_SECURE`**（同時抑制截圖與錄影進近期任務縮圖）；
**iOS 在 resign active 蓋遮罩**，並對密碼／CVV 用安全輸入元件。
遮罩要在回前景時再移除，避免閃爍露出。

```swift
import UIKit

final class PrivacyOverlay {
    static var view: UIView?

    static func show(on window: UIWindow?) {
        guard let window, view == nil else { return }
        let blur = UIVisualEffectView(effect: UIBlurEffect(style: .systemMaterial))
        blur.frame = window.bounds
        blur.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        window.addSubview(blur)
        view = blur
    }

    static func hide() {
        view?.removeFromSuperview()
        view = nil
    }
}

func sceneWillResignActive(_ scene: UIScene) {
    PrivacyOverlay.show(on: (scene as? UIWindowScene)?.windows.first)
}

func sceneDidBecomeActive(_ scene: UIScene) {
    PrivacyOverlay.hide()
}

// 密碼／CVV
passwordField.isSecureTextEntry = true
```

```kotlin
import android.view.WindowManager

class TransferActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        setContentView(R.layout.activity_transfer)
    }
}

// 非敏感頁不要全域亂設，以免誤傷合法截圖需求；
// 持卡、轉帳、身分證預覽、顯示一次性權杖的頁面必須設。
```

### 常見誤判與處置

- **行銷／說明頁被規則要求 FLAG_SECURE**——無敏感欄位。
  處置：標記誤判；規則改為只掃描標了 `sensitive` 的 Activity／路由。

- **「系統仍可能被 root／錄影硬體繞過」**——不是不設旗標的理由。
  處置：**不當誤判**。先做平台提供的防護，再談殘餘風險。

- **WebView 內嵌銀行頁**——原生旗標管得到視窗，管不到遠端頁自己的政策。
  處置：敏感流程改原生頁＋FLAG_SECURE；或確認 WebView 所在 Activity 已設。

- **截圖用於客服除錯**——正式版不應在敏感頁開後門。
  處置：除錯建置才關旗標，並用字串／Manifest 合併證明正式版仍開啟。

### 判定準則

真漏洞：顯示完整卡片號、餘額明細、身分證、權杖、密碼的畫面，
未設 `FLAG_SECURE`（Android）或等價防護，且可被系統截圖／錄影／近期任務縮圖取得。

真漏洞：進入背景時敏感 UI 仍清晰出現在多工切換器快照。

誤判：畫面可證明無敏感欄位，或已遮罩／安全旗標且僅在非敏感流程允許截圖。

灰色地帶——**一律當真漏洞修**：只遮 App 圖示層、實際內容層仍可被系統快照——改為蓋住整個視窗。

---

## MAST-BIO-001 · 生物辨識可略過／無後備閘道

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
