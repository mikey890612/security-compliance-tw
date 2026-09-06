# MAST：抗逆向與竄改偵測（F 類加測）

這一類與其他 check 有一個根本差異：**其他類別檢查「你做錯了什麼」，
這一類檢查「你少做了什麼」。**

掃描器因此也不同。mobsfscan 的 `best_practices` 規則比對的是**偵測程式碼的樣式**
（`isRooted()`、Cydia 路徑字串…），**找不到才報**——這與一般規則「找到壞味道就報」
的方向相反。看報告時要留意：這類項目的「未命中」是壞事，不是好事。

**這一組全部屬於進階加測（F 類）或參考項目，非必要檢測項目。**
是否送測由送檢單位自行決定；未加測時不應報告本組，否則產生大量不適用雜訊。

⚠ **這一組的可驗證性是全知識庫最低的**，寫作時受三條額外約束：

1. **不點名任何商用加固廠商或 SDK。** 那些會過期、無法查證，且點名等於背書
2. **「過關寫法」只收平台原生機制與官方 API**
3. **偵測本身可被 hook 繞過。** 偵測結果不應作為唯一防線，
   更不應在偵測失敗時只顯示訊息卻繼續執行敏感操作

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

**「掃描器怎麼標」只收可查證的工具**：MobSF／mobsfscan、Android Lint、
detekt、SwiftLint、Semgrep——規則 id 逐一與官方原始碼或規則清單核對過。

## MAST-RESILIENCE-001 · 未偵測作業系統保護層被破解

涵蓋 App 在已 Root 的 Android 或已越獄的 iOS 裝置上照常執行敏感功能，
未偵測、未通知使用者、也未限縮功能。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| mobsfscan | `android_root_detection`（比對 `isRooted()`／`isDeviceRooted()`／`isJailBroken()`／`RootTools.isAccessGiven()`／`contains("test-keys")`，**缺少時報**）；`ios_jailbreak_detect`（比對 Cydia／MobileSubstrate／sshd 等已知路徑字串，同為缺少時報） | INFO | partial | 規則原始碼：`mobsfscan/rules/semgrep/best_practices/{kotlin/root_detection,swift/jailbreak}.yaml` |
| MobSF | 靜態報告的 "This app does not have root detection capabilities" / "does not have Jailbreak detection capabilities" | Info | partial | 同上（MobSF 內嵌 mobsfscan 規則） |
| Android Lint | —（無對應規則；Lint 不檢查執行期環境偵測） | — | unverified | — |
| detekt | —（無對應規則） | — | unverified | — |
| SwiftLint | —（無對應規則；SwiftLint 為風格檢查） | — | unverified | — |
| Semgrep | —（官方規則庫無對應規則） | — | unverified | — |

兩條規則都是**字面樣式比對**。這帶來一個實務後果：
把偵測邏輯抽進自訂函式名或第三方函式庫時，規則會比對不到而報「缺少」，
即使你確實做了偵測——這是本則最常見的誤判來源。

### 壞味道

```kotlin
class PaymentActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 完全沒有環境檢查，Root 裝置上照常跑轉帳流程
        setContentView(R.layout.activity_payment)
        loadWallet()
    }
}
```

```swift
final class PaymentViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        // 未檢查越獄跡象；Cydia／MobileSubstrate 存在也照常載入
        loadWallet()
    }
}
```

只顯示警告卻繼續執行，等同沒做：

```kotlin
if (isRooted()) {
    Toast.makeText(this, "偵測到 Root 環境", Toast.LENGTH_SHORT).show()
}
loadWallet()   // ← 照樣執行
```

### 過關寫法

Android 側優先用 **Play Integrity API**——它把判斷移到 Google 伺服器，
本機被 hook 也改不了裁決結果；本機的檔案／屬性檢查只當輔助訊號。

```kotlin
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest

// 取得 integrity token 後送到自家伺服器解讀，不在用戶端判斷
val manager = IntegrityManagerFactory.create(context)
manager.requestIntegrityToken(
    IntegrityTokenRequest.builder().setNonce(serverNonce).build()
).addOnSuccessListener { response ->
    // 只負責上傳；deviceIntegrity 的裁決由伺服器做，用戶端不得自行放行
    api.submitIntegrityToken(response.token())
}

// 輔助訊號：Build.TAGS 與 su 是否存在。可被繞過，不可作為唯一依據
fun hasRootIndicators(): Boolean {
    if (Build.TAGS?.contains("test-keys") == true) return true
    return listOf("/system/bin/su", "/system/xbin/su", "/sbin/su")
        .any { java.io.File(it).exists() }
}
```

```swift
import DeviceCheck

// App Attest：由 Apple 簽發證明，伺服器端驗證，本機無法偽造
let service = DCAppAttestService.shared
if service.isSupported {
    service.generateKey { keyId, error in
        guard let keyId else { return }
        service.attestKey(keyId, clientDataHash: serverNonceHash) { attestation, _ in
            guard let attestation else { return }
            api.submitAttestation(attestation)   // 裁決同樣在伺服器做
        }
    }
}

// 輔助訊號：已知越獄路徑與沙盒逃逸測試。可被繞過，不可作為唯一依據
func hasJailbreakIndicators() -> Bool {
    let paths = ["/Applications/Cydia.app",
                 "/Library/MobileSubstrate/MobileSubstrate.dylib",
                 "/usr/sbin/sshd", "/etc/apt"]
    if paths.contains(where: { FileManager.default.fileExists(atPath: $0) }) { return true }
    // 沙盒外寫入應失敗；成功代表沙盒已被破壞
    let probe = "/private/jailbreak_probe.txt"
    do {
        try "x".write(toFile: probe, atomically: true, encoding: .utf8)
        try? FileManager.default.removeItem(atPath: probe)
        return true
    } catch { return false }
}
```

**偵測到之後要做什麼比偵測本身重要。** 敏感操作應由伺服器依證明結果決定是否放行；
用戶端只負責蒐集訊號與限縮功能，不做最終裁決——因為用戶端的任何判斷都可被改寫。

### 常見誤判與處置

- **偵測邏輯確實存在，但寫在自訂函式或第三方函式庫裡**——規則比對不到
  `isRooted()` 這類名稱就報「缺少」。
  處置：標記誤判，佐證寫明偵測實作的檔案位置與行號、以及被呼叫的進入點。
  若能無痛改名，**把入口函式命名為 `isDeviceRooted()` 之類的常見名稱更省事**——
  規則立刻不報，也不必逐次說明。

- **App 本身不處理敏感資料**——工具型、無登入、無交易的 App。
  處置：這一組屬 F 類加測，本來就非必要。若未送 F 類檢測，
  整組標「不適用（未加測 F 類）」，不要逐條寫誤判說明。

- **企業內部 App 部署在受管裝置上**——由 MDM 保證裝置合規，App 端不重複偵測。
  處置：標記誤判，佐證附 MDM 的合規政策與條件式存取設定。
  注意這個論點只在裝置確實受管時成立，BYOD 情境不適用。

### 判定準則

真漏洞：App 具備金流、身分鑑別或個資存取功能，且在 Root／越獄裝置上
不做任何偵測與限縮，同時送測 F 類。

真漏洞：有偵測但失敗路徑仍繼續執行敏感操作（只顯示訊息、只寫日誌）。

真漏洞：偵測結果由用戶端自行裁決放行，未經伺服器驗證——
用戶端的布林值可被 hook 改寫，等同沒做。

誤判：偵測確實存在，只是函式命名未落在規則的比對清單內，且有行號佐證。

誤判：未送測 F 類，本組整體不適用。

## MAST-RESILIENCE-002 · 偵錯模式未關閉或未偵測

涵蓋正式建置仍可被除錯器附掛，以及未偵測裝置端已開啟 USB 偵錯。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | manifest 分析的 "Debug Enabled For App"（比對 `android:debuggable="true"`）；iOS 側檢查建置設定是否含除錯符號 | High | partial | MobSF `manifest_analysis.py` 的 manifest 檢查項 |
| Android Lint | `HardcodedDebugMode`（`android:debuggable` 寫死在 manifest 內） | Warning | unverified | — |
| mobsfscan | —（無專屬規則；`android_kotlin_webview_debug` 只管 WebView 的 `setWebContentsDebuggingEnabled`） | — | unverified | — |
| detekt | —（無對應規則） | — | unverified | — |
| Semgrep | —（官方規則庫無 manifest debuggable 規則） | — | unverified | — |

`android:debuggable` 是**設定檔字面比對**，最單純也最無誤判空間的一類——
改一個屬性就過，沒有申報誤判的理由。

### 壞味道

```xml
<!-- AndroidManifest.xml：正式建置仍可被除錯器附掛 -->
<application
    android:name=".App"
    android:debuggable="true">
</application>
```

```gradle
// build.gradle：release 沿用 debug 設定
android {
    buildTypes {
        release {
            debuggable true
            minifyEnabled false
        }
    }
}
```

### 過關寫法

**不要在 manifest 寫 `android:debuggable`。** 讓建置系統依 build type 決定——
Lint 的 `HardcodedDebugMode` 針對的就是「寫死在 manifest」這件事本身。

```xml
<!-- AndroidManifest.xml：整個屬性不出現 -->
<application android:name=".App">
</application>
```

```gradle
// build.gradle：由 build type 決定，release 明確關閉
android {
    buildTypes {
        release {
            debuggable false
            minifyEnabled true
            proguardFiles getDefaultProguardFile("proguard-android-optimize.txt"),
                          "proguard-rules.pro"
        }
        debug {
            debuggable true
        }
    }
}
```

iOS 側對應的是 Release 組態不含 `DEBUG` 旗標、不輸出除錯符號到正式包，
並在 Archive 設定中確認 `ENABLE_TESTABILITY` 為 `NO`。

執行期偵測 USB 偵錯與除錯器附掛（F 類加測項目）：

```kotlin
// USB 偵錯是裝置設定，讀得到但改不了；作為風險訊號而非阻擋條件
fun isUsbDebuggingEnabled(context: Context): Boolean =
    Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1

// 除錯器是否已附掛
fun isDebuggerAttached(): Boolean =
    Debug.isDebuggerConnected() || Debug.waitingForDebugger()
```

### 常見誤判與處置

- **`android:debuggable="true"` 只出現在 debug 專用的 manifest**
  （`src/debug/AndroidManifest.xml`）。
  處置：標記誤判，佐證寫明該檔案路徑與 manifest merger 的合併結果，
  並附 release APK 的實際 manifest 佐證該屬性不存在。

- **掃描的是 debug 建置的 APK**——送錯檔案。
  處置：不是誤判也不是漏洞，重新送測 release 建置。

- **偵測到除錯器就直接結束程式，導致正常的品保測試無法進行。**
  處置：這是設計問題不是掃描問題。偵測結果應回報伺服器並限縮功能，
  而非直接 `exit()`——後者只會擋住自己人，擋不住有心人。

### 判定準則

真漏洞：release 建置的 manifest 或 build type 中 `debuggable` 為 true。

真漏洞：送測 F 類但完全未偵測除錯器附掛與 USB 偵錯狀態。

誤判：`debuggable="true"` 僅存在於 debug 專用 manifest，且有 release 產出佐證。

## MAST-RESILIENCE-003 · 未偵測模擬器或動態分析框架

涵蓋 App 在模擬器、或已注入 Frida／Xposed 等動態分析框架的環境中照常執行。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| mobsfscan | `ios_jailbreak_detect` 的比對字串**含 `frida-server`／`cycript`**，可間接涵蓋部分動態分析工具 | INFO | partial | 規則原始碼：`mobsfscan/rules/semgrep/best_practices/swift/jailbreak.yaml` |
| MobSF | 靜態報告無專屬項目；動態分析模組才會觀察到 | — | unverified | — |
| Android Lint | —（無對應規則） | — | unverified | — |
| detekt | —（無對應規則） | — | unverified | — |
| Semgrep | —（官方規則庫無對應規則） | — | unverified | — |

**這一則的自動化涵蓋率最低。** 除了 iOS 的 Frida 路徑字串之外，
沒有靜態規則檢查模擬器或 hook 框架偵測——實務上由人工審查或動態測試發現。

### 壞味道

```kotlin
// 完全不檢查執行環境，模擬器與注入環境一律照常
class WalletActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        startTransactionFlow()
    }
}
```

```swift
final class WalletViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        // 未檢查除錯器附掛，也未檢查已知注入函式庫
        startTransactionFlow()
    }
}
```

### 過關寫法

```kotlin
// 模擬器訊號：組合多個而非單一判斷，任一項都可被改
fun looksLikeEmulator(): Boolean {
    val signals = listOf(
        Build.FINGERPRINT.startsWith("generic"),
        Build.FINGERPRINT.contains("vbox"),
        Build.MODEL.contains("Emulator"),
        Build.MODEL.contains("Android SDK built for"),
        Build.MANUFACTURER.contains("Genymotion"),
        Build.HARDWARE == "goldfish" || Build.HARDWARE == "ranchu",
        Build.PRODUCT == "sdk" || Build.PRODUCT == "google_sdk",
    )
    return signals.count { it } >= 2   // 單一訊號誤判率高，要求多項同時成立
}

// 已注入的 hook 框架：檢查已載入的函式庫
fun hasInjectedFrameworks(): Boolean =
    java.io.File("/proc/self/maps").readLines().any {
        it.contains("frida") || it.contains("xposed") || it.contains("substrate")
    }
```

```swift
import Darwin

// 除錯器附掛偵測：sysctl 查 P_TRACED
func isDebuggerAttached() -> Bool {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
    guard result == 0 else { return false }
    return (info.kp_proc.p_flag & P_TRACED) != 0
}

// 模擬器：編譯期常數，Release 實機必為 false
func isRunningOnSimulator() -> Bool {
    #if targetEnvironment(simulator)
    return true
    #else
    return false
    #endif
}

// 已注入的動態函式庫
func hasInjectedLibraries() -> Bool {
    for i in 0..<_dyld_image_count() {
        guard let name = _dyld_get_image_name(i) else { continue }
        let path = String(cString: name).lowercased()
        if path.contains("frida") || path.contains("cycript")
            || path.contains("substrate") { return true }
    }
    return false
}
```

⚠ `ptrace(PT_DENY_ATTACH)` 常被建議用來阻擋除錯器附掛，
但它**在 App Store 審查中屬於使用私有 API 的灰色地帶**，且極易被繞過
（在 `ptrace` 呼叫前 hook 即可）。本知識庫不建議把它當作主要手段。

### 常見誤判與處置

- **CI 與自動化測試跑在模擬器上**——偵測邏輯會擋住自己的測試流程。
  處置：不是誤判。用 build type 或建置旗標讓偵測只在 release 生效，
  且該旗標**不可由執行期設定切換**——否則工具會認定該保護不存在。

- **偵測到就結束程式**——同 RESILIENCE-002，只擋得住自己人。
  處置：回報伺服器、限縮功能，不要直接終止。

- **`/proc/self/maps` 在較新的 Android 版本上讀取受限。**
  處置：這是真實限制。改以多重訊號綜合判斷，並在報告中說明該路徑的可用性隨版本變動。

### 判定準則

真漏洞：送測 F 類，且完全未偵測模擬器與動態分析框架。

真漏洞：偵測存在但可由執行期設定關閉。

誤判：未送測 F 類。

誤判：偵測存在但寫在自訂命名的函式中，規則比對不到，且有行號佐證。

## MAST-RESILIENCE-004 · 未驗證安裝包完整性

涵蓋 App 未檢查自身簽章、未驗證資源檔未被替換，重新打包後仍可正常執行。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | 靜態報告會列出簽章資訊與是否 v1/v2/v3 簽章，但**不判斷 App 是否自我驗證** | Info | unverified | — |
| mobsfscan | —（無對應規則） | — | unverified | — |
| Android Lint | —（無對應規則） | — | unverified | — |
| detekt | —（無對應規則） | — | unverified | — |
| Semgrep | —（官方規則庫無對應規則） | — | unverified | — |

**這一則沒有任何靜態規則涵蓋。** 檢測實驗室以人工重新打包測試來驗證，
本知識庫只能提供判定準則與寫法，無法預判掃描器行為。

### 壞味道

```kotlin
// 從不檢查自身簽章；重新簽名打包後照常執行
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        initSdks()
    }
}
```

```swift
final class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ app: UIApplication,
                     didFinishLaunchingWithOptions opts: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // 未驗證 embedded.mobileprovision 或收據，重簽後照常執行
        return true
    }
}
```

### 過關寫法

```kotlin
import android.content.pm.PackageManager
import java.security.MessageDigest

// 比對自身簽章憑證的 SHA-256；預期值不要寫死在同一個模組
fun signatureDigest(context: Context): String? {
    val flag = PackageManager.GET_SIGNING_CERTIFICATES
    val info = context.packageManager.getPackageInfo(context.packageName, flag)
    val signers = info.signingInfo?.apkContentsSigners ?: return null
    val first = signers.firstOrNull() ?: return null
    val sha = MessageDigest.getInstance("SHA-256").digest(first.toByteArray())
    return sha.joinToString("") { "%02x".format(it) }
}

// 裁決交給伺服器：把 digest 連同 Play Integrity token 一起上傳
suspend fun attestToServer(context: Context) {
    api.verifyInstall(
        packageName = context.packageName,
        signatureSha256 = signatureDigest(context),
    )
}
```

```swift
// iOS 的對應機制是 App Attest 與收據驗證，兩者都在伺服器端裁決
import DeviceCheck

func attestInstall(nonceHash: Data) {
    let service = DCAppAttestService.shared
    guard service.isSupported else { return }
    service.generateKey { keyId, _ in
        guard let keyId else { return }
        service.attestKey(keyId, clientDataHash: nonceHash) { attestation, _ in
            guard let attestation else { return }
            api.verifyInstall(attestation: attestation)   // 伺服器驗證
        }
    }
}
```

**把預期簽章值寫死在同一個 APK 內是無效的**——攻擊者重新打包時
連同那個常數一起改掉即可。有意義的做法是把裁決放在伺服器。

### 常見誤判與處置

- **企業內部散布，每次建置簽章不同。**
  處置：改為驗證簽章屬於某個受信任的憑證集合，而非單一固定值；
  或於受管環境中以 MDM 的受管 App 清單取代自我驗證，並附政策佐證。

- **App 不含敏感功能，重新打包無實際獲益。**
  處置：這一則的來源在檢測基準中屬**參考項目**（非必要）。
  未送 F 類時整則標不適用。

### 判定準則

真漏洞：具備金流或身分鑑別功能，且重新簽名打包後可正常執行所有敏感功能。

真漏洞：有驗證但預期值寫死在同一產出物內，重新打包時可一併修改。

誤判：屬參考項目且未送測；或已由受管環境的 App 派送機制取代，並有佐證。

## MAST-RESILIENCE-005 · 未實作程式碼混淆與加殼

涵蓋正式建置未啟用最佳化與符號重命名，反編譯後可直接讀到類別名、方法名與字串常數。

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| MobSF | 靜態報告會列出反編譯後的 Java／Smali 原始碼；**未混淆時類別與方法名清晰可讀**，但無專屬「未混淆」規則 | — | unverified | — |
| Android Lint | —（無對應規則；`minifyEnabled` 屬建置設定） | — | unverified | — |
| mobsfscan | —（無對應規則） | — | unverified | — |
| detekt | —（無對應規則） | — | unverified | — |
| Semgrep | —（無對應規則） | — | unverified | — |

沒有靜態規則直接判定「未混淆」。檢測實驗室以反編譯後的可讀性人工判定。

### 壞味道

```gradle
// build.gradle：release 未啟用 R8，反編譯後與原始碼幾乎等價
android {
    buildTypes {
        release {
            minifyEnabled false
            shrinkResources false
        }
    }
}
```

### 過關寫法

Android 側有官方方案，可查證也穩定：

```gradle
// build.gradle：R8 全模式，同時做縮減、最佳化與符號重命名
android {
    buildTypes {
        release {
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile("proguard-android-optimize.txt"),
                          "proguard-rules.pro"
        }
    }
}
```

```properties
# gradle.properties：啟用 R8 full mode（更積極的最佳化與重命名）
android.enableR8.fullMode=true
```

保留規則要精準——`-keep class **` 這種寬鬆規則等於沒混淆：

```properties
# proguard-rules.pro：只保留反射與序列化真正需要的進入點
-keepclassmembers class com.example.model.** { <fields>; }
-keepattributes Signature,RuntimeVisibleAnnotations
```

⚠ **iOS 側沒有官方混淆方案，本知識庫在此留白。**

Apple 未提供 Swift 的符號混淆工具。可做到的僅有部分縮減：

- Build Settings 的 `Strip Style` 設為 `All Symbols`、
  `Deployment Postprocessing` 於 Release 開啟——移除不必要的符號表
- `SWIFT_REFLECTION_METADATA_LEVEL` 設為 `none`——
  減少反射中繼資料（但會影響依賴 `Mirror` 的程式碼）

**這些只是縮減符號，不等於混淆。** Swift 的型別名稱與方法名在多數情況下
仍可由 binary 還原。完整混淆需第三方方案，**本知識庫不提供廠商建議**——
那類方案會過期、無法查證，且點名等於背書。
需要時請自行評估，並在檢測報告中說明所採方案與其驗證方式。

加殼（檢測基準的參考項目）同理：Android 與 iOS 的加殼皆非平台原生能力，
本知識庫不提供實作建議。

### 常見誤判與處置

- **函式庫模組未混淆，但主程式已混淆。**
  處置：確認 `minifyEnabled` 套用於最終的 application 模組——
  library 模組的混淆設定不會傳遞到最終產出。

- **崩潰堆疊變得無法閱讀。**
  處置：不是誤判也不是不修的理由。保留 `mapping.txt` 並上傳到崩潰回報服務，
  堆疊即可還原。**不要為了看堆疊而關掉混淆。**

- **iOS 被要求提供混淆佐證。**
  處置：如實說明 Swift 無官方混淆方案，列出已採行的符號縮減設定，
  並說明敏感邏輯已移至伺服器端的部分。**不要宣稱已混淆。**

### 判定準則

真漏洞：Android release 建置 `minifyEnabled` 為 false，或保留規則寬鬆到
（如 `-keep class **`）實質未重命名。

真漏洞：宣稱已混淆但反編譯後類別與方法名仍為原始名稱。

誤判：iOS 側因無官方方案而未混淆——**這是平台限制，不是實作缺陷**。
報告中應如實說明並列出已採行的符號縮減設定。

灰色地帶——**依實際風險判斷**：敏感邏輯（金鑰推導、風控規則）留在用戶端
且未混淆。正解不是加強混淆，而是**把該邏輯移到伺服器**——
混淆只提高成本，移走才是消除。
