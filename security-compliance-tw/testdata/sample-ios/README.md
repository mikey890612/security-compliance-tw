# sample-ios

**刻意寫成不安全的 iOS fixture，用於驗證知識庫的掃描器對照。**

⚠ **不要抄這裡的任何程式碼。** 每一段都對應到一則 check 的「壞味道」。
正確寫法看 `references/checks/mast-*.md` 的「過關寫法」。

不是可建置的完整專案——只有掃描器需要讀的檔案。
mobsfscan 掃原始碼而非 IPA，因此不需要能編譯。

## 刻意觸發的 check

| 檔案 | 對應的 check |
|---|---|
| `App/Info.plist` | NETWORK-001（ATS 全域關閉）、PLATFORM-008（用途說明空泛） |
| `App/AuthManager.swift` | STORAGE-001／002／004、CRYPTO-001／002 |
| `App/NetworkClient.swift` | NETWORK-002／003 |
| `App/LoginViewController.swift` | PLATFORM-003（Pasteboard）、PLATFORM-007（鍵盤快取） |
| 全檔缺席 | RESILIENCE-001（無越獄偵測） |

## 假金鑰的寫法限制

**不要寫成像真的金鑰。** 本 fixture 第一版用了 `sk_live_…` 格式，
被 GitHub 的 secret scanning push protection 擋下（判定為 Stripe API Key）。

mobsfscan 的 `android_kotlin_hardcoded` 與 `ios_hardcoded_secret`
**比對的是變數名稱**（`password`／`secret`／`key`／`api_key` 等，
見規則的 `metavariable-regex`），**不看字串值**。
因此值用 `FIXTURE-NOT-A-REAL-KEY-…` 這種明顯是假的即可，規則照樣命中。

變數名稱**不可改**——改了規則就不報，fixture 也就失去驗證作用。
