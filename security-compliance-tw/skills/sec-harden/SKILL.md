---
name: sec-harden
description: 在撰寫或修改程式碼時直接套用「掃描器認得的安全寫法」，讓程式碼一開始就不會被 Fortify / Checkmarx / Semgrep / gosec / bandit / AWVS 標紅字。也可把這套規則安裝進當前專案，產出 AGENTS.md、Cursor .mdc、Cline / Windsurf / Copilot 規則檔，讓 Cursor 或任何本機 agent 都能套用。Use when writing or modifying database queries, HTTP handlers, file path handling, subprocess calls, password or key handling, logging, error handling, TLS configuration, or LLM calls — and when the user asks to 安裝安全規則, 設定 coding 規範, 讓 Cursor 也能用, or mentions AGENTS.md / cursor rules for security.
---

# sec-harden

**目標：寫的當下就用過關寫法，不要事後再修。**

預防比事後修便宜——`sec-audit` 是拿來補救的，這支是拿來避免需要補救的。

## 兩個模式

**使用者要求「安裝 / 設定到專案 / 讓 Cursor 也能用」→ 安裝模式。
其餘情況（正在寫程式）→ 直接使用模式。**

---

## 知識庫根目錄（ROOT）（先讀這段）

讀知識庫前，先解析 **ROOT**（plugin 根目錄，其下有 `references/`）：

1. 若環境變數 `SECURITY_COMPLIANCE_TW_ROOT` 已設定 → 用它
2. 否則若存在 `~/.security-compliance-tw/root` → 讀取該檔單行路徑（plugin 絕對路徑）
3. 否則 fallback：相對於本 `SKILL.md` 的 `../..`（仍在 clone／plugin 樹的 `skills/<name>/` 下開發時）

知識庫路徑一律表述為 `{ROOT}/references/…`。用 Read 工具讀**解析後的絕對路徑**（或開發時 fallback 的明確相對路徑）。

**不要用 shell 的 `cd ../..` 導航**——先解析 ROOT 再 Read。`cd` 是邏輯解析，在 symlink 或已安裝的 skill 目錄下會跑錯地方。

要在 shell 操作時，先解析 ROOT 取得絕對路徑，再用絕對路徑操作。

---

## 直接使用模式

讀 `{ROOT}/references/quick-patterns.md`，依當下情境套用對應段落。

段落依情境分：寫資料庫查詢 / 寫 HTTP handler / 處理檔案路徑 / 執行外部命令 /
處理密碼與金鑰 / 寫日誌 / 錯誤處理 / 設定伺服器 / 呼叫 LLM。

**只讀需要的段落。** 要更完整的說明（掃描器規則名稱、誤判處置、判定準則）
再去 `{ROOT}/references/checks/`——但寫程式時通常不需要，速查就夠。

撰寫 **狀態變更表單／伺服端代發 URL／檔案上傳** 時，
`quick-patterns.md` 尚無 CSRF／SSRF／UPLOAD 速查——改讀
`checks/sast-request-abuse.md`（一律；`SAST-CSRF-001`／`SAST-SSRF-001`／`SAST-UPLOAD-001`；勿整份貼進規則檔）。

撰寫 **iOS／Android 原生 App** 或 **EMM／MDM／MAM** 相關程式時，
`quick-patterns.md` 尚無對應速查段落——改讀
`mast-storage.md`、`mast-crypto.md`、`mast-network.md`、`mast-auth.md`、`mast-platform.md`、`mdm-controls.md`
（MDM 含 LOCK／JAIL／PATCH／VPN／MTD；是否載入由 `profile.md` 的
「有行動 App」「有 EMM／MDM／MAM」決定；勿整份貼進規則檔）。

---

## 安裝模式

把 `quick-patterns.md` 的內容產出成各家 agent 的規則檔，寫進**當前專案**。
裝完之後不依賴 Claude Code 在場，Cursor / Cline / Codex 都能用。

### 步驟 1：偵測語言

| 存在的檔案 | 語言 | 產出的 .mdc |
|---|---|---|
| `go.mod` | Go | `sec-harden-go.mdc` |
| `requirements.txt` / `pyproject.toml` / `Pipfile` | Python | `sec-harden-python.mdc` |
| `package.json` | JavaScript / TypeScript | `sec-harden-web.mdc` |
| `*.html` 或 `*.css` 存在**且**無 `package.json` | 純前端 | `sec-harden-web.mdc` |
| `build.gradle` / `build.gradle.kts` / `settings.gradle` | Kotlin / Java（Android） | `sec-harden-android.mdc` |
| `Podfile` / `Package.swift` / `*.xcodeproj` / `*.xcworkspace` | Swift（iOS） | `sec-harden-ios.mdc` |

最後一列處理純靜態網站——它沒有 `package.json`，但 `sec-harden-web.mdc`
的 globs 涵蓋 `.html`，若不列這條，純前端專案會落到「偵測不到」而漏裝。

**只產出用得到的語言。** 沒有 Python 就不要產 `sec-harden-python.mdc`——
少一個常駐檔就少一份 context 開銷。

一種都偵測不到時，詢問使用者，不要全產。

### 步驟 2：確認要寫哪些檔

列出將建立或修改的檔案清單給使用者確認後才動手。清單固定順序：

```
AGENTS.md                              附加區塊
.cursor/rules/sec-harden-<lang>.mdc    每個偵測到的語言一個檔
.clinerules                            附加區塊
.windsurfrules                         附加區塊
.github/copilot-instructions.md        附加區塊
```

使用者可以只挑其中幾項。

**無法取得確認時的預設行為**（非互動執行、subagent、CI 等情境）：
若使用者的要求已明示範圍——例如「讓 Cursor 和其他 agent 也能用」、
「裝到這個專案」——**視為已授權，直接全部產出**，不要因為等不到確認而中止。
步驟 2 的用意是避免動到未預期的檔案，不是設一道非過不可的閘門。
產出後在回報中逐檔列出即可。

### 步驟 3：產出

#### 標記區塊（AGENTS.md / .clinerules / .windsurfrules / copilot-instructions.md）

這四個檔案專案裡可能已有內容。**一律附加，絕不覆蓋。**
用下列標記包住，重跑安裝時只替換區塊內容：

```markdown
<!-- BEGIN sec-harden v0.1.0 — 由 security-compliance-tw 的 quick-patterns.md 產生。
     請勿直接編輯本區塊內容，重跑安裝器即可更新。 -->

## 安全撰寫規範

（此處放 quick-patterns.md 的內容，依偵測到的語言篩選）

<!-- END sec-harden -->
```

已存在同名區塊時：**只替換區塊內部**，區塊外的內容一字不動。
檔案不存在時才建立新檔。

⚠ **用正規表示式替換區塊時，替換字串必須走替換函式。**
規則內容含 `\n`、`\r`、`\x1b` 等字面反斜線（日誌轉義那節），
直接把內容當替換字串會被當成跳脫序列，Python 的 `re.sub` 會拋
`bad escape \x`，其他語言則可能靜默產生錯誤內容。

```python
# ✅ 正確
out = pattern.sub(lambda m: new_block, txt)

# ❌ 會炸
out = pattern.sub(new_block, txt)
```

替換後務必驗證：BEGIN 與 END 各剩一個、區塊外的使用者內容仍在。

#### Cursor 規則檔（`.cursor/rules/sec-harden-<lang>.mdc`）

每個語言一個檔，用 `globs` 自動附加——這是所有目標中唯一精準的觸發機制，
編輯什麼檔就載入什麼規則。

```markdown
---
description: 掃描器認得的安全寫法（Go）。撰寫或修改 Go 程式碼時套用。
globs: **/*.go
alwaysApply: false
---

（此處放 quick-patterns.md 的內容，只保留 Go 的 API 名稱）
```

各語言的 `globs`：

| 語言 | globs |
|---|---|
| Go | `**/*.go` |
| Python | `**/*.py` |
| JS / TS / HTML | `**/*.{js,jsx,ts,tsx,html}` |
| Android | `**/*.{kt,java}` 以及 `**/AndroidManifest.xml`、`**/*.gradle`、`**/*.gradle.kts` |
| iOS | `**/*.{swift,m}` 以及 `**/Info.plist` |

行動端的 globs **必須涵蓋設定檔**。`android:allowBackup`、`NSAllowsArbitraryLoads`
這類屬性正是掃描器比對的目標，而它們不在 `.kt` / `.swift` 裡——
globs 只寫程式碼副檔名，等於規則在最需要的時候不會載入。

Cursor 的檔案是獨立的，不需要標記區塊——直接覆寫整個檔案即可。

### 步驟 4：回報

列出實際寫了哪些檔、每個檔是新建還是更新區塊。

---

## 產出內容的硬性要求

這些規則檔會被 commit 進 git、推上 GitHub 或 Cursor 組織空間，
拿到它們的人不會有這個 plugin。因此：

1. **不得出現任何絕對路徑。**
   不要寫 `/Users/…` 或 `{ROOT}/references/…`——對方的 repo 沒有那些檔案。
   需要指向完整說明時，寫「詳見 security-compliance-tw plugin 的 `references/checks/`」，
   不要寫成可點擊的本機路徑。

2. **不得出現法規或 OWASP 編號。**
   與 `checks/` 相同的約束。規則檔是給人寫程式用的，不是法遵文件。

3. **輸出順序固定**，照 `quick-patterns.md` 的段落順序。
   順序浮動會讓每次重裝都產生整份翻動的 diff。

4. **不要加時間戳記或產生者資訊。**
   同上，會讓 diff 每次都髒。版本號寫在標記區塊裡就夠了。

5. **語言篩選要確實，且兩類檔案的規則不同。**

   | 檔案 | 語言範圍 |
   |---|---|
   | Cursor `.mdc` | **單一語言**。Go 檔不得出現 `subprocess.run`、`helmet`；Python 檔不得出現 `defer`、`filepath.` |
   | 常駐檔（AGENTS.md 等） | **偵測到的全部語言**，未偵測到的一律剔除 |

   常駐檔只有一份，要涵蓋專案實際用到的所有語言；
   Cursor 檔由 globs 決定何時載入，必須嚴格單語言，否則編輯 Go 檔時
   會載入一堆 Python API 名稱，白白佔用 context。

   **未偵測到的語言一律剔除**——沒有 `package.json` 就不該在任何檔案裡
   出現 `innerHTML`、`crypto.randomBytes`、`Math.random()`。

   情境標題一律保留，只換 API 名稱。

6. **控制長度，有具體上限。**
   `quick-patterns.md` 原始長度約 170 行。產出時：

   | 目標 | 上限 | 理由 |
   |---|---|---|
   | `AGENTS.md` / `.clinerules` / `.windsurfrules` / copilot | **100 行** | 常駐，每個 session 都在吃 context |
   | Cursor `.mdc` | **180 行** | 有 globs，只在編輯該語言檔案時載入 |

   **常駐檔一律用緊湊格式，這是預設不是補救**：

   - 每則寫成兩行：`- ✅ …` 與 `- ❌ … — 理由`（理由**併入 ❌ 行**，不另起一行）
   - **規則之間不留空行**，只有情境標題前留一行
   - 多語言專案只保留**偵測到的**語言的 API 名稱，未偵測到的剔除

   照這個格式寫，單語言約 75 行、雙語言約 92 行，都在 100 行內。
   把緊湊格式當成「超標後才用的補救手段」會導致第一版就超標——
   原始的 `quick-patterns.md` 格式（三行一則、規則間有空行）**不適合常駐檔**。

   仍超標時，依序處理：

   1. **未使用的情境段落**——例如專案無 AI 功能時的「呼叫 LLM 時」：
      **保留標題，內容換成一行指向說明**，例如
      `（本專案無 LLM 相依，完整內容見 quick-patterns.md）`。
      留標題是為了讓人知道還有這一類，不要整段消失
   2. 「設定伺服器時」——多為部署期設定，可比照第 1 點處理
   3. 縮短舉例，保留判斷準則

   Cursor `.mdc` 有 globs、只在編輯該語言檔案時載入，
   可維持三行一則的完整格式並保留全部情境段落。

   ⚠ **不要為了湊行數把程式碼擠成一行。** 規則檔裡的程式碼會被直接抄走，
   壓成 `if !ok { return err }` 這種寫法不符 gofmt，抄過去會製造新問題。
   單語言檔本來就沒有 LLM 段落可砍，若壓縮程式碼是唯一手段，
   **應調整上限而非破壞內容**——這是 Cursor 檔上限從 160 調為 180 的原因。

## 與 sec-audit 的關係

| | sec-harden | sec-audit |
|---|---|---|
| 時機 | 寫的當下 | 送掃前 / 拿到報告後 |
| 讀 | `quick-patterns.md` | `checks/` + `mapping.md` |
| 產出 | 專案的規則檔 | `security-audit/` 報告 |

`quick-patterns.md` 是從 `checks/` 的 Web／API／LLM 則萃取出「寫的當下能預防」的約 20 則（MAST／MDM／裝置隱私／PIN／LOCK／請求濫用 等尚未收入速查）。
兩者內容不一致時，**以 `checks/` 為準**——那是完整版。

## 行動專案的產出邊界

偵測到 Android 或 iOS 時，內容來源同樣是 `quick-patterns.md`——
取「在行動端儲存資料時 / 在行動端連線時 / 處理行動端平台介面時 /
做行動端身分鑑別時」四個段落。

**Android 與 iOS 同時偵測到時，常駐檔（`AGENTS.md` 等）的 100 行上限很容易破。**
處理方式與多語言專案相同：常駐檔只保留兩平台**共通的判斷準則**，
API 名稱各列一個；完整的雙平台範例留在 Cursor `.mdc`（上限 180 行，
由 globs 決定何時載入）。**不要為了塞進去而把設定檔片段壓成單行**——
`AndroidManifest.xml` 的屬性抄過去要能直接用。

### 不產出工具設定檔

detekt（`detekt.yml`）、SwiftLint（`.swiftlint.yml`）、Android Lint（`lint.xml`）
的規則設定**不在本 skill 的產出範圍**。

理由：這些檔案要寫出具體的規則 id，而 id 寫錯時工具會**靜默忽略整份設定**——
工程師以為裝好了，實際上一條都沒生效。這比規則名稱不準嚴重得多。
在本知識庫於真實 Android／iOS 專案驗證過之前，不產出這類檔案。

