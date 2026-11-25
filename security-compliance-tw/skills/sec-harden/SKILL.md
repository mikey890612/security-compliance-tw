---
name: sec-harden
description: 一般開發任務一律套用：新增或修改任何程式碼時，當下就用 Fortify / Checkmarx / Semgrep / gosec / bandit / MobSF / AWVS 認得的安全寫法（查詢、handler、檔案、命令、金鑰、日誌、錯誤、TLS、LLM、Android／iOS）。Use for ANY task that adds or modifies code; also for 安裝安全規則, 讓 Cursor 也能用, AGENTS.md / cursor rules.
---

# sec-harden

**寫的當下就用過關寫法，不要事後再修。** 補救交給 `sec-audit`。

使用者要「安裝／設定到專案／讓 Cursor 也能用」→ 讀 `{ROOT}/references/harden-guide.md` 的「安裝模式」照做。
其餘（寫或改程式）→ 套用下方核心規則，碰到路由表情境才讀對應檔。

---

## 知識庫根目錄（ROOT）（先讀這段）

讀知識庫前，先解析 **ROOT**（plugin 根目錄，其下有 `references/`）：

1. 若環境變數 `SECURITY_COMPLIANCE_TW_ROOT` 已設定 → 用它
2. 否則若存在 `~/.security-compliance-tw/root` → 讀取該檔單行路徑（plugin 絕對路徑）
3. 否則 fallback：本 `SKILL.md` **所在目錄**往上兩層（`skills/<name>/../..`；仍在 clone 裡開發時才成立）

三者都找不到 `references/` 時，停下來請使用者執行 repo 的 `install.sh`——
**不要憑印象作答**，本 skill 的價值在於答案來自知識庫。

解析出 ROOT 後，讀 `~/.security-compliance-tw/installed.json`；不存在就略過（例如直接在 clone 裡開發）。
其中 `checked_at`（最後一次安裝或檢查更新的日期）距今超過 30 天時，在回覆開頭提醒一句：
「知識庫是 v{version}，上次檢查更新是 {checked_at}；可在 repo 執行 `./install.sh --check` 看看有沒有新版。」
只提醒這一句，接著照常做事。

知識庫路徑一律表述為 `{ROOT}/references/…`。用 Read 工具讀**解析後的絕對路徑**（或開發時 fallback 的明確相對路徑）。

**不要用 shell 的 `cd ../..` 導航**——先解析 ROOT 再 Read。`cd` 是邏輯解析，在 symlink 或已安裝的 skill 目錄下會跑錯地方。

要在 shell 操作時，先解析 ROOT 取得絕對路徑，再用絕對路徑操作。

---

## 核心規則（每次改程式都對照）

1. **參數化查詢**：placeholder／ORM 綁定，不拼接字串；欄名、排序用白名單。
2. **輸出編碼**：用樣板自動跳脫；使用者資料不進 `innerHTML`、`template.HTML`、`|safe`、`v-html`。
3. **每個端點在伺服端驗身分與權限**（含 POST、API、管理功能、下載）；物件存取查擁有者（防 IDOR）。
4. **不寫死秘密**：密碼、key、token、簽章金鑰、預設帳密由環境變數或秘密管理提供；不進 git、日誌、前端。
5. **錯誤對外只回通用訊息**；stack trace、SQL、路徑只寫伺服端日誌；不吞錯。
6. **伺服端輸入驗證**：型別、長度、範圍、格式白名單，不合格就拒絕。
7. **密碼與亂數**：Argon2id／bcrypt／scrypt；token、salt 用 CSPRNG（`crypto/rand`、`secrets`），不用 `math/rand`、`Math.random()`；不用 MD5／SHA1／ECB、不自創加密。
8. **Session／token**：登入換 session ID；Cookie 加 `Secure`、`HttpOnly`、`SameSite`；token 會過期、登出或改密碼即失效、不放 URL；狀態變更防 CSRF。
9. **日誌**：記登入成敗、權限拒絕、管理操作（時間、帳號、來源、結果）；不記密碼、token、個資；跳脫換行。
10. **路徑／SSRF／反序列化／命令**：路徑正規化後須在基底目錄內；代發 URL 用允許清單、擋內網；不反序列化不可信資料、XML 關外部實體；命令用參數陣列不經 shell。
11. **相依套件**：維護中版本、鎖 lockfile，新增或升級前查已知弱點。
12. **LLM／Agent**：指令與資料分離、輸出視為不可信、系統提示不放金鑰、工具最小權限。

## 路由表

**不要預先載入 reference，只讀符合當下改動的那一份**（`quick-patterns.md` 只讀對應段落；勿整份貼進規則檔）。
路徑為 `{ROOT}/references/…`；與 `checks/` 不一致時以 `checks/` 為準。

| 當下改動 | 讀 |
|---|---|
| 查詢、handler、路徑、命令、金鑰、日誌、錯誤、伺服器設定、LLM | `quick-patterns.md` 對應段落 |
| CSRF、SSRF、上傳、登入後導回 | `checks/sast-request-abuse.md` |
| XML、反序列化、回應標頭／`Set-Cookie` | `checks/sast-injection.md`（INJ-005～007） |
| 新增或升級套件 | `checks/sast-dependencies.md` |
| Agent／MCP／工具呼叫 | `checks/sast-llm.md` 檔尾 |
| Android／iOS 儲存、連線、平台、鑑別 | `quick-patterns.md` 行動端四段；不夠再讀對應 `mast-storage.md`／`mast-network.md`／`mast-platform.md`／`mast-auth.md` |
| 行動端加密；輸入驗證與第三方庫；防竄改（F 類）；EMM／MDM | `mast-crypto.md`；`mast-code.md`；`mast-resilience.md`；`mdm-controls.md` |
| 規則名稱、誤判處置 | 該主題 `checks/*.md` |
| 安裝到專案、完整說明 | `harden-guide.md` |

語言：Go、Python、JS／TS 的 API 名稱見 `quick-patterns.md`；Kotlin／Swift 走行動端列；
PHP（含 Workerman）、Rust、Flutter／Dart 等尚無專屬檔，依同情境準則換成等價 API（Flutter 的 `AndroidManifest.xml`／`Info.plist` 照行動端）。
