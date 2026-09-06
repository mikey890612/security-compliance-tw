# 知識庫導覽

本目錄由 `skills/` 下的各 skill 共用。路徑相對於 skill 目錄為 `../../references/`。

| 要做什麼 | 讀哪個檔 | 使用者 |
|---|---|---|
| 決定專案分級、決定要載入哪些 check | `profile.md` | sec-audit / sec-deliverables |
| 判斷某個掃描工具的習性與誤判處置慣例 | `scanners.md` | sec-audit |
| 查某個壞味道怎麼偵測、怎麼修 | `checks/*.md` | sec-audit |
| 把 check-id 換成附表十或 OWASP 編號 | `mapping.md` | sec-audit / sec-deliverables |
| 寫程式當下的過關寫法速查 | `quick-patterns.md` | sec-harden |
| 附表十查檢表全文與分級 | `controls-appendix10.md` | sec-deliverables |
| 行動應用 App 基本資安檢測基準的條號與標題（65 條） | `controls-mas-v4.md` | sec-deliverables |
| 掃描器對照的驗證紀錄（工具版本、fixture、findings） | `scanner-verification-log.md` | sec-audit |
| 各類交付文件的產出規則與格式 | `templates/*.md` | sec-deliverables |
| 檢測基準勾稽表的產出規則 | `templates/checklist-mas.md` | sec-deliverables |
| 流程類項目該問誰、該備什麼證據 | `evidence-mas-process.md` | sec-deliverables |

## 路徑注意事項

skill 目錄在本機是以 symlink 掛進 `~/.claude/skills/` 的。
**用 Read 工具讀 `../../references/…` 會正確解析**（syscall 先解 symlink，
`..` 才套用到真實父目錄）。

**但不要用 shell 的 `cd ../..` 導航到這裡**——`cd` 用邏輯解析，
會跑到 `~/.claude/` 而不是 plugin 根目錄。要在 shell 操作請用絕對路徑。

## 設計約束

1. **`checks/` 內不得出現法規或 OWASP 編號。** 對照關係一律放 `mapping.md`。
   理由：同一個壞味道對映四張清單，內嵌編號會導致清單改版時需修改全部 check 檔。

2. **每則 check 必須有五個小節**：掃描器怎麼標 / 壞味道 / 過關寫法 /
   常見誤判與處置 / 判定準則。

3. **程式碼範例的語言要求依 check-id 前綴決定。**

   | 前綴 | 必要的圍籬 |
   |---|---|
   | `SAST-` | ` ```go `、` ```python `、` ```javascript ` |
   | `MAST-` | ` ```swift `、` ```kotlin ` |
   | `DAST-` / `MDM-` | 不要求（其壞味道與過關寫法以設定與驗證步驟描述） |

4. **設定檔屬性不得只出現在程式碼圍籬內。**
   `android:allowBackup`、`NSAllowsArbitraryLoads`、`cleartextTrafficPermitted`
   這類字面樣式**就是掃描器比對的目標**。把它們寫成 Kotlin／Swift 註解時，
   工程師複製程式碼會整段漏掉——而那正是紅字的來源。
   凡在程式碼圍籬內出現的設定檔屬性，必須另附可複製的
   ` ```xml `／` ```plist `／` ```gradle ` 圍籬。散文提及不受此限。
   受管制的屬性清單見 `../tools/validate_kb.py` 的 `CONFIG_MARKERS`。

5. **掃描器表格必須有「狀態」與「證據」欄。**
   狀態限 `verified` / `unverified` / `partial`；`verified` 必須填證據。

6. **check-id 格式**：`{SAST|DAST|MAST|MDM}-{主題縮寫}-{三位數字}`，
   一經發布不得變更。

以上各點由 `../tools/validate_kb.py` 自動驗證。新增或修改 check 後執行：

    cd security-compliance-tw && python3 tools/validate_kb.py

驗證器同時檢查 `checks/` 與 `mapping.md` 的**雙向對應**——
有 check 沒 mapping、或有 mapping 沒 check，都會報錯。

## 目前涵蓋範圍

共 89 則 check：伺服器與 Web 46 則、行動端 35 則、MDM 8 則。

### 行動端與 MDM

| check 檔 | 則數 | 涵蓋 |
|---|---|---|
| `mast-storage.md` | 6 | 明文儲存 / 日誌 / 系統備份 / 硬編碼機密 / 快取殘留 / 憑證儲存設施 |
| `mast-crypto.md` | 3 | 弱演算法與加密模式 / 不安全亂數 / 金鑰與 IV 重用 |
| `mast-network.md` | 4 | 明文與 ATS／NSC / 憑證釘選 / 信任評估 / 網域宣告 |
| `mast-auth.md` | 5 | 用戶端鑑別閘道 / 生物辨識 / 用戶端授權 / 交易鑑別 / 密碼強度提示 |
| `mast-platform.md` | 8 | IPC／深層連結 / WebView / 剪貼簿 / 螢幕擷取 / 資料分享 / 螢幕覆蓋 / 鍵盤快取 / 權限宣告 |
| `mast-resilience.md` | 6 | Root／越獄 / 偵錯模式 / 模擬器與動態分析 / 安裝包完整性 / 混淆與加殼 / 執行期竄改 |
| `mast-code.md` | 3 | 輸入驗證 / 注入防護 / 函式庫已知漏洞 |
| `mdm-controls.md` | 8 | 註冊 / 受管 App / 遠端抹除 / 鎖定 / 越獄偵測 / 修補 / VPN / MTD |

`MAST-*` 對照《行動應用 App 基本資安檢測基準》的條號（`mapping.md` 的 `MAS` 欄）。

⚠ **`mast-resilience.md` 全部屬 F 類加測或參考項目，非必要檢測項目。**
只在 profile 勾選「將送 F 類加測」時載入——未加測卻報告會產生大量不適用雜訊。
該檔的 `MAST-RESILIENCE-005`（混淆）**iOS 側刻意留白**：
Swift 無官方混淆方案，本知識庫不提供廠商建議。
`MDM-*` 的 `MAS` 與附表十兩欄皆為 `—`——檢測基準規範的是行動應用程式本身，
MDM 屬機關端裝置管理政策，不在其收錄範圍；附表十亦無對應的應用程式層項目。

`controls-mas-v4.md` 收錄該基準全部 65 條的條號與標題，**僅在產出勾稽表時讀取**。
其中多數條目目前尚無對應 check，產出時會落在「非程式碼可判定，需人工確認」
或「本知識庫尚未涵蓋」。

### 伺服器與 Web

| check 檔 | 則數 | 涵蓋 |
|---|---|---|
| `sast-injection.md` | 4 | SQL 注入 / OS 命令注入 / 路徑尋訪 / 跨站腳本攻擊 |
| `sast-authz.md` | 4 | 未執行授權檢查 / 水平越權 / 垂直越權 / 未以最小權限執行 |
| `sast-session-auth.md` | 4 | 硬編碼憑證 / Session 固定 / 逾時與登出 / 鎖定與密碼強度 |
| `sast-crypto.md` | 4 | 已破解演算法 / 未用 KDF / 不安全亂數 / TLS 驗證關閉 |
| `sast-logging.md` | 4 | 日誌注入 / 敏感資訊入日誌 / 缺稽核事件 / 日誌權限過寬 |
| `sast-errors.md` | 4 | 訊息外洩 / 回傳值未檢查 / 資源未釋放 / 例外捕捉過廣 |
| `sast-request-abuse.md` | 3 | 跨站請求偽造 / 伺服器端請求偽造 / 檔案上傳 |
| `sast-api-authz.md` | 4 | 物件層級 / 屬性層級 / 功能層級授權失效 / 資源消耗無限制 |
| `sast-llm.md` | 4 | 提示注入 / 輸出處理不當 / 過度代理權 / 系統提示放金鑰 |
| `dast-headers.md` | 3 | CSP / HSTS / Clickjacking |
| `dast-tls-cookie.md` | 4 | Cookie Secure / HttpOnly / SameSite / TLS 版本與套件 |
| `dast-info-leak.md` | 4 | 錯誤頁 / 目錄列表 / 版本指紋 / 敏感檔案殘留 |

`controls-appendix10.md` 收錄附表十查檢表全文與分級，僅在產出 `checklist.md` 時讀取。

`quick-patterns.md` 是 `sec-harden` 的內容來源——從既有 check 萃取出
「寫的當下能預防」的約 20 則，依情境（寫查詢 / 寫 handler / 處理路徑…）而非
依 check-id 組織。修改後需重跑 `sec-harden` 安裝，各專案的規則檔才會更新。
兩者不一致時以 `checks/` 為準。

## 新增 check 的流程

1. 在對應的 `checks/*.md` 加一則，嚴格照五小節格式
2. 在 `mapping.md` 加一列（12 欄，缺一不可）
3. 跑 `python3 tools/validate_kb.py` 確認通過
4. 更新本檔的涵蓋範圍表與 `skills/sec-audit/SKILL.md` 的涵蓋範圍段落
