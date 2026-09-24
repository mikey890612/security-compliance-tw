# 專案 profile 與 check 集合選取

## 分級問答

**每次啟動都問，不推測、不寫設定檔。一次問完，不逐題往返。**

要蒐集六個資料點，但 `AskUserQuestion` 一次最多四題。
**用 multiSelect 壓成三題**，不要拆成兩輪問——拆輪等於逐題往返。

**第 1 題（單選）安全分級**：普 / 中 / 高

> 依「資通安全責任等級分級辦法附表九」由機關核定。使用者不確定時請其查驗收文件；
> 仍不確定則以「中」進行，並**在報告首頁註明此假設**。

**第 2 題（複選）專案具備哪些特性**——七個選項，全不勾也是有效答案：

- 對外提供服務（公開網際網路可存取）
- 有 API 端點（REST / GraphQL / gRPC）
- 有 LLM / RAG / Agent 功能
- 處理個人資料或金流
- 有行動 App（iOS／Android 原生）
- 有 EMM／MDM／MAM
- 行動 App 將送 **F 類加測**（逆向工程與竄改防護）

> **F 類必須問，不能推導。** 它是《行動應用 App 基本資安檢測基準》的
> 進階加測項目，由**送檢單位自行決定**是否加測——程式碼裡沒有任何線索。
> 未勾選時不要載入 `mast-resilience.md`：那一組全部是 F 類或參考項目，
> 未加測卻報告會產生大量不適用雜訊。
>
> 相對地，**L1／L2／L3 不要問**——見下方「行動專案的檢測基準分級」。

**維持三題。** `AskUserQuestion` 上限四題，留一格給日後需求；
把 F 類拆成第四題等於用掉最後的安全邊際。

**第 3 題（複選）已知將面對哪些掃描器**：

- 商用 SAST（Fortify / Checkmarx）
- 開源 SAST（Semgrep / SonarQube / CodeQL / gosec / bandit）
- DAST / 弱點掃描（AWVS / Nessus / ZAP / WebInspect）
- 不知道

另需判定「**是否有登入功能**」（決定是否載入 `sast-session-auth.md`）。
這一項**不要問**——從程式碼判定即可：是否有**用來辨識使用者身分**的 session／cookie／JWT／密碼
處理。CSRF token、語系偏好這類不帶身分的 cookie 不算。判不出來時才問，且併入上面三題一起問。

## 分級的實質差異

以下項目**僅高等級要求**。普 / 中等級不應報告，否則產生大量不適用雜訊
（掃描器會標的例外，見下方「逐則決定要不要查」）：

- 多重因素身分鑑別
- 資訊系統備援採高可用性架構
- 滲透測試
- 機敏資料靜態加密
- 重要資料或紀錄留存雜湊值
- 自動化工具監控進出通信流量
- 稽核失效即時告警

以下僅中 / 高等級要求：

- 最小權限（使用者/角色、程序執行權限）
- 圖形驗證碼
- 密碼重設一次性時效令牌
- 密碼加 Salt 雜湊
- 開發 / 測試 / 正式環境區隔
- 伺服器端正規表示式輸入驗證

普 / 中 / 高一律要求的（最常卡驗收的就是這些）：

- Session 閒置至多 30 分鐘失效、登出即失效
- 密碼長度 12 字元以上，含大小寫、數字、特殊字元
- 不可與前 3 次密碼相同
- 登入失敗 5 次鎖定帳號**及來源 IP** 至少 15 分鐘
- 身分鑑別資訊不以明文傳輸
- 防範 SQL 注入、XSS、CSRF
- 錯誤頁僅顯示簡短訊息與代碼
- 所有功能皆進行錯誤與例外處理並正確釋放資源
- 日誌記錄身分鑑別失敗、存取資源失敗、重要資料異動、管理者行為
- 弱點掃描

## check 集合選取規則

**本表由 `mapping.md` 的分級欄與各 check 的掃描器表推導**：檔內只要有一則在某分級標 ◎，
該分級就要載入這個檔——那一則是查檢表必查，漏載等於漏查；檔內只要有一則列了 SAST（或 DAST）
工具，將面對該類掃描器時就要載入。依專案特性才成立的檔（登入、API、LLM、行動端、MDM）看特性，
**檔內只能放以該特性為前提的 check**——與特性無關的 check 放進特性檔，沒有該特性的專案就會整則漏查
（0.5.0 以前的 `SAST-AUTH-001` 就是如此）。驗證器會檢查本表與分級欄、掃描器表一致。

| 條件 | 載入 |
|---|---|
| 一律 | `checks/sast-injection.md` |
| 一律 | `checks/sast-errors.md` |
| 一律 | `checks/sast-request-abuse.md` |
| 一律 | `checks/sast-dependencies.md` |
| 一律 | `checks/sast-secrets.md` |
| 一律 | `checks/sast-authz.md` |
| 一律 | `checks/sast-logging.md` |
| 一律 | `checks/dast-tls-cookie.md` |
| 一律 | `checks/dast-info-leak.md` |
| 分級 ≥ 中，或有個資或金流，或將面對 SAST，或將面對 DAST | `checks/sast-crypto.md` |
| 分級 ≥ 中，或對外服務，或將面對 DAST | `checks/dast-headers.md` |
| 有登入功能 | `checks/sast-session-auth.md` |
| 有 API 端點 | `checks/sast-api-authz.md` |
| 有 LLM / RAG / Agent | `checks/sast-llm.md` |
| 有行動 App | `checks/mast-storage.md`、`checks/mast-crypto.md`、`checks/mast-network.md`、`checks/mast-auth.md`、`checks/mast-platform.md`、`checks/mast-code.md` |
| 有 EMM／MDM／MAM | `checks/mdm-controls.md` |
| 行動 App **且**勾選 F 類加測 | `checks/mast-resilience.md` |

第 3 題的答案對應如下。**勾「不知道」視為各類都會面對**——附表十 4.5.4 普中高都要求弱點掃描，
送驗收幾乎一定會被掃。

| 第 3 題勾選 | 將面對 | 對應「掃描器怎麼標」表的工具 |
|---|---|---|
| 商用 SAST | SAST | Fortify、Checkmarx |
| 開源 SAST | SAST | Semgrep、SonarQube、CodeQL、gosec、bandit |
| DAST／弱點掃描 | DAST | AWVS、Nessus、ZAP、WebInspect |
| 不知道 | SAST 與 DAST | 全部 |

### 逐則決定要不要查

載入的是整個檔，但檔內每一則是否適用本專案，逐則判斷：

| 情況 | 處理 |
|---|---|
| 本分級在 `mapping.md` 標 ◎ | 查——查檢表必查 |
| 未標 ◎，但該 check 的「掃描器怎麼標」表列了本專案將面對的工具（不論狀態；註明「需自訂規則」的列不算） | 查——掃描器不看分級，照樣會標 |
| 兩者皆否 | 不適用，不列 |

例：分級「中」的專案，`SAST-CRYPTO-001`（弱演算法）附表十只要求高，但 Fortify、gosec、bandit
都會標 MD5，所以照樣查；優先序依下方規則，不因此變成查檢表必查。
行動端 check 看 L1／L2／L3／F 欄，不適用本節。

**程式碼看得出來的特性，以較寬的一方為準。** 使用者答「否」、但程式碼明顯具備時照樣載入，
並在 `findings.md` 開頭寫明「使用者未勾選，但程式碼可見 X（位置），因此載入 Y」：

| 特性 | 程式碼裡的跡象 |
|---|---|
| 有 API 端點 | handler 回傳 JSON（`application/json`、`json.NewEncoder(w)`、`jsonify`、`res.json`），或供 XHR／fetch 呼叫的路由 |
| 有 LLM／RAG／Agent | 相依或呼叫 LLM SDK（`openai`、`anthropic`、`langchain` 等） |
| 有行動 App | 見下方「語言對應」的 Android／iOS 檔案 |

「對外服務」「處理個資或金流」「EMM／MDM／MAM」「F 類加測」程式碼看不出來，**照使用者的答案**。

**載入前先確認檔案存在。** 知識庫仍在擴充中，規則表可能列出尚未建立的檔案。
遇到不存在的檔案時，在報告中註明「該類別尚未涵蓋」，**不要憑印象生成內容**。

## 行動專案的檢測基準分級（L1 / L2 / L3 + F）

行動專案有**兩套並行的分級**，兩者都要判定，不可互相取代：

- **附表十的普 / 中 / 高**——由機關核定，決定伺服器端 check 的載入
- **檢測基準的 L1 / L2 / L3**——由 App 本身的功能決定，決定行動端條目的適用範圍

L1 / L2 / L3 **不要問，從既有資料點推導**：

| 條件 | 類別 |
|---|---|
| 無使用者身分鑑別功能 | L1 |
| 有登入功能，但無金錢交易 | L2 |
| 有線上金錢交易 | L3 |

「有無登入功能」已從程式碼判定；「處理個人資料或金流」已在第 2 題問過。
兩者足以推出 L1 / L2 / L3，**不需要額外問題**。

**F 是附加類別**，與 L1/L2/L3 並存（例如「L2 + F」），由第 2 題的選項決定。
各行動 check 的適用分級見 `mapping.md` 行動端對照表的 `L1`/`L2`/`L3`/`F`/`參` 欄，
條號全文見 `controls-mas-v4.md`。

## 語言對應

讀取專案根目錄判定技術棧：

| 檔案 | 語言 | 取用的範例區塊 |
|---|---|---|
| `go.mod` | Go | ` ```go ` |
| `requirements.txt` / `pyproject.toml` / `Pipfile` | Python | ` ```python ` |
| `package.json` | JavaScript | ` ```javascript ` |
| `build.gradle` / `build.gradle.kts` / `settings.gradle` | Kotlin / Java（Android） | ` ```kotlin ` |
| `Podfile` / `Package.swift` / `*.xcodeproj` / `*.xcworkspace` | Swift（iOS） | ` ```swift ` |
| `AndroidManifest.xml` / `Info.plist` | 設定檔 | ` ```xml ` / ` ```plist ` |
| 沒有 `package.json`，但有 `*.js`／`*.ts`／`*.html`（伺服器端模板、前端靜態檔） | JavaScript | ` ```javascript ` |

manifest 只是捷徑：**專案裡有該語言的原始檔就算**，掃描器會掃到它們——包括 `vendor/`
下的第三方檔案（處置見 `scanners.md` 的「第三方程式碼的發現」）。
多語言專案全部載入。找不到任何一種時，詢問使用者。

**行動專案的伺服器端仍走既有的 `sast-*` 與 `dast-*`**——
行動 App 打的那組 API 後端與一般 Web 服務沒有差別。偵測到 Android／iOS 時兩邊都要載入。

## 優先序

排的是**不修會不會被驗收退件**。驗收有兩關：掃描報告，以及人工審查（查檢表逐項）。
任一關會擋就要修。判定分類見 `sec-audit` 的「判定分類與優先序」。

| 優先序 | 條件 |
|---|---|
| **P0** | 真漏洞，且符合任一：① 查檢表必查——`mapping.md` 該 check 的附表十欄有項次（不是「查檢表外」，也不是標「（內文）」的指引內文項目），且本專案分級欄標 ◎；行動端看推導出的 L1／L2／L3 欄，勾了 F 類加測再看 F 欄 ② 掃描器確定會標為 Critical／High——模式 2 看**報告上的等級**；模式 1 只看 **`verified` 列**的等級 |
| **P1** | 其他真漏洞 |
| **P2** | 改寫即過 |
| — | 誤判：不排序，列為「送掃前備妥的佐證」。不適用：不列 |

- **`unverified` 列的等級不參與排序**——那是未校準的宣稱，實測常比表上低。寫成「可能被標，等級待確認」
- **人工審查才抓得到的真漏洞照樣排 P0**（例如完全沒有授權檢查、沒有稽核紀錄），不另立「表外」
- P0 必修才能送掃。P1 應修；排不進本次的列「已知、待修」並附理由與時程。P2 順手改寫即可
