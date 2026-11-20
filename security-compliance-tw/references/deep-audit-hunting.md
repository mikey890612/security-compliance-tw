# 深度稽核：各領域獵洞清單

> 改寫自 Cloudflare [security-audit-skill](https://github.com/cloudflare/security-audit-skill)
> （commit `c1c8a8c`）的 `ATTACK-CLASSES.md` 與各領域指南，MIT License，Copyright (c) 2025-2026 Cloudflare, Inc.；
> 授權全文見 plugin 根目錄的 `THIRD_PARTY_NOTICES.md`。本檔為精簡摘要，每類只留「要查什麼」；
> 完整的獵洞說明請讀上游原文。對應到本知識庫 check 的部分為另加。

**用法**：階段 1 偵察完，依目標實際有的輸入面挑選要用的區塊，放進覆蓋帳本的攻擊類別欄；
**沒有的面就排除並寫理由**（例如「無訊息佇列」）。AI／LLM 另見 `deep-audit-ai.md`。

每個領域都先套用該領域的**核心紀律**——它決定什麼「不算」發現。
回報前一律過 `deep-audit.md` 的候選門檻。

---

## 0. 一般攻擊類別（每個目標都要考慮）

| 類別 | 要查什麼 | 相關 check |
|---|---|---|
| **注入** | 不可信輸入進入 SQL、命令、模板、路徑、LDAP、XPath、反序列化等 sink 的完整路徑，與中途的參數化或消毒是否真的生效 | `sast-injection.md` |
| **存取控制** | 每個資源操作是否在伺服器端檢查「這個主體 × 這個資源」；水平越權、垂直越權、批次與匯出等旁路 | `sast-authz.md`、`sast-api-authz.md` |
| **資源與檔案處理** | 上傳、解壓縮、暫存檔、路徑組合、符號連結、檔案權限 | `sast-request-abuse.md` |
| **密碼學與機密** | 演算法、金鑰來源與輪替、亂數、比較時間、機密是否進日誌或錯誤訊息 | `sast-crypto.md`、`sast-secrets.md` |
| **業務邏輯** | 狀態機能否跳步、金額或數量能否為負、重複提交、競態、優惠與額度的計算 | —（人工審查） |
| **功能濫用與資料外洩** | 合法功能被拿來列舉、外洩或轉送（匯出、預覽、通知、搜尋） | `dast-info-leak.md` |
| **鏈結漏洞與信任邊界** | 每個低嚴重度的結果當成下一步的前提，不假設後面的邊界成立 | — |
| **顯而易見的項目** | 硬編碼機密、跟資安有關的 TODO／FIXME、正式環境可開啟的除錯模式、可用的測試帳號、未保護的 `/debug`／`/admin`／`/metrics`／`/.env`、進版控的金鑰檔、`.gitignore` 漏掉機密、未鎖版本的相依、動態輸入的 `eval`／`exec`、過寬的 CORS、Cookie 屬性、Open Redirect、未強制 TLS、正式環境回傳堆疊 | `sast-secrets.md`、`sast-errors.md`、`sast-dependencies.md`、`dast-tls-cookie.md`、`dast-headers.md` |

「顯而易見的項目」**照單逐項檢查並逐項記錄結果**，不需要創意，需要的是完整。
其中多數已有 check：掃描器會標的照 check 判定；深度稽核只補「它真的能被利用到什麼程度」。

---

## 1. Web 協定與身分鑑別

**核心紀律**：框架與快取問題要有「同一請求或回應被兩個元件做出兩種解讀」；每個憑證都要找到簽章或機密驗證，
以及它的角色所需的每項綁定（issuer、audience、origin、client、session、主體、資源、等級、期限、一次性狀態）；
`Host`、`X-Forwarded-*`、`Origin`、`Referer`、重新導向目標、callback state 都是信任判斷。
**只是缺標頭、缺 Cookie 屬性、沒有 MFA 提示或沒有速率限制，單獨不算深度稽核的發現**——
但掃描器會標的仍依 `dast-headers.md`、`dast-tls-cookie.md` 處理。

| 子領域 | 要查的類別 | 相關 check |
|---|---|---|
| HTTP 框架與快取 | 請求走私／desync、未納入快取鍵的輸入造成快取投毒、私人回應被快取（cache deception）、信任 Host 與 forwarded 標頭、回應標頭注入 | SAST-INJ-007 |
| 瀏覽器 session | CSRF、session 固定與登出後失效、Cookie 範圍與傳輸 | SAST-CSRF-001、SAST-AUTH-002、SAST-AUTH-003、DAST-COOKIE-001 |
| 聯合身分 | JWT 驗章與 claim 綁定（alg、kid、aud、exp）、OAuth／OIDC 請求與 callback 綁定（state、nonce、PKCE、redirect_uri）、SAML 已簽物件與 assertion 綁定 | — |
| MFA、passkey 與帳號轉換 | MFA 綁定時的等級降級、step-up 綁定與繞過、WebAuthn 驗證（RP ID、origin、challenge、counter）、帳號連結與身分碰撞、密碼重設與帳號復原 | SAST-AUTH-004 |
| API key 與 mTLS | API key 的範圍與資源綁定、API key 外露與不安全傳輸、mTLS 對端身分與應用層主體混淆、憑證生命週期的退回路徑 | SAST-AUTH-001、SAST-CRYPTO-004 |

## 2. 前端（瀏覽器端）

**核心紀律**：要有可到達的 source → sink 與其他使用者或來源受到的影響；渲染器或瀏覽器行為不在 repo 內時判待驗證。

| 子領域 | 要查的類別 | 相關 check |
|---|---|---|
| DOM 與物件狀態 | DOM 型 XSS、DOM clobbering、原型污染與 gadget 鏈 | SAST-INJ-004 |
| 跨來源訊息與網路 | `postMessage` 的 origin 與 source 信任、跨站 WebSocket、帶憑證的 CORS | — |
| Service worker 與瀏覽器儲存 | 註冊與 scope 接管、快取與身分混淆、儲存外洩與過期授權、跨脈絡的儲存與 broadcast 混淆 | — |
| 跨站資訊外洩 | XS-Leaks 與跨來源狀態預言機、視窗與 opener 狀態外洩 | — |
| UI 偽裝與導覽 | 點擊劫持、前端導覽混淆 | DAST-HDR-003、SAST-REDIRECT-001 |

## 3. 供應鏈、CI 與發布

**核心紀律**：可變或已知有漏洞的相依**本身**不是發現——要指出誰能影響解析、哪個建置消費它、之後跨越了什麼執行或發布邊界。
CI 設定就是授權程式碼：觸發事件、誰的程式碼在跑、有哪些機密與 token、能發布或改動什麼。
從同一個不可信位置抓來的 checksum 不構成獨立完整性。分支保護、託管 runner、registry、簽章服務等 repo 看不到的事實判待驗證。

| 子領域 | 要查的類別 | 相關 check |
|---|---|---|
| 相依與建置輸入 | 相依來源與命名空間混淆（dependency confusion）、可變且未綁定的建置輸入、產生的原始碼來源不明、建置脈絡夾帶不該有的檔案 | SAST-DEP-001（僅已知漏洞部分） |
| CI 與自動化 | 不可信程式碼在特權 workflow 中執行（例如 fork PR 觸發帶機密的工作）、workflow 指令與運算式注入、快取／成品／工作區的信任混用、自動化身分權限過大 | — |
| 發布與更新 | 建置到上架之間被替換、發布授權與簽章政策缺口、更新 metadata 與回滾混淆、外掛與擴充的信任擴張 | — |

## 4. 雲端與部署

**核心紀律**：不能只憑 manifest 推論線上暴露——要確立哪個環境消費它、哪些預設值或 overlay 改了它、該路徑是否生效。
寬鬆的政策只有在低信任輸入能到達未授權動作時才是發現。機密的**引用**不是機密外洩。
帳號政策、網路掛載、執行期 admission、託管 metadata、設定漂移都需要擁有者觀察，判待驗證。

| 子領域 | 要查的類別 | 相關 check |
|---|---|---|
| 工作負載身分與 IAM | 工作負載身分權限過大、跨帳號或跨租戶角色混淆、把應用授權交給雲端 metadata 判斷 | SAST-AUTHZ-004 |
| 入口、網路與控制平面 | 非預期可達的服務或管理介面、繞過受信代理或 mesh 身分、可達 metadata 與內部服務 | SAST-SSRF-001 |
| 容器與編排 | 暴露主機或控制平面能力（特權容器、掛載 socket）、admission 與政策路徑不一致、命名空間與 label 的信任混淆 | — |
| 設定與機密生命週期 | 資安控制的優先序漂移（後面的設定蓋掉前面的）、機密跨工作負載外露、憑證更新與中斷時的退回行為 | SAST-AUTH-001 |
| 託管儲存、事件與邊緣 | 物件儲存與簽章 URL 政策混淆、事件來源身分混淆、邊緣與執行期邊界不一致 | — |

## 5. 資料隔離與生命週期

**核心紀律**：紀錄上有租戶或擁有者欄位**不等於**隔離——要找到每條讀寫路徑上實際強制它的查詢、鍵、路徑、政策或 row-level 控制。
追所有衍生副本：主資料消毒過，搜尋、快取、分析、匯出、預覽、日誌、replica、備份可能有不同的 ACL 與保存規則。
隱私或保存偏好不自動是漏洞；要有明確的資料存取邊界或刪除／撤銷保證，以及未授權的讀取者或後續操作。

| 子領域 | 要查的類別 | 相關 check |
|---|---|---|
| 租戶與物件隔離 | 缺少租戶或擁有者強制、複合鍵與命名空間碰撞、政策與查詢不一致、blob 與簽章參照的範圍過大 | SAST-AUTHZ-002、SAST-API-001 |
| 衍生資料與揭露 | 搜尋／快取／索引的 ACL 漂移、分析／日誌／追蹤／診斷成為替代讀取者、列舉與彙總預言機 | SAST-LOG-002 |
| 匯出、備份、還原與遷移 | 匯出與備份範圍擴大、匯入與還原的權限擴大、遷移的預設值與擁有權混淆、備份與複寫的邊界漂移 | — |
| 刪除、撤銷與生命週期 | 軟刪除與 tombstone 被繞過、過期授權與衍生副本仍可用、保存期限與排隊工作超時、還原後重新引入無效狀態 | SAST-AUTH-003 |

## 6. RPC、協定與訊息

**核心紀律**：要有兩個元件對同一訊息的不同解讀，或某條路徑少了其他路徑有的授權；broker ACL 與部署路由看不到時判待驗證。

| 子領域 | 要查的類別 |
|---|---|
| 框架、schema 與解讀 | 訊息邊界與正規化不一致、union／enum／預設值混淆、信封與內容的身分不一致 |
| RPC 身分與授權 | 攔截器（interceptor）與方法路徑不一致、對端身分與應用主體混淆、逐項與串流授權缺口、callback 與回覆關聯混淆 |
| Broker 與佇列隔離 | topic／routing key／訂閱範圍缺口、dead-letter／重試／診斷佇列外洩、不可信生產者被當控制平面 |
| 重送、順序與交易 | 重複投遞與冪等缺口、亂序與過期訊息被接受、ack／commit 順序錯誤、多消費者的部分轉換 |

## 7. 資源耗盡與可用性

**核心紀律**：要有「輸入 → 成本」的路徑、缺少有效上限，且影響到其他使用者、共用服務、安全功能或營運方的花費；
只在請求者自己行程內、會自我限制的工作不是服務漏洞。**只是沒有速率限制不夠**——先查 body／訊息／檔案上限、並行數、佇列、
deadline、資料庫限制、上游 gateway 與逐租戶額度。**不跑壓力測試**；用漸近分析、小型邊界 fixture、mock 付費呼叫與嚴格的本機資源上限證明。

| 子領域 | 要查的類別 | 相關 check |
|---|---|---|
| 運算放大 | 超線性的解析／比對／求值（ReDoS、巢狀結構）、解壓縮與表示放大（zip bomb、XML 實體）、資料庫與下游查詢放大 | SAST-API-004、SAST-INJ-005 |
| 資源累積 | 無上限的緩衝與基數、檔案描述符／handle／暫存資源洩漏、取消後仍在跑的背景工作 | SAST-ERR-003 |
| 額度與排程 | 驗證前就做大量工作、額度計算的範圍與重置缺口、worker／pool／優先序餓死 | SAST-AUTH-004 |
| 失敗與復原 | 可到達的致命錯誤或死結、重試風暴與 fail-open 放大、毒訊息與隊頭阻塞、不安全的復原與容量回滾 | SAST-ERR-004 |

## 8. 桌面、行動 App 與本機 IPC

**核心紀律**：要有低信任來源（其他 App、網頁、檔案、本機使用者）透過 deep link、WebView、IPC 或本機檔案取得它不該有的能力或資料；
作業系統的權限模型與簽章設定看不到時判待驗證。行動端掃描器會標的寫法另依 `mast-platform.md`、`mast-storage.md` 判定。

| 子領域 | 要查的類別 | 相關 check |
|---|---|---|
| Deep link、callback 與導覽 | 自訂 scheme 與 deep link 的歧義與搶註、App 與帳號交接混淆、開檔與 intent 的權限混淆 | MAST-PLATFORM-001 |
| WebView 與原生橋接 | 導覽來源與橋接權限混淆、原生橋接能力過寬、WebView 的檔案與 universal access | MAST-PLATFORM-002 |
| 本機 IPC 與匯出元件 | IPC 對端未驗證、宣稱的主體與通道身分不符、匯出的 service／activity／receiver／provider 權限過大、IPC 生命週期與關聯混淆 | MAST-PLATFORM-001、MAST-PLATFORM-005 |
| 特權 helper 與本機檔案 | 特權 helper 成為代理人混淆、安裝／更新／修復路徑的信任、本機檔案擁有權與 TOCTOU、憑證儲存與本機機密的邊界不符 | MAST-STORAGE-001、MAST-STORAGE-006 |
| App 狀態與裝置生命週期 | 切換帳號、登出與裝置還原時的資料殘留、待決動作與使用者在場的混淆 | MAST-STORAGE-005、MAST-AUTH-001 |

## 9. 記憶體安全與二進位（C／C++／Rust unsafe／cgo／FFI）

**核心紀律**：要有攻擊者可控的輸入到達記憶體錯誤，且在沙箱內以 sanitizer 或最小 harness 觀察到；
**不把當機升格成程式碼執行**。

| 子領域 | 要查的類別 |
|---|---|
| 邊界、整數與表示 | 越界讀寫、整數溢位／下溢／截斷／正負號、單位與指標層數混淆、未初始化或部分初始化的資料 |
| 生命週期、型別與並行 | use-after-free／過期 view／重複釋放、型別混淆與不合法的 downcast、參考計數與擁有權競態、共用狀態競態與 TOCTOU、鎖順序／死結／餓死 |
| FFI 與 ABI | 指標與長度的擁有權約定不符、layout／對齊／enum 不一致、unwind／例外／執行緒親和性違規 |
| 二進位載入與執行期 | 函式庫／外掛／執行檔的搜尋順序信任、成品缺少身分或簽章綁定、畸形的二進位 metadata 與 relocation 處理、JIT 與產生程式碼的一致性、卸載／重新載入／拆除的安全 |
| 核心與特權介面 | user-copy 的邊界與重複讀取、特權物件的生命週期與 dispatch 一致性、授權不足的強大介面 |
