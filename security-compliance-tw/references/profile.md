# 專案 profile 與 check 集合選取

## 分級問答

**每次啟動都問，不推測、不寫設定檔。一次問完，不逐題往返。**

要蒐集六個資料點，但 `AskUserQuestion` 一次最多四題。
**用 multiSelect 壓成三題**，不要拆成兩輪問——拆輪等於逐題往返。

**第 1 題（單選）安全分級**：普 / 中 / 高

> 依「資通安全責任等級分級辦法附表九」由機關核定。使用者不確定時請其查驗收文件；
> 仍不確定則以「中」進行，並**在報告首頁註明此假設**。

**第 2 題（複選）專案具備哪些特性**——六個選項，全不勾也是有效答案：

- 對外提供服務（公開網際網路可存取）
- 有 API 端點（REST / GraphQL / gRPC）
- 有 LLM / RAG / Agent 功能
- 處理個人資料或金流
- 有行動 App（iOS／Android 原生）
- 有 EMM／MDM／MAM

**第 3 題（複選）已知將面對哪些掃描器**：

- 商用 SAST（Fortify / Checkmarx）
- 開源 SAST（Semgrep / SonarQube / CodeQL / gosec / bandit）
- DAST / 弱點掃描（AWVS / Nessus / ZAP / WebInspect）
- 不知道

另需判定「**是否有登入功能**」（決定是否載入 `sast-session-auth.md`）。
這一項**不要問**——從程式碼判定即可：是否有 session / cookie / JWT / 密碼
相關的處理。判不出來時才問，且併入上面三題一起問。

## 分級的實質差異

以下項目**僅高等級要求**。普 / 中等級不應報告，否則產生大量不適用雜訊：

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

| 條件 | 載入 |
|---|---|
| 一律 | `checks/sast-injection.md` |
| 一律 | `checks/sast-errors.md` |
| 對外服務 = 是 | `checks/dast-headers.md`、`checks/dast-tls-cookie.md`、`checks/dast-info-leak.md` |
| 分級 ≥ 中 | `checks/sast-authz.md`、`checks/sast-crypto.md` |
| 有登入功能 | `checks/sast-session-auth.md` |
| 有 API 端點 | `checks/sast-api-authz.md` |
| 有 LLM / RAG / Agent | `checks/sast-llm.md` |
| 有個資或金流 | `checks/sast-logging.md`、`checks/sast-crypto.md` |
| 有行動 App | `checks/mast-storage-crypto.md`、`checks/mast-network-ipc.md` |
| 有 EMM／MDM／MAM | `checks/mdm-controls.md` |

**載入前先確認檔案存在。** 知識庫仍在擴充中，規則表可能列出尚未建立的檔案。
遇到不存在的檔案時，在報告中註明「該類別尚未涵蓋」，**不要憑印象生成內容**。

## 語言對應

讀取專案根目錄判定技術棧：

| 檔案 | 語言 | 取用的範例區塊 |
|---|---|---|
| `go.mod` | Go | ` ```go ` |
| `requirements.txt` / `pyproject.toml` / `Pipfile` | Python | ` ```python ` |
| `package.json` | JavaScript | ` ```javascript ` |

多語言專案全部載入。找不到任何一種時，詢問使用者。

## 優先序

修補順序 = 掃描器預設等級 × 專案分級。

| 掃描器等級 | 分級 高 | 分級 中 | 分級 普 |
|---|---|---|---|
| Critical / Blocker | P0 | P0 | P0 |
| High | P0 | P1 | P1 |
| Medium | P1 | P2 | P2 |
| Low / Info | P2 | P3 | P3 |

P0 必修才能送掃。P3 可在報告中列為「已知、不修」並附理由。
