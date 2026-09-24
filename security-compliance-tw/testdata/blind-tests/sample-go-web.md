# 盲測：sample-go-web（sec-audit 模式 1）

測的是：**送掃之前，sec-audit 預判得到 Fortify 實際會標的東西嗎？**

`../sample-go-web/` 是自行撰寫的 Go 網頁專案（`html/template`、前端 JS、內附第三方編輯器），
重現了一份真實專案 Fortify SCA 26.1 報告中觀察到的四種觸發樣式。報告本身不入庫，
fixture 不含該專案的任何程式碼或內容。

⚠ **本檔是標準答案，刻意放在 fixture 目錄之外。** 盲測時不可讓受測的 agent 讀到本檔。

## 標準答案

依據：同樣式在真實報告中被標的類別與等級。**fixture 本身未經 Fortify 掃描**——這是推論，不是實測。

| # | 位置 | Fortify 類別 | 等級 | check | 依知識庫的預期判定 |
|---|---|---|---|---|---|
| 1 | `templates/profile.html:18` | Often Misused: File Upload | Low | SAST-UPLOAD-001 | 誤判：handler 有允許清單、大小上限、系統產生檔名、站外目錄 |
| 2 | `templates/import.html:15` | Often Misused: File Upload | Low | SAST-UPLOAD-001 | 同上 |
| 3 | `templates/attachment.html:15` | Often Misused: File Upload | Low | SAST-UPLOAD-001 | 同上 |
| 4 | `templates/attachment.html:22` | Often Misused: File Upload | Low | SAST-UPLOAD-001 | 同上（`/editor/images`） |
| 5 | `static/js/app.js:7` | System Information Leak: External | Medium | SAST-ERR-001 | 真漏洞：錯誤物件寫進 DOM，改顯示常數訊息 |
| 6 | `static/vendor/richedit/richedit.js:41` | System Information Leak: External | Medium | SAST-ERR-001 | 第三方：以 `settings.uploader` 覆寫，不改套件檔 |
| 7 | `static/vendor/richedit/richedit.js:12` | Cross-Site Request Forgery | Low | SAST-CSRF-001 | 誤判：接收端 `withCSRF` 驗 `X-CSRF-Token` |
| 8 | `events.go:29` | Weak Cryptographic Hash | Low | SAST-CRYPTO-001 | 真漏洞：校驗碼離開行程，改 SHA-256 |

命中 = findings 在同一檔案、同一元素或行列出，且 check-id 相符。其餘項目不計分，逐項判斷是否合理。

## 結果（2026-09-24）

每次都由沒看過報告與本檔的全新子代理執行，profile 答案相同。

| | 0.1.0（校準前） | 0.2.0（校準後） |
|---|---|---|
| 命中 | **2／8**（#7、#8） | **8／8** |
| HTML 檔案欄位 #1–4 | 未預判；把 handler 預判成 `Unrestricted File Upload`（Critical） | 全中，判誤判並附 handler 行號 |
| 前端錯誤外洩 #5–6 | 判 SAST-ERR-001「通過」——只看伺服器端 | 全中；#6 依第三方處置 |
| #8 的優先序 | P0（表上 Critical–High） | P3（Low，與實際報告一致） |

兩次都另外找到 fixture 裡的真問題：所有路由沒有身分鑑別（SAST-AUTHZ-001）、
沒有稽核紀錄（SAST-LOG-003）；0.2.0 那次還指出 CSRF 中介層先解析了整個
multipart 本體，使上傳 handler 的大小上限對表單路徑失效。

**限制：** fixture 與 0.2.0 的校準來自同一份報告，所以這證明的是「校準確實傳到了模式 1」，
不是「模式 1 在任意專案上都準」。真實專案的盲測仍待做。

## 重跑方式

開一個全新、沒看過本檔的 agent，給它下面這段（路徑依環境調整），再依上表計分：

```text
你是使用者的 coding agent。使用者的專案在 <repo>/security-compliance-tw/testdata/sample-go-web/。
使用者的請求：這個專案下個月要送 Fortify 源碼掃描。送掃前先幫我檢查會被標什麼、
哪些是真的要修。先不要改程式碼，只要產出報告。
請讀 <repo>/security-compliance-tw/skills/sec-audit/SKILL.md，把它當成已被呼叫的 skill，逐步照做。
使用者已回答 profile：安全分級「中」；專案特性只勾「處理個人資料或金流」；
掃描器「商用 SAST（Fortify / Checkmarx）」。你無法再詢問使用者。
不要看 git 歷史，不要讀 SKILL.md 沒要求的檔，不要讀專案以外的 testdata。不要修改程式碼。
```
