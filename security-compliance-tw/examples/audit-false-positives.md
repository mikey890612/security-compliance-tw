# 誤判清單與佐證

- 稽核對象：`security-compliance-tw/testdata/sample-go`
- 模式：模式 1（送掃之前）
- 日期：2026-08-22（第二輪；本檔取代第一輪版本）
- 預期掃描器：商用 SAST（Fortify / Checkmarx）、開源 SAST（Semgrep / SonarQube /
  CodeQL / gosec / bandit）、DAST（AWVS / Nessus / ZAP / WebInspect）

## 結論

**本次無任何誤判項目（0 筆）。**

`findings.md` 中的 10 項發現全數判定為真漏洞或真問題。依 SKILL.md，
誤判標記需**同時**滿足三個條件：

1. 資料實際不可控（來源為常數、列舉，或已通過白名單驗證）
2. 路徑上確實有有效的消毒或參數化，只是工具追不到
3. 有具體佐證可寫入報告：檔案位置、資料來源、消毒點行號

三項注入發現（SAST-INJ-001 / 002 / 003）的資料來源皆為
`r.URL.Query().Get(...)`，**第 1 條即不成立**；路徑上不存在任何消毒或參數化，
**第 2 條亦不成立**。其餘發現屬「應有的設定或檢查不存在」，本質上無誤判空間。

## 供複掃與人工審查參考

以下為**不適用**（非誤判）的類別。列出的原因是稽核人員依附表十逐項對照時，
可能詢問「為何報告中沒有這些項目」：

| 類別 | 不適用理由 | 佐證 |
|---|---|---|
| 密碼學（SAST-CRYPTO-001~004） | 全檔無任何密碼學呼叫 | `main.go` import 僅 `database/sql`、`fmt`、`net/http`、`os`、`os/exec`；`grep -nE "md5\|sha1\|math/rand\|tls\."` 無命中 |
| 個資靜態加密 | **分級「中」不要求** | 依 `profile.md`，機敏資料靜態加密屬僅高等級要求。分級若核定為「高」需重評 |
| Cookie 屬性（DAST-COOKIE-001~003） | 程式不會產生 `Set-Cookie` | 全檔無 `http.SetCookie` 呼叫 |
| Session 與身分鑑別（`sast-session-auth.md`） | 專案無登入功能 | `grep -nE "session\|jwt\|password\|token"` 對 `main.go` 無命中，故未載入該 check 檔 |
| API 授權（`sast-api-authz.md`） | 無 REST / GraphQL / gRPC 端點 | 三支 handler 回傳純文字與檔案位元組 |
| LLM / Agent（`sast-llm.md`） | 無相關功能 | `go.mod` 無任何相依套件 |
| 稽核紀錄檔權限（SAST-LOG-004） | 程式不自行落地日誌檔 | 無 `os.OpenFile` / `WriteFile` / `Chmod` |

**注意**：上述「不適用」的前提是專案現況，補完 findings 的第 4 與第 6 項後
會立即改變——導入身分機制會讓 Session 與 Cookie 兩類變成適用；
補上稽核日誌會讓 SAST-LOG-001（Log Forging）、SAST-LOG-002（敏感資訊寫入日誌）
與 SAST-LOG-004（紀錄檔權限）三項同時變成適用。屆時需重跑本流程。

## 已知風險接受

無。本次無任何項目以「架構限制」或「相容性需求」結案。

## 給複掃的提醒

第 6 項（SAST-LOG-003）**不會出現在任何掃描報告中**——七款 SAST 皆無現成規則，
DAST 無從觀測日誌內容。複掃結果乾淨不代表這一項通過，
該項的查核方式是人工審查源碼中的稽核寫入呼叫。
