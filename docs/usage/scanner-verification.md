# 掃描器驗證（商用延後路徑）

本文件說明**商用**掃描報告如何用於把知識庫掃描器表從 `unverified` 提升為 `verified`／`partial`。  
開源實跑流程見 `security-compliance-tw/tools/verify_scanners.md`。

**明確原則：在尚未提供合規報告前，Fortify／Checkmarx／AWVS／WebInspect／Nessus 等商用列必須維持 `unverified`。** 不得僅憑猜測或公開 rule 名稱就標 `verified`。

---

## 1. 報告必備欄位

送入驗證流程的報告（或redacted 摘要）至少要能還原下列欄位：

| 欄位 | 說明 |
|------|------|
| 工具 | 例如 Fortify SCA、Checkmarx、Acunetix WVS |
| 版本 | 引擎／rulepack／掃描器版本字串 |
| 規則 ID | 工具原生規則識別（如 Fortify kingdom／Checkmarx query 名） |
| 嚴重度 | 工具原始等級（Critical／High／…） |
| 位置或分類 | `file:line`，或至少可對應的 CWE／弱點類別 |

缺少規則 ID 與位置／CWE 任一關鍵欄時，只能標 `partial` 或維持 `unverified`，並在 log 註明缺漏。

---

## 2. 紅action 規則

`testdata/scan-artifacts/commercial/` **預設 gitignore**，禁止把客戶原始報告直接推上公開 GitHub。

紅action 時必須移除或改寫：

- 客戶原始碼片段、路徑中的客戶專案／主機名稱
- 祕密、token、連線字串、個資
- 可識別客戶的報告 metadata（合約編號、系統正式名稱等，視政策）

公開知識庫的 `證據` 欄**不要**貼報告內容；改寫成內部標記，例如：

```text
internal-verified:2026-09-05
```

原始redacted 檔僅留在本機 `commercial/` 或內部安全存放區。

---

## 3. 操作者 checklist

1. 將redacted 報告放到 `security-compliance-tw/testdata/scan-artifacts/commercial/`（本機即可）
2. 以報告中的規則 ID／CWE／檔案模式，對照 `references/checks/*.md` 各則 `### 掃描器怎麼標` 表列
3. 對得上且證據充分：該列 `狀態` → `verified`；僅部分吻合 → `partial`
4. `證據` 填公開可 commit 的字串（如 `internal-verified:YYYY-MM-DD`），**不要**填會洩漏客戶內容的路徑細節進公開 repo（若路徑必須出現，僅用已redacted 相對名）
5. 執行 `python3 security-compliance-tw/tools/validate_kb.py`，確認商用 `verified` 列皆有非 `—` 證據
6. 在 `security-compliance-tw/references/scanner-verification-log.md` 追加一列（工具、版本、對應 checks、摘要）

---

## 4. 在報告到來前的狀態

| 情況 | 應有狀態 |
|------|----------|
| 尚無任何商用報告 | 所有商用工具列 = `unverified`，證據 = `—` |
| 有報告但規則對不上既有列 | 維持 `unverified` 或另開追蹤；勿捏造命中 |
| 有報告且對得上 | `verified` 或 `partial`，並完成 log |

`sec-audit` 模式 2 若命中 `unverified` 列，findings 應註明「規則名待真實報告確認」（由後續 skill 更新任務負責；本文件僅定義驗證流程）。
