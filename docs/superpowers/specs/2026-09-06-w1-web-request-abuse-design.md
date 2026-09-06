# W1：Web 補洞（CSRF／SSRF／不安全上傳）— 設計規格

日期：2026-09-06
狀態：§1–§3 已與使用者確認核准；實作計畫待 writing-plans
專案：`security_skill_creator` / `security-compliance-tw`
來源：Web 應用程式安全參考指引 v3.2 附件 1 查檢表缺口盤點
相關 GitHub：https://github.com/mikey890612/security-compliance-tw

---

## 0. 背景

既有 Web 43 則（整體知識庫含 mobile 後為 63 則）已覆蓋多數高頻驗收題，但附件 1「開發階段」明文要求的 **CSRF**，以及實務高頻的 **SSRF**、**不安全檔案上傳**，尚無獨立 check。使用者選擇 **W1 Approach A**：新建一律載入的 `sast-request-abuse.md`，只加這三則。

---

## 1. 目標與非目標（§1 已核准）

### 目標

- 新建 `references/checks/sast-request-abuse.md`，三則：
  - `SAST-CSRF-001` · 跨站請求偽造未防護
  - `SAST-SSRF-001` · 伺服器端請求偽造
  - `SAST-UPLOAD-001` · 不安全檔案上傳
- 五小節 + 五欄掃描表（多為 `unverified`）；SAST 語言 fence：`go` + `python` + `javascript`
- `profile.md`：**一律**載入（與 `sast-injection.md` 並列）
- `mapping.md` +3 列；skills／README 總 checks **63→66**（Web 表述 43→46）

### 非目標

- P1：密碼重設 token、CAPTCHA、管理者介面來源限制
- 獨立 DAST 對題、A3 CI／CHANGELOG、掃描器實跑校準
- 不改 `sast-injection.md` 與既有 Web／MAST／MDM check 語意

### 成功標準

1. `validate_kb.py` 通過：**66** checks、0 errors
2. profile 一律載入路徑含 `sast-request-abuse.md`
3. 單元測試全綠
4. 不宣稱 Fortify／Checkmarx／特定規則為 `verified`（無證據時）

---

## 2. ID 與題意邊界（§2 已核准）

| ID | 涵蓋 | 不涵蓋 |
|---|---|---|
| SAST-CSRF-001 | 狀態變更請求缺 CSRF token／Origin／Referer 驗證等伺服端防護 | 純 Cookie `SameSite` 屬性題（`DAST-COOKIE-003`） |
| SAST-SSRF-001 | 使用者可控 URL 被伺服端發出請求（內網／metadata／任意 host） | 僅把 LLM 輸出當唯一敘事；可交叉引用但不取代本則 |
| SAST-UPLOAD-001 | 未驗證類型／內容、危險副檔名、任意路徑寫入、無大小上限 | 純路徑尋訪讀檔（`SAST-INJ-003`）；儲存型 XSS 主體（`SAST-INJ-004`） |

### mapping 建議

| check-id | 附表十 | 普/中/高 | Web25 | CWE |
|---|---|---|---|---|
| SAST-CSRF-001 | 4.5.3.1 | ◎◎◎ | A01 | CWE-352 |
| SAST-SSRF-001 | —（查檢表外） | ◎◎◎ | A10 | CWE-918 |
| SAST-UPLOAD-001 | —（查檢表外） | ◎◎◎ | A04 | CWE-434 |

Web21／API23／LLM25／Mob25：依題意填 `—` 或可誠實對到的 API 列；不捏造附表十編號。

---

## 3. 架構與驗收（§3 已核准）

### 檔案

| 動作 | 路徑 |
|---|---|
| 新建 | `security-compliance-tw/references/checks/sast-request-abuse.md` |
| 修改 | `security-compliance-tw/references/profile.md`（一律列） |
| 修改 | `security-compliance-tw/references/mapping.md`（+3） |
| 輕觸 | `skills/sec-audit|harden|deliverables/SKILL.md`、`README.md`、可選 `docs/usage/sec-audit.md` |
| 不改 | `tools/validate_kb.py`（既有 SAST 規則已足夠） |

### 體裁

同既有 SAST：五小節、五欄掃描表、Traditional Chinese 正文、無法規／OWASP 編號於 check 本文。

### 驗收

```bash
python3 security-compliance-tw/tools/validate_kb.py   # 66 則
python3 -m unittest discover -s security-compliance-tw/tools -v
```

### 實作順序（供 writing-plans）

1. Author `sast-request-abuse.md`（3 checks）
2. mapping + profile
3. skills／README
4. Acceptance → finishing-a-development-branch

---

## 4. 核准紀錄

| 節 | 狀態 |
|---|---|
| Approach A | 已核准 |
| §1 | 已核准 |
| §2 | 已核准 |
| §3 | 已核准 |
