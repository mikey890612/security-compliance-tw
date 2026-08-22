---
name: sec-deliverables
description: 產出台灣政府資訊系統驗收所需的 SSDLC 交付文件——附表十安全查檢表、源碼安全查檢表、安全測試報告、威脅建模（DFD/STRIDE/DREAD）、需求追溯矩陣 RTM、委外 RFP 資安需求。Use when the user asks for 查檢表, 勾稽表, 驗收文件, 交付文件, 威脅建模, threat model, STRIDE, DREAD, 需求追溯矩陣, RTM, RFP 資安需求, 委外需求規格, 安全測試報告, or needs documents for 資安稽核 or 系統驗收.
---

# sec-deliverables

**目標：把技術結果變成交得出去的文件。**

`sec-audit` 找問題修問題，這支把結果轉成稽核人員看得懂、驗收時交得出去的文件。

## 最重要的原則：不編造

這些文件會送到稽核人員手上。**編造比留白危險得多**——
一個對不上的頁碼、一個沒有證據的「符合」，會讓整份文件的可信度崩掉。

三條硬規則：

1. **看不到證據的項目不可標「符合」**，一律標「非程式碼可判定，需人工確認」
2. **推導不出來的欄位填 `（待填）`**，不要填看似合理的內容
3. **自動判斷的地方要標示信心度**，低信心的寫明依據什麼假設

## 四種文件，各自獨立

先問使用者要產哪一份，不要一次全產。

| 要什麼 | 讀哪個模板 | 需要 findings.md 嗎 |
|---|---|---|
| 附表十查檢表 / 源碼查檢表 / 測試報告 | `../../references/templates/checklist.md` | **是** |
| 威脅建模 | `../../references/templates/threat-model.md` | 否，但有更好 |
| 需求追溯矩陣 RTM | `../../references/templates/rtm.md` | 否，但有更好 |
| 委外 RFP 資安需求 | `../../references/templates/rfp.md` | **否**，與程式碼無關 |

模板本身寫明了各自的產出步驟與格式，照著做。

## 共同的前置作業

除了 RFP 之外，都要先確認：

1. **專案分級**（普/中/高）——決定要涵蓋哪些項目。問法見
   `../../references/profile.md`，同樣一次問完不逐題往返
2. **有無 `security-audit/findings.md`**——沒有的話，
   產查檢表類要先請使用者跑 `sec-audit`；威脅建模與 RTM 可以做，
   但要說明「未經源碼檢視，實作狀態欄位無法回填」

RFP 不需要在專案目錄下執行，也不需要 findings。

## 輸出位置

一律寫入專案根目錄的 `security-deliverables/`：

```
security-deliverables/
├── checklist-appendix10.md          附表十安全查檢表
├── checklist-source.md              源碼安全查檢表
├── security-test-report.md          安全測試報告
├── threat-model.md                  威脅建模
├── rtm.md                           需求追溯矩陣
└── rfp-security-requirements.md     委外 RFP 資安需求
```

與 `sec-audit` 的 `security-audit/` 分開——一個是技術產出，一個是交付文件。

## 知識庫

| 檔案 | 何時讀 |
|---|---|
| `templates/*.md` | 依要產的文件選一份 |
| `controls-appendix10.md` | 查檢表、RTM、RFP 都要讀 |
| `mapping.md` | 把 check-id 換成附表十項次時 |
| `profile.md` | 問分級時 |

**一次只讀要用的那一份模板。** 不要四份全載入。

用 Read 工具讀 `../../references/…` 會正確解析。
**不要用 shell 的 `cd ../..` 導航**——`cd` 是邏輯解析，在 symlink 底下會跑錯地方。

## 產出後一定要做的事

**驗算與自檢**，尤其這兩項：

- **威脅建模的 DREAD 分數**——五欄總和要等於風險值欄，等級要與區間相符。
  算術錯誤稽核時很容易被抓到
- **查檢表的項目數**——要與該分級在 `controls-appendix10.md` 的項目數一致，
  少一項就是漏列

最後在文件末尾列出「待人工確認事項」彙整，把所有 `（待填）`
與「非程式碼可判定」的項目集中呈現。**這一節不可省略**——
它是使用者知道還要做什麼的唯一依據，尤其當使用者不是資安專家時。
