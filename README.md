# security-compliance-tw

讓程式碼通過**源碼掃描**與**弱點掃描**，不需要與稽核人員逐項協調。

依台灣「資通安全責任等級分級辦法**附表十** 資通系統防護基準」，
結合 OWASP Web Top 10（2021 / 2025）、API Security Top 10（2023）、
Top 10 for LLM Applications（2025），提供給 Claude Code、Cursor
及其他本機 agent 使用的資安知識庫與工作流程。

程式語言涵蓋 **Go、Python、JavaScript**。

---

## 這個專案在解決什麼

政府指引寫「應針對輸入資料進行驗證」——那是給人看的，人可以判斷你做到了。

但 Fortify 做的是**污點分析**：它追資料從 source 流到 sink 的路徑。
你的程式碼可能真的安全，但只要它追不出你在中間消毒過，照樣標 Critical。

**「安全的寫法」與「掃描器認得的寫法」不是同一個集合。**
兩者的差距就是大部分專案卡在驗收的地方。

本專案的知識庫因此不只寫「正確寫法」，而是寫**掃描器規則明確認得的那一種寫法**，
並針對每一則說明：哪些工具會標、標什麼名字、什麼情況是誤判、誤判怎麼處置。


## 三支 skill

| Skill | 時機 | 產出 | 使用說明 |
|---|---|---|---|
| **`sec-audit`** | 送掃之前 / 拿到掃描報告之後 | `security-audit/findings.md`、`false-positives.md` | [詳細用法](docs/usage/sec-audit.md) |
| **`sec-harden`** | 寫程式的當下 | 專案的 `AGENTS.md`、Cursor `.mdc`、Cline / Windsurf / Copilot 規則檔 | [詳細用法](docs/usage/sec-harden.md) |
| **`sec-deliverables`** | 要交文件時 | 附表十查檢表、源碼查檢表、測試報告、威脅建模、RTM、委外 RFP | [詳細用法](docs/usage/sec-deliverables.md) |

**第一次用建議從 [`sec-audit`](docs/usage/sec-audit.md) 開始**——
它會告訴你這個專案現在的體質，另外兩支的產出都依賴它的結果。

### sec-audit 的兩個模式

- **模式 1（送掃之前）**——樣式比對，預判會被標什麼，先修掉
- **模式 2（拿到報告之後）**——讀你手上的 Fortify / Checkmarx / AWVS 報告，
  逐項判定真漏洞或誤判、給修法、產出誤判佐證

**本專案不執行任何掃描工具。** 掃描由人執行。

### sec-harden 是跨工具的

它把規則安裝進你的專案，產出各家 agent 的格式：

```
你的專案/
├── AGENTS.md                        通用基底
├── .cursor/rules/sec-harden-*.mdc   依語言分檔，用 globs 自動附加
├── .clinerules
├── .windsurfrules
└── .github/copilot-instructions.md
```

裝完之後**不依賴 Claude Code 在場**，Cursor、Cline、Codex 都能用。
一律附加不覆蓋，重跑安裝只替換標記區塊內容。

---

## 安裝

```bash
git clone https://github.com/mikey890612/security-compliance-tw.git
cd security-compliance-tw
ln -sfn "$PWD/security-compliance-tw/skills/sec-audit"        ~/.claude/skills/sec-audit
ln -sfn "$PWD/security-compliance-tw/skills/sec-harden"       ~/.claude/skills/sec-harden
ln -sfn "$PWD/security-compliance-tw/skills/sec-deliverables" ~/.claude/skills/sec-deliverables
```

驗證知識庫完整性：

```bash
cd security-compliance-tw && python3 tools/validate_kb.py
```

需要 Python 3，無外部相依。

---

## 知識庫結構

核心設計是**偵測與對照分離**：

```
references/
├── checks/              43 則：怎麼偵測、怎麼修（不含任何法規或 OWASP 編號）
├── mapping.md           唯一對照表：check-id → 附表十 / OWASP / CWE
├── controls-appendix10.md   附表十查檢表全文與分級
├── quick-patterns.md    寫程式當下的速查（sec-harden 的內容來源）
├── templates/           各類交付文件的產出規則
├── profile.md           分級問答與 check 選取規則
└── scanners.md          各工具的行為特性與誤判處置慣例
```

同一個壞味道會同時對映四張清單（例：字串拼接 SQL = 附表十 4.5.3.1 +
Web21 A03 + Web25 A05 + LLM05 + CWE-89）。若在每則 check 內嵌編號，
清單改版時要修改全部檔案；集中對照則只需改一個檔。

每則 check 固定五個小節：**掃描器怎麼標 / 壞味道 / 過關寫法 /
常見誤判與處置 / 判定準則**。SAST 類必須含 Go、Python、JavaScript 三種範例。
以上由 `tools/validate_kb.py` 自動驗證，同時檢查 `checks/` 與 `mapping.md`
的雙向對應。

### 涵蓋範圍（43 則）

注入（含 XSS）· 存取控制 · 身分鑑別與 Session · 密碼學 · 日誌與稽核 ·
錯誤與例外 · API 授權 · LLM / Agent · HTTP 安全標頭 · TLS 與 Cookie · 資訊外洩

**未涵蓋**：備份備援、稽核儲存容量、時戳校時、系統文件、委外管理、
供應鏈完整性、基礎設施加固（GCB / 防火牆 / OS）。

---

## 範例產出

`security-compliance-tw/examples/` 收錄對測試 fixture 實際跑出來的成果：

| 檔案 | 內容 |
|---|---|
| `audit-findings.md` | sec-audit 的逐項判定 |
| `checklist-appendix10.md` | 附表十勾稽表（44 項，分級中） |
| `checklist-source.md` | 源碼安全查檢表（23 項） |
| `threat-model.md` | DFD + STRIDE + DREAD（含驗算） |
| `rtm.md` | 需求追溯矩陣 |
| `rfp-security-requirements.md` | 委外 RFP 資安需求（45 條） |
| `security-test-report.md` | 安全測試報告 |

⚠ 這些是對一個 **41 行的測試 fixture** 產出的示範，不是真實專案的稽核結果。

---

## 核心原則：不編造

交付文件會送到稽核人員手上。**編造比留白危險得多。**

- 看不到證據的項目**不可標「符合」**，一律標「非程式碼可判定，需人工確認」
- 推導不出來的欄位填「（待填）」
- 自動判斷處標示信心度，低信心的寫明依據什麼假設
- 附表十查檢表未收錄的風險，標為「查檢表外」，不硬湊章節號

誤判標記須同時滿足三要件：資料實際不可控、路徑上確有消毒只是工具追不到、
有具體佐證。三者缺一即當真漏洞修。

不採用「遮蔽掃描結果讓紅字消失」的做法——附表十每項的查核方式
都同時要求**自動化工具檢測**與**人工審查**，遮蔽會在人工審查那關破功。

---

## 已知限制

誠實列出，請據此判斷可信度：

1. **商用 SAST 的規則名稱未經真實報告驗證**——Fortify、Checkmarx
   的規則名稱來自模型知識，未與實際掃描報告比對。開源工具
   （gosec、bandit、SonarQube、Semgrep、CodeQL）的規則編號已人工核對。
2. **僅對測試 fixture 驗證過**，尚未在真實專案上跑過。
3. **OWASP Top 10:2025 的定稿狀態**需自行至 owasp.org/Top10 核對。
   `mapping.md` 的 Web25 欄依 2025 版排序。
4. **樣式比對無法取代污點分析**——不安全操作被包進多層 helper、
   動態組成的字串、二階注入等情形可能漏判。「未命中」不等於「無此問題」。
5. **指引內文與附件 1 查檢表的收錄範圍不完全相同**——例如 HTTP 安全標頭
   （4.5.3.4）收錄於內文，查檢表未收錄。產出勾稽表時這類項目會另立區段。
   詳見 `references/controls-appendix10.md` 的「內文與查檢表的收錄範圍」。

---

## 資料來源與著作權

### 法規本文（不受著作權保護）

`references/controls-appendix10.md` 收錄的控制措施與分級，出自：

- **《資通安全責任等級分級辦法》附表十「資通系統防護基準」**
  （依《資通安全管理法》授權訂定之法規命令）

依**著作權法第 9 條**，憲法、法律、命令或公文不得為著作權之標的。

### 參考指引（著作權屬各機關，本專案不重製）

下列文件為前述法規的實作參考，本專案**僅參考其技術觀念**，
所有實作內容均另行以 Go / Python / JavaScript 撰寫，並補上掃描器規則對應、
API 層與 AI 層內容：

- 《Web 應用程式安全參考指引 V3.2》，數位發展部資通安全署，114.12.31
- 《安全軟體發展流程指引》《安全軟體設計參考指引》《安全軟體測試參考指引》，
  行政院資通安全辦公室，103 年

**這些文件的原始 PDF 及其實作建議、程式範例、編排，著作權分屬上述機關，
不隨本專案散布**，請自行至各機關網站取得。

---

## 授權

MIT（見 [LICENSE](LICENSE)）。

涉及外部來源的部分——法規本文、參考指引、OWASP 清單、掃描工具規則名稱——
的處理方式與界線，見 [NOTICE.md](NOTICE.md)。
