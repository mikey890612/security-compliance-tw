# sec-harden 使用說明

**寫程式的當下就用掃描器認得的寫法，不要事後再修。**

預防比補救便宜。`sec-audit` 是拿來補救的，這支是拿來避免需要補救的。

---

## 兩種用法

| 用法 | 做什麼 | 誰在用 |
|---|---|---|
| **安裝模式** | 把規則寫進你的專案，產出各家 agent 的設定檔 | 一個專案做一次 |
| **直接使用模式** | 你在 Claude Code 裡寫程式時即時套用 | 每次寫 code |

**安裝模式是重點**——裝完之後 Cursor、Cline、Codex、Copilot 都能用，
**不需要 Claude Code 在場**。

---

## 安裝模式

### 怎麼觸發

在**要安裝的專案根目錄**開 Claude Code：

```
/sec-harden 安裝到這個專案
```

```
幫我把安全撰寫規則裝進來，讓 Cursor 也能用
```

```
設定這個專案的資安 coding 規範
```

### 它會做什麼

**1. 偵測語言**

| 看到什麼檔案 | 判定 |
|---|---|
| `go.mod` | Go |
| `requirements.txt` / `pyproject.toml` / `Pipfile` | Python |
| `package.json` | JavaScript / TypeScript |
| 有 `.html` / `.css` 但沒有 `package.json` | 純前端 |

**只產出用得到的語言。** 沒有 Python 就不會產 Python 的規則檔——
少一個常駐檔就少一份 context 開銷。

**2. 列出要寫哪些檔給你確認**（除非你的要求已明示範圍）

**3. 產出**

### 你會拿到什麼

```
你的專案/
├── AGENTS.md                          通用基底，多數 agent 工具都讀
├── .cursor/rules/
│   ├── sec-harden-go.mdc              globs: **/*.go
│   ├── sec-harden-python.mdc          globs: **/*.py
│   └── sec-harden-web.mdc             globs: **/*.{js,jsx,ts,tsx,html}
├── .clinerules                        Cline
├── .windsurfrules                     Windsurf
└── .github/copilot-instructions.md    GitHub Copilot
```

**Cursor 的檔案依語言分開，用 `globs` 自動附加**——編輯 `.go` 檔就載入
Go 的規則，編輯 `.py` 就載入 Python 的。這是所有目標裡唯一精準的觸發機制，
其餘都是常駐。

實測（Go + Python 專案）：Cursor 檔各 158 / 159 行，四個常駐檔各 92 行。

### 規則內容長什麼樣

依情境分段，不是依編號：

```
寫資料庫查詢時 / 寫 HTTP handler 時 / 處理檔案路徑時 /
執行外部命令時 / 處理密碼與金鑰時 / 寫日誌時 /
錯誤處理時 / 設定伺服器時 / 呼叫 LLM 時
```

每則三行：`✅ 這樣寫` / `❌ 不要這樣寫` / **為什麼掃描器認得或不認得**。

理由那行是重點。例如：

> ✅ `bcrypt.GenerateFromPassword`
> ❌ `sha256` 直接雜湊密碼，即使加了 salt
> → 掃描器認的是**函式名稱**，sink 換成已知 KDF 呼叫規則就不再命中

---

## 重跑安裝會發生什麼

**不會覆蓋你自己寫的內容。**

`AGENTS.md`、`.clinerules`、`.windsurfrules`、`copilot-instructions.md`
這四個檔可能你原本就有東西。它用標記區塊包住自己的內容：

```markdown
<!-- BEGIN sec-harden v0.1.0 — 由 quick-patterns.md 產生。
     請勿直接編輯本區塊內容，重跑安裝器即可更新。 -->
...
<!-- END sec-harden -->
```

重跑時**只替換區塊內部**，區塊外一字不動。實測過：在 `AGENTS.md` 區塊外
加一行手寫規則，重跑後手寫內容保留、區塊正確更新。

所以知識庫更新後，重跑一次就好。Cursor 的 `.mdc` 是獨立檔案，直接覆寫。

---

## 直接使用模式

不用安裝，你在 Claude Code 裡寫程式時它會套用。觸發不需要你明講——
description 涵蓋了這些情境：

寫資料庫查詢、寫 HTTP handler、處理檔案路徑、呼叫外部程式、
處理密碼或金鑰、寫日誌、錯誤處理、設定 TLS、呼叫 LLM。

也可以主動要求：

```
用安全的寫法實作這個查詢功能
```

它讀的是濃縮速查（約 20 則），不是完整的 43 則——寫程式時不需要那麼詳細。
要細節（掃描器規則名稱、誤判處置）時它會去查完整版。

---

## 推上 GitHub 沒問題

生成的規則檔設計成**可以 commit、可以分享**：

- **不含任何絕對路徑**——拿到的人 repo 裡沒有這個 plugin，寫 `/Users/...` 沒意義
- **不含法規或 OWASP 編號**——規則檔是給人寫程式用的，不是法遵文件
- **輸出順序固定**——重裝不會產生整份翻動的 diff
- **不加時間戳**——同上

所以直接 `git add` 進版控，同事 clone 下來就能用。

---

## 它不會做的事

| 不做 | 說明 |
|---|---|
| 掃描你的程式碼 | 那是 `sec-audit` |
| 修改既有程式碼 | 它只寫規則檔，不動你的原始碼 |
| 產出未偵測到的語言的規則 | 沒有 `package.json` 就不會有 JS 規則 |
| 覆蓋你在標記區塊外寫的內容 | 一律附加 |

---

## 常見問題

**Q：裝完 Cursor 沒反應？**
Cursor 需要 `.cursor/rules/*.mdc` 在**專案根目錄**下。確認你是在專案根目錄
執行安裝的。另外 Cursor 要重開專案才會重新載入 rules。

**Q：常駐檔會不會吃掉太多 context？**
單語言約 75 行、雙語言約 92 行，都控制在 100 行內。
Cursor 檔比較長（上限 180 行）但有 `globs`，只在編輯該語言檔案時載入。

**Q：知識庫更新後怎麼同步到已安裝的專案？**
`git pull` 更新 plugin，然後到各專案重跑一次安裝。標記區塊會被替換，
你自己寫的內容不受影響。

**Q：可以只裝其中幾個檔嗎？**
可以，直接說「只要 Cursor 的」或「只要 AGENTS.md」。
