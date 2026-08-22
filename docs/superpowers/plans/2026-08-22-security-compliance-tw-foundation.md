# security-compliance-tw 地基與第一條垂直切片 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立 security-compliance-tw plugin 的共用知識庫與可運作的 sec-audit skill，涵蓋一個 SAST check 檔與一個 DAST check 檔，證明整條管線可用。

**Architecture:** plugin 目錄建在專案內，透過 symlink 掛進 `~/.claude/skills/` 供本機使用。知識庫採「偵測與對照分離」——`references/checks/` 只寫怎麼偵測與怎麼修，所有法規與 OWASP 編號集中在 `references/mapping.md`。一支純 stdlib 的 Python 驗證器負責把關知識庫的結構完整性與雙向對應，作為每個內容任務的驗收閘門。

**Tech Stack:** Markdown（知識庫與 skill）、Python 3 stdlib（驗證器，使用 `unittest`，無外部相依）

**Spec:** `docs/superpowers/specs/2026-08-22-security-compliance-tw-plugin-design.md`

**本計畫不涵蓋：** 其餘 9 個 check 檔、skill B（sec-harden）、skill C（sec-deliverables）、git 初始化。

---

## 檔案結構

| 路徑 | 職責 |
|---|---|
| `security-compliance-tw/.claude-plugin/plugin.json` | plugin 中繼資料 |
| `security-compliance-tw/skills/sec-audit/SKILL.md` | skill A 的操作流程；只放流程與索引，不內嵌 check 內容 |
| `security-compliance-tw/references/README.md` | 知識庫導覽 |
| `security-compliance-tw/references/profile.md` | 分級問答腳本、check 集合選取規則 |
| `security-compliance-tw/references/scanners.md` | 六類工具的行為特性與誤判處置慣例 |
| `security-compliance-tw/references/mapping.md` | check-id → 附表十 / Web21 / Web25 / API23 / LLM25 / CWE 的唯一對照表 |
| `security-compliance-tw/references/checks/sast-injection.md` | 注入類偵測與過關寫法 |
| `security-compliance-tw/references/checks/dast-headers.md` | HTTP 安全標頭偵測與過關設定 |
| `security-compliance-tw/tools/validate_kb.py` | 知識庫結構與對應關係驗證器（可 import 的函式 + CLI） |
| `security-compliance-tw/tools/test_validate_kb.py` | 驗證器自身的 unittest |

`references/controls-appendix10.md`（附表十全文）不在本計畫——僅產出 `checklist.md` 時才需要，屬後續計畫。

---

## Phase 1：地基

### Task 1：驗證 references 相對路徑可讀性

Spec 4.2 列為必須第一步驗證的阻擋項。若相對路徑不可讀，整個共用知識庫架構要改。

**Files:**
- Create: `security-compliance-tw/references/probe.txt`
- Create: `security-compliance-tw/skills/path-probe/SKILL.md`

- [ ] **Step 1: 建立探針檔**

```bash
mkdir -p security-compliance-tw/references
mkdir -p security-compliance-tw/skills/path-probe
printf 'PROBE_OK_7F3A\n' > security-compliance-tw/references/probe.txt
```

- [ ] **Step 2: 建立探針 skill**

寫入 `security-compliance-tw/skills/path-probe/SKILL.md`：

```markdown
---
name: path-probe
description: Internal probe to verify that a skill can read files two levels above its own directory. Use when explicitly asked to run the path probe.
---

# Path Probe

讀取本 skill 目錄上兩層的 `references/probe.txt`，把內容原樣回報。

路徑：`../../references/probe.txt`（相對於本 SKILL.md 所在目錄）

回報格式：`PROBE RESULT: <檔案內容>` 或 `PROBE FAILED: <錯誤>`
```

- [ ] **Step 3: 掛載到本機 skills 目錄**

```bash
ln -sfn security-compliance-tw/skills/path-probe ~/.claude/skills/path-probe
ls -l ~/.claude/skills/path-probe
```

預期輸出：symlink 指向專案內的 `path-probe` 目錄。

- [ ] **Step 4: 在新 session 呼叫探針並記錄結果**

在新的 Claude Code session 執行：`/path-probe`

預期：回報 `PROBE RESULT: PROBE_OK_7F3A`

若回報 FAILED，**停止並回報**——需依 spec 4.2 改為將 `references/` 置於
`skills/sec-audit/` 之下，後續所有任務的路徑要跟著改。

- [ ] **Step 5: 清除探針**

```bash
rm ~/.claude/skills/path-probe
rm -rf security-compliance-tw/skills/path-probe
rm security-compliance-tw/references/probe.txt
```

---

### Task 2：建立 plugin 骨架

**Files:**
- Create: `security-compliance-tw/.claude-plugin/plugin.json`
- Create: `security-compliance-tw/references/checks/.gitkeep`
- Create: `security-compliance-tw/tools/.gitkeep`

- [ ] **Step 1: 建立目錄**

```bash
cd security-compliance-tw
mkdir -p .claude-plugin skills/sec-audit references/checks tools
touch references/checks/.gitkeep tools/.gitkeep
```

- [ ] **Step 2: 寫 plugin.json**

寫入 `security-compliance-tw/.claude-plugin/plugin.json`：

```json
{
  "name": "security-compliance-tw",
  "version": "0.1.0",
  "description": "依台灣附表十資通系統防護基準與 OWASP Web/API/LLM Top 10，讓程式碼通過源碼掃描與弱點掃描",
  "author": { "name": "mikey" }
}
```

- [ ] **Step 3: 確認結構**

```bash
cd security-compliance-tw && find . -type f -o -type d | sort
```

預期：可見 `.claude-plugin/plugin.json`、`skills/sec-audit`、`references/checks`、`tools`。

---

### Task 3：驗證器——check 檔解析

**Files:**
- Create: `security-compliance-tw/tools/test_validate_kb.py`
- Create: `security-compliance-tw/tools/validate_kb.py`

- [ ] **Step 1: 寫失敗的測試**

寫入 `security-compliance-tw/tools/test_validate_kb.py`：

```python
import unittest
import tempfile
import pathlib
import validate_kb


class TestParseChecks(unittest.TestCase):
    def _write(self, text):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "sast-demo.md").write_text(text, encoding="utf-8")
        return d

    def test_extracts_check_ids(self):
        d = self._write(
            "# Demo\n\n"
            "## SAST-INJ-001 · SQL 指令注入\n\n"
            "### 掃描器怎麼標\nx\n\n"
            "### 壞味道\n```go\nx\n```\n```python\nx\n```\n```javascript\nx\n```\n\n"
            "### 過關寫法\n```go\nx\n```\n```python\nx\n```\n```javascript\nx\n```\n\n"
            "### 常見誤判與處置\nx\n\n"
            "### 判定準則\nx\n"
        )
        checks = validate_kb.parse_checks(d)
        self.assertEqual([c.id for c in checks], ["SAST-INJ-001"])
        self.assertEqual(checks[0].title, "SQL 指令注入")

    def test_rejects_malformed_id(self):
        d = self._write("## sast-inj-1 · 壞掉的 id\n")
        errors = validate_kb.validate_checks(validate_kb.parse_checks(d))
        self.assertTrue(any("id 格式" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 執行測試確認失敗**

```bash
cd security-compliance-tw/tools && python3 -m unittest test_validate_kb -v
```

預期：`ModuleNotFoundError: No module named 'validate_kb'`

- [ ] **Step 3: 寫最小實作**

寫入 `security-compliance-tw/tools/validate_kb.py`：

```python
"""知識庫結構與對應關係驗證器。純 stdlib，無外部相依。"""

import dataclasses
import pathlib
import re
import sys

CHECK_ID_RE = re.compile(r"^(SAST|DAST)-[A-Z]+-\d{3}$")
HEADING_RE = re.compile(r"^##\s+(\S+)\s+·\s+(.+?)\s*$", re.MULTILINE)

REQUIRED_SECTIONS = [
    "掃描器怎麼標",
    "壞味道",
    "過關寫法",
    "常見誤判與處置",
    "判定準則",
]

REQUIRED_LANGS = ["go", "python", "javascript"]


@dataclasses.dataclass
class Check:
    id: str
    title: str
    body: str
    source: str


def parse_checks(checks_dir):
    """讀取目錄下所有 .md，回傳 Check 清單，依 id 排序。"""
    checks = []
    for path in sorted(pathlib.Path(checks_dir).glob("*.md")):
        text = path.read_text(encoding="utf-8")
        matches = list(HEADING_RE.finditer(text))
        for i, m in enumerate(matches):
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            checks.append(
                Check(
                    id=m.group(1),
                    title=m.group(2),
                    body=text[m.end():end],
                    source=path.name,
                )
            )
    return sorted(checks, key=lambda c: c.id)


def validate_checks(checks):
    """回傳錯誤訊息清單。空清單代表通過。"""
    errors = []
    seen = set()

    for c in checks:
        where = f"{c.source} / {c.id}"

        if not CHECK_ID_RE.match(c.id):
            errors.append(f"{where}: id 格式不符 {{SAST|DAST}}-主題-三位數字")
            continue

        if c.id in seen:
            errors.append(f"{where}: check-id 重複")
        seen.add(c.id)

        for section in REQUIRED_SECTIONS:
            if f"### {section}" not in c.body:
                errors.append(f"{where}: 缺少「{section}」小節")

        # 註：此處檢查整則 check 的內文，未細分到「過關寫法」小節。
        # 涵蓋三語言即通過，屬刻意放寬的近似檢查。
        if c.id.startswith("SAST-"):
            for lang in REQUIRED_LANGS:
                if f"```{lang}" not in c.body:
                    errors.append(f"{where}: 缺少 {lang} 範例")

    return errors
```

- [ ] **Step 4: 執行測試確認通過**

```bash
cd security-compliance-tw/tools && python3 -m unittest test_validate_kb -v
```

預期：`OK`，2 個測試通過。

---

### Task 4：驗證器——mapping 雙向對應

**Files:**
- Modify: `security-compliance-tw/tools/test_validate_kb.py`（附加測試類別）
- Modify: `security-compliance-tw/tools/validate_kb.py`（附加函式與 CLI）

- [ ] **Step 1: 寫失敗的測試**

在 `test_validate_kb.py` 的 `if __name__` 之前插入：

```python
class TestMapping(unittest.TestCase):
    def _write_mapping(self, text):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "mapping.md").write_text(text, encoding="utf-8")
        return d / "mapping.md"

    def test_extracts_mapped_ids(self):
        p = self._write_mapping(
            "| check-id | 附表十 | 普 | 中 | 高 | Web21 | Web25 | API23 | LLM25 | CWE |\n"
            "|---|---|---|---|---|---|---|---|---|---|\n"
            "| SAST-INJ-001 | 4.5.3.1 | ◎ | ◎ | ◎ | A03 | A05 | — | LLM05 | CWE-89 |\n"
        )
        rows = validate_kb.parse_mapping(p)
        self.assertEqual(list(rows.keys()), ["SAST-INJ-001"])
        self.assertEqual(rows["SAST-INJ-001"]["附表十"], "4.5.3.1")

    def test_detects_missing_mapping(self):
        errors = validate_kb.cross_validate(["SAST-INJ-001"], {})
        self.assertTrue(any("未出現在 mapping" in e for e in errors))

    def test_detects_orphan_mapping(self):
        errors = validate_kb.cross_validate([], {"SAST-INJ-999": {}})
        self.assertTrue(any("找不到對應的 check" in e for e in errors))

    def test_requires_at_least_one_level(self):
        rows = {"SAST-INJ-001": {"普": "", "中": "", "高": ""}}
        errors = validate_kb.cross_validate(["SAST-INJ-001"], rows)
        self.assertTrue(any("至少一個分級" in e for e in errors))
```

- [ ] **Step 2: 執行測試確認失敗**

```bash
cd security-compliance-tw/tools && python3 -m unittest test_validate_kb -v
```

預期：`AttributeError: module 'validate_kb' has no attribute 'parse_mapping'`

- [ ] **Step 3: 寫實作**

在 `validate_kb.py` 末尾附加：

```python
MAPPING_COLUMNS = [
    "check-id", "附表十", "普", "中", "高",
    "Web21", "Web25", "API23", "LLM25", "CWE",
]


def parse_mapping(mapping_path):
    """解析 mapping.md 的表格，回傳 {check-id: {欄位: 值}}。"""
    rows = {}
    for line in pathlib.Path(mapping_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != len(MAPPING_COLUMNS):
            continue
        if cells[0] in ("check-id", "") or set(cells[0]) <= set("- :"):
            continue
        rows[cells[0]] = dict(zip(MAPPING_COLUMNS, cells))
    return rows


def cross_validate(check_ids, mapping_rows):
    """比對 check 與 mapping 的雙向對應。回傳錯誤訊息清單。"""
    errors = []

    for cid in check_ids:
        if cid not in mapping_rows:
            errors.append(f"{cid}: 未出現在 mapping.md")

    for cid in mapping_rows:
        if cid not in check_ids:
            errors.append(f"{cid}: mapping.md 有此列，但找不到對應的 check")

    for cid, row in mapping_rows.items():
        if cid not in check_ids:
            continue
        if not any(row.get(lv, "").strip() for lv in ("普", "中", "高")):
            errors.append(f"{cid}: 至少一個分級欄位必須標記 ◎")

    return errors


def main():
    root = pathlib.Path(__file__).resolve().parent.parent / "references"
    checks = parse_checks(root / "checks")
    errors = validate_checks(checks)

    mapping_path = root / "mapping.md"
    if mapping_path.exists():
        errors += cross_validate([c.id for c in checks], parse_mapping(mapping_path))
    else:
        errors.append("references/mapping.md 不存在")

    if errors:
        print(f"知識庫驗證失敗（{len(errors)} 項）：")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"知識庫驗證通過：{len(checks)} 則 check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: 執行測試確認通過**

```bash
cd security-compliance-tw/tools && python3 -m unittest test_validate_kb -v
```

預期：`OK`，6 個測試通過。

- [ ] **Step 5: 對真實（空）知識庫執行 CLI**

```bash
cd security-compliance-tw && python3 tools/validate_kb.py
```

預期：退出碼 1，輸出 `- references/mapping.md 不存在`。
這是正確的——內容還沒寫。此為後續任務的驗收靶。

---

## Phase 2：第一條垂直切片

### Task 5：scanners.md

**Files:**
- Create: `security-compliance-tw/references/scanners.md`

- [ ] **Step 1: 寫入檔案**

```markdown
# 掃描工具行為特性

本檔說明各類掃描器的判定方式與誤判習性，供判讀掃描報告時參考。
**本 plugin 不執行任何掃描工具**——掃描由人執行。

## 商用 SAST

### Fortify SCA
- 判定方式：污點分析（taint analysis），追蹤資料從 source 流向 sink 的路徑
- 等級：Critical / High / Medium / Low
- 習性：偏保守，寧可多報。自訂的消毒函式（custom sanitizer）追不出來，
  除非在 Fortify 的 rulepack 中註冊為 cleanse rule
- 誤判處置：在 Audit Workbench 中標記為 Not an Issue 並填寫理由，
  該判定會寫入 `.fpr`，複掃時保留

### Checkmarx
- 判定方式：以 CxQL 查詢語言對程式碼圖譜（AST + DFG）比對
- 等級：High / Medium / Low / Information
- 習性：對框架的內建防護辨識度較 Fortify 好，但對動態語言誤判偏多
- 誤判處置：於結果介面標記 Not Exploitable，可設定為跨掃描持續

## 開源 SAST

| 工具 | 語言 | 判定方式 | 等級 |
|---|---|---|---|
| Semgrep | 多語 | 語法樣式比對（部分規則支援 taint mode） | ERROR / WARNING / INFO |
| SonarQube | 多語 | 規則引擎 + 部分資料流分析 | Blocker / Critical / Major / Minor |
| CodeQL | 多語 | 對程式碼資料庫下 QL 查詢，資料流分析完整 | error / warning / note |
| gosec | Go | AST 規則比對，無跨函式資料流 | HIGH / MEDIUM / LOW |
| bandit | Python | AST 規則比對，無跨函式資料流 | HIGH / MEDIUM / LOW |

gosec 與 bandit 只看單一函式內的樣式，把不安全操作包進 helper 函式就會漏報——
**這代表「gosec 沒報」不等於「Fortify 不會報」**。判讀時以資料流分析工具為準。

## DAST / 弱點掃描

| 工具 | 觀察對象 |
|---|---|
| Acunetix WVS | HTTP 回應標頭、錯誤頁內容、表單注入回應、Cookie 屬性 |
| Nessus | 服務版本指紋、TLS 組態、已知 CVE |
| OWASP ZAP | 同 AWVS，另含被動掃描規則 |
| HP WebInspect | 同 AWVS |

DAST 完全看不到源碼，只看執行期表現。因此 DAST 家族的 check
偵測的是**決定執行期行為的程式碼與設定**：middleware 註冊順序、
標頭設定、Cookie flags、錯誤處理器、TLS 組態。

## 誤判處置的共同原則

標記誤判前必須確認三件事，缺一不可：

1. 資料實際上不可控（來源為常數、列舉、或已通過白名單驗證）
2. 該路徑上確實存在有效的消毒或參數化，只是工具追不到
3. 有具體佐證可寫入 `false-positives.md`：檔案位置、資料來源、消毒點

若三者無法同時滿足，視為真漏洞處理。
```

- [ ] **Step 2: 確認檔案存在且非空**

```bash
wc -l security-compliance-tw/references/scanners.md
```

預期：行數大於 50。

---

### Task 6：sast-injection.md

**Files:**
- Create: `security-compliance-tw/references/checks/sast-injection.md`

- [ ] **Step 1: 寫入檔案**

````markdown
# SAST：注入類

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## SAST-INJ-001 · SQL 指令注入

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | SQL Injection | Critical |
| Checkmarx | SQL_Injection | High |
| Semgrep | `*.security.*.string-formatted-query` / `*.sql-injection*` | ERROR |
| SonarQube | S3649 | Blocker |
| gosec | G201（SQL 字串格式化）/ G202（SQL 字串串接） | HIGH |
| bandit | B608 | MEDIUM |
| AWVS / ZAP | SQL Injection | High |

### 壞味道

```go
q := "SELECT * FROM users WHERE name = '" + name + "'"
rows, _ := db.Query(q)

q2 := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
rows2, _ := db.Query(q2)
```

```python
cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
cur.execute("SELECT * FROM users WHERE id = " + str(user_id))
```

```javascript
db.query("SELECT * FROM users WHERE name = '" + name + "'");
db.query(`SELECT * FROM users WHERE id = ${userId}`);
```

### 過關寫法

關鍵不是「有沒有消毒」，而是**驅動層的參數化**——污點分析引擎對
標準函式庫的 placeholder 有內建 cleanse 規則，對自製 escape helper 沒有。

```go
rows, err := db.Query("SELECT * FROM users WHERE name = ?", name)

// 動態欄位名無法參數化時，用白名單映射，不要拼接使用者輸入
var allowedSort = map[string]string{"name": "name", "created": "created_at"}
col, ok := allowedSort[req.SortBy]
if !ok {
    return ErrInvalidSort
}
rows, err = db.Query("SELECT * FROM users ORDER BY " + col)
```

```python
cur.execute("SELECT * FROM users WHERE name = %s", (name,))
cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))

ALLOWED_SORT = {"name": "name", "created": "created_at"}
col = ALLOWED_SORT.get(req.sort_by)
if col is None:
    raise ValueError("invalid sort")
cur.execute(f"SELECT * FROM users ORDER BY {col}")
```

```javascript
await db.query("SELECT * FROM users WHERE name = ?", [name]);
await client.query("SELECT * FROM users WHERE id = $1", [userId]);
```

### 常見誤判與處置

- **常數或列舉組成的查詢**——SQL 完全由程式內常數組成，無外部輸入。
  gosec 的 G201 只看是否用了 `fmt.Sprintf`，不看參數來源，必然誤報。
  處置：改用常數字串直接傳入，消除格式化動作。

- **ORM 的 raw 查詢已參數化**——`gorm.Raw("... WHERE id = ?", id)`
  部分工具版本辨識不出 gorm 的 placeholder。
  處置：確認 placeholder 語法正確後標記誤判，佐證寫明 ORM 版本與參數繫結位置。

- **白名單映射後的欄位名拼接**——如上方過關寫法的排序範例。
  拼接的是 map 的 **value**（程式內常數），非使用者輸入。
  處置：標記誤判，佐證寫明白名單定義位置與 `ok` 檢查行號。
  **前提是白名單查不到時必須回傳錯誤**，若查不到時 fallback 用原輸入，就是真漏洞。

### 判定準則

真漏洞：SQL 字串中存在任何來自 HTTP 請求、檔案、資料庫、環境變數的值，
且該值未經白名單映射或未走驅動層 placeholder。

誤判：拼接進 SQL 的值可回溯到程式內常數（含白名單 map 的 value），
或已由驅動層 placeholder 承載。

灰色地帶——**一律當真漏洞修**：值來自其他內部服務的回應、
或來自資料庫但該欄位曾由使用者寫入（二階注入）。

---

## SAST-INJ-002 · 作業系統命令注入

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | Command Injection | Critical |
| Checkmarx | Command_Injection | High |
| Semgrep | `*.security.*.command-injection*` | ERROR |
| SonarQube | S2076 | Blocker |
| gosec | G204 | HIGH |
| bandit | B602（shell=True）/ B605 | HIGH |
| AWVS / ZAP | OS Command Injection | High |

### 壞味道

```go
exec.Command("sh", "-c", "convert "+userFile+" out.png").Run()
exec.Command("/bin/bash", "-c", cmdFromRequest).Run()
```

```python
os.system("convert " + user_file + " out.png")
subprocess.run(f"convert {user_file} out.png", shell=True)
subprocess.Popen("ls " + path, shell=True)
```

```javascript
const { exec } = require("child_process");
exec("convert " + userFile + " out.png");
```

### 過關寫法

核心是**不要經過 shell**。把參數當成 argv 陣列傳入，shell 不介入就沒有
metacharacter 可以逃逸，資料流分析也會把 sink 從「shell 命令」降級為「程式參數」。

```go
// 不經 shell，參數逐一傳入
cmd := exec.Command("convert", userFile, "out.png")
if err := cmd.Run(); err != nil {
    return err
}
```

```python
subprocess.run(["convert", user_file, "out.png"], shell=False, check=True)
```

```javascript
const { execFile } = require("child_process");
execFile("convert", [userFile, "out.png"], (err, stdout) => { /* ... */ });
```

若參數是檔案路徑，另外加上路徑正規化與根目錄限制（見 SAST-INJ-003）。

### 常見誤判與處置

- **命令與參數全為常數**——gosec G204 只要看到 `exec.Command` 的參數
  不是字面常數就報，即使該變數來自設定檔常數。
  處置：若確為程式內常數，標記誤判並註明變數定義位置。

- **參數已通過嚴格白名單**——例如只允許 `["png", "jpg"]` 之一。
  處置：標記誤判，佐證寫明白名單與拒絕分支。

### 判定準則

真漏洞：命令字串或參數含外部輸入，**且**透過 `sh -c` / `shell=True` /
`exec()` 執行。

真漏洞（即使不經 shell）：外部輸入被當成**命令本身**（argv[0]），
而非參數——此時攻擊者可指定任意執行檔。

誤判：不經 shell，且外部輸入僅作為參數傳入，且已限制其取值範圍。

---

## SAST-INJ-003 · 路徑尋訪

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| Fortify | Path Manipulation | Critical |
| Checkmarx | Path_Traversal | High |
| Semgrep | `*.security.*.path-traversal*` | ERROR |
| SonarQube | S2083 | Blocker |
| gosec | G304（以變數開檔） | MEDIUM |
| bandit | —（無專屬規則，靠 Semgrep/CodeQL 補） | — |
| AWVS / ZAP | Directory Traversal | High |

### 壞味道

```go
data, _ := os.ReadFile("/var/data/" + r.URL.Query().Get("file"))
http.ServeFile(w, r, filepath.Join("/var/data", r.URL.Path))
```

```python
with open("/var/data/" + request.args["file"]) as f:
    data = f.read()
path = os.path.join("/var/data", user_input)
```

```javascript
fs.readFile("/var/data/" + req.query.file, cb);
res.sendFile(path.join("/var/data", req.params.name));
```

`filepath.Join` 與 `os.path.join` **不會**擋 `../`——這是最常見的誤解。
`Join` 只做路徑正規化，`/var/data` + `../../etc/passwd` 會正規化成 `/etc/passwd`。

### 過關寫法

樣式是固定的三步：正規化 → 確認仍在根目錄內 → 才開檔。
資料流分析引擎認得「比對後才使用」這個結構。

```go
root := "/var/data"
target := filepath.Join(root, filepath.Clean("/"+userInput))
if !strings.HasPrefix(target, filepath.Clean(root)+string(os.PathSeparator)) {
    return ErrForbidden
}
data, err := os.ReadFile(target)
```

```python
import os

root = os.path.realpath("/var/data")
target = os.path.realpath(os.path.join(root, user_input))
if not (target == root or target.startswith(root + os.sep)):
    raise PermissionError("path escapes root")
with open(target) as f:
    data = f.read()
```

```javascript
const path = require("path");
const root = path.resolve("/var/data");
const target = path.resolve(root, userInput);
if (target !== root && !target.startsWith(root + path.sep)) {
  throw new Error("path escapes root");
}
fs.readFile(target, cb);
```

更穩的做法是完全不接受路徑：讓使用者傳識別碼，由程式查表得到實際檔名。
這會讓污點路徑徹底斷開，多數工具直接不報。

### 常見誤判與處置

- **路徑來自資料庫且由系統產生**——例如上傳時以 UUID 命名、
  資料庫只存 UUID。gosec G304 看到變數開檔就報。
  處置：標記誤判，佐證寫明檔名產生位置與格式限制。

- **已做前綴檢查但工具追不到**——如上方過關寫法。
  部分 Fortify 版本認不得 `strings.HasPrefix` 的守衛。
  處置：標記誤判，佐證寫明守衛的行號與拒絕分支。

### 判定準則

真漏洞：開檔或送檔的路徑含外部輸入，且**沒有**在開檔前做根目錄前綴比對。

真漏洞：有做比對但比對的是**正規化前**的字串（先檢查再 `Join`，順序錯了）。

誤判：路徑完全由系統產生，或已在正規化**之後**做前綴比對且不符時中止。
````

- [ ] **Step 2: 執行驗證器（預期因 mapping 缺失而失敗）**

```bash
cd security-compliance-tw && python3 tools/validate_kb.py
```

預期：退出碼 1，錯誤包含 `references/mapping.md 不存在`。
**check 檔本身不應出現「缺少小節」或「缺少範例」錯誤**——若有，先修 check 檔。

---

### Task 7：mapping.md

**Files:**
- Create: `security-compliance-tw/references/mapping.md`

- [ ] **Step 1: 寫入檔案**

```markdown
# check-id 對照表

本檔是 check-id 與各風險清單編號的**唯一**對照來源。
`checks/` 內不得出現任何法規或 OWASP 編號。

- 分級欄（普 / 中 / 高）依附表十的適用等級標記 ◎
- 附表十欄標「—（缺口）」者，表示該風險掃描器會抓，但附表十查檢表上無對應項

| check-id | 附表十 | 普 | 中 | 高 | Web21 | Web25 | API23 | LLM25 | CWE |
|---|---|---|---|---|---|---|---|---|---|
| SAST-INJ-001 | 4.5.3.1 | ◎ | ◎ | ◎ | A03 | A05 | — | LLM05 | CWE-89 |
| SAST-INJ-002 | 4.5.3.1 | ◎ | ◎ | ◎ | A03 | A05 | — | LLM05 | CWE-78 |
| SAST-INJ-003 | 4.1 | ◎ | ◎ | ◎ | A01 | A01 | — | — | CWE-22 |
| DAST-HDR-001 | 4.5.3.4 | | ◎ | ◎ | A05 | A02 | API8 | — | CWE-693 |
| DAST-HDR-002 | 4.5.3.4 | | ◎ | ◎ | A05 | A02 | API8 | — | CWE-319 |
| DAST-HDR-003 | 4.5.3.4 | | ◎ | ◎ | A05 | A02 | API8 | — | CWE-1021 |

## 版本註記

- **Web21** = OWASP Top 10:2021。指引 V3.2 的對應版本，法遵稽核以此為準。
- **Web25** = OWASP Top 10:2025。定稿狀態需核對 owasp.org/Top10；
  SSRF 已併入 A01，注入降至 A05，新增供應鏈（A03）與例外處理（A10）。
- **API23** = OWASP API Security Top 10:2023。
- **LLM25** = OWASP Top 10 for LLM Applications:2025。
```

- [ ] **Step 2: 執行驗證器（預期因 DAST check 未建立而失敗）**

```bash
cd security-compliance-tw && python3 tools/validate_kb.py
```

預期：退出碼 1，錯誤為三則 `DAST-HDR-00x: mapping.md 有此列，但找不到對應的 check`。
這正是雙向驗證在運作——mapping 先寫了，check 還沒補。

---

### Task 8：dast-headers.md

**Files:**
- Create: `security-compliance-tw/references/checks/dast-headers.md`

- [ ] **Step 1: 寫入檔案**

````markdown
# DAST：HTTP 安全標頭

DAST 掃描器看不到源碼，只看回應標頭。因此本檔的偵測對象是
**設定標頭的那段程式碼或設定檔**，據以預判掃描器會看到什麼。

## DAST-HDR-001 · 缺少 Content-Security-Policy

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| AWVS | Content Security Policy not implemented | Medium |
| ZAP | Content Security Policy (CSP) Header Not Set | Medium |
| WebInspect | Missing Content-Security-Policy Header | Medium |
| Nessus | Missing or Permissive CSP | Medium |
| SecurityHeaders.com | 評分扣分（無 CSP 難以達 A） | — |

### 壞味道

回應中完全沒有 `Content-Security-Policy`，或設成過寬的值：

```go
// 沒有任何 CSP 設定的 handler
func handler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("<html>..."))
}
```

```python
# Flask 未掛任何 after_request 標頭處理
@app.route("/")
def index():
    return render_template("index.html")
```

```javascript
// Express 未使用 helmet 或手動設定標頭
app.get("/", (req, res) => res.send("<html>..."));
```

以下設定值等同沒設，掃描器仍會標記：
`default-src *`、`script-src 'unsafe-inline' 'unsafe-eval' *`、只設 `report-uri`

### 過關寫法

集中在 middleware 一次設定，不要散在各 handler——散開設定會漏，
DAST 只要掃到一個沒有標頭的路徑就會標記。

```go
func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Security-Policy",
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'")
        next.ServeHTTP(w, r)
    })
}
// 掛載：mux 外層包一次，涵蓋所有路由
srv := &http.Server{Handler: securityHeaders(mux)}
```

```python
@app.after_request
def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; object-src 'none'; "
        "frame-ancestors 'none'; base-uri 'self'"
    )
    return resp
```

```javascript
const helmet = require("helmet");
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    objectSrc: ["'none'"],
    frameAncestors: ["'none'"],
    baseUri: ["'self'"],
  },
}));
```

### 常見誤判與處置

- **前後端分離、CSP 由前端 CDN 或 Nginx 設定**——掃描器打的是 API 網域，
  該網域回傳 JSON 不需要 CSP，但工具照樣標記。
  處置：對純 API 網域仍設 `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
  ——一行解決，比寫誤判說明省事。

- **CSP 半套被判高風險**——這是指引附件 3 明確警告的情形：
  只設部分指令（如未定義 `default-src`）會讓工具基於保守假設放大風險。
  處置：**補完而非移除**。至少定義 `default-src`、`object-src`、
  `frame-ancestors`、`base-uri` 四項。

- **必須保留 `'unsafe-inline'`**——舊架構把腳本內嵌在 HTML 中。
  處置：這是真實的架構限制，不是誤判。若無法改為外部腳本，
  在 `false-positives.md` 記錄為「已知風險接受」並註明架構原因，
  同時把其他指令收緊到最嚴，降低整體評分衝擊。

### 判定準則

真問題：任何會回傳 HTML 的路徑，其回應缺少 `Content-Security-Policy`。

真問題：CSP 存在但 `default-src` 未定義，或 `script-src` 含 `*` 萬用來源。

可接受：CSP 完整定義四項核心指令，`'unsafe-inline'` 僅出現在
`style-src` 且有架構原因記錄在案。

---

## DAST-HDR-002 · 缺少 Strict-Transport-Security

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| AWVS | HSTS not enabled | Medium |
| ZAP | Strict-Transport-Security Header Not Set | Low–Medium |
| WebInspect | Missing HSTS Header | Medium |
| Nessus | Missing HSTS | Medium |

### 壞味道

HTTPS 回應中沒有 `Strict-Transport-Security`，或 `max-age` 過短
（低於 31536000 常被標為 weak configuration）。

```go
// 只設了其他標頭，漏掉 HSTS
w.Header().Set("X-Frame-Options", "DENY")
```

```python
resp.headers["X-Frame-Options"] = "DENY"  # 缺 HSTS
```

```javascript
app.use(helmet({ hsts: false }));  // 明確關閉
```

### 過關寫法

```go
w.Header().Set("Strict-Transport-Security",
    "max-age=31536000; includeSubDomains")
```

```python
resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
```

```javascript
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
```

`preload` 視情況加。加了之後要提交到 hstspreload.org，且**很難撤銷**——
子網域全部必須支援 HTTPS，否則會全站無法存取。指引建議先不鎖太久，
驗證穩定後再拉長。

### 常見誤判與處置

- **服務只在內網以 HTTP 提供**——HSTS 在 HTTP 回應中無效，
  瀏覽器會忽略。掃描器仍可能標記。
  處置：若確實不對外，標記誤判並註明部署範圍；
  但若有任何對外可能，直接改用 HTTPS 並設 HSTS。

- **TLS 由前端負載平衡器終結**——應用程式看到的是 HTTP。
  處置：在 LB 或反向代理層設定標頭，並在佐證中註明設定位置。

### 判定準則

真問題：對外提供 HTTPS 服務，但回應缺少 HSTS 或 `max-age` 小於 31536000。

誤判：純內網 HTTP 服務，且無對外路徑。

---

## DAST-HDR-003 · 缺少 X-Frame-Options 或 frame-ancestors

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 |
|---|---|---|
| AWVS | Clickjacking: X-Frame-Options header missing | Medium |
| ZAP | Missing Anti-clickjacking Header | Medium |
| WebInspect | Missing X-Frame-Options Header | Medium |
| Nessus | Web Application Potentially Vulnerable to Clickjacking | Medium |

### 壞味道

回應缺少 `X-Frame-Options`，且 CSP 中也沒有 `frame-ancestors`。

```go
w.Header().Set("Content-Security-Policy", "default-src 'self'")  // 缺 frame-ancestors
```

```python
resp.headers["Content-Security-Policy"] = "default-src 'self'"  # 缺 frame-ancestors
```

```javascript
app.use(helmet({ frameguard: false }));
```

`X-Frame-Options: ALLOW-FROM` 已被現代瀏覽器廢棄，設了等於沒設。

### 過關寫法

兩者都設——舊掃描器只認 `X-Frame-Options`，新的認 `frame-ancestors`。

```go
w.Header().Set("X-Frame-Options", "DENY")
w.Header().Set("Content-Security-Policy",
    "default-src 'self'; frame-ancestors 'none'")
```

```python
resp.headers["X-Frame-Options"] = "DENY"
resp.headers["Content-Security-Policy"] = (
    "default-src 'self'; frame-ancestors 'none'"
)
```

```javascript
app.use(helmet.frameguard({ action: "deny" }));
app.use(helmet.contentSecurityPolicy({
  directives: { defaultSrc: ["'self'"], frameAncestors: ["'none'"] },
}));
```

需要允許同源嵌入時用 `SAMEORIGIN` + `frame-ancestors 'self'`；
需要允許特定網域時**只能**用 `frame-ancestors https://partner.example.com`。

### 常見誤判與處置

- **已用 CSP frame-ancestors，但工具只找 X-Frame-Options**——
  舊版 AWVS / Nessus 常見。
  處置：兩個都設，比寫誤判說明省事。

- **該頁面本來就設計為被 iframe 嵌入**（如金流元件、地圖嵌入）。
  處置：設 `frame-ancestors` 明列允許的網域，不要留空。
  留空會被標記，明列則多數工具接受。

### 判定準則

真問題：回傳 HTML 的路徑同時缺少 `X-Frame-Options` 與 CSP `frame-ancestors`。

真問題：使用 `X-Frame-Options: ALLOW-FROM`（已廢棄，無效）。

誤判：已設 `frame-ancestors` 且明列允許來源，僅因工具版本舊而被標記。
````

- [ ] **Step 2: 執行驗證器（預期通過）**

```bash
cd security-compliance-tw && python3 tools/validate_kb.py
```

預期：退出碼 0，輸出 `知識庫驗證通過：6 則 check`。

---

### Task 9：profile.md

**Files:**
- Create: `security-compliance-tw/references/profile.md`

- [ ] **Step 1: 寫入檔案**

```markdown
# 專案 profile 與 check 集合選取

## 分級問答

**每次啟動都問，不推測、不寫設定檔。** 一次問完六題，不逐題往返。

1. **安全分級**：普 / 中 / 高
   （依「資通安全責任等級分級辦法附表九」由機關核定。若使用者不確定，
   請其查驗收文件；仍不確定則以「中」進行並在報告首頁註明此假設。）
2. 是否對外提供服務（公開網際網路可存取）？
3. 是否有 API 端點（REST / GraphQL / gRPC）？
4. 是否有 LLM / RAG / Agent 功能？
5. 是否處理個人資料或金流？
6. 已知將面對哪些掃描器？（可答不知道）

## 分級的實質差異

以下項目**僅高等級要求**，普/中等級不應報告，否則產生大量不適用雜訊：

- 多重因素身分鑑別
- 資訊系統備援採高可用性架構
- 滲透測試
- 機敏資料靜態加密
- 重要資料或紀錄留存雜湊值
- 自動化工具監控進出通信流量
- 稽核失效即時告警

以下僅中/高等級要求：

- 最小權限（使用者/角色、程序執行權限）
- 圖形驗證碼
- 密碼重設一次性時效令牌
- 密碼加 Salt 雜湊
- 開發/測試/正式環境區隔
- 伺服器端正規表示式輸入驗證

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

**本計畫階段只有 `sast-injection.md` 與 `dast-headers.md` 存在。**
規則表中其他檔案尚未建立——遇到時跳過並在報告中註明「該類別尚未涵蓋」，
不要捏造內容。

## 語言對應

讀取專案根目錄判定技術棧：

| 檔案 | 語言 | 取用的範例區塊 |
|---|---|---|
| `go.mod` | Go | ` ```go ` |
| `requirements.txt` / `pyproject.toml` / `Pipfile` | Python | ` ```python ` |
| `package.json` | JavaScript | ` ```javascript ` |

多語言專案全部載入。找不到任何一種時，詢問使用者。
```

- [ ] **Step 2: 確認驗證器仍通過**

```bash
cd security-compliance-tw && python3 tools/validate_kb.py
```

預期：退出碼 0，`知識庫驗證通過：6 則 check`。

---

### Task 10：references/README.md

**Files:**
- Create: `security-compliance-tw/references/README.md`

- [ ] **Step 1: 寫入檔案**

```markdown
# 知識庫導覽

本目錄由 `skills/` 下的各 skill 共用。路徑相對於 skill 目錄為 `../../references/`。

| 要做什麼 | 讀哪個檔 |
|---|---|
| 決定專案分級、決定要載入哪些 check | `profile.md` |
| 判斷某個掃描工具的習性與誤判處置慣例 | `scanners.md` |
| 查某個壞味道怎麼偵測、怎麼修 | `checks/*.md` |
| 把 check-id 換成附表十或 OWASP 編號 | `mapping.md` |

## 設計約束

1. **`checks/` 內不得出現法規或 OWASP 編號。** 對照關係一律放 `mapping.md`。
   理由：同一個壞味道對映四張清單，內嵌編號會導致清單改版時需修改全部 check 檔。

2. **每則 check 必須有五個小節**：掃描器怎麼標 / 壞味道 / 過關寫法 /
   常見誤判與處置 / 判定準則。

3. **SAST 類 check 的範例必須涵蓋 Go、Python、JavaScript 三種。**

4. **check-id 格式**：`{SAST|DAST}-{主題縮寫}-{三位數字}`，一經發布不得變更。

以上四點由 `../tools/validate_kb.py` 自動驗證。新增或修改 check 後執行：

    cd security-compliance-tw && python3 tools/validate_kb.py

## 目前涵蓋範圍

| check 檔 | 狀態 |
|---|---|
| `sast-injection.md` | 已完成（SQLi / OS Command / 路徑尋訪） |
| `dast-headers.md` | 已完成（CSP / HSTS / Clickjacking） |
| 其餘 9 個檔 | 未建立，見 spec 第 4 節 |
```

- [ ] **Step 2: 確認檔案存在**

```bash
ls -1 security-compliance-tw/references/
```

預期：`README.md`、`checks`、`mapping.md`、`profile.md`、`scanners.md`。

---

### Task 11：sec-audit SKILL.md

**Files:**
- Create: `security-compliance-tw/skills/sec-audit/SKILL.md`

- [ ] **Step 1: 寫入檔案**

````markdown
---
name: sec-audit
description: 依台灣附表十資通系統防護基準與 OWASP Web/API/LLM Top 10 檢視程式碼，讓專案通過源碼掃描（Fortify/Checkmarx/Semgrep/gosec/bandit）與弱點掃描（AWVS/Nessus/ZAP）。送掃之前用來預防被標紅字，拿到掃描報告之後用來逐項判定真漏洞或誤判並修補。Use when the user mentions 源碼掃描, 弱點掃描, 資安稽核, 附表十, OWASP, Fortify, Checkmarx, AWVS, 驗收, or asks to make code pass a security scan.
---

# sec-audit

**目標：讓程式碼通過掃描，不需要與稽核人員逐項協調。**

本 skill 不執行任何掃描工具。掃描由人執行。

## 判定準則（最重要）

預設路徑是**真的修好，而且用掃描器追得到的方式修好**。

只有在同時滿足以下三點時，才走誤判標記：

1. 資料實際不可控（來源為常數、列舉，或已通過白名單驗證）
2. 路徑上確實有有效的消毒或參數化，只是工具追不到
3. 有具體佐證可寫入報告：檔案位置、資料來源、消毒點行號

三點無法同時滿足就當真漏洞修。不採用單純遮蔽結果讓紅字消失的做法——
附表十每項的查核方式都同時要求自動化工具檢測**與**人工審查，遮蔽會在人工審查破功。

## 兩個模式

**有掃描報告檔案 → 模式 2。沒有 → 模式 1。情境不明就直接問。**

## 模式 1：送掃之前

1. **建立 profile**——依 `../../references/profile.md` 的問答腳本，一次問完六題
2. **偵測技術棧**——讀 `go.mod` / `requirements.txt` / `package.json`
3. **選定 check 集合**——依 `profile.md` 的選取規則決定載入哪些 `checks/*.md`。
   **只載入需要的檔案**，這是控制 context 的關鍵
4. **樣式比對**——用 check 檔內「壞味道」區塊的樣式在 codebase 搜尋
5. **逐項判定**——每個命中歸為：真漏洞 / 誤判 / 不適用，各自記錄理由
6. **修補**——**先列出待修清單與影響檔案數，取得使用者確認後才動手**。
   依 check 檔的「過關寫法」修改。優先序 = 掃描器預設等級 × 專案分級
7. **產出**——見下方

## 模式 2：拿到掃描報告之後

1. 讀取使用者提供的報告檔（csv / txt 優先支援；html / pdf 盡力解析）
2. 取出每項發現的規則名稱、等級、檔案位置
3. 以各 check 的「掃描器怎麼標」表格反查 check-id
   （找不到對應的 check 時，明確標示「本知識庫尚未涵蓋」，不要猜測）
4. 依該 check 的「判定準則」逐項判定
5. 真漏洞依「過關寫法」修補；誤判產出佐證
6. **產出**——見下方

## 產出

寫入專案根目錄的 `security-audit/`：

- `findings.md`——逐項：check-id / 檔案位置 / 判定 / 處置
- `false-positives.md`——誤判清單與佐證，供複掃與人工審查使用
- `checklist.md`——附表十勾稽表（使用者要求時才產出，經 `mapping.md` 回貼）

## 知識庫

全部位於 `../../references/`：

| 檔案 | 何時讀 |
|---|---|
| `profile.md` | 步驟 1 與 3，一定要讀 |
| `checks/*.md` | 依 profile 選取，只讀需要的 |
| `scanners.md` | 判讀報告或處理誤判時 |
| `mapping.md` | 產 `checklist.md` 或需要法規編號時才讀 |

**不要一次載入所有 check 檔。**

## 目前涵蓋範圍

只有 `sast-injection.md`（SQLi / OS Command / 路徑尋訪）與
`dast-headers.md`（CSP / HSTS / Clickjacking）。

其他類別尚未建立。遇到超出範圍的項目時，明確告知使用者
「此類別本知識庫尚未涵蓋」，**不要憑印象生成建議**——
本 skill 的價值在於答案來自經過驗證的知識庫。
````

- [ ] **Step 2: 掛載到本機**

```bash
ln -sfn security-compliance-tw/skills/sec-audit ~/.claude/skills/sec-audit
ls -l ~/.claude/skills/sec-audit
```

預期：symlink 指向專案內的 `sec-audit` 目錄。

---

### Task 12：端到端驗收

**Files:**
- Create: `security-compliance-tw/testdata/sample-go/main.go`
- Create: `security-compliance-tw/testdata/sample-go/go.mod`

- [ ] **Step 1: 建立含已知漏洞的樣本專案**

```bash
mkdir -p security-compliance-tw/testdata/sample-go
```

寫入 `testdata/sample-go/go.mod`：

```
module sample

go 1.22
```

寫入 `testdata/sample-go/main.go`：

```go
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

var db *sql.DB

// 應命中 SAST-INJ-001
func getUser(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	q := "SELECT * FROM users WHERE name = '" + name + "'"
	rows, _ := db.Query(q)
	defer rows.Close()
	fmt.Fprintln(w, "ok")
}

// 應命中 SAST-INJ-002
func convert(w http.ResponseWriter, r *http.Request) {
	f := r.URL.Query().Get("file")
	exec.Command("sh", "-c", "convert "+f+" out.png").Run()
}

// 應命中 SAST-INJ-003
func readFile(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile("/var/data/" + r.URL.Query().Get("file"))
	w.Write(data)
}

// 應命中 DAST-HDR-001 / 002 / 003：沒有任何安全標頭 middleware
func main() {
	http.HandleFunc("/user", getUser)
	http.HandleFunc("/convert", convert)
	http.HandleFunc("/file", readFile)
	http.ListenAndServe(":8080", nil)
}
```

- [ ] **Step 2: 在新 session 對樣本專案執行 skill**

開啟新的 Claude Code session，切到 `security-compliance-tw/testdata/sample-go`，
執行：`/sec-audit`

回答 profile 問題：分級「中」、對外服務「是」、無 API 端點、無 LLM、無個資、掃描器「不知道」。

- [ ] **Step 3: 驗收判準**

skill 的行為必須符合以下全部條件，缺一即為未通過：

- 一次問完六題 profile，未逐題往返
- 依規則只載入 `sast-injection.md` 與 `dast-headers.md`，未載入不存在的檔案
- 找出全部三個 SAST 命中（INJ-001 / 002 / 003），位置正確
- 指出缺少安全標頭 middleware（HDR-001 / 002 / 003）
- **修補前先列清單並徵求確認**，未直接動手改檔
- 明確聲明未涵蓋的類別（如授權、加密、Session），未憑印象生成建議

任一條不符，回頭修 `SKILL.md` 或對應的 check 檔，重跑本任務。

- [ ] **Step 4: 確認產出**

```bash
ls -1 security-compliance-tw/testdata/sample-go/security-audit/
```

預期：`findings.md` 與 `false-positives.md`。

- [ ] **Step 5: 最終驗證**

```bash
cd security-compliance-tw && python3 tools/validate_kb.py && python3 -m unittest discover tools -v
```

預期：知識庫驗證通過 6 則 check，且 6 個 unittest 全數 OK。

---

## 完成後的狀態

- `security-compliance-tw/` 為完整 plugin 目錄，日後 `git init` 可直接推上 GitHub
- `~/.claude/skills/sec-audit` symlink 指向專案內，本機立即可用
- 知識庫涵蓋 6 則 check，結構由驗證器把關
- 後續新增 check 檔的流程固定：寫 check → 補 mapping → 跑驗證器 → 更新
  `README.md` 的涵蓋範圍表與 `SKILL.md` 的涵蓋範圍段落

## 下一步計畫的候選

1. 其餘 9 個 check 檔（同一套模式，可平行進行）
2. `controls-appendix10.md` 與 `checklist.md` 產出功能
3. skill B（sec-harden）與 `quick-patterns.md`
