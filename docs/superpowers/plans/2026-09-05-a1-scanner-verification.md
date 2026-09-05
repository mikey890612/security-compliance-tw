# A1 Scanner Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make open-source scanner rule names in the knowledge base verifiable (and verified where we can run tools), mark commercial scanner rows as `unverified`, and document how to upgrade them later from real reports—without inventing Fortify/Checkmarx evidence.

**Architecture:** Extend each check’s「掃描器怎麼標」table with `狀態` / `證據` columns; enforce the schema in `validate_kb.py`; run gosec/bandit/semgrep against existing fixtures when available; keep commercial artifacts gitignored; teach `sec-audit` to flag `unverified` hits in findings.

**Tech Stack:** Python 3 stdlib (`validate_kb.py`, `unittest`), Markdown knowledge base under `security-compliance-tw/references/`, optional CLI tools gosec / bandit / semgrep, bash helper script.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-09-05-a1-scanner-verification-design.md`
- Working tree root for plugin content: `security-compliance-tw/`
- No commercial scanner reports in git; `testdata/scan-artifacts/commercial/` must be gitignored
- Commercial tool tokens (row is commercial if the 工具 cell contains any): `Fortify`, `Checkmarx`, `AWVS`, `WebInspect`, `Nessus`
- Status enum only: `verified` | `unverified` | `partial`
- Commercial rows must not be `verified` in this plan’s default data (no reports yet)
- Non-commercial `verified` requires non-empty 證據 (not `—`)
- Do not add SonarQube/CodeQL CI; Sonar/CodeQL rows may stay `unverified` or `partial` with a public docs URL in 證據
- Do not implement A2/A3/B* in this plan
- Validator remains pure stdlib; tests via `python3 -m unittest`

---

## File Structure

| File | Responsibility |
|---|---|
| `security-compliance-tw/tools/validate_kb.py` | Parse + validate check bodies including scanner tables |
| `security-compliance-tw/tools/test_validate_kb.py` | Unit tests for new validation rules |
| `security-compliance-tw/references/checks/*.md` | Five-column scanner tables + statuses |
| `security-compliance-tw/references/scanner-verification-log.md` | Human-readable run/mapping log (committed) |
| `security-compliance-tw/tools/verify_scanners.md` | How to run open-source scanners |
| `security-compliance-tw/tools/run_open_scanners.sh` | Optional runner; missing tools → skip, exit 0 |
| `security-compliance-tw/testdata/scan-artifacts/` | Raw scan outputs (mostly gitignored) |
| `security-compliance-tw/testdata/scan-artifacts/README.md` | What belongs here |
| `.gitignore` | Ignore raw artifacts + commercial/ |
| `docs/usage/scanner-verification.md` | Commercial deferred verification workflow |
| `security-compliance-tw/skills/sec-audit/SKILL.md` | unverified finding note |
| `README.md` | Known-limitations rewrite |

---
### Task 1: Validator — scanner table schema (TDD)

**Files:**
- Modify: `security-compliance-tw/tools/validate_kb.py`
- Modify: `security-compliance-tw/tools/test_validate_kb.py`

**Interfaces:**
- Produces: `COMMERCIAL_TOOLS`, `ALLOWED_STATUSES`, `SCANNER_TABLE_COLUMNS`
- Produces: `parse_scanner_tables(body: str) -> list[dict]` with keys `headers`, `rows`
- Produces: `validate_scanner_tables(check: Check) -> list[str]`
- Consumes: existing `Check`, `validate_checks`

- [ ] **Step 1: Write failing tests**

Append class `TestScannerTables` to `test_validate_kb.py` covering:
1. three-column table → error mentioning 掃描器表/欄
2. invalid status `ok` → error mentioning 狀態
3. Fortify + verified + evidence `—` → error
4. gosec + verified + evidence `—` → error
5. Fortify unverified + gosec verified with real evidence → no errors

Use helper that wraps a full five-section check body around a scanner table string.

- [ ] **Step 2: Run tests — expect fail**

```bash
cd security-compliance-tw/tools
python3 -m unittest test_validate_kb.TestScannerTables -v
```

Expected: AttributeError or FAIL on missing `validate_scanner_tables`.

- [ ] **Step 3: Implement in `validate_kb.py`**

```python
ALLOWED_STATUSES = frozenset({"verified", "unverified", "partial"})
COMMERCIAL_TOOLS = frozenset(
    {"Fortify", "Checkmarx", "AWVS", "WebInspect", "Nessus"}
)
SCANNER_TABLE_COLUMNS = ["工具", "規則", "預設等級", "狀態", "證據"]


def _is_commercial_tool_cell(tool_cell: str) -> bool:
    return any(name in tool_cell for name in COMMERCIAL_TOOLS)


def parse_scanner_tables(body: str):
    tables = []
    lines = body.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].strip() == "### 掃描器怎麼標":
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("|"):
                i += 1
            if i < len(lines) and lines[i].strip().startswith("|"):
                headers = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                i += 1
                if i < len(lines) and set(lines[i].replace("|", "").strip()) <= set("- :"):
                    i += 1
                rows = []
                while i < len(lines) and lines[i].strip().startswith("|"):
                    cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                    if len(cells) == len(headers):
                        rows.append(dict(zip(headers, cells)))
                    i += 1
                tables.append({"headers": headers, "rows": rows})
            continue
        i += 1
    return tables


def validate_scanner_tables(check):
    errors = []
    where = f"{check.source} / {check.id}"
    tables = parse_scanner_tables(check.body)
    if not tables:
        errors.append(f"{where}: 找不到可解析的掃描器表")
        return errors
    for t_index, table in enumerate(tables):
        if table["headers"] != SCANNER_TABLE_COLUMNS:
            errors.append(
                f"{where}: 掃描器表#{t_index+1} 欄位必須為 "
                + " | ".join(SCANNER_TABLE_COLUMNS)
            )
            continue
        for r_index, row in enumerate(table["rows"]):
            status = row.get("狀態", "").strip()
            evidence = row.get("證據", "").strip()
            tool = row.get("工具", "").strip()
            loc = f"{where} 列{r_index+1} ({tool})"
            if status not in ALLOWED_STATUSES:
                errors.append(f"{loc}: 狀態必須為 verified|unverified|partial")
                continue
            if status == "verified" and evidence in ("", "—", "-"):
                prefix = "商用列 " if _is_commercial_tool_cell(tool) else ""
                errors.append(f"{loc}: {prefix}verified 必須填證據")
    return errors
```

Call `errors.extend(validate_scanner_tables(c))` at end of each check loop in `validate_checks`.

- [ ] **Step 4: Re-run unit tests — expect PASS**

```bash
cd security-compliance-tw/tools
python3 -m unittest test_validate_kb.TestScannerTables -v
```

- [ ] **Step 5: Commit**

```bash
git add security-compliance-tw/tools/validate_kb.py security-compliance-tw/tools/test_validate_kb.py
git commit -m "feat(kb): validate scanner table status and evidence columns"
```

---

### Task 2: Migrate all check scanner tables to five columns

**Files:**
- Modify: `security-compliance-tw/references/checks/*.md`

**Interfaces:**
- Consumes: Task 1 schema
- Produces: every scanner table has five columns; all rows start as `unverified` / `—`

- [ ] **Step 1: Inventory**

```bash
cd security-compliance-tw
rg -n "### 掃描器怎麼標" references/checks
```

- [ ] **Step 2: Transform**

Run a one-off script that for each `references/checks/*.md`:
- replaces `| 工具 | 規則 | 預設等級 |` with five-column header
- replaces three-dash separator with five-dash separator
- appends `| unverified | — |` to each 3-cell data row

Do not double-append if a row already has 5 cells. Review `git diff` before commit.

- [ ] **Step 3: Validate**

```bash
cd security-compliance-tw && python3 tools/validate_kb.py
```

Expected: `知識庫驗證通過：43 則 check` (or current check count).

- [ ] **Step 4: Commit**

```bash
git add security-compliance-tw/references/checks/*.md
git commit -m "refactor(kb): add status and evidence columns to scanner tables"
```

---
### Task 3: Artifacts layout, docs, and log stub

**Files:**
- Modify or create: `security-compliance-tw/.gitignore` (and repo-root `.gitignore` if that is where ignore rules live)
- Create: `security-compliance-tw/testdata/scan-artifacts/README.md`
- Create: `security-compliance-tw/testdata/scan-artifacts/open-source/.gitkeep`
- Create: `security-compliance-tw/testdata/scan-artifacts/commercial/.gitkeep`
- Create: `security-compliance-tw/tools/verify_scanners.md`
- Create: `docs/usage/scanner-verification.md` (repo root `docs/`, same tree as the design spec)
- Create: `security-compliance-tw/references/scanner-verification-log.md`

**Interfaces:**
- Produces: documented process for open-source runs and deferred commercial reports
- Produces: committed log stub; raw scan JSON stays gitignored under `testdata/scan-artifacts/`

- [ ] **Step 1: `.gitignore`**

Ensure these patterns exist (create/append as needed):

```
security-compliance-tw/testdata/scan-artifacts/open-source/**
!security-compliance-tw/testdata/scan-artifacts/open-source/.gitkeep
security-compliance-tw/testdata/scan-artifacts/commercial/**
!security-compliance-tw/testdata/scan-artifacts/commercial/.gitkeep
!security-compliance-tw/testdata/scan-artifacts/README.md
```

(If ignores are scoped inside `security-compliance-tw/.gitignore`, drop the `security-compliance-tw/` prefix.)

- [ ] **Step 2: Write `testdata/scan-artifacts/README.md`**

Explain:
- `open-source/` holds raw JSON from local fixture runs (not committed)
- `commercial/` reserved for future redacted reports (not committed)
- Only README and `.gitkeep` are tracked

- [ ] **Step 3: Write `tools/verify_scanners.md`**

Contents:
1. Prerequisites: install `gosec`, `bandit`, `semgrep`
2. How to run `tools/run_open_scanners.sh` (Task 4) against existing `testdata/sample-go` and `testdata/sample-multi`
3. Where JSON lands (`testdata/scan-artifacts/open-source/`)
4. How to promote a row to `verified` (match rule ID + fill 證據 + re-run validate + log row)

- [ ] **Step 4: Write `docs/usage/scanner-verification.md`**

Contents for deferred commercial path:
1. Required report fields (tool, version, rule ID, severity, file:line or CWE)
2. Redaction rules (no customer code / secrets)
3. Operator checklist: drop into `testdata/scan-artifacts/commercial/`, map to check rows, set `verified` or `partial`
4. Explicit note: commercial tools stay `unverified` until a report is supplied

- [ ] **Step 5: Write log stub `references/scanner-verification-log.md`**

```markdown
# 掃描器驗證紀錄

| 日期 | 工具 | 版本 | 對應 checks | 結果摘要 | 操作者 |
|------|------|------|-------------|----------|--------|
| — | — | — | — | stub | — |
```

- [ ] **Step 6: Commit**

```bash
git add security-compliance-tw/.gitignore   security-compliance-tw/testdata/scan-artifacts   security-compliance-tw/tools/verify_scanners.md   docs/usage/scanner-verification.md   security-compliance-tw/references/scanner-verification-log.md
# also add repo-root .gitignore if that file was changed
git commit -m "docs: add scanner verification process and artifact layout"
```

---

### Task 4: Open-source fixture runner + first verified rows

**Files:**
- Create: `security-compliance-tw/tools/run_open_scanners.sh`
- Reuse (do not reinvent unless missing): `security-compliance-tw/testdata/sample-go`, `security-compliance-tw/testdata/sample-multi`
- Modify: selected `security-compliance-tw/references/checks/*.md` rows that match real findings
- Modify: `security-compliance-tw/references/scanner-verification-log.md`

**Interfaces:**
- Produces: `run_open_scanners.sh` writing JSON under `testdata/scan-artifacts/open-source/`
- Produces: at least one `verified` row each for gosec, bandit, semgrep (if tool installed)
- Consumes: Task 2 tables; Task 3 paths; existing sample fixtures from the design

- [ ] **Step 1: Confirm fixtures**

Verify `testdata/sample-go` exists (required for gosec). If Python sample exists under `testdata/sample-multi`, use it for bandit. Only create a tiny supplemental sample under `testdata/` if a required fixture is missing — do not invent a parallel `tools/fixtures/` tree.

- [ ] **Step 2: Write `run_open_scanners.sh`**

Bash script that:
1. Creates timestamped dir under `testdata/scan-artifacts/open-source/`
2. Runs gosec/bandit/semgrep if present; skips with message if missing
3. Writes `gosec.json`, `bandit.json`, `semgrep.json`
4. Prints paths and non-zero finding counts
5. Exits 0 even when findings exist (findings are success for this workflow)

- [ ] **Step 3: Run once**

```bash
cd security-compliance-tw
bash tools/run_open_scanners.sh
```

If a tool is missing, install it or document skip in log; do not block whole A1 on optional installs beyond documenting.

- [ ] **Step 4: Map hits → check rows**

For each tool with ≥1 finding:
- find the check whose rule ID matches (or closest existing rule string)
- set `狀態` to `verified`
- set `證據` to relative path like `scan-artifacts/open-source/<run>/gosec.json#rule=<ID>`
- leave unmatched rows `unverified`

If zero tools available in environment, leave all `unverified` and record that in the log; still ship the runner + fixtures.

- [ ] **Step 5: Validate + log**

```bash
python3 tools/validate_kb.py
```

Append a real row to `references/scanner-verification-log.md`.

- [ ] **Step 6: Commit**

```bash
git add security-compliance-tw/tools/run_open_scanners.sh \
  security-compliance-tw/testdata \
  security-compliance-tw/references/checks \
  security-compliance-tw/references/scanner-verification-log.md
git commit -m "feat(tools): open-source scanner fixture runner and first verified rows"
```

---
### Task 5: Wire sec-audit skill + README limitations

**Files:**
- Modify: `security-compliance-tw/skills/sec-audit/SKILL.md`
- Modify: `security-compliance-tw/README.md`

**Interfaces:**
- Consumes: Task 3 docs paths; Task 4 runner
- Produces: agents instructed to respect `狀態` / `證據` and not invent commercial rule IDs

- [ ] **Step 1: Update `sec-audit/SKILL.md`**

Add a short section (Traditional Chinese OK) that agents must:
1. Prefer rows with `verified` when citing scanner coverage
2. Treat `unverified` as “claimed mapping, not calibrated”
3. Never invent Fortify/Checkmarx/etc. rule IDs
4. Point operators to `tools/verify_scanners.md` and `docs/usage/scanner-verification.md`

- [ ] **Step 2: Update README known limitations**

State clearly:
- Open-source tools may be partially verified via fixtures
- Commercial scanner mappings remain `unverified` until a redacted report is supplied
- Link both usage docs

- [ ] **Step 3: Commit**

```bash
git add security-compliance-tw/skills/sec-audit/SKILL.md security-compliance-tw/README.md
git commit -m "docs(skill): respect scanner verification status in sec-audit"
```

---

### Task 6: Acceptance gate

**Files:**
- None new (verification only)

**Interfaces:**
- Consumes: all prior tasks
- Produces: green `validate_kb.py` + documented deferred commercial path

- [ ] **Step 1: Full validation**

```bash
cd security-compliance-tw
python3 tools/validate_kb.py
python3 -m unittest discover -s tools -v
```

Expected: all pass; check count unchanged except schema-valid tables.

- [ ] **Step 2: Spec checklist**

Confirm against `docs/superpowers/specs/2026-09-05-a1-scanner-verification-design.md`:
- [ ] five-column scanner tables
- [ ] status enum enforced
- [ ] commercial verified requires evidence
- [ ] open-source runner + fixtures present
- [ ] deferred commercial docs present
- [ ] log stub (or real first entry) present
- [ ] skill/README warn about unverified commercial

- [ ] **Step 3: Manual smoke**

Pick one check file; confirm header is five columns and at least one open-source row is `verified` **or** log documents why tools were unavailable.

- [ ] **Step 4: Done criteria met → stop**

Do not start Track A2/A3 or Track B in this plan.

---

## Self-review vs design spec

| Spec requirement | Plan coverage |
|------------------|---------------|
| Approach 2: fixture runs + deferred commercial | Task 3–4 |
| Five-column tables + status enum | Task 1–2 |
| Commercial verified needs evidence | Task 1 tests + validator |
| Open-source verification workflow | Task 3–4 |
| Deferred commercial process doc | Task 3 `scanner-verification.md` |
| Agent behavior / honesty in citations | Task 5 |
| Acceptance without blocking on commercial licenses | Task 4 skip path + Task 6 |

## Execution notes

- Work in repo root that contains `security-compliance-tw/` (creator workspace or clone).
- Prefer TDD for Task 1; do not skip failing-test step.
- Keep commits small and message-focused as listed.
- If environment lacks gosec/bandit/semgrep, still complete Tasks 1–3, 5–6; Task 4 ships runner + fixtures and documents skips.

## After plan approval

Choose execution mode:
1. **Subagent-driven development** — one task per agent with review checkpoints
2. **Executing-plans** — sequential in one session with checkpoints

Do not implement until the user picks a mode.
