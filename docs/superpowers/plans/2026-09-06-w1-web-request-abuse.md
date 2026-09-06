# W1 Web Request-Abuse Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three always-loaded SAST checks (CSRF, SSRF, insecure file upload) in `sast-request-abuse.md` so `validate_kb` reaches 66 checks without changing existing Web/mobile semantics.

**Architecture:** New markdown check file + profile always-load row + three mapping rows + light skills/README touch. Validator unchanged (existing SAST go/python/javascript rules).

**Tech Stack:** Python 3 stdlib (`validate_kb.py`, unittest), Markdown knowledge base, existing skills.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-09-06-w1-web-request-abuse-design.md`
- Exactly **3** new checks: `SAST-CSRF-001`, `SAST-SSRF-001`, `SAST-UPLOAD-001`
- Boundaries: CSRF ≠ DAST-COOKIE-003；SSRF ≠ LLM-only；UPLOAD ≠ INJ-003／INJ-004
- Five sections + five-column scanner tables; status mostly `unverified`
- SAST language fences: ```go``` + ```python``` + ```javascript``` (bad and good each)
- No regulations/OWASP numbers in check bodies（mapping only）
- Do not edit `sast-injection.md` or other existing check bodies
- No P1／DAST／A3／scanner calibration
- Work from git worktree/branch `w1-web-request-abuse` at execution time

---

## File Structure

| File | Responsibility |
|---|---|
| `security-compliance-tw/references/checks/sast-request-abuse.md` | NEW: CSRF/SSRF/UPLOAD |
| `security-compliance-tw/references/mapping.md` | +3 rows |
| `security-compliance-tw/references/profile.md` | Always-load new file |
| `security-compliance-tw/skills/sec-audit/SKILL.md` | 66 / new file |
| `security-compliance-tw/skills/sec-harden/SKILL.md` | Short pointer |
| `security-compliance-tw/skills/sec-deliverables/SKILL.md` | Coverage note |
| `README.md` | 66 / Web 46 |
| Optional `docs/usage/sec-audit.md` | Always-load example |

---

### Task 1: Author sast-request-abuse.md

**Files:**
- Create: `security-compliance-tw/references/checks/sast-request-abuse.md`

**Interfaces:**
- Produces: `SAST-CSRF-001`, `SAST-SSRF-001`, `SAST-UPLOAD-001`
- Consumes: section tone from `sast-injection.md`

- [ ] **Step 1: Create file** with Traditional Chinese intro (pointer to mapping; no regs in body) and three headings:
  - `## SAST-CSRF-001 · 跨站請求偽造未防護`
  - `## SAST-SSRF-001 · 伺服器端請求偽造`
  - `## SAST-UPLOAD-001 · 不安全檔案上傳`

- [ ] **Step 2: For each check**, mirror the five-section heading order used in `sast-injection.md` (same `###` titles). Include:
  - Five-column scanner table（工具｜規則｜預設等級｜狀態｜證據）— Semgrep／CodeQL／Sonar／gosec／bandit／商業列可列名但 `unverified`
  - `### 壞味道`：```go``` then ```python``` then ```javascript```
  - `### 過關寫法`：same three languages
  - Content per spec boundaries（CSRF token／Origin 驗證；SSRF allowlist／block metadata；UPLOAD type+content+size+safe storage）

- [ ] **Step 3: Isolated validate**

```bash
cd security-compliance-tw
python3 -c "
from pathlib import Path
import tools.validate_kb as v
errs=[]
v.validate_checks(Path('references/checks/sast-request-abuse.md'), errs)
print('errors', len(errs))
for e in errs: print(e)
"
```

Expected: `errors 0`（3 headings; each SAST has go×2 + python×2 + javascript×2）

- [ ] **Step 4: Commit**

```bash
git add security-compliance-tw/references/checks/sast-request-abuse.md
git commit -m "feat(kb): add SAST CSRF/SSRF/upload request-abuse checks"
```

---

### Task 2: mapping.md + profile.md

**Files:**
- Modify: `security-compliance-tw/references/mapping.md`
- Modify: `security-compliance-tw/references/profile.md`

**Interfaces:**
- Full KB validate becomes 66 after this task

- [ ] **Step 1: Add mapping rows**（column order matches header）

| check-id | 附表十 | 普 | 中 | 高 | Web21 | Web25 | API23 | LLM25 | Mob25 | CWE |
|---|---|---|---|---|---|---|---|---|---|---|
| SAST-CSRF-001 | 4.5.3.1 | ◎ | ◎ | ◎ | A01 | A01 | — | — | — | CWE-352 |
| SAST-SSRF-001 | —（查檢表外） | ◎ | ◎ | ◎ | A10 | A10 | — | — | — | CWE-918 |
| SAST-UPLOAD-001 | —（查檢表外） | ◎ | ◎ | ◎ | A04 | A04 | — | — | — | CWE-434 |

（Web21 若專案慣例用舊編號，可改為誠實 `—`；勿捏造附表十。）

- [ ] **Step 2: Profile always-load** — add alongside injection:

From selection table「一律」rows, ensure:

`| 一律 | `checks/sast-request-abuse.md` |`

（保留既有 `sast-injection.md`／`sast-errors.md` 列。）

- [ ] **Step 3: Full validate**

```bash
cd security-compliance-tw
python3 tools/validate_kb.py
python3 -m unittest discover -s tools -v
```

Expected: `知識庫驗證通過：66 則 check`；all unit tests OK.

- [ ] **Step 4: Commit**

```bash
git add security-compliance-tw/references/mapping.md security-compliance-tw/references/profile.md
git commit -m "feat(kb): map request-abuse checks and always-load in profile"
```

---

### Task 3: Skills + README

**Files:**
- Modify: `security-compliance-tw/skills/sec-audit/SKILL.md`
- Modify: `security-compliance-tw/skills/sec-harden/SKILL.md`
- Modify: `security-compliance-tw/skills/sec-deliverables/SKILL.md`
- Modify: `README.md`
- Optional: `docs/usage/sec-audit.md`

- [ ] **Step 1: Update counts** 63→66；mention `sast-request-abuse.md` and three IDs；no verified lies；`install.sh` untouched.

- [ ] **Step 2: Commit**

```bash
git add security-compliance-tw/skills/*/SKILL.md README.md docs/usage/sec-audit.md
git commit -m "docs(skills): wire request-abuse checks into skills and README"
```

---

### Task 4: Acceptance gate

- [ ] **Step 1:**

```bash
python3 security-compliance-tw/tools/validate_kb.py
python3 -m unittest discover -s security-compliance-tw/tools -v
```

Expected: 66 checks; tests OK.

- [ ] **Step 2: Checklist** — 3 IDs; always-load; boundaries intact; injection untouched; total 66.

- [ ] **Step 3: Done — stop.** Parent runs finishing-a-development-branch.

---

## Self-review vs design

| Spec | Task |
|---|---|
| New file 3 checks | Task 1 |
| mapping + profile always | Task 2 |
| skills/README | Task 3 |
| 66 validate | Task 2–4 |
| No P1/DAST/A3 | Global constraints |

---

## After plan approval

Choose: **subagent-driven-development** (recommended) or **executing-plans**.
