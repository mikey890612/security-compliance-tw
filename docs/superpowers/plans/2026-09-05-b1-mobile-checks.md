# B1 Mobile Checks First Batch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 10 Web-parity mobile checks (7 MAST + 3 MDM) to `security-compliance-tw`, extend validator/profile/mapping/skills so `sec-audit` can select and use them without breaking the existing 43 Web checks.

**Architecture:** Extend `CHECK_ID_RE` and language rules for `MAST`/`MDM`; author three check markdown files with five-section + five-column scanner tables (mostly `unverified`); add `Mob25` mapping column; extend profile selection; light skill touch-ups.

**Tech Stack:** Python 3 stdlib (`validate_kb.py`, unittest), Markdown knowledge base, existing skill markdown.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-09-05-b1-mobile-checks-design.md`
- Exactly **10** checks (IDs locked in §4.3 of spec) unless a blocker forces ±2 with explicit note
- IDs: `MAST-*-*` and `MDM-*-*`; regex `^(SAST|DAST|MAST|MDM)-[A-Z]+-\d{3}$`
- `MAST-*` requires ```swift``` and ```kotlin``` fences; `MDM-*` does not require language fences
- Five sections + five-column scanner tables; status enum `verified|unverified|partial`; B1 rows default `unverified`
- No regulations/OWASP numbers inside check bodies (mapping only)
- Do not change semantics of existing 43 Web checks
- No new `sec-mobile` skill; no MobSF install/calibration; no Flutter/RN; no A3
- PDF guide stays out of git

---

## File Structure

| File | Responsibility |
|---|---|
| `security-compliance-tw/tools/validate_kb.py` | ID regex + MAST/MDM language rules |
| `security-compliance-tw/tools/test_validate_kb.py` | Unit tests for new rules |
| `security-compliance-tw/references/checks/mast-storage-crypto.md` | STORE/CRYPTO/LOG |
| `security-compliance-tw/references/checks/mast-network-ipc.md` | NET/AUTH/IPC/WEB |
| `security-compliance-tw/references/checks/mdm-controls.md` | ENROLL/APP/WIPE |
| `security-compliance-tw/references/mapping.md` | Mob25 column + 10 rows |
| `security-compliance-tw/references/profile.md` | Mobile/MDM selection |
| `security-compliance-tw/skills/sec-audit/SKILL.md` | Load new checks via profile |
| `security-compliance-tw/skills/sec-harden/SKILL.md` | Short mobile note / patterns |
| `security-compliance-tw/skills/sec-deliverables/SKILL.md` | Mention mobile when selected |
| `README.md` | Note mobile coverage |
| `docs/usage/sec-audit.md` | Optional profile options |

---

### Task 1: Validator + tests for MAST/MDM (TDD)

**Files:**
- Modify: `security-compliance-tw/tools/validate_kb.py`
- Modify: `security-compliance-tw/tools/test_validate_kb.py`

**Interfaces:**
- Produces: `CHECK_ID_RE` accepts MAST/MDM
- Produces: MAST requires swift+kotlin; MDM skips REQUIRED_LANGS loop
- Consumes: existing `Check`, `validate_checks`, scanner table validation

- [ ] **Step 1: Write failing tests**

Add cases:
1. id `MAST-STORE-001` format OK
2. id `MDM-ENROLL-001` format OK
3. MAST body missing ```kotlin``` → error
4. MDM body without code fences but with five sections + valid scanner table → no language errors
5. Existing SAST still requires go/python/javascript

- [ ] **Step 2: Run tests — expect FAIL**

```bash
cd security-compliance-tw/tools
python3 -m unittest test_validate_kb -v
```

- [ ] **Step 3: Implement**

Update `CHECK_ID_RE`. In `validate_checks` language loop:
- if id startswith `MAST-`: require `swift` and `kotlin`
- elif id startswith `SAST-`: keep go/python/javascript
- elif id startswith `MDM-` or `DAST-`: no SAST language requirements (DAST already exempt)

Keep scanner-table validation unchanged.

- [ ] **Step 4: Re-run tests — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add security-compliance-tw/tools/validate_kb.py security-compliance-tw/tools/test_validate_kb.py
git commit -m "feat(kb): allow MAST/MDM check ids and language rules"
```

---

### Task 2: Author mast-storage-crypto.md (3 checks)

**Files:**
- Create: `security-compliance-tw/references/checks/mast-storage-crypto.md`

**Interfaces:**
- Produces: MAST-STORE-001, MAST-CRYPTO-001, MAST-LOG-001

- [ ] **Step 1: Draft three checks** with full five sections; Swift+Kotlin bad/good samples; scanner tables (MobSF / platform tools / Semgrep mobile rules as applicable) all `unverified` / `—` unless known public rule id with docs URL as `partial`

- [ ] **Step 2: Sanity** — headings match `## MAST-… · …`

- [ ] **Step 3: Commit**

```bash
git add security-compliance-tw/references/checks/mast-storage-crypto.md
git commit -m "feat(kb): add MAST storage/crypto/logging checks"
```

---

### Task 3: Author mast-network-ipc.md (4 checks)

**Files:**
- Create: `security-compliance-tw/references/checks/mast-network-ipc.md`

**Interfaces:**
- Produces: MAST-NET-001, MAST-AUTH-001, MAST-IPC-001, MAST-WEB-001

- [ ] **Step 1: Draft four checks** (same quality bar as Task 2)

- [ ] **Step 2: Commit**

```bash
git add security-compliance-tw/references/checks/mast-network-ipc.md
git commit -m "feat(kb): add MAST network/auth/ipc/webview checks"
```

---

### Task 4: Author mdm-controls.md (3 checks)

**Files:**
- Create: `security-compliance-tw/references/checks/mdm-controls.md`

**Interfaces:**
- Produces: MDM-ENROLL-001, MDM-APP-001, MDM-WIPE-001

- [ ] **Step 1: Draft three MDM checks** — policy/verification focused; scanner table may cite MDM console checks / manual review as tools with `unverified`

- [ ] **Step 2: Commit**

```bash
git add security-compliance-tw/references/checks/mdm-controls.md
git commit -m "feat(kb): add MDM enrollment/app/wipe controls"
```

---

### Task 5: mapping.md + profile.md

**Files:**
- Modify: `security-compliance-tw/references/mapping.md`
- Modify: `security-compliance-tw/references/profile.md`
- Modify: `security-compliance-tw/tools/validate_kb.py` (MAPPING_COLUMNS if needed)

**Interfaces:**
- Produces: `Mob25` column on all rows; 10 new mapping rows
- Produces: profile questions + load rules for mast/mdm files

- [ ] **Step 1: Extend MAPPING_COLUMNS** with `Mob25`; backfill `—` for existing 43 rows

- [ ] **Step 2: Add 10 mapping rows** (honest `—（查檢表外）` where no 附表十 id; Mob25 ids from OWASP Mobile Top 10 where applicable)

- [ ] **Step 3: Update profile** selection table + multiSelect options

- [ ] **Step 4: `python3 tools/validate_kb.py`** — expect 53 checks (43+10) pass

- [ ] **Step 5: Commit**

```bash
git add security-compliance-tw/references/mapping.md security-compliance-tw/references/profile.md security-compliance-tw/tools/validate_kb.py
git commit -m "feat(kb): map mobile checks and extend profile selection"
```

---

### Task 6: Skills + README (+ optional usage)

**Files:**
- Modify: `security-compliance-tw/skills/sec-audit/SKILL.md`
- Modify: `security-compliance-tw/skills/sec-harden/SKILL.md`
- Modify: `security-compliance-tw/skills/sec-deliverables/SKILL.md`
- Modify: `README.md`
- Optional: `docs/usage/sec-audit.md`

**Interfaces:**
- Consumes: profile rules; new check paths
- Produces: agents load mast/mdm when selected

- [ ] **Step 1: Patch skills** to mention mobile profile flags and check files; harden short pointer only

- [ ] **Step 2: README** note MAST/MDM + guide source (PDF not shipped)

- [ ] **Step 3: Optional usage doc** for profile options

- [ ] **Step 4: Commit**

```bash
git add security-compliance-tw/skills/*/SKILL.md README.md docs/usage/sec-audit.md
git commit -m "docs(skills): wire mobile checks into existing skills"
```

---

### Task 7: Acceptance gate

- [ ] **Step 1:**

```bash
python3 security-compliance-tw/tools/validate_kb.py
python3 -m unittest discover -s security-compliance-tw/tools -v
```

Expect: 53 checks; all unit tests pass.

- [ ] **Step 2: Spec checklist** — 10 checks, MAST/MDM rules, profile, skills, Web intact

- [ ] **Step 3: Done — stop** (no B2/A3)

---

## Self-review vs design

| Spec | Plan |
|---|---|
| 10 checks / 3 files | Tasks 2–4 |
| Validator MAST/MDM | Task 1 |
| mapping Mob25 + profile | Task 5 |
| skills + README | Task 6 |
| No MobSF calibration | Global constraints |

## After plan approval

Choose: **subagent-driven-development** (recommended) or **executing-plans**.
