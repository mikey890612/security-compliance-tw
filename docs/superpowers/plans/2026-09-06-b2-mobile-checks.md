# B2 Mobile Checks P0 Batch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 10 P0 native mobile checks (5 MAST + 5 MDM) from the B2 gap matrix so `validate_kb` reaches 63 checks and profile loads the new privacy file without breaking Web/B1 coverage.

**Architecture:** Reuse existing MAST/MDM validator rules. Author one new check file (`mast-device-privacy.md`), append `MAST-PIN-001` to `mast-network-ipc.md`, append five MDM IDs to `mdm-controls.md`, then extend mapping/profile and lightly touch skills/README.

**Tech Stack:** Python 3 stdlib (`validate_kb.py`, unittest), Markdown knowledge base, existing three skills.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-09-06-b2-mobile-checks-design.md`
- Exactly **10** new checks (IDs locked in spec §4.2)
- IDs: `MAST-BACKUP-001`, `MAST-CLIP-001`, `MAST-SCREEN-001`, `MAST-BIO-001`, `MAST-PIN-001`, `MDM-LOCK-001`, `MDM-JAIL-001`, `MDM-PATCH-001`, `MDM-VPN-001`, `MDM-MTD-001`
- Boundaries: NET≠PIN；AUTH≠BIO（see spec §4.3）
- `MAST-*` requires ```swift``` and ```kotlin``` fences; `MDM-*` no language fences
- Five sections + five-column scanner tables; default `unverified` / `—`（`partial` only with public evidence URL）
- No regulations/OWASP numbers in check bodies（mapping only）
- Native iOS/Android only; no Flutter/RN; no MobSF calibration; no checklist automation; no A3
- Do not change semantics of existing 53 checks
- PDF guide stays out of git
- Work from a git worktree/branch `b2-mobile-checks` created via using-git-worktrees at execution time

---

## File Structure

| File | Responsibility |
|---|---|
| `security-compliance-tw/references/checks/mast-device-privacy.md` | NEW: BACKUP/CLIP/SCREEN/BIO |
| `security-compliance-tw/references/checks/mast-network-ipc.md` | Append PIN-001 |
| `security-compliance-tw/references/checks/mdm-controls.md` | Append LOCK/JAIL/PATCH/VPN/MTD |
| `security-compliance-tw/references/mapping.md` | +10 rows |
| `security-compliance-tw/references/profile.md` | Load `mast-device-privacy.md` for 有行動 App |
| `security-compliance-tw/skills/sec-audit/SKILL.md` | 63 checks / new file |
| `security-compliance-tw/skills/sec-harden/SKILL.md` | Short pointer to new MAST/MDM IDs |
| `security-compliance-tw/skills/sec-deliverables/SKILL.md` | Coverage note |
| `README.md` | 63 / list new file |
| `docs/usage/sec-audit.md` | Optional: load example includes privacy file |

Validator changes: **none expected**（MAST/MDM rules already in place）. Only touch `test_validate_kb.py` if a regression appears.

---

### Task 1: Author mast-device-privacy.md (4 checks)

**Files:**
- Create: `security-compliance-tw/references/checks/mast-device-privacy.md`

**Interfaces:**
- Produces: `MAST-BACKUP-001`, `MAST-CLIP-001`, `MAST-SCREEN-001`, `MAST-BIO-001`
- Consumes: B1 tone from `mast-storage-crypto.md`（five sections, scanner table shape）

- [ ] **Step 1: Create file** with Traditional Chinese intro (no regs/OWASP numbers) and four `## MAST-…` headings with exact titles from spec:
  - `## MAST-BACKUP-001 · 不安全備份／雲端同步外洩`
  - `## MAST-CLIP-001 · 剪貼簿外洩敏感資料`
  - `## MAST-SCREEN-001 · 截圖／螢幕錄影／背景快照未擋`
  - `## MAST-BIO-001 · 生物辨識可略過／無後備閘道`

- [ ] **Step 2: For each check**, write all five sections matching B1 order:
  1. lead paragraph
  2. `### 掃描器怎麼標` + five-column table（工具｜規則｜預設等級｜狀態｜證據）— rows like MobSF / mobsfscan / Semgrep / platform tools; status `unverified` unless public URL → `partial`
  3. `### 壞味道` with ```swift``` then ```kotlin``` bad samples
  4. `### 過關寫法` with ```swift``` then ```kotlin``` good samples
  5. remaining sections as in B1 files（同一套五小節標題，勿自創英文 heading）

  Content hints:
  - BACKUP: `allowBackup=true`、未排除 Keychain／Documents、無差別 iCloud／Auto Backup
  - CLIP: 權杖寫入 `UIPasteboard`／`ClipboardManager`；應短命／敏感勿寫
  - SCREEN: 缺 `FLAG_SECURE`／未擋截圖／背景快照露敏感 UI
  - BIO: 生物辨識成功只設本地 bool；應綁 Keychain／CryptoObject 且失敗有後備政策（勿重寫成 AUTH-001）

- [ ] **Step 3: Isolated validate**

```bash
cd security-compliance-tw
python3 -c "
from pathlib import Path
import tools.validate_kb as v
errs=[]
v.validate_checks(Path('references/checks/mast-device-privacy.md'), errs)
print('errors', len(errs))
for e in errs: print(e)
"
```

Expected: `errors 0`（4 headings; each MAST has swift×2 + kotlin×2 fences; scanner tables OK）

- [ ] **Step 4: Commit**

```bash
git add security-compliance-tw/references/checks/mast-device-privacy.md
git commit -m "feat(kb): add MAST backup/clipboard/screen/biometric checks"
```

---

### Task 2: Append MAST-PIN-001 to mast-network-ipc.md

**Files:**
- Modify: `security-compliance-tw/references/checks/mast-network-ipc.md`

**Interfaces:**
- Produces: `MAST-PIN-001`
- Must not alter NET-001 semantics（PIN = certificate pinning only）

- [ ] **Step 1: Append** after existing WEB-001 block:

`## MAST-PIN-001 · 無憑證釘選（僅 ATS／NSC 不夠）`

Full five sections; swift+kotlin bad/good（TrustKit／URLSession pin／OkHttp CertificatePinner vs 僅 ATS／全信任）.

- [ ] **Step 2: Isolated validate** on this file only — expect 0 errors and **5** MAST headings（NET/AUTH/IPC/WEB/PIN）.

```bash
cd security-compliance-tw
python3 -c "
from pathlib import Path
import tools.validate_kb as v
errs=[]
p=Path('references/checks/mast-network-ipc.md')
v.validate_checks(p, errs)
ids=[l for l in p.read_text().splitlines() if l.startswith('## MAST-')]
print('headings', len(ids)); print('errors', len(errs))
for e in errs: print(e)
"
```

- [ ] **Step 3: Commit**

```bash
git add security-compliance-tw/references/checks/mast-network-ipc.md
git commit -m "feat(kb): add MAST certificate pinning check"
```

---

### Task 3: Append five MDM checks to mdm-controls.md

**Files:**
- Modify: `security-compliance-tw/references/checks/mdm-controls.md`

**Interfaces:**
- Produces: `MDM-LOCK-001`, `MDM-JAIL-001`, `MDM-PATCH-001`, `MDM-VPN-001`, `MDM-MTD-001`
- No language fences

- [ ] **Step 1: Append** five `## MDM-…` sections with titles:
  - `## MDM-LOCK-001 · 螢幕鎖政策不足`
  - `## MDM-JAIL-001 · 允許／未偵測越獄或 Root`
  - `## MDM-PATCH-001 · OS／韌體版本不合規`
  - `## MDM-VPN-001 · 未強制公司 VPN／安全通道`
  - `## MDM-MTD-001 · 未部署威脅防禦／安全軟體要求`

  Each: five sections; scanner table rows may cite EMM console／manual／policy audit as `unverified`; **zero** ```swift```/```kotlin``` fences.

- [ ] **Step 2: Isolated validate** — expect 0 errors; **8** MDM headings（ENROLL/APP/WIPE + 5）.

```bash
cd security-compliance-tw
python3 -c "
from pathlib import Path
import tools.validate_kb as v
errs=[]
p=Path('references/checks/mdm-controls.md')
v.validate_checks(p, errs)
ids=[l for l in p.read_text().splitlines() if l.startswith('## MDM-')]
print('headings', len(ids)); print('errors', len(errs))
for e in errs: print(e)
"
```

- [ ] **Step 3: Commit**

```bash
git add security-compliance-tw/references/checks/mdm-controls.md
git commit -m "feat(kb): add MDM lock/jailbreak/patch/VPN/MTD controls"
```

---

### Task 4: mapping.md + profile.md

**Files:**
- Modify: `security-compliance-tw/references/mapping.md`
- Modify: `security-compliance-tw/references/profile.md`

**Interfaces:**
- Produces: 10 mapping rows; profile loads privacy file
- Full KB validate becomes possible after this task

- [ ] **Step 1: Add mapping rows**（columns: check-id｜附表十｜普｜中｜高｜Web21｜Web25｜API23｜LLM25｜Mob25｜CWE）

Suggested values（adjust CWE only if confident; else `—`）:

| check-id | 附表十 | 普/中/高 | Web/API/LLM | Mob25 | CWE |
|---|---|---|---|---|---|
| MAST-BACKUP-001 | —（查檢表外） | ◎◎◎ | — | M9 | CWE-530 or — |
| MAST-CLIP-001 | —（查檢表外） | ◎◎◎ | — | M6 | CWE-200 or — |
| MAST-SCREEN-001 | —（查檢表外） | ◎◎◎ | — | M6 | — |
| MAST-BIO-001 | —（查檢表外） | ◎◎◎ | — | M3 | CWE-287 or — |
| MAST-PIN-001 | —（查檢表外） | ◎◎◎ | — | M5 | CWE-295 or — |
| MDM-LOCK-001 | —（查檢表外） | ◎◎◎ | — | — | — |
| MDM-JAIL-001 | —（查檢表外） | ◎◎◎ | — | — | — |
| MDM-PATCH-001 | —（查檢表外） | ◎◎◎ | — | — | — |
| MDM-VPN-001 | —（查檢表外） | ◎◎◎ | — | — | — |
| MDM-MTD-001 | —（查檢表外） | ◎◎◎ | — | — | — |

Do **not** invent 附表十 ids.

- [ ] **Step 2: Update profile** selection table line for 有行動 App:

From:
`| 有行動 App | `checks/mast-storage-crypto.md`、`checks/mast-network-ipc.md` |`

To:
`| 有行動 App | `checks/mast-storage-crypto.md`、`checks/mast-network-ipc.md`、`checks/mast-device-privacy.md` |`

EMM／MDM row unchanged（still `mdm-controls.md`）.

- [ ] **Step 3: Full validate**

```bash
cd security-compliance-tw
python3 tools/validate_kb.py
python3 -m unittest discover -s tools -v
```

Expected: `知識庫驗證通過：63 則 check`；all unit tests OK.

- [ ] **Step 4: Commit**

```bash
git add security-compliance-tw/references/mapping.md security-compliance-tw/references/profile.md
git commit -m "feat(kb): map B2 mobile checks and load privacy file in profile"
```

---

### Task 5: Skills + README (+ optional usage)

**Files:**
- Modify: `security-compliance-tw/skills/sec-audit/SKILL.md`
- Modify: `security-compliance-tw/skills/sec-harden/SKILL.md`
- Modify: `security-compliance-tw/skills/sec-deliverables/SKILL.md`
- Modify: `README.md`
- Optional: `docs/usage/sec-audit.md`

**Interfaces:**
- Produces: docs saying 63 checks / privacy file / new MDM IDs
- No install.sh change

- [ ] **Step 1: Patch skills** — update coverage counts 53→63; mention `mast-device-privacy.md` and new MDM IDs; keep profile flag names; no Fortify/MobSF verified claims.

- [ ] **Step 2: Patch README** — list `mast-device-privacy.md`; note B2 P0 (+10); 53→63.

- [ ] **Step 3: Optional** — if `docs/usage/sec-audit.md` shows load examples, add privacy file to 有行動 App example.

- [ ] **Step 4: Commit**

```bash
git add security-compliance-tw/skills/*/SKILL.md README.md docs/usage/sec-audit.md
git commit -m "docs(skills): wire B2 mobile privacy checks into skills and README"
```

---

### Task 6: Acceptance gate

**Files:** none（or trivial fix only）

- [ ] **Step 1: Validate**

```bash
python3 security-compliance-tw/tools/validate_kb.py
python3 -m unittest discover -s security-compliance-tw/tools -v
```

Expected: 63 checks; all tests pass.

- [ ] **Step 2: Spec checklist**
  - [ ] 10 P0 IDs present
  - [ ] NET≠PIN、AUTH≠BIO still distinct
  - [ ] profile loads `mast-device-privacy.md`
  - [ ] mapping has 10 new rows
  - [ ] Web 43 + B1 10 intact（total 63）
  - [ ] No Flutter/RN; no MobSF verified lies

- [ ] **Step 3: Done — stop**（no B3/A3）. Parent runs finishing-a-development-branch.

---

## Self-review vs design

| Spec item | Plan task |
|---|---|
| Gap matrix / P0 locked | Global constraints + Task titles |
| mast-device-privacy 4 | Task 1 |
| PIN in network file | Task 2 |
| 5 MDM append | Task 3 |
| mapping + profile | Task 4 |
| skills/README | Task 5 |
| 63 validate | Task 4 Step 3 + Task 6 |
| No MobSF calibration / Flutter / A3 | Global constraints |

---

## After plan approval

Choose: **subagent-driven-development** (recommended) or **executing-plans**.
