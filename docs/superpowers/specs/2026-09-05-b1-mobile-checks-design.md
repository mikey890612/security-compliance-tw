# B1：行動裝置 checks 第一批 — 設計規格

日期：2026-09-05
狀態：已與使用者確認 §1–§4，待使用者 review 本檔後進入 writing-plans
專案：`security_skill_creator` / `security-compliance-tw`
來源指引：《行動裝置資安防護資安參考指引 V2.0》（PDF 不進 git；本地目錄 `行動裝置資安防護資安參考指引V2.0_1121231/`）
相關 GitHub：https://github.com/mikey890612/security-compliance-tw

---

## 0. 子專案地圖

| ID | 內容 |
|---|---|
| A1–A2 | Web／附表十：掃描器可信度、一鍵安裝（已完成） |
| A3 | CI／CHANGELOG（本規格不做） |
| **B1（本規格）** | 第一批行動裝置 checks（Web 同規）＋選取／驗證器擴充 |
| B2 | MobSF 等實跑校準、更多 checks、查檢表模板自動化（預留） |
| B3–B4 | 後續擴充（預留） |

---

## 1. 背景與問題

Web／附表十知識庫已有 43 則 SAST／DAST checks。機關導入行動化時另依《行動裝置資安防護資安參考指引 V2.0》，但 plugin 尚無對應 checks。使用者要 **B1 直接做第一批 mobile checks／skill 行為**，比照 Web 深度，而不是只做目錄盤點。

---

## 2. 目標與非目標（§1 已核准）

### 目標

- 在現有 `security-compliance-tw` 新增 **8–12 則**（本規格鎖定 **10 則**）Web 同規五小節 checks
- 涵蓋 **iOS／Android App** 與 **EMM／MDM／MAM 管理面**
- 擴充 `mapping.md`、`profile.md`、既有三支 skill 選取
- 掃描器對照先多為 `unverified`（可列 MobSF 等）

### 非目標

- 不覆蓋整本指引全文
- 不做 Flutter／React Native
- 不新開 `sec-mobile` skill
- 不在 B1 安裝／校準 MobSF 或商用掃描器實跑（→ B2）
- 不改既有 43 則 Web checks 語意
- 不做 A3

### 成功標準

1. `validate_kb.py` 通過（含新 id 規則）
2. profile 能選到 mobile／MDM 集合
3. `sec-audit` 能載入新 checks 並產出 findings
4. App 類與 MDM 類皆有 checks
5. 既有 Web 43 則仍通過驗證

---

## 3. 做法（Approach 1 已核准）

比照 Web：五小節、五欄掃描器表（A1 狀態模型）、壞味道／過關寫法用 Swift＋Kotlin；MDM 以政策與驗證步驟為主。

---

## 4. §2 ID、檔案與題目清單（已核准）

### 4.1 ID 與驗證器規則

| 類型 | 前綴 | 範例語言 |
|---|---|---|
| App | `MAST-<主題>-###` | 必備 `swift`、`kotlin`（objc／java 可選） |
| 管理 | `MDM-<主題>-###` | 不強制程式 fence |

- 擴充 `CHECK_ID_RE`：`^(SAST|DAST|MAST|MDM)-[A-Z]+-\d{3}$`
- `MAST-*`：五小節＋掃描器表＋ swift/kotlin fences
- `MDM-*`：五小節＋掃描器表；無語言 fence 要求
- 狀態 enum 沿用 A1：`verified`｜`unverified`｜`partial`

### 4.2 檔案

- `references/checks/mast-storage-crypto.md`
- `references/checks/mast-network-ipc.md`
- `references/checks/mdm-controls.md`

### 4.3 題目（10 則）

| ID | 標題（暫） | 檔案 |
|---|---|---|
| MAST-STORE-001 | 不安全本機儲存 | mast-storage-crypto |
| MAST-CRYPTO-001 | 弱密碼學／硬編碼密鑰 | mast-storage-crypto |
| MAST-NET-001 | 明文傳輸／ATS／NSC | mast-network-ipc |
| MAST-AUTH-001 | 本機驗證可繞過 | mast-network-ipc |
| MAST-IPC-001 | 過度匯出元件／危險 Deep Link | mast-network-ipc |
| MAST-LOG-001 | 敏感日誌外洩 | mast-storage-crypto |
| MAST-WEB-001 | 不安全 WebView | mast-network-ipc |
| MDM-ENROLL-001 | 裝置註冊與合規狀態 | mdm-controls |
| MDM-APP-001 | 應用控管（允許清單／MAM） | mdm-controls |
| MDM-WIPE-001 | 遠端／選擇性抹除與遺失應變 | mdm-controls |

實作時標題用 Traditional Chinese；check 本文**不寫**法規／OWASP 編號（對照只在 mapping）。

### 4.4 mapping

- 表頭新增 `Mob25`（OWASP Mobile Top 10 對照；精確年份標註於 mapping 檔頭）
- 既有 Web 列該欄填 `—`
- 指引章節／附件 2 對照原則寫在 mapping 說明；必要時「附表十」欄對行動裝置可為 `—（查檢表外）` 或標註適用之機關控制（以可追溯為準，不捏造）

---

## 5. §3 Profile、skill、測試（已核准）

### 5.1 profile.md

新增複選特性：

- 有行動 App（iOS／Android）
- 有導入／規劃 EMM／MDM／MAM

選取：

| 條件 | 載入 |
|---|---|
| 有行動 App | `mast-storage-crypto.md`、`mast-network-ipc.md` |
| 有 EMM／MDM／MAM | `mdm-controls.md` |

可與 Web 條件並存。

### 5.2 Skills

- 更新 `sec-audit`／`sec-harden`／`sec-deliverables` 使依 profile 載入新檔
- harden：`quick-patterns` 可加短段或指向 checks，避免爆量
- 不安裝新 skill 名；`install.sh` 仍複製既有三支

### 5.3 測試

- 擴充 `test_validate_kb.py`：MAST 缺 kotlin 失敗；MDM 無 fence 可過；新 id 正則
- 全量 `validate_kb.py` 含 43＋10

---

## 6. §4 文件與驗收（已核准）

### 文件

- README：註明涵蓋行動裝置（MAST／MDM）與指引來源（PDF 不散布）
- 可選：`docs/usage/sec-audit.md` 補 mobile profile
- mapping 檔頭：Mob25 與指引對照原則

### 驗收清單

1. 10 則新 checks，五小節＋五欄掃描器表
2. `validate_kb.py` 通過
3. unittest 全綠
4. profile 規則可載入對應檔
5. Web 43 則不破壞

### 交付物

- 3× checks md
- mapping／profile／validate_kb＋tests
- 三支 skill 小改
- README（＋可選 usage）

---

## 7. 風險與 B2

| 風險 | 緩解 |
|---|---|
| 指引 PDF 著作權 | 不進 git；知識庫為轉化實作 |
| MobSF 規則名不準 | B1 一律 unverified；B2 實跑 |
| profile 題數變多 | 維持一次問完；複選合併 |
| harden 內容過重 | B1 短段或連回 checks |

**B2 預留：** MobSF 校準、更多 checks、附件查檢表模板自動化。

---

## 8. 核准紀錄

- §1 目標／非目標：已核准
- §2 前綴／清單／檔案：已核准
- §3 profile／validator／skill：已核准
- §4 文件／驗收：已核准（整份設計通過，待本檔 review）
