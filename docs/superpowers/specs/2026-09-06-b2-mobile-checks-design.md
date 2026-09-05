# B2：行動裝置 checks 第二批（缺口矩陣 + P0）— 設計規格

日期：2026-09-06
狀態：§1–§4 已與使用者確認核准；實作計畫待 writing-plans
專案：`security_skill_creator` / `security-compliance-tw`
來源指引：《行動裝置資安防護資安參考指引 V2.0》（PDF 不進 git；本地目錄 `行動裝置資安防護資安參考指引V2.0_1121231/`）
相關：B1 規格 `docs/superpowers/specs/2026-09-05-b1-mobile-checks-design.md`；GitHub https://github.com/mikey890612/security-compliance-tw

---

## 0. 子專案地圖

| ID | 內容 |
|---|---|
| A1–A2 | 掃描器可信度、一鍵安裝（已完成並已 push） |
| A3 | CI／CHANGELOG（本規格不做） |
| B1 | 第一批 10 則 MAST／MDM（已完成，`fe62ede`） |
| **B2（本規格）** | 缺口矩陣 + 只實作 P0（10 則）；原生 only |
| B3 | P1 checks、MobSF 校準、查檢表模板、Flutter／RN（預留） |

---

## 1. 背景與問題

B1 已落地 7 MAST + 3 MDM，並接上 mapping／profile／skills（總計 53 checks）。指引 §3、OWASP Mobile、附件 2 仍有高頻缺口未覆蓋；B1 明確把「更多 checks」與「MobSF 校準」留給後續。

使用者選擇 **B2 Approach A**：設計內完成缺口盤點，同軌只實作 **P0**；平台維持原生 iOS／Android；App／MAST 與 MDM／EMM 高優先缺口各半。

---

## 2. 目標與非目標（§1 已核准）

### 目標

- 產出指引缺口矩陣（§3 威脅／OWASP Mobile／附件 2 ↔ 既有 B1 checks）
- 只實作 **P0：10 則**（MAST 5 + MDM 5），五小節 + 五欄掃描表，體裁同 B1
- 接上既有 `mapping`（含 Mob25）、`profile` 行動／EMM 旗標、validator MAST／MDM 規則
- 原生 iOS／Android only

### 非目標

- Flutter／React Native
- MobSF／mobsfscan 實跑校準
- 查檢表模板自動化
- A3 CI／CHANGELOG
- 不把附件 2「教育訓練／約定書／資產清冊」硬做成 App check
- 不改 B1／Web 既有 check 語意

### 成功標準

1. 規格含完整矩陣 + 鎖定的 P0 ID 清單
2. `validate_kb.py` 通過：**63** checks（53 + 10）、0 errors
3. profile「有行動 App」會載入 `mast-device-privacy.md`；「有 EMM／MDM／MAM」仍載擴大的 `mdm-controls.md`
4. skills／README 覆蓋數與檔名更新；不宣稱 MobSF／Fortify verified
5. 既有 Web 43 + B1 10 則仍通過驗證

---

## 3. 做法（Approach A 已核准）

缺口矩陣標 P0／P1／P2 → B2 只寫 P0 → 掃描列多為 `unverified`（可 `partial` 若有公開規則文件 URL）→ P1 留 B3。

---

## 4. §2 缺口矩陣與 P0 清單（已核准）

### 4.1 B1 已覆蓋

| ID | 主題 |
|---|---|
| MAST-STORE-001 | 不安全本機儲存 |
| MAST-CRYPTO-001 | 弱密碼學／硬編碼密鑰 |
| MAST-NET-001 | 明文傳輸／ATS／NSC |
| MAST-AUTH-001 | 本機驗證可繞過 |
| MAST-IPC-001 | 過度匯出／危險 Deep Link |
| MAST-LOG-001 | 敏感日誌外洩 |
| MAST-WEB-001 | 不安全 WebView |
| MDM-ENROLL-001 | 裝置未強制註冊／監督不足 |
| MDM-APP-001 | 未受管 App／公司資料外流 |
| MDM-WIPE-001 | 遠端抹除／遺失應變未就緒 |

### 4.2 P0（本規格實作，10 則）

| ID | 主題 | 主要對照 |
|---|---|---|
| MAST-BACKUP-001 | 不安全備份／`allowBackup`／雲端同步外洩 | §3.1 同步；附件 2 二.5 |
| MAST-CLIP-001 | 剪貼簿外洩敏感資料 | §3 資料層；實務高頻 |
| MAST-SCREEN-001 | 截圖／螢幕錄影／背景快照未擋 | §3.1.9 螢幕 |
| MAST-BIO-001 | 生物辨識可被略過／無後備閘道 | 表 2 生物辨識（≠ AUTH-001） |
| MAST-PIN-001 | 無憑證釘選（僅 ATS／NSC 不夠） | §3 網路；OWASP M5 補強（≠ NET-001） |
| MDM-LOCK-001 | 螢幕鎖政策不足 | 附件 2 一.9 |
| MDM-JAIL-001 | 允許／未偵測越獄／Root | 附件 2 一.3 |
| MDM-PATCH-001 | OS／韌體版本不合規 | 附件 2 一.4–1.5／1.7 |
| MDM-VPN-001 | 未強制公司 VPN／安全通道 | 附件 2 一.11；§3.1 竊聽 |
| MDM-MTD-001 | 未部署威脅防禦／安全軟體要求 | 附件 2 一.8；§3 MTD |

### 4.3 邊界（寫死）

- **NET vs PIN**：NET = 明文／ATS／NSC／TrustAll；PIN = 憑證釘選（SPKI／公鑰釘選）
- **AUTH vs BIO**：AUTH = 本機布林閘道可繞過；BIO = 生物辨識略過／無後備／錯誤處理
- 附件 2 流程項（資產清冊、約定書、教育訓練、報廢程序）→ P2／不進 check 本文法規編號

### 4.4 P1（本輪不寫，B3 候選）

無線功能關閉、外接儲存政策、通知列敏感、鍵盤快取、第三方 SDK 隱私、遠端定位細部、核准安裝來源細則（部分已由 MDM-APP-001 涵蓋）等。

### 4.5 P2／不做為 check

教育訓練、使用者約定書、資產清冊、與他人共用裝置等純流程項。

---

## 5. §3 架構與接線（已核准）

### 5.1 Check 檔

| 檔案 | 內容 |
|---|---|
| **新建** `references/checks/mast-device-privacy.md` | BACKUP／CLIP／SCREEN／BIO |
| **擴充** `references/checks/mast-network-ipc.md` | 新增 `MAST-PIN-001` |
| **擴充** `references/checks/mdm-controls.md` | 新增 LOCK／JAIL／PATCH／VPN／MTD |

體裁：五小節、五欄掃描表、MAST 必備 ```swift``` + ```kotlin```、MDM 無語言 fence、本文不寫法規／OWASP 編號。

### 5.2 Validator

`CHECK_ID_RE` 與 MAST／MDM 語言規則已存在 → **原則不改**；僅在測試不足時補單元測試。

### 5.3 mapping／profile

- `mapping.md`：新增 10 列；附表十多為 `—（查檢表外）`；Mob25 誠實對照；MDM 列 Mob25 可為 `—`；普／中／高採 ◎／◎／◎（同 B1 行動列）
- `profile.md`：「有行動 App」載入規則加上 `mast-device-privacy.md`（`mast-network-ipc.md`／`mast-storage-crypto.md` 已在）；「有 EMM／MDM／MAM」仍載 `mdm-controls.md`

### 5.4 skills／README

輕觸：覆蓋 **63** checks、列出新檔與新 ID；不新開 skill；`install.sh` 仍複製三支 skill。

### 5.5 驗證

```bash
python3 security-compliance-tw/tools/validate_kb.py   # 期望：63 則
python3 -m unittest discover -s security-compliance-tw/tools -v
```

---

## 6. §4 驗收、風險、B3（已核准）

### 驗收清單

- [ ] 規格含矩陣與鎖定 P0
- [ ] 10 則 P0 齊，validate_kb = 63、單元測試綠
- [ ] profile 載入路徑正確
- [ ] skills／README 更新；無 verified 謊稱
- [ ] Web 43 + B1 10 未破壞

### 風險與緩解

| 風險 | 緩解 |
|---|---|
| PIN／NET、BIO／AUTH 重疊 | §4.3 邊界寫死；實作／review 對照 |
| 附件 2 流程項膨脹 | P2 排除；review gate |
| 掃描器列不準 | 一律 unverified／誠實 partial；校準 → B3 |

### B3 預留

P1 checks、MobSF 校準、查檢表模板自動化、Flutter／RN、A3。

---

## 7. 實作順序（供 writing-plans）

1. 開 worktree／分支 `b2-mobile-checks`
2. 寫入缺口矩陣附錄（可嵌本規格；計畫可再拆 task）
3. Author `mast-device-privacy.md`（4 checks）
4. 擴充 `mast-network-ipc.md`（PIN）
5. 擴充 `mdm-controls.md`（5 checks）
6. mapping + profile
7. skills／README
8. Acceptance（63 + tests）→ finishing-a-development-branch

---

## 8. 核准紀錄

| 節 | 狀態 |
|---|---|
| 做法 A | 已核准 |
| §1 目標／非目標 | 已核准 |
| §2 矩陣／P0 10 則 | 已核准 |
| §3 架構 | 已核准 |
| §4 驗收／風險 | 已核准 |
