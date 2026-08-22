# 第三方內容聲明 / Third-Party Content Notice

本專案以 MIT 授權釋出（見 [LICENSE](LICENSE)）。
本檔說明其中涉及外部來源的部分。

---

## 法規本文（不受著作權保護）

`security-compliance-tw/references/controls-appendix10.md` 所收錄的
控制措施項目與適用分級，出自：

> **《資通安全責任等級分級辦法》附表十「資通系統防護基準」**
> ——依《資通安全管理法》授權訂定之法規命令

依**著作權法第 9 條**：

> 下列各款不得為著作權之標的：
> 一、憲法、法律、**命令**或公文。

法規命令不得為著作權之標的，故該附表內容可自由重製。

The security control items and classification levels in
`references/controls-appendix10.md` originate from Appendix 10 of the
Regulations on Classification of Cyber Security Responsibility Levels, a
regulation issued under Taiwan's Cyber Security Management Act. Under
Article 9 of Taiwan's Copyright Act, constitutions, acts, regulations, and
official documents are not eligible for copyright protection.

---

## 參考指引（著作權屬各機關，本專案未重製）

下列文件為前述法規的實作參考文件：

- 《Web 應用程式安全參考指引 V3.2》，數位發展部資通安全署，114.12.31
- 《安全軟體發展流程指引》，行政院資通安全辦公室，103.06
- 《安全軟體設計參考指引》，行政院資通安全辦公室，103.10
- 《安全軟體測試參考指引》，行政院資通安全辦公室，103.12

**本專案僅參考其技術觀念，未重製其內容。** 具體而言：

| 該等指引的內容 | 本專案的處理 |
|---|---|
| ASP.NET / Java / PHP 程式範例 | **未使用**。本專案的範例均為另行撰寫的 Go / Python / JavaScript |
| 實作建議與說明文字 | **未重製**。本專案改以「掃描器規則對應」的角度重寫 |
| 文件編排與表格設計 | **未沿用**。本專案的 check 檔格式為自行設計 |
| 技術觀念（如 STRIDE、DREAD、SSDLC 階段劃分） | 參考採用。這些本身為國際公開方法論，非該等指引所獨創 |

**原始 PDF 不隨本專案散布。** 請自行至各機關網站取得。

These reference guidelines are cited for their technical concepts only. Their
original PDF documents, implementation examples, and layout remain the
property of the respective agencies and are NOT redistributed by this project.

---

## 國際標準與清單

本專案引用下列公開發布之風險清單編號，用於對照參考：

- OWASP Top 10 (2021, 2025) — Open Worldwide Application Security Project
- OWASP API Security Top 10 (2023)
- OWASP Top 10 for LLM Applications (2025) — OWASP GenAI Security Project
- CWE — MITRE Corporation

引用範圍限於編號與項目名稱，用於建立對照關係，未重製其內容。

---

## 掃描工具規則名稱

`references/checks/` 中列出的掃描器規則名稱（如 Fortify `SQL Injection`、
gosec `G201`、SonarQube `S3649`）為各工具的識別代號，用於說明該工具會如何
標記特定程式碼樣式，屬事實性引用。

各工具名稱與商標分屬其所有者。本專案與 OpenText（Fortify）、
Checkmarx、Sonar、Acunetix、Tenable 等公司無任何從屬或背書關係。
