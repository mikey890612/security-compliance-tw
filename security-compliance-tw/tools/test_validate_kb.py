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


class TestMapping(unittest.TestCase):
    def _write_mapping(self, text):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "mapping.md").write_text(text, encoding="utf-8")
        return d / "mapping.md"

    def test_extracts_mapped_ids(self):
        p = self._write_mapping(
            "| check-id | 附表十 | MAS | 普 | 中 | 高 | Web21 | Web25 | API23 | LLM25 | CWE |\n"
            "|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| SAST-INJ-001 | 4.5.3.1 | — | ◎ | ◎ | ◎ | A03 | A05 | — | LLM05 | CWE-89 |\n"
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



class TestScannerTables(unittest.TestCase):
    def _check_with_table(self, table_md, check_id="SAST-INJ-001", source="sast-demo.md"):
        body = (
            "\n### 掃描器怎麼標\n\n"
            f"{table_md}\n\n"
            "### 壞味道\n```go\nx\n```\n```python\nx\n```\n```javascript\nx\n```\n\n"
            "### 過關寫法\n```go\nx\n```\n```python\nx\n```\n```javascript\nx\n```\n\n"
            "### 常見誤判與處置\nx\n\n"
            "### 判定準則\nx\n"
        )
        return validate_kb.Check(id=check_id, title="demo", body=body, source=source)

    def test_three_column_table_errors(self):
        table = (
            "| 工具 | 規則 | 預設等級 |\n"
            "|---|---|---|\n"
            "| Fortify | SQL Injection | High |\n"
        )
        errors = validate_kb.validate_scanner_tables(self._check_with_table(table))
        self.assertTrue(any("掃描器表" in e or "欄" in e for e in errors), errors)

    def test_invalid_status_ok_errors(self):
        table = (
            "| 工具 | 規則 | 預設等級 | 狀態 | 證據 |\n"
            "|---|---|---|---|---|\n"
            "| Fortify | SQL Injection | High | ok | — |\n"
        )
        errors = validate_kb.validate_scanner_tables(self._check_with_table(table))
        self.assertTrue(any("狀態" in e for e in errors), errors)

    def test_fortify_verified_dash_evidence_errors(self):
        table = (
            "| 工具 | 規則 | 預設等級 | 狀態 | 證據 |\n"
            "|---|---|---|---|---|\n"
            "| Fortify | SQL Injection | High | verified | — |\n"
        )
        errors = validate_kb.validate_scanner_tables(self._check_with_table(table))
        self.assertTrue(any("verified" in e and "證據" in e for e in errors), errors)

    def test_gosec_verified_dash_evidence_errors(self):
        table = (
            "| 工具 | 規則 | 預設等級 | 狀態 | 證據 |\n"
            "|---|---|---|---|---|\n"
            "| gosec | G201 | HIGH | verified | — |\n"
        )
        errors = validate_kb.validate_scanner_tables(self._check_with_table(table))
        self.assertTrue(any("verified" in e and "證據" in e for e in errors), errors)

    def test_mixed_status_with_real_evidence_ok(self):
        table = (
            "| 工具 | 規則 | 預設等級 | 狀態 | 證據 |\n"
            "|---|---|---|---|---|\n"
            "| Fortify | SQL Injection | High | unverified | — |\n"
            "| gosec | G201 | HIGH | verified | gosec G201 on demo/\n"
        )
        errors = validate_kb.validate_scanner_tables(self._check_with_table(table))
        self.assertEqual(errors, [])



class TestMastMdmLanguageRules(unittest.TestCase):
    """MAST/MDM id format and language fence rules (B1 Task 1)."""

    VALID_SCANNER_TABLE = (
        "| 工具 | 規則 | 預設等級 | 狀態 | 證據 |\n"
        "|---|---|---|---|---|\n"
        "| MobSF | demo | HIGH | unverified | — |\n"
    )

    def _sections(self, fences=""):
        return (
            "\n### 掃描器怎麼標\n\n"
            f"{self.VALID_SCANNER_TABLE}\n\n"
            f"### 壞味道\n{fences}\n\n"
            f"### 過關寫法\n{fences}\n\n"
            "### 常見誤判與處置\nx\n\n"
            "### 判定準則\nx\n"
        )

    def _check(self, check_id, fences="", source="mobile-demo.md"):
        return validate_kb.Check(
            id=check_id,
            title="demo",
            body=self._sections(fences),
            source=source,
        )

    def test_mast_id_format_ok(self):
        fences = "```swift\nx\n```\n```kotlin\nx\n```\n"
        errors = validate_kb.validate_checks([self._check("MAST-STORAGE-001", fences)])
        self.assertFalse(any("id 格式" in e for e in errors), errors)
        self.assertEqual(errors, [])

    def test_mdm_id_format_ok(self):
        errors = validate_kb.validate_checks([self._check("MDM-ENROLL-001", fences="")])
        self.assertFalse(any("id 格式" in e for e in errors), errors)
        self.assertEqual(errors, [])

    def test_mast_missing_kotlin_errors(self):
        """平台為「雙平台」時才要求 kotlin——語言需求來自 mapping，不是硬編碼。"""
        fences = "```swift\nx\n```\n"
        rows = {"MAST-STORAGE-001": {"平台": "雙平台", "_schema": "mobile"}}
        errors = validate_kb.validate_checks(
            [self._check("MAST-STORAGE-001", fences)], rows
        )
        self.assertTrue(any("缺少 kotlin" in e for e in errors), errors)

    def test_mast_config_only_does_not_require_kotlin(self):
        """設定檔類的 MAST 只要有 xml 就夠，不該被逼著寫 kotlin 湊數。"""
        fences = '```xml\n<application android:allowBackup="false" />\n```\n'
        rows = {"MAST-STORAGE-003": {"平台": "設定檔", "_schema": "mobile"}}
        errors = validate_kb.validate_checks(
            [self._check("MAST-STORAGE-003", fences)], rows
        )
        self.assertEqual(errors, [])

    def test_mdm_no_language_fences_ok(self):
        # five sections + valid scanner table, no code fences
        errors = validate_kb.validate_checks([self._check("MDM-ENROLL-001", fences="")])
        self.assertFalse(any("缺少" in e and "範例" in e for e in errors), errors)
        self.assertEqual(errors, [])

    def test_sast_still_requires_go_python_javascript(self):
        # only swift/kotlin — must still fail for missing go/python/javascript
        fences = "```swift\nx\n```\n```kotlin\nx\n```\n"
        errors = validate_kb.validate_checks(
            [self._check("SAST-INJ-001", fences, source="sast-demo.md")]
        )
        for lang in ("go", "python", "javascript"):
            self.assertTrue(
                any(f"缺少 {lang}" in e for e in errors),
                f"expected missing {lang}; got {errors}",
            )



class TestConfigFences(unittest.TestCase):
    """設定檔屬性不得只以註解形式藏在 kotlin/swift 區塊裡。

    掃描器實際比對的是 manifest／plist 屬性本身。把它寫成 Kotlin 註解，
    工程師複製那段程式碼時會整段漏掉——而那正是紅字的來源。
    """

    VALID_SCANNER_TABLE = (
        "| 工具 | 規則 | 預設等級 | 狀態 | 證據 |\n"
        "|---|---|---|---|---|\n"
        "| MobSF | demo | HIGH | unverified | — |\n"
    )

    def _check(self, fences, check_id="MAST-STORAGE-003"):
        body = (
            "\n### 掃描器怎麼標\n\n"
            f"{self.VALID_SCANNER_TABLE}\n\n"
            f"### 壞味道\n{fences}\n\n"
            f"### 過關寫法\n{fences}\n\n"
            "### 常見誤判與處置\nx\n\n"
            "### 判定準則\nx\n"
        )
        return validate_kb.Check(
            id=check_id, title="demo", body=body, source="mast-demo.md"
        )

    BOTH_LANGS = "```swift\nx\n```\n```kotlin\nx\n```\n"

    def test_config_attribute_only_in_kotlin_comment_errors(self):
        fences = (
            "```swift\nx\n```\n"
            "```kotlin\n"
            '// Manifest：android:allowBackup="false"\n'
            "val a = 1\n"
            "```\n"
        )
        errors = validate_kb.validate_checks([self._check(fences)])
        self.assertTrue(
            any("設定檔" in e and "android:allowBackup" in e for e in errors), errors
        )

    def test_config_attribute_in_real_xml_fence_ok(self):
        fences = (
            self.BOTH_LANGS
            + "```xml\n"
            '<application android:allowBackup="false" />\n'
            "```\n"
        )
        errors = validate_kb.validate_checks([self._check(fences)])
        self.assertEqual(errors, [])

    def test_plist_marker_needs_plist_fence(self):
        fences = (
            "```kotlin\nx\n```\n"
            "```swift\n"
            "// Info.plist：NSAllowsArbitraryLoads = true\n"
            "```\n"
        )
        errors = validate_kb.validate_checks([self._check(fences)])
        self.assertTrue(
            any("NSAllowsArbitraryLoads" in e for e in errors), errors
        )

    def test_prose_mention_outside_fences_is_not_flagged(self):
        """散文裡提到屬性名是正常的說明，不該被擋。"""
        body = (
            "\n### 掃描器怎麼標\n\n"
            f"{self.VALID_SCANNER_TABLE}\n\n"
            "MobSF 比對的是 android:allowBackup 這個屬性。\n\n"
            f"### 壞味道\n{self.BOTH_LANGS}\n\n"
            f"### 過關寫法\n{self.BOTH_LANGS}\n\n"
            "### 常見誤判與處置\nx\n\n"
            "### 判定準則\nx\n"
        )
        check = validate_kb.Check(
            id="MAST-STORAGE-003", title="demo", body=body, source="mast-demo.md"
        )
        self.assertEqual(validate_kb.validate_checks([check]), [])


class TestDuplicateMappingRow(unittest.TestCase):
    def _write_mapping(self, text):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "mapping.md").write_text(text, encoding="utf-8")
        return d / "mapping.md"

    HEADER = (
        "| check-id | 附表十 | MAS | 普 | 中 | 高 | Web21 | Web25 | API23 | LLM25 | CWE |\n"
        "|---|---|---|---|---|---|---|---|---|---|---|\n"
    )

    def test_detects_duplicate_mapping_row(self):
        p = self._write_mapping(
            self.HEADER
            + "| SAST-INJ-001 | 4.5.3.1 | — | ◎ | ◎ | ◎ | A03 | A05 | — | LLM05 | CWE-89 |\n"
            + "| SAST-INJ-001 | 4.1 | — | ◎ | ◎ | ◎ | A01 | A01 | — | — | CWE-22 |\n"
        )
        rows = validate_kb.parse_mapping(p)
        errors = validate_kb.cross_validate(["SAST-INJ-001"], rows)
        self.assertTrue(any("重複" in e for e in errors), errors)

    def test_mas_and_masvs_columns_parsed_from_mobile_table(self):
        p = self._write_mapping(
            "| check-id | MAS | L1 | L2 | L3 | F | 參 | 平台 | 附表十 | MASVS | MTop10 | CWE |\n"
            "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| MAST-STORAGE-001 | MAS 4.1.2.3.7 | ◎ | ◎ | ◎ |  |  | 雙平台 | —（查檢表外） | MASVS-STORAGE-1 | M9 | CWE-922 |\n"
        )
        rows = validate_kb.parse_mapping(p)
        self.assertEqual(rows["MAST-STORAGE-001"]["MAS"], "MAS 4.1.2.3.7")
        self.assertEqual(rows["MAST-STORAGE-001"]["MASVS"], "MASVS-STORAGE-1")
        self.assertEqual(rows["MAST-STORAGE-001"]["MTop10"], "M9")


class TestPlatformLangRules(unittest.TestCase):
    """MAST 的必要語言由 mapping 的「平台」欄決定，不是一律 kotlin+swift。

    一律要求兩種語言會逼出變形內容：純設定檔議題（manifest 屬性）
    只能把設定檔內容當註解塞進 kotlin 區塊來湊數。
    """

    def test_sast_requires_three_web_languages(self):
        self.assertEqual(
            validate_kb.required_langs("SAST-INJ-001", None),
            ["go", "python", "javascript"],
        )

    def test_dast_and_mdm_require_no_language(self):
        self.assertEqual(validate_kb.required_langs("DAST-HDR-001", None), [])
        self.assertEqual(validate_kb.required_langs("MDM-ENROLL-001", None), [])

    def test_mast_android_requires_kotlin_only(self):
        self.assertEqual(
            validate_kb.required_langs("MAST-PLATFORM-001", "Android"), ["kotlin"]
        )

    def test_mast_ios_requires_swift_only(self):
        self.assertEqual(
            validate_kb.required_langs("MAST-STORAGE-004", "iOS"), ["swift"]
        )

    def test_mast_both_requires_kotlin_and_swift(self):
        self.assertEqual(
            validate_kb.required_langs("MAST-STORAGE-001", "雙平台"),
            ["kotlin", "swift"],
        )

    def test_mast_config_only_requires_no_program_language(self):
        self.assertEqual(validate_kb.required_langs("MAST-NETWORK-001", "設定檔"), [])

    def test_unknown_platform_raises(self):
        with self.assertRaises(ValueError):
            validate_kb.required_langs("MAST-STORAGE-001", "Symbian")


class TestThreeSchemas(unittest.TestCase):
    def _write_mapping(self, text):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "mapping.md").write_text(text, encoding="utf-8")
        return d / "mapping.md"

    WEB = (
        "| check-id | 附表十 | MAS | 普 | 中 | 高 | Web21 | Web25 | API23 | LLM25 | CWE |\n"
        "|---|---|---|---|---|---|---|---|---|---|---|\n"
        "| SAST-INJ-001 | 4.5.3.1 | — | ◎ | ◎ | ◎ | A03 | A05 | — | LLM05 | CWE-89 |\n"
    )
    MOBILE = (
        "| check-id | MAS | L1 | L2 | L3 | F | 參 | 平台 | 附表十 | MASVS | MTop10 | CWE |\n"
        "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
        "| MAST-STORAGE-001 | MAS 4.1.2.3.7 | ◎ | ◎ | ◎ |  |  | 雙平台 | —（查檢表外） | MASVS-STORAGE-1 | M9 | CWE-922 |\n"
    )
    MDM = (
        "| check-id | 附表十 | 普 | 中 | 高 | CWE |\n"
        "|---|---|---|---|---|---|\n"
        "| MDM-ENROLL-001 | —（查檢表外） | ◎ | ◎ | ◎ | — |\n"
    )

    def test_parses_all_three_tables(self):
        p = self._write_mapping(self.WEB + "\n說明文字\n\n" + self.MOBILE + "\n更多說明\n\n" + self.MDM)
        rows = validate_kb.parse_mapping(p)
        self.assertEqual(
            sorted(rows), ["MAST-STORAGE-001", "MDM-ENROLL-001", "SAST-INJ-001"]
        )
        self.assertEqual(rows["SAST-INJ-001"]["_schema"], "web")
        self.assertEqual(rows["MAST-STORAGE-001"]["_schema"], "mobile")
        self.assertEqual(rows["MDM-ENROLL-001"]["_schema"], "mdm")
        self.assertEqual(rows["MAST-STORAGE-001"]["平台"], "雙平台")

    def test_reference_only_item_counts_as_a_level(self):
        rows = {
            "MAST-CRYPTO-004": {
                "check-id": "MAST-CRYPTO-004", "_schema": "mobile",
                "L1": "", "L2": "", "L3": "", "F": "", "參": "◎", "平台": "雙平台",
            }
        }
        self.assertEqual(validate_kb.cross_validate(["MAST-CRYPTO-004"], rows), [])

    def test_mobile_row_needs_some_level(self):
        rows = {
            "MAST-STORAGE-001": {
                "check-id": "MAST-STORAGE-001", "_schema": "mobile",
                "L1": "", "L2": "", "L3": "", "F": "", "參": "", "平台": "雙平台",
            }
        }
        errors = validate_kb.cross_validate(["MAST-STORAGE-001"], rows)
        self.assertTrue(any("至少一個分級" in e for e in errors), errors)

    def test_invalid_platform_reported(self):
        rows = {
            "MAST-STORAGE-001": {
                "check-id": "MAST-STORAGE-001", "_schema": "mobile",
                "L1": "◎", "L2": "", "L3": "", "F": "", "參": "", "平台": "Symbian",
            }
        }
        errors = validate_kb.cross_validate(["MAST-STORAGE-001"], rows)
        self.assertTrue(any("平台" in e for e in errors), errors)


MAS_ITEMS_MD = (
    "| 條號 | 分類 | 條目標題 |\n"
    "|---|---|---|\n"
    "| 4.1.1.1.1 | 參考項目 | 參考 |\n"
    "| 4.1.1.1.2 | L1、L2、L3 | 必要 |\n"
    "| 4.1.1.1.3 | F | 加測 |\n"
)


class TestMasRefs(unittest.TestCase):
    def _items(self):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "controls-mas-v4.md").write_text(MAS_ITEMS_MD, encoding="utf-8")
        return validate_kb.parse_mas_items(d / "controls-mas-v4.md")

    def test_parses_item_numbers_and_classes(self):
        self.assertEqual(
            self._items(),
            {"4.1.1.1.1": "參考項目", "4.1.1.1.2": "L1、L2、L3", "4.1.1.1.3": "F"},
        )

    def test_unknown_mas_ref_errors(self):
        rows = {"MAST-STORAGE-001": {"MAS": "MAS 4.1.1.1.2、MAS 4.9.9.9.9"}}
        errors = validate_kb.validate_mas_refs(rows, self._items())
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("4.9.9.9.9", errors[0])

    def test_missing_items_file_is_empty(self):
        d = pathlib.Path(tempfile.mkdtemp())
        self.assertEqual(validate_kb.parse_mas_items(d / "nope.md"), {})


def _check_md(check_id, status="unverified"):
    evidence = "fixture.json#rule=x" if status == "verified" else "—"
    return (
        f"## {check_id} · demo\n\n"
        "### 掃描器怎麼標\n\n"
        "| 工具 | 規則 | 預設等級 | 狀態 | 證據 |\n"
        "|---|---|---|---|---|\n"
        f"| mobsfscan | demo | HIGH | {status} | {evidence} |\n\n"
        "### 壞味道\nx\n\n### 過關寫法\nx\n\n### 常見誤判與處置\nx\n\n### 判定準則\nx\n\n"
    )


class TestKbFacts(unittest.TestCase):
    def test_counts_come_from_the_kb(self):
        refs = pathlib.Path(tempfile.mkdtemp())
        (refs / "checks").mkdir()
        (refs / "checks" / "sast-demo.md").write_text(
            _check_md("SAST-INJ-001") + _check_md("DAST-HDR-001"), encoding="utf-8"
        )
        (refs / "checks" / "mast-demo.md").write_text(
            _check_md("MAST-STORAGE-001", "verified") + _check_md("MDM-ENROLL-001"),
            encoding="utf-8",
        )
        (refs / "controls-mas-v4.md").write_text(MAS_ITEMS_MD, encoding="utf-8")
        (refs / "quick-patterns.md").write_text(
            "**✅** a\n**❌** b\n\n**✅** c\n", encoding="utf-8"
        )
        checks = validate_kb.parse_checks(refs / "checks")
        rows = {"MAST-STORAGE-001": {"MAS": "MAS 4.1.1.1.1"}}

        facts = validate_kb.kb_facts(refs, checks, rows)

        self.assertEqual(facts["checks"], 4)
        self.assertEqual(facts["web"], 2)
        self.assertEqual(facts["mobile"], 1)
        self.assertEqual(facts["mdm"], 1)
        self.assertEqual(facts["check_files"], 2)
        self.assertEqual(facts["checks_per_file"]["sast-demo.md"], 2)
        self.assertEqual(facts["mas_total"], 3)
        self.assertEqual(facts["mas_covered"], 1)
        self.assertEqual(facts["mas_uncovered"], 2)
        # 未涵蓋的是 L1、L2、L3 與 F；F 是加測，不算必要
        self.assertEqual(facts["mas_uncovered_mandatory"], 1)
        self.assertEqual(facts["mas_uncovered_by_class"]["F"], 1)
        self.assertEqual(facts["mobile_verified_rows"], 1)
        self.assertEqual(facts["quick_patterns"], 2)


class TestDocCounts(unittest.TestCase):
    FACTS = {
        "checks": 90,
        "mobile": 36,
        "checks_per_file": {"sast-injection.md": 4},
        "mas_uncovered_mandatory": 14,
    }

    def _doc(self, text):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "doc.md").write_text(text, encoding="utf-8")
        return d / "doc.md"

    def test_stale_number_reported_with_line(self):
        doc = self._doc("標題\n\n它讀的不是完整的 43 則。\n")
        errors = validate_kb.validate_doc_counts([doc], self.FACTS)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("doc.md:3", errors[0])
        self.assertIn("完整的 43 則", errors[0])
        self.assertIn("90", errors[0])

    def test_correct_numbers_pass(self):
        doc = self._doc("知識庫共 90 則，行動端 36 則。其中 14 條屬必要檢測項目。\n")
        self.assertEqual(validate_kb.validate_doc_counts([doc], self.FACTS), [])

    def test_per_file_table_row_checked(self):
        doc = self._doc("| 檔 | 則數 |\n|---|---|\n| `sast-injection.md` | 5 | 注入 |\n")
        errors = validate_kb.validate_doc_counts([doc], self.FACTS)
        self.assertTrue(any("sast-injection.md" in e for e in errors), errors)

    def test_per_file_table_row_for_unknown_file_expects_zero(self):
        doc = self._doc("| `sast-gone.md` | 3 | 已刪除 |\n")
        errors = validate_kb.validate_doc_counts([doc], self.FACTS)
        self.assertTrue(any("sast-gone.md" in e for e in errors), errors)


class TestReferences(unittest.TestCase):
    """執行期文件的路徑必須存在，且不得跑出 plugin 目錄。"""

    def _plugin(self, skill_text, profile_text="`checks/sast-demo.md`\n"):
        repo = pathlib.Path(tempfile.mkdtemp())
        plugin = repo / "plugin"
        (plugin / "references" / "checks").mkdir(parents=True)
        (plugin / "references" / "templates").mkdir()
        (plugin / "skills" / "sec-audit").mkdir(parents=True)
        (plugin / "tools").mkdir()
        (plugin / "references" / "checks" / "sast-demo.md").write_text("x", encoding="utf-8")
        (plugin / "references" / "templates" / "rtm.md").write_text("x", encoding="utf-8")
        (plugin / "references" / "profile.md").write_text(profile_text, encoding="utf-8")
        (plugin / "references" / "README.md").write_text("`sast-demo.md`\n", encoding="utf-8")
        (plugin / "tools" / "verify_scanners.md").write_text("x", encoding="utf-8")
        (plugin / "skills" / "sec-audit" / "SKILL.md").write_text(
            "`sast-demo.md`\n" + skill_text, encoding="utf-8"
        )
        return plugin

    def test_valid_references_pass(self):
        plugin = self._plugin(
            "讀 `{ROOT}/references/profile.md`、`{ROOT}/references/…`、"
            "`{ROOT}/tools/verify_scanners.md`、`checks/sast-demo.md`、"
            "`templates/rtm.md`、`../../references/profile.md`\n"
        )
        self.assertEqual(validate_kb.validate_references(plugin), [])

    def test_path_escaping_plugin_errors(self):
        plugin = self._plugin("見 `../../../docs/usage/scanner-verification.md`\n")
        errors = validate_kb.validate_references(plugin)
        self.assertTrue(any("plugin 目錄之外" in e for e in errors), errors)

    def test_missing_root_path_errors(self):
        plugin = self._plugin("讀 `{ROOT}/references/gone.md`\n")
        errors = validate_kb.validate_references(plugin)
        self.assertTrue(any("gone.md" in e and "不存在" in e for e in errors), errors)

    def test_root_path_followed_by_chinese_is_not_swallowed(self):
        plugin = self._plugin("讀{ROOT}/references/profile.md之後\n")
        self.assertEqual(validate_kb.validate_references(plugin), [])

    def test_missing_check_file_errors(self):
        plugin = self._plugin("改讀 `checks/mast-gone.md`\n")
        errors = validate_kb.validate_references(plugin)
        self.assertTrue(any("mast-gone.md" in e for e in errors), errors)

    def test_missing_template_errors(self):
        plugin = self._plugin("讀 `templates/gone.md`\n")
        errors = validate_kb.validate_references(plugin)
        self.assertTrue(any("templates/gone.md" in e for e in errors), errors)

    def test_check_file_not_registered_in_profile_errors(self):
        plugin = self._plugin("", profile_text="（沒有列任何 check 檔）\n")
        errors = validate_kb.validate_references(plugin)
        self.assertTrue(
            any("profile.md" in e and "sast-demo.md" in e for e in errors), errors
        )

    def test_installed_snapshot_has_no_repo_docs(self):
        plugin = self._plugin("")
        self.assertEqual(validate_kb.repo_docs(plugin), [])
        (plugin.parent / "install.sh").write_text("", encoding="utf-8")
        (plugin.parent / "README.md").write_text("", encoding="utf-8")
        self.assertEqual(
            [p.name for p in validate_kb.repo_docs(plugin)], ["README.md"]
        )


class TestRootSections(unittest.TestCase):
    BODY = "\n1. 環境變數\n2. 指標檔\n3. fallback\n\n"

    def _skills(self, bodies):
        d = pathlib.Path(tempfile.mkdtemp())
        for name, body in bodies.items():
            (d / name).mkdir()
            text = "# x\n\n" if body is None else f"# x\n\n## 知識庫根目錄（ROOT）{body}---\n\n## 其他\n"
            (d / name / "SKILL.md").write_text(text, encoding="utf-8")
        return d

    def test_identical_sections_pass(self):
        d = self._skills({"a": self.BODY, "b": self.BODY})
        self.assertEqual(validate_kb.validate_root_sections(d), [])

    def test_heading_suffix_is_allowed(self):
        """sec-harden 的標題多了「（先讀這段）」；只比內文。"""
        d = self._skills({"a": self.BODY, "b": "（先讀這段）" + self.BODY})
        self.assertEqual(validate_kb.validate_root_sections(d), [])

    def test_diverging_section_errors(self):
        d = self._skills({"a": self.BODY, "b": self.BODY + "多一行\n"})
        errors = validate_kb.validate_root_sections(d)
        self.assertTrue(any("skills/b/SKILL.md" in e and "不一致" in e for e in errors), errors)

    def test_missing_section_errors(self):
        d = self._skills({"a": self.BODY, "b": None})
        errors = validate_kb.validate_root_sections(d)
        self.assertTrue(any("skills/b/SKILL.md" in e and "缺少" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
