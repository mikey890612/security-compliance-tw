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
            "| check-id | 附表十 | 普 | 中 | 高 | Web21 | Web25 | API23 | LLM25 | Mob25 | CWE |\n"
            "|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| SAST-INJ-001 | 4.5.3.1 | ◎ | ◎ | ◎ | A03 | A05 | — | LLM05 | — | CWE-89 |\n"
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
        errors = validate_kb.validate_checks([self._check("MAST-STORE-001", fences)])
        self.assertFalse(any("id 格式" in e for e in errors), errors)
        self.assertEqual(errors, [])

    def test_mdm_id_format_ok(self):
        errors = validate_kb.validate_checks([self._check("MDM-ENROLL-001", fences="")])
        self.assertFalse(any("id 格式" in e for e in errors), errors)
        self.assertEqual(errors, [])

    def test_mast_missing_kotlin_errors(self):
        fences = "```swift\nx\n```\n"
        errors = validate_kb.validate_checks([self._check("MAST-STORE-001", fences)])
        self.assertTrue(any("缺少 kotlin" in e for e in errors), errors)

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



if __name__ == "__main__":
    unittest.main()
