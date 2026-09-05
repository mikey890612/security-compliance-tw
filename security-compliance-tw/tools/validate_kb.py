"""知識庫結構與對應關係驗證器。純 stdlib，無外部相依。"""

import dataclasses
import pathlib
import re
import sys

CHECK_ID_RE = re.compile(r"^(SAST|DAST|MAST|MDM)-[A-Z]+-\d{3}$")
HEADING_RE = re.compile(r"^##\s+(\S+)\s+·\s+(.+?)\s*$", re.MULTILINE)

REQUIRED_SECTIONS = [
    "掃描器怎麼標",
    "壞味道",
    "過關寫法",
    "常見誤判與處置",
    "判定準則",
]

REQUIRED_LANGS = ["go", "python", "javascript"]

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
            errors.append(f"{where}: id 格式不符 {{SAST|DAST|MAST|MDM}}-主題-三位數字")
            continue

        if c.id in seen:
            errors.append(f"{where}: check-id 重複")
        seen.add(c.id)

        for section in REQUIRED_SECTIONS:
            if f"### {section}" not in c.body:
                errors.append(f"{where}: 缺少「{section}」小節")

        # 註：此處檢查整則 check 的內文，未細分到「過關寫法」小節。
        # 涵蓋所需語言即通過，屬刻意放寬的近似檢查。
        # MAST → swift+kotlin；SAST → go/python/javascript；MDM/DAST → 無語言圍欄要求。
        if c.id.startswith("MAST-"):
            for lang in ("swift", "kotlin"):
                if f"```{lang}" not in c.body:
                    errors.append(f"{where}: 缺少 {lang} 範例")
        elif c.id.startswith("SAST-"):
            for lang in REQUIRED_LANGS:
                if f"```{lang}" not in c.body:
                    errors.append(f"{where}: 缺少 {lang} 範例")
        # elif MDM- or DAST-: no SAST/MAST language requirements

        errors.extend(validate_scanner_tables(c))

    return errors


MAPPING_COLUMNS = [
    "check-id", "附表十", "普", "中", "高",
    "Web21", "Web25", "API23", "LLM25", "Mob25", "CWE",
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
