"""知識庫結構與對應關係驗證器。純 stdlib，無外部相依。"""

import dataclasses
import pathlib
import re
import sys

CHECK_ID_RE = re.compile(r"^(SAST|DAST)-[A-Z]+-\d{3}$")
HEADING_RE = re.compile(r"^##\s+(\S+)\s+·\s+(.+?)\s*$", re.MULTILINE)

REQUIRED_SECTIONS = [
    "掃描器怎麼標",
    "壞味道",
    "過關寫法",
    "常見誤判與處置",
    "判定準則",
]

REQUIRED_LANGS = ["go", "python", "javascript"]


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
            errors.append(f"{where}: id 格式不符 {{SAST|DAST}}-主題-三位數字")
            continue

        if c.id in seen:
            errors.append(f"{where}: check-id 重複")
        seen.add(c.id)

        for section in REQUIRED_SECTIONS:
            if f"### {section}" not in c.body:
                errors.append(f"{where}: 缺少「{section}」小節")

        # 註：此處檢查整則 check 的內文，未細分到「過關寫法」小節。
        # 涵蓋三語言即通過，屬刻意放寬的近似檢查。
        if c.id.startswith("SAST-"):
            for lang in REQUIRED_LANGS:
                if f"```{lang}" not in c.body:
                    errors.append(f"{where}: 缺少 {lang} 範例")

    return errors


MAPPING_COLUMNS = [
    "check-id", "附表十", "普", "中", "高",
    "Web21", "Web25", "API23", "LLM25", "CWE",
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
