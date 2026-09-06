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

LANGS_BY_PREFIX = {
    "SAST": ["go", "python", "javascript"],
    "DAST": [],
    "MDM": [],
}

# MAST 的必要語言由 mapping 的「平台」欄決定。一律要求 kotlin+swift 會逼出
# 變形內容——純設定檔議題（manifest 屬性）只能把設定檔當註解塞進 kotlin 湊數。
LANGS_BY_PLATFORM = {
    "Android": ["kotlin"],
    "iOS": ["swift"],
    "雙平台": ["kotlin", "swift"],
    "設定檔": [],
}


def required_langs(check_id, platform):
    """回傳該 check 必須具備的程式碼圍籬語言清單。"""
    prefix = check_id.split("-", 1)[0]
    if prefix != "MAST":
        return LANGS_BY_PREFIX.get(prefix, [])
    if platform not in LANGS_BY_PLATFORM:
        raise ValueError(f"未知的平台值：{platform!r}")
    return LANGS_BY_PLATFORM[platform]

ALLOWED_STATUSES = frozenset({"verified", "unverified", "partial"})
COMMERCIAL_TOOLS = frozenset(
    {"Fortify", "Checkmarx", "AWVS", "WebInspect", "Nessus"}
)
SCANNER_TABLE_COLUMNS = ["工具", "規則", "預設等級", "狀態", "證據"]

# 設定檔屬性：掃描器實際比對的就是這些字面樣式（manifest 屬性、plist 鍵）。
# 它們必須以可複製的設定檔圍籬呈現，不可只當註解塞在 kotlin/swift 區塊裡——
# 工程師複製那段程式碼時會整段漏掉，而那正是紅字的來源。
CONFIG_MARKERS = [
    "android:allowBackup",
    "android:debuggable",
    "android:exported",
    "android:usesCleartextTraffic",
    "cleartextTrafficPermitted",
    "fullBackupContent",
    "dataExtractionRules",
    "network_security_config",
    "NSAllowsArbitraryLoads",
    "NSAppTransportSecurity",
    "NSExceptionMinimumTLSVersion",
    "UIFileSharingEnabled",
    "<pin-set",
]
CONFIG_FENCE_LANGS = ("xml", "plist", "gradle", "properties", "json")
CODE_FENCE_LANGS = ("kotlin", "swift", "java", "objectivec")

FENCE_RE = re.compile(r"^```([a-zA-Z]*)\n(.*?)^```", re.S | re.M)


def _is_commercial_tool_cell(tool_cell: str) -> bool:
    return any(name in tool_cell for name in COMMERCIAL_TOOLS)


def _fences(body):
    """回傳 [(語言, 內容)]。語言為空字串代表未標註。"""
    return [(m.group(1).lower(), m.group(2)) for m in FENCE_RE.finditer(body)]


def validate_config_fences(check):
    """設定檔屬性若出現在程式碼圍籬內，必須另有可複製的設定檔圍籬。

    只檢查出現在 kotlin/swift 等程式碼圍籬內的情況——散文裡提到屬性名
    是正常的說明，不在此限。
    """
    errors = []
    where = f"{check.source} / {check.id}"
    fences = _fences(check.body)

    in_code = set()
    in_config = set()
    for lang, content in fences:
        bucket = None
        if lang in CODE_FENCE_LANGS:
            bucket = in_code
        elif lang in CONFIG_FENCE_LANGS:
            bucket = in_config
        if bucket is None:
            continue
        for marker in CONFIG_MARKERS:
            if marker in content:
                bucket.add(marker)

    for marker in sorted(in_code - in_config):
        errors.append(
            f"{where}: 設定檔屬性 {marker} 只出現在程式碼圍籬內"
            f"（多半是註解），需另附 {'/'.join(CONFIG_FENCE_LANGS[:3])} 圍籬"
        )
    return errors


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


def validate_checks(checks, mapping_rows=None):
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
        row = (mapping_rows or {}).get(c.id)
        # MAST 的平台來自 mapping；沒有 mapping 列時平台無從得知，
        # 交給 cross_validate 報「未出現在 mapping.md」，不要在這裡用 None 去撞
        if not (c.id.startswith("MAST-") and row is None):
            platform = (row or {}).get("平台")
            try:
                langs = required_langs(c.id, platform)
            except ValueError as exc:
                errors.append(f"{where}: {exc}")
                langs = []
            for lang in langs:
                if f"```{lang}" not in c.body:
                    errors.append(f"{where}: 缺少 {lang} 範例")
            if platform == "設定檔" and not any(
                f"```{f}" in c.body for f in CONFIG_FENCE_LANGS
            ):
                errors.append(
                    f"{where}: 設定檔類 check 至少需一種 "
                    f"{'/'.join(CONFIG_FENCE_LANGS[:3])} 範例"
                )

        errors.extend(validate_scanner_tables(c))
        errors.extend(validate_config_fences(c))

    return errors


SCHEMAS = {
    "web": [
        "check-id", "附表十", "MAS", "普", "中", "高",
        "Web21", "Web25", "API23", "LLM25", "CWE",
    ],
    "mobile": [
        "check-id", "MAS", "L1", "L2", "L3", "F", "參",
        "平台", "附表十", "MASVS", "MTop10", "CWE",
    ],
    # MDM 是規格外的延伸（機關端裝置管理政策，非 App 程式碼）。
    # 獨立一張表就是它的隔離方式：欄位少，且不假裝掛得上 OWASP 清單。
    "mdm": ["check-id", "附表十", "普", "中", "高", "CWE"],
}

LEVEL_COLUMNS = {
    "web": ("普", "中", "高"),
    "mobile": ("L1", "L2", "L3", "F", "參"),
    "mdm": ("普", "中", "高"),
}


def _cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _is_separator(cells):
    return all(set(c) <= set("-: ") and c for c in cells)


def parse_mapping(mapping_path):
    """解析 mapping.md 的三張表，回傳 {check-id: {欄位: 值, '_schema': 名稱}}。

    由表頭文字決定 schema，不用欄數——欄數相同的兩張表無從分辨。
    欄數不符的列整列丟棄（避免 zip 截短產生錯位資料），後果由
    cross_validate 以「未出現在 mapping.md」報出。
    重複的 check-id 標記 _duplicate，直接覆蓋會讓其中一列無聲消失。
    """
    rows = {}
    current = None
    for line in pathlib.Path(mapping_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            current = None
            continue
        cells = _cells(line)
        if _is_separator(cells):
            continue
        for name, cols in SCHEMAS.items():
            if cells == cols:
                current = name
                break
        else:
            if current is None:
                continue
            cols = SCHEMAS[current]
            if len(cells) != len(cols):
                continue
            row = dict(zip(cols, cells))
            row["_schema"] = current
            if cells[0] in rows:
                row["_duplicate"] = True
            rows[cells[0]] = row
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
        if row.get("_duplicate"):
            errors.append(f"{cid}: mapping.md 有重複的列")
        schema = row.get("_schema", "web")
        levels = LEVEL_COLUMNS[schema]
        if not any(row.get(lv, "").strip() for lv in levels):
            errors.append(
                f"{cid}: 至少一個分級欄位必須標記 ◎（{'/'.join(levels)}）"
            )
        if schema == "mobile":
            platform = row.get("平台", "").strip()
            if platform not in LANGS_BY_PLATFORM:
                errors.append(f"{cid}: 平台欄值無效 {platform!r}")

    return errors


def main():
    root = pathlib.Path(__file__).resolve().parent.parent / "references"
    checks = parse_checks(root / "checks")

    mapping_path = root / "mapping.md"
    mapping_rows = parse_mapping(mapping_path) if mapping_path.exists() else {}

    errors = validate_checks(checks, mapping_rows)
    if mapping_path.exists():
        errors += cross_validate([c.id for c in checks], mapping_rows)
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
