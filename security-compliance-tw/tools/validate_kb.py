"""知識庫結構與對應關係驗證器。純 stdlib，無外部相依。"""

import collections
import dataclasses
import hashlib
import json
import os
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


# ── 文件一致性 ───────────────────────────────────────────────────
# 以下檢查的對象是 SKILL.md、README 等說明文件，不是 check 本身。
# 知識庫每擴充一次，散在各檔的數字與路徑就有機會漏改；這些錯誤
# 不會讓任何一則 check 壞掉，但會讓 agent 讀到錯的指示。

MAS_ITEM_RE = re.compile(r"^\| (4(?:\.\d+){4}) \| ([^|]+?) \|", re.M)
MAS_REF_RE = re.compile(r"MAS (4(?:\.\d+){4})")


def parse_mas_items(path):
    """controls-mas-v4.md → {條號: 分類}。檔案不存在時回傳空 dict。"""
    path = pathlib.Path(path)
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    return {m.group(1): m.group(2).strip() for m in MAS_ITEM_RE.finditer(text)}


def validate_mas_refs(mapping_rows, mas_items):
    """mapping.md 的 MAS 欄引用的條號必須存在於 controls-mas-v4.md。"""
    errors = []
    for cid, row in mapping_rows.items():
        for ref in MAS_REF_RE.findall(row.get("MAS", "")):
            if ref not in mas_items:
                errors.append(f"{cid}: MAS 欄的 {ref} 不在 controls-mas-v4.md")
    return errors


def kb_facts(references_dir, checks, mapping_rows):
    """從知識庫本身算出文件會引用的數字。文件裡寫的數字一律以此為準。"""
    references_dir = pathlib.Path(references_dir)
    prefix = collections.Counter(c.id.split("-", 1)[0] for c in checks)
    mas_items = parse_mas_items(references_dir / "controls-mas-v4.md")
    covered = {
        ref
        for row in mapping_rows.values()
        for ref in MAS_REF_RE.findall(row.get("MAS", ""))
        if ref in mas_items
    }
    uncovered = [cls for num, cls in mas_items.items() if num not in covered]
    mobile_verified = sum(
        1
        for c in checks
        if c.id.startswith("MAST-")
        for table in parse_scanner_tables(c.body)
        for row in table["rows"]
        if row.get("狀態") == "verified"
    )
    commercial = collections.Counter(
        row.get("狀態")
        for c in checks
        for table in parse_scanner_tables(c.body)
        for row in table["rows"]
        if _is_commercial_tool_cell(row.get("工具", ""))
    )
    quick = references_dir / "quick-patterns.md"
    return {
        "checks": len(checks),
        "web": prefix["SAST"] + prefix["DAST"],
        "mobile": prefix["MAST"],
        "mdm": prefix["MDM"],
        "check_files": len(list((references_dir / "checks").glob("*.md"))),
        "checks_per_file": collections.Counter(c.source for c in checks),
        "mas_total": len(mas_items),
        "mas_covered": len(covered),
        "mas_uncovered": len(uncovered),
        # L1／L2／L3 是必要檢測項目；F 是加測、參考項目非必要
        "mas_uncovered_mandatory": sum(1 for cls in uncovered if cls.startswith("L")),
        "mas_uncovered_by_class": collections.Counter(uncovered),
        "mobile_verified_rows": mobile_verified,
        "commercial_verified_rows": commercial["verified"],
        "commercial_partial_rows": commercial["partial"],
        "quick_patterns": (
            quick.read_text(encoding="utf-8").count("**✅**") if quick.exists() else 0
        ),
    }


# 文件裡寫死的數字：(regex, kb_facts 的鍵)。每個 match 的數字都必須等於實際值。
# 一個群組 → 純量；兩個群組 → (鍵, 數字)，比對 kb_facts 裡的 Counter。
# ⚠ 改寫句子讓 regex 對不上時不會報錯——新增或改寫含數字的句子，要同步這張表。
DOC_COUNT_CLAIMS = [
    (r"共 (\d+) 則", "checks"),
    (r"(\d+) 則 check", "checks"),
    (r"涵蓋範圍（(\d+) 則）", "checks"),
    (r"checks/\s+(\d+) 則", "checks"),
    (r"完整的 (\d+) 則", "checks"),
    (r"目前 (\d+) 則檢查", "checks"),
    (r"伺服器與 Web (\d+) 則", "web"),
    (r"行動端 (\d+) 則", "mobile"),
    (r"MDM[`*-]* (\d+) 則", "mdm"),
    (r"這 (\d+) 則\*\*不計入", "mdm"),
    (r"則 check，(\d+) 個檔", "check_files"),
    (r"^\| `([a-z0-9-]+\.md)` \| (\d+) \|", "checks_per_file"),
    (r"(\d+) 條的條號", "mas_total"),
    (r"(\d+) 條條號", "mas_total"),
    (r"標題（(\d+) 條）", "mas_total"),
    (r"(\d+) 條中", "mas_total"),
    (r"目前有 (\d+) 條", "mas_covered"),
    (r"其餘 (\d+) 條沒有", "mas_uncovered"),
    (r"未涵蓋的 (\d+) 條", "mas_uncovered"),
    (r"(\d+) 條流程類", "mas_uncovered"),
    (r"(\d+) 條源碼判不出來", "mas_uncovered"),
    (r"那 (\d+) 條全部是", "mas_uncovered"),
    (r"這 (\d+) 條本來就", "mas_uncovered"),
    (r"其中 (\d+) 條目前尚無對應", "mas_uncovered"),
    (r"其中 (\d+) 條屬必要檢測項目", "mas_uncovered_mandatory"),
    (r"^\| (L1、L2、L3|L1、L2|L2、L3|L3|F|參考項目) \| (\d+) \|$", "mas_uncovered_by_class"),
    (r"(\d+) 列掃描器對照", "mobile_verified_rows"),
    (r"(\d+) 列商用對照已 verified", "commercial_verified_rows"),
    (r"已 verified、(\d+) 列 partial", "commercial_partial_rows"),
    (r"寫的當下能預防」的 (\d+) 則", "quick_patterns"),
    (r"濃縮速查（(\d+) 則）", "quick_patterns"),
]
_DOC_COUNT_CLAIMS = [(re.compile(p, re.M), key) for p, key in DOC_COUNT_CLAIMS]

# skill 執行期會讀到的文件，與只在 repo 裡存在的文件
RUNTIME_DOC_GLOBS = (
    "skills/*/SKILL.md",
    "references/*.md",
    "references/templates/*.md",
    "tools/*.md",
)
REPO_DOC_GLOBS = ("README.md", "docs/usage/*.md")


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def _display(path, base):
    """相對於 plugin 目錄顯示；repo 根目錄的檔案會顯示成 ../README.md。"""
    return os.path.relpath(path, base)


def _inside(path, base):
    """Path.is_relative_to 要 3.9 以上；這裡只要求 Python 3。"""
    try:
        pathlib.Path(path).relative_to(base)
        return True
    except ValueError:
        return False


def runtime_docs(plugin_dir):
    plugin_dir = pathlib.Path(plugin_dir)
    return [p for g in RUNTIME_DOC_GLOBS for p in sorted(plugin_dir.glob(g))]


def repo_docs(plugin_dir):
    """repo 根目錄的 README 與使用說明。已安裝的快照沒有 repo 根目錄，回傳空清單。"""
    repo = pathlib.Path(plugin_dir).parent
    if not (repo / "install.sh").exists():
        return []
    return [p for g in REPO_DOC_GLOBS for p in sorted(repo.glob(g))]


def validate_doc_counts(doc_paths, facts, base=None):
    """文件裡寫死的數字必須等於 kb_facts 算出的實際值。"""
    errors = []
    for path in doc_paths:
        text = pathlib.Path(path).read_text(encoding="utf-8")
        name = _display(path, base) if base else pathlib.Path(path).name
        for regex, key in _DOC_COUNT_CLAIMS:
            for m in regex.finditer(text):
                if regex.groups == 2:
                    label = f"{key}[{m.group(1)}]"
                    expected = facts[key].get(m.group(1), 0)
                    claimed = int(m.group(2))
                else:
                    label = key
                    expected = facts[key]
                    claimed = int(m.group(1))
                if claimed != expected:
                    errors.append(
                        f"{name}:{_line_of(text, m.start())}: 寫「{m.group(0).strip()}」，"
                        f"實際 {label} = {expected}"
                    )
    return errors


# re.ASCII：\w 預設會吃進中文，路徑後面緊接中文字時會被算成路徑的一部分
ROOT_PATH_RE = re.compile(r"\{ROOT\}/([\w./*-]*[\w*/-])", re.ASCII)
CHECK_FILE_REF_RE = re.compile(r"`(?:checks/)?((?:sast|dast|mast|mdm)-[a-z0-9-]+\.md)`")
TEMPLATE_REF_RE = re.compile(r"`templates/([a-z0-9-]+\.md)`")
REL_PATH_RE = re.compile(r"(?<![\w/])((?:\.\./)+(?:[\w-]+/)*[\w-]+\.\w+)", re.ASCII)

# 每個 check 檔都必須出現在這些檔案裡，否則 agent 不會知道要載入它
CHECK_FILE_REGISTRIES = (
    "references/profile.md",
    "references/README.md",
    "skills/sec-audit/SKILL.md",
)


def validate_references(plugin_dir):
    """執行期文件裡的路徑必須存在，且不得指向 plugin 目錄之外。

    install.sh 只複製 plugin 目錄；repo 根目錄的 docs/、README.md 不在
    安裝後的快照裡，指過去的相對路徑安裝後必定失效。
    """
    plugin_dir = pathlib.Path(plugin_dir).resolve()
    references = plugin_dir / "references"
    errors = []

    for path in runtime_docs(plugin_dir):
        text = path.read_text(encoding="utf-8")
        name = _display(path, plugin_dir)

        for m in ROOT_PATH_RE.finditer(text):
            rel = m.group(1).rstrip(".")
            target = plugin_dir / rel
            if "*" in rel:
                ok = any(plugin_dir.glob(rel))
            elif rel.endswith("/"):
                ok = target.is_dir()
            else:
                ok = target.exists()
            if not ok:
                errors.append(f"{name}:{_line_of(text, m.start())}: {{ROOT}}/{rel} 不存在")

        for m in CHECK_FILE_REF_RE.finditer(text):
            if not (references / "checks" / m.group(1)).exists():
                errors.append(
                    f"{name}:{_line_of(text, m.start())}: checks/{m.group(1)} 不存在"
                )

        for m in TEMPLATE_REF_RE.finditer(text):
            if not (references / "templates" / m.group(1)).exists():
                errors.append(
                    f"{name}:{_line_of(text, m.start())}: templates/{m.group(1)} 不存在"
                )

        for m in REL_PATH_RE.finditer(text):
            target = (path.parent / m.group(1)).resolve()
            where = f"{name}:{_line_of(text, m.start())}"
            if not _inside(target, plugin_dir):
                errors.append(
                    f"{where}: {m.group(1)} 指向 plugin 目錄之外，安裝後會失效"
                )
            elif not target.exists():
                errors.append(f"{where}: {m.group(1)} 不存在")

    for check_file in sorted((references / "checks").glob("*.md")):
        for registry in CHECK_FILE_REGISTRIES:
            reg_path = plugin_dir / registry
            if reg_path.exists() and check_file.name not in reg_path.read_text(
                encoding="utf-8"
            ):
                errors.append(f"{registry}: 沒有列出 checks/{check_file.name}")

    return errors


ROOT_SECTION_HEADING = "## 知識庫根目錄（ROOT）"


def _root_section(text):
    """回傳 ROOT 段落的內文（不含標題列）；找不到時回傳 None。"""
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.startswith(ROOT_SECTION_HEADING):
            body = []
            for nxt in lines[i + 1:]:
                if nxt.startswith("## ") or nxt == "---":
                    break
                body.append(nxt)
            return "\n".join(body).strip()
    return None


def validate_root_sections(skills_dir):
    """三支 skill 的 ROOT 段落必須逐字相同。

    段落無法抽成共用檔——要先解析出 ROOT 才讀得到共用檔——只能各抄一份，
    所以由這裡確保沒有人只改了其中一份。
    """
    errors = []
    sections = {}
    for path in sorted(pathlib.Path(skills_dir).glob("*/SKILL.md")):
        body = _root_section(path.read_text(encoding="utf-8"))
        name = f"skills/{path.parent.name}/SKILL.md"
        if body is None:
            errors.append(f"{name}: 缺少「{ROOT_SECTION_HEADING}」段落")
        else:
            sections[name] = body
    if len(set(sections.values())) > 1:
        reference_name, reference_body = next(iter(sections.items()))
        for name, body in sections.items():
            if body != reference_body:
                errors.append(f"{name}: ROOT 段落與 {reference_name} 不一致")
    return errors


# ── 版本 ─────────────────────────────────────────────────────────
# 版本號只有一個來源：.claude-plugin/plugin.json。skill 與知識庫的內容一變，
# 使用者就該被告知有新版——但人會忘記調升版本號。release-lock.json 記錄
# 上次發布的版本與內容指紋：內容變了、版本卻還是已發布的那一版，就擋下來。

FINGERPRINT_DIRS = ("skills", "references")
SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
CHANGELOG_HEADING_RE = re.compile(r"^## (\d+\.\d+\.\d+)(?:（(.+?)）)?\s*$", re.M)
UNRELEASED = "未發布"


def content_fingerprint(plugin_dir):
    """skills/ 與 references/ 的內容指紋。換行統一成 LF，Windows checkout 不會誤判。"""
    plugin_dir = pathlib.Path(plugin_dir)
    digest = hashlib.sha256()
    for top in FINGERPRINT_DIRS:
        for path in sorted((plugin_dir / top).rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.name == ".DS_Store":
                continue
            digest.update(path.relative_to(plugin_dir).as_posix().encode("utf-8") + b"\0")
            digest.update(path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return "sha256:" + digest.hexdigest()


def _semver(text):
    m = SEMVER_RE.match(text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def changelog_entries(path):
    """CHANGELOG.md → {版本: 標題括號內的文字（日期或「未發布」）}。"""
    path = pathlib.Path(path)
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    return {m.group(1): (m.group(2) or "") for m in CHANGELOG_HEADING_RE.finditer(text)}


def validate_version(version, lock, fingerprint, changelog):
    """內容一變就必須是未發布的新版本，且 CHANGELOG 有對應的一節。"""
    errors = []
    current, released = _semver(version), _semver(lock.get("version"))
    if current is None:
        return [f"plugin.json 的 version {version!r} 不是 X.Y.Z 格式"]
    if released is None:
        return [f"release-lock.json 的 version {lock.get('version')!r} 不是 X.Y.Z 格式"]

    if current < released:
        errors.append(f"plugin.json 的 version {version} 比已發布的 {lock['version']} 舊")
    elif current == released and fingerprint != lock.get("fingerprint"):
        errors.append(
            f"skills/ 或 references/ 的內容已變更，但版本仍是已發布的 {version}："
            "調升 .claude-plugin/plugin.json 的 version，並在 CHANGELOG.md 加一節"
            f"「## 新版本（{UNRELEASED}）」"
        )

    if version not in changelog:
        errors.append(f"CHANGELOG.md 沒有「## {version}」這一節")
    elif current == released and changelog[version] == UNRELEASED:
        errors.append(
            f"CHANGELOG.md 的 {version} 仍標「{UNRELEASED}」，但它已經發布——改成發布日期"
        )
    return errors


def validate_released(version, lock):
    """--require-released：合併進 main 的版本必須已標記發布。"""
    if version != lock.get("version"):
        return [
            f"版本 {version} 尚未發布（release-lock.json 是 {lock.get('version')}）："
            f"把 CHANGELOG.md 的「{UNRELEASED}」改成日期，執行 "
            "python3 tools/validate_kb.py --release，並提交 tools/release-lock.json"
        ]
    return []


VERSION_MENTION_RE = re.compile(r"sec-harden v(\d+\.\d+\.\d+)")


def validate_version_mentions(doc_paths, version, base=None):
    """說明文件裡的標記範例（sec-harden vX.Y.Z）必須是目前版本。"""
    errors = []
    for path in doc_paths:
        text = pathlib.Path(path).read_text(encoding="utf-8")
        name = _display(path, base) if base else pathlib.Path(path).name
        for m in VERSION_MENTION_RE.finditer(text):
            if m.group(1) != version:
                errors.append(
                    f"{name}:{_line_of(text, m.start())}: 寫「{m.group(0)}」，目前版本是 {version}"
                )
    return errors


def release(plugin_dir):
    """把目前版本標為已發布：寫入 release-lock.json。回傳錯誤清單。"""
    plugin_dir = pathlib.Path(plugin_dir)
    version = json.loads((plugin_dir / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))["version"]
    entries = changelog_entries(plugin_dir / "CHANGELOG.md")
    if version not in entries:
        return [f"CHANGELOG.md 沒有「## {version}」這一節，先補上再發布"]
    if entries[version] == UNRELEASED:
        return [f"CHANGELOG.md 的 {version} 仍標「{UNRELEASED}」，先改成發布日期再發布"]
    lock = {"version": version, "fingerprint": content_fingerprint(plugin_dir)}
    (plugin_dir / "tools" / "release-lock.json").write_text(
        json.dumps(lock, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return []


def main():
    plugin = pathlib.Path(__file__).resolve().parent.parent
    if "--release" in sys.argv[1:]:
        release_errors = release(plugin)
        if release_errors:
            for e in release_errors:
                print(f"發布失敗：{e}")
            return 1
        print("已寫入 tools/release-lock.json")

    root = plugin / "references"
    checks = parse_checks(root / "checks")

    mapping_path = root / "mapping.md"
    mapping_rows = parse_mapping(mapping_path) if mapping_path.exists() else {}

    errors = validate_checks(checks, mapping_rows)
    if mapping_path.exists():
        errors += cross_validate([c.id for c in checks], mapping_rows)
    else:
        errors.append("references/mapping.md 不存在")

    errors += validate_mas_refs(
        mapping_rows, parse_mas_items(root / "controls-mas-v4.md")
    )
    errors += validate_references(plugin)
    errors += validate_root_sections(plugin / "skills")

    manifest = plugin / ".claude-plugin" / "plugin.json"
    lock_path = plugin / "tools" / "release-lock.json"
    if not lock_path.exists():
        errors.append("tools/release-lock.json 不存在")
    else:
        version = json.loads(manifest.read_text(encoding="utf-8"))["version"]
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        errors += validate_version(
            version,
            lock,
            content_fingerprint(plugin),
            changelog_entries(plugin / "CHANGELOG.md"),
        )
        if "--require-released" in sys.argv[1:]:
            errors += validate_released(version, lock)
        errors += validate_version_mentions(
            runtime_docs(plugin) + repo_docs(plugin), version, base=plugin
        )
    errors += validate_doc_counts(
        runtime_docs(plugin) + repo_docs(plugin),
        kb_facts(root, checks, mapping_rows),
        base=plugin,
    )

    if errors:
        print(f"知識庫驗證失敗（{len(errors)} 項）：")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"知識庫驗證通過：{len(checks)} 則 check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
