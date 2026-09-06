"""從《行動應用 App 基本資安檢測基準 V4.0》抽出檢測項目的條號、標題與分類。

只抽條號、標題、分類三項——條文內文屬行動應用資安聯盟著作，不得收錄。

用法：
    pdftotext -layout <V4.0.pdf> mas4.txt
    python3 extract_mas_items.py mas4.txt > items.tsv

正文 §4 每條的版面是欄位式（檢測編號 / 檢測分類 / …），
比附錄二的合併儲存格表格可靠。附錄二僅用於交叉驗證。
"""
import re
import sys

NUM = r"4\.\d+\.\d+\.\d+\.\d+"
HEADING = re.compile(rf"^\s*({NUM})\.\s*(\S.*)$")
FIELD_NO = re.compile(rf"^\s*檢測編號\s+({NUM})\s*$")
FIELD_CLS = re.compile(r"^\s*檢測分類\s+(\S.*?)\s*$")
REF_NO = re.compile(r"^\s*參考編號\s+(REF-\d+)\s*$")
REF_HEAD = re.compile(rf"^\s*({NUM})\s+(\S.*)$")
STOP = re.compile(r"^\s*(檢測編號|參考編號|此項為建議參考項目|\d{1,3})\s*$|^\s*4\.\d")
FIELD_NAMES = ("檢測編號", "此項為建議參考項目", "參考編號", "檢測分類", "檢測依據")


def gather_title(lines, i, first):
    """標題可能折行，續接到句號為止，再於已知欄位名截斷。"""
    parts = [first]
    if "。" not in first:
        for j in range(i + 1, min(i + 6, len(lines))):
            nxt = lines[j]
            if not nxt.strip() or STOP.match(nxt):
                break
            parts.append(nxt.strip())
            if "。" in nxt:
                break
    title = re.sub(r"\s+", "", "".join(parts)).split("。")[0]
    for stop in FIELD_NAMES:
        title = title.split(stop)[0]
    return re.sub(r"\.{3,}.*$|\d+$", "", title)


def extract(path):
    lines = open(path, encoding="utf-8").read().splitlines()
    body_end = max(i for i, l in enumerate(lines) if "附錄一、" in l)
    titles, classes, refs = {}, {}, {}

    for i, line in enumerate(lines[:body_end]):
        h = HEADING.match(line)
        if h:
            num, t = h.group(1), gather_title(lines, i, h.group(2))
            if t and len(t) > len(titles.get(num, "")):
                titles[num] = t
        n = FIELD_NO.match(line)
        if n:
            for j in range(i + 1, min(i + 12, len(lines))):
                c = FIELD_CLS.match(lines[j])
                if c:
                    classes[n.group(1)] = re.sub(r"\s+", "", c.group(1))
                    break

    for i, line in enumerate(lines[body_end:], start=body_end):
        r = REF_NO.match(line)
        if not r:
            continue
        for j in range(i - 1, max(i - 12, body_end), -1):
            hh = REF_HEAD.match(lines[j]) or HEADING.match(lines[j])
            if hh:
                num = hh.group(1)
                # 分類欄只允許 L1/L2/L3/F/參考項目；REF-NN 只是附錄五的
                # 參考編號，不是分類，故一律正規化為「參考項目」。
                refs[num] = "參考項目"
                t = gather_title(lines, j, hh.group(2))
                if t and len(t) > len(titles.get(num, "")):
                    titles[num] = t
                break

    body = "\n".join(lines[:body_end])
    for num in list(titles):
        if num in classes or num in refs:
            continue
        if re.search(
            re.escape(num) + r"\.[^\n]*\n(?:[^\n]*\n){0,5}?[^\n]*此項為建議參考項目",
            body,
        ):
            refs[num] = "參考項目"

    return titles, classes, refs


def main(path):
    titles, classes, refs = extract(path)
    order = sorted(titles, key=lambda s: [int(x) for x in s.split(".")])
    missing = [n for n in order if n not in classes and n not in refs]
    if missing:
        sys.exit(f"分類缺漏：{missing}")
    print(f"# 總條數 {len(order)}｜檢測項目 {len(classes)}｜參考項目 {len(refs)}")
    for num in order:
        print(f"{num}\t{classes.get(num) or refs[num]}\t{titles[num]}")


if __name__ == "__main__":
    main(sys.argv[1])
