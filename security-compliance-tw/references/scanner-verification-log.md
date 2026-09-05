# 掃描器驗證紀錄

| 日期 | 工具 | 版本 | 對應 checks | 結果摘要 | 操作者 |
|------|------|------|-------------|----------|--------|
| 2026-09-05 | gosec | dev (securego/gosec/v2@latest) | sast-injection (INJ-001 G202, INJ-002 G204); sast-errors (ERR-002 G104) | sample-go: 10 findings; verified 3 rows; artifact `testdata/scan-artifacts/open-source/20260905T084457Z/gosec.json` | 埕碩 許 |
| 2026-09-05 | bandit | 1.9.4 | sast-injection (INJ-001 B608, INJ-002 B602); sast-authz (AUTHZ-004 B103) | sample-multi (+insecure.py): 4 findings; verified 3 rows; artifact `testdata/scan-artifacts/open-source/20260905T084457Z/bandit.json` | 埕碩 許 |
| 2026-09-05 | semgrep | 1.176.1 | sast-injection (INJ-001 string-formatted-query, INJ-002 dangerous-exec-command, INJ-004 xss ResponseWriter) | sample-go+sample-multi: 8 findings; verified 3 rows; artifact `testdata/scan-artifacts/open-source/20260905T084457Z/semgrep.json` | 埕碩 許 |
