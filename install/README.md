# Install manifest

`targets.tsv` drives `./install.sh`. Each row is one agent install target.

## Columns (tab-separated)

| Column | Meaning |
|---|---|
| `id` | Target id used by `--list` / `--only` (e.g. `claude`) |
| `enabled` | `1` = active, `0` = skipped |
| `mode` | `skill-dir` (copy skills) or `doc-only` (print hint only) |
| `dest_template` | Destination path template; required for `skill-dir` |

Comments start with `#`. Blank `dest_template` is allowed for `doc-only`.

## Path placeholders

- `~` expands to `$HOME`
- `{skill}` expands to each of: `sec-audit`, `sec-harden`, `sec-deliverables`

## Add a new target

1. Append one TSV row (tabs, not spaces), for example:

```tsv
my-agent	1	skill-dir	~/.my-agent/skills/{skill}
```

Or for documentation-only agents:

```tsv
my-agent	1	doc-only	
```

2. Run `./install.sh --list` and confirm the new id appears.
3. Run `./install.sh --dry-run` (and later a real install) to verify paths.
4. Document user-facing notes in `docs/usage/install.md` when that file exists.

## Disable a target

Set `enabled` to `0`, or remove the row. Prefer `0` so history stays visible.
