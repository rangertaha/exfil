# The TUI

`exfil tui` is a live, mutt-style workbench: run scans (with a progress gauge
and findings streaming in), browse the index, and open a finding in the pager
with its file record. `/` limits the index; `:` opens a command bar.

## Keys

| Key | Action |
|---|---|
| `j`/`k`, arrows | move through the findings index |
| `Enter` | open the finding in the pager (with its file record) |
| `/` | limit (filter) the index, mutt-style |
| `:` | command bar: `scan [path]`, `rules`, `get <id>`, `clean`, `quit` |
| `s` | scan the current directory |
| `r` | reload findings from the store |
| `q` | quit (or leave the pager) |
