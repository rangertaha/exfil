# The TUI

`exfil tui` is a live, mutt-style workbench: run scans (with a progress gauge
and findings streaming in), browse the index, and open a finding in the pager
with its file record. `/` limits the index; `:` opens a command bar.

Each finding row is color-coded by severity — bold red for critical, cooling
through yellow and blue down to gray for unrated rules — so the index reads as
a heat map at a glance. A severity tally (`C:2 H:5 …`) sits in the status bar.

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
