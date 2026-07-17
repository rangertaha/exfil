# Quick Start

```sh
# scan the current directory (streams matches; progress bar on a terminal)
exfil scan

# query stored findings
exfil search                      # everything
exfil search severity=critical    # by field: rule/cwe/severity/path
exfil search aws                  # free text against rule names

# open the live TUI (mutt-style index + pager)
exfil tui

# look at one record, list rules, clean up
exfil get file:<blake3-hash>
exfil rules
exfil clean
```

## Example scan output

Each finding is `path:line:col SEVERITY [rule] snippet`. The severity tag is
color-coded on a terminal (bright red for critical down to cyan for info) and
plain text when piped, so `grep CRIT` still works. Set `NO_COLOR=1` to disable
color.

```text
./.env:1:26 CRIT [aws-access-key-id] export AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF
./src/config.toml:1:7 HIGH [password-in-url] db = "postgres://admin:hunter2@db.internal/prod"
scanned 3 files (0 unchanged): 2 new matches, 0 unreadable
```

Next: the full [Commands](commands.md) reference, or open the
[TUI](tui.md) for an interactive workbench.
