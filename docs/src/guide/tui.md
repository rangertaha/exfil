# The TUI

`exfil tui` is a full-screen, app-style workbench over the findings graph. The
layout has four parts:

- a **stats bar** across the top — total findings, a colored per-severity tally,
  and live scan progress (toggle it with `t`);
- a **left menu** of sections — Findings, Files, Indicators, Events, Rules,
  Scans, Datasets — the active one highlighted;
- the main **data grid** for the active section (findings show as
  `S · RULE · LOCATION · MATCH`, color-coded by severity so the grid reads as a
  heat map); and
- a **status/command bar** at the bottom that shows the current keys and becomes
  the `:` command / `/` filter input line while you type.

## Fixing a finding

On a finding row:

- **`Enter`** opens the file in your editor (`$EDITOR`/`$VISUAL`, falling back to
  `nvim`/`vim`/`vi`/`nano`) at the finding's line.
- **`v`** shows the source *inside* the TUI, with every finding in that file
  marked in the gutter (`▶`), scrolled to the selected one.

## Editing & classifying records

Press **`c`** on any row to edit it in place — set its **severity**, add
**metadata**, or change any field. Type `field=value` (e.g. `note=known-c2`,
`confidence=0.9`), or just a bare severity word (`high`) as a shortcut for
`severity=high`. Findings and browsed records (domains, packages, indicators,
rules, …) are all editable; the change persists to the store and the grid
reloads.

## Navigating the graph

Press **`n`** on a finding to open the **graph navigator**, which renders as
cascading *Miller columns*: a breadcrumb path on top, then one panel per visited
node (each listing its edges). `l`/`Enter` descends (a new panel opens on the
right), `h`/`<` pops back; older panels compress and drop onto the breadcrumb
when they don't fit. The far-right pane previews the focused node's fields. In
the navigator, `c` edits a field and `d` deletes the selected edge, with `u`/`U`
to undo/redo.

## Keys

| Key | Action |
|---|---|
| `j`/`k`, arrows, `g`/`G` | move through the grid |
| `Tab` / `Shift-Tab` | switch section |
| `Enter` | open the finding in `$EDITOR` at its line |
| `v` | view the source in-TUI, findings marked in the gutter |
| `c` | edit the selected row (`field=value`, or a bare severity word) |
| `n` | open the finding's file in the graph navigator |
| `/` | limit (filter) the grid, mutt-style |
| `:` | command bar: `scan [path]`, `rules`, `get <id>`, `clean`, `quit` |
| `s` | scan the current directory |
| `t` | show / hide the stats bar |
| `r` | reload from the store |
| `?` | in-app key reference |
| `q` | quit (or leave a view) |
