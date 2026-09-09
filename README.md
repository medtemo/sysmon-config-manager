# Sysmon Config Manager (Web UI)

A browser-based UI for loading, editing, validating, and applying Sysmon XML
configuration files — Flask backend + a modern HTML/CSS/JS frontend (no
build step, no framework, just plain JS).

## Setup (WSL / Linux / macOS / Windows)

```bash
pip install -r requirements.txt
python3 server.py                          # blank config
python3 server.py path/to/config.xml       # load a config on startup
python3 server.py path/to/config.xml --host 0.0.0.0   # also reachable from other devices on your network
python3 server.py --port 5050              # use a different port
```

Then open **http://127.0.0.1:5000** in your browser.

## Features

- **Categorized sidebar navigation** — event types grouped into Process &
  Execution / File & Storage / Network & Remote / Registry & System / Other,
  with a filter box and rule-count badges. Collapsible (‹ toggle) to hand
  more width to the rule editor.
- **Rule table** with Excel-style column controls — click a header to sort,
  use the filter row under the headers to filter any column (including a
  **Status** column for Added/Modified/Deleted/Unchanged), and drag a
  column's right edge to resize it. Per-row **Duplicate / Edit / Delete**
  appear on hover to keep the table clean; Duplicate opens the Add-Rule form
  pre-filled from that row (value text pre-selected for quick editing) and
  saves as a brand-new rule, leaving the original untouched. A dashed
  underline + warning icon flags any field not in the active schema.
- **Templates** — a built-in, offline library of MITRE ATT&CK-mapped
  detection rules (T1055 process injection, T1218 LOLBin proxy execution,
  T1003 credential access, T1547 persistence, and more). Selecting one
  shows a preview of the exact XML it would add before you confirm.
- **Changes / Validation / XML Preview** tabs (in that order) on the right —
  collapsible (› toggle) and narrower by default so the rule editor gets
  the room. Validation flags unknown tags, invalid conditions, un-escaped
  `&`, fields outside the documented schema, and `include` blocks with no
  rules (which silently log nothing).
- **Open** — upload a local file from your browser, or load a file by
  server-side path (handy since the Flask process and your files are
  typically on the same machine).
- **Save** — writes to a path on the server's filesystem.
- **Download** — downloads the current config as a `.xml` file via the
  browser.
- **Apply to Sysmon** — saves, then runs `sysmon.exe -c <path>` if a Sysmon
  binary is found on PATH (Windows only, needs Administrator; see
  `apply.py`).
- **Dark/light theme toggle** (◐ button, top right; remembered via
  localStorage).
- **Multi-version schema support** — bundled Sysmon schema exports (v4.82,
  v4.90, v4.91, from real `sysmon -s` output) constrain which event types,
  fields, and conditions are offered. The active schema is shown as a badge
  in the top bar with a dropdown to switch, plus an "Upload…" button to add
  your own `sysmon -s` export (session-only, not persisted to disk).
  Validation, the sidebar, and the Add/Edit Rule form all respect whichever
  schema is currently active.
- **Include/Exclude filter** — a prominent All/Include/Exclude segmented
  toggle filters the rule table and nested groups by `onmatch`.
- **Section tree** — each Include/Exclude header is the parent of the rules
  and nested-group cards below it: children are indented and hang off a
  vertical spine (green for include, amber for exclude) aligned to the
  header's own collapse chevron, so it's clear at a glance which section a
  row belongs to. The two headers pin to the top of the table as you scroll
  (native `position: sticky`, stacked — Exclude comes to rest under
  Include), and stay put once pinned.
- **Nested group management** — each group card has a colored left-border
  connector distinguishing its rows from standalone ones, a one-click
  **collapse/expand** toggle (plus **Collapse All / Expand All** for the
  whole section — collapsed cards show a filter-count summary), an inline
  **AND/OR** toggle right on the header, **Duplicate** (review popup
  pre-filled with the group's name/AND-OR/include-exclude, same pattern as
  duplicating a single rule — nothing is created until you confirm; all its
  filters are cloned along automatically), and **Edit** (change its label,
  AND/OR relation, and include/exclude — changing match type moves just
  that one group to the matching bucket, siblings untouched).
- **Change tracking & diff** — opening a file snapshots it as a baseline.
  Edits are tracked against that baseline for the whole session (surviving
  Save; only resets on New/Open): added rows are tinted green, modified
  rows amber (with a before→after in the Changes panel), deleted rows show
  struck-through in red — deleted rows stay visually anchored inside their
  original group card if that group still exists. Nested groups themselves
  are tracked too (added/deleted/modified — renaming, flipping AND/OR, or
  changing include/exclude all count). Every changed row or card gets a
  **Revert** button: added → removed, modified → restored, deleted →
  re-inserted with its original ID and position (including inside a nested
  group, or the whole group itself if that was deleted too). The **Changes**
  tab lists every pending change across all event types with its own search
  box; **View** scrolls straight to it and briefly highlights it without
  switching away from whichever side-panel tab you're currently on.

## Project layout

```
sysmon_manager_web/
  server.py          Flask REST API + serves the static frontend
  schema_loader.py   Parses `sysmon -s` manifest XML exports (UTF-8/UTF-16)
  schema_registry.py Holds all loaded schema versions + tracks the active one
  schemas/           Bundled default manifests (4.82.xml, 4.90.xml, 4.91.xml)
  model.py           In-memory data model (+ diff-revert support)
  xml_io.py          XML parsing/serialization (preserves comments)
  validator.py       Config validation rules (driven by the active schema)
  diff.py            Baseline-vs-current change detection
  templates.py       Built-in MITRE ATT&CK rule templates
  apply.py           Applies a saved config via `sysmon.exe -c`
  static/
    index.html       Page shell
    style.css         Dark/light theme, modern flat design
    app.js            All frontend logic (vanilla JS, fetch-based)
  requirements.txt
```

## REST API (for reference / scripting)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/schema` | Event types, fields, conditions |
| GET | `/api/state` | Current config (serialized) |
| GET | `/api/preview` | Current config as XML text |
| GET | `/api/validate` | Validation issues |
| GET | `/api/templates` | Built-in templates |
| GET | `/api/download` | Download current config as a file |
| POST | `/api/new` | Reset to a blank config |
| POST | `/api/open` | Load a config (multipart `file`, or JSON `{"path": ...}`) |
| POST | `/api/save` | Save to JSON `{"path": ...}` |
| POST | `/api/rules` | Add a rule (also used for Duplicate) |
| PUT | `/api/rules/<uid>` | Edit a rule |
| DELETE | `/api/rules/<uid>` | Delete a rule |
| POST | `/api/templates/<id>/insert` | Insert a template's rules |
| POST | `/api/apply` | Save + apply to the local Sysmon service |
| GET | `/api/schemas` | List available schema versions |
| POST | `/api/schemas/activate` | Switch the active schema, JSON `{"version": ...}` |
| POST | `/api/schemas/upload` | Upload a custom `sysmon -s` manifest (multipart `file`) |
| PUT | `/api/rulegroups/relation` | Set a RuleGroup's AND/OR, JSON `{"name":, "group_relation":}` |
| PUT | `/api/groups/<uid>` | Edit a nested group's name/relation/onmatch |
| POST | `/api/groups/<uid>/duplicate` | Duplicate a nested group and its filters |
| GET | `/api/diff` | Added/modified/deleted rules & groups vs. baseline |
| POST | `/api/revert/rule/<uid>` | Revert one rule's change |
| POST | `/api/revert/group/<uid>` | Revert one nested group's change (add or delete) |

## Notes

- This is a single-user local tool: the Flask process holds one in-memory
  config. It's meant to run on `127.0.0.1` on your own machine, not as a
  shared multi-user service.
- "Apply to Sysmon" only works on Windows (Sysmon itself is Windows-only).
  From WSL2, it works if `sysmon64.exe`/`sysmon.exe` is reachable on PATH
  (Windows interop is on by default in WSL2).
