# TC WoW Analyzer — IDA Pro 9.3 plugin

> **READ THIS FIRST if Claude was launched from this folder.** This plugin is normally developed from
> **`c:\dumps`** Claude sessions, where the canonical project memory and dev scaffolding live. A Claude
> started here is a *separate project with empty memory* and will not see that context unless you read it.
> **Don't rebuild functionality from scratch — extend the existing analyzers.** (This already happened once.)

## What this is
A WIP IDA Pro 9.3 plugin that extracts WoW client knowledge (opcodes, JAM wire types, DB2 schemas, RTTI,
CVars, hashes, vtables, Lua bindings) into a SQLite store and TrinityCore-compatible C++ codegen.

- **Hotkey**: Ctrl+Shift+W · **Menu**: Edit → Plugins → TC WoW Analyzer · **Entry**: `tc_wow_analyzer_plugin.py`
- **70 registered analyzers** — authoritative list is the `analyzers = [...]` registry at
  `analyzers/__init__.py:122`. Do **not** count `.py` files (`_dbd_parser.py` etc. are helpers, not analyzers).
- **8 modules**: `analyzers/` `batch/` `codegen/` `core/` `diffing/` `mcp/` `ui/` (+`__pycache__/`).
- This directory **is its own git repo** (`.git` here). It is the *only* copy of the plugin.
  Note `c:\dumps\tools\ida_enhance\plugins\` is **third-party** IDA plugins — NOT this one.

## Canonical context lives in c:\dumps (read these before working)
- **Project memory** (the full implementation history — hash facts, struct layouts, gotchas, per-analyzer
  notes): `C:\Users\daimon\.claude\projects\c--dumps\memory\tc_wow_analyzer_plugin.md`
- **Workspace instructions / build state**: `c:\dumps\CLAUDE.md`
- **Data store**: `c:\dumps\wow_dump.bin.tc_wow.db` (SQLite — the analyzers' output)
- **AutoDump inputs**: `c:\dumps\wow_*_<build>.json` (current build 67186; migrating to 12.0.7 / 68235)
- **Dev scaffolding**: `c:\dumps\tools\ida_enhance\scripts\` (hash tooling, probe runners) and
  `c:\dumps\pipeline\output\` (standalone, no-IDA runners)

**Best practice: do plugin work from a `c:\dumps` Claude session** so the project memory auto-loads.
If you must work from here, first read the two files above.

## Running
- **GUI**: open the IDB in IDA, press Ctrl+Shift+W. Full sequential analysis ≈ 3h (single idat session).
- **Headless preset**: `batch/headless.py` (via `c:\dumps\pipeline\tc_wow_headless_run.py`). Presets include
  `analyzers_only` (skip importer/TC-import/enrichment/LLM/QA/save — ~20s per-analyzer probes) and `full`.
- **Per-analyzer probe**: env `TC_ONLY_ANALYZERS=<name>` (or `TC_SKIP_ANALYZERS=`), runner
  `c:\dumps\tools\ida_enhance\scripts\probe_analyzers_individually.py`.

## Gotchas (carried from memory — verify against current code)
- **DB columns**: opcodes use `tc_name` (not `name`); strings use `value` (not `content`); functions use
  `subsystem` (not `system`). No `string_xrefs` table — use `strings.system` autodump tags.
- **IDA 9.x type API**: `idc_parse_types`/`parse_decls` reject many decls; use direct
  `tinfo_t.create_udt` / `enum_type_data_t` / `idaapi.get_tinfo` paths (see `idb_enrichment.py`).
- **No coverage caps**: user prefers analyzers run uncapped; algorithmic per-instruction guards in
  `jam_recovery.py` are the exception.
- **Plugin-load hang** (~50% of idat starts): suspected Gepetto LM Studio fetch at startup — rename
  `Gepetto/` aside while batch-probing.
- **LLM**: client supports a `claude-cli` provider (subscription via subprocess) + LM Studio/Ollama aliases.

## Git hygiene
Last commit `296d723` (2026-03-09). As of 2026-06-25 there are **uncommitted modifications** in
`analyzers/__init__.py`, `cross_build_migration.py`, `cvar_extraction.py`, `db2_data_content.py`,
`execution_trace_sim.py`, `function_similarity.py`, `idb_enrichment.py`, `return_value_semantics.py`,
`update_fields.py`, `batch/headless.py`. Commit before the 12.0.7 migration churn.
