# TC WoW Analyzer — IDA Pro 9.3 plugin

> **READ THIS FIRST if Claude was launched from this folder.** This plugin is normally developed from
> **`c:\dumps`** Claude sessions, where the canonical project memory and dev scaffolding live. A Claude
> started here is a *separate project with empty memory* and will not see that context unless you read it.
> **Don't rebuild functionality from scratch — extend the existing analyzers.** (This already happened once.)

## What this is
A WIP IDA Pro 9.3 plugin that extracts WoW client knowledge (opcodes, JAM wire types, DB2 schemas, RTTI,
CVars, hashes, vtables, Lua bindings) into a SQLite store and TrinityCore-compatible C++ codegen.

- **Hotkey**: Ctrl+Shift+W · **Menu**: Edit → TC WoW · **Entry**: `tc_wow_analyzer_plugin.py`
- **71 registered analyzers** — authoritative list is the `analyzers = [...]` run loop at
  `analyzers/__init__.py:178`, mirrored 1:1 by `REGISTRY` in `analyzers/registry.py`.
  `tests/static_checks.py` fails if the two drift apart. Do **not** count `.py` files
  (`_dbd_parser.py` etc. are helpers, not analyzers).
- **9 modules**: `analyzers/` `batch/` `codegen/` `core/` `diffing/` `mcp/` `ui/` `tests/`.
- This directory **is its own git repo** (`.git` here). It is the *only* copy of the plugin.
  Note `c:\dumps\tools\ida_enhance\plugins\` is **third-party** IDA plugins — NOT this one.

## Current target build

**WoW 12.1.0.69382** (AutoDump 2026-08-18).

| | |
|---|---|
| ImageBase | `0x7FF780FD0000` (dec 140704806928384) |
| Entry point RVA | `0x1D9E00` |
| SizeOfImage | 115,916,800 |
| DllCharacteristics | `0x8160` (CFG off, as in 12.0.5) |
| Binary | `c:\dumps\wow_dump.bin` |
| Knowledge DB | `c:\dumps\wow_dump.bin.69382.tc_wow.db` (**per build** — see below) |

Prior builds: 68275 (12.0.7), 67186 (12.0.5), 66838, 66198.

### Degenerate 69382 AutoDump outputs (known, not a plugin bug)
`wow_opcode_dispatch` (111 B), `wow_db2_metadata` (2.7 KB vs 473 KB on 67186), `wow_db2_schemas`
(101 B), `wow_updatefields` (273 B), `wow_vtable_methods` (47 methods), `wow_lua_bytecode` (95 B).
The importer now records these in the failure ledger as `import_empty` instead of skipping them
silently, and the affected analyzers fall through to their binary-scan path.

Rich and currently **unconsumed** 69382 sources, in rough order of value:
`wow_handler_stubs` (383 stubs), `wow_func_protos` (23 MB), `wow_offsets` (5.3 MB — the actual name
source, still has no importer), `wow_db2_schemas`, `wow_cvars` (402), `wow_spell_effects` (512).

## Canonical context lives in c:\dumps (read these before working)
- **Project memory**: `C:\Users\daimon\.claude\projects\c--dumps\memory\tc_wow_analyzer_plugin.md`
- **Workspace instructions / build state**: `c:\dumps\CLAUDE.md`
- **AutoDump inputs**: `c:\dumps\wow_*_<build>.json`
- **Dev scaffolding**: `c:\dumps\tools\ida_enhance\scripts\` and `c:\dumps\pipeline\output\`

## Running
- **Static self-check (no IDA needed, run this first after any edit)**:
  `python tests/static_checks.py` — verifies imports resolve, every SQL literal matches the schema,
  run loop == registry, every kv key has a writer, and every analyzer wrapper exists.
- **GUI**: open the IDB in IDA, press Ctrl+Shift+W. Full sequential analysis ≈ 3h.
- **Headless**: `batch/headless.py` (via `c:\dumps\pipeline\tc_wow_headless_run.py`).
  Presets: `quick`, `full` (default), `complete`, `extraction`, `quality`, `llm_only`,
  `analyzers_only`. Steps: 1 import → 2 analyzers → 3 TC source → 4 enrichment → 5 LLM →
  6 conformance → **7 codegen** → report → export → IDB save.
  Every step is isolated: a failing step is logged and the run still reaches the export and the
  IDB save.
- **Per-analyzer probe**: env `TC_ONLY_ANALYZERS=<name>` (or `TC_SKIP_ANALYZERS=`).
- **`TC_SKIP_IDB_SAVE=1` suppresses only the FINAL save** in `batch/headless.py`.
  `idb_enrichment` writes its own per-iteration checkpoints and deliberately
  ignores the variable — an enrichment pass that survives a later crash is worth
  more than a pristine IDB. Copy the `.i64` first if you need an untouched
  baseline.

### Run order matters (measured on 12.1.0.69382)
36 of the 71 analyzers fetch pseudocode via `get_decompiled_text()`, which hits
`cfunc_cache` in the knowledge DB before invoking Hex-Rays. Decompilation
dominates the runtime, so a warm cache is the single biggest speedup available:

  1. `analyzers_only` (or the `build_decompile_cache` task) FIRST — fills
     `cfunc_cache` and applies types via IDB enrichment.
  2. `full` SECOND — every decompiling analyzer then reads from the cache AND
     sees *typed* pseudocode, which is both faster and better input.

Six analyzers early-out when their table is already populated
(`db2_metadata`, `jam_recovery`, `lua_api`, `opcode_dispatcher`,
`update_fields`, `vtable_analyzer`). With the per-build DB that is safe — the
rows are guaranteed to belong to this build — but a later fix to one of those
six will not take effect until its table is cleared.

`topic_deep_extractor` reads pseudocode from `cfunc_cache`, NOT from the IDB,
so its coverage is a function of how warm the cache was when it ran. A low
`primary=` count means a cold cache, not a small subsystem.

## Gotchas (verified against the current code, 2026-08-19)
- **Build detection**: the **image base of the open IDB decides**. A `build_number` in
  `tc_wow_config.json` is only a fallback, and a contradiction is a loud warning. Every build needs a
  `builds["<n>"].image_base` entry — without one, build-scoped lookups are disabled and say so.
- **One database per build**: `db_path` is `<idb>.<build>.tc_wow.db`. AutoDump always overwrites
  `wow_dump.bin`, so a shared name previously mixed 12.0.5 and 12.1 EAs in one file with no build
  column to tell them apart.
- **Archive fallback**: `autodump_candidates()` only offers `<dumps_dir>_<build>/` archives when the
  build is known, skips the current build, and `first_existing()` warns on every archive hit. Pass
  `allow_archive=False` for anything address-bearing (rtti / ctor_dtor / vtable_methods / globals
  already do).
- **DB columns**: opcodes use `tc_name` (not `name`); strings use `value` (not `content`); functions
  have **both** `system` and `subsystem`. No `string_xrefs` table — use `strings.system`.
- **kv keys**: import them from `core/kv_keys.py`, never as string literals. Seven silent
  producer/consumer mismatches were found in one audit; `tests/static_checks.py` now blocks new ones.
- **IDA 9.x type API**: `idc_parse_types`/`parse_decls` reject many decls; use direct
  `tinfo_t.create_udt` / `enum_type_data_t` / `idaapi.get_tinfo` (see `idb_enrichment.py`).
- **No coverage caps**: analyzers run uncapped; the per-instruction guards in `jam_recovery.py` are
  the exception.
- **Plugin-load hang** (~50% of idat starts): suspected Gepetto LM Studio fetch at startup — rename
  `Gepetto/` aside while batch-probing.
- **Threading**: IDA APIs and the SQLite connection belong to the main thread. Use
  `core.utils.run_on_main_thread` (MFF_WRITE) or the scheduler's `_sync()`. The web dashboard
  resolves everything IDA-dependent at start time, on the main thread.

## Git hygiene
Direct-to-master (single-user, edited in place). Tag `backup/pre-12.1-69382` marks the last 12.0.7-era
state. Note the working tree is CRLF while the repo stores LF — run git with `core.autocrlf=true`
(the Windows default) or the whole tree looks modified.
