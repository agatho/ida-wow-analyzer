# TC WoW Analyzer — IDA Pro Plugin for World of Warcraft Server Development

A comprehensive IDA Pro plugin that accelerates World of Warcraft private server development by extracting game systems knowledge directly from the WoW client binary. Built for the [TrinityCore](https://github.com/TrinityCore/TrinityCore) ecosystem.

---

## Why This Plugin Exists

Building a WoW server emulator requires understanding thousands of client-server interactions: opcodes, packet structures, DB2 schemas, update fields, Lua API bindings, state machines, and more. This knowledge traditionally lives in scattered documentation, years of manual reverse engineering, and tribal knowledge.

**TC WoW Analyzer** automates this entire process. It turns a WoW client binary loaded in IDA Pro into a structured, queryable knowledge base — complete with auto-generated TrinityCore C++ handler code, wire format specifications, conformance scoring against your server implementation, and LLM-powered semantic analysis.

---

## Key Features

### Binary Analysis (55 Analyzers)

| Category | Analyzers | What They Extract |
|---|---|---|
| **Protocol Recovery** | Opcode Dispatcher, JAM Recovery, Wire Format, Response Reconstruction | CMSG/SMSG opcodes, handler addresses, JAM message structures, bit-level serialization formats |
| **Data Structures** | DB2 Metadata, Update Fields, Object Layout, Enum Recovery | Client DB2 table schemas, object update field definitions, C++ class layouts, enum universes |
| **Code Intelligence** | VTable Analysis, Lua API, Call Graph Analytics, Indirect Call Resolution | Virtual dispatch tables, Lua↔C++ bindings, function centrality, virtual call targets |
| **Quality Assurance** | DB2 Drift, Conformance Scoring, Validation Extraction, Sniff Conformance | Schema drift between binary and TC, handler fidelity scores, guard/range checks, packet capture validation |
| **Behavioral Analysis** | State Machines, Taint Analysis, Protocol Sequencing, Behavioral Spec | Implicit state machines, user input flow tracking, packet ordering rules, execution path enumeration |
| **Code Generation** | Pseudocode Transpiler, Handler Scaffolding, Test Generator | Hex-Rays → TC C++ translation, ready-to-compile handler stubs, auto-generated unit tests |
| **Cross-Build** | Build Delta, Multi-Build Temporal, Cross-Build Migration | Semantic diffing between WoW patches, evolution tracking, automatic migration patches |
| **LLM-Powered** | LLM Semantic Decompiler, Sniff Conformance Auto-Fix | AI-driven function naming/annotation, automated divergence fixing |
| **Low-Level** | PE Metadata, Data Archaeology, CVar Extraction, Compiler Artifacts | Exception tables, .rdata mining, console variables, MSVC compiler patterns |
| **Architecture** | Function Similarity, Shared Code Detection, Thread Safety Map, Event System Recovery | Structural clustering, client/server shared code, mutex patterns, event topologies |

### LLM Integration

- **Auto-discovery** of locally installed LLM providers (Ollama, LM Studio)
- **Cloud API support** for OpenAI and Anthropic
- **Generic OpenAI-compatible** endpoint support (vLLM, LocalAI, text-generation-inference)
- **Model selector** with scrollable list of all discovered providers and models
- **Overnight scheduler** — configure time windows (e.g., 23:00–05:00) for unattended LLM-powered analysis with automatic model loading, user activity detection, and pause/resume

### Code Generation

Generate production-ready TrinityCore C++ code directly from binary analysis:

- **Packet structures** — WorldPacket read/write methods matching the binary's wire format
- **DB2 LoadInfo** — complete `LoadInfo` definitions with field types and hotfix SQL
- **UpdateField structs** — object update field enumerations and accessors
- **Opcode enums** — CMSG/SMSG opcode constant definitions
- **Handler scaffolding** — full handler implementations with validation, DB queries, and response packets

### Interactive Dashboards

- **System Navigator** — browse all extracted knowledge by game system (housing, combat, quests, etc.)
- **Quality Dashboard** — 42 specialized views for conformance analysis, wire formats, behavioral specs
- **Web Dashboard** — browser-based analysis UI with 12 API routes and 10 frontend views
- **Housing Deep Dive** — dedicated view for the WoW housing/neighborhood system

### Knowledge Database

All analysis results are stored in a per-IDB SQLite database (WAL mode) with tables for opcodes, JAM types, DB2 tables, functions, update fields, vtables, conformance scores, and more. The database persists across IDA sessions and supports incremental updates.

---

## Requirements

- **IDA Pro 9.0+** with Hex-Rays Decompiler (x86-64)
- **Python 3.10+** (bundled with IDA Pro 9.x)
- **No pip dependencies** — the plugin uses only the Python standard library

### Optional

- **Ollama** or **LM Studio** — for local LLM-powered analysis
- **OpenAI / Anthropic API key** — for cloud LLM analysis
- **TrinityCore source tree** — for conformance scoring and drift detection

---

## Installation

1. Copy `tc_wow_analyzer.py` to your IDA plugins directory:
   ```
   # Windows
   %APPDATA%\Hex-Rays\IDA Pro\plugins\

   # Linux
   ~/.idapro/plugins/

   # macOS
   ~/Library/Application Support/Hex-Rays/IDA Pro/plugins/
   ```

2. Copy the `tc_wow_analyzer/` package directory to the same location:
   ```
   plugins/
     tc_wow_analyzer.py          # Plugin entry point
     tc_wow_analyzer/            # Plugin package
       core/                     # Configuration, database, hooks, LLM, scheduler
       analyzers/                # 55 binary analysis passes
       ui/                       # IDA GUI (dashboards, dialogs, choosers)
       codegen/                  # TrinityCore C++ code generators
       batch/                    # Headless batch processing and data import
       diffing/                  # Cross-build binary comparison
       mcp/                      # MCP tool server integration
   ```

3. Restart IDA Pro. The plugin initializes automatically when a 64-bit binary is loaded.

---

## Usage

### First Launch

1. Open a WoW client binary (x64 PE) in IDA Pro
2. The plugin initializes automatically — look for `[TC-WoW] Plugin loaded` in the Output window
3. Open **Edit > Plugins > TC WoW > Settings...** to configure:
   - **Extraction directory** — where JSON exports are saved
   - **TrinityCore source directory** — for conformance and drift analysis
   - **Build number** and **image base** — for multi-build tracking

### Running Analysis

**Menu:** Edit > Plugins > TC WoW > Run Tasks... (or `Ctrl+Shift+A`)

Select tasks from the scrollable multi-select list organized by category. Default selections cover the core binary analysis passes. Quality and deep extraction tasks can be enabled as needed.

### Using LLM Features

1. **Select a model:** Edit > Plugins > TC WoW > Select LLM Model...
   - The plugin auto-discovers Ollama (port 11434), LM Studio (port 1234), and checks for API keys
   - Pick a provider and model from the list

2. **Run immediately:** Edit > Plugins > TC WoW > Run LLM Task Now... (or `Ctrl+Shift+L`)
   - Choose between LLM Semantic Decompiler or Handler Scaffolding Generator
   - Runs with the selected model

3. **Schedule overnight:** Edit > Plugins > TC WoW > LLM Scheduler...
   - Set a time window (e.g., 23:00–05:00)
   - Select active days and tasks
   - The scheduler auto-loads the model, pauses when you use IDA, resumes when idle

### Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+Shift+W` | Open main dashboard |
| `Ctrl+Shift+A` | Run tasks |
| `Ctrl+Shift+L` | Run LLM task now |
| `Ctrl+Shift+Q` | Quality dashboard |
| `Ctrl+Shift+D` | Web dashboard |

### Python Console

The plugin exposes a `session` variable in IDA's Python console for scripting:

```python
# Query the knowledge database
session.db.fetchall("SELECT tc_name, direction FROM opcodes WHERE system = 'housing'")

# Get analysis statistics
session.db.get_stats()

# Run a specific analyzer programmatically
from tc_wow_analyzer.analyzers.opcode_dispatcher import analyze_opcode_dispatcher
analyze_opcode_dispatcher(session)
```

### Context Menu

Right-click in the disassembly or pseudocode view to access:

- **Analyze Current Function** — run analysis on the function at cursor
- **Lookup Opcode at Cursor** — show opcode info for a handler function
- **Classify Function** — manually tag a function with a game system

---

## Architecture

```
tc_wow_analyzer.py                 Plugin entry point (plugmod_t)
tc_wow_analyzer/
  core/
    session.py                     Central plugin session and action registry
    config.py                      JSON-based configuration (per-IDB)
    db.py                          SQLite knowledge database (WAL mode)
    hooks.py                       IDA UI/IDB event hooks
    llm_provider.py                LLM abstraction (6 backends, auto-discovery)
    scheduler.py                   Overnight LLM scheduler with activity detection
    incremental_engine.py          55-analyzer dependency DAG with change detection
    utils.py                       Logging and utility functions
  analyzers/                       55 analysis passes (see table above)
  ui/
    dashboard.py                   Main system navigator
    conformance_view.py            Quality dashboard (42 views)
    web_dashboard.py               Browser-based dashboard (stdlib HTTP)
    settings_dialog.py             Settings and task runner
    llm_dialog.py                  LLM model selector and quick-run
    scheduler_dialog.py            Overnight scheduler configuration
    housing_view.py                Housing system deep dive
    hexrays_annotations.py         Hex-Rays decompiler annotations
    wire_format_viewer.py          Wire format visualization
  codegen/
    packet_scaffolding.py          WorldPacket C++ generation
    db2_stores.py                  DB2 LoadInfo C++ generation
    update_fields_gen.py           UpdateFields C++ generation
    opcode_enums.py                Opcode enum generation
  batch/
    importer.py                    JSON extraction importer
    tc_source_importer.py          TrinityCore source knowledge importer
    headless.py                    Headless/batch mode support
  diffing/
    build_differ.py                Cross-build binary comparison
  mcp/
    wow_tools.py                   MCP tool server for external integrations
```

---

## Supported WoW Versions

The plugin is designed for the modern WoW client (12.x / The War Within and beyond). It works with any x86-64 WoW PE binary loaded in IDA Pro. Multi-build tracking supports analyzing multiple client versions and generating migration patches between them.

---

## Project Stats

- **88 Python source files**
- **~87,000 lines of code**
- **55 binary analyzers** in dependency-ordered pipeline
- **42 quality dashboard views**
- **6 LLM provider backends** with auto-discovery
- **4 code generators** (packets, DB2, update fields, opcodes)
- **Zero pip dependencies** — pure stdlib

---

## License

This project is provided as-is for use with legitimate WoW server development projects. It requires a licensed copy of IDA Pro with the Hex-Rays Decompiler.

---

## Acknowledgments

Built for the [TrinityCore](https://github.com/TrinityCore/TrinityCore) community to accelerate open-source WoW server development.
