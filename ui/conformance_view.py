"""
Conformance & Quality Dashboard
Provides IDA chooser views for conformance scores, validation gaps,
state machines, dependency maps, and generated test cases.
"""

import ida_kernwin
import idaapi

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn


# ─── Conformance Scorecard ────────────────────────────────────────

class ConformanceChooser(ida_kernwin.Choose):
    """Shows per-handler conformance scores (binary vs TC)."""

    COLUMNS = [
        ["Handler", 30],
        ["Score", 8],
        ["Calls", 8],
        ["Branches", 8],
        ["Validation", 8],
        ["Size", 8],
        ["Issues", 40],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Conformance Scores",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        from tc_wow_analyzer.analyzers.conformance import get_conformance_report
        report = get_conformance_report(self._session)

        self._items = []
        if not report:
            return

        for h in report.get("handlers", []):
            missing = "; ".join(h.get("missing", []))
            self._items.append([
                h.get("tc_name", "?"),
                f"{h.get('score', 0)}%",
                f"{h.get('call_score', 0)}%",
                f"{h.get('branch_score', 0)}%",
                f"{h.get('validation_score', 0)}%",
                f"{h.get('size_score', 0)}%",
                missing or "OK",
            ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 7

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]

    def OnSelectLine(self, n):
        sel = n[0] if isinstance(n, list) else n
        if sel < len(self._items):
            handler = self._items[sel][0]
            msg_info(f"Selected handler: {handler}")


# ─── System Scores Summary ───────────────────────────────────────

class SystemScoresChooser(ida_kernwin.Choose):
    """Shows per-system average conformance scores."""

    COLUMNS = [
        ["System", 20],
        ["Avg Score", 10],
        ["Handlers", 10],
        ["Min", 8],
        ["Max", 8],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: System Conformance",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        from tc_wow_analyzer.analyzers.conformance import get_conformance_report
        report = get_conformance_report(self._session)

        self._items = []
        if not report:
            return

        for sys_name, data in sorted(
            report.get("system_scores", {}).items(),
            key=lambda x: x[1].get("average_score", 0)
        ):
            self._items.append([
                sys_name,
                f"{data.get('average_score', 0)}%",
                str(data.get("handler_count", 0)),
                f"{data.get('min_score', 0)}%",
                f"{data.get('max_score', 0)}%",
            ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Validation Gaps ─────────────────────────────────────────────

class ValidationGapsChooser(ida_kernwin.Choose):
    """Shows handlers where TC is missing validation checks."""

    COLUMNS = [
        ["Handler", 30],
        ["Binary Checks", 12],
        ["TC Checks", 12],
        ["Missing", 8],
        ["Details", 40],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Missing Validations",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        import json
        db = self._session.db
        report = db.kv_get("validation_comparison_report") or {}

        self._items = []
        for item in report.get("items", []):
            missing_desc = []
            for m in item.get("missing", [])[:3]:
                missing_desc.append(f"{m.get('type', '?')}: {m.get('condition', '?')[:50]}")

            self._items.append([
                item.get("handler", "?"),
                str(item.get("binary_total", 0)),
                str(item.get("tc_total", 0)),
                str(item.get("missing_count", 0)),
                "; ".join(missing_desc) or "—",
            ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── State Machines ──────────────────────────────────────────────

class StateMachineChooser(ida_kernwin.Choose):
    """Shows recovered state machines."""

    COLUMNS = [
        ["State Variable", 25],
        ["States", 8],
        ["Transitions", 10],
        ["Handlers", 40],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: State Machines",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        from tc_wow_analyzer.analyzers.state_machine import get_state_machines
        machines = get_state_machines(self._session)

        self._items = []
        for sm in machines:
            handlers = ", ".join(sm.get("handlers", [])[:5])
            self._items.append([
                sm.get("name", "?"),
                str(sm.get("state_count", 0)),
                str(sm.get("transition_count", 0)),
                handlers,
            ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 4

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]

    def OnSelectLine(self, n):
        sel = n[0] if isinstance(n, list) else n
        if sel < len(self._items):
            from tc_wow_analyzer.analyzers.state_machine import generate_state_enum
            sm_name = self._items[sel][0]
            code = generate_state_enum(self._session, sm_name)
            msg_info(f"Generated enum for {sm_name}:\n{code}")


# ─── Dependency Map ──────────────────────────────────────────────

class DependencyMapChooser(ida_kernwin.Choose):
    """Shows cross-system dependency edges."""

    COLUMNS = [
        ["From System", 15],
        ["To System", 15],
        ["Weight", 8],
        ["Handlers", 8],
        ["Shared Functions", 40],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: System Dependencies",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        from tc_wow_analyzer.analyzers.dependency_mapper import get_dependency_map
        dep_map = get_dependency_map(self._session)

        self._items = []
        for edge in dep_map.get("edges", []):
            shared = ", ".join(edge.get("shared_functions", [])[:3])
            self._items.append([
                edge.get("from", "?"),
                edge.get("to", "?"),
                str(edge.get("weight", 0)),
                str(edge.get("handler_count", 0)),
                shared or "—",
            ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── DB2 Drift ───────────────────────────────────────────────────

class DB2DriftChooser(ida_kernwin.Choose):
    """Shows DB2 schema drift between binary and TC."""

    COLUMNS = [
        ["Table", 25],
        ["Severity", 10],
        ["Binary Fields", 12],
        ["TC Fields", 12],
        ["Details", 40],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: DB2 Schema Drift",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        from tc_wow_analyzer.analyzers.db2_drift import get_drift_report
        report = get_drift_report(self._session)

        self._items = []
        for item in report.get("drift_items", []):
            self._items.append([
                item.get("table", "?"),
                item.get("severity", "?").upper(),
                str(item.get("binary_fields", 0)),
                str(item.get("tc_fields", 0)),
                item.get("message", "")[:80],
            ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Test Cases ──────────────────────────────────────────────────

class TestCasesChooser(ida_kernwin.Choose):
    """Shows generated test cases."""

    COLUMNS = [
        ["Test Name", 35],
        ["Category", 15],
        ["Handler", 25],
        ["Priority", 8],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Generated Tests",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        from tc_wow_analyzer.analyzers.test_generator import get_generated_tests
        tests = get_generated_tests(self._session)

        self._items = []
        for t in tests:
            self._items.append([
                t.get("test_name", "?"),
                t.get("category", "?"),
                t.get("handler", "?"),
                t.get("priority", "?"),
            ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 4

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]

    def OnSelectLine(self, n):
        sel = n[0] if isinstance(n, list) else n
        if sel < len(self._items):
            test_name = self._items[sel][0]
            tests = get_generated_tests_by_name(self._session, test_name)
            if tests:
                msg_info(f"Test code:\n{tests[0].get('code', '(no code)')}")


def get_generated_tests_by_name(session, test_name):
    """Helper to find a test by name."""
    from tc_wow_analyzer.analyzers.test_generator import get_generated_tests
    return [t for t in get_generated_tests(session)
            if t.get("test_name") == test_name]


# ─── Wire Format ─────────────────────────────────────────────────

class WireFormatChooser(ida_kernwin.Choose):
    """Shows recovered bit-level wire formats."""

    COLUMNS = [
        ["Opcode", 30],
        ["Fields", 8],
        ["Bits Total", 10],
        ["Has Optional", 10],
        ["Has Arrays", 10],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Wire Formats",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("wire_formats") or {}
        self._items = []
        for name, fmt in sorted(data.items()) if isinstance(data, dict) else []:
            fields = fmt.get("fields", [])
            total_bits = sum(f.get("bit_size", 0) for f in fields)
            has_opt = any(f.get("is_optional") for f in fields)
            has_arr = any(f.get("is_array") for f in fields)
            self._items.append([
                name,
                str(len(fields)),
                str(total_bits),
                "Yes" if has_opt else "No",
                "Yes" if has_arr else "No",
            ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Enum Recovery ───────────────────────────────────────────────

class EnumRecoveryChooser(ida_kernwin.Choose):
    """Shows recovered enum types."""

    COLUMNS = [
        ["Enum Name", 25],
        ["Key", 20],
        ["Values", 8],
        ["Type", 10],
        ["Flags?", 6],
        ["Sources", 8],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Recovered Enums",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        enums = self._session.db.kv_get("recovered_enums") or []
        self._items = []
        for e in (enums if isinstance(enums, list) else []):
            self._items.append([
                e.get("suggested_name", "?"),
                e.get("key", "?"),
                str(e.get("value_count", 0)),
                e.get("underlying_type", "?"),
                "Yes" if e.get("is_flags") else "No",
                str(e.get("source_function_count", 0)),
            ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 6

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]

    def OnSelectLine(self, n):
        sel = n[0] if isinstance(n, list) else n
        if sel < len(self._items):
            try:
                from tc_wow_analyzer.analyzers.enum_recovery import generate_enum_cpp
                key = self._items[sel][1]
                code = generate_enum_cpp(self._session, key)
                msg_info(f"Generated enum:\n{code}")
            except Exception as e:
                msg_info(f"Enum: {self._items[sel][0]} ({self._items[sel][1]})")


# ─── Object Layout ──────────────────────────────────────────────

class ObjectLayoutChooser(ida_kernwin.Choose):
    """Shows recovered C++ class layouts."""

    COLUMNS = [
        ["Class", 25],
        ["Fields", 8],
        ["Size", 10],
        ["Sources", 8],
        ["Inheritance", 25],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Object Layouts",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        layouts = self._session.db.kv_get("object_layouts") or []
        self._items = []
        for layout in (layouts if isinstance(layouts, list) else []):
            inheritance = ", ".join(layout.get("inheritance", [])[:3])
            self._items.append([
                layout.get("class_name", "?"),
                str(layout.get("field_count", 0)),
                f"0x{layout.get('total_size', 0):X}",
                str(layout.get("source_function_count", 0)),
                inheritance or "—",
            ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Taint Analysis ────────────────────────────────────────────

class TaintAnalysisChooser(ida_kernwin.Choose):
    """Shows unguarded taint flows (security issues)."""

    COLUMNS = [
        ["Handler", 25],
        ["Severity", 8],
        ["Source", 20],
        ["Sink", 20],
        ["Category", 15],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Taint Analysis (Security)",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        report = self._session.db.kv_get("taint_analysis") or {}
        self._items = []
        for flow in report.get("flows", report.get("results", [])):
            if isinstance(flow, dict):
                source = flow.get("source", {})
                sink = flow.get("sink", {})
                self._items.append([
                    flow.get("handler", "?"),
                    flow.get("severity", "?").upper(),
                    source.get("read_call", source.get("variable", "?"))[:20],
                    sink.get("operation", sink.get("category", "?"))[:20],
                    sink.get("category", "?"),
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Protocol Sequencing ───────────────────────────────────────

class ProtocolSequenceChooser(ida_kernwin.Choose):
    """Shows recovered protocol sequencing rules."""

    COLUMNS = [
        ["Handler", 25],
        ["Phase", 8],
        ["Prerequisites", 30],
        ["Sets State", 20],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Protocol Sequences",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("protocol_sequences") or {}
        self._items = []
        for handler in data.get("handlers", data.get("sequences", [])):
            if isinstance(handler, dict):
                prereqs = ", ".join(str(p) for p in handler.get("prerequisites", [])[:3])
                writes = ", ".join(str(w) for w in handler.get("state_writes", [])[:3])
                self._items.append([
                    handler.get("name", handler.get("handler", "?")),
                    str(handler.get("phase", "?")),
                    prereqs or "none",
                    writes or "—",
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 4

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Transpiled Handlers ──────────────────────────────────────

class TranspiledHandlerChooser(ida_kernwin.Choose):
    """Shows transpiled handler code (Hex-Rays → TC C++)."""

    COLUMNS = [
        ["Handler", 30],
        ["Confidence", 10],
        ["Unresolved", 10],
        ["Lines", 8],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        self._data = []
        super().__init__(
            "TC WoW: Transpiled Handlers",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("transpiled_handlers") or {}
        self._items = []
        self._data = []
        items = data.get("handlers", data) if isinstance(data, dict) else []
        if isinstance(items, dict):
            items = list(items.values())
        for h in (items if isinstance(items, list) else []):
            if isinstance(h, dict):
                code = h.get("code", "")
                self._items.append([
                    h.get("handler", h.get("name", "?")),
                    f"{h.get('confidence', 0)}%",
                    str(h.get("unresolved_count", 0)),
                    str(code.count("\n") + 1 if code else 0),
                ])
                self._data.append(h)

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 4

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]

    def OnSelectLine(self, n):
        sel = n[0] if isinstance(n, list) else n
        if sel < len(self._data):
            code = self._data[sel].get("code", "(no code)")
            msg_info(f"Transpiled code:\n{code[:2000]}")


# ─── Game Constants ──────────────────────────────────────────────

class GameConstantsChooser(ida_kernwin.Choose):
    """Shows mined game constants."""

    COLUMNS = [
        ["Suggested Name", 30],
        ["Value", 12],
        ["Category", 12],
        ["System", 12],
        ["Function", 25],
        ["Mismatch?", 10],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Game Constants",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("game_constants") or {}
        constants = data.get("constants", []) if isinstance(data, dict) else []
        self._items = []
        for c in constants[:500]:
            if isinstance(c, dict):
                val = c.get("value", 0)
                val_str = f"{val}" if isinstance(val, (int, float)) else str(val)
                self._items.append([
                    c.get("suggested_name", "?"),
                    val_str,
                    c.get("category", "?"),
                    c.get("system", "?"),
                    c.get("function", "?")[:25],
                    "MISMATCH" if c.get("is_mismatch") else "OK",
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 6

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── IDB Enrichment ─────────────────────────────────────────────

class IDBEnrichmentChooser(ida_kernwin.Choose):
    """Shows IDB enrichment results (renames, retypes, comments)."""

    COLUMNS = [
        ["Action", 12],
        ["Address", 16],
        ["Old Name", 25],
        ["New Name", 25],
        ["Source", 15],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: IDB Enrichment",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("idb_enrichment") or {}
        self._items = []
        for action in data.get("actions", [])[:500]:
            if isinstance(action, dict):
                self._items.append([
                    action.get("type", "?"),
                    action.get("ea", "?"),
                    action.get("old_name", "")[:25],
                    action.get("new_name", "")[:25],
                    action.get("source", "?"),
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── String Intelligence ───────────────────────────────────────

class StringIntelligenceChooser(ida_kernwin.Choose):
    """Shows string-derived intelligence (recovered names, system boundaries)."""

    COLUMNS = [
        ["Suggested Name", 30],
        ["Address", 16],
        ["Source String", 35],
        ["Confidence", 10],
        ["Category", 12],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: String Intelligence",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("string_intelligence") or {}
        self._items = []
        for item in data.get("recovered_names", [])[:500]:
            if isinstance(item, dict):
                self._items.append([
                    item.get("suggested_name", "?"),
                    item.get("ea", "?"),
                    item.get("source_string", "")[:35],
                    f"{item.get('confidence', 0)}%",
                    item.get("category", "?"),
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Cross-Analyzer Synthesis ──────────────────────────────────

class SynthesisChooser(ida_kernwin.Choose):
    """Shows unified per-handler synthesis with coverage scores."""

    COLUMNS = [
        ["Handler", 25],
        ["Coverage", 10],
        ["Conformance", 10],
        ["Taint Flows", 10],
        ["Priority", 10],
        ["Analyzers", 8],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Cross-Analyzer Synthesis",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("synthesis_report") or {}
        self._items = []
        for h in data.get("handler_profiles", [])[:500]:
            if isinstance(h, dict):
                self._items.append([
                    h.get("handler", "?"),
                    f"{h.get('coverage_pct', 0)}%",
                    f"{h.get('conformance_score', 0)}%",
                    str(h.get("taint_count", 0)),
                    f"{h.get('priority_score', 0):.1f}",
                    str(h.get("analyzer_count", 0)),
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 6

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Function Similarity ──────────────────────────────────────

class FunctionSimilarityChooser(ida_kernwin.Choose):
    """Shows function similarity clusters."""

    COLUMNS = [
        ["Cluster ID", 10],
        ["Type", 12],
        ["Members", 8],
        ["Fingerprint", 20],
        ["Representative", 25],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Function Similarity Clusters",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("function_similarity") or {}
        self._items = []
        for c in data.get("clusters", [])[:500]:
            if isinstance(c, dict):
                members = c.get("members", [])
                rep = members[0].get("name", "?") if members else "?"
                self._items.append([
                    str(c.get("id", "?")),
                    c.get("type", "?"),
                    str(c.get("member_count", len(members))),
                    str(c.get("fingerprint_hash", "?"))[:20],
                    rep[:25],
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Thread Safety Map ────────────────────────────────────────

class ThreadSafetyChooser(ida_kernwin.Choose):
    """Shows detected synchronization primitives and thread safety."""

    COLUMNS = [
        ["Lock Type", 15],
        ["Address", 16],
        ["Function", 25],
        ["Protected Fields", 8],
        ["System", 12],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Thread Safety Map",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("thread_safety_map") or {}
        self._items = []
        for lock in data.get("lock_instances", [])[:500]:
            if isinstance(lock, dict):
                self._items.append([
                    lock.get("type", "?"),
                    lock.get("ea", "?"),
                    lock.get("function_name", lock.get("function_ea", "?"))[:25],
                    str(len(lock.get("protected_fields", []))),
                    lock.get("system", "?"),
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Negative Space ──────────────────────────────────────────

class NegativeSpaceChooser(ida_kernwin.Choose):
    """Shows missing validations, notifications, and error handling."""

    COLUMNS = [
        ["Handler", 25],
        ["Gap Type", 15],
        ["Severity", 8],
        ["Missing Pattern", 30],
        ["Similar With", 8],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Negative Space (Missing Checks)",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("negative_space") or {}
        self._items = []
        for gap in data.get("missing_validations", [])[:500]:
            if isinstance(gap, dict):
                self._items.append([
                    gap.get("handler", "?"),
                    gap.get("gap_type", gap.get("missing_pattern", "?"))[:15],
                    gap.get("severity", "?").upper(),
                    gap.get("missing_pattern", gap.get("details", "?"))[:30],
                    str(gap.get("similar_handlers_with", 0)),
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── UpdateField Descriptors ────────────────────────────────

class UpdateFieldChooser(ida_kernwin.Choose):
    """Shows extracted UpdateField descriptors from .rdata."""

    COLUMNS = [
        ["Field Name", 30],
        ["Object Type", 15],
        ["Offset", 8],
        ["Size", 6],
        ["Type", 10],
        ["Flags", 10],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: UpdateField Descriptors",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("updatefield_descriptors") or {}
        self._items = []
        for obj_type in data.get("object_types", []):
            if isinstance(obj_type, dict):
                type_name = obj_type.get("type_name", "?")
                for f in obj_type.get("fields", []):
                    if isinstance(f, dict):
                        self._items.append([
                            f.get("name", "?"),
                            type_name,
                            str(f.get("offset", 0)),
                            str(f.get("size", 0)),
                            f.get("type", "?"),
                            f.get("flags", "?"),
                        ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 6

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Allocation Class Catalog ──────────────────────────────

class ClassCatalogChooser(ida_kernwin.Choose):
    """Shows classes discovered via operator new allocation sizes."""

    COLUMNS = [
        ["Class Name", 25],
        ["Size", 8],
        ["VTable", 16],
        ["Constructor", 16],
        ["Base Classes", 20],
        ["TC Match", 8],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Class Catalog (Alloc Sizes)",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("class_catalog") or {}
        self._items = []
        for cls in data.get("classes", [])[:500]:
            if isinstance(cls, dict):
                bases = ", ".join(cls.get("base_classes", [])[:3])
                self._items.append([
                    cls.get("name", "?"),
                    f"0x{cls.get('size', 0):X}",
                    cls.get("vtable_ea", "?"),
                    cls.get("constructor_ea", "?"),
                    bases or "—",
                    "Yes" if cls.get("tc_size_match") else "No",
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 6

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Shared Code Detection ─────────────────────────────────

class SharedCodeChooser(ida_kernwin.Choose):
    """Shows client-server shared code (validations, formulas)."""

    COLUMNS = [
        ["Category", 15],
        ["Function", 25],
        ["Opcode", 20],
        ["Criticality", 10],
        ["TC Equivalent", 10],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Shared Code Detection",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("shared_code") or {}
        self._items = []
        for cat_key in ("validations", "formulas", "shared_utilities"):
            for item in data.get(cat_key, [])[:200]:
                if isinstance(item, dict):
                    self._items.append([
                        item.get("check_type", item.get("formula_type", cat_key))[:15],
                        item.get("function_ea", item.get("name", "?"))[:25],
                        item.get("opcode", "?")[:20],
                        item.get("criticality", "?"),
                        "Yes" if item.get("tc_equivalent") else "No",
                    ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Sniff Verification ────────────────────────────────────

class SniffVerificationChooser(ida_kernwin.Choose):
    """Shows sniff verification results per opcode."""

    COLUMNS = [
        ["Opcode", 25],
        ["Total", 8],
        ["Success", 8],
        ["Fail", 8],
        ["Rate", 8],
        ["Avg Size", 8],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Sniff Format Verification",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("sniff_verification") or {}
        self._items = []
        for op in data.get("per_opcode", [])[:500]:
            if isinstance(op, dict):
                total = op.get("total", 0)
                success = op.get("success", 0)
                rate = f"{(success / total * 100):.0f}%" if total > 0 else "—"
                self._items.append([
                    op.get("name", op.get("opcode", "?")),
                    str(total),
                    str(success),
                    str(op.get("fail", 0)),
                    rate,
                    str(op.get("avg_size", 0)),
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 6

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Multi-Build Temporal ──────────────────────────────────

class TemporalEvolutionChooser(ida_kernwin.Choose):
    """Shows opcode/system evolution across builds."""

    COLUMNS = [
        ["Opcode", 25],
        ["First Seen", 10],
        ["Last Seen", 10],
        ["Changes", 8],
        ["Volatility", 10],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Multi-Build Evolution",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("temporal_evolution") or {}
        self._items = []
        for item in data.get("opcode_timeline", [])[:500]:
            if isinstance(item, dict):
                self._items.append([
                    item.get("opcode", "?"),
                    str(item.get("first_seen", "?")),
                    str(item.get("last_seen", "?")),
                    str(item.get("change_count", 0)),
                    f"{item.get('volatility', 0):.2f}",
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── DB2 Data Content ──────────────────────────────────────

class DB2ContentChooser(ida_kernwin.Choose):
    """Shows DB2 data content analysis results."""

    COLUMNS = [
        ["Table", 25],
        ["Rows", 8],
        ["Fields", 8],
        ["Foreign Keys", 10],
        ["Enum Fields", 10],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: DB2 Data Content",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("db2_data_content") or {}
        self._items = []
        for t in data.get("table_stats", [])[:500]:
            if isinstance(t, dict):
                self._items.append([
                    t.get("name", "?"),
                    str(t.get("row_count", 0)),
                    str(t.get("field_count", 0)),
                    str(t.get("foreign_keys", 0)),
                    str(t.get("enum_fields", 0)),
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── PE Metadata ───────────────────────────────────────────────

class PEMetadataChooser(ida_kernwin.Choose):
    """Shows PE metadata: CFG targets, exception entries, debug info."""

    COLUMNS = [
        ["Category", 15],
        ["Address", 16],
        ["Details", 35],
        ["Classification", 15],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: PE Metadata",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("pe_metadata") or {}
        self._items = []
        for t in data.get("cfg_targets", [])[:300]:
            if isinstance(t, dict):
                self._items.append([
                    "CFG Target",
                    t.get("rva", "?"),
                    t.get("function_name", "?")[:35],
                    "vtable" if t.get("is_vtable_member") else "callback" if t.get("is_callback") else "unknown",
                ])
        for f in data.get("ida_missed_functions", [])[:100]:
            if isinstance(f, dict):
                self._items.append(["Missed Func", f.get("rva", "?"), f"size={f.get('size', 0)}", "pdata-only"])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 4

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Data Section Archaeology ─────────────────────────────────

class DataArchaeologyChooser(ida_kernwin.Choose):
    """Shows discovered tables, arrays, and globals from .rdata/.data."""

    COLUMNS = [
        ["Type", 15],
        ["Address", 16],
        ["Entries", 8],
        ["Element Size", 10],
        ["Details", 30],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Data Section Archaeology",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("data_archaeology") or {}
        self._items = []
        for cat, label in [("function_pointer_tables", "FuncPtr Table"),
                           ("jump_tables", "Jump Table"),
                           ("const_arrays", "Const Array"),
                           ("string_tables", "String Table")]:
            for item in data.get(cat, [])[:150]:
                if isinstance(item, dict):
                    self._items.append([
                        label,
                        item.get("ea", "?"),
                        str(item.get("entry_count", item.get("element_count", item.get("string_count", 0)))),
                        str(item.get("element_size", "—")),
                        str(item.get("enum_suggestion", item.get("enum_name_suggestion", "")))[:30],
                    ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── CVar Extraction ─────────────────────────────────────────

class CVarChooser(ida_kernwin.Choose):
    """Shows extracted console variables."""

    COLUMNS = [
        ["CVar Name", 25],
        ["Default", 15],
        ["Type", 8],
        ["Flags", 20],
        ["Server?", 8],
        ["System", 12],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Console Variables (CVars)",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("cvars") or {}
        self._items = []
        for cv in data.get("cvars", [])[:500]:
            if isinstance(cv, dict):
                flags = ", ".join(cv.get("flags_decoded", [])[:3])
                self._items.append([
                    cv.get("name", "?"),
                    str(cv.get("default_value", ""))[:15],
                    cv.get("value_type", "?"),
                    flags[:20],
                    "Yes" if cv.get("server_relevant") else "No",
                    cv.get("system", "?"),
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 6

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Call Graph Analytics ─────────────────────────────────────

class CallGraphChooser(ida_kernwin.Choose):
    """Shows call graph analytics: PageRank, centrality, communities."""

    COLUMNS = [
        ["Function", 25],
        ["PageRank", 10],
        ["Centrality", 10],
        ["Community", 8],
        ["System", 12],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Call Graph Analytics",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("call_graph_analytics") or {}
        self._items = []
        for f in data.get("pagerank_top100", []):
            if isinstance(f, dict):
                self._items.append([
                    f.get("name", "?")[:25],
                    f"{f.get('score', 0):.6f}",
                    "",
                    "",
                    f.get("system", "?"),
                ])
        for f in data.get("centrality_top100", [])[:50]:
            if isinstance(f, dict):
                self._items.append([
                    f.get("name", "?")[:25],
                    "",
                    f"{f.get('score', 0):.4f}",
                    "",
                    f.get("bridges_systems", "?")[:12],
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Indirect Call Resolution ────────────────────────────────

class IndirectCallChooser(ida_kernwin.Choose):
    """Shows resolved indirect calls."""

    COLUMNS = [
        ["Call Site", 16],
        ["Caller", 20],
        ["Type", 12],
        ["Quality", 10],
        ["Targets", 8],
        ["VTable Slot", 10],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Indirect Call Resolution",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("indirect_calls") or {}
        self._items = []
        for r in data.get("resolutions", [])[:500]:
            if isinstance(r, dict):
                self._items.append([
                    r.get("call_ea", "?"),
                    r.get("caller_name", "?")[:20],
                    r.get("call_type", "?"),
                    r.get("quality", "?"),
                    str(r.get("target_count", 0)),
                    str(r.get("vtable_slot", "—")),
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 6

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Symbolic Constraints ────────────────────────────────────

class SymbolicConstraintChooser(ida_kernwin.Choose):
    """Shows symbolic constraint analysis per handler parameter."""

    COLUMNS = [
        ["Handler", 25],
        ["Parameter", 15],
        ["Type", 8],
        ["Constraint", 25],
        ["Checks", 6],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Symbolic Constraints",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("symbolic_constraints") or {}
        self._items = []
        for h in data.get("handler_constraints", [])[:300]:
            if isinstance(h, dict):
                for p in h.get("parameters", []):
                    if isinstance(p, dict):
                        self._items.append([
                            h.get("handler", "?")[:25],
                            p.get("name", "?")[:15],
                            p.get("type", "?"),
                            str(p.get("final_constraint", p.get("concrete_values", "?")))[:25],
                            str(len(p.get("constraining_checks", []))),
                        ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Binary-TC Alignment ────────────────────────────────────

class BinaryTCAlignmentChooser(ida_kernwin.Choose):
    """Shows binary vs TC handler alignment scores."""

    COLUMNS = [
        ["Handler", 25],
        ["Score", 8],
        ["Matching", 8],
        ["Differing", 8],
        ["Worst Diff", 30],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Binary-TC Alignment",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("binary_tc_alignment") or {}
        self._items = []
        for a in data.get("alignments", [])[:500]:
            if isinstance(a, dict):
                diffs = a.get("differences", [])
                worst = diffs[0].get("description", "")[:30] if diffs else "—"
                self._items.append([
                    a.get("opcode", a.get("tc_handler", "?"))[:25],
                    f"{a.get('alignment_score', 0)}%",
                    str(a.get("matching_blocks", 0)),
                    str(a.get("differing_blocks", 0)),
                    worst,
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Return Value Semantics ──────────────────────────────────

class ReturnValueChooser(ida_kernwin.Choose):
    """Shows return value semantic analysis."""

    COLUMNS = [
        ["Function", 25],
        ["Convention", 18],
        ["Callers", 8],
        ["Check", 8],
        ["Ignore", 8],
        ["Risk", 8],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Return Value Semantics",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("return_value_semantics") or {}
        self._items = []
        for f in data.get("unchecked_returns", [])[:500]:
            if isinstance(f, dict):
                self._items.append([
                    f.get("callee_name", "?")[:25],
                    f.get("return_type", "?"),
                    "",
                    "",
                    "",
                    f.get("risk_level", "?"),
                ])
        for f in data.get("function_semantics", [])[:200]:
            if isinstance(f, dict):
                self._items.append([
                    f.get("name", "?")[:25],
                    f.get("convention", "?"),
                    str(f.get("caller_count", 0)),
                    str(f.get("callers_that_check", 0)),
                    str(f.get("callers_that_ignore", 0)),
                    "",
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 6

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Execution Trace Simulation ──────────────────────────────

class ExecutionTraceChooser(ida_kernwin.Choose):
    """Shows execution trace simulation results."""

    COLUMNS = [
        ["Handler", 25],
        ["Paths", 8],
        ["Complexity", 10],
        ["Effects", 8],
        ["Dead Paths", 8],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Execution Trace Simulation",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("execution_traces") or {}
        self._items = []
        for h in data.get("handler_traces", [])[:500]:
            if isinstance(h, dict):
                self._items.append([
                    h.get("handler", "?")[:25],
                    str(h.get("path_count", 0)),
                    f"{h.get('complexity_score', 0):.1f}",
                    str(sum(len(p.get("effects", [])) for p in h.get("paths", []))),
                    str(len(h.get("dead_paths", []))),
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Compiler Artifacts ──────────────────────────────────────

class CompilerArtifactChooser(ida_kernwin.Choose):
    """Shows compiler artifacts: hot/cold splits, SIMD, /GS, COMDAT."""

    COLUMNS = [
        ["Type", 15],
        ["Function", 25],
        ["Details", 25],
        ["System", 12],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Compiler Artifacts",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("compiler_artifacts") or {}
        self._items = []
        for s in data.get("simd_functions", [])[:200]:
            if isinstance(s, dict):
                self._items.append([
                    "SIMD",
                    s.get("name", "?")[:25],
                    f"{s.get('purpose', '?')} ({s.get('instruction_count', 0)} insns)",
                    s.get("system", "?"),
                ])
        for h in data.get("hot_cold_splits", [])[:200]:
            if isinstance(h, dict):
                self._items.append([
                    "Hot/Cold",
                    h.get("function_ea", "?"),
                    f"hot={h.get('hot_size', 0)} cold={h.get('cold_size', 0)}",
                    h.get("system", "?"),
                ])
        for g in data.get("gs_protected", [])[:100]:
            if isinstance(g, dict):
                self._items.append([
                    "/GS Protected",
                    g.get("name", "?")[:25],
                    f"buf~{g.get('buffer_size_estimate', 0)}",
                    "",
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 4

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Event System ────────────────────────────────────────────

class EventSystemChooser(ida_kernwin.Choose):
    """Shows recovered event/callback/timer system topology."""

    COLUMNS = [
        ["Type", 12],
        ["Event/Timer", 20],
        ["Handler", 25],
        ["System", 12],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Event System",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("event_system") or {}
        self._items = []
        for e in data.get("event_registrations", [])[:300]:
            if isinstance(e, dict):
                self._items.append([
                    "Event",
                    str(e.get("event_id", "?"))[:20],
                    e.get("handler_name", "?")[:25],
                    e.get("system", "?"),
                ])
        for t in data.get("timers", [])[:200]:
            if isinstance(t, dict):
                self._items.append([
                    "Timer",
                    f"{t.get('interval_ms', '?')}ms {'repeat' if t.get('is_repeating') else 'once'}",
                    t.get("callback_name", "?")[:25],
                    t.get("system", "?"),
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 4

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Instruction N-grams ────────────────────────────────────

class InstructionNgramChooser(ida_kernwin.Choose):
    """Shows frequent instruction N-gram patterns."""

    COLUMNS = [
        ["Pattern Hash", 16],
        ["Frequency", 8],
        ["Functions", 8],
        ["Tokens", 35],
        ["Category", 12],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Instruction N-grams",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("instruction_ngrams") or {}
        self._items = []
        for p in data.get("frequent_patterns", [])[:500]:
            if isinstance(p, dict):
                tokens = " ".join(p.get("tokens", [])[:6])
                self._items.append([
                    str(p.get("hash", "?"))[:16],
                    str(p.get("frequency", 0)),
                    str(p.get("function_count", 0)),
                    tokens[:35],
                    "inline" if p.get("is_inline_candidate") else "pattern",
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── LLM Semantic Decompiler ────────────────────────────────────

class LLMDecompilerChooser(ida_kernwin.Choose):
    """Shows LLM-assisted semantic decompilation results."""

    COLUMNS = [
        ["Handler", 25],
        ["Variables", 8],
        ["Constants", 8],
        ["Quality", 8],
        ["Provider", 15],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: LLM Semantic Decompiler",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("llm_semantic_decompilation") or {}
        self._items = []
        for name, r in (data.get("results", {}) if isinstance(data, dict) else {}).items():
            if isinstance(r, dict):
                self._items.append([
                    name[:25],
                    str(len(r.get("variable_map", {}))),
                    str(len(r.get("constants_identified", {}))),
                    f"{r.get('quality_score', 0)}%",
                    data.get("provider", "?")[:15],
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Handler Scaffolding ────────────────────────────────────

class HandlerScaffoldingChooser(ida_kernwin.Choose):
    """Shows generated TC handler scaffolds."""

    COLUMNS = [
        ["Handler", 25],
        ["Category", 12],
        ["Complete", 8],
        ["Confidence", 8],
        ["Gaps", 6],
        ["Validations", 8],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Handler Scaffolding",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("handler_scaffolding") or {}
        self._items = []
        for name, s in (data.get("scaffolds", {}) if isinstance(data, dict) else {}).items():
            if isinstance(s, dict):
                self._items.append([
                    name[:25],
                    s.get("category", "?")[:12],
                    f"{s.get('completeness_score', 0)}%",
                    f"{s.get('confidence_score', 0)}%",
                    str(s.get("gap_count", 0)),
                    f"{s.get('validation_coverage', 0)}%",
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 6

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Cross-Build Migration ────────────────────────────────────

class CrossBuildMigrationChooser(ida_kernwin.Choose):
    """Shows cross-build migration analysis results."""

    COLUMNS = [
        ["Handler", 25],
        ["Change Type", 15],
        ["Priority", 8],
        ["Confidence", 8],
        ["Description", 30],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Cross-Build Migration",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("cross_build_migration") or {}
        self._items = []
        for h in (data.get("changed_handlers", []) if isinstance(data, dict) else []):
            if isinstance(h, dict):
                for c in h.get("changes", []):
                    if isinstance(c, dict):
                        self._items.append([
                            h.get("handler", "?")[:25],
                            c.get("type", "?")[:15],
                            c.get("priority", "?"),
                            f"{h.get('match_confidence', 0)}%",
                            c.get("description", "")[:30],
                        ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Sniff Conformance Loop ────────────────────────────────────

class SniffConformanceChooser(ida_kernwin.Choose):
    """Shows sniff-based conformance divergences and auto-fixes."""

    COLUMNS = [
        ["Handler", 25],
        ["Divergence", 18],
        ["Priority", 8],
        ["Packets", 8],
        ["Fix Type", 15],
    ]

    def __init__(self, session):
        self._session = session
        self._items = []
        super().__init__(
            "TC WoW: Sniff Conformance Loop",
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self._load()

    def _load(self):
        data = self._session.db.kv_get("sniff_conformance_loop") or {}
        self._items = []
        for fix in (data.get("fixes", []) if isinstance(data, dict) else []):
            if isinstance(fix, dict):
                self._items.append([
                    fix.get("handler_name", "?")[:25],
                    fix.get("divergence_type", "?")[:18],
                    fix.get("priority", "?"),
                    str(len(fix.get("evidence_packets", []))),
                    fix.get("fix_type", "?")[:15],
                ])

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n] if n < len(self._items) else [""] * 5

    def OnRefresh(self, n):
        self._load()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]


# ─── Master Quality Dashboard ────────────────────────────────────

def _kv_count(db, key, sub_key=None):
    """Helper to get a count from kv_store data."""
    data = db.kv_get(key) or {}
    if sub_key and isinstance(data, dict):
        val = data.get(sub_key, 0)
        return val if isinstance(val, int) else len(val) if isinstance(val, list) else 0
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        return data.get("total", data.get("count", len(data)))
    return 0


def show_quality_dashboard(session):
    """Show the quality analysis dashboard with a chooser selector."""
    db = session.db

    lines = ["TC WoW Analyzer — Quality & Deep Analysis Dashboard", "=" * 55, ""]

    # --- Quality Analysis Summary ---
    lines.append("─── Quality Analysis ───")

    from tc_wow_analyzer.analyzers.conformance import get_conformance_report
    conf = get_conformance_report(session)
    if conf:
        lines.append(f"  Conformance: {conf.get('total_handlers', 0)} handlers, "
                     f"avg {conf.get('average_score', 0)}%")
    else:
        lines.append("  Conformance: not yet analyzed")

    from tc_wow_analyzer.analyzers.state_machine import get_state_machines
    lines.append(f"  State Machines: {len(get_state_machines(session))} recovered")

    from tc_wow_analyzer.analyzers.dependency_mapper import get_dependency_map
    deps = get_dependency_map(session)
    lines.append(f"  Dependencies: {len(deps.get('edges', []))} edges" if deps
                 else "  Dependencies: not yet analyzed")

    from tc_wow_analyzer.analyzers.db2_drift import get_drift_report
    drift = get_drift_report(session)
    lines.append(f"  DB2 Drift: {drift.get('errors', 0)}E/{drift.get('warnings', 0)}W"
                 if drift else "  DB2 Drift: not yet analyzed")

    lines.append(f"  Generated Tests: {_kv_count(db, 'generated_tests', 'total')}")

    # --- Deep Extraction Summary ---
    lines.append("")
    lines.append("─── Deep Binary Extraction ───")

    wire_data = db.kv_get("wire_formats") or {}
    wire_count = len(wire_data) if isinstance(wire_data, dict) else 0
    lines.append(f"  Wire Formats: {wire_count} packet formats recovered")

    enum_data = db.kv_get("recovered_enums") or []
    lines.append(f"  Enums: {len(enum_data) if isinstance(enum_data, list) else 0} recovered")

    const_data = db.kv_get("game_constants") or {}
    const_count = len(const_data.get("constants", [])) if isinstance(const_data, dict) else 0
    lines.append(f"  Game Constants: {const_count} mined")

    layout_data = db.kv_get("object_layouts") or []
    lines.append(f"  Object Layouts: {len(layout_data) if isinstance(layout_data, list) else 0} classes")

    resp_data = db.kv_get("response_packets") or {}
    resp_count = len(resp_data.get("handlers", [])) if isinstance(resp_data, dict) else 0
    lines.append(f"  Response Packets: {resp_count} SMSG reconstructed")

    # --- Behavioral Analysis Summary ---
    lines.append("")
    lines.append("─── Behavioral Analysis ───")

    taint_data = db.kv_get("taint_analysis") or {}
    taint_count = len(taint_data.get("flows", taint_data.get("results", []))) \
        if isinstance(taint_data, dict) else 0
    lines.append(f"  Taint Flows: {taint_count} unguarded flows")

    spec_data = db.kv_get("behavioral_specs") or {}
    spec_count = spec_data.get("total", len(spec_data.get("specs", []))) \
        if isinstance(spec_data, dict) else 0
    lines.append(f"  Behavioral Specs: {spec_count} handlers specified")

    proto_data = db.kv_get("protocol_sequences") or {}
    proto_count = len(proto_data.get("sequences", proto_data.get("handlers", []))) \
        if isinstance(proto_data, dict) else 0
    lines.append(f"  Protocol Sequences: {proto_count} rules")

    contract_data = db.kv_get("callee_contracts") or {}
    contract_count = len(contract_data.get("contracts", [])) \
        if isinstance(contract_data, dict) else 0
    lines.append(f"  Callee Contracts: {contract_count} utility contracts")

    # --- Synthesis Summary ---
    lines.append("")
    lines.append("─── Synthesis & Generation ───")

    transpiled = db.kv_get("transpiled_handlers") or {}
    t_count = transpiled.get("total", len(transpiled.get("handlers", {}))) \
        if isinstance(transpiled, dict) else 0
    lines.append(f"  Transpiled Handlers: {t_count}")

    lifecycle = db.kv_get("object_lifecycles") or {}
    lc_count = len(lifecycle.get("lifecycles", [])) \
        if isinstance(lifecycle, dict) else 0
    lines.append(f"  Object Lifecycles: {lc_count}")

    lua_data = db.kv_get("lua_contracts") or {}
    lua_count = len(lua_data.get("contracts", [])) \
        if isinstance(lua_data, dict) else 0
    lines.append(f"  Lua Contracts: {lua_count}")

    # --- Intelligence & Enrichment Summary ---
    lines.append("")
    lines.append("--- Intelligence & Enrichment ---")

    enrich_data = db.kv_get("idb_enrichment") or {}
    enrich_count = len(enrich_data.get("actions", [])) if isinstance(enrich_data, dict) else 0
    lines.append(f"  IDB Enrichment: {enrich_count} actions applied "
                 f"({enrich_data.get('iterations', 0)} iterations)"
                 if enrich_count else "  IDB Enrichment: not yet run")

    str_data = db.kv_get("string_intelligence") or {}
    str_count = str_data.get("total_names_recovered", 0) if isinstance(str_data, dict) else 0
    lines.append(f"  String Intelligence: {str_count} names recovered")

    synth_data = db.kv_get("synthesis_report") or {}
    synth_count = synth_data.get("total_handlers", 0) if isinstance(synth_data, dict) else 0
    lines.append(f"  Cross-Analyzer Synthesis: {synth_count} handlers profiled, "
                 f"avg coverage {synth_data.get('avg_coverage', 0):.0f}%"
                 if synth_count else "  Cross-Analyzer Synthesis: not yet run")

    # --- Data & Verification Summary ---
    lines.append("")
    lines.append("--- Data & Verification ---")

    db2c_data = db.kv_get("db2_data_content") or {}
    lines.append(f"  DB2 Data Content: {db2c_data.get('tables_analyzed', 0)} tables, "
                 f"{db2c_data.get('total_rows_read', 0)} rows"
                 if isinstance(db2c_data, dict) and db2c_data.get("tables_analyzed")
                 else "  DB2 Data Content: not yet run")

    sniff_data = db.kv_get("sniff_verification") or {}
    lines.append(f"  Sniff Verification: {sniff_data.get('verified_packets', 0)} verified, "
                 f"{sniff_data.get('failed_packets', 0)} failed"
                 if isinstance(sniff_data, dict) and sniff_data.get("total_packets")
                 else "  Sniff Verification: not yet run")

    temp_data = db.kv_get("temporal_evolution") or {}
    lines.append(f"  Multi-Build Temporal: {temp_data.get('builds_analyzed', 0)} builds analyzed"
                 if isinstance(temp_data, dict) and temp_data.get("builds_analyzed")
                 else "  Multi-Build Temporal: not yet run")

    # --- Structural Analysis Summary ---
    lines.append("")
    lines.append("--- Structural Analysis ---")

    sim_data = db.kv_get("function_similarity") or {}
    lines.append(f"  Function Similarity: {sim_data.get('total_clusters', 0)} clusters "
                 f"from {sim_data.get('total_functions_analyzed', 0)} functions"
                 if isinstance(sim_data, dict) and sim_data.get("total_clusters")
                 else "  Function Similarity: not yet run")

    shared_data = db.kv_get("shared_code") or {}
    lines.append(f"  Shared Code: {shared_data.get('total_shared_items', 0)} items, "
                 f"{shared_data.get('critical_items', 0)} critical"
                 if isinstance(shared_data, dict) and shared_data.get("total_shared_items")
                 else "  Shared Code: not yet run")

    thread_data = db.kv_get("thread_safety_map") or {}
    lines.append(f"  Thread Safety: {thread_data.get('total_locks', 0)} locks, "
                 f"{thread_data.get('total_threads', 0)} threads, "
                 f"{thread_data.get('deadlock_risks', 0)} deadlock risks"
                 if isinstance(thread_data, dict) and thread_data.get("total_locks")
                 else "  Thread Safety: not yet run")

    # --- Gap & Completeness Summary ---
    lines.append("")
    lines.append("--- Gap & Completeness ---")

    neg_data = db.kv_get("negative_space") or {}
    lines.append(f"  Negative Space: {neg_data.get('total_gaps', 0)} gaps, "
                 f"{neg_data.get('critical_gaps', 0)} critical"
                 if isinstance(neg_data, dict) and neg_data.get("total_gaps")
                 else "  Negative Space: not yet run")

    uf_data = db.kv_get("updatefield_descriptors") or {}
    lines.append(f"  UpdateField Descriptors: {uf_data.get('total_fields', 0)} fields extracted"
                 if isinstance(uf_data, dict) and uf_data.get("total_fields")
                 else "  UpdateField Descriptors: not yet run")

    cat_data = db.kv_get("class_catalog") or {}
    lines.append(f"  Class Catalog: {cat_data.get('total_classes', 0)} classes, "
                 f"{cat_data.get('total_factories', 0)} factories"
                 if isinstance(cat_data, dict) and cat_data.get("total_classes")
                 else "  Class Catalog: not yet run")

    # --- PE & Low-Level Summary ---
    lines.append("")
    lines.append("--- PE & Low-Level ---")

    pe_data = db.kv_get("pe_metadata") or {}
    lines.append(f"  PE Metadata: {pe_data.get('total_cfg_targets', 0)} CFG targets, "
                 f"{pe_data.get('ida_missed_count', 0)} missed functions"
                 if isinstance(pe_data, dict) and pe_data.get("total_cfg_targets")
                 else "  PE Metadata: not yet run")

    arch_data = db.kv_get("data_archaeology") or {}
    lines.append(f"  Data Archaeology: {arch_data.get('total_tables', 0)} tables, "
                 f"{arch_data.get('total_globals', 0)} globals"
                 if isinstance(arch_data, dict) and arch_data.get("total_tables")
                 else "  Data Archaeology: not yet run")

    cvar_data = db.kv_get("cvars") or {}
    lines.append(f"  CVars: {cvar_data.get('total_cvars', 0)} extracted, "
                 f"{cvar_data.get('server_relevant_count', 0)} server-relevant"
                 if isinstance(cvar_data, dict) and cvar_data.get("total_cvars")
                 else "  CVars: not yet run")

    # --- Graph & Architecture Summary ---
    lines.append("")
    lines.append("--- Graph & Architecture ---")

    cg_data = db.kv_get("call_graph_analytics") or {}
    gs = cg_data.get("graph_stats", {}) if isinstance(cg_data, dict) else {}
    lines.append(f"  Call Graph: {gs.get('nodes', 0)} nodes, {gs.get('edges', 0)} edges, "
                 f"{len(cg_data.get('communities', []))} communities"
                 if gs.get("nodes") else "  Call Graph: not yet run")

    ic_data = db.kv_get("indirect_calls") or {}
    lines.append(f"  Indirect Calls: {ic_data.get('resolved_exact', 0)} exact, "
                 f"{ic_data.get('resolved_narrow', 0)} narrow, "
                 f"{ic_data.get('unresolved', 0)} unresolved"
                 if isinstance(ic_data, dict) and ic_data.get("indirect_call_sites")
                 else "  Indirect Calls: not yet run")

    ev_data = db.kv_get("event_system") or {}
    lines.append(f"  Event System: {ev_data.get('total_events', 0)} events, "
                 f"{ev_data.get('total_timers', 0)} timers"
                 if isinstance(ev_data, dict) and ev_data.get("total_events")
                 else "  Event System: not yet run")

    # --- Semantic Analysis Summary ---
    lines.append("")
    lines.append("--- Semantic Analysis ---")

    sc_data = db.kv_get("symbolic_constraints") or {}
    lines.append(f"  Symbolic Constraints: {sc_data.get('total_constrained', 0)} constrained, "
                 f"{sc_data.get('total_unconstrained', 0)} unconstrained"
                 if isinstance(sc_data, dict) and sc_data.get("total_params_analyzed")
                 else "  Symbolic Constraints: not yet run")

    ba_data = db.kv_get("binary_tc_alignment") or {}
    ba_agg = ba_data.get("aggregate", {}) if isinstance(ba_data, dict) else {}
    lines.append(f"  Binary-TC Alignment: {ba_agg.get('total_handlers_compared', 0)} handlers, "
                 f"avg {ba_agg.get('avg_alignment_score', 0):.0f}%"
                 if ba_agg.get("total_handlers_compared") else "  Binary-TC Alignment: not yet run")

    rv_data = db.kv_get("return_value_semantics") or {}
    lines.append(f"  Return Semantics: {rv_data.get('total_functions', 0)} functions, "
                 f"{rv_data.get('total_unchecked', 0)} unchecked"
                 if isinstance(rv_data, dict) and rv_data.get("total_functions")
                 else "  Return Semantics: not yet run")

    # --- Pattern Mining Summary ---
    lines.append("")
    lines.append("--- Pattern Mining ---")

    ng_data = db.kv_get("instruction_ngrams") or {}
    lines.append(f"  Instruction N-grams: {len(ng_data.get('frequent_patterns', []))} patterns, "
                 f"{len(ng_data.get('inline_candidates', []))} inline candidates"
                 if isinstance(ng_data, dict) and ng_data.get("total_functions_analyzed")
                 else "  Instruction N-grams: not yet run")

    et_data = db.kv_get("execution_traces") or {}
    lines.append(f"  Execution Traces: {et_data.get('total_handlers', 0)} handlers, "
                 f"{et_data.get('total_paths', 0)} paths"
                 if isinstance(et_data, dict) and et_data.get("total_handlers")
                 else "  Execution Traces: not yet run")

    ca_data = db.kv_get("compiler_artifacts") or {}
    lines.append(f"  Compiler Artifacts: {ca_data.get('total_artifacts', 0)} items"
                 if isinstance(ca_data, dict) and ca_data.get("total_artifacts")
                 else "  Compiler Artifacts: not yet run")

    # --- LLM & Generation Summary ---
    lines.append("")
    lines.append("--- LLM & Code Generation ---")

    llm_data = db.kv_get("llm_semantic_decompilation") or {}
    lines.append(f"  LLM Decompiler: {llm_data.get('handlers_processed', 0)} handlers, "
                 f"provider={llm_data.get('provider', 'none')}"
                 if isinstance(llm_data, dict) and llm_data.get("handlers_processed")
                 else "  LLM Decompiler: not yet run")

    scaff_data = db.kv_get("handler_scaffolding") or {}
    lines.append(f"  Handler Scaffolding: {scaff_data.get('handlers_generated', 0)} handlers, "
                 f"avg {scaff_data.get('avg_completeness', 0):.0f}% complete"
                 if isinstance(scaff_data, dict) and scaff_data.get("handlers_generated")
                 else "  Handler Scaffolding: not yet run")

    # --- Cross-Build & Conformance Summary ---
    lines.append("")
    lines.append("--- Cross-Build & Conformance ---")

    mig_data = db.kv_get("cross_build_migration") or {}
    mig_sum = mig_data.get("summary", {}) if isinstance(mig_data, dict) else {}
    lines.append(f"  Cross-Build Migration: {mig_sum.get('changed', 0)} changed handlers, "
                 f"{mig_sum.get('critical_changes', 0)} critical"
                 if mig_sum.get("changed") else "  Cross-Build Migration: not yet run")

    conf_loop = db.kv_get("sniff_conformance_loop") or {}
    lines.append(f"  Sniff Conformance: {conf_loop.get('total_divergences', 0)} divergences, "
                 f"{conf_loop.get('coverage_pct', 0):.0f}% opcode coverage"
                 if isinstance(conf_loop, dict) and conf_loop.get("total_divergences") is not None
                 and conf_loop.get("total_packets", 0) > 0
                 else "  Sniff Conformance: not yet run")

    lines.extend([
        "",
        "Select a view:",
        "  1  — Conformance Scores       8  — Wire Formats",
        "  2  — System Scores             9  — Recovered Enums",
        "  3  — Validation Gaps          10  — Object Layouts",
        "  4  — State Machines           11  — Taint Analysis",
        "  5  — Dependency Map           12  — Protocol Sequences",
        "  6  — DB2 Drift                13  — Transpiled Handlers",
        "  7  — Generated Tests          14  — Game Constants",
        "  15 — IDB Enrichment           20  — Thread Safety Map",
        "  16 — String Intelligence      21  — Negative Space",
        "  17 — Cross-Analyzer Synthesis  22  — UpdateField Descriptors",
        "  18 — Function Similarity      23  — Class Catalog",
        "  19 — Shared Code Detection    24  — Sniff Verification",
        "  25 — Multi-Build Temporal     26  — DB2 Data Content",
        "  27 — PE Metadata              32  — Symbolic Constraints",
        "  28 — Data Archaeology         33  — Binary-TC Alignment",
        "  29 — CVars                    34  — Return Value Semantics",
        "  30 — Call Graph Analytics     35  — Instruction N-grams",
        "  31 — Indirect Calls           36  — Execution Traces",
        "  37 — Event System             38  — Compiler Artifacts",
        "  39 — LLM Decompiler           41  — Cross-Build Migration",
        "  40 — Handler Scaffolding      42  — Sniff Conformance Loop",
    ])

    msg_info("\n".join(lines))

    choice = ida_kernwin.ask_long(1,
        "Dashboard View (1-42):\n"
        "1=Conformance 2=Systems 3=Validations 4=StateMachines\n"
        "5=Dependencies 6=DB2Drift 7=Tests 8=WireFormats\n"
        "9=Enums 10=Layouts 11=Taint 12=Protocol\n"
        "13=Transpiled 14=Constants 15=IDBEnrich 16=StringIntel\n"
        "17=Synthesis 18=FuncSim 19=SharedCode 20=ThreadSafe\n"
        "21=NegSpace 22=UpdateFields 23=ClassCat 24=SniffVerify\n"
        "25=Temporal 26=DB2Content 27=PE 28=DataArch 29=CVars\n"
        "30=CallGraph 31=IndirectCalls 32=SymConstraints\n"
        "33=BinaryTC 34=ReturnVal 35=NGrams 36=ExecTrace\n"
        "37=EventSys 38=CompilerArt 39=LLMDecomp 40=Scaffolds\n"
        "41=CrossBuild 42=SniffConformance")

    if choice == 1:
        ConformanceChooser(session).Show()
    elif choice == 2:
        SystemScoresChooser(session).Show()
    elif choice == 3:
        ValidationGapsChooser(session).Show()
    elif choice == 4:
        StateMachineChooser(session).Show()
    elif choice == 5:
        DependencyMapChooser(session).Show()
    elif choice == 6:
        DB2DriftChooser(session).Show()
    elif choice == 7:
        TestCasesChooser(session).Show()
    elif choice == 8:
        WireFormatChooser(session).Show()
    elif choice == 9:
        EnumRecoveryChooser(session).Show()
    elif choice == 10:
        ObjectLayoutChooser(session).Show()
    elif choice == 11:
        TaintAnalysisChooser(session).Show()
    elif choice == 12:
        ProtocolSequenceChooser(session).Show()
    elif choice == 13:
        TranspiledHandlerChooser(session).Show()
    elif choice == 14:
        GameConstantsChooser(session).Show()
    elif choice == 15:
        IDBEnrichmentChooser(session).Show()
    elif choice == 16:
        StringIntelligenceChooser(session).Show()
    elif choice == 17:
        SynthesisChooser(session).Show()
    elif choice == 18:
        FunctionSimilarityChooser(session).Show()
    elif choice == 19:
        SharedCodeChooser(session).Show()
    elif choice == 20:
        ThreadSafetyChooser(session).Show()
    elif choice == 21:
        NegativeSpaceChooser(session).Show()
    elif choice == 22:
        UpdateFieldChooser(session).Show()
    elif choice == 23:
        ClassCatalogChooser(session).Show()
    elif choice == 24:
        SniffVerificationChooser(session).Show()
    elif choice == 25:
        TemporalEvolutionChooser(session).Show()
    elif choice == 26:
        DB2ContentChooser(session).Show()
    elif choice == 27:
        PEMetadataChooser(session).Show()
    elif choice == 28:
        DataArchaeologyChooser(session).Show()
    elif choice == 29:
        CVarChooser(session).Show()
    elif choice == 30:
        CallGraphChooser(session).Show()
    elif choice == 31:
        IndirectCallChooser(session).Show()
    elif choice == 32:
        SymbolicConstraintChooser(session).Show()
    elif choice == 33:
        BinaryTCAlignmentChooser(session).Show()
    elif choice == 34:
        ReturnValueChooser(session).Show()
    elif choice == 35:
        InstructionNgramChooser(session).Show()
    elif choice == 36:
        ExecutionTraceChooser(session).Show()
    elif choice == 37:
        EventSystemChooser(session).Show()
    elif choice == 38:
        CompilerArtifactChooser(session).Show()
    elif choice == 39:
        LLMDecompilerChooser(session).Show()
    elif choice == 40:
        HandlerScaffoldingChooser(session).Show()
    elif choice == 41:
        CrossBuildMigrationChooser(session).Show()
    elif choice == 42:
        SniffConformanceChooser(session).Show()
