"""
Allocation Pattern -> Object Lifecycle Recovery

Every `operator new(size)` call reveals object sizes.  Every destructor reveals
cleanup requirements.  By tracing allocation -> initialization -> use ->
destruction patterns, we recover the complete object lifecycle for game objects.

Catches TC memory leaks, use-after-free, and lifecycle mismatches by comparing
the binary's allocation/deallocation discipline against TrinityCore's C++
ownership model.

Results are stored in kv_store under key "object_lifecycles".
"""

import json
import re
import time
from collections import defaultdict

import ida_funcs
import ida_name
import ida_xref
import idautils

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Allocation patterns — regex library
# ---------------------------------------------------------------------------

# operator new(size) — standard heap allocation
_OP_NEW_RE = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*\w[\w\s\*]*\s*\)\s*)?'       # v5 = (Type *)
    r'(?:operator\s+new|j_?operator_new|\?\?2@YAPAXI|'    # operator new variants
    r'_(?:o_)?(?:malloc|calloc)|(?:j_)?(?:malloc|calloc))' # malloc/calloc
    r'\s*\(\s*(0x[0-9A-Fa-f]+|\d+)',                      # (size
    re.IGNORECASE
)

# operator new[] — array allocation
_OP_NEW_ARRAY_RE = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*\w[\w\s\*]*\s*\)\s*)?'
    r'operator\s+new\[\]\s*\(\s*(.+?)\s*\)',
    re.IGNORECASE
)

# calloc(count, size) — C-style zero-initialized allocation
_CALLOC_RE = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*\w[\w\s\*]*\s*\)\s*)?'
    r'(?:_(?:o_)?)?calloc\s*\(\s*(.+?)\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)',
    re.IGNORECASE
)

# malloc(size) — C-style allocation
_MALLOC_RE = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*\w[\w\s\*]*\s*\)\s*)?'
    r'(?:_(?:o_)?)?malloc\s*\(\s*(0x[0-9A-Fa-f]+|\d+)\s*\)',
    re.IGNORECASE
)

# alloca / _alloca — stack dynamic allocation
_ALLOCA_RE = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*\w[\w\s\*]*\s*\)\s*)?'
    r'(?:_)?alloca\s*\(\s*(0x[0-9A-Fa-f]+|\d+)\s*\)',
    re.IGNORECASE
)

# Factory pattern: var = SomeClass::Create(...) or var = CreateSomething(...)
_FACTORY_RE = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*\w[\w\s\*]*\s*\)\s*)?'
    r'(\w+(?:::\w+)?)\s*\('
)

# Pool allocation: var = pool->Allocate() or pool->Get()
_POOL_ALLOC_RE = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*\w[\w\s\*]*\s*\)\s*)?'
    r'(\w+)\s*->\s*(Allocate|Get|Acquire|Pop|Obtain)\s*\(',
    re.IGNORECASE
)

# Vtable assignment: *(_QWORD *)v5 = &SomeClass::vftable  or
#   *v5 = off_7FF6...
_VTABLE_ASSIGN_RE = re.compile(
    r'\*\s*\(\s*_QWORD\s*\*\s*\)\s*(\w+)\s*=\s*'
    r'(?:&\s*)?(?:(\w+::)?`?vftable\'?|off_([\dA-Fa-f]+))'
    r'|'
    r'\*\s*(\w+)\s*=\s*(?:&\s*)?(?:(\w+::)?`?vftable\'?|off_([\dA-Fa-f]+))'
)

# Vtable assignment IDA-style: *(_QWORD *)var = 0x7FF6... (literal address)
_VTABLE_LITERAL_RE = re.compile(
    r'\*\s*\(\s*_QWORD\s*\*\s*\)\s*(\w+)\s*=\s*(0x[0-9A-Fa-f]{8,})\s*;'
    r'|'
    r'\*\s*(\w+)\s*=\s*(0x[0-9A-Fa-f]{8,})\s*;'
)

# Constructor-like call right after allocation: sub_XXXX(v5, ...)
_CONSTRUCTOR_CALL_RE = re.compile(
    r'(sub_[0-9A-Fa-f]+|\w+::\w+)\s*\(\s*(\w+)\s*(?:,|\))'
)

# ---------------------------------------------------------------------------
# Destruction patterns
# ---------------------------------------------------------------------------

# operator delete / free
_DELETE_RE = re.compile(
    r'(?:operator\s+delete|j_?operator_delete|j_?free|_(?:o_)?free)\s*'
    r'\(\s*(\w+)\s*\)',
    re.IGNORECASE
)

# operator delete[]
_DELETE_ARRAY_RE = re.compile(
    r'operator\s+delete\[\]\s*\(\s*(\w+)\s*\)',
    re.IGNORECASE
)

# Destructor virtual dispatch: (*(void (__fastcall **)(type))(*ptr))(ptr)
# i.e., calling vtable[0] (dtor) through the vtable pointer
_VIRT_DTOR_RE = re.compile(
    r'\(\s*\*\s*\(\s*(?:void\s*\(\s*__\w+\s*\*+\s*\)\s*'
    r'\(\s*[\w\s\*,]+\s*\)\s*\*?\s*)\)\s*'
    r'\(\s*\*\s*(\w+)\s*\)\s*\)\s*\(\s*\1'
)

# Explicit destructor call: ClassName::~ClassName(ptr) or sub_XXX(ptr) before delete
_EXPLICIT_DTOR_RE = re.compile(
    r'(\w+::~\w+|sub_[0-9A-Fa-f]+)\s*\(\s*(\w+)\s*\)\s*;'
)

# Pool deallocation: pool->Free(ptr) / pool->Release(ptr)
_POOL_FREE_RE = re.compile(
    r'(\w+)\s*->\s*(Free|Release|Return|Push|Deallocate)\s*\(\s*(\w+)\s*\)',
    re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Usage / method call patterns
# ---------------------------------------------------------------------------

# Method call on pointer: ptr->Method(...) or sub_XXX(ptr, ...)
_METHOD_CALL_RE = re.compile(
    r'(\w+)\s*->\s*(\w+)\s*\('
    r'|'
    r'(sub_[0-9A-Fa-f]+)\s*\(\s*(\w+)\s*(?:,|\))'
)

# Virtual dispatch: (*(func_ptr_type)(*(ptr) + offset))(ptr, ...)
_VIRTUAL_DISPATCH_RE = re.compile(
    r'\(\s*\*\s*\(\s*[\w\s\*\(\)]+\)\s*'
    r'\(\s*\*\s*(?:\(\s*_QWORD\s*\*\s*\)\s*)?(\w+)\s*'
    r'(?:\+\s*(0x[0-9A-Fa-f]+|\d+))?\s*\)\s*\)\s*\(\s*\1'
)

# Field write: *(type*)(ptr + offset) = value
_FIELD_WRITE_RE = re.compile(
    r'\*\s*\(\s*(\w+)\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)\s*=\s*(.+?)\s*;'
)

# Container store: container->push_back(ptr), container->insert(ptr),
#   container->emplace(ptr), or container[idx] = ptr
_CONTAINER_STORE_RE = re.compile(
    r'(\w+)\s*->\s*(push_back|emplace_back|emplace|insert|Add|Append|'
    r'add|append|push)\s*\(\s*(?:.*,\s*)?(\w+)\s*\)'
    r'|'
    r'(\w+)\s*\[\s*\w+\s*\]\s*=\s*(\w+)\s*;',
    re.IGNORECASE
)

# Passed to function (ownership transfer candidate):
# SomeFunc(..., ptr, ...) where ptr is not first arg (first arg is often 'this')
_PASS_TO_FUNC_RE = re.compile(
    r'(\w+(?:::\w+)?|sub_[0-9A-Fa-f]+)\s*\([^)]*,\s*(\w+)\s*[,)]'
)

# ---------------------------------------------------------------------------
# Known WoW/TC allocation sizes (common game object sizes)
# Populated dynamically from vtable + object_layout data when available
# ---------------------------------------------------------------------------
_KNOWN_SIZES = {}

# Factory function name heuristics
_FACTORY_KEYWORDS = {
    "create", "spawn", "make", "build", "construct", "instantiate",
    "new", "generate", "produce", "allocate", "get", "acquire",
}

# Known pool type indicators
_POOL_KEYWORDS = {
    "pool", "cache", "freelist", "slab", "arena", "recycler",
    "objectpool", "mempool",
}


# =========================================================================
# Public API
# =========================================================================

def recover_object_lifecycles(session, system_filter=None):
    """Main entry point: recover object lifecycles from handler functions.

    1. Find all allocation patterns in handler functions
    2. For each allocated object, trace its lifecycle
    3. Match allocations with destructors
    4. Build lifecycle state machines
    5. Compare against TC patterns
    6. Store in kv_store as "object_lifecycles"

    Args:
        session: PluginSession with .db attribute
        system_filter: Optional system name to restrict analysis

    Returns:
        Number of lifecycles recovered.
    """
    db = session.db
    start_time = time.time()

    # Populate known sizes from existing object_layout data if available
    _populate_known_sizes(db)

    # Gather candidate handler functions
    handlers = _get_candidate_functions(db, system_filter)
    msg_info(f"Scanning {len(handlers)} functions for object lifecycles...")

    all_lifecycles = []
    issues = []
    func_count = 0

    for func_info in handlers:
        ea = func_info["ea"]
        func_name = func_info["name"] or f"sub_{ea:X}"

        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            continue

        func_count += 1
        lines = pseudocode.split("\n")

        # Step 1: find allocations
        allocs = _find_allocations(pseudocode, func_name, ea)
        if not allocs:
            continue

        # Step 2: find destructions
        destructions = _find_destructors(pseudocode, ea)

        # Step 3: for each allocation, trace its usage
        for alloc in allocs:
            timeline = _trace_object_usage(pseudocode, alloc["variable"], alloc["line"])

            # Step 4: determine ownership
            ownership = _analyze_ownership(alloc, timeline)

            # Step 5: try to recover class identity
            class_name = _recover_class_from_allocation(
                db, alloc.get("size"), alloc.get("vtable_ea"),
                alloc.get("constructor_call_ea")
            )
            if class_name:
                alloc["class_name"] = class_name

            lifecycle = {
                "function": func_name,
                "function_ea": ea,
                "allocation": alloc,
                "timeline": timeline,
                "ownership": ownership,
                "class_name": alloc.get("class_name", "unknown"),
                "size": alloc.get("size"),
            }
            all_lifecycles.append(lifecycle)

        # Step 5b: match allocations with destructions
        match_issues = _match_allocation_destruction(allocs, destructions)
        for issue in match_issues:
            issue["function"] = func_name
            issue["function_ea"] = ea
        issues.extend(match_issues)

    # Deduplicate lifecycles by class + size
    merged = _merge_lifecycles(all_lifecycles)

    # Store results
    db.kv_set("object_lifecycles", merged)
    db.kv_set("object_lifecycle_issues", issues)
    db.commit()

    elapsed = time.time() - start_time
    msg_info(f"Recovered {len(merged)} object lifecycles from "
             f"{func_count} functions in {elapsed:.1f}s")
    msg_info(f"  Found {len(issues)} potential lifecycle issues")

    # Log summary of top classes
    size_counts = defaultdict(int)
    for lc in merged:
        key = lc.get("class_name", "unknown")
        if key == "unknown" and lc.get("size"):
            key = f"size_0x{lc['size']:X}"
        size_counts[key] += 1
    for cls, count in sorted(size_counts.items(), key=lambda x: -x[1])[:15]:
        msg(f"  {cls}: {count} lifecycle(s)")

    return len(merged)


def compare_lifecycles_with_tc(session):
    """Compare recovered lifecycles against TC patterns.

    For each recovered lifecycle, attempt to find the TC equivalent and
    flag discrepancies in allocation strategy, ownership model, and
    destructor discipline.

    Returns list of comparison results.
    """
    db = session.db
    lifecycles = db.kv_get("object_lifecycles") or []
    if not lifecycles:
        msg_warn("No object lifecycles recovered yet. Run recover_object_lifecycles first.")
        return []

    comparisons = []

    # Build a map of TC class info from vtables and functions tables
    tc_classes = _build_tc_class_map(db)

    for lc in lifecycles:
        class_name = lc.get("class_name", "unknown")
        if class_name == "unknown":
            continue

        tc_info = tc_classes.get(class_name, {})
        comparison = {
            "class_name": class_name,
            "binary_size": lc.get("size"),
            "binary_ownership": lc.get("ownership"),
            "binary_alloc_type": lc.get("allocation", {}).get("type"),
            "tc_class_found": bool(tc_info),
            "issues": [],
        }

        if tc_info:
            # Check allocation type mismatch
            tc_alloc = tc_info.get("alloc_type")
            bin_alloc = lc.get("allocation", {}).get("type")
            if tc_alloc and bin_alloc and tc_alloc != bin_alloc:
                comparison["issues"].append({
                    "type": "alloc_mismatch",
                    "detail": f"Binary uses '{bin_alloc}' but TC uses '{tc_alloc}'",
                    "severity": "warning",
                })

            # Check size mismatch
            tc_size = tc_info.get("size")
            bin_size = lc.get("size")
            if tc_size and bin_size and tc_size != bin_size:
                comparison["issues"].append({
                    "type": "size_mismatch",
                    "detail": f"Binary size 0x{bin_size:X} vs TC size 0x{tc_size:X}",
                    "severity": "info",
                })

            # Check ownership model
            tc_ownership = tc_info.get("ownership")
            bin_ownership = lc.get("ownership")
            if tc_ownership and bin_ownership and tc_ownership != bin_ownership:
                comparison["issues"].append({
                    "type": "ownership_mismatch",
                    "detail": f"Binary ownership '{bin_ownership}' vs TC '{tc_ownership}'",
                    "severity": "warning",
                })

            # Check destructor presence
            has_dtor_binary = any(
                e.get("phase") == "destroy"
                for e in lc.get("timeline", [])
            )
            has_dtor_tc = tc_info.get("has_destructor", False)
            if has_dtor_binary and not has_dtor_tc:
                comparison["issues"].append({
                    "type": "missing_destructor",
                    "detail": "Binary has destructor cleanup, TC may be missing it",
                    "severity": "error",
                })
            elif not has_dtor_binary and has_dtor_tc:
                comparison["issues"].append({
                    "type": "extra_destructor",
                    "detail": "TC has destructor but binary does not seem to need one",
                    "severity": "info",
                })

        comparisons.append(comparison)

    # Store
    db.kv_set("object_lifecycle_comparisons", comparisons)
    db.commit()

    issue_count = sum(len(c["issues"]) for c in comparisons)
    msg_info(f"Compared {len(comparisons)} lifecycles with TC: "
             f"{issue_count} issues found")

    for comp in comparisons:
        if comp["issues"]:
            for iss in comp["issues"]:
                severity = iss["severity"].upper()
                msg(f"  [{severity}] {comp['class_name']}: {iss['detail']}")

    return comparisons


def generate_lifecycle_docs(session, class_name=None):
    """Generate human-readable documentation for recovered lifecycles.

    Args:
        session: PluginSession
        class_name: Optional filter for a specific class

    Returns:
        Documentation string.
    """
    db = session.db
    lifecycles = db.kv_get("object_lifecycles") or []
    comparisons = db.kv_get("object_lifecycle_comparisons") or []
    comp_map = {c["class_name"]: c for c in comparisons}

    if class_name:
        lifecycles = [
            lc for lc in lifecycles
            if lc.get("class_name") == class_name
            or (class_name.lower() in (lc.get("class_name") or "").lower())
        ]

    if not lifecycles:
        return f"No lifecycles found{' for ' + class_name if class_name else ''}.\n"

    sections = []

    for lc in lifecycles:
        cls = lc.get("class_name", "unknown")
        size = lc.get("size")
        ownership = lc.get("ownership", "unknown")
        alloc = lc.get("allocation", {})
        timeline = lc.get("timeline", [])

        header = f"## {cls} Object Lifecycle"
        lines = [header]

        if size:
            lines.append(f"**Size:** 0x{size:X} ({size} bytes)")
        lines.append(f"**Allocation:** {alloc.get('type', 'unknown')}")
        lines.append(f"**Ownership:** {ownership}")

        vtable_ea = alloc.get("vtable_ea")
        if vtable_ea:
            lines.append(f"**VTable:** {ea_str(vtable_ea)}")

        # Creation phase
        creation_events = [e for e in timeline if e["phase"] in ("allocate", "construct", "init")]
        if creation_events:
            lines.append("")
            lines.append("### Creation")
            for i, ev in enumerate(creation_events, 1):
                lines.append(f"{i}. `{ev['detail']}`")

        # Configuration phase
        config_events = [e for e in timeline if e["phase"] == "configure"]
        if config_events:
            lines.append("")
            lines.append("### Configuration")
            for i, ev in enumerate(config_events, 1):
                lines.append(f"{i}. `{ev['detail']}`")

        # Usage phase
        use_events = [e for e in timeline if e["phase"] in ("use", "store")]
        if use_events:
            lines.append("")
            lines.append("### Usage")
            seen = set()
            for ev in use_events:
                detail = ev["detail"]
                if detail not in seen:
                    lines.append(f"- `{detail}`")
                    seen.add(detail)

        # Destruction phase
        destroy_events = [e for e in timeline if e["phase"] == "destroy"]
        if destroy_events:
            lines.append("")
            lines.append("### Destruction")
            for i, ev in enumerate(destroy_events, 1):
                lines.append(f"{i}. `{ev['detail']}`")

        # TC Comparison
        comp = comp_map.get(cls)
        if comp:
            lines.append("")
            lines.append("### TC Comparison")
            if comp["issues"]:
                for iss in comp["issues"]:
                    severity = iss["severity"]
                    marker = {"error": "X", "warning": "!", "info": "~"}.get(severity, "?")
                    lines.append(f"- [{marker}] {iss['detail']}")
            else:
                lines.append("- All checks passed.")

        # Functions that manipulate this object
        funcs = lc.get("functions", [])
        if funcs:
            lines.append("")
            lines.append("### Functions")
            for fn in funcs[:20]:
                lines.append(f"- `{fn}`")
            if len(funcs) > 20:
                lines.append(f"- ... and {len(funcs) - 20} more")

        sections.append("\n".join(lines))

    return "\n\n---\n\n".join(sections) + "\n"


def get_object_lifecycles(session):
    """Retrieve stored lifecycle data."""
    return session.db.kv_get("object_lifecycles") or []


def get_lifecycle_issues(session):
    """Retrieve potential bugs: leaks, double-frees, mismatches."""
    return session.db.kv_get("object_lifecycle_issues") or []


def generate_raii_wrapper(session, class_name):
    """Generate C++ RAII wrapper for a class if the binary shows it needs
    explicit cleanup that TC might miss.

    Args:
        session: PluginSession
        class_name: Class to generate wrapper for

    Returns:
        C++ source code string.
    """
    db = session.db
    lifecycles = db.kv_get("object_lifecycles") or []

    target = None
    for lc in lifecycles:
        if lc.get("class_name") == class_name:
            target = lc
            break
        if class_name.lower() in (lc.get("class_name") or "").lower():
            target = lc
            break

    if not target:
        return f"// Class '{class_name}' not found in recovered lifecycles.\n"

    cls = target.get("class_name", class_name)
    size = target.get("size")
    ownership = target.get("ownership", "unknown")
    timeline = target.get("timeline", [])

    # Collect cleanup actions from destruction phase
    cleanup_actions = []
    for ev in timeline:
        if ev["phase"] == "destroy":
            cleanup_actions.append(ev["detail"])

    # Collect initialization actions
    init_actions = []
    for ev in timeline:
        if ev["phase"] in ("construct", "init", "configure"):
            init_actions.append(ev["detail"])

    lines = [
        f"// RAII wrapper for {cls}",
        f"// Generated from binary lifecycle analysis",
    ]
    if size:
        lines.append(f"// Binary object size: 0x{size:X} ({size} bytes)")
    lines.append(f"// Ownership model: {ownership}")
    lines.append("")

    # Unique pointer typedef
    lines.append(f"// Option 1: std::unique_ptr with custom deleter")
    lines.append(f"struct {cls}Deleter {{")
    lines.append(f"    void operator()({cls}* ptr) const {{")
    if cleanup_actions:
        for action in cleanup_actions:
            lines.append(f"        // Binary: {action}")
    lines.append(f"        delete ptr;")
    lines.append(f"    }}")
    lines.append(f"}};")
    lines.append(f"using {cls}Ptr = std::unique_ptr<{cls}, {cls}Deleter>;")
    lines.append("")

    # RAII wrapper class
    lines.append(f"// Option 2: Full RAII wrapper")
    lines.append(f"class {cls}Guard {{")
    lines.append(f"public:")
    lines.append(f"    explicit {cls}Guard({cls}* obj = nullptr) : _obj(obj) {{}}")
    lines.append(f"")
    lines.append(f"    ~{cls}Guard() {{")
    lines.append(f"        reset();")
    lines.append(f"    }}")
    lines.append(f"")
    lines.append(f"    {cls}Guard({cls}Guard&& other) noexcept : _obj(other._obj) {{")
    lines.append(f"        other._obj = nullptr;")
    lines.append(f"    }}")
    lines.append(f"")
    lines.append(f"    {cls}Guard& operator=({cls}Guard&& other) noexcept {{")
    lines.append(f"        if (this != &other) {{")
    lines.append(f"            reset();")
    lines.append(f"            _obj = other._obj;")
    lines.append(f"            other._obj = nullptr;")
    lines.append(f"        }}")
    lines.append(f"        return *this;")
    lines.append(f"    }}")
    lines.append(f"")
    lines.append(f"    {cls}Guard(const {cls}Guard&) = delete;")
    lines.append(f"    {cls}Guard& operator=(const {cls}Guard&) = delete;")
    lines.append(f"")
    lines.append(f"    void reset({cls}* newObj = nullptr) {{")
    lines.append(f"        if (_obj) {{")
    if cleanup_actions:
        for action in cleanup_actions:
            lines.append(f"            // Binary cleanup: {action}")
    lines.append(f"            delete _obj;")
    lines.append(f"        }}")
    lines.append(f"        _obj = newObj;")
    lines.append(f"    }}")
    lines.append(f"")
    lines.append(f"    {cls}* get() const {{ return _obj; }}")
    lines.append(f"    {cls}* operator->() const {{ return _obj; }}")
    lines.append(f"    {cls}& operator*() const {{ return *_obj; }}")
    lines.append(f"    explicit operator bool() const {{ return _obj != nullptr; }}")
    lines.append(f"")
    lines.append(f"    {cls}* release() {{")
    lines.append(f"        {cls}* tmp = _obj;")
    lines.append(f"        _obj = nullptr;")
    lines.append(f"        return tmp;")
    lines.append(f"    }}")
    lines.append(f"")
    lines.append(f"private:")
    lines.append(f"    {cls}* _obj;")
    lines.append(f"}};")

    return "\n".join(lines) + "\n"


# =========================================================================
# Internal: Allocation finding
# =========================================================================

def _find_allocations(pseudocode, func_name, func_ea):
    """Find all object creation patterns in decompiled pseudocode.

    Returns list of allocation records.
    """
    allocs = []
    lines = pseudocode.split("\n")

    for line_idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue

        # --- operator new(size) ---
        m = _OP_NEW_RE.search(stripped)
        if m:
            var_name = m.group(1)
            raw_size = m.group(2)
            size = _parse_int(raw_size)
            alloc = {
                "type": "heap",
                "size": size,
                "line": line_idx,
                "variable": var_name,
                "constructor_call": None,
                "constructor_call_ea": None,
                "vtable_assign": None,
                "vtable_ea": None,
                "class_name": None,
                "raw": stripped,
            }
            # Look ahead for constructor call and vtable assignment
            _scan_post_alloc(lines, line_idx, var_name, alloc)
            allocs.append(alloc)
            continue

        # --- operator new[](expr) ---
        m = _OP_NEW_ARRAY_RE.search(stripped)
        if m:
            var_name = m.group(1)
            size_expr = m.group(2)
            size = _parse_int(size_expr)
            alloc = {
                "type": "heap_array",
                "size": size,
                "size_expr": size_expr if size is None else None,
                "line": line_idx,
                "variable": var_name,
                "constructor_call": None,
                "constructor_call_ea": None,
                "vtable_assign": None,
                "vtable_ea": None,
                "class_name": None,
                "raw": stripped,
            }
            allocs.append(alloc)
            continue

        # --- calloc(count, size) ---
        m = _CALLOC_RE.search(stripped)
        if m:
            var_name = m.group(1)
            count_expr = m.group(2)
            elem_size = _parse_int(m.group(3))
            alloc = {
                "type": "heap",
                "size": elem_size,
                "count_expr": count_expr,
                "line": line_idx,
                "variable": var_name,
                "constructor_call": None,
                "constructor_call_ea": None,
                "vtable_assign": None,
                "vtable_ea": None,
                "class_name": None,
                "raw": stripped,
            }
            allocs.append(alloc)
            continue

        # --- malloc(size) ---
        m = _MALLOC_RE.search(stripped)
        if m:
            var_name = m.group(1)
            size = _parse_int(m.group(2))
            alloc = {
                "type": "heap",
                "size": size,
                "line": line_idx,
                "variable": var_name,
                "constructor_call": None,
                "constructor_call_ea": None,
                "vtable_assign": None,
                "vtable_ea": None,
                "class_name": None,
                "raw": stripped,
            }
            _scan_post_alloc(lines, line_idx, var_name, alloc)
            allocs.append(alloc)
            continue

        # --- alloca(size) — stack allocation ---
        m = _ALLOCA_RE.search(stripped)
        if m:
            var_name = m.group(1)
            size = _parse_int(m.group(2))
            alloc = {
                "type": "stack",
                "size": size,
                "line": line_idx,
                "variable": var_name,
                "constructor_call": None,
                "constructor_call_ea": None,
                "vtable_assign": None,
                "vtable_ea": None,
                "class_name": None,
                "raw": stripped,
            }
            allocs.append(alloc)
            continue

        # --- Pool allocation ---
        m = _POOL_ALLOC_RE.search(stripped)
        if m:
            var_name = m.group(1)
            pool_var = m.group(2)
            method = m.group(3)
            alloc = {
                "type": "pool",
                "size": None,
                "line": line_idx,
                "variable": var_name,
                "pool_source": f"{pool_var}->{method}",
                "constructor_call": None,
                "constructor_call_ea": None,
                "vtable_assign": None,
                "vtable_ea": None,
                "class_name": None,
                "raw": stripped,
            }
            _scan_post_alloc(lines, line_idx, var_name, alloc)
            allocs.append(alloc)
            continue

        # --- Factory pattern (heuristic) ---
        m = _FACTORY_RE.search(stripped)
        if m:
            var_name = m.group(1)
            func_called = m.group(2)
            # Only count as factory if the function name contains factory keywords
            func_lower = func_called.lower()
            is_factory = any(kw in func_lower for kw in _FACTORY_KEYWORDS)
            # Also check for ClassName::Create patterns
            if "::" in func_called and func_called.split("::")[-1].lower() in _FACTORY_KEYWORDS:
                is_factory = True
            if is_factory:
                # Extract class name from factory function name
                factory_class = None
                if "::" in func_called:
                    factory_class = func_called.split("::")[0]
                alloc = {
                    "type": "factory",
                    "size": None,
                    "line": line_idx,
                    "variable": var_name,
                    "factory_func": func_called,
                    "constructor_call": None,
                    "constructor_call_ea": None,
                    "vtable_assign": None,
                    "vtable_ea": None,
                    "class_name": factory_class,
                    "raw": stripped,
                }
                allocs.append(alloc)
                continue

    return allocs


def _scan_post_alloc(lines, alloc_line, var_name, alloc_record):
    """Scan lines after allocation for constructor call and vtable assignment.

    Looks at the next 10 lines after allocation for:
    - Constructor call: sub_XXX(var, ...) or ClassName::ClassName(var, ...)
    - Vtable assignment: *(_QWORD *)var = &vftable or literal address
    """
    scan_end = min(alloc_line + 12, len(lines))
    constructor_found = False

    for i in range(alloc_line + 1, scan_end):
        stripped = lines[i].strip()
        if not stripped:
            continue

        # Check for vtable assignment with class name
        m = _VTABLE_ASSIGN_RE.search(stripped)
        if m:
            assigned_var = m.group(1) or m.group(4)
            if assigned_var == var_name:
                class_prefix = m.group(2) or m.group(5)
                off_addr = m.group(3) or m.group(6)
                if class_prefix:
                    # Strip trailing ::
                    alloc_record["class_name"] = class_prefix.rstrip(":")
                if off_addr:
                    try:
                        alloc_record["vtable_ea"] = int(off_addr, 16)
                    except ValueError:
                        pass
                alloc_record["vtable_assign"] = i
                continue

        # Check for vtable literal address assignment
        m = _VTABLE_LITERAL_RE.search(stripped)
        if m:
            assigned_var = m.group(1) or m.group(3)
            addr_str = m.group(2) or m.group(4)
            if assigned_var == var_name and addr_str:
                try:
                    vtable_ea = int(addr_str, 16)
                    alloc_record["vtable_ea"] = vtable_ea
                    alloc_record["vtable_assign"] = i
                except ValueError:
                    pass
                continue

        # Check for constructor call (function with var as first argument)
        if not constructor_found:
            m = _CONSTRUCTOR_CALL_RE.search(stripped)
            if m:
                called_func = m.group(1)
                first_arg = m.group(2)
                if first_arg == var_name:
                    alloc_record["constructor_call"] = called_func
                    # Try to resolve EA for sub_ functions
                    if called_func.startswith("sub_"):
                        try:
                            ctor_ea = int(called_func[4:], 16)
                            alloc_record["constructor_call_ea"] = ctor_ea
                        except ValueError:
                            pass
                    constructor_found = True
                    continue


# =========================================================================
# Internal: Usage tracing
# =========================================================================

def _trace_object_usage(pseudocode, alloc_var, alloc_line):
    """Track all uses of an allocated pointer through the function.

    Returns a timeline of usage events ordered by line number.
    """
    lines = pseudocode.split("\n")
    timeline = []

    # Start with the allocation itself
    if alloc_line < len(lines):
        timeline.append({
            "phase": "allocate",
            "line": alloc_line,
            "detail": lines[alloc_line].strip(),
        })

    # Track variable aliases (assignments like v10 = v5)
    aliases = {alloc_var}
    alias_re = re.compile(
        rf'(\w+)\s*=\s*(?:\(\s*\w[\w\s\*]*\s*\)\s*)?{re.escape(alloc_var)}\s*;'
    )

    for line_idx in range(alloc_line + 1, len(lines)):
        stripped = lines[line_idx].strip()
        if not stripped:
            continue

        # Track aliases
        m = alias_re.search(stripped)
        if m:
            new_alias = m.group(1)
            aliases.add(new_alias)

        # Check if any alias is referenced on this line
        referenced_var = None
        for alias in aliases:
            if re.search(r'\b' + re.escape(alias) + r'\b', stripped):
                referenced_var = alias
                break

        if not referenced_var:
            continue

        # Classify the usage
        event = _classify_usage(stripped, referenced_var, line_idx)
        if event:
            timeline.append(event)

    return timeline


def _classify_usage(line, var_name, line_idx):
    """Classify a line of pseudocode as a lifecycle event for the given variable."""

    # --- Vtable assignment (init phase) ---
    if re.search(
        rf'\*\s*(?:\(\s*_QWORD\s*\*\s*\)\s*)?{re.escape(var_name)}\s*=\s*'
        r'(?:&\s*)?(?:\w+::.*vftable|off_[0-9A-Fa-f]+|0x[0-9A-Fa-f]{{8,}})',
        line
    ):
        return {
            "phase": "init",
            "line": line_idx,
            "detail": line.strip(),
        }

    # --- Destructor / delete (destroy phase) ---
    m = _DELETE_RE.search(line)
    if m and m.group(1) == var_name:
        return {
            "phase": "destroy",
            "line": line_idx,
            "detail": f"operator delete({var_name})",
        }

    m = _DELETE_ARRAY_RE.search(line)
    if m and m.group(1) == var_name:
        return {
            "phase": "destroy",
            "line": line_idx,
            "detail": f"operator delete[]({var_name})",
        }

    m = _POOL_FREE_RE.search(line)
    if m and m.group(3) == var_name:
        return {
            "phase": "destroy",
            "line": line_idx,
            "detail": f"{m.group(1)}->{m.group(2)}({var_name})",
        }

    # Check for explicit destructor call before delete
    m = _EXPLICIT_DTOR_RE.search(line)
    if m and m.group(2) == var_name:
        func_name = m.group(1)
        if "~" in func_name or "dtor" in func_name.lower():
            return {
                "phase": "destroy",
                "line": line_idx,
                "detail": f"{func_name}({var_name})",
            }

    # --- Container store (store phase) ---
    m = _CONTAINER_STORE_RE.search(line)
    if m:
        if m.group(3) == var_name:
            container = m.group(1)
            method = m.group(2)
            return {
                "phase": "store",
                "line": line_idx,
                "detail": f"{container}->{method}({var_name})",
            }
        if m.group(5) == var_name:
            container = m.group(4)
            return {
                "phase": "store",
                "line": line_idx,
                "detail": f"{container}[...] = {var_name}",
            }

    # --- Virtual dispatch (use phase) ---
    m = _VIRTUAL_DISPATCH_RE.search(line)
    if m and m.group(1) == var_name:
        offset = m.group(2) or "0"
        return {
            "phase": "use",
            "line": line_idx,
            "detail": f"VirtualCall({var_name}, vtable+{offset})",
        }

    # --- Method call (use phase) ---
    m = _METHOD_CALL_RE.search(line)
    if m:
        if m.group(1) == var_name:
            method = m.group(2)
            return {
                "phase": "use",
                "line": line_idx,
                "detail": f"{var_name}->{method}()",
            }
        if m.group(4) == var_name:
            func = m.group(3)
            return {
                "phase": "use",
                "line": line_idx,
                "detail": f"{func}({var_name}, ...)",
            }

    # --- Field write (configure phase) ---
    m = _FIELD_WRITE_RE.search(line)
    if m and m.group(2) == var_name:
        field_type = m.group(1)
        offset = m.group(3)
        value = m.group(4)[:40]  # truncate long values
        return {
            "phase": "configure",
            "line": line_idx,
            "detail": f"*({field_type}*)({var_name}+{offset}) = {value}",
        }

    # --- Constructor call (construct phase) ---
    m = _CONSTRUCTOR_CALL_RE.search(line)
    if m and m.group(2) == var_name:
        func = m.group(1)
        # If this looks like a constructor (sub_ or ClassName::ClassName)
        if func.startswith("sub_") or "::" in func:
            return {
                "phase": "construct",
                "line": line_idx,
                "detail": f"{func}({var_name}, ...)",
            }

    # --- Pass to function (potential ownership transfer) ---
    m = _PASS_TO_FUNC_RE.search(line)
    if m and m.group(2) == var_name:
        target_func = m.group(1)
        return {
            "phase": "use",
            "line": line_idx,
            "detail": f"PassedTo: {target_func}(..., {var_name}, ...)",
        }

    return None


# =========================================================================
# Internal: Destructor finding
# =========================================================================

def _find_destructors(pseudocode, func_ea):
    """Find all destruction patterns in decompiled pseudocode.

    Returns list of destruction records with variable, line, and type.
    """
    destructions = []
    lines = pseudocode.split("\n")

    for line_idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue

        # operator delete(ptr)
        m = _DELETE_RE.search(stripped)
        if m:
            var = m.group(1)
            # Check for destructor call on the previous lines
            dtor_call = None
            for back in range(max(0, line_idx - 3), line_idx):
                dm = _EXPLICIT_DTOR_RE.search(lines[back].strip())
                if dm and dm.group(2) == var:
                    dtor_call = dm.group(1)
                    break
            destructions.append({
                "variable": var,
                "line": line_idx,
                "type": "delete",
                "destructor_call": dtor_call,
                "raw": stripped,
            })
            continue

        # operator delete[](ptr)
        m = _DELETE_ARRAY_RE.search(stripped)
        if m:
            destructions.append({
                "variable": m.group(1),
                "line": line_idx,
                "type": "delete_array",
                "destructor_call": None,
                "raw": stripped,
            })
            continue

        # Virtual destructor dispatch
        m = _VIRT_DTOR_RE.search(stripped)
        if m:
            destructions.append({
                "variable": m.group(1),
                "line": line_idx,
                "type": "virtual_dtor",
                "destructor_call": "vtable[0]",
                "raw": stripped,
            })
            continue

        # Pool free
        m = _POOL_FREE_RE.search(stripped)
        if m:
            destructions.append({
                "variable": m.group(3),
                "line": line_idx,
                "type": "pool_free",
                "pool_source": f"{m.group(1)}->{m.group(2)}",
                "destructor_call": None,
                "raw": stripped,
            })
            continue

        # Explicit destructor without delete (unusual but possible)
        m = _EXPLICIT_DTOR_RE.search(stripped)
        if m:
            func_name = m.group(1)
            if "~" in func_name:
                # Check if there's a delete on the next few lines
                has_delete = False
                for fwd in range(line_idx + 1, min(line_idx + 4, len(lines))):
                    dm = _DELETE_RE.search(lines[fwd].strip())
                    if dm and dm.group(1) == m.group(2):
                        has_delete = True
                        break
                if not has_delete:
                    # Standalone destructor call (placement delete or RAII)
                    destructions.append({
                        "variable": m.group(2),
                        "line": line_idx,
                        "type": "dtor_only",
                        "destructor_call": func_name,
                        "raw": stripped,
                    })

    return destructions


# =========================================================================
# Internal: Matching allocations with destructions
# =========================================================================

def _match_allocation_destruction(allocs, destructions):
    """Pair allocations with their corresponding destructions.

    Returns list of issues found (leaks, double-frees, mismatches).
    """
    issues = []

    # Build sets for quick lookup
    alloc_vars = {}
    for alloc in allocs:
        var = alloc["variable"]
        if var not in alloc_vars:
            alloc_vars[var] = []
        alloc_vars[var].append(alloc)

    destr_vars = {}
    for destr in destructions:
        var = destr["variable"]
        if var not in destr_vars:
            destr_vars[var] = []
        destr_vars[var].append(destr)

    matched_allocs = set()
    matched_destrs = set()

    # Match by variable name
    for var, var_allocs in alloc_vars.items():
        if var in destr_vars:
            var_destrs = destr_vars[var]
            # Simple 1:1 matching by order
            for i, alloc in enumerate(var_allocs):
                if i < len(var_destrs):
                    destr = var_destrs[i]
                    matched_allocs.add(id(alloc))
                    matched_destrs.add(id(destr))

                    # Check for type mismatch
                    if alloc["type"] == "heap_array" and destr["type"] == "delete":
                        issues.append({
                            "type": "array_delete_mismatch",
                            "severity": "error",
                            "variable": var,
                            "alloc_line": alloc["line"],
                            "destr_line": destr["line"],
                            "detail": f"Allocated with new[] but freed with delete "
                                      f"(should be delete[])",
                        })
                    elif alloc["type"] == "heap" and destr["type"] == "delete_array":
                        issues.append({
                            "type": "scalar_delete_array_mismatch",
                            "severity": "error",
                            "variable": var,
                            "alloc_line": alloc["line"],
                            "destr_line": destr["line"],
                            "detail": f"Allocated with new but freed with delete[] "
                                      f"(should be delete)",
                        })
                    elif alloc["type"] == "pool" and destr["type"] not in ("pool_free",):
                        issues.append({
                            "type": "pool_alloc_wrong_free",
                            "severity": "error",
                            "variable": var,
                            "alloc_line": alloc["line"],
                            "destr_line": destr["line"],
                            "detail": f"Pool-allocated object freed with "
                                      f"'{destr['type']}' instead of pool return",
                        })

                    # Check if alloc happens after destruction (use-after-free candidate)
                    if alloc["line"] > destr["line"]:
                        issues.append({
                            "type": "possible_reuse_after_free",
                            "severity": "warning",
                            "variable": var,
                            "alloc_line": alloc["line"],
                            "destr_line": destr["line"],
                            "detail": f"Variable '{var}' allocated at line "
                                      f"{alloc['line']} after destruction at "
                                      f"line {destr['line']}",
                        })
                else:
                    # More allocations than destructions for this variable
                    break

            # Check for excess destructions (double-free candidates)
            if len(var_destrs) > len(var_allocs):
                for extra_destr in var_destrs[len(var_allocs):]:
                    issues.append({
                        "type": "possible_double_free",
                        "severity": "error",
                        "variable": var,
                        "destr_line": extra_destr["line"],
                        "detail": f"Extra destruction of '{var}' at line "
                                  f"{extra_destr['line']} with no matching allocation",
                    })

    # Unmatched allocations — potential leaks
    for alloc in allocs:
        if id(alloc) not in matched_allocs:
            # Not a leak if ownership is transferred (stored in container, etc.)
            # We note it but at lower severity
            issues.append({
                "type": "potential_leak",
                "severity": "info",
                "variable": alloc["variable"],
                "alloc_line": alloc["line"],
                "alloc_type": alloc["type"],
                "size": alloc.get("size"),
                "detail": f"Allocation of '{alloc['variable']}' "
                          f"(type={alloc['type']}, size={alloc.get('size')}) "
                          f"at line {alloc['line']} has no matching deallocation "
                          f"in this function (may be ownership-transferred)",
            })

    # Unmatched destructions — freeing external/parameter pointers
    for destr in destructions:
        if id(destr) not in matched_destrs:
            issues.append({
                "type": "external_free",
                "severity": "info",
                "variable": destr["variable"],
                "destr_line": destr["line"],
                "detail": f"Deallocation of '{destr['variable']}' at line "
                          f"{destr['line']} — not allocated in this function "
                          f"(external ownership)",
            })

    return issues


# =========================================================================
# Internal: Ownership analysis
# =========================================================================

def _analyze_ownership(alloc_info, usage_timeline):
    """Determine the ownership semantics from the allocation + usage timeline.

    Returns one of:
    - "local": created and destroyed in the same function
    - "container_owned": stored in a container that manages lifetime
    - "transferred": passed to another function that takes ownership
    - "shared": multiple references, reference-counted
    - "leaked": allocated but never freed (potential bug or intentional global)
    - "pool_managed": returned to an object pool
    """
    has_alloc = False
    has_destroy = False
    has_store = False
    has_pass = False
    is_pool = alloc_info.get("type") == "pool"
    pass_targets = []

    for event in usage_timeline:
        phase = event["phase"]
        if phase == "allocate":
            has_alloc = True
        elif phase == "destroy":
            has_destroy = True
        elif phase == "store":
            has_store = True
        elif phase == "use":
            detail = event.get("detail", "")
            if detail.startswith("PassedTo:"):
                has_pass = True
                # Extract the target function name
                func_match = re.search(r'PassedTo:\s*(\S+)', detail)
                if func_match:
                    pass_targets.append(func_match.group(1))

    # Check for shared_ptr / reference counting patterns
    has_addref = any(
        "AddRef" in e.get("detail", "") or "addref" in e.get("detail", "").lower()
        or "IncRef" in e.get("detail", "") or "Release" in e.get("detail", "")
        for e in usage_timeline
    )
    if has_addref:
        return "shared"

    if is_pool:
        if has_destroy:
            return "pool_managed"
        if has_store:
            return "container_owned"
        return "pool_managed"

    if has_alloc and has_destroy and not has_store and not has_pass:
        return "local"

    if has_store:
        return "container_owned"

    if has_pass and not has_destroy:
        return "transferred"

    if has_alloc and not has_destroy and not has_store and not has_pass:
        return "leaked"

    if has_alloc and has_destroy:
        return "local"

    return "leaked"


# =========================================================================
# Internal: Class recovery from allocation context
# =========================================================================

def _recover_class_from_allocation(db, size, vtable_ea, constructor_ea):
    """Identify the class from allocation context.

    Priority:
    1. vtable EA -> look up in vtables table
    2. constructor EA -> look up function name
    3. allocation size -> match against known class sizes
    """
    # 1. From vtable EA
    if vtable_ea:
        row = db.fetchone(
            "SELECT class_name FROM vtables WHERE ea = ?", (vtable_ea,)
        )
        if row and row["class_name"]:
            return row["class_name"]

        # Also try RVA-based lookup (vtable_ea might be absolute)
        row = db.fetchone(
            "SELECT class_name FROM vtables WHERE rva = ?", (vtable_ea,)
        )
        if row and row["class_name"]:
            return row["class_name"]

    # 2. From constructor EA
    if constructor_ea:
        name = None
        try:
            name = ida_name.get_name(constructor_ea)
        except Exception:
            pass

        if name:
            # Demangle: ClassName::ClassName -> ClassName
            if "::" in name:
                parts = name.split("::")
                # Constructor: X::X, or X::Y where Y is init-like
                if len(parts) >= 2:
                    return parts[0]
            # sub_ functions: check if we have it in the functions table
            row = db.fetchone(
                "SELECT name, system FROM functions WHERE ea = ?",
                (constructor_ea,)
            )
            if row and row["name"] and not row["name"].startswith("sub_"):
                fname = row["name"]
                if "::" in fname:
                    return fname.split("::")[0]

    # 3. From size
    if size and size in _KNOWN_SIZES:
        return _KNOWN_SIZES[size]

    return None


# =========================================================================
# Internal: Helpers
# =========================================================================

def _parse_int(s):
    """Parse a string as an integer (hex or decimal). Returns None on failure."""
    if s is None:
        return None
    s = s.strip()
    try:
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return None


def _populate_known_sizes(db):
    """Populate _KNOWN_SIZES from existing object_layout and vtable data."""
    global _KNOWN_SIZES
    _KNOWN_SIZES.clear()

    # From object_layouts kv_store (if object_layout analyzer has run)
    layouts = db.kv_get("object_layouts")
    if layouts and isinstance(layouts, list):
        for layout in layouts:
            class_name = layout.get("class_name")
            size = layout.get("total_size") or layout.get("size")
            if class_name and size and isinstance(size, int):
                _KNOWN_SIZES[size] = class_name

    # From vtables table — some vtable entries have associated size info
    # in annotations
    try:
        rows = db.fetchall(
            "SELECT v.class_name, a.value FROM vtables v "
            "JOIN annotations a ON a.ea = v.ea "
            "WHERE a.ann_type = 'comment' AND a.value LIKE '%size%'"
        )
        for row in rows:
            class_name = row["class_name"]
            comment = row["value"]
            # Try to extract size from comment: "size=0x2A0" or "sizeof=672"
            m = re.search(r'size\s*[=:]\s*(0x[0-9A-Fa-f]+|\d+)', comment)
            if m and class_name:
                size = _parse_int(m.group(1))
                if size:
                    _KNOWN_SIZES[size] = class_name
    except Exception:
        pass


def _get_candidate_functions(db, system_filter):
    """Get functions to scan for object lifecycles.

    Returns list of dicts with 'ea' and 'name' keys.
    """
    candidates = []

    # Start with opcode handlers (richest source of object lifecycle patterns)
    query = "SELECT handler_ea AS ea, tc_name AS name FROM opcodes WHERE handler_ea IS NOT NULL"
    if system_filter:
        query += (f" AND (tc_name LIKE '%{system_filter}%' "
                  f"OR jam_type LIKE '%{system_filter}%')")
    rows = db.fetchall(query)
    seen_eas = set()
    for row in rows:
        ea = row["ea"]
        if ea and ea not in seen_eas:
            candidates.append({"ea": ea, "name": row["name"]})
            seen_eas.add(ea)

    # Add functions from the functions table that belong to the system
    if system_filter:
        func_query = (
            f"SELECT ea, name FROM functions WHERE system = ? "
            f"ORDER BY ea"
        )
        rows = db.fetchall(func_query, (system_filter,))
    else:
        # Without filter, add functions that are likely interesting
        # (named, or in known systems)
        func_query = (
            "SELECT ea, name FROM functions "
            "WHERE system IS NOT NULL AND name IS NOT NULL "
            "ORDER BY ea"
        )
        rows = db.fetchall(func_query)

    for row in rows:
        ea = row["ea"]
        if ea and ea not in seen_eas:
            candidates.append({"ea": ea, "name": row["name"]})
            seen_eas.add(ea)

    # Add vtable methods (constructors/destructors are vtable-associated)
    vtable_query = (
        "SELECT DISTINCT ve.func_ea AS ea, ve.func_name AS name "
        "FROM vtable_entries ve"
    )
    if system_filter:
        vtable_query += (
            f" JOIN vtables v ON ve.vtable_ea = v.ea "
            f"WHERE v.class_name LIKE '%{system_filter}%'"
        )
    vtable_query += " ORDER BY ve.func_ea"
    rows = db.fetchall(vtable_query)
    for row in rows:
        ea = row["ea"]
        if ea and ea not in seen_eas:
            candidates.append({"ea": ea, "name": row["name"]})
            seen_eas.add(ea)

    return candidates


def _merge_lifecycles(lifecycles):
    """Merge lifecycles that describe the same class.

    Groups by class_name (or size if class unknown), merges timelines
    and collects all functions that participate.
    """
    groups = defaultdict(list)

    for lc in lifecycles:
        cls = lc.get("class_name", "unknown")
        size = lc.get("size")
        if cls == "unknown" and size:
            key = f"unknown_0x{size:X}"
        elif cls == "unknown":
            key = f"unknown_{lc.get('allocation', {}).get('variable', 'anon')}"
        else:
            key = cls
        groups[key].append(lc)

    merged = []
    for key, group in groups.items():
        # Pick the richest lifecycle as the base
        group.sort(key=lambda lc: len(lc.get("timeline", [])), reverse=True)
        base = group[0]

        # Collect all functions that deal with this class
        funcs = list(set(
            lc["function"] for lc in group if lc.get("function")
        ))

        # Merge timelines: take unique phases
        seen_details = set()
        merged_timeline = []
        for lc in group:
            for event in lc.get("timeline", []):
                detail = event.get("detail", "")
                phase_key = (event["phase"], detail)
                if phase_key not in seen_details:
                    seen_details.add(phase_key)
                    merged_timeline.append(event)

        # Sort timeline by phase priority
        phase_order = {
            "allocate": 0, "construct": 1, "init": 2,
            "configure": 3, "store": 4, "use": 5, "destroy": 6,
        }
        merged_timeline.sort(
            key=lambda e: (phase_order.get(e["phase"], 99), e.get("line", 0))
        )

        # Determine consensus ownership
        ownership_votes = defaultdict(int)
        for lc in group:
            ownership = lc.get("ownership", "unknown")
            ownership_votes[ownership] += 1
        consensus_ownership = max(ownership_votes, key=ownership_votes.get)

        # Take the best allocation info (one with most fields populated)
        best_alloc = max(
            (lc.get("allocation", {}) for lc in group),
            key=lambda a: sum(1 for v in a.values() if v is not None),
            default={}
        )

        merged_entry = {
            "class_name": base.get("class_name", key),
            "size": base.get("size"),
            "allocation": best_alloc,
            "timeline": merged_timeline,
            "ownership": consensus_ownership,
            "functions": sorted(funcs),
            "instance_count": len(group),
        }
        merged.append(merged_entry)

    # Sort by instance count descending
    merged.sort(key=lambda e: e["instance_count"], reverse=True)
    return merged


def _build_tc_class_map(db):
    """Build a map of TC class information from the knowledge DB.

    Returns dict keyed by class_name with alloc_type, size, ownership, etc.
    """
    tc_classes = {}

    # From vtables
    rows = db.fetchall("SELECT * FROM vtables WHERE class_name IS NOT NULL")
    for row in rows:
        cls = row["class_name"]
        if cls not in tc_classes:
            tc_classes[cls] = {
                "class_name": cls,
                "vtable_ea": row["ea"],
                "parent_class": row["parent_class"],
                "has_destructor": False,
                "alloc_type": None,
                "size": None,
                "ownership": None,
            }

    # Check for destructor in vtable slot 0
    for cls, info in tc_classes.items():
        vtable_ea = info.get("vtable_ea")
        if vtable_ea:
            dtor_row = db.fetchone(
                "SELECT func_name FROM vtable_entries "
                "WHERE vtable_ea = ? AND slot_index = 0",
                (vtable_ea,)
            )
            if dtor_row:
                func_name = dtor_row["func_name"] or ""
                if "~" in func_name or "dtor" in func_name.lower() or "deleting" in func_name.lower():
                    info["has_destructor"] = True

    # From functions table, look for Create/new/Delete patterns
    for cls in list(tc_classes.keys()):
        create_row = db.fetchone(
            "SELECT name FROM functions WHERE name LIKE ?",
            (f"%{cls}%Create%",)
        )
        if create_row:
            tc_classes[cls]["alloc_type"] = "factory"

    # From object_layouts if available
    layouts = db.kv_get("object_layouts")
    if layouts and isinstance(layouts, list):
        for layout in layouts:
            cls = layout.get("class_name")
            if cls and cls in tc_classes:
                tc_classes[cls]["size"] = layout.get("total_size") or layout.get("size")

    return tc_classes
