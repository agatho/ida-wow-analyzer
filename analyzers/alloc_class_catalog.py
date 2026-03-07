"""
Allocation-Based Class Catalog Builder

Uses `operator new(size)` calls and custom allocator invocations to determine
exact class sizes from the WoW client binary.  Builds a comprehensive class
catalog by cross-referencing allocation sites with vtable data, RTTI (when
present), constructor patterns, and recovered object layouts.

The resulting catalog maps every (size, vtable) pair to a named class entry
with inheritance relationships, factory function provenance, and optional
TrinityCore size comparisons for drift detection.

Results are stored in the knowledge DB under kv_store key "class_catalog".
"""

import json
import re
import time
import struct
from collections import defaultdict

import ida_funcs
import ida_name
import ida_bytes
import idautils
import idaapi
import idc

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# MSVC x64 mangled names for heap allocators
_OPERATOR_NEW_NAMES = {
    "operator new",
    "j_operator_new",
    "??2@YAPEAX_K@Z",           # operator new(size_t) — MSVC x64
    "??2@YAPAXI@Z",             # operator new(size_t) — MSVC x86
    "??_U@YAPEAX_K@Z",          # operator new[](size_t) — MSVC x64
    "??_U@YAPAXI@Z",            # operator new[](size_t) — MSVC x86
    "operator new[]",
    "j_operator_new[]",
}

# Custom WoW allocator function names (Blizzard's memory subsystem)
_CUSTOM_ALLOCATOR_NAMES = {
    "SMemAlloc",
    "SMemReAlloc",
    "WoWAlloc",
    "BlzAlloc",
    "BLZ_ALLOC",
    "Storm_MemAlloc",
    "SMemNew",
    "SFile_MemAlloc",
}

# Pool allocator patterns (substring match)
_POOL_ALLOCATOR_SUBSTRINGS = [
    "PoolAlloc",
    "Pool_Alloc",
    "Allocate",  # MemoryPool::Allocate
    "ObjectPool",
    "FrameAlloc",
    "FrameNew",
    "Arena_Alloc",
    "ScratchAlloc",
]

# Operator delete names for destructor detection
_OPERATOR_DELETE_NAMES = {
    "operator delete",
    "j_operator_delete",
    "??3@YAXPEAX@Z",            # operator delete(void*) — MSVC x64
    "??3@YAXPAX@Z",             # operator delete(void*) — MSVC x86
    "??_V@YAXPEAX@Z",           # operator delete[](void*) — MSVC x64
    "operator delete[]",
    "j_operator_delete[]",
    "SMemFree",
    "WoWFree",
    "BlzFree",
    "BLZ_FREE",
    "Storm_MemFree",
}

# Known TrinityCore class sizes (common game classes)
# Populated dynamically from TC source scanning when tc_source_dir is set
_TC_CLASS_SIZES = {
    # Base game objects — these are approximate and version-dependent
    # They will be overridden by actual TC source scanning
    "Object":               0x30,
    "WorldObject":          0x208,
    "Unit":                 0x1E00,
    "Player":               0xA000,
    "Creature":             0x2200,
    "GameObject":           0x500,
    "Item":                 0x350,
    "Corpse":               0x280,
    "DynamicObject":        0x260,
    "AreaTrigger":          0x300,
    "Conversation":         0x280,
    "SceneObject":          0x260,
    "WorldSession":         0xA00,
    "Map":                  0x900,
    "InstanceMap":          0xA00,
    "BattlegroundMap":      0xA80,
    "Spell":                0xE00,
    "Aura":                 0x180,
    "AuraEffect":           0xC0,
    "SpellCastTargets":     0x100,
    "Transport":            0x600,
    "Pet":                  0x2400,
    "Totem":                0x2300,
    "TempSummon":           0x2300,
    "Vehicle":              0x60,
    "VehicleSeat":          0x40,
    "Loot":                 0x200,
    "Group":                0x300,
    "Guild":                0x800,
    "Quest":                0x300,
    "WorldPacket":          0x40,
    "ByteBuffer":           0x28,
}

# Minimum pointer count to consider a region a vtable
_MIN_VTABLE_ENTRIES = 2

# Maximum function scan count before progress reporting
_PROGRESS_INTERVAL = 500

# Maximum number of xrefs to follow per allocator function
_MAX_XREFS_PER_ALLOC = 50000

# Maximum pseudocode lines to scan per function
_MAX_PSEUDOCODE_LINES = 5000


# ---------------------------------------------------------------------------
# Regex patterns for pseudocode analysis
# ---------------------------------------------------------------------------

# operator new(SIZE) in decompiled code — captures variable and size
_RE_OP_NEW = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*[\w\s\*]+\s*\)\s*)?'
    r'(?:operator\s+new|j_?operator_new|'
    r'\?\?2@YAPEAX_K@Z|'
    r'\?\?2@YAPAXI@Z)'
    r'\s*\(\s*(0x[0-9A-Fa-f]+|\d+)',
    re.IGNORECASE
)

# operator new[](SIZE)
_RE_OP_NEW_ARRAY = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*[\w\s\*]+\s*\)\s*)?'
    r'(?:operator\s+new\[\]|j_?operator_new\[\]|'
    r'\?\?_U@YAPEAX_K@Z)'
    r'\s*\(\s*(0x[0-9A-Fa-f]+|\d+)',
    re.IGNORECASE
)

# SMemAlloc / custom allocators: var = SMemAlloc(size, ...)
_RE_CUSTOM_ALLOC = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*[\w\s\*]+\s*\)\s*)?'
    r'(SMemAlloc|WoWAlloc|BlzAlloc|BLZ_ALLOC|Storm_MemAlloc|SMemNew)'
    r'\s*\(\s*(0x[0-9A-Fa-f]+|\d+)',
    re.IGNORECASE
)

# Constructor call after allocation: sub_XXX(allocated_var, ...) or ClassName::ClassName(var)
_RE_CTOR_CALL = re.compile(
    r'(sub_[0-9A-Fa-f]+|\w+::\w+)\s*\(\s*(\w+)\s*(?:,|\))'
)

# Vtable assignment: *(_QWORD *)var = &off_XXXX or *(_QWORD *)var = &ClassName::vftable
_RE_VTABLE_ASSIGN = re.compile(
    r'\*\s*\(\s*_QWORD\s*\*\s*\)\s*(\w+)\s*=\s*'
    r'(?:&\s*)?'
    r'(?:'
    r'off_([0-9A-Fa-f]+)'
    r'|'
    r'(\w+)::(?:`vftable\'|vftable)'
    r')'
)

# Vtable literal assignment: *(_QWORD *)var = 0x7FF6XXXXXXXX
_RE_VTABLE_LITERAL = re.compile(
    r'\*\s*\(\s*_QWORD\s*\*\s*\)\s*(\w+)\s*=\s*(0x[0-9A-Fa-f]{8,})\s*;'
)

# Vtable assignment at offset: *(_QWORD *)(var + OFFSET) = &off_XXXX
# This indicates multiple inheritance (secondary vtable pointer)
_RE_VTABLE_OFFSET_ASSIGN = re.compile(
    r'\*\s*\(\s*_QWORD\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)\s*=\s*'
    r'(?:&\s*)?'
    r'(?:'
    r'off_([0-9A-Fa-f]+)'
    r'|'
    r'(\w+)::(?:`vftable\'|vftable)'
    r'|'
    r'(0x[0-9A-Fa-f]{8,})'
    r')'
)

# operator delete(var) — destructor indicator
_RE_OP_DELETE = re.compile(
    r'(?:operator\s+delete|j_?operator_delete|'
    r'\?\?3@YAXPEAX@Z|SMemFree|WoWFree|BlzFree|BLZ_FREE)'
    r'\s*\(\s*(\w+)',
    re.IGNORECASE
)

# Destructor call: var->~ClassName() or ClassName::~ClassName(var)
_RE_DTOR_CALL = re.compile(
    r'(\w+)::~(\w+)\s*\(\s*(\w+)\s*\)'
    r'|'
    r'(\w+)\s*->\s*~(\w+)\s*\(\s*\)'
)

# Constructor calling base constructor: ClassName::ClassName(this) inside another ctor
_RE_BASE_CTOR_CALL = re.compile(
    r'(\w+::\w+)\s*\(\s*(\w+)\s*\)'
)

# Switch-case pattern for factory detection
_RE_SWITCH_CASE = re.compile(
    r'case\s+(0x[0-9A-Fa-f]+|\d+)\s*:'
)

# memset pattern: memset(var, 0, SIZE) — reveals allocation size for zero-init
_RE_MEMSET = re.compile(
    r'memset\s*\(\s*(\w+)\s*,\s*0\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'
)


# ---------------------------------------------------------------------------
# Allocator discovery
# ---------------------------------------------------------------------------

def _find_allocator_functions():
    """Locate all allocator functions in the binary by name matching.

    Returns a dict mapping allocator EA -> (name, alloc_type) where
    alloc_type is one of: "new", "new[]", "custom", "pool".
    """
    allocators = {}

    # Scan all named functions
    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if not name:
            continue

        # Standard operator new / new[]
        if name in _OPERATOR_NEW_NAMES:
            is_array = "[]" in name or "_U@" in name
            alloc_type = "new[]" if is_array else "new"
            allocators[ea] = (name, alloc_type)
            continue

        # Custom Blizzard allocators
        for custom_name in _CUSTOM_ALLOCATOR_NAMES:
            if custom_name.lower() in name.lower():
                allocators[ea] = (name, "custom")
                break
        else:
            # Pool allocator patterns
            for substr in _POOL_ALLOCATOR_SUBSTRINGS:
                if substr.lower() in name.lower():
                    allocators[ea] = (name, "pool")
                    break

    # Also check imports
    for i in range(idaapi.get_import_module_qty()):
        def _import_cb(ea, name, ordinal):
            if name:
                if name in _OPERATOR_NEW_NAMES:
                    is_array = "[]" in name or "_U@" in name
                    allocators[ea] = (name, "new[]" if is_array else "new")
                for custom_name in _CUSTOM_ALLOCATOR_NAMES:
                    if custom_name.lower() in name.lower():
                        allocators[ea] = (name, "custom")
            return True
        idaapi.enum_import_names(i, _import_cb)

    return allocators


def _find_delete_functions():
    """Locate all deallocation functions (operator delete, free, etc.).

    Returns a set of function EAs.
    """
    deleters = set()

    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if not name:
            continue
        if name in _OPERATOR_DELETE_NAMES:
            deleters.add(ea)
            continue
        lower = name.lower()
        if "operator_delete" in lower or "free" in lower:
            deleters.add(ea)

    return deleters


# ---------------------------------------------------------------------------
# Allocation site extraction (binary-level, via xrefs)
# ---------------------------------------------------------------------------

def _collect_alloc_sites_binary(allocators):
    """For each allocator function, find all call sites and extract the SIZE
    argument from the binary (RCX register on x64 before the call).

    Returns a list of dicts: {caller_ea, alloc_ea, alloc_size, alloc_type,
    caller_func_ea, caller_func_name}
    """
    alloc_sites = []

    for alloc_ea, (alloc_name, alloc_type) in allocators.items():
        xref_count = 0
        for xref in idautils.XrefsTo(alloc_ea, 0):
            if xref.type not in (idaapi.fl_CN, idaapi.fl_CF,
                                 idaapi.fl_JN, idaapi.fl_JF):
                continue

            xref_count += 1
            if xref_count > _MAX_XREFS_PER_ALLOC:
                msg_warn(f"Truncating xrefs for {alloc_name} at {_MAX_XREFS_PER_ALLOC}")
                break

            caller_ea = xref.frm
            caller_func = ida_funcs.get_func(caller_ea)
            if not caller_func:
                continue

            caller_func_ea = caller_func.start_ea
            caller_func_name = ida_name.get_name(caller_func_ea) or f"sub_{caller_func_ea:X}"

            # Try to extract the size argument (RCX on x64) by scanning
            # backwards from the call instruction for a MOV RCX, imm
            alloc_size = _extract_size_arg_binary(caller_ea)

            alloc_sites.append({
                "caller_ea": caller_ea,
                "alloc_ea": alloc_ea,
                "alloc_size": alloc_size,
                "alloc_type": alloc_type,
                "alloc_name": alloc_name,
                "caller_func_ea": caller_func_ea,
                "caller_func_name": caller_func_name,
            })

    return alloc_sites


def _extract_size_arg_binary(call_ea):
    """Scan backwards from a call instruction to find the size argument.

    On x64 Windows, the first argument is passed in RCX.  We look for:
      MOV  ECX, imm32    (size fits in 32 bits — common)
      MOV  RCX, imm64    (large allocations)
      LEA  RCX, [rsp+...]  (dynamic — cannot resolve statically)

    Returns the integer size, or None if not resolvable.
    """
    # Scan up to 20 instructions backwards
    ea = call_ea
    for _ in range(20):
        ea = idc.prev_head(ea, ea - 0x100)
        if ea == idaapi.BADADDR:
            break

        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue

        # Check for MOV ECX/RCX, immediate
        if mnem.upper() in ("MOV", "LEA"):
            op0_type = idc.get_operand_type(ea, 0)
            op0_value = idc.get_operand_value(ea, 0)

            # RCX = register 1, ECX = register 1 (same logical register)
            # In IDA's internal numbering: ECX=1, RCX=1
            if op0_type == idc.o_reg and op0_value == 1:  # ECX/RCX
                op1_type = idc.get_operand_type(ea, 1)
                if op1_type == idc.o_imm:
                    size_val = idc.get_operand_value(ea, 1)
                    if 0 < size_val < 0x1000000:  # sanity: up to 16MB
                        return size_val

        # If we hit another CALL or a label, stop scanning
        if mnem.upper() == "CALL":
            break
        # If we see an instruction that writes to RCX with non-immediate, stop
        if mnem.upper() in ("MOV", "LEA", "XOR", "ADD", "SUB"):
            op0_type = idc.get_operand_type(ea, 0)
            op0_value = idc.get_operand_value(ea, 0)
            if op0_type == idc.o_reg and op0_value == 1:
                # RCX is being set to something non-immediate
                op1_type = idc.get_operand_type(ea, 1)
                if op1_type != idc.o_imm:
                    return None  # dynamic size

    return None


# ---------------------------------------------------------------------------
# Pseudocode-level analysis
# ---------------------------------------------------------------------------

def _analyze_function_pseudocode(func_ea, func_name):
    """Decompile a function and extract allocation patterns, constructor
    calls, vtable assignments, and destructor calls from pseudocode.

    Returns a dict with keys:
      allocations: [{variable, size, type, line_num, alloc_call}]
      constructors: [{variable, constructor_name, constructor_ea_str, line_num}]
      vtable_writes: [{variable, vtable_ea, offset, class_name, line_num}]
      destructors: [{variable, destructor_name, line_num}]
      delete_calls: [{variable, line_num}]
      switch_cases: [case_value, ...]
      memsets: [{variable, size, line_num}]
    """
    pseudocode = get_decompiled_text(func_ea)
    if not pseudocode:
        return None

    lines = pseudocode.split("\n")
    if len(lines) > _MAX_PSEUDOCODE_LINES:
        lines = lines[:_MAX_PSEUDOCODE_LINES]

    allocations = []
    constructors = []
    vtable_writes = []
    destructors = []
    delete_calls = []
    switch_cases = []
    memsets = []

    for line_num, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        # --- Allocations ---
        for m in _RE_OP_NEW.finditer(stripped):
            var_name = m.group(1)
            size_str = m.group(2)
            size_val = int(size_str, 16) if size_str.startswith("0x") else int(size_str)
            allocations.append({
                "variable": var_name,
                "size": size_val,
                "type": "new",
                "line_num": line_num,
                "alloc_call": stripped,
            })

        for m in _RE_OP_NEW_ARRAY.finditer(stripped):
            var_name = m.group(1)
            size_str = m.group(2)
            size_val = int(size_str, 16) if size_str.startswith("0x") else int(size_str)
            allocations.append({
                "variable": var_name,
                "size": size_val,
                "type": "new[]",
                "line_num": line_num,
                "alloc_call": stripped,
            })

        for m in _RE_CUSTOM_ALLOC.finditer(stripped):
            var_name = m.group(1)
            alloc_func = m.group(2)
            size_str = m.group(3)
            size_val = int(size_str, 16) if size_str.startswith("0x") else int(size_str)
            allocations.append({
                "variable": var_name,
                "size": size_val,
                "type": f"custom:{alloc_func}",
                "line_num": line_num,
                "alloc_call": stripped,
            })

        # --- Vtable assignments ---
        for m in _RE_VTABLE_ASSIGN.finditer(stripped):
            var_name = m.group(1)
            off_addr = m.group(2)
            class_name = m.group(3)
            vtable_ea_val = None
            if off_addr:
                vtable_ea_val = int(off_addr, 16)
            vtable_writes.append({
                "variable": var_name,
                "vtable_ea": vtable_ea_val,
                "offset": 0,
                "class_name": class_name,
                "line_num": line_num,
            })

        for m in _RE_VTABLE_LITERAL.finditer(stripped):
            var_name = m.group(1)
            addr_str = m.group(2)
            vtable_ea_val = int(addr_str, 16)
            vtable_writes.append({
                "variable": var_name,
                "vtable_ea": vtable_ea_val,
                "offset": 0,
                "class_name": None,
                "line_num": line_num,
            })

        for m in _RE_VTABLE_OFFSET_ASSIGN.finditer(stripped):
            var_name = m.group(1)
            offset_str = m.group(2)
            offset_val = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
            off_addr = m.group(3)
            class_name = m.group(4)
            literal_addr = m.group(5)
            vtable_ea_val = None
            if off_addr:
                vtable_ea_val = int(off_addr, 16)
            elif literal_addr:
                vtable_ea_val = int(literal_addr, 16)
            vtable_writes.append({
                "variable": var_name,
                "vtable_ea": vtable_ea_val,
                "offset": offset_val,
                "class_name": class_name,
                "line_num": line_num,
            })

        # --- Constructor calls (must follow allocation) ---
        for m in _RE_CTOR_CALL.finditer(stripped):
            ctor_name = m.group(1)
            var_name = m.group(2)
            # Skip if this is the allocation call itself
            if "operator" in ctor_name.lower() or "alloc" in ctor_name.lower():
                continue
            constructors.append({
                "variable": var_name,
                "constructor_name": ctor_name,
                "constructor_ea_str": ctor_name,
                "line_num": line_num,
            })

        # --- Destructor calls ---
        for m in _RE_DTOR_CALL.finditer(stripped):
            if m.group(1):
                dtor_name = f"{m.group(1)}::~{m.group(2)}"
                var_name = m.group(3)
            else:
                dtor_name = f"~{m.group(5)}"
                var_name = m.group(4)
            destructors.append({
                "variable": var_name,
                "destructor_name": dtor_name,
                "line_num": line_num,
            })

        # --- Delete calls ---
        for m in _RE_OP_DELETE.finditer(stripped):
            var_name = m.group(1)
            delete_calls.append({
                "variable": var_name,
                "line_num": line_num,
            })

        # --- Switch cases ---
        for m in _RE_SWITCH_CASE.finditer(stripped):
            case_str = m.group(1)
            case_val = int(case_str, 16) if case_str.startswith("0x") else int(case_str)
            switch_cases.append(case_val)

        # --- Memset (reveals allocation size for zero-init) ---
        for m in _RE_MEMSET.finditer(stripped):
            var_name = m.group(1)
            size_str = m.group(2)
            size_val = int(size_str, 16) if size_str.startswith("0x") else int(size_str)
            memsets.append({
                "variable": var_name,
                "size": size_val,
                "line_num": line_num,
            })

    return {
        "allocations": allocations,
        "constructors": constructors,
        "vtable_writes": vtable_writes,
        "destructors": destructors,
        "delete_calls": delete_calls,
        "switch_cases": switch_cases,
        "memsets": memsets,
    }


# ---------------------------------------------------------------------------
# Constructor / vtable linking
# ---------------------------------------------------------------------------

def _link_allocations_to_constructors(pseudo_data):
    """For each allocation, find the constructor call that receives the
    allocated pointer (the first function call where the allocation variable
    is the first argument, after the allocation line).

    Returns a list of linked entries:
    {variable, size, alloc_type, constructor_name, constructor_line,
     vtable_ea, vtable_class_name, vtable_offsets}
    """
    if not pseudo_data:
        return []

    allocs = pseudo_data["allocations"]
    ctors = pseudo_data["constructors"]
    vt_writes = pseudo_data["vtable_writes"]
    memset_info = pseudo_data["memsets"]

    linked = []

    for alloc in allocs:
        var = alloc["variable"]
        alloc_line = alloc["line_num"]
        size = alloc["size"]

        entry = {
            "variable": var,
            "size": size,
            "alloc_type": alloc["type"],
            "alloc_line": alloc_line,
            "constructor_name": None,
            "constructor_line": None,
            "vtable_ea": None,
            "vtable_class_name": None,
            "vtable_offsets": [],
            "memset_size": None,
        }

        # Find the earliest constructor call to this variable after allocation
        best_ctor = None
        best_line = float("inf")
        for ctor in ctors:
            if ctor["variable"] == var and ctor["line_num"] > alloc_line:
                if ctor["line_num"] < best_line:
                    best_line = ctor["line_num"]
                    best_ctor = ctor
        if best_ctor:
            entry["constructor_name"] = best_ctor["constructor_name"]
            entry["constructor_line"] = best_ctor["line_num"]

        # Find vtable writes to this variable (or within the constructor scope)
        # We look for vtable writes to the same variable name
        for vw in vt_writes:
            if vw["variable"] == var or (
                best_ctor and vw["line_num"] >= alloc_line
            ):
                if vw["offset"] == 0 and entry["vtable_ea"] is None:
                    entry["vtable_ea"] = vw["vtable_ea"]
                    entry["vtable_class_name"] = vw["class_name"]
                if vw["offset"] > 0:
                    entry["vtable_offsets"].append({
                        "offset": vw["offset"],
                        "vtable_ea": vw["vtable_ea"],
                        "class_name": vw["class_name"],
                    })

        # Check for memset that confirms size
        for ms in memset_info:
            if ms["variable"] == var and ms["line_num"] >= alloc_line:
                entry["memset_size"] = ms["size"]
                break

        linked.append(entry)

    return linked


def _resolve_constructor_ea(ctor_name):
    """Resolve a constructor name (sub_XXXX or ClassName::ClassName) to an EA.

    Returns the EA, or None.
    """
    if ctor_name.startswith("sub_"):
        try:
            return int(ctor_name[4:], 16)
        except ValueError:
            return None

    # Try finding by name
    ea = ida_name.get_name_ea(idaapi.BADADDR, ctor_name)
    if ea != idaapi.BADADDR:
        return ea

    return None


# ---------------------------------------------------------------------------
# RTTI scanning (limited — WoW compiled with /GR-)
# ---------------------------------------------------------------------------

def _scan_rtti_near_vtable(vtable_ea):
    """Check for RTTI Complete Object Locator (COL) at vtable[-1].

    WoW is compiled with /GR- so game classes have no RTTI, but some
    CRT/STL classes might.  The COL is stored at vtable_ea - 8 on x64.

    Returns the class name if RTTI is found, else None.
    """
    if vtable_ea is None or vtable_ea == 0:
        return None

    try:
        # On x64, the COL pointer is at vtable_ea - 8
        col_ptr = ida_bytes.get_qword(vtable_ea - 8)
        if col_ptr == 0 or col_ptr == idaapi.BADADDR:
            return None

        # Validate COL signature field (should be 0 for 32-bit or 1 for x64)
        sig = ida_bytes.get_dword(col_ptr)
        if sig not in (0, 1):
            return None

        # Read type descriptor offset (at COL + 12 on x64 COL v1)
        # COL layout: signature(4), offset(4), cdOffset(4), typeDescriptorRVA(4), ...
        if sig == 1:  # x64 with RVA-based pointers
            # Need image base to resolve RVAs in COL
            image_base = idaapi.get_imagebase()
            td_rva = ida_bytes.get_dword(col_ptr + 12)
            td_ea = image_base + td_rva

            # TypeDescriptor starts with: void* pVFTable, void* spare, char name[]
            # name is at offset 16 on x64
            name_ea = td_ea + 16
            rtti_name = idc.get_strlit_contents(name_ea, -1, idc.STRTYPE_C)
            if rtti_name:
                return _demangle_rtti_name(rtti_name.decode("utf-8", errors="replace"))
        else:
            # 32-bit absolute pointer mode (unlikely in x64 WoW)
            td_ptr = ida_bytes.get_qword(col_ptr + 16)
            if td_ptr and td_ptr != idaapi.BADADDR:
                name_ea = td_ptr + 16
                rtti_name = idc.get_strlit_contents(name_ea, -1, idc.STRTYPE_C)
                if rtti_name:
                    return _demangle_rtti_name(rtti_name.decode("utf-8", errors="replace"))
    except Exception:
        pass

    return None


def _demangle_rtti_name(raw_name):
    """Convert MSVC RTTI encoded name to a readable class name.

    RTTI names start with '.?AV' (class) or '.?AU' (struct):
      .?AVClassName@@    -> ClassName
      .?AVNamespace@ClassName@@  -> Namespace::ClassName
    """
    if not raw_name:
        return None

    # Strip leading '.' and '?'
    name = raw_name.lstrip(".?")

    # Remove type prefix: AV (class), AU (struct), AT (union)
    if name[:2] in ("AV", "AU", "AT"):
        name = name[2:]
    elif name[:1] in ("V", "U", "T"):
        name = name[1:]

    # Strip trailing @@ and reconstruct namespace
    name = name.rstrip("@")
    parts = [p for p in name.split("@") if p]

    if not parts:
        return None

    # MSVC stores innermost name first, then enclosing namespaces
    parts.reverse()
    return "::".join(parts)


# ---------------------------------------------------------------------------
# Vtable slot counting and analysis
# ---------------------------------------------------------------------------

def _count_vtable_slots(vtable_ea):
    """Count the number of virtual function slots in a vtable.

    A vtable is a contiguous array of function pointers in .rdata.
    We stop at the first non-function-pointer QWORD.

    Returns (slot_count, slot_eas[]).
    """
    if vtable_ea is None or vtable_ea == 0:
        return 0, []

    slots = []
    ea = vtable_ea

    for i in range(1024):  # safety limit
        try:
            ptr = ida_bytes.get_qword(ea)
        except Exception:
            break

        if ptr == 0 or ptr == idaapi.BADADDR:
            break

        # Check if the pointer targets a function
        func = ida_funcs.get_func(ptr)
        if not func:
            # Could be a thunk or imported function — check if it's in a code segment
            seg = idaapi.getseg(ptr)
            if not seg or not (seg.perm & 1):  # not executable
                break

        slots.append(ptr)
        ea += 8  # x64 pointer size

    return len(slots), slots


def _get_destructor_from_vtable(vtable_ea):
    """Virtual destructor is typically vtable slot 0 on MSVC.

    Returns the destructor EA, or None.
    """
    if vtable_ea is None or vtable_ea == 0:
        return None

    try:
        dtor_ptr = ida_bytes.get_qword(vtable_ea)
        if dtor_ptr and dtor_ptr != idaapi.BADADDR:
            func = ida_funcs.get_func(dtor_ptr)
            if func:
                return dtor_ptr
    except Exception:
        pass

    return None


# ---------------------------------------------------------------------------
# Inheritance detection
# ---------------------------------------------------------------------------

def _detect_inheritance_from_constructors(linked_entries, pseudo_cache):
    """Detect inheritance by analyzing constructor call chains.

    If constructor C1 calls constructor C2 at offset 0 of 'this', then the
    class owning C1 inherits from the class owning C2.

    Also detects multiple inheritance: a constructor that writes vtable
    pointers at multiple offsets.

    Returns a list of {derived, base, offset} relationships.
    """
    relationships = []
    seen = set()

    for entry in linked_entries:
        ctor_name = entry.get("constructor_name")
        if not ctor_name:
            continue

        ctor_ea = _resolve_constructor_ea(ctor_name)
        if not ctor_ea:
            continue

        # Get or decompile the constructor
        ctor_key = f"ctor_{ctor_ea:X}"
        if ctor_key in pseudo_cache:
            ctor_pseudo = pseudo_cache[ctor_key]
        else:
            ctor_pseudo = _analyze_function_pseudocode(ctor_ea, ctor_name)
            pseudo_cache[ctor_key] = ctor_pseudo

        if not ctor_pseudo:
            continue

        derived_class = entry.get("vtable_class_name") or ctor_name
        derived_size = entry.get("size", 0)

        # Look for constructor calls within this constructor that pass 'this'
        # as first argument (typically a1 in constructors)
        for ctor_call in ctor_pseudo["constructors"]:
            var = ctor_call["variable"]
            # In a constructor, first param is 'this' (a1, this, or result)
            if var not in ("a1", "this", "result", "v1"):
                continue

            base_ctor_name = ctor_call["constructor_name"]
            if base_ctor_name == ctor_name:
                continue  # skip recursive (shouldn't happen)

            # This is a base class constructor call
            rel_key = (derived_class, base_ctor_name)
            if rel_key not in seen:
                seen.add(rel_key)
                relationships.append({
                    "derived": derived_class,
                    "base": base_ctor_name,
                    "offset": 0,
                    "derived_size": derived_size,
                })

        # Multiple inheritance: vtable writes at non-zero offsets
        for vt_off in entry.get("vtable_offsets", []):
            offset = vt_off["offset"]
            base_class = vt_off.get("class_name") or f"vtable_{vt_off.get('vtable_ea', 0):X}"
            rel_key = (derived_class, base_class, offset)
            if rel_key not in seen:
                seen.add(rel_key)
                relationships.append({
                    "derived": derived_class,
                    "base": base_class,
                    "offset": offset,
                    "derived_size": derived_size,
                })

    return relationships


def _build_inheritance_tree(relationships):
    """Build a hierarchical inheritance tree from flat relationships.

    Returns a list of {parent, children} dicts forming a forest.
    """
    children_of = defaultdict(set)
    all_classes = set()

    for rel in relationships:
        parent = rel["base"]
        child = rel["derived"]
        children_of[parent].add(child)
        all_classes.add(parent)
        all_classes.add(child)

    # Find roots (classes that are never a child)
    all_children = set()
    for kids in children_of.values():
        all_children.update(kids)
    roots = all_classes - all_children

    tree = []
    for root in sorted(roots):
        tree.append({
            "parent": root,
            "children": sorted(children_of.get(root, set())),
        })

    # Also include intermediate nodes that have children
    for parent in sorted(all_classes - roots):
        kids = children_of.get(parent, set())
        if kids:
            tree.append({
                "parent": parent,
                "children": sorted(kids),
            })

    return tree


# ---------------------------------------------------------------------------
# Factory function detection
# ---------------------------------------------------------------------------

def _detect_factory_functions(alloc_sites, pseudo_cache):
    """Find functions that call multiple different new(size) + constructor
    combos — these are factory functions.

    Factory patterns:
      - Switch statement selecting different class constructors
      - If/else chains with different allocation sizes
      - Functions creating 3+ different object types

    Returns a list of factory descriptors.
    """
    # Group allocation sites by caller function
    func_allocs = defaultdict(list)
    for site in alloc_sites:
        func_allocs[site["caller_func_ea"]].append(site)

    factories = []

    for func_ea, sites in func_allocs.items():
        # A factory creates at least 2 different class types
        unique_sizes = set()
        for s in sites:
            if s["alloc_size"] is not None:
                unique_sizes.add(s["alloc_size"])

        if len(unique_sizes) < 2:
            continue

        func_name = sites[0]["caller_func_name"]

        # Decompile to check for switch statements
        cache_key = f"factory_{func_ea:X}"
        if cache_key in pseudo_cache:
            pseudo_data = pseudo_cache[cache_key]
        else:
            pseudo_data = _analyze_function_pseudocode(func_ea, func_name)
            pseudo_cache[cache_key] = pseudo_data

        has_switch = bool(pseudo_data and pseudo_data["switch_cases"])

        # Link allocations to their constructors
        linked = []
        if pseudo_data:
            linked = _link_allocations_to_constructors(pseudo_data)

        classes_created = []
        for link in linked:
            classes_created.append({
                "size": link["size"],
                "constructor": link.get("constructor_name"),
                "vtable_ea": link.get("vtable_ea"),
                "class_name": link.get("vtable_class_name"),
            })

        # Deduplicate by size
        seen_sizes = set()
        deduped = []
        for cc in classes_created:
            if cc["size"] not in seen_sizes:
                seen_sizes.add(cc["size"])
                deduped.append(cc)

        if len(deduped) < 2:
            continue

        factories.append({
            "ea": func_ea,
            "function_name": func_name,
            "class_count": len(deduped),
            "classes_created": deduped,
            "has_switch": has_switch,
            "switch_case_count": len(pseudo_data["switch_cases"]) if pseudo_data else 0,
        })

    return factories


# ---------------------------------------------------------------------------
# TC source comparison
# ---------------------------------------------------------------------------

def _scan_tc_source_for_sizes(tc_source_dir):
    """Scan TrinityCore source tree for sizeof(ClassName) and class
    declarations to extract known class sizes.

    Returns a dict mapping class_name -> estimated_size.
    """
    import os

    if not tc_source_dir or not os.path.isdir(tc_source_dir):
        return {}

    sizes = dict(_TC_CLASS_SIZES)  # start with known defaults

    # Patterns to extract from TC headers
    # Look for: static_assert(sizeof(ClassName) == SIZE)
    sizeof_re = re.compile(
        r'static_assert\s*\(\s*sizeof\s*\(\s*(\w+)\s*\)\s*'
        r'(?:==|<=)\s*(0x[0-9A-Fa-f]+|\d+)',
        re.IGNORECASE
    )

    # Also look for: // sizeof = 0xNNN comments
    sizeof_comment_re = re.compile(
        r'(?:class|struct)\s+(\w+)\b.*?//.*?sizeof\s*[=:]\s*(0x[0-9A-Fa-f]+|\d+)',
        re.IGNORECASE
    )

    # Walk source tree
    search_dirs = [
        os.path.join(tc_source_dir, "src", "server", "game"),
        os.path.join(tc_source_dir, "src", "server", "shared"),
        os.path.join(tc_source_dir, "src", "common"),
    ]

    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for root, _dirs, files in os.walk(search_dir):
            for fname in files:
                if not fname.endswith((".h", ".hpp", ".cpp")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except Exception:
                    continue

                for m in sizeof_re.finditer(content):
                    cls = m.group(1)
                    val_str = m.group(2)
                    val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
                    sizes[cls] = val

                for m in sizeof_comment_re.finditer(content):
                    cls = m.group(1)
                    val_str = m.group(2)
                    val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
                    if cls not in sizes:  # don't override static_assert
                        sizes[cls] = val

    return sizes


def _compare_sizes(catalog_classes, tc_sizes):
    """Compare binary class sizes against TC class sizes.

    Returns a list of mismatches.
    """
    mismatches = []

    for cls_entry in catalog_classes:
        name = cls_entry.get("name")
        binary_size = cls_entry.get("size")

        if not name or not binary_size:
            continue

        # Try exact match first, then strip namespaces
        tc_size = tc_sizes.get(name)
        if tc_size is None:
            # Try stripping namespace
            short_name = name.split("::")[-1] if "::" in name else name
            tc_size = tc_sizes.get(short_name)

        if tc_size is not None:
            cls_entry["tc_size_match"] = (binary_size == tc_size)
            if binary_size != tc_size:
                mismatches.append({
                    "class_name": name,
                    "binary_size": binary_size,
                    "tc_size": tc_size,
                    "diff": binary_size - tc_size,
                })
        else:
            cls_entry["tc_size_match"] = None

    return mismatches


# ---------------------------------------------------------------------------
# Class name resolution
# ---------------------------------------------------------------------------

def _resolve_class_name(vtable_ea, vtable_class_name, ctor_name, rtti_name,
                        vtable_db):
    """Determine the best class name from available sources.

    Priority: RTTI > vtable DB > vtable class name from pseudocode >
              constructor name > generic name from vtable EA.
    """
    if rtti_name:
        return rtti_name

    # Check vtable database from previous analysis
    if vtable_ea and vtable_db:
        db_entry = vtable_db.get(vtable_ea)
        if db_entry and db_entry.get("class_name"):
            return db_entry["class_name"]

    if vtable_class_name:
        return vtable_class_name

    if ctor_name:
        # Try to extract class name from constructor name
        if "::" in ctor_name:
            parts = ctor_name.split("::")
            # ClassName::ClassName pattern
            if len(parts) == 2 and parts[0] == parts[1]:
                return parts[0]
            return parts[0]
        if ctor_name.startswith("sub_"):
            return f"Class_{ctor_name[4:]}"
        return ctor_name

    if vtable_ea:
        return f"VClass_{vtable_ea:X}"

    return None


# ---------------------------------------------------------------------------
# vtable DB loading
# ---------------------------------------------------------------------------

def _load_vtable_db(session):
    """Load existing vtable data from the knowledge DB.

    Returns a dict mapping vtable_ea -> {class_name, entry_count, ...}.
    """
    db = session.db
    vtable_map = {}

    try:
        rows = db.fetchall("SELECT ea, class_name, entry_count, parent_class FROM vtables")
        for row in rows:
            vtable_map[row["ea"]] = {
                "class_name": row["class_name"],
                "entry_count": row["entry_count"],
                "parent_class": row["parent_class"],
            }
    except Exception:
        pass

    # Also try kv_store "vtables" key (from importer)
    kv_vtables = db.kv_get("vtables")
    if isinstance(kv_vtables, dict):
        for ea_str_key, info in kv_vtables.items():
            try:
                ea_int = int(ea_str_key, 16) if isinstance(ea_str_key, str) else ea_str_key
                if ea_int not in vtable_map:
                    vtable_map[ea_int] = info
            except (ValueError, TypeError):
                pass

    return vtable_map


# ---------------------------------------------------------------------------
# Main catalog builder
# ---------------------------------------------------------------------------

def build_class_catalog(session):
    """Build a complete class catalog from allocation sites.

    Main entry point for the analyzer.  Discovers every operator new(size)
    call in the binary, links each to its constructor, extracts vtable
    assignments, checks for RTTI, detects inheritance and factory patterns,
    and compares against TrinityCore class sizes.

    Results are stored in session.db.kv_set("class_catalog", {...}).

    Args:
        session: PluginSession with .db and .cfg attributes.

    Returns:
        Number of classes cataloged.
    """
    db = session.db
    cfg = session.cfg
    start_time = time.time()

    msg_info("=" * 60)
    msg_info("Building Allocation-Based Class Catalog")
    msg_info("=" * 60)

    # ── Step 1: Discover allocator functions ──────────────────────────
    msg_info("Step 1/8: Discovering allocator functions...")
    allocators = _find_allocator_functions()
    if not allocators:
        msg_error("No allocator functions found in the binary!")
        msg_warn("Ensure the binary has operator new / SMemAlloc symbols.")
        return 0

    alloc_by_type = defaultdict(int)
    for _, (_, atype) in allocators.items():
        alloc_by_type[atype] += 1
    for atype, count in sorted(alloc_by_type.items()):
        msg(f"  Found {count} '{atype}' allocator(s)")
    msg_info(f"  Total: {len(allocators)} allocator functions")

    # ── Step 2: Collect allocation call sites (binary level) ─────────
    msg_info("Step 2/8: Collecting allocation call sites from xrefs...")
    alloc_sites = _collect_alloc_sites_binary(allocators)

    resolved = sum(1 for s in alloc_sites if s["alloc_size"] is not None)
    msg_info(f"  Found {len(alloc_sites)} allocation sites "
             f"({resolved} with resolved sizes)")

    # ── Step 3: Discover delete functions ─────────────────────────────
    msg_info("Step 3/8: Discovering deallocation functions...")
    delete_funcs = _find_delete_functions()
    msg_info(f"  Found {len(delete_funcs)} deallocation functions")

    # ── Step 4: Load existing vtable data ─────────────────────────────
    msg_info("Step 4/8: Loading vtable database...")
    vtable_db = _load_vtable_db(session)
    msg_info(f"  Loaded {len(vtable_db)} known vtables")

    # ── Step 5: Decompile and analyze key functions ───────────────────
    msg_info("Step 5/8: Analyzing allocation-containing functions (decompilation)...")

    # Group alloc sites by caller function to avoid duplicate decompilation
    funcs_to_analyze = defaultdict(list)
    for site in alloc_sites:
        if site["alloc_size"] is not None and site["alloc_size"] > 0:
            funcs_to_analyze[site["caller_func_ea"]].append(site)

    msg_info(f"  {len(funcs_to_analyze)} unique functions to decompile...")

    pseudo_cache = {}
    all_linked = []
    func_count = 0
    fail_count = 0

    for func_ea, sites in funcs_to_analyze.items():
        func_count += 1
        if func_count % _PROGRESS_INTERVAL == 0:
            msg(f"  ... decompiled {func_count}/{len(funcs_to_analyze)} functions")

        func_name = sites[0]["caller_func_name"]
        cache_key = f"func_{func_ea:X}"

        if cache_key not in pseudo_cache:
            pseudo_data = _analyze_function_pseudocode(func_ea, func_name)
            pseudo_cache[cache_key] = pseudo_data
        else:
            pseudo_data = pseudo_cache[cache_key]

        if not pseudo_data:
            fail_count += 1
            continue

        linked = _link_allocations_to_constructors(pseudo_data)
        for entry in linked:
            entry["caller_func_ea"] = func_ea
            entry["caller_func_name"] = func_name
        all_linked.extend(linked)

    msg_info(f"  Decompiled {func_count} functions ({fail_count} failures)")
    msg_info(f"  Linked {len(all_linked)} allocation-to-constructor pairs")

    # ── Step 6: Resolve class identities ──────────────────────────────
    msg_info("Step 6/8: Resolving class identities (RTTI + vtable cross-ref)...")

    # Build the class catalog entries
    # Key by (size, vtable_ea) to deduplicate
    catalog_key_map = {}  # (size, vtable_ea) -> catalog entry
    rtti_found = 0

    for entry in all_linked:
        size = entry["size"]
        vtable_ea = entry.get("vtable_ea")

        # Check RTTI near vtable
        rtti_name = None
        if vtable_ea:
            rtti_name = _scan_rtti_near_vtable(vtable_ea)
            if rtti_name:
                rtti_found += 1

        # Resolve best class name
        class_name = _resolve_class_name(
            vtable_ea,
            entry.get("vtable_class_name"),
            entry.get("constructor_name"),
            rtti_name,
            vtable_db,
        )

        if not class_name:
            class_name = f"UnknownClass_size_{size:X}"

        # Constructor EA
        ctor_ea = _resolve_constructor_ea(entry.get("constructor_name"))

        # Vtable slot count
        slot_count = 0
        slot_eas = []
        if vtable_ea:
            slot_count, slot_eas = _count_vtable_slots(vtable_ea)

        # Destructor from vtable
        dtor_ea = None
        if vtable_ea:
            dtor_ea = _get_destructor_from_vtable(vtable_ea)

        # Estimate field count from size (rough: size / avg_field_size)
        # Subtract vtable pointer (8 bytes) and estimate 4-8 bytes per field
        effective_size = max(0, size - 8) if vtable_ea else size
        field_count_estimate = max(1, effective_size // 6)  # average 6 bytes per field

        catalog_key = (size, vtable_ea or 0)
        if catalog_key in catalog_key_map:
            # Merge: prefer named class, keep more data
            existing = catalog_key_map[catalog_key]
            if class_name and not existing["name"].startswith("UnknownClass"):
                pass  # keep existing named entry
            elif not existing["name"].startswith("UnknownClass"):
                continue  # existing is better
            else:
                existing["name"] = class_name
            # Accumulate constructor locations
            if ctor_ea and ctor_ea not in existing.get("_ctor_eas", set()):
                existing.setdefault("_ctor_eas", set()).add(ctor_ea)
            existing["alloc_site_count"] = existing.get("alloc_site_count", 1) + 1
            continue

        catalog_key_map[catalog_key] = {
            "name": class_name,
            "size": size,
            "vtable_ea": vtable_ea,
            "constructor_ea": ctor_ea,
            "destructor_ea": dtor_ea,
            "base_classes": [],
            "vtable_slot_count": slot_count,
            "factory_function_ea": None,
            "tc_size_match": None,
            "field_count_estimate": field_count_estimate,
            "rtti_name": rtti_name,
            "alloc_type": entry.get("alloc_type"),
            "alloc_site_count": 1,
            "multiple_inheritance": len(entry.get("vtable_offsets", [])) > 0,
            "secondary_vtables": entry.get("vtable_offsets", []),
            "_ctor_eas": {ctor_ea} if ctor_ea else set(),
        }

    msg_info(f"  Resolved {len(catalog_key_map)} unique class entries")
    msg_info(f"  RTTI found for {rtti_found} classes")

    # ── Step 7: Detect inheritance and factories ──────────────────────
    msg_info("Step 7/8: Detecting inheritance relationships and factory functions...")

    inheritance_rels = _detect_inheritance_from_constructors(all_linked, pseudo_cache)
    inheritance_tree = _build_inheritance_tree(inheritance_rels)

    # Apply inheritance info to catalog entries
    child_to_parents = defaultdict(list)
    for rel in inheritance_rels:
        child_to_parents[rel["derived"]].append(rel["base"])

    for entry in catalog_key_map.values():
        name = entry["name"]
        bases = child_to_parents.get(name, [])
        entry["base_classes"] = bases

    msg_info(f"  Detected {len(inheritance_rels)} inheritance relationships")
    msg_info(f"  Inheritance tree has {len(inheritance_tree)} root/intermediate nodes")

    # Factory detection
    factories = _detect_factory_functions(alloc_sites, pseudo_cache)
    msg_info(f"  Detected {len(factories)} factory functions")

    # Link factory functions to catalog entries
    for factory in factories:
        for cls_created in factory["classes_created"]:
            fsize = cls_created.get("size")
            fvt = cls_created.get("vtable_ea") or 0
            key = (fsize, fvt)
            if key in catalog_key_map:
                catalog_key_map[key]["factory_function_ea"] = factory["ea"]

    # ── Step 8: TC size comparison ────────────────────────────────────
    msg_info("Step 8/8: Comparing with TrinityCore class sizes...")

    tc_sizes = dict(_TC_CLASS_SIZES)
    if cfg.tc_source_dir:
        scanned = _scan_tc_source_for_sizes(cfg.tc_source_dir)
        tc_sizes.update(scanned)
        msg_info(f"  Loaded {len(scanned)} sizes from TC source tree")
    else:
        msg_warn("  No TC source dir configured — using built-in size estimates")

    # Finalize catalog entries — convert sets to lists, EAs to ints
    catalog_classes = []
    for entry in catalog_key_map.values():
        # Clean up internal tracking fields
        entry.pop("_ctor_eas", None)

        # Convert secondary vtable info to serializable form
        sec_vts = entry.pop("secondary_vtables", [])
        if sec_vts:
            entry["secondary_vtable_offsets"] = [
                {"offset": sv["offset"], "vtable_ea": sv.get("vtable_ea")}
                for sv in sec_vts
            ]

        catalog_classes.append(entry)

    # Sort by size descending (largest classes first)
    catalog_classes.sort(key=lambda c: (c.get("size") or 0), reverse=True)

    # TC comparison
    size_mismatches = _compare_sizes(catalog_classes, tc_sizes)
    if size_mismatches:
        msg_info(f"  Found {len(size_mismatches)} size mismatches with TC:")
        for mm in size_mismatches[:10]:
            direction = "larger" if mm["diff"] > 0 else "smaller"
            msg(f"    {mm['class_name']}: binary 0x{mm['binary_size']:X} "
                f"vs TC 0x{mm['tc_size']:X} ({direction} by {abs(mm['diff'])} bytes)")
        if len(size_mismatches) > 10:
            msg(f"    ... and {len(size_mismatches) - 10} more")

    # ── Build final result ────────────────────────────────────────────
    # Serialize EAs as hex strings for JSON compatibility
    def _serialize_ea(ea):
        if ea is None:
            return None
        return f"0x{ea:X}"

    serialized_classes = []
    for cls in catalog_classes:
        serialized_classes.append({
            "name": cls["name"],
            "size": cls["size"],
            "vtable_ea": _serialize_ea(cls.get("vtable_ea")),
            "constructor_ea": _serialize_ea(cls.get("constructor_ea")),
            "destructor_ea": _serialize_ea(cls.get("destructor_ea")),
            "base_classes": cls.get("base_classes", []),
            "vtable_slot_count": cls.get("vtable_slot_count", 0),
            "factory_function_ea": _serialize_ea(cls.get("factory_function_ea")),
            "tc_size_match": cls.get("tc_size_match"),
            "field_count_estimate": cls.get("field_count_estimate", 0),
            "rtti_name": cls.get("rtti_name"),
            "alloc_type": cls.get("alloc_type"),
            "alloc_site_count": cls.get("alloc_site_count", 1),
            "multiple_inheritance": cls.get("multiple_inheritance", False),
            "secondary_vtable_offsets": cls.get("secondary_vtable_offsets", []),
        })

    serialized_factories = []
    for fact in factories:
        serialized_factories.append({
            "ea": _serialize_ea(fact["ea"]),
            "function_name": fact["function_name"],
            "class_count": fact["class_count"],
            "classes_created": [
                {
                    "size": cc["size"],
                    "constructor": cc.get("constructor"),
                    "vtable_ea": _serialize_ea(cc.get("vtable_ea")),
                    "class_name": cc.get("class_name"),
                }
                for cc in fact["classes_created"]
            ],
            "has_switch": fact.get("has_switch", False),
            "switch_case_count": fact.get("switch_case_count", 0),
        })

    serialized_inheritance = []
    for node in inheritance_tree:
        serialized_inheritance.append({
            "parent": node["parent"],
            "children": node["children"],
        })

    serialized_mismatches = []
    for mm in size_mismatches:
        serialized_mismatches.append({
            "class_name": mm["class_name"],
            "binary_size": mm["binary_size"],
            "tc_size": mm["tc_size"],
            "diff": mm["diff"],
        })

    result = {
        "classes": serialized_classes,
        "inheritance_tree": serialized_inheritance,
        "factories": serialized_factories,
        "size_mismatches": serialized_mismatches,
        "total_classes": len(serialized_classes),
        "total_factories": len(serialized_factories),
        "total_alloc_sites": len(alloc_sites),
        "total_resolved_sizes": resolved,
        "total_inheritance_rels": len(inheritance_rels),
        "rtti_classes": rtti_found,
        "analysis_time_sec": round(time.time() - start_time, 1),
    }

    db.kv_set("class_catalog", result)
    db.commit()

    elapsed = time.time() - start_time
    msg_info("=" * 60)
    msg_info("Class Catalog Complete")
    msg_info(f"  Classes cataloged:    {result['total_classes']}")
    msg_info(f"  Allocation sites:     {result['total_alloc_sites']}")
    msg_info(f"  Resolved sizes:       {result['total_resolved_sizes']}")
    msg_info(f"  RTTI classes:         {result['rtti_classes']}")
    msg_info(f"  Inheritance rels:     {result['total_inheritance_rels']}")
    msg_info(f"  Factory functions:    {result['total_factories']}")
    msg_info(f"  TC size mismatches:   {len(result['size_mismatches'])}")
    msg_info(f"  Elapsed time:         {elapsed:.1f}s")
    msg_info("=" * 60)

    # Log top 20 largest classes
    msg("")
    msg("Top 20 largest classes:")
    for cls in serialized_classes[:20]:
        name = cls["name"]
        size = cls["size"]
        vt = cls.get("vtable_slot_count", 0)
        match_str = ""
        if cls.get("tc_size_match") is True:
            match_str = " [TC match]"
        elif cls.get("tc_size_match") is False:
            match_str = " [TC MISMATCH]"
        msg(f"  0x{size:06X} ({size:>8d} bytes) {name}  "
            f"({vt} vfuncs, {cls.get('alloc_site_count', 1)} alloc sites){match_str}")

    return result["total_classes"]


# ---------------------------------------------------------------------------
# Public helper: retrieve stored catalog
# ---------------------------------------------------------------------------

def get_class_catalog(session):
    """Retrieve the stored class catalog from the knowledge DB.

    Returns the catalog dict, or None if not yet built.
    """
    return session.db.kv_get("class_catalog")


def get_class_by_name(session, class_name):
    """Look up a single class by name (case-insensitive substring match).

    Returns the first matching class entry, or None.
    """
    catalog = get_class_catalog(session)
    if not catalog:
        return None

    lower = class_name.lower()
    for cls in catalog.get("classes", []):
        if lower in (cls.get("name") or "").lower():
            return cls

    return None


def get_class_by_size(session, size):
    """Find all classes with a given allocation size.

    Returns a list of matching class entries.
    """
    catalog = get_class_catalog(session)
    if not catalog:
        return []

    return [
        cls for cls in catalog.get("classes", [])
        if cls.get("size") == size
    ]


def get_class_by_vtable(session, vtable_ea):
    """Find a class by its vtable EA (accepts int or hex string).

    Returns the matching class entry, or None.
    """
    catalog = get_class_catalog(session)
    if not catalog:
        return None

    if isinstance(vtable_ea, int):
        vtable_ea = f"0x{vtable_ea:X}"

    for cls in catalog.get("classes", []):
        if cls.get("vtable_ea") == vtable_ea:
            return cls

    return None


def get_factories(session):
    """Retrieve discovered factory functions.

    Returns a list of factory descriptors, or [].
    """
    catalog = get_class_catalog(session)
    if not catalog:
        return []
    return catalog.get("factories", [])


def get_size_mismatches(session):
    """Retrieve binary-vs-TC size mismatches.

    Returns a list of mismatch dicts, or [].
    """
    catalog = get_class_catalog(session)
    if not catalog:
        return []
    return catalog.get("size_mismatches", [])


def get_inheritance_tree(session):
    """Retrieve the inheritance tree.

    Returns a list of {parent, children} nodes, or [].
    """
    catalog = get_class_catalog(session)
    if not catalog:
        return []
    return catalog.get("inheritance_tree", [])


def print_class_summary(session, class_name):
    """Print a human-readable summary for a class to the IDA output window.

    Args:
        session: PluginSession
        class_name: Full or partial class name to look up
    """
    cls = get_class_by_name(session, class_name)
    if not cls:
        msg_warn(f"Class '{class_name}' not found in catalog")
        return

    msg("")
    msg(f"=== {cls['name']} ===")
    msg(f"  Size:             0x{cls['size']:X} ({cls['size']} bytes)")
    msg(f"  VTable:           {cls.get('vtable_ea', 'N/A')}")
    msg(f"  VTable slots:     {cls.get('vtable_slot_count', 'N/A')}")
    msg(f"  Constructor:      {cls.get('constructor_ea', 'N/A')}")
    msg(f"  Destructor:       {cls.get('destructor_ea', 'N/A')}")
    msg(f"  Alloc type:       {cls.get('alloc_type', 'N/A')}")
    msg(f"  Alloc sites:      {cls.get('alloc_site_count', 'N/A')}")
    msg(f"  Field est:        ~{cls.get('field_count_estimate', 'N/A')}")
    msg(f"  Multi-inherit:    {cls.get('multiple_inheritance', False)}")

    bases = cls.get("base_classes", [])
    if bases:
        msg(f"  Base classes:     {', '.join(bases)}")

    if cls.get("rtti_name"):
        msg(f"  RTTI name:        {cls['rtti_name']}")

    match = cls.get("tc_size_match")
    if match is True:
        msg(f"  TC comparison:    MATCH")
    elif match is False:
        msg(f"  TC comparison:    MISMATCH")
    else:
        msg(f"  TC comparison:    N/A (class not in TC map)")

    factory_ea = cls.get("factory_function_ea")
    if factory_ea:
        msg(f"  Factory func:     {factory_ea}")

    sec_vts = cls.get("secondary_vtable_offsets", [])
    if sec_vts:
        msg(f"  Secondary vtables:")
        for sv in sec_vts:
            msg(f"    offset +0x{sv['offset']:X} -> {sv.get('vtable_ea', 'N/A')}")

    msg("")
