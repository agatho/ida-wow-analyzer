"""
Indirect Call Resolver for WoW x64 Binary

Resolves indirect calls (virtual dispatch, function pointers, CFG-guarded
jump tables) to their actual target sets.  Combines vtable slot analysis,
Control Flow Guard (CFG) table intersection, decompiler-assisted type
propagation, and function-pointer-table enumeration to produce a
per-callsite resolution with quality scoring.

Results are stored in the knowledge DB kv_store under key "indirect_calls".
"""

import json
import re
import time
from collections import defaultdict

import ida_funcs
import ida_name
import ida_bytes
import idautils
import idaapi
import idc
import ida_ua

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# x64 pointer size
PTR_SIZE = 8

# ida_ua operand type constants
o_void = 0   # No operand
o_reg = 1    # General register
o_mem = 2    # Direct memory reference
o_phrase = 3 # Memory reference [base + index]
o_displ = 4  # Memory reference [base + index + displacement]
o_imm = 5    # Immediate value
o_near = 7   # Near branch

# Call instruction mnemonics
_CALL_MNEMONICS = {"call", "jmp"}

# Quality tiers
QUALITY_EXACT = "EXACT"         # 1 target
QUALITY_NARROW = "NARROW"       # 2-5 targets
QUALITY_BROAD = "BROAD"         # 6-50 targets
QUALITY_UNRESOLVED = "UNRESOLVED"  # 0 or >50 targets

# Classification of indirect call types
CALL_TYPE_REG = "register_indirect"         # call rax
CALL_TYPE_MEM = "memory_indirect"           # call [rip+xxx]
CALL_TYPE_VTABLE = "vtable_dispatch"        # call [rcx+offset]
CALL_TYPE_FPTR_TABLE = "fptr_table"         # call [base + idx*8]
CALL_TYPE_UNKNOWN = "unknown_indirect"

# Registers commonly used for `this` pointer in MSVC x64
_THIS_REGS = {"rcx", "ecx"}

# Maximum functions to scan (safety limit for huge binaries)
_MAX_FUNCTIONS = 200000

# Maximum indirect calls to attempt decompiler resolution on
_MAX_DECOMPILE = 25000

# Maximum targets before we give up on a single call site
_MAX_TARGETS_PER_SITE = 500

# Vtable assignment patterns in decompiled output
_VTABLE_ASSIGN_RE = re.compile(
    r'\*\s*\(\s*_QWORD\s*\*\s*\)\s*(\w+)\s*=\s*'
    r'(?:&\s*)?(\w*::`vftable\'|vtable_[A-Za-z0-9_]+|off_[0-9A-Fa-f]+)',
    re.IGNORECASE,
)

# Alternative vtable assignment: v->__vftable = (T *)&Class::`vftable';
_VTABLE_ASSIGN_ALT_RE = re.compile(
    r'(\w+)->__vftable\s*=\s*'
    r'(?:\(\s*\w+\s*\*\s*\)\s*)?(?:&\s*)?'
    r'(\w*::`vftable\'|vtable_[A-Za-z0-9_]+|off_[0-9A-Fa-f]+)',
    re.IGNORECASE,
)

# Virtual call pattern in decompiler output: (*(void (__fastcall **)(T *, ...))(v + 0x10))(v, ...);
_VCALL_DECOMPILED_RE = re.compile(
    r'\(\s*\*\s*\(\s*[^)]+\*\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)\s*\)',
)

# Function pointer table access: call qword ptr [base + reg*8]
_FPTR_TABLE_RE = re.compile(
    r'call\s+qword\s+ptr\s+\[\s*(\w+)\s*\+\s*(\w+)\s*\*\s*8\s*\]',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _quality_for_count(n):
    """Return quality tier string for a given target count."""
    if n == 1:
        return QUALITY_EXACT
    elif 2 <= n <= 5:
        return QUALITY_NARROW
    elif 6 <= n <= 50:
        return QUALITY_BROAD
    else:
        return QUALITY_UNRESOLVED


def _get_func_at(ea):
    """Return ida_funcs function object containing *ea*, or None."""
    return ida_funcs.get_func(ea)


def _func_name(ea):
    """Robust function-name lookup; falls back to hex address."""
    name = ida_name.get_name(ea)
    if name:
        return name
    func = ida_funcs.get_func(ea)
    if func:
        n = ida_name.get_name(func.start_ea)
        if n:
            return n
    return ea_str(ea)


def _is_code_ea(ea):
    """True if *ea* points to a defined instruction."""
    flags = ida_bytes.get_flags(ea)
    return ida_bytes.is_code(flags)


def _read_ptr(ea):
    """Read a native pointer (8 bytes on x64) from *ea*."""
    return ida_bytes.get_qword(ea)


def _is_func_start(ea):
    """True if *ea* is the start of a known function."""
    func = ida_funcs.get_func(ea)
    return func is not None and func.start_ea == ea


def _get_segment_by_name(name):
    """Return segment object by name, e.g. '.rdata'."""
    import ida_segment
    return ida_segment.get_segm_by_name(name)


# ---------------------------------------------------------------------------
# Phase 1: Indirect call site detection
# ---------------------------------------------------------------------------

def _scan_indirect_call_sites():
    """Scan all functions for indirect call/jmp instructions.

    Returns a list of dicts:
        call_ea      - address of the call instruction
        caller_ea    - start of the containing function
        caller_name  - name of the containing function
        call_type    - classification string
        operand_reg  - register name (if register-indirect)
        displacement - displacement value (if memory-indirect)
        mnemonic     - 'call' or 'jmp'
        raw_disasm   - disassembly text
    """
    sites = []
    func_count = 0
    insn = ida_ua.insn_t()

    for func_ea in idautils.Functions():
        func_count += 1
        if func_count > _MAX_FUNCTIONS:
            msg_warn(f"Hit function scan limit ({_MAX_FUNCTIONS}), stopping")
            break

        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        ea = func.start_ea
        end_ea = func.end_ea
        caller_name = _func_name(func_ea)

        while ea < end_ea:
            size = ida_ua.decode_insn(insn, ea)
            if size <= 0:
                ea += 1
                continue

            mnem = insn.get_canon_mnem()
            if mnem not in _CALL_MNEMONICS:
                ea += size
                continue

            op = insn.ops[0]

            # Skip direct calls/jumps (o_near = direct code reference)
            if op.type == o_near or op.type == o_imm:
                ea += size
                continue

            # Skip void operand
            if op.type == o_void:
                ea += size
                continue

            site = {
                "call_ea": ea,
                "caller_ea": func_ea,
                "caller_name": caller_name,
                "mnemonic": mnem,
                "raw_disasm": idc.generate_disasm_line(ea, 0),
                "operand_reg": None,
                "displacement": 0,
                "call_type": CALL_TYPE_UNKNOWN,
                "base_reg": None,
                "index_reg": None,
            }

            if op.type == o_reg:
                # call rax, call rbx, etc.
                reg_name = ida_ua.print_operand(ea, 0).strip()
                site["operand_reg"] = reg_name
                site["call_type"] = CALL_TYPE_REG

            elif op.type == o_mem:
                # call [0x7FF7XXXXXXXX] -- absolute memory
                site["displacement"] = op.addr
                site["call_type"] = CALL_TYPE_MEM

            elif op.type == o_displ:
                # call [reg + displacement]  -- vtable dispatch or struct fptr
                disp = op.addr if op.addr else op.value
                reg_name = _decode_base_reg(insn, 0)
                site["displacement"] = disp
                site["base_reg"] = reg_name
                site["call_type"] = CALL_TYPE_VTABLE

            elif op.type == o_phrase:
                # call [reg + index*scale] -- no displacement, phrase addressing
                reg_name = _decode_base_reg(insn, 0)
                site["base_reg"] = reg_name
                site["call_type"] = CALL_TYPE_VTABLE
                site["displacement"] = 0

            else:
                site["call_type"] = CALL_TYPE_UNKNOWN

            sites.append(site)
            ea += size

    msg_info(f"Scanned {func_count} functions, found {len(sites)} indirect call sites")
    return sites


def _decode_base_reg(insn, op_idx):
    """Extract the base register name from an operand.

    Uses the printed operand text as a fallback when the IDA API
    register-number mapping is not straightforward.
    """
    op_text = ida_ua.print_operand(insn.ea, op_idx)
    if not op_text:
        return None

    # Strip the brackets and extract the first register-looking token
    inner = op_text.strip()
    # Remove 'qword ptr' and similar prefixes
    inner = re.sub(r'(?:qword|dword|word|byte)\s+ptr\s+', '', inner, flags=re.IGNORECASE)
    # Remove brackets
    inner = inner.strip('[]')

    # Split on +/- and take the first token that looks like a register
    parts = re.split(r'[+\-*\s]+', inner)
    _REGS = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    }
    for p in parts:
        p_lower = p.lower().strip()
        if p_lower in _REGS:
            return p_lower
    return parts[0] if parts else None


# ---------------------------------------------------------------------------
# Phase 2: VTable dispatch resolution
# ---------------------------------------------------------------------------

def _load_vtable_data(db):
    """Load all vtable and vtable_entries data from the knowledge DB.

    Returns:
        vtables_by_ea   - {vtable_ea: {class_name, entry_count, parent_class, ...}}
        slots_by_index  - {slot_index: [{vtable_ea, func_ea, func_name, class_name}]}
        entries_by_vtea - {vtable_ea: [{slot_index, func_ea, func_name}]}
        vtables_by_name - {class_name: [vtable_ea, ...]}
    """
    vtables_by_ea = {}
    slots_by_index = defaultdict(list)
    entries_by_vtea = defaultdict(list)
    vtables_by_name = defaultdict(list)

    try:
        rows = db.fetchall("SELECT * FROM vtables")
    except Exception:
        rows = []

    for row in rows:
        ea = row["ea"]
        class_name = row["class_name"] or f"UnknownClass_{ea_str(ea)}"
        vtables_by_ea[ea] = {
            "class_name": class_name,
            "entry_count": row["entry_count"],
            "parent_class": row["parent_class"],
            "source": row["source"],
        }
        vtables_by_name[class_name].append(ea)

    try:
        entry_rows = db.fetchall("SELECT * FROM vtable_entries ORDER BY vtable_ea, slot_index")
    except Exception:
        entry_rows = []

    for row in entry_rows:
        vtable_ea = row["vtable_ea"]
        slot_idx = row["slot_index"]
        func_ea = row["func_ea"]
        func_name = row["func_name"] or _func_name(func_ea) if func_ea else None

        vt_info = vtables_by_ea.get(vtable_ea)
        class_name = vt_info["class_name"] if vt_info else "Unknown"

        entry_info = {
            "vtable_ea": vtable_ea,
            "func_ea": func_ea,
            "func_name": func_name,
            "class_name": class_name,
            "slot_index": slot_idx,
        }
        slots_by_index[slot_idx].append(entry_info)
        entries_by_vtea[vtable_ea].append({
            "slot_index": slot_idx,
            "func_ea": func_ea,
            "func_name": func_name,
        })

    msg_info(f"Loaded {len(vtables_by_ea)} vtables, "
             f"{len(entry_rows)} vtable entries across "
             f"{len(slots_by_index)} unique slots")

    return vtables_by_ea, slots_by_index, entries_by_vtea, vtables_by_name


def _resolve_vtable_dispatches(sites, vtables_by_ea, slots_by_index,
                                entries_by_vtea, vtables_by_name):
    """For each vtable-dispatch call site, determine the vtable slot and
    enumerate all classes that override that virtual function.

    Modifies sites in-place by adding 'targets' and 'vtable_slot' fields.
    Returns the number of sites resolved.
    """
    resolved = 0

    for site in sites:
        if site["call_type"] != CALL_TYPE_VTABLE:
            continue

        disp = site.get("displacement", 0)
        if disp is None:
            disp = 0

        # Convert displacement to vtable slot index
        slot_index = disp // PTR_SIZE

        site["vtable_slot"] = slot_index

        # Look up all functions at this slot across all vtables
        slot_entries = slots_by_index.get(slot_index, [])

        if not slot_entries:
            continue

        # Deduplicate by func_ea
        seen_eas = set()
        targets = []
        for entry in slot_entries:
            fea = entry["func_ea"]
            if fea and fea not in seen_eas:
                seen_eas.add(fea)
                targets.append({
                    "ea": fea,
                    "name": entry["func_name"] or _func_name(fea),
                    "class_name": entry["class_name"],
                })

        if targets:
            site["targets"] = targets
            site["target_count"] = len(targets)
            site["quality"] = _quality_for_count(len(targets))
            resolved += 1

    msg_info(f"VTable dispatch resolution: {resolved} sites resolved "
             f"from vtable slot data")
    return resolved


# ---------------------------------------------------------------------------
# Phase 3: CFG table cross-reference
# ---------------------------------------------------------------------------

def _load_cfg_targets(db):
    """Load Control Flow Guard valid target addresses from pe_metadata kv.

    Returns a set of EAs that are valid indirect call targets per CFG.
    """
    pe_meta = db.kv_get("pe_metadata")
    if not pe_meta:
        msg_info("No pe_metadata in kv_store, skipping CFG intersection")
        return None

    cfg_targets_raw = None

    # pe_metadata might store CFG data in several ways
    if isinstance(pe_meta, dict):
        cfg_targets_raw = pe_meta.get("cfg_targets") or pe_meta.get("guard_cf_targets")
        if not cfg_targets_raw:
            # Try nested structure
            load_config = pe_meta.get("load_config", {})
            if isinstance(load_config, dict):
                cfg_targets_raw = load_config.get("cfg_targets")

    if not cfg_targets_raw:
        msg_info("No CFG targets found in pe_metadata")
        return None

    # Parse into a set of EAs
    cfg_set = set()
    if isinstance(cfg_targets_raw, list):
        for entry in cfg_targets_raw:
            if isinstance(entry, int):
                cfg_set.add(entry)
            elif isinstance(entry, str):
                try:
                    cfg_set.add(int(entry, 16) if entry.startswith("0x") else int(entry))
                except ValueError:
                    pass
            elif isinstance(entry, dict):
                ea_val = entry.get("ea") or entry.get("address") or entry.get("rva")
                if isinstance(ea_val, int):
                    cfg_set.add(ea_val)

    if cfg_set:
        msg_info(f"Loaded {len(cfg_set)} CFG-valid targets")
    else:
        msg_info("CFG target list was empty")
        return None

    return cfg_set


def _apply_cfg_constraint(sites, cfg_targets):
    """For unresolved sites, set the CFG table as an upper bound.
    For already-resolved sites, intersect targets with CFG set.

    Returns number of sites improved.
    """
    if not cfg_targets:
        return 0

    improved = 0

    for site in sites:
        existing_targets = site.get("targets")

        if existing_targets:
            # Intersect existing targets with CFG set
            filtered = [t for t in existing_targets if t["ea"] in cfg_targets]
            if len(filtered) < len(existing_targets) and filtered:
                site["targets"] = filtered
                site["target_count"] = len(filtered)
                site["quality"] = _quality_for_count(len(filtered))
                site["cfg_filtered"] = True
                improved += 1
        else:
            # For unresolved sites, note the CFG upper bound but don't
            # enumerate all CFG targets (too broad to be useful)
            site["cfg_upper_bound"] = len(cfg_targets)

    msg_info(f"CFG constraint: improved {improved} sites")
    return improved


# ---------------------------------------------------------------------------
# Phase 4: Function pointer table resolution
# ---------------------------------------------------------------------------

def _resolve_fptr_tables(sites):
    """Detect function pointer table accesses (jump tables, dispatch arrays)
    and enumerate their entries.

    Looks for patterns like: call [base + reg*8] where base is in .rdata,
    and reads consecutive pointers from the base address.

    Returns number of sites resolved.
    """
    resolved = 0
    rdata_seg = _get_segment_by_name(".rdata")

    for site in sites:
        if site.get("targets"):
            continue  # Already resolved

        disasm = site.get("raw_disasm", "")
        call_ea = site["call_ea"]

        # Check for memory-indirect calls pointing into .rdata
        if site["call_type"] == CALL_TYPE_MEM:
            mem_addr = site.get("displacement", 0)
            if mem_addr and rdata_seg and rdata_seg.start_ea <= mem_addr < rdata_seg.end_ea:
                # Single function pointer in .rdata
                target_ea = _read_ptr(mem_addr)
                if target_ea and _is_func_start(target_ea):
                    site["targets"] = [{
                        "ea": target_ea,
                        "name": _func_name(target_ea),
                        "class_name": "",
                    }]
                    site["target_count"] = 1
                    site["quality"] = QUALITY_EXACT
                    site["call_type"] = CALL_TYPE_FPTR_TABLE
                    resolved += 1
                    continue

        # Try to detect table-based dispatch from disassembly
        m = _FPTR_TABLE_RE.search(disasm)
        if not m:
            continue

        # The base might be a known label — try to resolve it
        base_token = m.group(1)
        base_ea = idc.get_name_ea_simple(base_token)
        if base_ea == idc.BADADDR:
            continue

        if rdata_seg and not (rdata_seg.start_ea <= base_ea < rdata_seg.end_ea):
            continue

        # Read consecutive function pointers from the table
        targets = []
        for i in range(_MAX_TARGETS_PER_SITE):
            ptr_ea = base_ea + i * PTR_SIZE
            if rdata_seg and ptr_ea >= rdata_seg.end_ea:
                break

            target = _read_ptr(ptr_ea)
            if not target or target == 0:
                break
            if not _is_func_start(target):
                # Allow a few non-function entries (padding), but stop after 3
                # consecutive non-function entries
                next1 = _read_ptr(ptr_ea + PTR_SIZE) if (ptr_ea + PTR_SIZE < rdata_seg.end_ea) else 0
                next2 = _read_ptr(ptr_ea + 2 * PTR_SIZE) if (ptr_ea + 2 * PTR_SIZE < rdata_seg.end_ea) else 0
                if not (_is_func_start(next1) or _is_func_start(next2)):
                    break
                continue

            targets.append({
                "ea": target,
                "name": _func_name(target),
                "class_name": "",
                "table_index": i,
            })

        if targets:
            site["targets"] = targets
            site["target_count"] = len(targets)
            site["quality"] = _quality_for_count(len(targets))
            site["call_type"] = CALL_TYPE_FPTR_TABLE
            site["fptr_table_base"] = base_ea
            resolved += 1

    msg_info(f"Function pointer table resolution: {resolved} sites")
    return resolved


# ---------------------------------------------------------------------------
# Phase 5: Decompiler-assisted resolution
# ---------------------------------------------------------------------------

def _resolve_via_decompiler(sites, vtables_by_ea, vtables_by_name,
                             entries_by_vtea):
    """Use decompiled pseudocode to trace vtable assignments and narrow
    down the set of possible targets for indirect calls.

    For each unresolved (or broadly resolved) vtable dispatch:
      1. Decompile the calling function
      2. Search for vtable assignment patterns before the call
      3. If a specific vtable is assigned to the object, resolve directly

    Returns number of sites resolved or improved.
    """
    resolved = 0
    decompile_count = 0

    # Group sites by calling function to avoid redundant decompilations
    sites_by_caller = defaultdict(list)
    for idx, site in enumerate(sites):
        quality = site.get("quality", QUALITY_UNRESOLVED)
        if quality in (QUALITY_EXACT,):
            continue  # Already fully resolved
        if site["call_type"] not in (CALL_TYPE_VTABLE, CALL_TYPE_REG, CALL_TYPE_UNKNOWN):
            continue
        sites_by_caller[site["caller_ea"]].append(idx)

    # Limit decompilation to avoid excessive runtime
    caller_eas = list(sites_by_caller.keys())
    if len(caller_eas) > _MAX_DECOMPILE:
        msg_warn(f"Limiting decompiler resolution to {_MAX_DECOMPILE} "
                 f"of {len(caller_eas)} callers")
        caller_eas = caller_eas[:_MAX_DECOMPILE]

    for caller_ea in caller_eas:
        decomp = get_decompiled_text(caller_ea)
        if not decomp:
            continue
        decompile_count += 1

        # Find vtable assignments in the decompiled text
        vtable_assignments = _extract_vtable_assignments(decomp, vtables_by_ea,
                                                          vtables_by_name)

        # Find virtual call patterns
        vcall_objects = _extract_vcall_objects(decomp)

        site_indices = sites_by_caller[caller_ea]
        for idx in site_indices:
            site = sites[idx]
            improved = _try_decompiler_resolve_site(
                site, decomp, vtable_assignments, vcall_objects,
                vtables_by_ea, entries_by_vtea, vtables_by_name
            )
            if improved:
                resolved += 1

    msg_info(f"Decompiler resolution: decompiled {decompile_count} functions, "
             f"resolved/improved {resolved} sites")
    return resolved


def _extract_vtable_assignments(decomp_text, vtables_by_ea, vtables_by_name):
    """Parse decompiled text for vtable assignment patterns.

    Returns a dict: {object_variable: [vtable_ea, ...]}
    """
    assignments = defaultdict(list)

    for pattern in (_VTABLE_ASSIGN_RE, _VTABLE_ASSIGN_ALT_RE):
        for m in pattern.finditer(decomp_text):
            obj_var = m.group(1)
            vtable_ref = m.group(2)

            vtable_ea = _resolve_vtable_ref(vtable_ref, vtables_by_ea, vtables_by_name)
            if vtable_ea is not None:
                assignments[obj_var].append(vtable_ea)

    return assignments


def _resolve_vtable_ref(ref_str, vtables_by_ea, vtables_by_name):
    """Resolve a vtable reference string to an EA.

    Handles:
      - off_7FF7XXXXXXXX  (IDA label)
      - ClassName::`vftable'  (MSVC name)
      - vtable_ClassName  (custom label)
    """
    # Try as IDA name
    ea = idc.get_name_ea_simple(ref_str)
    if ea != idc.BADADDR:
        if ea in vtables_by_ea:
            return ea
        # Even if not in our vtable DB, it might be a valid vtable
        return ea

    # Try extracting class name for ClassName::`vftable'
    if "::`vftable'" in ref_str:
        class_name = ref_str.split("::`vftable'")[0].strip()
        vt_eas = vtables_by_name.get(class_name, [])
        if vt_eas:
            return vt_eas[0]

    # Try vtable_ prefix
    if ref_str.startswith("vtable_"):
        class_name = ref_str[len("vtable_"):]
        vt_eas = vtables_by_name.get(class_name, [])
        if vt_eas:
            return vt_eas[0]

    return None


def _extract_vcall_objects(decomp_text):
    """Parse decompiled text for virtual call patterns.

    Returns a list of (object_variable, offset) pairs.
    """
    results = []
    for m in _VCALL_DECOMPILED_RE.finditer(decomp_text):
        obj_var = m.group(1)
        offset_str = m.group(2)
        try:
            offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
        except ValueError:
            continue
        results.append((obj_var, offset))
    return results


def _try_decompiler_resolve_site(site, decomp_text, vtable_assignments,
                                  vcall_objects, vtables_by_ea,
                                  entries_by_vtea, vtables_by_name):
    """Try to resolve a single call site using decompiler information.

    Returns True if the site was resolved or improved.
    """
    if site["call_type"] != CALL_TYPE_VTABLE:
        # For register-indirect calls, try to match decompiled vcall patterns
        # by looking for the call EA in the decompiled text
        call_ea_hex = f"0x{site['call_ea']:X}"
        # This is a heuristic — if we can't match, skip
        return False

    slot_index = site.get("vtable_slot")
    if slot_index is None:
        return False

    # Check if the base register is the `this` pointer
    base_reg = site.get("base_reg", "")

    # Try to find which vtable was assigned to the object used at this call
    # This is imprecise since we're matching by variable name, but useful
    matched_vtables = set()

    for obj_var, vtable_eas in vtable_assignments.items():
        # If this variable appears in the decompiled text near our call site,
        # it might be the relevant object
        for vt_ea in vtable_eas:
            matched_vtables.add(vt_ea)

    if not matched_vtables:
        return False

    # If we found specific vtables assigned in this function, narrow targets
    # to only functions at our slot from those vtables
    new_targets = []
    seen_eas = set()

    for vt_ea in matched_vtables:
        entries = entries_by_vtea.get(vt_ea, [])
        for entry in entries:
            if entry["slot_index"] == slot_index:
                fea = entry["func_ea"]
                if fea and fea not in seen_eas:
                    seen_eas.add(fea)
                    vt_info = vtables_by_ea.get(vt_ea, {})
                    new_targets.append({
                        "ea": fea,
                        "name": entry["func_name"] or _func_name(fea),
                        "class_name": vt_info.get("class_name", ""),
                    })

    if not new_targets:
        return False

    old_count = site.get("target_count", 0)
    new_count = len(new_targets)

    # Only update if we narrowed the targets or had none before
    if new_count < old_count or old_count == 0:
        site["targets"] = new_targets
        site["target_count"] = new_count
        site["quality"] = _quality_for_count(new_count)
        site["decompiler_resolved"] = True
        return True

    return False


# ---------------------------------------------------------------------------
# Phase 6: Type-based narrowing
# ---------------------------------------------------------------------------

def _narrow_by_type(sites, cfg_targets):
    """Filter unresolved sites by matching function signatures.

    For register-indirect calls where CFG data is available, try to
    determine the expected signature from:
      - How the return value is used
      - What arguments are passed (register setup before the call)
      - Whether RCX looks like a `this` pointer (member function call)

    Returns number of sites improved.
    """
    if not cfg_targets:
        return 0

    improved = 0

    for site in sites:
        if site.get("quality") in (QUALITY_EXACT, QUALITY_NARROW):
            continue
        if site["call_type"] != CALL_TYPE_REG:
            continue

        call_ea = site["call_ea"]

        # Check instructions before the call for argument setup
        is_member_call = _check_this_ptr_setup(call_ea)

        if is_member_call:
            site["is_member_call"] = True
            # Could narrow by looking for functions that take a this pointer
            # as their first arg, but without full type info this is marginal

        # Check if the register was loaded from a known location
        reg_source = _trace_reg_source(call_ea, site.get("operand_reg"))
        if reg_source:
            site["reg_source"] = reg_source
            if reg_source.get("type") == "vtable_load":
                # We found where the function pointer was loaded from
                vt_ea = reg_source.get("vtable_ea")
                slot = reg_source.get("slot")
                if vt_ea and slot is not None:
                    target_ea = _read_ptr(vt_ea + slot * PTR_SIZE)
                    if target_ea and _is_func_start(target_ea):
                        site["targets"] = [{
                            "ea": target_ea,
                            "name": _func_name(target_ea),
                            "class_name": "",
                        }]
                        site["target_count"] = 1
                        site["quality"] = QUALITY_EXACT
                        site["type_narrowed"] = True
                        improved += 1

    msg_info(f"Type-based narrowing: improved {improved} sites")
    return improved


def _check_this_ptr_setup(call_ea):
    """Check if the instruction(s) before *call_ea* set up RCX as a
    `this` pointer (e.g., lea rcx, [rbp+var] or mov rcx, rdi).

    Returns True if it looks like a member function call.
    """
    insn = ida_ua.insn_t()
    # Look at the previous 3 instructions
    prev_ea = call_ea
    for _ in range(5):
        prev_ea = idc.prev_head(prev_ea)
        if prev_ea == idc.BADADDR:
            break

        size = ida_ua.decode_insn(insn, prev_ea)
        if size <= 0:
            continue

        mnem = insn.get_canon_mnem()
        if mnem in ("mov", "lea"):
            op0_text = ida_ua.print_operand(prev_ea, 0).strip().lower()
            if op0_text in ("rcx", "ecx"):
                return True

    return False


def _trace_reg_source(call_ea, reg_name):
    """Trace backwards from *call_ea* to find where *reg_name* was loaded.

    Returns a dict describing the source, or None.
    """
    if not reg_name:
        return None

    reg_name_lower = reg_name.lower()
    insn = ida_ua.insn_t()

    prev_ea = call_ea
    for _ in range(10):
        prev_ea = idc.prev_head(prev_ea)
        if prev_ea == idc.BADADDR:
            break

        size = ida_ua.decode_insn(insn, prev_ea)
        if size <= 0:
            continue

        mnem = insn.get_canon_mnem()
        if mnem not in ("mov", "lea", "movzx", "movsxd"):
            continue

        op0_text = ida_ua.print_operand(prev_ea, 0).strip().lower()
        if op0_text != reg_name_lower:
            continue

        # Found the instruction that defines our register
        op1 = insn.ops[1]
        op1_text = ida_ua.print_operand(prev_ea, 1).strip()

        if op1.type == o_displ:
            # mov rax, [rcx+0x10]  -- loading from vtable slot?
            base = _decode_base_reg(insn, 1)
            disp = op1.addr if op1.addr else op1.value
            if base and base.lower() in _THIS_REGS:
                # Possibly loading from a vtable that's at *this
                return {
                    "type": "member_load",
                    "base_reg": base,
                    "offset": disp,
                    "instruction": prev_ea,
                }

        elif op1.type == o_mem:
            # mov rax, [absolute_addr]
            return {
                "type": "global_load",
                "address": op1.addr,
                "instruction": prev_ea,
            }

        # Whatever it is, we found the source
        return {
            "type": "other",
            "operand_text": op1_text,
            "instruction": prev_ea,
        }

    return None


# ---------------------------------------------------------------------------
# Phase 7: Resolution quality scoring (applied during each phase)
#           + final aggregation
# ---------------------------------------------------------------------------

def _finalize_quality(sites):
    """Ensure every site has a quality rating and target_count.
    Classify remaining unresolved sites.
    """
    for site in sites:
        if "targets" not in site:
            site["targets"] = []
            site["target_count"] = 0
            site["quality"] = QUALITY_UNRESOLVED
        else:
            count = len(site["targets"])
            site["target_count"] = count
            if "quality" not in site:
                site["quality"] = _quality_for_count(count)


# ---------------------------------------------------------------------------
# Phase 8: Call graph enhancement
# ---------------------------------------------------------------------------

def _enhance_call_graph(sites, db):
    """Add resolved indirect call edges to the knowledge database.

    For each resolved site, upserts a function record for both caller
    and callee (if missing), creating an edge in the implicit call graph
    stored in the functions table.

    Also stores per-callsite resolution in a dedicated kv entry for
    downstream consumers.

    Returns number of new edges added.
    """
    new_edges = 0

    for site in sites:
        targets = site.get("targets", [])
        if not targets:
            continue

        caller_ea = site["caller_ea"]

        for target in targets:
            target_ea = target.get("ea")
            if not target_ea:
                continue

            # Ensure both caller and target exist in functions table
            db.upsert_function(
                ea=caller_ea,
                name=site.get("caller_name"),
            )
            db.upsert_function(
                ea=target_ea,
                name=target.get("name"),
            )
            new_edges += 1

    db.commit()
    msg_info(f"Enhanced call graph with {new_edges} indirect edges")
    return new_edges


# ---------------------------------------------------------------------------
# Polymorphic hotspot detection
# ---------------------------------------------------------------------------

def _detect_polymorphic_hotspots(sites, slots_by_index):
    """Identify vtable slots that are overridden by many classes,
    making them polymorphic hotspots.

    Returns a list of hotspot dicts.
    """
    hotspots = []

    # Aggregate by vtable slot
    slot_targets = defaultdict(set)
    slot_classes = defaultdict(set)

    for site in sites:
        if site["call_type"] != CALL_TYPE_VTABLE:
            continue

        slot = site.get("vtable_slot")
        if slot is None:
            continue

        for target in site.get("targets", []):
            target_ea = target.get("ea")
            class_name = target.get("class_name", "")
            if target_ea:
                slot_targets[slot].add(target_ea)
            if class_name:
                slot_classes[slot].add(class_name)

    # Also include data from the full vtable database
    for slot_idx, entries in slots_by_index.items():
        unique_funcs = set()
        unique_classes = set()
        for entry in entries:
            if entry["func_ea"]:
                unique_funcs.add(entry["func_ea"])
            if entry["class_name"]:
                unique_classes.add(entry["class_name"])

        if len(unique_funcs) > 5:  # Threshold for "hotspot"
            slot_targets[slot_idx].update(unique_funcs)
            slot_classes[slot_idx].update(unique_classes)

    # Build hotspot list (slots with many distinct implementations)
    for slot_idx in sorted(slot_targets.keys()):
        target_count = len(slot_targets[slot_idx])
        if target_count < 5:
            continue

        classes = sorted(slot_classes.get(slot_idx, set()))

        # Try to find a representative function name for the slot
        representative_name = None
        for site in sites:
            if site.get("vtable_slot") == slot_idx and site.get("targets"):
                representative_name = site["targets"][0].get("name")
                break

        hotspots.append({
            "vtable_slot": slot_idx,
            "target_count": target_count,
            "classes": classes[:50],  # Limit to 50 class names
            "representative_name": representative_name,
        })

    hotspots.sort(key=lambda h: h["target_count"], reverse=True)
    msg_info(f"Detected {len(hotspots)} polymorphic hotspots")
    return hotspots


# ---------------------------------------------------------------------------
# Results serialization
# ---------------------------------------------------------------------------

def _serialize_sites(sites, max_targets_in_detail=20):
    """Convert site list into JSON-serializable resolution records.

    For sites with many targets, truncate the target list but keep counts.
    """
    resolutions = []

    for site in sites:
        targets = site.get("targets", [])

        # Truncate target list for storage
        stored_targets = targets[:max_targets_in_detail]

        # Convert EAs to hex strings for JSON
        serialized_targets = []
        for t in stored_targets:
            serialized_targets.append({
                "ea": ea_str(t["ea"]) if t.get("ea") else None,
                "name": t.get("name", ""),
                "class_name": t.get("class_name", ""),
            })

        rec = {
            "call_ea": ea_str(site["call_ea"]),
            "call_ea_int": site["call_ea"],
            "caller_name": site.get("caller_name", ""),
            "call_type": site.get("call_type", CALL_TYPE_UNKNOWN),
            "vtable_slot": site.get("vtable_slot"),
            "target_count": site.get("target_count", 0),
            "quality": site.get("quality", QUALITY_UNRESOLVED),
            "targets": serialized_targets,
            "mnemonic": site.get("mnemonic", "call"),
        }

        # Include optional metadata
        if site.get("cfg_filtered"):
            rec["cfg_filtered"] = True
        if site.get("decompiler_resolved"):
            rec["decompiler_resolved"] = True
        if site.get("type_narrowed"):
            rec["type_narrowed"] = True
        if site.get("is_member_call"):
            rec["is_member_call"] = True
        if site.get("fptr_table_base"):
            rec["fptr_table_base"] = ea_str(site["fptr_table_base"])

        resolutions.append(rec)

    return resolutions


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def resolve_indirect_calls(session):
    """Resolve indirect calls in the binary to their target function sets.

    Combines vtable analysis, CFG tables, decompiler output, function
    pointer tables, and type narrowing to produce per-callsite resolutions
    with quality scores.

    Args:
        session: PluginSession with .db and .cfg attributes.

    Returns:
        int: Total number of resolved call sites (quality != UNRESOLVED).
    """
    db = session.db
    start_time = time.time()

    msg("=" * 70)
    msg("Indirect Call Resolver — starting analysis")
    msg("=" * 70)

    # ------------------------------------------------------------------
    # Phase 1: Scan for indirect call sites
    # ------------------------------------------------------------------
    msg_info("Phase 1: Scanning for indirect call/jump sites...")
    sites = _scan_indirect_call_sites()

    if not sites:
        msg_warn("No indirect call sites found — nothing to resolve")
        db.kv_set("indirect_calls", {
            "indirect_call_sites": 0,
            "resolved_exact": 0,
            "resolved_narrow": 0,
            "resolved_broad": 0,
            "unresolved": 0,
            "resolutions": [],
            "polymorphic_hotspots": [],
            "enhanced_edges": 0,
            "analysis_time_s": 0,
        })
        db.commit()
        return 0

    # Classify initial distribution
    type_counts = defaultdict(int)
    for s in sites:
        type_counts[s["call_type"]] += 1
    for ct, count in sorted(type_counts.items()):
        msg(f"  {ct}: {count}")

    # ------------------------------------------------------------------
    # Phase 2: VTable dispatch resolution
    # ------------------------------------------------------------------
    msg_info("Phase 2: Loading vtable data and resolving dispatches...")
    vtables_by_ea, slots_by_index, entries_by_vtea, vtables_by_name = \
        _load_vtable_data(db)

    vtable_resolved = _resolve_vtable_dispatches(
        sites, vtables_by_ea, slots_by_index, entries_by_vtea, vtables_by_name
    )

    # ------------------------------------------------------------------
    # Phase 3: CFG table cross-reference
    # ------------------------------------------------------------------
    msg_info("Phase 3: Applying CFG constraints...")
    cfg_targets = _load_cfg_targets(db)
    cfg_improved = _apply_cfg_constraint(sites, cfg_targets)

    # ------------------------------------------------------------------
    # Phase 4: Function pointer table resolution
    # ------------------------------------------------------------------
    msg_info("Phase 4: Resolving function pointer tables...")
    fptr_resolved = _resolve_fptr_tables(sites)

    # ------------------------------------------------------------------
    # Phase 5: Decompiler-assisted resolution
    # ------------------------------------------------------------------
    msg_info("Phase 5: Decompiler-assisted resolution...")
    decomp_resolved = _resolve_via_decompiler(
        sites, vtables_by_ea, vtables_by_name, entries_by_vtea
    )

    # ------------------------------------------------------------------
    # Phase 6: Type-based narrowing
    # ------------------------------------------------------------------
    msg_info("Phase 6: Type-based narrowing...")
    type_improved = _narrow_by_type(sites, cfg_targets)

    # ------------------------------------------------------------------
    # Phase 7: Finalize quality scores
    # ------------------------------------------------------------------
    msg_info("Phase 7: Finalizing quality scores...")
    _finalize_quality(sites)

    # ------------------------------------------------------------------
    # Phase 8: Call graph enhancement
    # ------------------------------------------------------------------
    msg_info("Phase 8: Enhancing call graph...")
    new_edges = _enhance_call_graph(sites, db)

    # ------------------------------------------------------------------
    # Polymorphic hotspot detection
    # ------------------------------------------------------------------
    msg_info("Detecting polymorphic hotspots...")
    hotspots = _detect_polymorphic_hotspots(sites, slots_by_index)

    # ------------------------------------------------------------------
    # Aggregate statistics
    # ------------------------------------------------------------------
    count_exact = sum(1 for s in sites if s.get("quality") == QUALITY_EXACT)
    count_narrow = sum(1 for s in sites if s.get("quality") == QUALITY_NARROW)
    count_broad = sum(1 for s in sites if s.get("quality") == QUALITY_BROAD)
    count_unresolved = sum(1 for s in sites if s.get("quality") == QUALITY_UNRESOLVED)

    total_resolved = count_exact + count_narrow + count_broad

    elapsed = time.time() - start_time

    msg("=" * 70)
    msg(f"Indirect Call Resolution Complete ({elapsed:.1f}s)")
    msg(f"  Total indirect sites: {len(sites)}")
    msg(f"  EXACT   (1 target):    {count_exact}")
    msg(f"  NARROW  (2-5 targets): {count_narrow}")
    msg(f"  BROAD   (6-50):        {count_broad}")
    msg(f"  UNRESOLVED:            {count_unresolved}")
    msg(f"  Enhanced edges:        {new_edges}")
    msg(f"  Polymorphic hotspots:  {len(hotspots)}")
    msg("=" * 70)

    # ------------------------------------------------------------------
    # Serialize and store results
    # ------------------------------------------------------------------
    msg_info("Serializing results...")
    resolutions = _serialize_sites(sites)

    # For the stored summary, only include resolved sites to avoid
    # a massive kv entry.  Keep full counts for statistics.
    resolved_resolutions = [r for r in resolutions
                            if r["quality"] != QUALITY_UNRESOLVED]

    # Also store a compact list of unresolved sites for reference
    unresolved_summary = []
    for r in resolutions:
        if r["quality"] == QUALITY_UNRESOLVED:
            unresolved_summary.append({
                "call_ea": r["call_ea"],
                "caller_name": r["caller_name"],
                "call_type": r["call_type"],
            })
    # Limit unresolved summary
    if len(unresolved_summary) > 1000:
        unresolved_summary = unresolved_summary[:1000]

    result_data = {
        "indirect_call_sites": len(sites),
        "resolved_exact": count_exact,
        "resolved_narrow": count_narrow,
        "resolved_broad": count_broad,
        "unresolved": count_unresolved,
        "resolutions": resolved_resolutions,
        "unresolved_summary": unresolved_summary,
        "polymorphic_hotspots": hotspots[:100],  # Top 100
        "enhanced_edges": new_edges,
        "analysis_time_s": round(elapsed, 2),
        "phase_stats": {
            "vtable_resolved": vtable_resolved,
            "cfg_improved": cfg_improved,
            "fptr_resolved": fptr_resolved,
            "decompiler_resolved": decomp_resolved,
            "type_narrowed": type_improved,
        },
        "type_distribution": dict(type_counts),
    }

    db.kv_set("indirect_calls", result_data)
    db.commit()

    msg_info(f"Results stored in kv_store key 'indirect_calls'")
    return total_resolved


# ---------------------------------------------------------------------------
# Report accessor
# ---------------------------------------------------------------------------

def get_indirect_call_report(session):
    """Retrieve stored indirect call resolution data.

    Returns the dict previously stored by resolve_indirect_calls(),
    or None if the analysis hasn't been run yet.
    """
    return session.db.kv_get("indirect_calls")


# ---------------------------------------------------------------------------
# Standalone helpers for interactive use
# ---------------------------------------------------------------------------

def lookup_call_targets(session, call_ea):
    """Look up the resolved targets for a specific call site EA.

    Args:
        session: PluginSession.
        call_ea: EA of the indirect call instruction.

    Returns:
        A dict with target information, or None if not found.
    """
    data = get_indirect_call_report(session)
    if not data:
        return None

    call_ea_str = ea_str(call_ea)
    for res in data.get("resolutions", []):
        if res.get("call_ea") == call_ea_str or res.get("call_ea_int") == call_ea:
            return res

    # Also check unresolved summary
    for u in data.get("unresolved_summary", []):
        if u.get("call_ea") == call_ea_str:
            return {"call_ea": call_ea_str, "quality": QUALITY_UNRESOLVED, "targets": []}

    return None


def get_hotspots_for_slot(session, slot_index):
    """Return polymorphic hotspot info for a specific vtable slot.

    Args:
        session: PluginSession.
        slot_index: The vtable slot index.

    Returns:
        A hotspot dict, or None.
    """
    data = get_indirect_call_report(session)
    if not data:
        return None

    for hs in data.get("polymorphic_hotspots", []):
        if hs.get("vtable_slot") == slot_index:
            return hs

    return None


def get_callsites_in_function(session, func_ea):
    """Return all resolved indirect call sites within a specific function.

    Args:
        session: PluginSession.
        func_ea: Start EA of the function.

    Returns:
        A list of resolution dicts.
    """
    data = get_indirect_call_report(session)
    if not data:
        return []

    func = ida_funcs.get_func(func_ea)
    if not func:
        return []

    func_name = _func_name(func_ea)
    results = []

    for res in data.get("resolutions", []):
        if res.get("caller_name") == func_name:
            results.append(res)

    return results


def print_resolution_summary(session):
    """Print a human-readable summary of the indirect call analysis.

    Useful for interactive IDA console sessions.
    """
    data = get_indirect_call_report(session)
    if not data:
        msg_warn("No indirect call analysis data found. Run resolve_indirect_calls() first.")
        return

    msg("=" * 70)
    msg("Indirect Call Resolution Summary")
    msg("=" * 70)
    msg(f"  Total indirect call sites: {data.get('indirect_call_sites', 0)}")
    msg(f"  EXACT   (1 target):        {data.get('resolved_exact', 0)}")
    msg(f"  NARROW  (2-5 targets):     {data.get('resolved_narrow', 0)}")
    msg(f"  BROAD   (6-50 targets):    {data.get('resolved_broad', 0)}")
    msg(f"  UNRESOLVED:                {data.get('unresolved', 0)}")
    msg(f"  Enhanced call graph edges: {data.get('enhanced_edges', 0)}")
    msg(f"  Analysis time:             {data.get('analysis_time_s', 0):.1f}s")
    msg("")

    phase_stats = data.get("phase_stats", {})
    if phase_stats:
        msg("Phase contributions:")
        for phase, count in phase_stats.items():
            msg(f"  {phase}: {count}")
        msg("")

    type_dist = data.get("type_distribution", {})
    if type_dist:
        msg("Call type distribution:")
        for ctype, count in sorted(type_dist.items()):
            msg(f"  {ctype}: {count}")
        msg("")

    hotspots = data.get("polymorphic_hotspots", [])
    if hotspots:
        msg(f"Top {min(10, len(hotspots))} polymorphic hotspots:")
        for hs in hotspots[:10]:
            slot = hs.get("vtable_slot", "?")
            tcount = hs.get("target_count", 0)
            rep_name = hs.get("representative_name", "")
            classes = hs.get("classes", [])
            msg(f"  Slot {slot}: {tcount} implementations "
                f"({rep_name or 'unnamed'})")
            if classes:
                preview = ", ".join(classes[:5])
                if len(classes) > 5:
                    preview += f", ... ({len(classes)} total)"
                msg(f"    Classes: {preview}")
        msg("")

    msg("=" * 70)
