"""
Thread Safety Map — Mutex/Lock Pattern and Threading Analysis

Detects synchronization primitives (critical sections, SRW locks, mutexes,
interlocked operations, std::mutex, std::atomic, spin locks), identifies what
data each lock protects, discovers thread entry points, analyzes lock hierarchy
for deadlock risks, and maps TLS (Thread Local Storage) usage.

Produces a comprehensive thread safety map that helps TrinityCore implement
correct concurrency discipline for equivalent game systems.

Results are stored in the knowledge DB kv_store under key "thread_safety_map".
"""

import json
import re
import time
from collections import defaultdict

import ida_funcs
import ida_name
import ida_bytes
import ida_xref
import ida_segment
import idautils
import idaapi
import idc

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Synchronization primitive names (Win32 + MSVC CRT)
# ---------------------------------------------------------------------------

# Critical sections
_CS_ACQUIRE = frozenset([
    "EnterCriticalSection", "TryEnterCriticalSection",
])
_CS_RELEASE = frozenset([
    "LeaveCriticalSection",
])
_CS_INIT = frozenset([
    "InitializeCriticalSection", "InitializeCriticalSectionAndSpinCount",
    "InitializeCriticalSectionEx",
])
_CS_DELETE = frozenset([
    "DeleteCriticalSection",
])

# SRW locks
_SRW_ACQUIRE = frozenset([
    "AcquireSRWLockExclusive", "AcquireSRWLockShared",
    "TryAcquireSRWLockExclusive", "TryAcquireSRWLockShared",
])
_SRW_RELEASE = frozenset([
    "ReleaseSRWLockExclusive", "ReleaseSRWLockShared",
])
_SRW_INIT = frozenset([
    "InitializeSRWLock",
])

# Kernel mutexes
_MUTEX_ACQUIRE = frozenset([
    "WaitForSingleObject", "WaitForSingleObjectEx",
    "WaitForMultipleObjects", "WaitForMultipleObjectsEx",
])
_MUTEX_RELEASE = frozenset([
    "ReleaseMutex",
])
_MUTEX_CREATE = frozenset([
    "CreateMutexA", "CreateMutexW",
    "CreateMutexExA", "CreateMutexExW",
    "OpenMutexA", "OpenMutexW",
])

# Interlocked operations
_INTERLOCKED_OPS = frozenset([
    "InterlockedIncrement", "InterlockedDecrement",
    "InterlockedExchange", "InterlockedCompareExchange",
    "InterlockedExchangeAdd", "InterlockedAnd", "InterlockedOr",
    "InterlockedXor", "InterlockedIncrement64", "InterlockedDecrement64",
    "InterlockedExchange64", "InterlockedCompareExchange64",
    "InterlockedExchangeAdd64",
    "_InterlockedIncrement", "_InterlockedDecrement",
    "_InterlockedExchange", "_InterlockedCompareExchange",
    "_InterlockedExchangeAdd", "_InterlockedAnd", "_InterlockedOr",
    "_InterlockedXor", "_InterlockedIncrement64", "_InterlockedDecrement64",
    "_InterlockedExchange64", "_InterlockedCompareExchange64",
    "_InterlockedExchangeAdd64",
    "_InterlockedCompareExchange128",
])

# std::mutex (MSVC CRT)
_STD_MUTEX_ACQUIRE = frozenset([
    "_Mtx_lock", "_Mtx_trylock", "_Mtx_timedlock",
    "Concurrency::critical_section::lock",
    "Concurrency::critical_section::try_lock",
])
_STD_MUTEX_RELEASE = frozenset([
    "_Mtx_unlock",
    "Concurrency::critical_section::unlock",
])
_STD_MUTEX_INIT = frozenset([
    "_Mtx_init", "_Mtx_init_in_situ",
])
_STD_MUTEX_DESTROY = frozenset([
    "_Mtx_destroy", "_Mtx_destroy_in_situ",
])

# Condition variables
_CONDVAR_OPS = frozenset([
    "SleepConditionVariableCS", "SleepConditionVariableSRW",
    "WakeConditionVariable", "WakeAllConditionVariable",
    "InitializeConditionVariable",
    "_Cnd_wait", "_Cnd_timedwait", "_Cnd_signal", "_Cnd_broadcast",
    "_Cnd_init", "_Cnd_destroy",
])

# Thread creation
_THREAD_CREATE = frozenset([
    "CreateThread", "_beginthreadex", "_beginthread",
    "CreateRemoteThread", "CreateRemoteThreadEx",
])
_THREAD_POOL = frozenset([
    "QueueUserWorkItem", "TrySubmitThreadpoolCallback",
    "CreateThreadpoolWork", "SubmitThreadpoolWork",
    "SetThreadpoolTimer", "CreateThreadpoolTimer",
    "CreateThreadpoolIo",
])

# TLS operations
_TLS_OPS = frozenset([
    "TlsAlloc", "TlsFree", "TlsGetValue", "TlsSetValue",
    "FlsAlloc", "FlsFree", "FlsGetValue", "FlsSetValue",
])

# All acquire primitives (for quick lookup)
_ALL_ACQUIRE = _CS_ACQUIRE | _SRW_ACQUIRE | _MUTEX_ACQUIRE | _STD_MUTEX_ACQUIRE
_ALL_RELEASE = _CS_RELEASE | _SRW_RELEASE | _MUTEX_RELEASE | _STD_MUTEX_RELEASE
_ALL_SYNC_FUNCS = (
    _CS_ACQUIRE | _CS_RELEASE | _CS_INIT | _CS_DELETE
    | _SRW_ACQUIRE | _SRW_RELEASE | _SRW_INIT
    | _MUTEX_ACQUIRE | _MUTEX_RELEASE | _MUTEX_CREATE
    | _INTERLOCKED_OPS
    | _STD_MUTEX_ACQUIRE | _STD_MUTEX_RELEASE | _STD_MUTEX_INIT | _STD_MUTEX_DESTROY
    | _CONDVAR_OPS
    | _THREAD_CREATE | _THREAD_POOL
    | _TLS_OPS
)


# ---------------------------------------------------------------------------
# Regex patterns for decompiled pseudocode analysis
# ---------------------------------------------------------------------------

# Pattern: EnterCriticalSection(base + 0x48) or EnterCriticalSection(&this->field_48)
_RE_LOCK_CALL_OFFSET = re.compile(
    r'(\w+(?:CriticalSection|SRWLock\w*|_Mtx_\w+|Mutex\w*))\s*\(\s*'
    r'(?:&?\s*)?'                               # optional &
    r'(?:'
        r'(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)'   # base + offset
        r'|'
        r'(\w+)\s*->\s*(\w+)'                   # ptr->field
        r'|'
        r'&?\s*(\w+)'                           # plain variable
    r')',
    re.IGNORECASE
)

# Pattern: InterlockedIncrement(base + offset)
_RE_INTERLOCKED_OFFSET = re.compile(
    r'(?:_?Interlocked\w+)\s*\(\s*'
    r'(?:&?\s*)?'
    r'(?:'
        r'(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)'
        r'|'
        r'(\w+)\s*->\s*(\w+)'
        r'|'
        r'&?\s*(\w+)'
    r')',
    re.IGNORECASE
)

# Pattern: lock prefix instructions in disassembly
_RE_LOCK_PREFIX = re.compile(
    r'lock\s+(xchg|cmpxchg|add|sub|inc|dec|or|and|xor|bts|btr|btc)',
    re.IGNORECASE
)

# Pattern: member access between acquire/release *(type*)(base + offset)
_RE_MEMBER_ACCESS = re.compile(
    r'\*\s*\(\s*([\w ]+?)\s*\*\s*\)\s*\(\s*'
    r'(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)'
    r'\s*\)'
)

# Pattern: ptr->field access
_RE_ARROW_ACCESS = re.compile(
    r'(\w+)\s*->\s*(\w+)'
)

# Pattern: CreateThread(_, _, startRoutine, param, _, _)
_RE_CREATE_THREAD = re.compile(
    r'(?:CreateThread|_beginthreadex|CreateRemoteThread\w*)\s*\(\s*'
    r'(?:[^,]+,\s*){2}'                  # SecurityAttr, StackSize
    r'(\w+)'                              # lpStartAddress / start_address
    r'(?:\s*,\s*([^,\)]+))?',            # lpParameter (optional capture)
    re.IGNORECASE
)

# Pattern: _beginthread(startRoutine, stackSize, argList)
_RE_BEGINTHREAD = re.compile(
    r'_beginthread\s*\(\s*(\w+)\s*,',
    re.IGNORECASE
)

# Pattern: QueueUserWorkItem(callback, context, flags)
_RE_QUEUE_WORK = re.compile(
    r'(?:QueueUserWorkItem|TrySubmitThreadpoolCallback)\s*\(\s*(\w+)',
    re.IGNORECASE
)

# Pattern: TlsAlloc / TlsGetValue / TlsSetValue
_RE_TLS_ALLOC = re.compile(
    r'(\w+)\s*=\s*(?:Tls|Fls)Alloc\s*\(',
    re.IGNORECASE
)
_RE_TLS_GET = re.compile(
    r'(\w+)\s*=\s*(?:Tls|Fls)GetValue\s*\(\s*(\w+)',
    re.IGNORECASE
)
_RE_TLS_SET = re.compile(
    r'(?:Tls|Fls)SetValue\s*\(\s*(\w+)\s*,\s*(\w+)',
    re.IGNORECASE
)

# Pattern: Spin lock detection (tight loop with cmpxchg)
_RE_SPIN_LOOP = re.compile(
    r'(?:while|for)\s*\(.*?(?:Interlocked|cmpxchg|xchg).*?\)',
    re.IGNORECASE | re.DOTALL
)

# System classification by function name patterns
_SYSTEM_PATTERNS = {
    "Housing":     ["Housing", "House", "Decor", "Neighborhood", "Interior",
                    "Plot", "Steward"],
    "Quest":       ["Quest", "QuestGiver"],
    "Combat":      ["Spell", "Aura", "Attack", "Damage", "Heal", "Cast",
                    "Combat", "Weapon"],
    "Movement":    ["Move", "Movement", "Teleport", "Transport", "Flight",
                    "Path", "Navigate"],
    "Social":      ["Guild", "Chat", "Mail", "Friend", "Party", "Group",
                    "Raid", "Channel"],
    "Item":        ["Item", "Inventory", "Equip", "Bag", "Loot", "Container"],
    "PvP":         ["Battleground", "Arena", "PvP", "Honor", "Conquest"],
    "Auction":     ["Auction", "AuctionHouse"],
    "Crafting":    ["Trade", "Profession", "Craft", "Recipe", "Reagent"],
    "Achievement": ["Achievement", "Criteria"],
    "Pet":         ["Pet", "BattlePet", "Companion"],
    "Character":   ["Character", "Player", "Login", "Logout"],
    "NPC":         ["Creature", "Gossip", "Trainer", "Vendor", "NPC"],
    "Map":         ["Map", "Zone", "Area", "Instance", "Scenario", "Phase",
                    "Grid", "Cell"],
    "Network":     ["Socket", "Packet", "Session", "Opcode", "Network",
                    "Connection"],
    "Database":    ["Database", "MySQL", "Query", "Transaction", "PreparedStatement"],
    "World":       ["World", "WorldUpdate", "Tick", "Update"],
    "Object":      ["Object", "ObjectMgr", "ObjectGuid", "GUID"],
    "Garrison":    ["Garrison", "Follower", "Mission", "Shipment"],
    "Collection":  ["Collection", "Mount", "Toy", "Heirloom", "Transmog",
                    "Wardrobe"],
}

# Known TC mutexes/locks and their purpose (for comparison)
_TC_KNOWN_LOCKS = {
    "Map::_updateLock":             {"system": "Map", "type": "std::shared_mutex",
                                     "protects": "Map::_updateObjects, object visibility"},
    "World::_stopEvent":            {"system": "World", "type": "std::atomic<bool>",
                                     "protects": "Server shutdown flag"},
    "ObjectAccessor::_hashLock":    {"system": "Object", "type": "std::shared_mutex",
                                     "protects": "Global player/creature lookup hash maps"},
    "MapManager::_mapsLock":        {"system": "Map", "type": "std::mutex",
                                     "protects": "Map instance creation/destruction"},
    "SessionMap::_lock":            {"system": "Network", "type": "std::mutex",
                                     "protects": "Active session map"},
    "WorldPacketQueue::_lock":      {"system": "Network", "type": "std::mutex",
                                     "protects": "Inbound packet queue per session"},
    "MySQLConnection::_mutex":      {"system": "Database", "type": "std::mutex",
                                     "protects": "MySQL connection state"},
    "CharacterDatabaseWorkerPool":  {"system": "Database", "type": "ProducerConsumerQueue",
                                     "protects": "Async character DB queries"},
    "LoginDatabaseWorkerPool":      {"system": "Database", "type": "ProducerConsumerQueue",
                                     "protects": "Async login DB queries"},
    "WorldDatabaseWorkerPool":      {"system": "Database", "type": "ProducerConsumerQueue",
                                     "protects": "Async world DB queries"},
    "CliThread":                    {"system": "World", "type": "std::thread",
                                     "protects": "Console command processing"},
    "MapUpdateThread":              {"system": "Map", "type": "std::thread",
                                     "protects": "Per-map update tick"},
    "BattlegroundQueue::_lock":     {"system": "PvP", "type": "std::mutex",
                                     "protects": "BG queue state"},
    "AuctionHouseObject::_lock":    {"system": "Auction", "type": "std::mutex",
                                     "protects": "Auction listings per house"},
    "MailDraft::_lock":             {"system": "Social", "type": "std::mutex",
                                     "protects": "Pending mail delivery"},
    "GuildMgr::_lock":              {"system": "Social", "type": "std::mutex",
                                     "protects": "Guild creation/deletion"},
    "GroupMgr::_lock":              {"system": "Social", "type": "std::mutex",
                                     "protects": "Group/party management"},
}


# ---------------------------------------------------------------------------
# Helper: classify a function name into a game system
# ---------------------------------------------------------------------------

def _classify_system(func_name):
    """Map a function name to a game system based on keyword matching."""
    if not func_name:
        return "Unknown"
    upper = func_name.upper()
    for system, keywords in _SYSTEM_PATTERNS.items():
        for kw in keywords:
            if kw.upper() in upper:
                return system
    return "Unknown"


# ---------------------------------------------------------------------------
# Helper: resolve an import name from a call target address
# ---------------------------------------------------------------------------

def _get_import_name(ea):
    """Get the import/API name at the given address, following thunks."""
    name = ida_name.get_name(ea)
    if not name:
        return None
    # Strip IDA prefixes like j_, __imp_, etc.
    stripped = name
    for prefix in ("j_", "__imp_", "_imp_", "__imp__"):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
    return stripped


def _strip_func_name(name):
    """Strip common prefixes/decorations from a function name."""
    if not name:
        return name
    # Remove leading underscores (MSVC decoration)
    while name.startswith("_") and len(name) > 1:
        name = name[1:]
    # Remove trailing @N (stdcall decoration)
    at_idx = name.find("@")
    if at_idx > 0 and name[at_idx + 1:].isdigit():
        name = name[:at_idx]
    return name


# ---------------------------------------------------------------------------
# Phase 1: Lock Pattern Detection
# ---------------------------------------------------------------------------

def _find_sync_calls_in_function(func_ea):
    """Scan a function for calls to synchronization primitives.

    Returns a list of dicts: {
        "ea": instruction address,
        "callee_name": stripped API name,
        "callee_ea": target address,
        "raw_name": original IDA name,
        "category": "acquire"|"release"|"init"|"interlocked"|"thread"|"tls"|...
    }
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []

    results = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.XrefsFrom(head, 0):
            if xref.type not in (idaapi.fl_CN, idaapi.fl_CF):
                continue
            raw_name = _get_import_name(xref.to)
            if not raw_name:
                continue
            stripped = _strip_func_name(raw_name)
            if stripped not in _ALL_SYNC_FUNCS:
                continue

            category = _categorize_sync_call(stripped)
            results.append({
                "ea": head,
                "callee_name": stripped,
                "callee_ea": xref.to,
                "raw_name": raw_name,
                "category": category,
            })

    return results


def _categorize_sync_call(name):
    """Return the category string for a synchronization function name."""
    if name in _CS_ACQUIRE or name in _SRW_ACQUIRE or name in _STD_MUTEX_ACQUIRE:
        return "acquire"
    if name in _CS_RELEASE or name in _SRW_RELEASE or name in _STD_MUTEX_RELEASE:
        return "release"
    if name in _CS_INIT or name in _SRW_INIT or name in _STD_MUTEX_INIT:
        return "init"
    if name in _CS_DELETE or name in _STD_MUTEX_DESTROY:
        return "destroy"
    if name in _MUTEX_ACQUIRE:
        return "mutex_acquire"
    if name in _MUTEX_RELEASE:
        return "mutex_release"
    if name in _MUTEX_CREATE:
        return "mutex_create"
    if name in _INTERLOCKED_OPS:
        return "interlocked"
    if name in _CONDVAR_OPS:
        return "condvar"
    if name in _THREAD_CREATE:
        return "thread_create"
    if name in _THREAD_POOL:
        return "thread_pool"
    if name in _TLS_OPS:
        return "tls"
    return "other"


def _detect_lock_type(callee_name):
    """Determine the lock type from the synchronization function name."""
    if callee_name in _CS_ACQUIRE or callee_name in _CS_RELEASE or callee_name in _CS_INIT:
        return "CriticalSection"
    if callee_name in _SRW_ACQUIRE or callee_name in _SRW_RELEASE or callee_name in _SRW_INIT:
        if "Shared" in callee_name:
            return "SRWLock_Shared"
        return "SRWLock_Exclusive"
    if callee_name in _MUTEX_ACQUIRE or callee_name in _MUTEX_RELEASE or callee_name in _MUTEX_CREATE:
        return "KernelMutex"
    if callee_name in _STD_MUTEX_ACQUIRE or callee_name in _STD_MUTEX_RELEASE or callee_name in _STD_MUTEX_INIT:
        return "std::mutex"
    if callee_name in _INTERLOCKED_OPS:
        return "Interlocked"
    if "critical_section" in callee_name.lower():
        return "Concurrency::critical_section"
    return "Unknown"


def _extract_lock_variable_from_pseudocode(pseudocode, callee_name, call_ea):
    """Extract the lock variable address/offset from decompiled pseudocode.

    Searches for the synchronization call near the given address and extracts
    the first argument, which is typically the lock pointer.

    Returns a dict with keys: base, offset, field_name, or variable.
    """
    if not pseudocode:
        return {"variable": "unknown", "offset": None}

    # Search for the call in pseudocode
    for m in _RE_LOCK_CALL_OFFSET.finditer(pseudocode):
        api_name = m.group(1)
        # Rough match: skip if the API name doesn't match our callee
        if callee_name not in api_name and api_name not in callee_name:
            continue

        if m.group(2) and m.group(3):
            # base + offset form
            base = m.group(2)
            offset_str = m.group(3)
            offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
            return {"base": base, "offset": offset, "variable": f"{base}+0x{offset:X}"}
        elif m.group(4) and m.group(5):
            # ptr->field form
            return {"base": m.group(4), "field_name": m.group(5),
                    "variable": f"{m.group(4)}->{m.group(5)}"}
        elif m.group(6):
            # plain variable
            return {"variable": m.group(6), "offset": None}

    return {"variable": "unknown", "offset": None}


def _scan_lock_prefix_instructions(func_ea):
    """Scan a function's disassembly for lock-prefixed instructions (atomics).

    Returns a list of dicts with ea, mnemonic, and operands.
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []

    results = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        disasm = idc.GetDisasm(head)
        if not disasm:
            continue
        m = _RE_LOCK_PREFIX.search(disasm)
        if m:
            results.append({
                "ea": head,
                "instruction": m.group(0),
                "mnemonic": m.group(1),
                "full_disasm": disasm.strip(),
            })
    return results


def _detect_spin_locks(pseudocode, func_ea):
    """Detect spin lock patterns: tight loops with atomic compare-and-swap.

    Returns list of spin lock descriptions.
    """
    if not pseudocode:
        return []

    spin_locks = []

    # Pattern 1: while loop with InterlockedCompareExchange
    pattern1 = re.compile(
        r'(?:while|for)\s*\([^)]*?'
        r'(?:InterlockedCompareExchange|_InterlockedCompareExchange)\s*\('
        r'([^,]+)',
        re.IGNORECASE | re.DOTALL
    )
    for m in pattern1.finditer(pseudocode):
        spin_locks.append({
            "type": "spin_lock_interlocked",
            "variable": m.group(1).strip(),
            "function_ea": func_ea,
            "pattern": m.group(0)[:120],
        })

    # Pattern 2: loop with lock cmpxchg (in pseudocode sometimes shown as inline asm)
    pattern2 = re.compile(
        r'(?:do|while|for)\s*\{?\s*.*?'
        r'(?:lock\s+cmpxchg|__sync_val_compare_and_swap|__atomic_compare_exchange)',
        re.IGNORECASE | re.DOTALL
    )
    for m in pattern2.finditer(pseudocode):
        spin_locks.append({
            "type": "spin_lock_asm",
            "variable": "unknown",
            "function_ea": func_ea,
            "pattern": m.group(0)[:120],
        })

    # Pattern 3: _mm_pause / YieldProcessor in a tight loop (spin-wait hint)
    pattern3 = re.compile(
        r'(?:while|for)\s*\([^)]*\)\s*\{[^}]*?'
        r'(?:_mm_pause|YieldProcessor|__yield|_Pause)',
        re.IGNORECASE | re.DOTALL
    )
    for m in pattern3.finditer(pseudocode):
        spin_locks.append({
            "type": "spin_wait",
            "variable": "unknown",
            "function_ea": func_ea,
            "pattern": m.group(0)[:120],
        })

    return spin_locks


# ---------------------------------------------------------------------------
# Phase 2: Protected Data Identification
# ---------------------------------------------------------------------------

def _find_protected_data(pseudocode, acquire_calls, release_calls):
    """Analyze code between lock acquire and release to find protected data.

    For each acquire-release pair in the pseudocode, extract memory accesses
    (struct member reads/writes) that occur between them.

    Returns a list of protected region dicts.
    """
    if not pseudocode:
        return []

    lines = pseudocode.split("\n")
    regions = []

    # Build a list of line indices for acquire and release calls
    acquire_lines = []
    release_lines = []

    for i, line in enumerate(lines):
        for acq in acquire_calls:
            if acq["callee_name"] in line:
                acquire_lines.append((i, acq))
                break
        for rel in release_calls:
            if rel["callee_name"] in line:
                release_lines.append((i, rel))
                break

    # Pair each acquire with the nearest following release
    for acq_idx, acq_info in acquire_lines:
        best_rel = None
        best_rel_idx = len(lines) + 1
        for rel_idx, rel_info in release_lines:
            if rel_idx > acq_idx and rel_idx < best_rel_idx:
                best_rel_idx = rel_idx
                best_rel = rel_info

        if best_rel is None:
            # No release found — might be released in a different scope
            # Still analyze to end of function
            best_rel_idx = min(acq_idx + 100, len(lines))

        # Extract member accesses between acquire and release
        accessed_offsets = []
        accessed_fields = []
        protected_code = lines[acq_idx + 1:best_rel_idx]

        for line in protected_code:
            # *(type*)(base + offset) pattern
            for m in _RE_MEMBER_ACCESS.finditer(line):
                type_name = m.group(1).strip()
                base = m.group(2)
                offset_str = m.group(3)
                offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                accessed_offsets.append({
                    "base": base,
                    "offset": offset,
                    "type": type_name,
                    "is_write": "=" in line and line.index("=") < line.index(m.group(0)),
                })

            # ptr->field pattern
            for m in _RE_ARROW_ACCESS.finditer(line):
                field_name = m.group(2)
                # Skip the lock function itself
                if field_name in ("lock", "unlock", "Lock", "Unlock"):
                    continue
                accessed_fields.append({
                    "base": m.group(1),
                    "field": field_name,
                    "is_write": "=" in line and line.index("=") < line.index(m.group(0)),
                })

        if accessed_offsets or accessed_fields:
            regions.append({
                "lock_variable": acq_info.get("callee_name", "unknown"),
                "acquire_ea": acq_info.get("ea", 0),
                "release_ea": best_rel.get("ea", 0) if best_rel else 0,
                "accessed_offsets": accessed_offsets,
                "accessed_fields": accessed_fields,
                "line_span": best_rel_idx - acq_idx,
            })

    return regions


def _cross_reference_object_layouts(protected_regions, session):
    """Cross-reference protected data with known object layouts.

    If the object_layouts kv has been populated, map lock-protected offsets
    to known class fields.
    """
    layouts = session.db.kv_get("object_layouts")
    if not layouts:
        return

    layout_map = {}
    if isinstance(layouts, list):
        for layout in layouts:
            class_name = layout.get("class_name", "")
            if class_name:
                layout_map[class_name] = layout
    elif isinstance(layouts, dict):
        layout_map = layouts

    for region in protected_regions:
        for access in region.get("accessed_offsets", []):
            base = access.get("base", "")
            offset = access.get("offset", 0)

            # Try to match base variable to a known class
            for class_name, layout in layout_map.items():
                fields = layout.get("fields", [])
                for field in fields:
                    if field.get("offset") == offset:
                        access["resolved_class"] = class_name
                        access["resolved_field"] = field.get("name", f"field_0x{offset:X}")
                        break


# ---------------------------------------------------------------------------
# Phase 3: Thread Entry Point Detection
# ---------------------------------------------------------------------------

def _find_thread_entry_points(session, func_sync_map):
    """Find all thread creation points and their start routines.

    Scans functions that call CreateThread/_beginthreadex/etc. and extracts
    the thread start routine argument.

    Returns a list of thread entry point dicts.
    """
    thread_entries = []
    seen_start_routines = set()

    for func_ea, sync_calls in func_sync_map.items():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = ida_name.get_name(func.start_ea) or ea_str(func.start_ea)

        for call in sync_calls:
            if call["category"] not in ("thread_create", "thread_pool"):
                continue

            # Get the pseudocode to extract the start routine
            pseudocode = get_decompiled_text(func_ea)
            if not pseudocode:
                continue

            start_routines = _extract_thread_start_routines(pseudocode, call["callee_name"])
            for routine_info in start_routines:
                routine_name = routine_info.get("name", "unknown")
                if routine_name in seen_start_routines:
                    continue
                seen_start_routines.add(routine_name)

                # Try to resolve the routine address
                routine_ea = _resolve_function_ea(routine_name)
                system = _classify_system(routine_name)
                if system == "Unknown":
                    system = _classify_system(func_name)

                thread_entries.append({
                    "ea": routine_ea or 0,
                    "function_name": routine_name,
                    "creator_ea": func_ea,
                    "creator_name": func_name,
                    "creation_api": call["callee_name"],
                    "system": system,
                    "parameter": routine_info.get("parameter", ""),
                })

    return thread_entries


def _extract_thread_start_routines(pseudocode, api_name):
    """Extract thread start routine names from pseudocode containing thread creation."""
    results = []

    if api_name in ("CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx"):
        for m in _RE_CREATE_THREAD.finditer(pseudocode):
            results.append({
                "name": m.group(1),
                "parameter": m.group(2).strip() if m.group(2) else "",
            })

    elif api_name in ("_beginthreadex",):
        # _beginthreadex(security, stack_size, start_address, arglist, initflag, thrdaddr)
        pattern = re.compile(
            r'_beginthreadex\s*\(\s*'
            r'(?:[^,]+,\s*){2}'
            r'(\w+)',
            re.IGNORECASE
        )
        for m in pattern.finditer(pseudocode):
            results.append({"name": m.group(1), "parameter": ""})

    elif api_name == "_beginthread":
        for m in _RE_BEGINTHREAD.finditer(pseudocode):
            results.append({"name": m.group(1), "parameter": ""})

    elif api_name in ("QueueUserWorkItem", "TrySubmitThreadpoolCallback"):
        for m in _RE_QUEUE_WORK.finditer(pseudocode):
            results.append({"name": m.group(1), "parameter": ""})

    elif api_name in ("CreateThreadpoolWork", "SubmitThreadpoolWork"):
        pattern = re.compile(
            r'CreateThreadpoolWork\s*\(\s*(\w+)',
            re.IGNORECASE
        )
        for m in pattern.finditer(pseudocode):
            results.append({"name": m.group(1), "parameter": ""})

    return results


def _resolve_function_ea(name):
    """Try to resolve a function name to an address."""
    if not name or name == "unknown":
        return None
    ea = ida_name.get_name_ea(idaapi.BADADDR, name)
    if ea != idaapi.BADADDR:
        return ea
    # Try with common prefixes
    for prefix in ("", "j_", "_", "__"):
        ea = ida_name.get_name_ea(idaapi.BADADDR, prefix + name)
        if ea != idaapi.BADADDR:
            return ea
    return None


# ---------------------------------------------------------------------------
# Phase 4: Lock Hierarchy Analysis
# ---------------------------------------------------------------------------

def _analyze_lock_hierarchy(func_sync_map, lock_instances):
    """Build a lock hierarchy graph to detect potential deadlocks.

    A deadlock risk exists when:
    - Function A acquires Lock X then Lock Y
    - Function B acquires Lock Y then Lock X

    We build the graph of (outer_lock -> inner_lock) edges per function
    and check for cycles.
    """
    # Map: func_ea -> ordered list of (acquire/release, lock_variable, ea)
    func_lock_orders = {}

    for func_ea, sync_calls in func_sync_map.items():
        ordered = []
        for call in sync_calls:
            if call["category"] in ("acquire", "mutex_acquire"):
                ordered.append(("acquire", call.get("lock_variable", "unknown"), call["ea"]))
            elif call["category"] in ("release", "mutex_release"):
                ordered.append(("release", call.get("lock_variable", "unknown"), call["ea"]))

        if len(ordered) >= 2:
            func_lock_orders[func_ea] = ordered

    # Build hierarchy edges: when lock A is held and lock B is acquired
    hierarchy_edges = []
    held_locks_global = defaultdict(set)  # lock_var -> set of inner lock_vars

    for func_ea, ordered in func_lock_orders.items():
        func_name = ida_name.get_name(func_ea) or ea_str(func_ea)
        held_stack = []  # Stack of currently held lock variables

        for action, lock_var, ea in ordered:
            if action == "acquire":
                # Record hierarchy: all currently held locks are "outer"
                for outer_lock in held_stack:
                    if outer_lock != lock_var:
                        edge = {
                            "outer_lock": outer_lock,
                            "inner_lock": lock_var,
                            "function_ea": func_ea,
                            "function_name": func_name,
                            "instruction_ea": ea,
                            "deadlock_risk": False,
                        }
                        hierarchy_edges.append(edge)
                        held_locks_global[outer_lock].add(lock_var)

                held_stack.append(lock_var)

            elif action == "release":
                # Pop the most recent matching lock
                if lock_var in held_stack:
                    held_stack.remove(lock_var)

    # Check for cycles (potential deadlocks)
    deadlock_risks = []
    for edge in hierarchy_edges:
        outer = edge["outer_lock"]
        inner = edge["inner_lock"]
        # Check if the reverse ordering exists anywhere
        if outer in held_locks_global.get(inner, set()):
            edge["deadlock_risk"] = True
            deadlock_risks.append({
                "lock_a": outer,
                "lock_b": inner,
                "function_ea": edge["function_ea"],
                "function_name": edge["function_name"],
                "description": (
                    f"Potential deadlock: {outer} -> {inner} in {edge['function_name']}, "
                    f"but reverse ordering {inner} -> {outer} exists elsewhere"
                ),
            })

    return hierarchy_edges, deadlock_risks


# ---------------------------------------------------------------------------
# Phase 5: TLS Detection
# ---------------------------------------------------------------------------

def _find_tls_usage(func_sync_map):
    """Find all TLS (Thread Local Storage) usage.

    Detects TlsAlloc/TlsGetValue/TlsSetValue patterns and maps
    slot IDs to the functions that use them.
    """
    tls_slots = defaultdict(lambda: {
        "alloc_ea": None,
        "alloc_func": None,
        "access_functions": [],
        "set_functions": [],
        "system": "Unknown",
    })

    for func_ea, sync_calls in func_sync_map.items():
        func_name = ida_name.get_name(func_ea) or ea_str(func_ea)

        for call in sync_calls:
            if call["category"] != "tls":
                continue

            callee = call["callee_name"]
            pseudocode = get_decompiled_text(func_ea)
            if not pseudocode:
                continue

            if callee in ("TlsAlloc", "FlsAlloc"):
                # Extract the variable that receives the slot index
                for m in _RE_TLS_ALLOC.finditer(pseudocode):
                    slot_var = m.group(1)
                    slot_info = tls_slots[slot_var]
                    slot_info["alloc_ea"] = func_ea
                    slot_info["alloc_func"] = func_name
                    slot_info["system"] = _classify_system(func_name)

            elif callee in ("TlsGetValue", "FlsGetValue"):
                for m in _RE_TLS_GET.finditer(pseudocode):
                    result_var = m.group(1)
                    slot_var = m.group(2)
                    slot_info = tls_slots[slot_var]
                    if func_name not in slot_info["access_functions"]:
                        slot_info["access_functions"].append(func_name)
                    if slot_info["system"] == "Unknown":
                        slot_info["system"] = _classify_system(func_name)

            elif callee in ("TlsSetValue", "FlsSetValue"):
                for m in _RE_TLS_SET.finditer(pseudocode):
                    slot_var = m.group(1)
                    value_var = m.group(2)
                    slot_info = tls_slots[slot_var]
                    if func_name not in slot_info["set_functions"]:
                        slot_info["set_functions"].append(func_name)
                    if slot_info["system"] == "Unknown":
                        slot_info["system"] = _classify_system(func_name)

    # Also detect __declspec(thread) variables via TLS directory
    tls_dir_vars = _scan_tls_directory()

    return tls_slots, tls_dir_vars


def _scan_tls_directory():
    """Scan the PE TLS directory for __declspec(thread) variables.

    These are stored in the .tls section and the TLS directory of the PE.
    """
    tls_vars = []

    # Find .tls segment
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        if seg_name in (".tls", "_tls", "TLS"):
            # Iterate through TLS data
            ea = seg.start_ea
            while ea < seg.end_ea:
                name = ida_name.get_name(ea)
                if name:
                    tls_vars.append({
                        "ea": ea,
                        "name": name,
                        "segment": seg_name,
                        "system": _classify_system(name),
                    })
                ea += 8  # Advance by pointer size on x64

    return tls_vars


# ---------------------------------------------------------------------------
# Phase 6: TC Thread Safety Comparison
# ---------------------------------------------------------------------------

def _compare_with_tc_locks(lock_instances, thread_entries, session):
    """Compare binary's threading model with known TC locks.

    Identifies:
    - TC systems that use locks where binary also uses locks (expected)
    - TC systems that are single-threaded but binary uses threading (risk!)
    - Binary locks without TC equivalents (missing TC implementation)
    """
    comparison = {
        "matched_locks": [],
        "tc_only_locks": [],
        "binary_only_locks": [],
        "threading_mismatches": [],
    }

    # Build a system -> lock map from binary findings
    binary_lock_systems = defaultdict(list)
    for lock in lock_instances:
        system = lock.get("system", "Unknown")
        if system != "Unknown":
            binary_lock_systems[system].append(lock)

    # Build a system -> lock map from TC known locks
    tc_lock_systems = defaultdict(list)
    for lock_name, info in _TC_KNOWN_LOCKS.items():
        tc_lock_systems[info["system"]].append({
            "name": lock_name,
            "type": info["type"],
            "protects": info["protects"],
        })

    # Compare systems
    all_systems = set(binary_lock_systems.keys()) | set(tc_lock_systems.keys())
    for system in sorted(all_systems):
        binary_locks = binary_lock_systems.get(system, [])
        tc_locks = tc_lock_systems.get(system, [])

        if binary_locks and tc_locks:
            comparison["matched_locks"].append({
                "system": system,
                "binary_lock_count": len(binary_locks),
                "tc_lock_count": len(tc_locks),
                "tc_locks": [l["name"] for l in tc_locks],
            })
        elif tc_locks and not binary_locks:
            comparison["tc_only_locks"].append({
                "system": system,
                "tc_locks": [l["name"] for l in tc_locks],
                "note": "TC uses locks but binary may use a different mechanism",
            })
        elif binary_locks and not tc_locks:
            comparison["binary_only_locks"].append({
                "system": system,
                "binary_lock_count": len(binary_locks),
                "lock_types": list(set(l.get("type", "unknown") for l in binary_locks)),
                "note": "Binary uses locks but TC may be missing thread safety",
            })

    # Check for systems that have threads in binary but no locks in TC
    binary_thread_systems = set()
    for entry in thread_entries:
        system = entry.get("system", "Unknown")
        if system != "Unknown":
            binary_thread_systems.add(system)

    for system in binary_thread_systems:
        if system not in tc_lock_systems:
            comparison["threading_mismatches"].append({
                "system": system,
                "has_binary_threads": True,
                "has_tc_locks": False,
                "risk": "HIGH",
                "note": f"Binary runs {system} on separate threads but TC has no known locks",
            })

    return comparison


# ---------------------------------------------------------------------------
# Contention Hotspot Analysis
# ---------------------------------------------------------------------------

def _find_contention_hotspots(lock_instances, func_sync_map):
    """Identify locks that are acquired in many different functions.

    High acquire counts indicate potential contention hotspots.
    """
    # Group lock instances by their variable identifier
    lock_usage = defaultdict(lambda: {
        "acquire_count": 0,
        "functions": set(),
        "systems": set(),
        "lock_type": "unknown",
    })

    for lock in lock_instances:
        lock_var = lock.get("variable", "unknown")
        if lock_var == "unknown":
            continue
        usage = lock_usage[lock_var]
        usage["acquire_count"] += 1
        func_name = lock.get("function_name", "")
        if func_name:
            usage["functions"].add(func_name)
        system = lock.get("system", "Unknown")
        if system != "Unknown":
            usage["systems"].add(system)
        usage["lock_type"] = lock.get("type", "unknown")

    # Convert to sorted list, highest contention first
    hotspots = []
    for lock_var, usage in lock_usage.items():
        if usage["acquire_count"] >= 2:  # Only report locks used in 2+ places
            hotspots.append({
                "lock_variable": lock_var,
                "acquire_count": usage["acquire_count"],
                "function_count": len(usage["functions"]),
                "functions": sorted(usage["functions"]),
                "systems_involved": sorted(usage["systems"]),
                "lock_type": usage["lock_type"],
            })

    hotspots.sort(key=lambda h: h["acquire_count"], reverse=True)
    return hotspots


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def map_thread_safety(session):
    """Analyze the binary for thread safety patterns and synchronization primitives.

    Scans all functions for:
      1. Lock acquire/release patterns (CriticalSection, SRW, mutex, std::mutex)
      2. Interlocked operations and atomic instructions
      3. Thread creation points and start routines
      4. Lock hierarchy and potential deadlocks
      5. TLS usage
      6. Comparison with known TC locking discipline

    Results are stored in session.db.kv_set("thread_safety_map", {...}).

    Returns the total number of synchronization primitives found.
    """
    db = session.db
    t0 = time.time()

    msg_info("=== Thread Safety Map: Starting analysis ===")

    # -----------------------------------------------------------------------
    # Step 1: Find all functions that reference synchronization primitives
    # -----------------------------------------------------------------------
    msg_info("Phase 1: Scanning for synchronization primitives...")

    # First, locate the imported synchronization functions and find their xrefs
    sync_import_eas = {}  # api_name -> [import EA, ...]
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        # Check import segments (.idata, .rdata, extern, IMPORTS)
        if seg_name not in (".idata", ".rdata", "extern", "IMPORTS", ".text"):
            # Also scan .text for thunks
            if seg_name != ".text":
                continue

        for head in idautils.Heads(seg.start_ea, seg.end_ea):
            name = _get_import_name(head)
            if not name:
                continue
            stripped = _strip_func_name(name)
            if stripped in _ALL_SYNC_FUNCS:
                if stripped not in sync_import_eas:
                    sync_import_eas[stripped] = []
                sync_import_eas[stripped].append(head)

    msg_info(f"  Found {len(sync_import_eas)} distinct sync API imports")

    # Find all functions that call any sync primitive via xrefs
    func_sync_map = defaultdict(list)   # func_ea -> [sync_call_info, ...]
    funcs_with_sync = set()

    for api_name, import_eas in sync_import_eas.items():
        for import_ea in import_eas:
            for xref in idautils.XrefsTo(import_ea, 0):
                caller_func = ida_funcs.get_func(xref.frm)
                if not caller_func:
                    continue
                func_ea = caller_func.start_ea
                funcs_with_sync.add(func_ea)

                category = _categorize_sync_call(api_name)
                func_sync_map[func_ea].append({
                    "ea": xref.frm,
                    "callee_name": api_name,
                    "callee_ea": import_ea,
                    "raw_name": api_name,
                    "category": category,
                })

    msg_info(f"  Found {len(funcs_with_sync)} functions using sync primitives")

    # -----------------------------------------------------------------------
    # Step 2: Build lock instance records
    # -----------------------------------------------------------------------
    msg_info("Phase 2: Building lock instance records...")

    lock_instances = []
    all_protected_regions = []
    spin_lock_count = 0

    progress_count = 0
    total_funcs = len(funcs_with_sync)
    progress_interval = max(1, total_funcs // 20)

    for func_ea in funcs_with_sync:
        progress_count += 1
        if progress_count % progress_interval == 0:
            msg_info(f"  Progress: {progress_count}/{total_funcs} functions analyzed")

        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = ida_name.get_name(func.start_ea) or ea_str(func.start_ea)
        system = _classify_system(func_name)
        sync_calls = func_sync_map[func_ea]

        # Get pseudocode (cached by IDA after first decompilation)
        pseudocode = get_decompiled_text(func_ea)

        # Separate acquires and releases
        acquire_calls = [c for c in sync_calls if c["category"] in ("acquire", "mutex_acquire")]
        release_calls = [c for c in sync_calls if c["category"] in ("release", "mutex_release")]
        interlocked_calls = [c for c in sync_calls if c["category"] == "interlocked"]
        init_calls = [c for c in sync_calls if c["category"] in ("init", "mutex_create")]

        # Extract lock variable info from pseudocode for acquire calls
        for acq in acquire_calls:
            lock_var = _extract_lock_variable_from_pseudocode(
                pseudocode, acq["callee_name"], acq["ea"]
            )
            acq["lock_variable"] = lock_var.get("variable", "unknown")

            lock_type = _detect_lock_type(acq["callee_name"])
            lock_instances.append({
                "type": lock_type,
                "ea": acq["ea"],
                "variable": lock_var.get("variable", "unknown"),
                "variable_offset": lock_var.get("offset"),
                "variable_base": lock_var.get("base", ""),
                "function_ea": func_ea,
                "function_name": func_name,
                "system": system,
                "callee_name": acq["callee_name"],
            })

        # Interlocked operations as lock instances too
        for il in interlocked_calls:
            lock_var = {"variable": "unknown", "offset": None}
            if pseudocode:
                for m in _RE_INTERLOCKED_OFFSET.finditer(pseudocode):
                    if m.group(1) and m.group(2):
                        offset_str = m.group(2)
                        offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                        lock_var = {
                            "variable": f"{m.group(1)}+0x{offset:X}",
                            "offset": offset,
                            "base": m.group(1),
                        }
                        break
                    elif m.group(3) and m.group(4):
                        lock_var = {
                            "variable": f"{m.group(3)}->{m.group(4)}",
                            "offset": None,
                            "base": m.group(3),
                            "field": m.group(4),
                        }
                        break
                    elif m.group(5):
                        lock_var = {
                            "variable": m.group(5),
                            "offset": None,
                        }
                        break

            lock_instances.append({
                "type": "Interlocked",
                "ea": il["ea"],
                "variable": lock_var.get("variable", "unknown"),
                "variable_offset": lock_var.get("offset"),
                "variable_base": lock_var.get("base", ""),
                "function_ea": func_ea,
                "function_name": func_name,
                "system": system,
                "callee_name": il["callee_name"],
            })

        # Init calls — record lock initialization sites
        for init_call in init_calls:
            lock_var = _extract_lock_variable_from_pseudocode(
                pseudocode, init_call["callee_name"], init_call["ea"]
            )
            lock_type = _detect_lock_type(init_call["callee_name"])
            lock_instances.append({
                "type": lock_type,
                "ea": init_call["ea"],
                "variable": lock_var.get("variable", "unknown"),
                "variable_offset": lock_var.get("offset"),
                "variable_base": lock_var.get("base", ""),
                "function_ea": func_ea,
                "function_name": func_name,
                "system": system,
                "callee_name": init_call["callee_name"],
                "is_init": True,
            })

        # Find protected data regions
        if acquire_calls and pseudocode:
            regions = _find_protected_data(pseudocode, acquire_calls, release_calls)
            for region in regions:
                region["function_ea"] = func_ea
                region["function_name"] = func_name
                region["system"] = system
            all_protected_regions.extend(regions)

        # Detect spin locks
        if pseudocode:
            spins = _detect_spin_locks(pseudocode, func_ea)
            for spin in spins:
                spin["function_name"] = func_name
                spin["system"] = system
                lock_instances.append({
                    "type": "SpinLock",
                    "ea": func_ea,
                    "variable": spin.get("variable", "unknown"),
                    "variable_offset": None,
                    "variable_base": "",
                    "function_ea": func_ea,
                    "function_name": func_name,
                    "system": system,
                    "callee_name": "spin_lock",
                    "spin_pattern": spin.get("pattern", ""),
                })
                spin_lock_count += 1

        # Detect lock-prefix atomic instructions
        lock_prefix_insns = _scan_lock_prefix_instructions(func_ea)
        for lpi in lock_prefix_insns:
            lock_instances.append({
                "type": "AtomicInstruction",
                "ea": lpi["ea"],
                "variable": lpi.get("full_disasm", ""),
                "variable_offset": None,
                "variable_base": "",
                "function_ea": func_ea,
                "function_name": func_name,
                "system": system,
                "callee_name": f"lock_{lpi['mnemonic']}",
                "disasm": lpi["full_disasm"],
            })

    msg_info(f"  Found {len(lock_instances)} lock instances "
             f"({spin_lock_count} spin locks)")
    msg_info(f"  Found {len(all_protected_regions)} protected data regions")

    # Cross-reference with object layouts
    _cross_reference_object_layouts(all_protected_regions, session)

    # -----------------------------------------------------------------------
    # Step 3: Thread entry point detection
    # -----------------------------------------------------------------------
    msg_info("Phase 3: Detecting thread entry points...")

    thread_entries = _find_thread_entry_points(session, func_sync_map)
    msg_info(f"  Found {len(thread_entries)} thread entry points")

    # -----------------------------------------------------------------------
    # Step 4: Lock hierarchy analysis
    # -----------------------------------------------------------------------
    msg_info("Phase 4: Analyzing lock hierarchy...")

    # Enrich func_sync_map with lock variable info for hierarchy analysis
    for func_ea in func_sync_map:
        for call in func_sync_map[func_ea]:
            if "lock_variable" not in call:
                # Find matching lock instance
                for lock in lock_instances:
                    if lock["ea"] == call["ea"] and lock["function_ea"] == func_ea:
                        call["lock_variable"] = lock.get("variable", "unknown")
                        break
                else:
                    call["lock_variable"] = "unknown"

    hierarchy_edges, deadlock_risks = _analyze_lock_hierarchy(func_sync_map, lock_instances)
    msg_info(f"  Found {len(hierarchy_edges)} lock ordering edges, "
             f"{len(deadlock_risks)} potential deadlock risks")

    # -----------------------------------------------------------------------
    # Step 5: TLS detection
    # -----------------------------------------------------------------------
    msg_info("Phase 5: Detecting TLS usage...")

    tls_slots, tls_dir_vars = _find_tls_usage(func_sync_map)
    msg_info(f"  Found {len(tls_slots)} TLS slot variables, "
             f"{len(tls_dir_vars)} __declspec(thread) variables")

    # -----------------------------------------------------------------------
    # Step 6: TC comparison
    # -----------------------------------------------------------------------
    msg_info("Phase 6: Comparing with TC threading model...")

    tc_comparison = _compare_with_tc_locks(lock_instances, thread_entries, session)

    # -----------------------------------------------------------------------
    # Step 7: Contention hotspot analysis
    # -----------------------------------------------------------------------
    msg_info("Phase 7: Identifying contention hotspots...")

    contention_hotspots = _find_contention_hotspots(lock_instances, func_sync_map)
    msg_info(f"  Found {len(contention_hotspots)} contention hotspots")

    # -----------------------------------------------------------------------
    # Build per-system summary
    # -----------------------------------------------------------------------
    system_summary = defaultdict(lambda: {
        "lock_count": 0,
        "thread_count": 0,
        "interlocked_count": 0,
        "atomic_insn_count": 0,
        "spin_lock_count": 0,
        "protected_region_count": 0,
        "lock_types": set(),
    })

    for lock in lock_instances:
        system = lock.get("system", "Unknown")
        summary = system_summary[system]
        lock_type = lock.get("type", "unknown")
        if lock_type in ("Interlocked",):
            summary["interlocked_count"] += 1
        elif lock_type in ("AtomicInstruction",):
            summary["atomic_insn_count"] += 1
        elif lock_type == "SpinLock":
            summary["spin_lock_count"] += 1
        else:
            summary["lock_count"] += 1
        summary["lock_types"].add(lock_type)

    for entry in thread_entries:
        system = entry.get("system", "Unknown")
        system_summary[system]["thread_count"] += 1

    for region in all_protected_regions:
        system = region.get("system", "Unknown")
        system_summary[system]["protected_region_count"] += 1

    # Convert sets to lists for JSON
    system_summary_serializable = {}
    for system, summary in system_summary.items():
        summary_copy = dict(summary)
        summary_copy["lock_types"] = sorted(summary_copy["lock_types"])
        system_summary_serializable[system] = summary_copy

    # -----------------------------------------------------------------------
    # Serialize lock instances for storage (ea as hex strings for readability)
    # -----------------------------------------------------------------------
    lock_instances_serializable = []
    for lock in lock_instances:
        entry = dict(lock)
        entry["ea"] = ea_str(lock["ea"])
        entry["function_ea"] = ea_str(lock["function_ea"])
        lock_instances_serializable.append(entry)

    protected_regions_serializable = []
    for region in all_protected_regions:
        entry = dict(region)
        entry["acquire_ea"] = ea_str(region.get("acquire_ea", 0))
        entry["release_ea"] = ea_str(region.get("release_ea", 0))
        entry["function_ea"] = ea_str(region.get("function_ea", 0))
        protected_regions_serializable.append(entry)

    thread_entries_serializable = []
    for entry in thread_entries:
        te = dict(entry)
        te["ea"] = ea_str(entry.get("ea", 0))
        te["creator_ea"] = ea_str(entry.get("creator_ea", 0))
        thread_entries_serializable.append(te)

    hierarchy_serializable = []
    for edge in hierarchy_edges:
        he = dict(edge)
        he["function_ea"] = ea_str(edge.get("function_ea", 0))
        he["instruction_ea"] = ea_str(edge.get("instruction_ea", 0))
        hierarchy_serializable.append(he)

    deadlock_serializable = []
    for risk in deadlock_risks:
        dr = dict(risk)
        dr["function_ea"] = ea_str(risk.get("function_ea", 0))
        deadlock_serializable.append(dr)

    tls_serializable = []
    for slot_var, info in tls_slots.items():
        tls_entry = dict(info)
        tls_entry["slot_variable"] = slot_var
        if tls_entry.get("alloc_ea"):
            tls_entry["alloc_ea"] = ea_str(tls_entry["alloc_ea"])
        tls_serializable.append(tls_entry)

    tls_dir_serializable = []
    for var in tls_dir_vars:
        tdv = dict(var)
        tdv["ea"] = ea_str(var.get("ea", 0))
        tls_dir_serializable.append(tdv)

    contention_serializable = contention_hotspots  # Already JSON-safe

    elapsed = time.time() - t0

    # -----------------------------------------------------------------------
    # Store results
    # -----------------------------------------------------------------------
    result = {
        "lock_instances": lock_instances_serializable,
        "protected_regions": protected_regions_serializable,
        "thread_entry_points": thread_entries_serializable,
        "lock_hierarchy": hierarchy_serializable,
        "deadlock_risks": deadlock_serializable,
        "tls_variables": tls_serializable,
        "tls_directory_vars": tls_dir_serializable,
        "contention_hotspots": contention_serializable,
        "tc_comparison": tc_comparison,
        "system_summary": system_summary_serializable,
        "total_locks": len(lock_instances),
        "total_threads": len(thread_entries),
        "total_protected_regions": len(all_protected_regions),
        "deadlock_risk_count": len(deadlock_risks),
        "spin_lock_count": spin_lock_count,
        "analysis_time_seconds": round(elapsed, 2),
    }

    db.kv_set("thread_safety_map", result)

    # Print summary
    msg_info(f"=== Thread Safety Map: Complete ({elapsed:.1f}s) ===")
    msg_info(f"  Total lock instances:     {len(lock_instances)}")
    msg_info(f"  Protected data regions:   {len(all_protected_regions)}")
    msg_info(f"  Thread entry points:      {len(thread_entries)}")
    msg_info(f"  Lock hierarchy edges:     {len(hierarchy_edges)}")
    msg_info(f"  Deadlock risks:           {len(deadlock_risks)}")
    msg_info(f"  TLS variables:            {len(tls_slots) + len(tls_dir_vars)}")
    msg_info(f"  Contention hotspots:      {len(contention_hotspots)}")
    msg_info(f"  Spin locks:               {spin_lock_count}")

    if system_summary_serializable:
        msg_info("  Per-system breakdown:")
        for system in sorted(system_summary_serializable.keys()):
            s = system_summary_serializable[system]
            parts = []
            if s["lock_count"]:
                parts.append(f"{s['lock_count']} locks")
            if s["interlocked_count"]:
                parts.append(f"{s['interlocked_count']} interlocked")
            if s["atomic_insn_count"]:
                parts.append(f"{s['atomic_insn_count']} atomic insns")
            if s["thread_count"]:
                parts.append(f"{s['thread_count']} threads")
            if s["spin_lock_count"]:
                parts.append(f"{s['spin_lock_count']} spin locks")
            if parts:
                msg_info(f"    {system}: {', '.join(parts)}")

    if deadlock_risks:
        msg_warn("  DEADLOCK RISKS DETECTED:")
        for risk in deadlock_risks[:10]:
            msg_warn(f"    {risk['description']}")

    if tc_comparison.get("threading_mismatches"):
        msg_warn("  TC THREADING MISMATCHES:")
        for mismatch in tc_comparison["threading_mismatches"]:
            msg_warn(f"    {mismatch['system']}: {mismatch['note']}")

    total_count = len(lock_instances)
    return total_count


# ---------------------------------------------------------------------------
# Report accessor
# ---------------------------------------------------------------------------

def get_thread_safety_report(session):
    """Retrieve the stored thread safety map data.

    Returns the full analysis dict, or an empty dict if not yet analyzed.
    """
    return session.db.kv_get("thread_safety_map") or {}


def get_thread_safety_summary(session):
    """Get a concise summary of thread safety findings.

    Returns a dict with high-level counts and key findings.
    """
    report = get_thread_safety_report(session)
    if not report:
        return {"status": "not_analyzed"}

    summary = {
        "status": "analyzed",
        "total_locks": report.get("total_locks", 0),
        "total_threads": report.get("total_threads", 0),
        "total_protected_regions": report.get("total_protected_regions", 0),
        "deadlock_risks": report.get("deadlock_risk_count", 0),
        "spin_locks": report.get("spin_lock_count", 0),
        "contention_hotspots": len(report.get("contention_hotspots", [])),
        "tls_variables": len(report.get("tls_variables", [])),
        "analysis_time": report.get("analysis_time_seconds", 0),
    }

    # Add system breakdown
    system_summary = report.get("system_summary", {})
    if system_summary:
        threaded_systems = []
        for system, info in system_summary.items():
            if info.get("thread_count", 0) > 0 or info.get("lock_count", 0) > 0:
                threaded_systems.append(system)
        summary["threaded_systems"] = sorted(threaded_systems)

    # Add top contention hotspots
    hotspots = report.get("contention_hotspots", [])
    if hotspots:
        summary["top_contention"] = [
            {
                "lock": h["lock_variable"],
                "acquires": h["acquire_count"],
                "functions": h["function_count"],
            }
            for h in hotspots[:5]
        ]

    # Add deadlock risk descriptions
    risks = report.get("deadlock_risks", [])
    if risks:
        summary["deadlock_descriptions"] = [r["description"] for r in risks[:5]]

    # Add TC comparison highlights
    tc_comp = report.get("tc_comparison", {})
    if tc_comp:
        mismatches = tc_comp.get("threading_mismatches", [])
        if mismatches:
            summary["tc_mismatches"] = [
                {"system": m["system"], "note": m["note"]}
                for m in mismatches
            ]
        binary_only = tc_comp.get("binary_only_locks", [])
        if binary_only:
            summary["binary_only_lock_systems"] = [b["system"] for b in binary_only]

    return summary


def get_locks_for_system(session, system_name):
    """Get all lock instances for a specific game system.

    Args:
        system_name: e.g. "Housing", "Combat", "Map", "Network"

    Returns list of lock instance dicts for that system.
    """
    report = get_thread_safety_report(session)
    if not report:
        return []

    system_upper = system_name.upper()
    return [
        lock for lock in report.get("lock_instances", [])
        if lock.get("system", "").upper() == system_upper
    ]


def get_threads_for_system(session, system_name):
    """Get all thread entry points for a specific game system.

    Args:
        system_name: e.g. "Map", "Database", "Network"

    Returns list of thread entry point dicts for that system.
    """
    report = get_thread_safety_report(session)
    if not report:
        return []

    system_upper = system_name.upper()
    return [
        entry for entry in report.get("thread_entry_points", [])
        if entry.get("system", "").upper() == system_upper
    ]


def get_deadlock_risks(session):
    """Get all detected deadlock risks.

    Returns list of deadlock risk dicts with lock names and descriptions.
    """
    report = get_thread_safety_report(session)
    if not report:
        return []
    return report.get("deadlock_risks", [])


def get_protected_data_for_lock(session, lock_variable):
    """Get the data protected by a specific lock.

    Args:
        lock_variable: The lock variable identifier string.

    Returns list of protected region dicts showing accessed offsets/fields.
    """
    report = get_thread_safety_report(session)
    if not report:
        return []

    return [
        region for region in report.get("protected_regions", [])
        if lock_variable in str(region.get("lock_variable", ""))
    ]
