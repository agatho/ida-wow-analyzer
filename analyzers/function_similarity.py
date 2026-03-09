"""
Function Similarity Analyzer
Groups functions by structural similarity to find copy-paste patterns,
template instantiations, and functionally equivalent code in the WoW x64 binary.

Produces clusters of structurally similar functions that can reveal:
  - Template instantiations (same structure, different type constants)
  - Copy-pasted handlers (identical structure, different string refs)
  - Shared handler patterns (CMSG handlers with identical flow)
  - Refactoring opportunities (merge duplicated logic)

Limits analysis to handler callees and named functions (~5000-10000) rather
than attempting to fingerprint all 115K+ functions in the binary.
"""

import json
import re
import time
import hashlib
from collections import defaultdict

import ida_funcs
import ida_name
import ida_bytes
import ida_gdl
import ida_xref
import idautils
import idaapi

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum function size in bytes to consider for clustering (skip trivial
# getters, stubs, thunks, etc.)
MIN_FUNC_SIZE = 32

# Size quantization bucket width for fingerprinting.  Two functions whose
# sizes are in the same 64-byte bucket will share that fingerprint component.
SIZE_BUCKET_WIDTH = 64

# Jaccard similarity threshold for near-match merging
NEAR_MATCH_THRESHOLD = 0.85

# Maximum number of functions to analyze (0 = no cap, analyze all)
MAX_FUNCTIONS_TO_ANALYZE = 0

# Maximum number of constants to collect per function
MAX_CONSTANTS_PER_FUNC = 128

# Maximum number of string refs to collect per function
MAX_STRINGS_PER_FUNC = 64

# Maximum decompilation attempts for handler-only structural fingerprints
MAX_DECOMP_ATTEMPTS = 2000

# Mnemonic categories for instruction class histograms.  Instructions are
# grouped into broad categories so that functionally equivalent code compiled
# with slightly different register allocation still fingerprints the same.
MNEMONIC_CATEGORIES = {
    # Data movement
    "mov": "data_mov", "movzx": "data_mov", "movsx": "data_mov",
    "movsxd": "data_mov", "movabs": "data_mov", "movaps": "data_mov",
    "movups": "data_mov", "movdqa": "data_mov", "movdqu": "data_mov",
    "movsd": "data_mov", "movss": "data_mov", "movq": "data_mov",
    "movd": "data_mov", "cmovz": "data_mov", "cmovnz": "data_mov",
    "cmova": "data_mov", "cmovb": "data_mov", "cmovae": "data_mov",
    "cmovbe": "data_mov", "cmovg": "data_mov", "cmovl": "data_mov",
    "cmovge": "data_mov", "cmovle": "data_mov", "cmovs": "data_mov",
    "cmovns": "data_mov",

    # LEA
    "lea": "lea",

    # Stack ops
    "push": "stack", "pop": "stack",

    # Arithmetic
    "add": "arith", "sub": "arith", "inc": "arith", "dec": "arith",
    "imul": "arith", "mul": "arith", "idiv": "arith", "div": "arith",
    "neg": "arith", "adc": "arith", "sbb": "arith",

    # Logic / bitwise
    "and": "logic", "or": "logic", "xor": "logic", "not": "logic",
    "shl": "logic", "shr": "logic", "sar": "logic", "sal": "logic",
    "rol": "logic", "ror": "logic", "bt": "logic", "bts": "logic",
    "btr": "logic", "bsf": "logic", "bsr": "logic",

    # Comparison / test
    "cmp": "compare", "test": "compare",

    # Call
    "call": "call",

    # Jump / branch
    "jmp": "branch", "jz": "branch", "jnz": "branch", "ja": "branch",
    "jb": "branch", "jae": "branch", "jbe": "branch", "jg": "branch",
    "jl": "branch", "jge": "branch", "jle": "branch", "js": "branch",
    "jns": "branch", "jp": "branch", "jnp": "branch", "jcxz": "branch",
    "jecxz": "branch", "jrcxz": "branch", "loop": "branch",
    "loopz": "branch", "loopnz": "branch",

    # Return
    "ret": "ret", "retn": "ret",

    # NOP
    "nop": "nop",

    # SSE / floating point
    "addss": "float", "subss": "float", "mulss": "float", "divss": "float",
    "addsd": "float", "subsd": "float", "mulsd": "float", "divsd": "float",
    "addps": "float", "subps": "float", "mulps": "float", "divps": "float",
    "addpd": "float", "subpd": "float", "mulpd": "float", "divpd": "float",
    "comiss": "float", "comisd": "float", "ucomiss": "float",
    "ucomisd": "float", "cvtsi2ss": "float", "cvtsi2sd": "float",
    "cvttss2si": "float", "cvttsd2si": "float", "cvtss2sd": "float",
    "cvtsd2ss": "float", "sqrtss": "float", "sqrtsd": "float",
    "xorps": "float", "xorpd": "float", "andps": "float", "andpd": "float",
    "orps": "float", "orpd": "float", "pxor": "float",
    "pcmpeqd": "float", "pcmpeqb": "float", "pcmpeqw": "float",
    "punpcklbw": "float", "punpcklwd": "float", "punpckldq": "float",
    "punpcklqdq": "float", "pshufd": "float", "shufps": "float",
    "shufpd": "float", "unpcklps": "float", "unpcklpd": "float",

    # String ops
    "rep": "string_op", "repz": "string_op", "repnz": "string_op",
    "stosb": "string_op", "stosw": "string_op", "stosd": "string_op",
    "stosq": "string_op", "movsb": "string_op", "movsw": "string_op",
    "movsd_rep": "string_op", "movsq": "string_op", "cmpsb": "string_op",
    "scasb": "string_op",

    # Misc
    "int": "misc", "syscall": "misc", "cpuid": "misc", "rdtsc": "misc",
    "lfence": "misc", "sfence": "misc", "mfence": "misc",
    "lock": "misc", "xchg": "misc", "cmpxchg": "misc",
    "bswap": "misc", "cdq": "misc", "cqo": "misc", "cdqe": "misc",
    "cwde": "misc",
}


# ---------------------------------------------------------------------------
# Fingerprinting helpers
# ---------------------------------------------------------------------------

def _categorize_mnemonic(mnemonic):
    """Map a mnemonic string to its broad category."""
    mn = mnemonic.lower()
    return MNEMONIC_CATEGORIES.get(mn, "other")


def _get_cfg_metrics(func):
    """Compute basic block count and edge count from the CFG.

    Returns (bb_count, edge_count) or (0, 0) on failure.
    """
    try:
        flowchart = ida_gdl.FlowChart(func, flags=ida_gdl.FC_PREDS)
    except Exception:
        return 0, 0

    bb_count = 0
    edge_count = 0
    for block in flowchart:
        bb_count += 1
        # Count successors (IDA 9: iterate succs(), older: nsucc())
        try:
            edge_count += sum(1 for _ in block.succs())
        except AttributeError:
            try:
                edge_count += block.nsucc()
            except AttributeError:
                pass

    return bb_count, edge_count


def _get_call_pattern(func):
    """Extract ordered list of (callee_ea, callee_name) for call instructions.

    Returns list of callee names (or hex addresses for unnamed callees).
    """
    callees = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        mnem = idautils.DecodeInstruction(head)
        if mnem is None:
            continue
        mnem_str = mnem.get_canon_mnem()
        if mnem_str and mnem_str.lower() == "call":
            for xref in idautils.XrefsFrom(head, 0):
                if xref.type in (ida_xref.fl_CF, ida_xref.fl_CN):
                    target_name = ida_name.get_name(xref.to)
                    if target_name:
                        callees.append(target_name)
                    else:
                        callees.append(f"sub_{xref.to:X}")
    return callees


def _get_instruction_histogram(func):
    """Build a histogram of instruction mnemonic categories.

    Returns dict {category: count}.
    """
    histogram = defaultdict(int)
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if not ida_bytes.is_code(ida_bytes.get_flags(head)):
            continue
        insn = idautils.DecodeInstruction(head)
        if insn is None:
            continue
        mnem_str = insn.get_canon_mnem()
        if mnem_str:
            cat = _categorize_mnemonic(mnem_str)
            histogram[cat] += 1
    return dict(histogram)


def _get_constants(func):
    """Extract immediate constant values from instructions.

    Filters out very small values (0, 1, -1) and alignment-related
    constants that add noise.  Returns a frozenset of integer values.
    """
    constants = set()
    noise_values = {0, 1, 2, 3, 4, 8, 0x10, 0x20, 0x40, 0x80,
                    0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                    -1, -2}
    count = 0

    for head in idautils.Heads(func.start_ea, func.end_ea):
        if count >= MAX_CONSTANTS_PER_FUNC:
            break
        if not ida_bytes.is_code(ida_bytes.get_flags(head)):
            continue
        insn = idautils.DecodeInstruction(head)
        if insn is None:
            continue
        for i in range(6):  # IDA supports up to 6 operands
            op = insn.ops[i]
            if op.type == idaapi.o_void:
                break
            if op.type == idaapi.o_imm:
                val = op.value
                # Mask to 64-bit unsigned for consistency
                val = val & 0xFFFFFFFFFFFFFFFF
                if val not in noise_values and val < 0x7FFFFFFFFFFFFFFF:
                    constants.add(val)
                    count += 1

    return frozenset(constants)


def _get_string_ref_hashes(func):
    """Get hashes of strings referenced by the function.

    Returns a frozenset of md5 hex digest strings (first 8 chars).
    """
    string_hashes = set()
    count = 0

    for head in idautils.Heads(func.start_ea, func.end_ea):
        if count >= MAX_STRINGS_PER_FUNC:
            break
        for xref in idautils.XrefsFrom(head, 0):
            if xref.type in (ida_xref.dr_R, ida_xref.dr_O):
                # Check if target is a string
                str_type = ida_bytes.get_str_type(xref.to)
                if str_type is not None and str_type >= 0:
                    string_val = ida_bytes.get_strlit_contents(
                        xref.to, -1, str_type)
                    if string_val:
                        if isinstance(string_val, bytes):
                            string_val = string_val.decode("utf-8", errors="replace")
                        h = hashlib.md5(string_val.encode("utf-8")).hexdigest()[:8]
                        string_hashes.add(h)
                        count += 1

    return frozenset(string_hashes)


def _compute_structural_fingerprint(func):
    """Compute the full structural fingerprint for a function.

    Returns a dict with all fingerprint components, plus a combined
    hash string suitable for exact-match grouping.

    Returns None if the function is too small or cannot be analyzed.
    """
    func_size = func.end_ea - func.start_ea
    if func_size < MIN_FUNC_SIZE:
        return None

    bb_count, edge_count = _get_cfg_metrics(func)
    call_pattern = _get_call_pattern(func)
    histogram = _get_instruction_histogram(func)
    constants = _get_constants(func)
    string_hashes = _get_string_ref_hashes(func)
    size_bucket = func_size // SIZE_BUCKET_WIDTH

    # Build a canonical representation for hashing
    # Sort histogram entries for determinism
    hist_tuple = tuple(sorted(histogram.items()))

    # Sort call pattern (we keep order for similarity, but hash uses sorted)
    calls_sorted = tuple(sorted(call_pattern))

    # Build the fingerprint hash from structural components
    # Deliberately EXCLUDE constants and strings from the exact hash so that
    # functions with identical structure but different constants/strings
    # still cluster together (they differ only in data, not shape).
    fp_components = (
        bb_count,
        edge_count,
        size_bucket,
        hist_tuple,
        calls_sorted,
    )

    fp_hash = hashlib.sha256(
        json.dumps(fp_components, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]

    return {
        "bb_count": bb_count,
        "edge_count": edge_count,
        "size_bucket": size_bucket,
        "func_size": func_size,
        "call_pattern": call_pattern,
        "call_set": frozenset(call_pattern),
        "histogram": histogram,
        "constants": constants,
        "string_hashes": string_hashes,
        "fp_hash": fp_hash,
    }


# ---------------------------------------------------------------------------
# Decompilation-based structural fingerprint (for handlers only)
# ---------------------------------------------------------------------------

def _normalize_pseudocode(text):
    """Normalize decompiled pseudocode for structural comparison.

    Strips variable names, replaces literal constants with TYPE markers,
    and removes whitespace variations.  The result captures the *shape*
    of the code, not the specific data it operates on.
    """
    if not text:
        return ""

    # Remove line comments
    text = re.sub(r'//[^\n]*', '', text)
    # Remove block comments
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)

    # Replace hex constants with CONST marker
    text = re.sub(r'0x[0-9A-Fa-f]+(?:LL|ULL|i64|ui64)?', 'CONST', text)
    # Replace decimal integer constants (but not single digits used for
    # indexing which are structural)
    text = re.sub(r'\b\d{2,}\b', 'CONST', text)

    # Replace string literals with STRING marker
    text = re.sub(r'"[^"]*"', 'STRING', text)

    # Replace variable names (v1, v2, a1, a2, etc.)
    text = re.sub(r'\b[va]\d+\b', 'VAR', text)

    # Replace casted types like (type *) with TYPE_PTR
    text = re.sub(r'\(\s*\w+\s*\*\s*\)', '(TYPE_PTR)', text)
    text = re.sub(r'\(\s*unsigned\s+\w+\s*\)', '(TYPE)', text)
    text = re.sub(r'\(\s*signed\s+\w+\s*\)', '(TYPE)', text)
    text = re.sub(r'\(\s*__int\d+\s*\)', '(TYPE)', text)

    # Replace specific type keywords
    text = re.sub(r'\b(?:__int64|__int32|__int16|__int8|DWORD|QWORD|WORD|BYTE'
                  r'|_DWORD|_QWORD|_WORD|_BYTE)\b', 'TYPE', text)

    # Collapse multiple whitespace
    text = re.sub(r'\s+', ' ', text).strip()

    return text


def _compute_decomp_fingerprint(pseudocode):
    """Hash the normalized pseudocode structure.

    Returns a hex digest string or None if pseudocode is empty.
    """
    normalized = _normalize_pseudocode(pseudocode)
    if not normalized or len(normalized) < 20:
        return None
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Similarity computation
# ---------------------------------------------------------------------------

def _jaccard_similarity(set_a, set_b):
    """Compute Jaccard similarity between two sets.

    Returns float in [0.0, 1.0].  Returns 1.0 if both sets are empty.
    """
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    if union == 0:
        return 1.0
    return intersection / union


def _histogram_similarity(hist_a, hist_b):
    """Compute cosine-like similarity between two instruction histograms.

    Returns float in [0.0, 1.0].
    """
    all_keys = set(hist_a.keys()) | set(hist_b.keys())
    if not all_keys:
        return 1.0

    dot = 0.0
    mag_a = 0.0
    mag_b = 0.0
    for k in all_keys:
        va = hist_a.get(k, 0)
        vb = hist_b.get(k, 0)
        dot += va * vb
        mag_a += va * va
        mag_b += vb * vb

    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a ** 0.5 * mag_b ** 0.5)


def _compute_pairwise_similarity(fp_a, fp_b):
    """Compute overall structural similarity between two fingerprints.

    Combines multiple similarity metrics with weights.
    Returns float in [0.0, 1.0].
    """
    # CFG shape: bb_count and edge_count should be identical or very close
    bb_diff = abs(fp_a["bb_count"] - fp_b["bb_count"])
    edge_diff = abs(fp_a["edge_count"] - fp_b["edge_count"])
    max_bb = max(fp_a["bb_count"], fp_b["bb_count"], 1)
    max_edge = max(fp_a["edge_count"], fp_b["edge_count"], 1)
    cfg_sim = 1.0 - (bb_diff / max_bb + edge_diff / max_edge) / 2.0

    # Call pattern similarity (Jaccard on callee sets)
    call_sim = _jaccard_similarity(fp_a["call_set"], fp_b["call_set"])

    # Instruction histogram similarity (cosine)
    hist_sim = _histogram_similarity(fp_a["histogram"], fp_b["histogram"])

    # Size similarity
    size_diff = abs(fp_a["func_size"] - fp_b["func_size"])
    max_size = max(fp_a["func_size"], fp_b["func_size"], 1)
    size_sim = 1.0 - (size_diff / max_size)

    # Constants similarity (Jaccard)
    const_sim = _jaccard_similarity(fp_a["constants"], fp_b["constants"])

    # Weighted combination
    # CFG and histogram are most important for structural similarity
    # Constants are least important (templates differ in constants)
    similarity = (
        0.30 * cfg_sim +
        0.25 * call_sim +
        0.25 * hist_sim +
        0.10 * size_sim +
        0.10 * const_sim
    )

    return similarity


# ---------------------------------------------------------------------------
# Target function selection
# ---------------------------------------------------------------------------

def _collect_target_functions(session):
    """Build the set of function EAs to analyze.

    Strategy: focus on handler callees and named functions rather than
    trying to fingerprint all 115K+ functions.

    Selection criteria (in priority order):
      1. All CMSG/SMSG handler functions
      2. Direct callees of handlers (1 level deep)
      3. Named functions that belong to a known system
      4. Named functions with RTTI class labels

    Returns dict {ea: name} of selected functions.
    """
    db = session.db
    targets = {}  # ea -> name

    msg_info("Collecting target functions for similarity analysis...")

    # 1. Handler functions
    handlers = db.fetchall(
        "SELECT handler_ea, tc_name, jam_type FROM opcodes "
        "WHERE handler_ea IS NOT NULL")
    handler_eas = set()
    for h in handlers:
        ea = h["handler_ea"]
        if ea and ea != 0:
            name = h["tc_name"] or h["jam_type"] or f"handler_{ea:X}"
            targets[ea] = name
            handler_eas.add(ea)

    handler_count = len(targets)
    msg_info(f"  Handlers: {handler_count}")

    # 2. Direct callees of handlers (1 level deep)
    callee_eas = set()
    for handler_ea in handler_eas:
        func = ida_funcs.get_func(handler_ea)
        if not func:
            continue
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.type in (ida_xref.fl_CF, ida_xref.fl_CN):
                    callee_func = ida_funcs.get_func(xref.to)
                    if callee_func and callee_func.start_ea not in targets:
                        callee_ea = callee_func.start_ea
                        callee_name = ida_name.get_name(callee_ea) or f"sub_{callee_ea:X}"
                        targets[callee_ea] = callee_name
                        callee_eas.add(callee_ea)

    msg_info(f"  Handler callees: {len(callee_eas)}")

    # 3. Named functions from the functions table (system-labeled)
    system_funcs = db.fetchall(
        "SELECT ea, name FROM functions "
        "WHERE system IS NOT NULL AND name IS NOT NULL AND size > ?",
        (MIN_FUNC_SIZE,))
    system_count = 0
    for row in system_funcs:
        ea = row["ea"]
        if ea not in targets:
            targets[ea] = row["name"]
            system_count += 1

    msg_info(f"  System-labeled functions: {system_count}")

    # 4. Named functions from IDA (non-sub_ names)
    # If MAX_FUNCTIONS_TO_ANALYZE is 0, collect all; otherwise cap at limit
    cap = MAX_FUNCTIONS_TO_ANALYZE
    collect_all = (cap == 0)
    remaining = (cap - len(targets)) if cap else 0

    if collect_all or len(targets) < cap:
        named_count = 0
        for seg_ea in idautils.Segments():
            if not collect_all and named_count >= remaining:
                break
            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue
            for func_ea in idautils.Functions(seg.start_ea, seg.end_ea):
                if not collect_all and named_count >= remaining:
                    break
                if func_ea in targets:
                    continue
                name = ida_name.get_name(func_ea)
                if name and not name.startswith("sub_") and not name.startswith("j_"):
                    func = ida_funcs.get_func(func_ea)
                    if func and (func.end_ea - func.start_ea) >= MIN_FUNC_SIZE:
                        targets[func_ea] = name
                        named_count += 1

        msg_info(f"  Additional named functions: {named_count}")

    msg_info(f"  Total target functions: {len(targets)}")
    return targets


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------

def _build_exact_clusters(fingerprints):
    """Group functions with identical structural fingerprints.

    Args:
        fingerprints: dict {ea: fingerprint_dict}

    Returns list of clusters, each cluster = list of (ea, name) tuples.
    Also returns dict {fp_hash: cluster_index} for later merging.
    """
    hash_groups = defaultdict(list)
    for ea, fp in fingerprints.items():
        hash_groups[fp["fp_hash"]].append(ea)

    clusters = []
    hash_to_cluster = {}
    for fp_hash, eas in hash_groups.items():
        if len(eas) < 2:
            continue  # singletons are not clusters
        cluster = [(ea, fingerprints[ea].get("name", f"sub_{ea:X}")) for ea in eas]
        idx = len(clusters)
        clusters.append(cluster)
        hash_to_cluster[fp_hash] = idx

    return clusters, hash_to_cluster


def _merge_near_clusters(clusters, fingerprints, threshold):
    """Merge clusters whose representative fingerprints are above threshold.

    Uses single-linkage: if the representatives of two clusters are similar
    enough, the clusters are merged.

    Args:
        clusters: list of clusters (each is list of (ea, name))
        fingerprints: dict {ea: fingerprint_dict}
        threshold: Jaccard/similarity threshold

    Returns new list of merged clusters.
    """
    if len(clusters) <= 1:
        return clusters

    # Use the first member of each cluster as representative
    reps = []
    for cluster in clusters:
        rep_ea = cluster[0][0]
        reps.append(fingerprints.get(rep_ea))

    # Build a union-find structure for merging
    parent = list(range(len(clusters)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    # Compare representatives pairwise — O(n^2) but n is small
    # (number of exact clusters, typically < 500)
    for i in range(len(reps)):
        if reps[i] is None:
            continue
        for j in range(i + 1, len(reps)):
            if reps[j] is None:
                continue
            # Quick reject: if size buckets differ by more than 2, skip
            if abs(reps[i]["size_bucket"] - reps[j]["size_bucket"]) > 2:
                continue
            # Quick reject: if bb_count differs by more than 3, skip
            if abs(reps[i]["bb_count"] - reps[j]["bb_count"]) > 3:
                continue

            sim = _compute_pairwise_similarity(reps[i], reps[j])
            if sim >= threshold:
                union(i, j)

    # Rebuild clusters from union-find
    merged = defaultdict(list)
    for i, cluster in enumerate(clusters):
        root = find(i)
        merged[root].extend(cluster)

    return list(merged.values())


def _build_near_match_clusters(singletons, fingerprints, threshold):
    """Build clusters from functions that did not exact-match.

    For efficiency, we first group by (bb_count, size_bucket) neighborhood,
    then do pairwise comparison only within those neighborhoods.

    Args:
        singletons: set of EAs that are not in any exact cluster
        fingerprints: dict {ea: fingerprint_dict}
        threshold: similarity threshold

    Returns list of near-match clusters.
    """
    if not singletons:
        return []

    # Group by (bb_count, size_bucket) for spatial hashing
    spatial_bins = defaultdict(list)
    for ea in singletons:
        fp = fingerprints.get(ea)
        if fp is None:
            continue
        key = (fp["bb_count"], fp["size_bucket"])
        spatial_bins[key].append(ea)

    # For each bin, expand to neighbors and do pairwise comparison
    clusters = []
    clustered = set()

    for (bb, sb), eas in spatial_bins.items():
        if len(eas) < 2:
            continue

        # Also consider adjacent bins
        neighbor_eas = list(eas)
        for dbb in (-1, 0, 1):
            for dsb in (-1, 0, 1):
                if dbb == 0 and dsb == 0:
                    continue
                nkey = (bb + dbb, sb + dsb)
                if nkey in spatial_bins:
                    neighbor_eas.extend(spatial_bins[nkey])

        # Remove duplicates and already-clustered
        neighbor_eas = list(set(neighbor_eas) - clustered)
        if len(neighbor_eas) < 2:
            continue

        # Pairwise comparison within this neighborhood (cap at 200 for perf)
        if len(neighbor_eas) > 200:
            neighbor_eas = neighbor_eas[:200]

        # Simple greedy clustering
        local_clusters = []
        used = set()
        for i in range(len(neighbor_eas)):
            if neighbor_eas[i] in used:
                continue
            ea_i = neighbor_eas[i]
            fp_i = fingerprints.get(ea_i)
            if fp_i is None:
                continue

            cluster = [(ea_i, fp_i.get("name", f"sub_{ea_i:X}"))]
            used.add(ea_i)

            for j in range(i + 1, len(neighbor_eas)):
                if neighbor_eas[j] in used:
                    continue
                ea_j = neighbor_eas[j]
                fp_j = fingerprints.get(ea_j)
                if fp_j is None:
                    continue

                sim = _compute_pairwise_similarity(fp_i, fp_j)
                if sim >= threshold:
                    cluster.append(
                        (ea_j, fp_j.get("name", f"sub_{ea_j:X}")))
                    used.add(ea_j)

            if len(cluster) >= 2:
                local_clusters.append(cluster)
                clustered.update(ea for ea, _ in cluster)

        clusters.extend(local_clusters)

    return clusters


# ---------------------------------------------------------------------------
# Template detection
# ---------------------------------------------------------------------------

def _detect_template_candidates(clusters, fingerprints):
    """Identify clusters that look like template instantiations.

    Heuristic: functions in the cluster have identical call patterns
    and histogram shapes but differ in constants that look like type-
    related values (DB2 table hashes, type IDs, vtable pointers).

    Returns list of template candidate dicts.
    """
    candidates = []

    for cluster_id, cluster in enumerate(clusters):
        if len(cluster) < 2:
            continue

        member_eas = [ea for ea, _ in cluster]
        fps = [fingerprints[ea] for ea in member_eas if ea in fingerprints]
        if len(fps) < 2:
            continue

        # Check if call patterns are identical across members
        call_sets = [fp["call_set"] for fp in fps]
        call_jaccard_all = True
        base_calls = call_sets[0]
        for cs in call_sets[1:]:
            if _jaccard_similarity(base_calls, cs) < 0.95:
                call_jaccard_all = False
                break

        if not call_jaccard_all:
            continue

        # Check if histograms are very similar
        hist_sims = []
        base_hist = fps[0]["histogram"]
        for fp in fps[1:]:
            hist_sims.append(_histogram_similarity(base_hist, fp["histogram"]))
        avg_hist_sim = sum(hist_sims) / len(hist_sims) if hist_sims else 0

        if avg_hist_sim < 0.9:
            continue

        # Check if constants DIFFER (template parameter signature)
        constant_sets = [fp["constants"] for fp in fps]
        # Compute the symmetric difference — constants that are unique to
        # each member (these are the "template parameters")
        common_constants = constant_sets[0]
        for cs in constant_sets[1:]:
            common_constants = common_constants & cs

        unique_per_member = []
        for cs in constant_sets:
            unique = cs - common_constants
            unique_per_member.append(unique)

        # If every member has at least some unique constants, it looks
        # like a template instantiation
        if all(len(u) > 0 for u in unique_per_member):
            # Try to infer the template parameter type
            param_type = _infer_template_parameter(unique_per_member, fps)
            template_name = _suggest_template_name(fps, base_calls)

            candidates.append({
                "cluster_id": cluster_id,
                "template_name": template_name,
                "parameter_type": param_type,
                "member_count": len(cluster),
                "members": [
                    {
                        "ea": ea,
                        "name": name,
                        "unique_constants": sorted(
                            unique_per_member[i]
                        )[:10] if i < len(unique_per_member) else []
                    }
                    for i, (ea, name) in enumerate(cluster)
                ],
                "shared_callees": sorted(base_calls)[:15],
                "avg_histogram_similarity": round(avg_hist_sim, 3),
            })

    return candidates


def _infer_template_parameter(unique_per_member, fps):
    """Try to infer what the template parameter represents.

    Heuristics:
      - If unique constants are all small ints (< 256) -> enum/type ID
      - If unique constants are large (> 0x1000000) -> pointer/vtable
      - If unique constants look like hashes (32-bit) -> DB2 layout hash
    """
    all_unique = set()
    for u in unique_per_member:
        all_unique.update(u)

    if not all_unique:
        return "unknown"

    max_val = max(all_unique)
    min_val = min(all_unique)

    if max_val < 256:
        return "enum_value"
    elif min_val > 0x100000 and max_val < 0xFFFFFFFF:
        return "hash_or_id"
    elif max_val > 0x7FF000000000:
        return "pointer"
    elif all(0x10000 <= v <= 0xFFFFFFFF for v in all_unique):
        return "db2_layout_hash"
    else:
        return "type_constant"


def _suggest_template_name(fps, shared_callees):
    """Suggest a template name based on shared callees.

    Looks for common prefixes in callee names to infer the template
    family name.
    """
    if not shared_callees:
        return "UnknownTemplate"

    # Look for the most descriptive callee name
    callee_names = sorted(shared_callees)
    for name in callee_names:
        # Skip generic names
        if any(skip in name.lower() for skip in
               ["sub_", "memcpy", "memset", "malloc", "free",
                "operator", "__"]):
            continue
        # Use the first meaningful callee as the template family
        # Strip common prefixes
        clean = re.sub(r'^(j_|_)', '', name)
        if len(clean) > 3:
            return f"Template_{clean}"

    # Fallback: use the first function name in the cluster
    first_name = fps[0].get("name", "Unknown")
    return f"Template_{first_name}"


# ---------------------------------------------------------------------------
# Copy-paste detection
# ---------------------------------------------------------------------------

def _detect_copypaste_candidates(clusters, fingerprints):
    """Identify clusters that look like copy-pasted code.

    Heuristic: functions with identical structure (same CFG, same call
    pattern) but different STRING references.  This indicates the same
    logic was duplicated for different error messages, log strings, etc.

    Returns list of copy-paste candidate dicts.
    """
    candidates = []

    for cluster_id, cluster in enumerate(clusters):
        if len(cluster) < 2:
            continue

        member_eas = [ea for ea, _ in cluster]
        fps = [fingerprints[ea] for ea in member_eas if ea in fingerprints]
        if len(fps) < 2:
            continue

        # Check if string references differ across members
        string_sets = [fp["string_hashes"] for fp in fps]

        # At least some members must have strings
        members_with_strings = sum(1 for s in string_sets if len(s) > 0)
        if members_with_strings < 2:
            continue

        # Compute pairwise string Jaccard similarities
        string_sims = []
        for i in range(len(string_sets)):
            for j in range(i + 1, len(string_sets)):
                if string_sets[i] and string_sets[j]:
                    string_sims.append(
                        _jaccard_similarity(string_sets[i], string_sets[j]))

        if not string_sims:
            continue

        avg_string_sim = sum(string_sims) / len(string_sims)

        # If strings are very different but structure is identical,
        # this is copy-paste
        if avg_string_sim < 0.5:
            # Describe the shared structure
            base_fp = fps[0]
            shared_structure = (
                f"bb={base_fp['bb_count']} edges={base_fp['edge_count']} "
                f"size~{base_fp['size_bucket'] * SIZE_BUCKET_WIDTH}B "
                f"calls={len(base_fp['call_pattern'])}"
            )

            candidates.append({
                "cluster_id": cluster_id,
                "member_count": len(cluster),
                "shared_structure": shared_structure,
                "avg_string_similarity": round(avg_string_sim, 3),
                "members": [
                    {"ea": ea, "name": name}
                    for ea, name in cluster
                ],
            })

    return candidates


# ---------------------------------------------------------------------------
# Handler grouping
# ---------------------------------------------------------------------------

def _group_similar_handlers(clusters, fingerprints, handler_eas):
    """Among CMSG/SMSG handlers, find those with identical structure.

    These indicate opportunities for a common handler template in TC.

    Returns list of handler group dicts.
    """
    handler_groups = []

    for cluster_id, cluster in enumerate(clusters):
        # Filter to only handlers in this cluster
        handler_members = [
            (ea, name) for ea, name in cluster if ea in handler_eas
        ]
        if len(handler_members) < 2:
            continue

        # Get the shared structure
        fps = [fingerprints[ea] for ea, _ in handler_members
               if ea in fingerprints]
        if not fps:
            continue

        base = fps[0]
        shared_callees = sorted(base["call_set"])[:10]

        handler_groups.append({
            "cluster_id": cluster_id,
            "member_count": len(handler_members),
            "members": [
                {"ea": ea, "name": name} for ea, name in handler_members
            ],
            "shared_callees": shared_callees,
            "bb_count": base["bb_count"],
            "edge_count": base["edge_count"],
            "template_suggestion": _suggest_handler_template(
                handler_members, shared_callees),
        })

    return handler_groups


def _suggest_handler_template(handler_members, shared_callees):
    """Suggest a template name for a group of similar handlers."""
    names = [name for _, name in handler_members]

    # Find common prefix among handler names
    if len(names) >= 2:
        # Try to find the longest common prefix
        prefix = names[0]
        for name in names[1:]:
            while prefix and not name.startswith(prefix):
                prefix = prefix[:-1]
            if not prefix:
                break

        if len(prefix) > 5:
            return f"HandleGeneric{prefix.rstrip('_')}()"

    # Try to find common substring in callee names
    if shared_callees:
        for callee in shared_callees:
            if any(kw in callee for kw in
                   ["Read", "Write", "Send", "Process", "Handle"]):
                return f"HandleCommon_{callee}()"

    return "HandleCommonStructure()"


# ---------------------------------------------------------------------------
# Decompilation-based clustering for handlers
# ---------------------------------------------------------------------------

def _cluster_by_decompilation(handler_eas, fingerprints):
    """Build decompilation-based clusters for handler functions.

    This catches template instantiations with different types that
    compile to different instruction patterns but have the same
    pseudocode structure.

    Only attempts decompilation for a limited number of handlers
    to avoid excessive processing time.

    Returns list of decomp clusters and dict of decomp fingerprints.
    """
    decomp_fps = {}  # ea -> decomp_hash
    decomp_groups = defaultdict(list)

    attempt_count = 0
    success_count = 0

    for ea in handler_eas:
        if attempt_count >= MAX_DECOMP_ATTEMPTS:
            break

        attempt_count += 1
        pseudocode = get_decompiled_text(ea)
        if not pseudocode:
            continue

        decomp_hash = _compute_decomp_fingerprint(pseudocode)
        if decomp_hash is None:
            continue

        success_count += 1
        decomp_fps[ea] = decomp_hash
        name = fingerprints[ea]["name"] if ea in fingerprints else f"sub_{ea:X}"
        decomp_groups[decomp_hash].append((ea, name))

    msg_info(f"  Decompiled {success_count}/{attempt_count} handlers")

    # Filter to groups with 2+ members
    clusters = [members for members in decomp_groups.values()
                if len(members) >= 2]

    return clusters, decomp_fps


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def get_cluster_members(session, cluster_id):
    """Get list of functions in a specific cluster.

    Args:
        session: PluginSession
        cluster_id: integer cluster index

    Returns list of {ea, name} dicts, or empty list if not found.
    """
    data = session.db.kv_get("function_similarity")
    if not data or "clusters" not in data:
        return []

    for cluster in data["clusters"]:
        if cluster["id"] == cluster_id:
            return cluster["members"]

    return []


def export_clusters_csv(session):
    """Export all clusters as a CSV string.

    Returns CSV text with columns:
      cluster_id, cluster_type, member_count, fingerprint_hash,
      function_ea, function_name

    Returns empty string if no data is available.
    """
    data = session.db.kv_get("function_similarity")
    if not data or "clusters" not in data:
        return ""

    lines = ["cluster_id,cluster_type,member_count,fingerprint_hash,"
             "function_ea,function_name"]

    for cluster in data["clusters"]:
        cid = cluster["id"]
        ctype = cluster["type"]
        count = cluster["member_count"]
        fp_hash = cluster.get("fingerprint_hash", "")

        for member in cluster["members"]:
            ea_hex = f"0x{member['ea']:X}" if isinstance(member["ea"], int) else member["ea"]
            name = member["name"].replace(",", ";")  # escape commas
            lines.append(f"{cid},{ctype},{count},{fp_hash},{ea_hex},{name}")

    return "\n".join(lines)


def get_similarity_clusters(session):
    """Retrieve stored similarity analysis data.

    Returns the full results dict, or empty dict if not yet computed.
    """
    return session.db.kv_get("function_similarity") or {}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def cluster_similar_functions(session):
    """Analyze functions for structural similarity and build clusters.

    This is the main entry point for the function similarity analyzer.
    It fingerprints target functions, groups them by structural similarity,
    detects template instantiations and copy-paste patterns, and stores
    results in the knowledge database.

    Args:
        session: PluginSession with initialized DB

    Returns:
        int: total number of clusters found
    """
    start_time = time.time()
    db = session.db

    msg("=" * 60)
    msg("Function Similarity Analyzer")
    msg("=" * 60)

    # ── Step 1: Collect target functions ──────────────────────────
    targets = _collect_target_functions(session)
    if not targets:
        msg_warn("No target functions found. Run opcode discovery first.")
        return 0

    # ── Step 2: Build structural fingerprints ─────────────────────
    msg_info("Building structural fingerprints...")
    fingerprints = {}  # ea -> fingerprint dict
    skipped = 0
    errors = 0

    progress_interval = max(len(targets) // 20, 1)
    for idx, (ea, name) in enumerate(targets.items()):
        if idx > 0 and idx % progress_interval == 0:
            pct = idx * 100 // len(targets)
            msg(f"  Progress: {pct}% ({idx}/{len(targets)})")

        func = ida_funcs.get_func(ea)
        if not func:
            skipped += 1
            continue

        try:
            fp = _compute_structural_fingerprint(func)
            if fp is None:
                skipped += 1
                continue
            fp["name"] = name
            fingerprints[ea] = fp
        except Exception as e:
            errors += 1
            if errors <= 5:
                msg_warn(f"  Fingerprint error at {ea_str(ea)}: {e}")

    msg_info(f"Fingerprinted {len(fingerprints)} functions "
             f"(skipped {skipped}, errors {errors})")

    if len(fingerprints) < 2:
        msg_warn("Too few functions fingerprinted. Cannot cluster.")
        return 0

    # ── Step 3: Build exact-match clusters ────────────────────────
    msg_info("Building exact-match clusters...")
    exact_clusters, hash_to_cluster = _build_exact_clusters(fingerprints)
    msg_info(f"  Found {len(exact_clusters)} exact-match clusters "
             f"({sum(len(c) for c in exact_clusters)} functions)")

    # ── Step 4: Build near-match clusters from singletons ─────────
    msg_info("Building near-match clusters...")
    clustered_eas = set()
    for cluster in exact_clusters:
        for ea, _ in cluster:
            clustered_eas.add(ea)

    singleton_eas = set(fingerprints.keys()) - clustered_eas
    near_clusters = _build_near_match_clusters(
        singleton_eas, fingerprints, NEAR_MATCH_THRESHOLD)
    msg_info(f"  Found {len(near_clusters)} near-match clusters "
             f"({sum(len(c) for c in near_clusters)} functions)")

    # ── Step 5: Merge near-match clusters with exact clusters ─────
    msg_info("Merging exact and near clusters...")
    all_clusters = exact_clusters + near_clusters
    merged_clusters = _merge_near_clusters(
        all_clusters, fingerprints, NEAR_MATCH_THRESHOLD)
    msg_info(f"  After merging: {len(merged_clusters)} clusters")

    # Sort clusters by size (largest first)
    merged_clusters.sort(key=lambda c: len(c), reverse=True)

    # ── Step 6: Handler-only decompilation clustering ─────────────
    msg_info("Running decompilation-based clustering on handlers...")
    handler_rows = db.fetchall(
        "SELECT handler_ea FROM opcodes WHERE handler_ea IS NOT NULL")
    handler_ea_set = set()
    for row in handler_rows:
        ea = row["handler_ea"]
        if ea and ea in fingerprints:
            handler_ea_set.add(ea)

    decomp_clusters, decomp_fps = _cluster_by_decompilation(
        handler_ea_set, fingerprints)
    msg_info(f"  Decompilation clusters: {len(decomp_clusters)}")

    # Merge decomp clusters into main clusters if they are novel
    decomp_clustered_eas = set()
    for cluster in merged_clusters:
        for ea, _ in cluster:
            decomp_clustered_eas.add(ea)

    novel_decomp = 0
    for dc in decomp_clusters:
        dc_eas = set(ea for ea, _ in dc)
        # If most members are not already clustered, add as new cluster
        overlap = dc_eas & decomp_clustered_eas
        if len(overlap) < len(dc_eas) * 0.5:
            merged_clusters.append(dc)
            novel_decomp += 1
            for ea, _ in dc:
                decomp_clustered_eas.add(ea)

    if novel_decomp > 0:
        msg_info(f"  Added {novel_decomp} novel decomp-based clusters")

    # Re-sort after adding decomp clusters
    merged_clusters.sort(key=lambda c: len(c), reverse=True)

    # ── Step 7: Detect template candidates ────────────────────────
    msg_info("Detecting template instantiation candidates...")
    template_candidates = _detect_template_candidates(
        merged_clusters, fingerprints)
    msg_info(f"  Template candidates: {len(template_candidates)}")

    # ── Step 8: Detect copy-paste candidates ──────────────────────
    msg_info("Detecting copy-paste candidates...")
    copypaste_candidates = _detect_copypaste_candidates(
        merged_clusters, fingerprints)
    msg_info(f"  Copy-paste candidates: {len(copypaste_candidates)}")

    # ── Step 9: Group similar handlers ────────────────────────────
    msg_info("Grouping similar handlers...")
    handler_groups = _group_similar_handlers(
        merged_clusters, fingerprints, handler_ea_set)
    msg_info(f"  Similar handler groups: {len(handler_groups)}")

    # ── Step 10: Count cluster types ──────────────────────────────
    exact_count = len(exact_clusters)
    near_count = len(merged_clusters) - exact_count
    if near_count < 0:
        near_count = len(near_clusters)

    # ── Step 11: Build final results structure ────────────────────
    result_clusters = []
    for idx, cluster in enumerate(merged_clusters):
        # Determine cluster type
        ctype = "exact_clone"
        if idx >= len(exact_clusters):
            ctype = "near_match"

        # Check if this is also a template or copypaste cluster
        for tc in template_candidates:
            if tc["cluster_id"] == idx:
                ctype = "template_candidate"
                break
        for cp in copypaste_candidates:
            if cp["cluster_id"] == idx:
                ctype = "copypaste_candidate"
                break

        # Get fingerprint hash from first member
        first_ea = cluster[0][0] if cluster else 0
        fp_hash = (fingerprints[first_ea]["fp_hash"]
                   if first_ea in fingerprints else "unknown")

        result_clusters.append({
            "id": idx,
            "type": ctype,
            "member_count": len(cluster),
            "fingerprint_hash": fp_hash,
            "members": [
                {"ea": ea, "name": name} for ea, name in cluster
            ],
        })

    # Reindex template and copypaste candidates after final cluster order
    # (cluster IDs may have shifted during merging)
    # We re-tag by matching member EAs instead of relying on the original
    # cluster_id which was assigned before merge.
    _retag_candidates_by_members(
        result_clusters, template_candidates, copypaste_candidates)

    results = {
        "total_functions_analyzed": len(fingerprints),
        "total_clusters": len(result_clusters),
        "exact_clone_clusters": exact_count,
        "near_match_clusters": near_count,
        "template_candidates": template_candidates,
        "copypaste_candidates": copypaste_candidates,
        "handler_groups": handler_groups,
        "clusters": result_clusters,
        "analysis_time_sec": round(time.time() - start_time, 1),
    }

    # ── Step 12: Store results ────────────────────────────────────
    db.kv_set("function_similarity", results)
    db.commit()

    elapsed = time.time() - start_time

    # ── Summary ───────────────────────────────────────────────────
    msg("=" * 60)
    msg("Function Similarity Analysis Complete")
    msg("=" * 60)
    msg(f"  Functions analyzed:     {len(fingerprints)}")
    msg(f"  Total clusters:         {len(result_clusters)}")
    msg(f"  Exact clone clusters:   {exact_count}")
    msg(f"  Near-match clusters:    {near_count}")
    msg(f"  Template candidates:    {len(template_candidates)}")
    msg(f"  Copy-paste candidates:  {len(copypaste_candidates)}")
    msg(f"  Similar handler groups: {len(handler_groups)}")
    msg(f"  Analysis time:          {elapsed:.1f}s")
    msg("")

    # Print top clusters
    if result_clusters:
        msg("Top clusters by size:")
        for cluster in result_clusters[:15]:
            msg(f"  Cluster #{cluster['id']} ({cluster['type']}): "
                f"{cluster['member_count']} members")
            for member in cluster["members"][:5]:
                msg(f"    {ea_str(member['ea'])} {member['name']}")
            if cluster["member_count"] > 5:
                msg(f"    ... and {cluster['member_count'] - 5} more")

    # Print template candidates
    if template_candidates:
        msg("")
        msg("Template instantiation candidates:")
        for tc in template_candidates[:10]:
            msg(f"  {tc['template_name']} ({tc['parameter_type']}): "
                f"{tc['member_count']} instantiations")
            for m in tc["members"][:3]:
                consts = ", ".join(f"0x{c:X}" for c in m["unique_constants"][:3])
                msg(f"    {ea_str(m['ea'])} {m['name']}  [{consts}]")

    # Print handler groups
    if handler_groups:
        msg("")
        msg("Similar handler groups (refactoring opportunities):")
        for hg in handler_groups[:10]:
            msg(f"  {hg['template_suggestion']}: "
                f"{hg['member_count']} handlers")
            for m in hg["members"][:3]:
                msg(f"    {ea_str(m['ea'])} {m['name']}")

    return len(result_clusters)


def _retag_candidates_by_members(result_clusters, template_candidates,
                                 copypaste_candidates):
    """Re-associate template and copypaste candidates with the final
    cluster IDs by matching member EAs.

    After merging and re-sorting, cluster IDs may have shifted.  This
    function updates the cluster_id field in each candidate to point
    to the correct final cluster.
    """
    # Build EA -> final cluster ID mapping
    ea_to_cluster = {}
    for cluster in result_clusters:
        for member in cluster["members"]:
            ea_to_cluster[member["ea"]] = cluster["id"]

    for tc in template_candidates:
        if tc["members"]:
            first_ea = tc["members"][0]["ea"]
            tc["cluster_id"] = ea_to_cluster.get(first_ea, tc["cluster_id"])

    for cp in copypaste_candidates:
        if cp["members"]:
            first_ea = cp["members"][0]["ea"]
            cp["cluster_id"] = ea_to_cluster.get(first_ea, cp["cluster_id"])
