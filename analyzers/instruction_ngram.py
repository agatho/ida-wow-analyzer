"""
Instruction N-gram Analyzer
Applies NLP-inspired N-gram analysis to assembly instruction sequences to find
inlined functions, recurring patterns, and system-specific instruction fingerprints
in the WoW x64 client binary.

Key capabilities:
  1. Instruction tokenization  -- normalize instructions to pattern tokens
  2. N-gram extraction         -- sliding window at multiple granularities
  3. Frequent pattern mining   -- find common instruction sequences
  4. Inlined function recovery -- detect compiler-inlined utility functions
  5. System fingerprinting     -- characteristic patterns per game system
  6. Assembly-level clone detection -- find copy-paste at instruction level
  7. Compiler pattern catalog  -- MSVC-specific patterns, SEH, PGO, SIMD

Results are stored in session.db.kv_set("instruction_ngrams", {...}) and
can be retrieved via get_ngram_report(session).
"""

import json
import re
import time
from collections import defaultdict, Counter
import hashlib

import ida_funcs
import ida_name
import ida_bytes
import ida_ua
import idautils
import idaapi
import idc

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# N-gram sizes to extract (different granularities)
NGRAM_SIZES = (4, 6, 8)

# Minimum instruction count for a function to be analyzed
MIN_INSTRUCTION_COUNT = 20

# Maximum number of functions to analyze
MAX_FUNCTIONS = 10000

# Minimum frequency for a pattern to be considered "common"
MIN_COMMON_FREQUENCY = 10

# Top N results to keep in each category
TOP_PATTERNS_LIMIT = 200

# Top N assembly clones to report
TOP_CLONES_LIMIT = 100

# Minimum shared N-gram count for assembly clone detection
MIN_CLONE_SHARED_NGRAMS = 5

# Progress reporting interval
PROGRESS_INTERVAL_PCT = 5

# Operand type constants from ida_ua (o_* enum)
O_VOID = 0       # No operand
O_REG = 1        # General register (al, ax, eax, rax, etc.)
O_MEM = 2        # Direct memory reference (DATA)
O_PHRASE = 3     # Memory ref [base + index] (no displacement)
O_DISPL = 4      # Memory ref [base + index + displacement]
O_IMM = 5        # Immediate value
O_FAR = 6        # Immediate far address (CODE)
O_NEAR = 7       # Immediate near address (CODE)
O_IDPSPEC0 = 8   # Processor-specific type
O_IDPSPEC1 = 9
O_IDPSPEC2 = 10
O_IDPSPEC3 = 11
O_IDPSPEC4 = 12
O_IDPSPEC5 = 13

# Common trivial prologue/epilogue N-gram tokens to filter out.
# These are so ubiquitous they provide no signal.
_TRIVIAL_PROLOGUE_TOKENS = frozenset([
    "push_reg", "mov_reg_reg", "sub_reg_imm",  # push rbp; mov rbp, rsp; sub rsp, X
])

_TRIVIAL_EPILOGUE_TOKENS = frozenset([
    "add_reg_imm", "pop_reg", "ret",  # add rsp, X; pop rbp; ret
])

# MSVC security cookie pattern tokens
_SECURITY_COOKIE_TOKENS = (
    "mov_reg_mem", "xor_reg_reg", "mov_mem_reg",  # mov rax, [__security_cookie]; xor rax, rbp; mov [rbp+X], rax
)

# SEH prolog pattern tokens
_SEH_PROLOG_TOKENS = (
    "push_reg", "push_reg", "lea_reg_mem_disp",  # push rbp; push rbx; lea rbp, [rsp-X]
)

# Compiler patterns we want to catalog
COMPILER_PATTERN_DEFS = {
    "security_cookie_init": {
        "description": "MSVC /GS security cookie initialization",
        "signature_tokens": ("mov_reg_mem", "xor_reg_reg",),
        "min_length": 3,
    },
    "security_cookie_check": {
        "description": "MSVC /GS security cookie verification before return",
        "signature_tokens": ("xor_reg_reg", "call_near",),
        "min_length": 3,
    },
    "seh_prolog": {
        "description": "Structured Exception Handling prologue",
        "signature_tokens": ("mov_mem_disp_reg", "mov_mem_disp_reg", "lea_reg_mem_disp",),
        "min_length": 4,
    },
    "seh_epilog": {
        "description": "Structured Exception Handling epilogue",
        "signature_tokens": ("lea_reg_mem_disp", "mov_reg_mem_disp",),
        "min_length": 3,
    },
    "pgo_cold_split": {
        "description": "PGO cold code path (unconditional jump to distant block)",
        "signature_tokens": ("test_reg_reg", "jnz_near", "jmp_near",),
        "min_length": 3,
    },
    "simd_loop_body": {
        "description": "Vectorized loop body with SIMD instructions",
        "signature_tokens": None,  # Detected via mnemonic classes
        "min_length": 4,
    },
}


# ---------------------------------------------------------------------------
# Instruction Tokenization
# ---------------------------------------------------------------------------

def _classify_operand(op_type):
    """Classify an operand by its IDA type into a normalized class string.

    Args:
        op_type: ida_ua operand type (o_void, o_reg, o_imm, etc.)

    Returns:
        str: operand class name ("reg", "imm", "mem", "mem_disp", "near", "far")
    """
    if op_type == O_REG:
        return "reg"
    elif op_type == O_IMM:
        return "imm"
    elif op_type == O_MEM:
        return "mem"
    elif op_type == O_PHRASE:
        return "mem"
    elif op_type == O_DISPL:
        return "mem_disp"
    elif op_type == O_NEAR:
        return "near"
    elif op_type == O_FAR:
        return "far"
    elif op_type == O_VOID:
        return None
    else:
        # Processor-specific or unknown
        return "spec"


def _tokenize_instruction(insn):
    """Convert a decoded instruction to a normalized token string.

    The token format is "mnemonic_operandclass1_operandclass2" which normalizes
    away specific registers and immediate values but preserves the instruction
    pattern. Special cases produce fixed tokens for nop, int3, ret, etc.

    Args:
        insn: ida_ua.insn_t — a decoded instruction

    Returns:
        str: normalized token (e.g., "mov_reg_imm", "call_near", "ret")
    """
    mnemonic = insn.get_canon_mnem()
    if not mnemonic:
        return "unknown"

    mn = mnemonic.lower()

    # Special-case instructions that need no operand classification
    if mn == "nop":
        return "nop"
    if mn == "int3" or (mn == "int" and insn.ops[0].type == O_IMM and insn.ops[0].value == 3):
        return "int3"
    if mn in ("ret", "retn"):
        return "ret"
    if mn == "syscall":
        return "syscall"

    # Handle call instructions with dedicated tokens
    if mn == "call":
        op0_type = insn.ops[0].type
        if op0_type == O_NEAR:
            return "call_near"
        elif op0_type == O_FAR:
            return "call_far"
        elif op0_type == O_REG:
            return "call_reg"
        elif op0_type in (O_MEM, O_PHRASE):
            return "call_mem"
        elif op0_type == O_DISPL:
            return "call_mem_disp"
        else:
            return "call_other"

    # Handle jump instructions — normalize branch target type
    if mn.startswith("j") and mn != "jmp":
        # Conditional jumps: preserve the condition but not the target
        return f"{mn}_near"
    if mn == "jmp":
        op0_type = insn.ops[0].type
        if op0_type == O_NEAR:
            return "jmp_near"
        elif op0_type == O_REG:
            return "jmp_reg"
        elif op0_type in (O_MEM, O_PHRASE, O_DISPL):
            return "jmp_mem"
        else:
            return "jmp_other"

    # General case: mnemonic + operand classes
    operand_classes = []
    for i in range(8):  # ida_ua supports up to 8 operands
        op = insn.ops[i]
        if op.type == O_VOID:
            break
        cls = _classify_operand(op.type)
        if cls:
            operand_classes.append(cls)

    if operand_classes:
        return f"{mn}_{'_'.join(operand_classes)}"
    else:
        return mn


def _tokenize_function(func_ea, func_end_ea):
    """Tokenize all instructions in a function into a list of (ea, token) pairs.

    Args:
        func_ea: start address of the function
        func_end_ea: end address of the function

    Returns:
        list of (int, str) tuples: [(ea, token), ...]
        Empty list if function is too small or cannot be decoded.
    """
    tokens = []
    insn = ida_ua.insn_t()

    for head_ea in idautils.Heads(func_ea, func_end_ea):
        # Only decode code heads (skip data items within functions)
        flags = ida_bytes.get_flags(head_ea)
        if not ida_bytes.is_code(flags):
            continue

        if ida_ua.decode_insn(insn, head_ea):
            token = _tokenize_instruction(insn)
            tokens.append((head_ea, token))

    return tokens


# ---------------------------------------------------------------------------
# N-gram Extraction
# ---------------------------------------------------------------------------

def _extract_ngrams(tokens, n):
    """Extract all N-grams of size n from a token sequence.

    Args:
        tokens: list of (ea, token_str) pairs
        n: N-gram size

    Returns:
        list of tuples: [(ngram_hash, ngram_tokens_tuple, start_ea, end_ea), ...]
    """
    if len(tokens) < n:
        return []

    ngrams = []
    for i in range(len(tokens) - n + 1):
        window = tokens[i:i + n]
        ngram_tokens = tuple(t[1] for t in window)
        start_ea = window[0][0]
        end_ea = window[-1][0]

        # Hash the token tuple for efficient comparison
        ngram_key = hashlib.md5(
            "|".join(ngram_tokens).encode("utf-8")
        ).hexdigest()[:16]

        ngrams.append((ngram_key, ngram_tokens, start_ea, end_ea))

    return ngrams


def _hash_ngram_tokens(ngram_tokens):
    """Compute a stable hash for an N-gram token tuple.

    Args:
        ngram_tokens: tuple of token strings

    Returns:
        str: 16-character hex hash
    """
    return hashlib.md5(
        "|".join(ngram_tokens).encode("utf-8")
    ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Trivial Pattern Filtering
# ---------------------------------------------------------------------------

def _is_trivial_pattern(ngram_tokens):
    """Check if an N-gram consists entirely of trivial prologue/epilogue tokens.

    Patterns composed only of push/pop/mov rbp,rsp/ret are so common they
    provide no analytical signal.

    Args:
        ngram_tokens: tuple of token strings

    Returns:
        bool: True if the pattern is trivially common and should be filtered
    """
    token_set = set(ngram_tokens)

    # Pure prologue
    if token_set.issubset(_TRIVIAL_PROLOGUE_TOKENS):
        return True

    # Pure epilogue
    if token_set.issubset(_TRIVIAL_EPILOGUE_TOKENS):
        return True

    # Mixed prologue/epilogue only
    if token_set.issubset(_TRIVIAL_PROLOGUE_TOKENS | _TRIVIAL_EPILOGUE_TOKENS):
        return True

    # All nops
    if all(t == "nop" for t in ngram_tokens):
        return True

    # All int3 (padding)
    if all(t == "int3" for t in ngram_tokens):
        return True

    return False


# ---------------------------------------------------------------------------
# Target Function Collection
# ---------------------------------------------------------------------------

def _collect_target_functions(session):
    """Build the set of function EAs to analyze.

    Selects up to MAX_FUNCTIONS functions, prioritizing:
      1. CMSG/SMSG handler functions
      2. Functions with system labels in the DB
      3. Named functions (non-sub_) from IDA
      4. Remaining functions sorted by size (larger = more interesting)

    Only includes functions with >= MIN_INSTRUCTION_COUNT instructions.

    Args:
        session: PluginSession with initialized DB

    Returns:
        dict: {ea: name} of selected functions
    """
    db = session.db
    targets = {}

    msg_info("Collecting target functions for N-gram analysis...")

    # 1. Handler functions from opcode table
    handlers = db.fetchall(
        "SELECT handler_ea, tc_name, jam_type FROM opcodes "
        "WHERE handler_ea IS NOT NULL"
    )
    handler_eas = set()
    for h in handlers:
        ea = h["handler_ea"]
        if ea and ea != 0:
            func = ida_funcs.get_func(ea)
            if func and _count_instructions(func) >= MIN_INSTRUCTION_COUNT:
                name = h["tc_name"] or h["jam_type"] or f"handler_{ea:X}"
                targets[ea] = name
                handler_eas.add(ea)

    msg_info(f"  Handlers: {len(handler_eas)}")

    # 2. System-labeled functions from DB
    system_funcs = db.fetchall(
        "SELECT ea, name, system FROM functions "
        "WHERE system IS NOT NULL AND name IS NOT NULL AND size > 64"
    )
    system_count = 0
    for row in system_funcs:
        ea = row["ea"]
        if ea not in targets and len(targets) < MAX_FUNCTIONS:
            func = ida_funcs.get_func(ea)
            if func and _count_instructions(func) >= MIN_INSTRUCTION_COUNT:
                targets[ea] = row["name"]
                system_count += 1

    msg_info(f"  System-labeled functions: {system_count}")

    # 3. Named functions from IDA (non-sub_, non-j_ prefixes)
    if len(targets) < MAX_FUNCTIONS:
        remaining = MAX_FUNCTIONS - len(targets)
        named_count = 0
        for seg_ea in idautils.Segments():
            if named_count >= remaining:
                break
            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue
            for func_ea in idautils.Functions(seg.start_ea, seg.end_ea):
                if named_count >= remaining:
                    break
                if func_ea in targets:
                    continue
                name = ida_name.get_name(func_ea)
                if name and not name.startswith("sub_") and not name.startswith("j_"):
                    func = ida_funcs.get_func(func_ea)
                    if func and _count_instructions(func) >= MIN_INSTRUCTION_COUNT:
                        targets[func_ea] = name
                        named_count += 1

        msg_info(f"  Additional named functions: {named_count}")

    msg_info(f"  Total target functions: {len(targets)}")
    return targets


def _count_instructions(func):
    """Count the number of code instructions in a function.

    Args:
        func: ida_funcs.func_t object

    Returns:
        int: instruction count
    """
    count = 0
    for head_ea in idautils.Heads(func.start_ea, func.end_ea):
        flags = ida_bytes.get_flags(head_ea)
        if ida_bytes.is_code(flags):
            count += 1
    return count


# ---------------------------------------------------------------------------
# System Label Retrieval
# ---------------------------------------------------------------------------

def _get_function_system(session, ea):
    """Look up the game system label for a function.

    Args:
        session: PluginSession
        ea: function address

    Returns:
        str or None: system label (e.g., "housing", "combat")
    """
    row = session.db.fetchone(
        "SELECT system FROM functions WHERE ea = ?", (ea,)
    )
    if row and row["system"]:
        return row["system"]
    return None


def _build_system_function_map(session, function_eas):
    """Build a mapping of system -> set of function EAs.

    Args:
        session: PluginSession
        function_eas: iterable of function addresses

    Returns:
        dict: {system_name: set(ea, ...)}
    """
    system_map = defaultdict(set)

    # Batch query from DB
    rows = session.db.fetchall(
        "SELECT ea, system FROM functions WHERE system IS NOT NULL"
    )
    db_systems = {}
    for row in rows:
        db_systems[row["ea"]] = row["system"]

    for ea in function_eas:
        system = db_systems.get(ea)
        if system:
            system_map[system].add(ea)

    return dict(system_map)


# ---------------------------------------------------------------------------
# Frequent Pattern Mining
# ---------------------------------------------------------------------------

def _mine_frequent_patterns(all_function_ngrams, min_frequency=MIN_COMMON_FREQUENCY):
    """Find N-grams that appear across many functions.

    Args:
        all_function_ngrams: dict {func_ea: {ngram_hash: (tokens, start_ea, end_ea), ...}}
        min_frequency: minimum number of distinct functions an N-gram must appear in

    Returns:
        list of dicts sorted by score (frequency x length):
            [{hash, tokens, frequency, function_count, representative_ea, n}, ...]
    """
    # Count how many distinct functions contain each N-gram hash
    ngram_func_count = Counter()    # hash -> count of distinct functions
    ngram_tokens_map = {}           # hash -> tokens tuple
    ngram_representative = {}       # hash -> (representative_ea, func_ea)

    for func_ea, ngrams_dict in all_function_ngrams.items():
        seen_in_func = set()
        for ngram_hash, (tokens, start_ea, end_ea) in ngrams_dict.items():
            if ngram_hash not in seen_in_func:
                seen_in_func.add(ngram_hash)
                ngram_func_count[ngram_hash] += 1

            # Store token mapping and a representative location
            if ngram_hash not in ngram_tokens_map:
                ngram_tokens_map[ngram_hash] = tokens
                ngram_representative[ngram_hash] = start_ea

    # Filter by minimum frequency and remove trivial patterns
    frequent = []
    for ngram_hash, count in ngram_func_count.items():
        if count < min_frequency:
            continue

        tokens = ngram_tokens_map[ngram_hash]
        if _is_trivial_pattern(tokens):
            continue

        n = len(tokens)
        score = count * n  # Longer common patterns are more interesting

        frequent.append({
            "hash": ngram_hash,
            "tokens": list(tokens),
            "frequency": count,
            "function_count": count,
            "representative_ea": ngram_representative[ngram_hash],
            "n": n,
            "score": score,
        })

    # Sort by score descending
    frequent.sort(key=lambda x: x["score"], reverse=True)

    return frequent[:TOP_PATTERNS_LIMIT]


# ---------------------------------------------------------------------------
# Inlined Function Recovery
# ---------------------------------------------------------------------------

def _detect_inline_candidates(all_function_ngrams, frequent_patterns,
                              all_function_tokens):
    """Detect likely inlined functions from frequent non-boundary N-grams.

    An inlined function candidate is a frequent N-gram sequence that:
      - Appears in many functions (high frequency)
      - Is NOT located at the very start or end of those functions (not prologue/epilogue)
      - Contains at least one interesting instruction (not pure data movement)

    Overlapping frequent N-grams are clustered into single inline candidates.

    Args:
        all_function_ngrams: dict {func_ea: {hash: (tokens, start, end)}}
        frequent_patterns: list of frequent pattern dicts
        all_function_tokens: dict {func_ea: [(ea, token), ...]}

    Returns:
        list of inline candidate dicts
    """
    # Build a set of frequent hashes for quick lookup
    frequent_hashes = {p["hash"]: p for p in frequent_patterns}

    # For each function, find frequent N-grams that are NOT at boundaries
    # boundary = first 3 or last 3 instructions of the function
    BOUNDARY_MARGIN = 3

    # Track where each frequent N-gram appears (non-boundary)
    ngram_interior_locations = defaultdict(list)  # hash -> [(func_ea, start_ea)]

    for func_ea, ngrams_dict in all_function_ngrams.items():
        tokens = all_function_tokens.get(func_ea, [])
        if not tokens:
            continue

        func_start = tokens[0][0] if tokens else 0
        func_end = tokens[-1][0] if tokens else 0

        # Compute boundary addresses
        boundary_start_eas = set(t[0] for t in tokens[:BOUNDARY_MARGIN])
        boundary_end_eas = set(t[0] for t in tokens[-BOUNDARY_MARGIN:])

        for ngram_hash, (tok, start_ea, end_ea) in ngrams_dict.items():
            if ngram_hash not in frequent_hashes:
                continue

            # Check if this N-gram occurrence is at a function boundary
            if start_ea in boundary_start_eas or end_ea in boundary_end_eas:
                continue

            ngram_interior_locations[ngram_hash].append((func_ea, start_ea))

    # Filter: only keep N-grams that appear in the interior of multiple functions
    MIN_INTERIOR_OCCURRENCES = 5

    candidates_raw = []
    for ngram_hash, locations in ngram_interior_locations.items():
        if len(locations) < MIN_INTERIOR_OCCURRENCES:
            continue

        pattern = frequent_hashes[ngram_hash]
        tokens = pattern["tokens"]

        # Skip if it's just basic data movement
        interesting_mnemonics = {"call_near", "call_mem", "call_reg", "call_mem_disp"}
        has_call = any(t.startswith("call") for t in tokens)

        candidates_raw.append({
            "hash": ngram_hash,
            "tokens": tokens,
            "n": len(tokens),
            "frequency": len(locations),
            "has_call": has_call,
            "locations": locations,
        })

    # Cluster overlapping candidates: if two N-gram candidates share locations
    # and their token sequences overlap, merge them into one candidate
    candidates_raw.sort(key=lambda c: (c["n"], c["frequency"]), reverse=True)

    merged_candidates = []
    used_hashes = set()

    for candidate in candidates_raw:
        if candidate["hash"] in used_hashes:
            continue

        # Find overlapping candidates (same locations, overlapping tokens)
        cluster = [candidate]
        used_hashes.add(candidate["hash"])

        loc_set = set((f, s) for f, s in candidate["locations"])

        for other in candidates_raw:
            if other["hash"] in used_hashes:
                continue
            other_loc_set = set((f, s) for f, s in other["locations"])

            # Check overlap ratio
            overlap = len(loc_set & other_loc_set)
            if overlap >= min(len(loc_set), len(other_loc_set)) * 0.5:
                cluster.append(other)
                used_hashes.add(other["hash"])
                loc_set |= other_loc_set

        # Build merged candidate from cluster
        # Use the longest token sequence as the representative
        best = max(cluster, key=lambda c: c["n"])

        # Try to name from callees
        estimated_name = _estimate_inline_name(best, all_function_tokens)

        # Collect example locations (up to 10)
        example_locations = []
        seen_funcs = set()
        for func_ea, start_ea in best["locations"]:
            if func_ea not in seen_funcs and len(example_locations) < 10:
                seen_funcs.add(func_ea)
                func_name = ida_name.get_name(func_ea) or ea_str(func_ea)
                example_locations.append({
                    "func_ea": func_ea,
                    "func_name": func_name,
                    "inline_ea": start_ea,
                })

        merged_candidates.append({
            "tokens": best["tokens"],
            "frequency": len(loc_set),
            "estimated_function_name": estimated_name,
            "example_locations": example_locations,
            "has_call": best["has_call"],
            "n": best["n"],
            "cluster_size": len(cluster),
        })

    # Sort by frequency * length
    merged_candidates.sort(key=lambda c: c["frequency"] * c["n"], reverse=True)

    return merged_candidates[:TOP_PATTERNS_LIMIT]


def _estimate_inline_name(candidate, all_function_tokens):
    """Try to guess the name of an inlined function from its call targets.

    If the inlined sequence contains a call instruction, the callee name
    can hint at what the inlined function was (e.g., call to memcpy suggests
    an inlined copy routine).

    Args:
        candidate: inline candidate dict
        all_function_tokens: dict {func_ea: [(ea, token), ...]}

    Returns:
        str: estimated name or "unknown_inline"
    """
    if not candidate["has_call"]:
        return "unknown_inline"

    # Find a location where this N-gram occurs and examine call targets
    for func_ea, start_ea in candidate["locations"][:5]:
        func_tokens = all_function_tokens.get(func_ea, [])
        if not func_tokens:
            continue

        # Find the start_ea in the token list
        for idx, (ea, token) in enumerate(func_tokens):
            if ea == start_ea:
                # Look at the N-gram window for call instructions
                window = func_tokens[idx:idx + candidate["n"]]
                for w_ea, w_token in window:
                    if w_token.startswith("call"):
                        # Get the callee name
                        insn = ida_ua.insn_t()
                        if ida_ua.decode_insn(insn, w_ea):
                            if insn.ops[0].type in (O_NEAR, O_FAR):
                                callee_ea = insn.ops[0].addr
                                callee_name = ida_name.get_name(callee_ea)
                                if callee_name and not callee_name.startswith("sub_"):
                                    # Derive inline name from callee
                                    return f"inlined_around_{callee_name}"
                break

    return "unknown_inline"


# ---------------------------------------------------------------------------
# System Fingerprinting
# ---------------------------------------------------------------------------

def _build_system_fingerprints(all_function_ngrams, system_function_map,
                               all_ngram_func_count):
    """Find N-gram patterns characteristic of specific game systems.

    A system fingerprint is an N-gram that is overrepresented in functions
    belonging to one game system compared to the overall population.

    We use a simple enrichment score: (frequency_in_system / system_size) /
    (frequency_overall / total_functions). A score > 3.0 means the pattern
    is 3x more common in that system than expected by chance.

    Args:
        all_function_ngrams: dict {func_ea: {hash: (tokens, start, end)}}
        system_function_map: dict {system: set(ea, ...)}
        all_ngram_func_count: Counter {hash: total_func_count}

    Returns:
        list of system fingerprint dicts
    """
    total_functions = len(all_function_ngrams)
    if total_functions == 0:
        return []

    MIN_ENRICHMENT = 3.0
    MIN_SYSTEM_FREQUENCY = 3
    MAX_PATTERNS_PER_SYSTEM = 20

    fingerprints = []

    for system, system_eas in system_function_map.items():
        system_size = len(system_eas)
        if system_size < 5:
            continue

        # Count N-gram frequencies within this system
        system_ngram_count = Counter()
        system_ngram_tokens = {}

        for func_ea in system_eas:
            ngrams_dict = all_function_ngrams.get(func_ea, {})
            seen = set()
            for ngram_hash, (tokens, start_ea, end_ea) in ngrams_dict.items():
                if ngram_hash not in seen:
                    seen.add(ngram_hash)
                    system_ngram_count[ngram_hash] += 1
                    if ngram_hash not in system_ngram_tokens:
                        system_ngram_tokens[ngram_hash] = tokens

        # Compute enrichment for each N-gram
        system_patterns = []
        for ngram_hash, sys_count in system_ngram_count.items():
            if sys_count < MIN_SYSTEM_FREQUENCY:
                continue

            overall_count = all_ngram_func_count.get(ngram_hash, 1)
            tokens = system_ngram_tokens[ngram_hash]

            if _is_trivial_pattern(tokens):
                continue

            # Enrichment score
            sys_rate = sys_count / system_size
            overall_rate = overall_count / total_functions
            if overall_rate == 0:
                continue

            enrichment = sys_rate / overall_rate

            if enrichment >= MIN_ENRICHMENT:
                system_patterns.append({
                    "hash": ngram_hash,
                    "tokens": list(tokens),
                    "system_frequency": sys_count,
                    "overall_frequency": overall_count,
                    "enrichment": round(enrichment, 2),
                    "n": len(tokens),
                })

        # Sort by enrichment descending and keep top N
        system_patterns.sort(key=lambda p: p["enrichment"], reverse=True)
        system_patterns = system_patterns[:MAX_PATTERNS_PER_SYSTEM]

        if system_patterns:
            fingerprints.append({
                "system": system,
                "function_count": system_size,
                "unique_patterns": system_patterns,
            })

    # Sort systems by number of unique patterns found
    fingerprints.sort(key=lambda f: len(f["unique_patterns"]), reverse=True)

    return fingerprints


def classify_function_by_ngrams(session, ea):
    """Predict which game system a function belongs to based on its N-gram profile.

    Compares the function's N-grams against stored system fingerprints
    and returns the best-matching system.

    Args:
        session: PluginSession
        ea: function address

    Returns:
        str: predicted system name, or "unknown" if no match
    """
    stored = session.db.kv_get("instruction_ngrams")
    if not stored or "system_fingerprints" not in stored:
        return "unknown"

    func = ida_funcs.get_func(ea)
    if not func:
        return "unknown"

    tokens = _tokenize_function(func.start_ea, func.end_ea)
    if len(tokens) < MIN_INSTRUCTION_COUNT:
        return "unknown"

    # Extract N-grams for this function
    func_ngram_hashes = set()
    for n in NGRAM_SIZES:
        ngrams = _extract_ngrams(tokens, n)
        for ngram_hash, _, _, _ in ngrams:
            func_ngram_hashes.add(ngram_hash)

    if not func_ngram_hashes:
        return "unknown"

    # Score against each system's fingerprints
    best_system = "unknown"
    best_score = 0.0

    for fp_entry in stored["system_fingerprints"]:
        system = fp_entry["system"]
        score = 0.0

        for pattern in fp_entry["unique_patterns"]:
            if pattern["hash"] in func_ngram_hashes:
                # Weight by enrichment and N-gram length
                score += pattern["enrichment"] * pattern["n"]

        if score > best_score:
            best_score = score
            best_system = system

    return best_system


# ---------------------------------------------------------------------------
# Assembly-Level Clone Detection
# ---------------------------------------------------------------------------

def _detect_assembly_clones(all_function_ngrams, function_names,
                            min_shared=MIN_CLONE_SHARED_NGRAMS):
    """Find function pairs that share long N-gram sequences.

    This is assembly-level copy-paste detection. Two functions sharing many
    8-gram sequences are likely derived from the same source, even if the
    decompiler would normalize them differently.

    Args:
        all_function_ngrams: dict {func_ea: {hash: (tokens, start, end)}}
        function_names: dict {func_ea: name}
        min_shared: minimum number of shared N-grams for a pair to be reported

    Returns:
        list of clone pair dicts sorted by similarity
    """
    # Build inverted index: ngram_hash -> set of func_eas
    # Only use longer N-grams (n >= 6) for clone detection
    ngram_to_funcs = defaultdict(set)
    ngram_lengths = {}

    for func_ea, ngrams_dict in all_function_ngrams.items():
        for ngram_hash, (tokens, start_ea, end_ea) in ngrams_dict.items():
            n = len(tokens)
            if n >= 6:
                ngram_to_funcs[ngram_hash].add(func_ea)
                ngram_lengths[ngram_hash] = n

    # Count shared N-grams between function pairs
    pair_shared_count = Counter()
    pair_shared_length_sum = Counter()

    for ngram_hash, func_set in ngram_to_funcs.items():
        if len(func_set) < 2 or len(func_set) > 50:
            # Skip very common patterns (appear in 50+ functions)
            continue

        func_list = sorted(func_set)
        n = ngram_lengths.get(ngram_hash, 6)

        for i in range(len(func_list)):
            for j in range(i + 1, len(func_list)):
                pair = (func_list[i], func_list[j])
                pair_shared_count[pair] += 1
                pair_shared_length_sum[pair] += n

    # Filter pairs by minimum shared count
    clones = []
    for (ea_a, ea_b), shared_count in pair_shared_count.most_common():
        if shared_count < min_shared:
            break

        # Compute similarity as shared N-grams / total unique N-grams
        ngrams_a = set(all_function_ngrams.get(ea_a, {}).keys())
        ngrams_b = set(all_function_ngrams.get(ea_b, {}).keys())
        union_size = len(ngrams_a | ngrams_b)
        if union_size == 0:
            continue

        intersection_size = len(ngrams_a & ngrams_b)
        similarity = intersection_size / union_size

        name_a = function_names.get(ea_a, ea_str(ea_a))
        name_b = function_names.get(ea_b, ea_str(ea_b))

        clones.append({
            "func_a_ea": ea_a,
            "func_a_name": name_a,
            "func_b_ea": ea_b,
            "func_b_name": name_b,
            "shared_ngram_count": shared_count,
            "shared_length_sum": pair_shared_length_sum[(ea_a, ea_b)],
            "similarity": round(similarity, 4),
        })

        if len(clones) >= TOP_CLONES_LIMIT:
            break

    # Sort by similarity descending
    clones.sort(key=lambda c: c["similarity"], reverse=True)

    return clones


# ---------------------------------------------------------------------------
# Compiler Pattern Catalog
# ---------------------------------------------------------------------------

def _detect_compiler_patterns(all_function_tokens, all_function_ngrams):
    """Identify MSVC-specific compiler patterns in the analyzed functions.

    Detects:
      - Security cookie checks (/GS)
      - SEH prolog/epilog patterns
      - PGO (Profile-Guided Optimization) artifacts
      - Vectorized loops (SIMD instruction sequences)
      - RTTI-related patterns

    Args:
        all_function_tokens: dict {func_ea: [(ea, token), ...]}
        all_function_ngrams: dict {func_ea: {hash: (tokens, start, end)}}

    Returns:
        list of compiler pattern dicts
    """
    pattern_counts = Counter()
    pattern_examples = defaultdict(list)
    MAX_EXAMPLES = 5

    for func_ea, tokens in all_function_tokens.items():
        if not tokens:
            continue

        token_strs = [t[1] for t in tokens]
        func_name = ida_name.get_name(func_ea) or ea_str(func_ea)

        # --- Security cookie initialization ---
        _check_token_sequence(
            token_strs, tokens, func_ea, func_name,
            ["mov_reg_mem", "xor_reg_reg"],
            "security_cookie_init",
            pattern_counts, pattern_examples, MAX_EXAMPLES,
            require_near_start=True, start_window=10
        )

        # --- Security cookie check ---
        _check_token_sequence(
            token_strs, tokens, func_ea, func_name,
            ["xor_reg_reg", "call_near"],
            "security_cookie_check",
            pattern_counts, pattern_examples, MAX_EXAMPLES,
            require_near_end=True, end_window=8
        )

        # --- SEH prolog ---
        _check_seh_patterns(
            token_strs, tokens, func_ea, func_name,
            pattern_counts, pattern_examples, MAX_EXAMPLES
        )

        # --- SIMD / vectorized loops ---
        _check_simd_patterns(
            token_strs, tokens, func_ea, func_name,
            pattern_counts, pattern_examples, MAX_EXAMPLES
        )

        # --- PGO cold code split ---
        _check_pgo_patterns(
            token_strs, tokens, func_ea, func_name,
            pattern_counts, pattern_examples, MAX_EXAMPLES
        )

        # --- RTTI patterns ---
        _check_rtti_patterns(
            func_ea, func_name,
            pattern_counts, pattern_examples, MAX_EXAMPLES
        )

    # Build result list
    results = []
    for pattern_type, count in pattern_counts.most_common():
        desc = COMPILER_PATTERN_DEFS.get(pattern_type, {}).get(
            "description", pattern_type
        )
        examples = pattern_examples.get(pattern_type, [])

        results.append({
            "type": pattern_type,
            "frequency": count,
            "description": desc,
            "examples": examples[:MAX_EXAMPLES],
        })

    return results


def _check_token_sequence(token_strs, tokens, func_ea, func_name,
                          pattern_tokens, pattern_name,
                          counts, examples, max_examples,
                          require_near_start=False, start_window=0,
                          require_near_end=False, end_window=0):
    """Check if a function contains a specific token sub-sequence.

    Args:
        token_strs: list of token strings from the function
        tokens: list of (ea, token) pairs
        func_ea: function start address
        func_name: function name
        pattern_tokens: list of tokens to search for
        pattern_name: name of the pattern for counting
        counts: Counter to increment
        examples: defaultdict(list) for example storage
        max_examples: max examples to store per pattern
        require_near_start: if True, pattern must be within start_window of function start
        start_window: how many instructions from start to search
        require_near_end: if True, pattern must be within end_window of function end
        end_window: how many instructions from end to search
    """
    plen = len(pattern_tokens)
    search_range = range(len(token_strs) - plen + 1)

    if require_near_start:
        search_range = range(min(start_window, len(token_strs) - plen + 1))
    elif require_near_end:
        start_idx = max(0, len(token_strs) - end_window - plen + 1)
        search_range = range(start_idx, len(token_strs) - plen + 1)

    for i in search_range:
        match = True
        for j in range(plen):
            if token_strs[i + j] != pattern_tokens[j]:
                match = False
                break
        if match:
            counts[pattern_name] += 1
            if len(examples[pattern_name]) < max_examples:
                examples[pattern_name].append({
                    "func_ea": func_ea,
                    "func_name": func_name,
                    "offset": i,
                })
            return  # Only count once per function


def _check_seh_patterns(token_strs, tokens, func_ea, func_name,
                        counts, examples, max_examples):
    """Detect SEH (Structured Exception Handling) prolog and epilog patterns.

    MSVC SEH prologs typically involve storing the frame pointer and setting
    up exception registration records. Common pattern:
      mov [rsp+8], rbx       (save nonvolatile)
      mov [rsp+10h], rsi     (save nonvolatile)
      push rbp
      lea rbp, [rsp-X]       (frame pointer)

    Args:
        token_strs: list of token strings
        tokens: list of (ea, token)
        func_ea: function address
        func_name: function name
        counts: Counter
        examples: defaultdict(list)
        max_examples: int
    """
    if len(token_strs) < 4:
        return

    # SEH prolog: starts with mov_mem_disp_reg, mov_mem_disp_reg, push_reg
    prolog_patterns = [
        ["mov_mem_disp_reg", "mov_mem_disp_reg", "push_reg", "lea_reg_mem_disp"],
        ["mov_mem_disp_reg", "push_reg", "lea_reg_mem_disp"],
        ["push_reg", "sub_reg_imm", "lea_reg_mem_disp", "mov_mem_disp_reg"],
    ]

    for pat in prolog_patterns:
        plen = len(pat)
        for i in range(min(5, len(token_strs) - plen + 1)):
            if all(token_strs[i + j] == pat[j] for j in range(plen)):
                counts["seh_prolog"] += 1
                if len(examples["seh_prolog"]) < max_examples:
                    examples["seh_prolog"].append({
                        "func_ea": func_ea,
                        "func_name": func_name,
                        "offset": i,
                    })
                break
        else:
            continue
        break

    # SEH epilog: lea rsp, [rbp+X]; pop rbp sequence near function end
    epilog_patterns = [
        ["lea_reg_mem_disp", "pop_reg", "ret"],
        ["lea_reg_mem_disp", "mov_reg_mem_disp", "pop_reg", "ret"],
    ]

    for pat in epilog_patterns:
        plen = len(pat)
        start = max(0, len(token_strs) - 8)
        for i in range(start, len(token_strs) - plen + 1):
            if all(token_strs[i + j] == pat[j] for j in range(plen)):
                counts["seh_epilog"] += 1
                if len(examples["seh_epilog"]) < max_examples:
                    examples["seh_epilog"].append({
                        "func_ea": func_ea,
                        "func_name": func_name,
                        "offset": i,
                    })
                break
        else:
            continue
        break


def _check_simd_patterns(token_strs, tokens, func_ea, func_name,
                         counts, examples, max_examples):
    """Detect SIMD/vectorized loop patterns.

    Looks for sequences with multiple SSE/AVX instructions (movaps, addps,
    mulps, etc.) that indicate compiler-vectorized loops.

    Args:
        token_strs: list of token strings
        tokens: list of (ea, token)
        func_ea: function address
        func_name: function name
        counts: Counter
        examples: defaultdict(list)
        max_examples: int
    """
    simd_prefixes = (
        "movaps", "movups", "movdqa", "movdqu", "addps", "subps", "mulps",
        "divps", "addpd", "subpd", "mulpd", "divpd", "shufps", "shufpd",
        "unpcklps", "unpckhps", "vaddps", "vsubps", "vmulps", "vdivps",
        "vmovaps", "vmovups", "vfmadd", "vfmsub",
        "pshufd", "punpckl", "pcmpeq",
    )

    # Count SIMD instructions in sliding windows of 8
    WINDOW = 8
    MIN_SIMD_IN_WINDOW = 4

    for i in range(len(token_strs) - WINDOW + 1):
        window = token_strs[i:i + WINDOW]
        simd_count = 0
        for t in window:
            mnemonic = t.split("_")[0] if "_" in t else t
            if any(mnemonic.startswith(sp) for sp in simd_prefixes):
                simd_count += 1

        if simd_count >= MIN_SIMD_IN_WINDOW:
            counts["simd_loop_body"] += 1
            if len(examples["simd_loop_body"]) < max_examples:
                examples["simd_loop_body"].append({
                    "func_ea": func_ea,
                    "func_name": func_name,
                    "offset": i,
                    "simd_density": simd_count,
                })
            return  # Only count once per function


def _check_pgo_patterns(token_strs, tokens, func_ea, func_name,
                        counts, examples, max_examples):
    """Detect PGO (Profile-Guided Optimization) artifacts.

    PGO-compiled code often has:
      - Unlikely branches that jump far away (cold code separation)
      - test reg, reg followed by jnz to a distant label then jmp to another
      - Function splitting (part of function in different section)

    Args:
        token_strs: list of token strings
        tokens: list of (ea, token)
        func_ea: function address
        func_name: function name
        counts: Counter
        examples: defaultdict(list)
        max_examples: int
    """
    # Look for test/cmp + conditional jump + unconditional jump pattern
    # This is characteristic of PGO-separated hot/cold paths
    for i in range(len(token_strs) - 2):
        if (token_strs[i] in ("test_reg_reg", "cmp_reg_imm", "cmp_reg_reg")
                and token_strs[i + 1].startswith("j") and token_strs[i + 1] != "jmp_near"
                and token_strs[i + 2] == "jmp_near"):
            # Check if the jmp target is far from current location
            if i + 2 < len(tokens):
                jmp_ea = tokens[i + 2][0]
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, jmp_ea):
                    if insn.ops[0].type == O_NEAR:
                        target = insn.ops[0].addr
                        distance = abs(target - jmp_ea)
                        if distance > 0x1000:  # More than 4KB away = likely cold split
                            counts["pgo_cold_split"] += 1
                            if len(examples["pgo_cold_split"]) < max_examples:
                                examples["pgo_cold_split"].append({
                                    "func_ea": func_ea,
                                    "func_name": func_name,
                                    "offset": i,
                                    "jump_distance": distance,
                                })
                            return


def _check_rtti_patterns(func_ea, func_name, counts, examples, max_examples):
    """Detect RTTI-related patterns in a function.

    Functions whose names contain RTTI indicators (dynamic_cast, typeid,
    type_info, __RTtypeid, etc.) are cataloged.

    Args:
        func_ea: function address
        func_name: function name
        counts: Counter
        examples: defaultdict(list)
        max_examples: int
    """
    rtti_indicators = [
        "dynamic_cast", "typeid", "type_info", "__RTtypeid",
        "__RTDynamicCast", "??_R0", "??_R1", "??_R2", "??_R3", "??_R4",
        "??_7",  # vtable symbol
    ]

    for indicator in rtti_indicators:
        if indicator in func_name:
            counts["rtti_usage"] += 1
            if len(examples["rtti_usage"]) < max_examples:
                examples["rtti_usage"].append({
                    "func_ea": func_ea,
                    "func_name": func_name,
                    "indicator": indicator,
                })
            return


# ---------------------------------------------------------------------------
# Export / Query Helpers
# ---------------------------------------------------------------------------

def get_top_patterns(session, n=50):
    """Return the top N most frequent non-trivial instruction patterns.

    Args:
        session: PluginSession
        n: number of patterns to return

    Returns:
        list of pattern dicts, or empty list if no data
    """
    stored = session.db.kv_get("instruction_ngrams")
    if not stored or "frequent_patterns" not in stored:
        return []

    return stored["frequent_patterns"][:n]


def get_system_fingerprints(session, system):
    """Return N-gram patterns unique to a specific game system.

    Args:
        session: PluginSession
        system: system name (e.g., "housing", "combat")

    Returns:
        list of pattern dicts for the specified system, or empty list
    """
    stored = session.db.kv_get("instruction_ngrams")
    if not stored or "system_fingerprints" not in stored:
        return []

    for fp_entry in stored["system_fingerprints"]:
        if fp_entry["system"] == system:
            return fp_entry["unique_patterns"]

    return []


def get_ngram_report(session):
    """Return the full stored N-gram analysis results.

    Args:
        session: PluginSession

    Returns:
        dict: full analysis results, or None if not yet run
    """
    return session.db.kv_get("instruction_ngrams")


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def analyze_instruction_ngrams(session):
    """Run the full instruction N-gram analysis pipeline.

    Steps:
      1. Collect target functions (handlers, system-labeled, named)
      2. Tokenize all instructions in each function
      3. Extract N-grams at multiple granularities (4, 6, 8)
      4. Mine frequent patterns
      5. Detect inlined function candidates
      6. Build system fingerprints
      7. Detect assembly-level clones
      8. Catalog compiler patterns
      9. Store results in the knowledge DB

    Args:
        session: PluginSession with initialized DB

    Returns:
        int: total number of patterns found
    """
    start_time = time.time()
    db = session.db

    msg("=" * 60)
    msg("Instruction N-gram Analyzer")
    msg("=" * 60)

    # ── Step 1: Collect target functions ──────────────────────────
    targets = _collect_target_functions(session)
    if not targets:
        msg_warn("No target functions found. Run opcode discovery first.")
        return 0

    total_funcs = len(targets)
    progress_step = max(total_funcs * PROGRESS_INTERVAL_PCT // 100, 1)

    # ── Step 2: Tokenize all functions ───────────────────────────
    msg_info("Tokenizing instructions...")
    all_function_tokens = {}   # func_ea -> [(ea, token), ...]
    skipped = 0
    errors = 0

    for idx, (func_ea, func_name) in enumerate(targets.items()):
        if idx > 0 and idx % progress_step == 0:
            pct = idx * 100 // total_funcs
            msg(f"  Tokenizing: {pct}% ({idx}/{total_funcs})")

        func = ida_funcs.get_func(func_ea)
        if not func:
            skipped += 1
            continue

        try:
            tokens = _tokenize_function(func.start_ea, func.end_ea)
            if len(tokens) < MIN_INSTRUCTION_COUNT:
                skipped += 1
                continue
            all_function_tokens[func_ea] = tokens
        except Exception as e:
            errors += 1
            if errors <= 5:
                msg_warn(f"  Tokenization error at {ea_str(func_ea)}: {e}")

    msg_info(f"Tokenized {len(all_function_tokens)} functions "
             f"(skipped {skipped}, errors {errors})")

    if len(all_function_tokens) < 2:
        msg_warn("Too few functions tokenized. Cannot analyze N-grams.")
        return 0

    # ── Step 3: Extract N-grams ──────────────────────────────────
    msg_info("Extracting N-grams...")
    all_function_ngrams = {}   # func_ea -> {hash: (tokens, start, end)}
    total_ngrams = 0
    ngram_func_count = Counter()   # hash -> distinct function count

    for idx, (func_ea, tokens) in enumerate(all_function_tokens.items()):
        if idx > 0 and idx % progress_step == 0:
            pct = idx * 100 // len(all_function_tokens)
            msg(f"  Extracting N-grams: {pct}% ({idx}/{len(all_function_tokens)})")

        func_ngrams = {}
        seen_hashes = set()

        for n in NGRAM_SIZES:
            ngrams = _extract_ngrams(tokens, n)
            for ngram_hash, ngram_tokens, start_ea, end_ea in ngrams:
                # Store only the first occurrence of each hash per function
                if ngram_hash not in func_ngrams:
                    func_ngrams[ngram_hash] = (ngram_tokens, start_ea, end_ea)

                if ngram_hash not in seen_hashes:
                    seen_hashes.add(ngram_hash)
                    ngram_func_count[ngram_hash] += 1

                total_ngrams += 1

        all_function_ngrams[func_ea] = func_ngrams

    msg_info(f"Extracted {total_ngrams} total N-grams "
             f"({len(ngram_func_count)} unique)")

    # ── Step 4: Mine frequent patterns ───────────────────────────
    msg_info("Mining frequent patterns...")
    frequent_patterns = _mine_frequent_patterns(
        all_function_ngrams, min_frequency=MIN_COMMON_FREQUENCY
    )
    msg_info(f"Found {len(frequent_patterns)} frequent non-trivial patterns")

    # Log top 10
    for i, pat in enumerate(frequent_patterns[:10]):
        tokens_preview = " ".join(pat["tokens"][:6])
        if len(pat["tokens"]) > 6:
            tokens_preview += "..."
        msg(f"  #{i+1}: freq={pat['frequency']} n={pat['n']} "
            f"score={pat['score']} [{tokens_preview}]")

    # ── Step 5: Detect inlined function candidates ────────────────
    msg_info("Detecting inlined function candidates...")
    inline_candidates = _detect_inline_candidates(
        all_function_ngrams, frequent_patterns, all_function_tokens
    )
    msg_info(f"Found {len(inline_candidates)} inline candidates")

    for i, cand in enumerate(inline_candidates[:5]):
        tokens_preview = " ".join(cand["tokens"][:6])
        if len(cand["tokens"]) > 6:
            tokens_preview += "..."
        msg(f"  #{i+1}: freq={cand['frequency']} "
            f"name={cand['estimated_function_name']} [{tokens_preview}]")

    # ── Step 6: Build system fingerprints ─────────────────────────
    msg_info("Building system fingerprints...")
    system_function_map = _build_system_function_map(
        session, all_function_tokens.keys()
    )
    msg_info(f"  Systems with labeled functions: {len(system_function_map)}")
    for system, eas in sorted(system_function_map.items(),
                               key=lambda x: len(x[1]), reverse=True):
        msg(f"    {system}: {len(eas)} functions")

    system_fingerprints = _build_system_fingerprints(
        all_function_ngrams, system_function_map, ngram_func_count
    )
    total_fingerprint_patterns = sum(
        len(fp["unique_patterns"]) for fp in system_fingerprints
    )
    msg_info(f"Found {total_fingerprint_patterns} system fingerprint patterns "
             f"across {len(system_fingerprints)} systems")

    for fp in system_fingerprints[:5]:
        msg(f"  {fp['system']}: {len(fp['unique_patterns'])} unique patterns "
            f"({fp['function_count']} functions)")

    # ── Step 7: Detect assembly-level clones ──────────────────────
    msg_info("Detecting assembly-level clones...")
    assembly_clones = _detect_assembly_clones(
        all_function_ngrams, targets, min_shared=MIN_CLONE_SHARED_NGRAMS
    )
    msg_info(f"Found {len(assembly_clones)} assembly clone pairs")

    for i, clone in enumerate(assembly_clones[:5]):
        msg(f"  #{i+1}: {clone['func_a_name']} <-> {clone['func_b_name']} "
            f"similarity={clone['similarity']:.3f} "
            f"shared={clone['shared_ngram_count']}")

    # ── Step 8: Catalog compiler patterns ─────────────────────────
    msg_info("Cataloging compiler patterns...")
    compiler_patterns = _detect_compiler_patterns(
        all_function_tokens, all_function_ngrams
    )
    msg_info(f"Found {len(compiler_patterns)} compiler pattern types")

    for cp in compiler_patterns:
        msg(f"  {cp['type']}: {cp['frequency']} occurrences - {cp['description']}")

    # ── Step 9: Serialize results for storage ─────────────────────
    # Convert EAs to strings for JSON serialization
    serializable_patterns = []
    for pat in frequent_patterns:
        sp = dict(pat)
        sp["representative_ea"] = ea_str(pat["representative_ea"])
        serializable_patterns.append(sp)

    serializable_inlines = []
    for cand in inline_candidates:
        sc = dict(cand)
        sc_locs = []
        for loc in cand.get("example_locations", []):
            sl = dict(loc)
            sl["func_ea"] = ea_str(loc["func_ea"])
            sl["inline_ea"] = ea_str(loc["inline_ea"])
            sc_locs.append(sl)
        sc["example_locations"] = sc_locs
        # Remove raw locations (not serializable, too large)
        sc.pop("locations", None)
        serializable_inlines.append(sc)

    serializable_clones = []
    for clone in assembly_clones:
        sc = dict(clone)
        sc["func_a_ea"] = ea_str(clone["func_a_ea"])
        sc["func_b_ea"] = ea_str(clone["func_b_ea"])
        serializable_clones.append(sc)

    serializable_compiler = []
    for cp in compiler_patterns:
        scp = dict(cp)
        ser_examples = []
        for ex in cp.get("examples", []):
            se = dict(ex)
            se["func_ea"] = ea_str(ex["func_ea"])
            ser_examples.append(se)
        scp["examples"] = ser_examples
        serializable_compiler.append(scp)

    results = {
        "total_functions_analyzed": len(all_function_tokens),
        "total_ngrams_extracted": total_ngrams,
        "unique_ngrams": len(ngram_func_count),
        "ngram_sizes": list(NGRAM_SIZES),
        "frequent_patterns": serializable_patterns,
        "inline_candidates": serializable_inlines,
        "system_fingerprints": system_fingerprints,
        "assembly_clones": serializable_clones,
        "compiler_patterns": serializable_compiler,
        "analysis_time_seconds": round(time.time() - start_time, 2),
        "timestamp": time.time(),
    }

    # Store in knowledge DB
    db.kv_set("instruction_ngrams", results)
    db.commit()

    # ── Summary ───────────────────────────────────────────────────
    elapsed = time.time() - start_time
    total_patterns = (
        len(frequent_patterns)
        + len(inline_candidates)
        + total_fingerprint_patterns
        + len(assembly_clones)
        + sum(cp["frequency"] for cp in compiler_patterns)
    )

    msg("=" * 60)
    msg("Instruction N-gram Analysis Complete")
    msg(f"  Functions analyzed:     {len(all_function_tokens)}")
    msg(f"  Total N-grams:          {total_ngrams} ({len(ngram_func_count)} unique)")
    msg(f"  Frequent patterns:      {len(frequent_patterns)}")
    msg(f"  Inline candidates:      {len(inline_candidates)}")
    msg(f"  System fingerprints:    {total_fingerprint_patterns} across "
        f"{len(system_fingerprints)} systems")
    msg(f"  Assembly clones:        {len(assembly_clones)} pairs")
    msg(f"  Compiler patterns:      {len(compiler_patterns)} types")
    msg(f"  Time elapsed:           {elapsed:.1f}s")
    msg("=" * 60)

    return total_patterns
