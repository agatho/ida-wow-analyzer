"""
MSVC Compiler Artifact Mining

Extracts intelligence about runtime behaviour from MSVC compiler artifacts found
in the WoW binary: hot/cold code splitting (PGO), branch prediction hints, loop
unrolling, SIMD instruction usage, /GS security cookies, stack frame analysis,
alignment padding, optimization level detection, and COMDAT folding (ICF).

These artifacts reveal which code paths are expected (hot) vs exceptional (cold),
which functions are performance-critical (SIMD, unrolled loops), what the
developer considered security-sensitive (/GS), and where identical template
instantiations exist (ICF).

Results are stored in the knowledge DB under key ``compiler_artifacts``.
"""

import json
import re
import time
import struct
from collections import defaultdict

import ida_funcs
import ida_name
import ida_bytes
import ida_ua
import ida_segment
import idautils
import idaapi
import idc

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str,
)


# ---------------------------------------------------------------------------
# Constants: x86-64 instruction mnemonics
# ---------------------------------------------------------------------------

# SSE scalar/packed float/double
_SSE_MNEMONICS = frozenset([
    "movaps", "movups", "movapd", "movupd",
    "movss", "movsd", "movlps", "movhps", "movlpd", "movhpd",
    "movlhps", "movhlps", "movmskps", "movmskpd",
    "addps", "addpd", "addss", "addsd",
    "subps", "subpd", "subss", "subsd",
    "mulps", "mulpd", "mulss", "mulsd",
    "divps", "divpd", "divss", "divsd",
    "sqrtps", "sqrtpd", "sqrtss", "sqrtsd",
    "rcpps", "rcpss", "rsqrtps", "rsqrtss",
    "maxps", "maxpd", "maxss", "maxsd",
    "minps", "minpd", "minss", "minsd",
    "cmpps", "cmppd", "cmpss", "cmpsd",
    "comiss", "comisd", "ucomiss", "ucomisd",
    "andps", "andpd", "andnps", "andnpd",
    "orps", "orpd", "xorps", "xorpd",
    "shufps", "shufpd", "unpckhps", "unpcklps",
    "unpckhpd", "unpcklpd",
    "cvtps2pd", "cvtpd2ps", "cvtss2sd", "cvtsd2ss",
    "cvtps2dq", "cvtdq2ps", "cvtpd2dq", "cvtdq2pd",
    "cvtss2si", "cvtsd2si", "cvtsi2ss", "cvtsi2sd",
    "cvttps2dq", "cvttpd2dq", "cvttss2si", "cvttsd2si",
    "dpps", "dppd",
    "haddps", "haddpd", "hsubps", "hsubpd",
    "blendps", "blendpd", "blendvps", "blendvpd",
    "insertps", "extractps",
    "roundps", "roundpd", "roundss", "roundsd",
    # SSE integer in XMM
    "paddd", "paddq", "psubd", "psubq", "pmulld", "pmuludq",
    "pand", "pandn", "por", "pxor",
    "pcmpeqd", "pcmpgtd", "pcmpeqb", "pcmpgtb",
    "pshufd", "pshufb", "pshuflw", "pshufhw",
    "punpckhwd", "punpckhdq", "punpckhqdq",
    "punpcklwd", "punpckldq", "punpcklqdq",
    "packuswb", "packsswb", "packusdw", "packssdw",
    "movdqa", "movdqu", "movq", "movd",
    "pslld", "psrld", "psllq", "psrlq", "pslldq", "psrldq",
    "pmaxsd", "pmaxud", "pminsd", "pminud",
    "pmaxsw", "pmaxuw", "pminsw", "pminuw",
])

# AVX (VEX-encoded)
_AVX_MNEMONICS = frozenset([
    "vmovaps", "vmovups", "vmovapd", "vmovupd",
    "vmovss", "vmovsd", "vmovdqa", "vmovdqu",
    "vaddps", "vaddpd", "vaddss", "vaddsd",
    "vsubps", "vsubpd", "vsubss", "vsubsd",
    "vmulps", "vmulpd", "vmulss", "vmulsd",
    "vdivps", "vdivpd", "vdivss", "vdivsd",
    "vsqrtps", "vsqrtpd", "vsqrtss", "vsqrtsd",
    "vmaxps", "vmaxpd", "vminps", "vminpd",
    "vcmpps", "vcmppd", "vcomiss", "vcomisd",
    "vandps", "vandpd", "vandnps", "vandnpd",
    "vorps", "vorpd", "vxorps", "vxorpd",
    "vshufps", "vshufpd",
    "vblendps", "vblendpd", "vblendvps", "vblendvpd",
    "vinsertps", "vextractps",
    "vbroadcastss", "vbroadcastsd", "vbroadcastf128",
    "vperm2f128", "vpermilps", "vpermilpd",
    "vfmadd132ps", "vfmadd213ps", "vfmadd231ps",
    "vfmadd132pd", "vfmadd213pd", "vfmadd231pd",
    "vfmadd132ss", "vfmadd213ss", "vfmadd231ss",
    "vfmadd132sd", "vfmadd213sd", "vfmadd231sd",
    "vfmsub132ps", "vfmsub213ps", "vfmsub231ps",
    "vfmsub132pd", "vfmsub213pd", "vfmsub231pd",
    "vfnmadd132ps", "vfnmadd213ps", "vfnmadd231ps",
    "vfnmadd132pd", "vfnmadd213pd", "vfnmadd231pd",
    "vdpps", "vdppd", "vhaddps", "vhaddpd",
    "vroundps", "vroundpd", "vroundss", "vroundsd",
    "vrcpps", "vrsqrtps",
    "vpaddd", "vpsubd", "vpmulld",
    "vpand", "vpandn", "vpor", "vpxor",
    "vpshufd", "vpshufb",
    "vmovq", "vmovd",
    "vpslld", "vpsrld", "vpsllq", "vpsrlq",
    "vzeroupper", "vzeroall",
    # AVX-512 basics
    "vmovaps", "vmovups",
])

_ALL_SIMD = _SSE_MNEMONICS | _AVX_MNEMONICS

# NOP-family for alignment detection
_NOP_MNEMONICS = frozenset([
    "nop", "xchg",   # xchg eax, eax is a 1-byte NOP on x86
])

# System classification (same scheme as other analyzers)
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
    "Database":    ["Database", "MySQL", "Query", "Transaction"],
    "World":       ["World", "WorldUpdate", "Tick", "Update"],
    "Object":      ["Object", "ObjectMgr", "ObjectGuid", "GUID"],
    "Garrison":    ["Garrison", "Follower", "Mission", "Shipment"],
    "Collection":  ["Collection", "Mount", "Toy", "Heirloom", "Transmog",
                    "Wardrobe"],
    "Rendering":   ["Render", "Draw", "GxDevice", "Shader", "Texture",
                    "Model", "M2", "WMO"],
    "Math":        ["Vector", "Matrix", "Quaternion", "Math", "Lerp",
                    "Bezier", "Spline"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _classify_system(func_name):
    """Map a function name to a game system via keyword matching."""
    if not func_name:
        return "Unknown"
    upper = func_name.upper()
    for system, keywords in _SYSTEM_PATTERNS.items():
        for kw in keywords:
            if kw.upper() in upper:
                return system
    return "Unknown"


def _get_func_name(ea):
    """Return the IDA name at *ea*, or a hex string if unnamed/sub_."""
    name = ida_name.get_name(ea)
    if name and not name.startswith("sub_"):
        return name
    return ea_str(ea)


def _get_import_name(ea):
    """Resolve an import name, stripping __imp_ / j_ prefixes."""
    name = ida_name.get_name(ea)
    if not name:
        return None
    for prefix in ("j_", "__imp_", "_imp_", "__imp__"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name


def _iter_func_instructions(func):
    """Yield (ea, mnemonic, insn) for every instruction in *func*,
    including non-contiguous chunks."""
    # Iterate over all chunks of the function
    fci = ida_funcs.func_tail_iterator_t(func)
    ok = fci.main()
    while ok:
        chunk = fci.chunk()
        for head in idautils.Heads(chunk.start_ea, chunk.end_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, head) > 0:
                mnem = insn.get_canon_mnem()
                yield head, mnem, insn
        ok = fci.next()


def _segment_of(ea):
    """Return the segment name containing *ea*."""
    seg = ida_segment.getseg(ea)
    if seg:
        return ida_segment.get_segm_name(seg)
    return ""


# ---------------------------------------------------------------------------
# Phase 1: Hot / Cold Code Splitting Detection
# ---------------------------------------------------------------------------

def _detect_hot_cold_splits():
    """Find functions with non-contiguous chunks (PGO hot/cold splitting).

    MSVC PGO places the main body in .text and cold parts in .text$mn or
    a separated address range.  IDA models these as "function tails"
    (additional chunks belonging to the same function).

    Returns a list of dicts describing each split function.
    """
    results = []

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        # Collect all chunks for this function
        chunks = []
        fci = ida_funcs.func_tail_iterator_t(func)
        ok = fci.main()
        while ok:
            chunk = fci.chunk()
            chunks.append({
                "start": chunk.start_ea,
                "end": chunk.end_ea,
                "size": chunk.end_ea - chunk.start_ea,
                "segment": _segment_of(chunk.start_ea),
            })
            ok = fci.next()

        if len(chunks) <= 1:
            continue

        # The first chunk is the "hot" (main) body
        hot_chunk = chunks[0]
        cold_chunks = chunks[1:]
        hot_size = hot_chunk["size"]
        cold_size = sum(c["size"] for c in cold_chunks)

        func_name = _get_func_name(func_ea)
        system = _classify_system(func_name)

        # Determine if cold chunks are in a different segment
        hot_seg = hot_chunk["segment"]
        cross_segment = any(c["segment"] != hot_seg for c in cold_chunks)

        results.append({
            "function_ea": ea_str(func_ea),
            "name": func_name,
            "hot_size": hot_size,
            "cold_size": cold_size,
            "cold_chunk_count": len(cold_chunks),
            "cold_chunk_ea": ea_str(cold_chunks[0]["start"]),
            "cross_segment": cross_segment,
            "hot_segment": hot_seg,
            "cold_segments": list(set(c["segment"] for c in cold_chunks)),
            "system": system,
            "total_size": hot_size + cold_size,
            "cold_ratio": round(cold_size / max(1, hot_size + cold_size), 3),
        })

    results.sort(key=lambda r: r["cold_size"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Phase 2: Security Cookie (/GS) Analysis
# ---------------------------------------------------------------------------

def _find_gs_protected_functions():
    """Identify functions that call ``__security_check_cookie``.

    These have the /GS stack buffer overrun protection.  The presence of /GS
    tells us the function uses a stack buffer large enough to trigger the
    compiler heuristic (typically >= 4 bytes for arrays of chars, >= 8 for
    pointers).

    We also extract an estimate of the buffer size from the stack frame.
    """
    results = []

    # Find __security_check_cookie import(s)
    cookie_eas = []
    for seg_ea in idautils.Segments():
        for head in idautils.Heads(seg_ea, ida_segment.getseg(seg_ea).end_ea):
            name = _get_import_name(head)
            if name and "security_check_cookie" in name.lower():
                cookie_eas.append(head)
            elif name and "security_cookie" in name.lower():
                cookie_eas.append(head)

    if not cookie_eas:
        # Try by name search
        for name_ea, name_str in idautils.Names():
            lower = name_str.lower()
            if "security_check_cookie" in lower or "__security_cookie" in lower:
                cookie_eas.append(name_ea)

    if not cookie_eas:
        return results

    # Find all callers of __security_check_cookie
    caller_funcs = set()
    for cookie_ea in cookie_eas:
        for xref in idautils.XrefsTo(cookie_ea, 0):
            caller_func = ida_funcs.get_func(xref.frm)
            if caller_func:
                caller_funcs.add(caller_func.start_ea)

    for func_ea in sorted(caller_funcs):
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = _get_func_name(func_ea)
        frame_size = idc.get_func_attr(func_ea, idc.FUNCATTR_FRSIZE)
        if frame_size is None or frame_size == idc.BADADDR:
            frame_size = 0

        system = _classify_system(func_name)

        results.append({
            "function_ea": ea_str(func_ea),
            "name": func_name,
            "buffer_size_estimate": frame_size,
            "system": system,
        })

    results.sort(key=lambda r: r["buffer_size_estimate"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Phase 3: SIMD (SSE/AVX) Pattern Detection
# ---------------------------------------------------------------------------

def _classify_simd_purpose(mnemonic_counts, func_name):
    """Heuristically classify the SIMD purpose based on instruction mix
    and function name."""
    # Count categories
    packed_float = 0
    scalar_float = 0
    integer_simd = 0
    shuffle_blend = 0
    fma_count = 0
    broadcast = 0
    convert = 0
    dot_product = 0

    for mnem, count in mnemonic_counts.items():
        lower = mnem.lower()
        if lower.endswith(("ps", "pd")) and not lower.startswith(("cvt", "shuf")):
            packed_float += count
        elif lower.endswith(("ss", "sd")):
            scalar_float += count
        elif any(lower.startswith(p) for p in
                 ("padd", "psub", "pmul", "pand", "por", "pxor",
                  "pcmp", "pack", "punpck", "vpadd", "vpsub",
                  "vpmul", "vpand", "vpor", "vpxor")):
            integer_simd += count
        if any(lower.startswith(p) for p in
               ("shuf", "blend", "pshuf", "unpack", "insert", "extract",
                "vperm", "vshuf", "vblend", "vpshuf")):
            shuffle_blend += count
        if "fma" in lower or "fms" in lower or "fnma" in lower:
            fma_count += count
        if "broadcast" in lower:
            broadcast += count
        if lower.startswith("cvt") or lower.startswith("vcvt"):
            convert += count
        if lower.startswith(("dpps", "dppd", "vdpps", "vdppd")):
            dot_product += count

    # Classify
    name_lower = (func_name or "").lower()
    total_packed = packed_float + integer_simd

    if dot_product > 0 or "dot" in name_lower:
        return "dot_product"
    if fma_count > 0:
        if any(kw in name_lower for kw in ("matrix", "mat", "transform")):
            return "matrix_math"
        return "fused_multiply_add"
    if any(kw in name_lower for kw in
           ("matrix", "mat4", "mat3", "transform")):
        return "matrix_math"
    if any(kw in name_lower for kw in
           ("quaternion", "quat", "slerp", "nlerp")):
        return "quaternion_math"
    if any(kw in name_lower for kw in
           ("vector", "vec3", "vec4", "normalize", "cross", "length")):
        return "vector_math"
    if any(kw in name_lower for kw in
           ("aabb", "bounds", "frustum", "intersect", "collision", "raycast")):
        return "collision_geometry"
    if any(kw in name_lower for kw in ("memcpy", "memmove", "memset", "rep")):
        return "memory_operation"
    if any(kw in name_lower for kw in ("string", "str", "wcs", "char")):
        return "string_operation"
    if shuffle_blend > total_packed * 0.5 and shuffle_blend > 3:
        return "data_permutation"
    if packed_float > scalar_float * 2 and packed_float > 4:
        return "batch_float_processing"
    if integer_simd > packed_float and integer_simd > 4:
        return "batch_integer_processing"
    if packed_float > 2:
        return "vector_math"
    if scalar_float > 2:
        return "scalar_float_math"
    return "general_simd"


def _detect_simd_functions():
    """Scan all functions for SSE/AVX instruction usage.

    Returns a list of dicts describing functions with significant SIMD usage.
    """
    results = []

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        mnemonic_counts = defaultdict(int)
        total_insns = 0
        simd_insn_count = 0
        has_avx = False

        for head, mnem, insn in _iter_func_instructions(func):
            total_insns += 1
            lower_mnem = mnem.lower()
            if lower_mnem in _ALL_SIMD:
                mnemonic_counts[lower_mnem] += 1
                simd_insn_count += 1
                if lower_mnem in _AVX_MNEMONICS:
                    has_avx = True

        if simd_insn_count < 2:
            continue

        func_name = _get_func_name(func_ea)
        simd_type = "AVX" if has_avx else "SSE"
        purpose = _classify_simd_purpose(mnemonic_counts, func_name)
        system = _classify_system(func_name)

        # Determine data type hints from instruction suffixes
        data_types = set()
        for mnem in mnemonic_counts:
            if mnem.endswith("ps") or mnem.endswith("ss"):
                data_types.add("float")
            elif mnem.endswith("pd") or mnem.endswith("sd"):
                data_types.add("double")
            elif any(mnem.startswith(p) for p in ("padd", "psub", "pmul", "pcmp",
                                                   "vpadd", "vpsub", "vpmul")):
                data_types.add("int32")

        density = round(simd_insn_count / max(1, total_insns), 3)

        results.append({
            "function_ea": ea_str(func_ea),
            "name": func_name,
            "simd_type": simd_type,
            "instruction_count": simd_insn_count,
            "total_instructions": total_insns,
            "simd_density": density,
            "purpose": purpose,
            "data_types": sorted(data_types),
            "top_mnemonics": dict(sorted(mnemonic_counts.items(),
                                         key=lambda x: -x[1])[:10]),
            "system": system,
        })

    results.sort(key=lambda r: r["instruction_count"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Phase 4: Loop Analysis
# ---------------------------------------------------------------------------

def _analyze_loops():
    """Detect loops via backward jumps, estimate unroll factors, and flag
    vectorised loops (loops containing SIMD instructions).

    We use a lightweight heuristic: a backward conditional branch (target
    address < instruction address) indicates a loop back-edge.  For each
    loop we scan the body for:
      - SIMD instructions (vectorised loop)
      - Repeated identical instruction sequences (unrolled)
      - prefetch instructions (hint at trip count)
      - loop-carried dependencies (inc/dec of a register across iterations)
    """
    results = []

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        # Collect all instructions with their addresses
        insn_list = []
        for head, mnem, insn in _iter_func_instructions(func):
            insn_list.append((head, mnem, insn))

        if not insn_list:
            continue

        # Find backward conditional jumps (loop back-edges)
        back_edges = []
        for head, mnem, insn in insn_list:
            lower = mnem.lower()
            # Conditional jumps: j* except jmp
            if lower.startswith("j") and lower != "jmp":
                # Check if the branch target is backward
                target = insn.Op1.addr
                if target != 0 and target < head:
                    back_edges.append({
                        "branch_ea": head,
                        "loop_top": target,
                        "mnemonic": lower,
                    })

        if not back_edges:
            continue

        func_name = _get_func_name(func_ea)

        for edge in back_edges:
            loop_top = edge["loop_top"]
            loop_bottom = edge["branch_ea"]
            loop_size = loop_bottom - loop_top

            # Skip tiny or huge "loops" (likely not real loops)
            if loop_size < 4 or loop_size > 65536:
                continue

            # Scan loop body
            body_mnemonics = []
            simd_in_loop = 0
            prefetch_count = 0
            has_inc_dec = False
            has_cmp = False

            for head, mnem, insn in insn_list:
                if head < loop_top or head > loop_bottom:
                    continue
                lower = mnem.lower()
                body_mnemonics.append(lower)
                if lower in _ALL_SIMD:
                    simd_in_loop += 1
                if lower in ("prefetcht0", "prefetcht1", "prefetcht2",
                             "prefetchnta", "prefetchw"):
                    prefetch_count += 1
                if lower in ("inc", "dec", "add", "sub"):
                    has_inc_dec = True
                if lower in ("cmp", "test"):
                    has_cmp = True

            is_vectorized = simd_in_loop >= 2

            # Estimate unroll factor from repeated instruction patterns
            unroll_factor = _estimate_unroll_factor(body_mnemonics)
            is_unrolled = unroll_factor > 1

            # Estimate trip count from unroll factor and prefetch distance
            estimated_trip_count = None
            if unroll_factor > 1:
                # Unrolled loops typically run many iterations
                estimated_trip_count = unroll_factor * 4  # rough heuristic
            if prefetch_count > 0:
                estimated_trip_count = max(estimated_trip_count or 0, 64)

            results.append({
                "function_ea": ea_str(func_ea),
                "function_name": func_name,
                "loop_ea": ea_str(loop_top),
                "loop_size_bytes": loop_size,
                "body_insn_count": len(body_mnemonics),
                "estimated_trip_count": estimated_trip_count,
                "is_vectorized": is_vectorized,
                "simd_insn_count": simd_in_loop,
                "is_unrolled": is_unrolled,
                "unroll_factor": unroll_factor,
                "has_prefetch": prefetch_count > 0,
                "prefetch_count": prefetch_count,
                "system": _classify_system(func_name),
            })

    results.sort(key=lambda r: (r["is_vectorized"], r["is_unrolled"],
                                r["body_insn_count"]), reverse=True)
    return results


def _estimate_unroll_factor(mnemonics):
    """Estimate loop unroll factor by finding repeated instruction subsequences.

    If the same sequence of N mnemonics repeats K times in the body, the
    unroll factor is approximately K.
    """
    if len(mnemonics) < 4:
        return 1

    # Try subsequence lengths from 2 to len/2
    best_factor = 1
    for sublen in range(2, min(32, len(mnemonics) // 2 + 1)):
        # Take the first subsequence as a reference
        ref = mnemonics[:sublen]
        repeats = 0
        i = 0
        while i + sublen <= len(mnemonics):
            if mnemonics[i:i + sublen] == ref:
                repeats += 1
                i += sublen
            else:
                i += 1
        if repeats > best_factor:
            best_factor = repeats

    return best_factor


# ---------------------------------------------------------------------------
# Phase 5: Branch Prediction Hints / Unreachable Code
# ---------------------------------------------------------------------------

def _find_unreachable_markers():
    """Detect compiler-inserted unreachable-code markers:

    - ``int 0x29`` (MSVC __fastfail) — catastrophic error, process terminates
    - ``ud2`` / ``ud2a`` — undefined instruction trap, used for __assume(0)
    - ``int3`` (``0xCC``) — debug breakpoint, assertion failure padding
    - Cold branches: unconditional jumps to a different segment (cold section)
    """
    results = []

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = _get_func_name(func_ea)

        for head, mnem, insn in _iter_func_instructions(func):
            lower = mnem.lower()
            marker_type = None

            if lower == "int":
                # int 0x29 = __fastfail
                int_num = insn.Op1.value
                if int_num == 0x29:
                    marker_type = "fastfail"
                elif int_num == 3:
                    marker_type = "int3_assertion"
            elif lower == "int3":
                marker_type = "int3_assertion"
            elif lower in ("ud2", "ud2a", "ud2b", "ud0"):
                marker_type = "ud2_unreachable"
            elif lower == "hlt":
                marker_type = "hlt_unreachable"

            if marker_type:
                results.append({
                    "function_ea": ea_str(func_ea),
                    "function_name": func_name,
                    "unreachable_ea": ea_str(head),
                    "marker_type": marker_type,
                    "system": _classify_system(func_name),
                })

    # Also detect cold branches: unconditional jumps whose target is in a
    # different segment than the jump instruction.
    cold_branches = []
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = _get_func_name(func_ea)
        func_seg = _segment_of(func_ea)

        for head, mnem, insn in _iter_func_instructions(func):
            if mnem.lower() != "jmp":
                continue
            target = insn.Op1.addr
            if target == 0 or target == idc.BADADDR:
                continue
            target_seg = _segment_of(target)
            if target_seg and target_seg != func_seg:
                cold_branches.append({
                    "function_ea": ea_str(func_ea),
                    "function_name": func_name,
                    "unreachable_ea": ea_str(head),
                    "marker_type": "cold_branch",
                    "target_segment": target_seg,
                    "system": _classify_system(func_name),
                })

    results.extend(cold_branches)
    return results


# ---------------------------------------------------------------------------
# Phase 6: Alignment and Padding Analysis
# ---------------------------------------------------------------------------

def _analyze_alignment():
    """Find NOP sleds used for code alignment and measure alignment patterns.

    Returns statistics about function and loop alignment preferences.
    """
    alignment_stats = {
        "function_alignments": defaultdict(int),
        "nop_sled_count": 0,
        "nop_sled_total_bytes": 0,
        "nop_sleds": [],  # first 200 examples
        "cache_line_aligned_functions": 0,
    }

    # Scan for NOP sleds between functions
    prev_func_end = None
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        # Check alignment of function start
        alignment = 1
        for power in range(1, 13):  # up to 4096
            if func_ea % (1 << power) == 0:
                alignment = 1 << power
            else:
                break
        alignment_stats["function_alignments"][alignment] += 1

        if alignment >= 64:
            alignment_stats["cache_line_aligned_functions"] += 1

        # Check for NOP padding before this function
        if prev_func_end is not None and prev_func_end < func_ea:
            gap_start = prev_func_end
            gap_end = func_ea
            gap_size = gap_end - gap_start

            if 0 < gap_size <= 64:
                # Check if the gap is filled with NOPs (0x90) or multi-byte NOPs
                is_nop_sled = True
                ea = gap_start
                while ea < gap_end:
                    byte_val = ida_bytes.get_byte(ea)
                    if byte_val == 0x90:
                        ea += 1
                    elif byte_val == 0xCC:
                        ea += 1  # int3 padding (also common)
                    elif byte_val == 0x0F and ea + 1 < gap_end:
                        next_byte = ida_bytes.get_byte(ea + 1)
                        if next_byte == 0x1F:
                            # Multi-byte NOP: 0F 1F ...
                            insn = ida_ua.insn_t()
                            insn_len = ida_ua.decode_insn(insn, ea)
                            if insn_len > 0:
                                ea += insn_len
                            else:
                                is_nop_sled = False
                                break
                        else:
                            is_nop_sled = False
                            break
                    elif byte_val == 0x66 and ea + 1 < gap_end:
                        # 66 prefix on NOP
                        next_byte = ida_bytes.get_byte(ea + 1)
                        if next_byte == 0x90 or next_byte == 0x0F:
                            insn = ida_ua.insn_t()
                            insn_len = ida_ua.decode_insn(insn, ea)
                            if insn_len > 0:
                                ea += insn_len
                            else:
                                is_nop_sled = False
                                break
                        else:
                            is_nop_sled = False
                            break
                    else:
                        is_nop_sled = False
                        break

                if is_nop_sled and gap_size > 0:
                    alignment_stats["nop_sled_count"] += 1
                    alignment_stats["nop_sled_total_bytes"] += gap_size
                    if len(alignment_stats["nop_sleds"]) < 200:
                        alignment_stats["nop_sleds"].append({
                            "ea": ea_str(gap_start),
                            "size": gap_size,
                            "before_function": _get_func_name(func_ea),
                        })

        prev_func_end = func.end_ea

    # Convert defaultdict keys to strings for JSON
    alignment_stats["function_alignments"] = {
        str(k): v for k, v in sorted(
            alignment_stats["function_alignments"].items()
        )
    }

    return alignment_stats


# ---------------------------------------------------------------------------
# Phase 7: Stack Frame Analysis
# ---------------------------------------------------------------------------

def _analyze_stack_frames():
    """Extract stack frame sizes and identify functions with large frames
    or dynamic stack allocation (__chkstk).

    Functions with large stack frames (> 4KB) require __chkstk to probe
    the stack guard page.  Extremely large frames may indicate stack-based
    buffers or arrays that are performance-sensitive.
    """
    large_frames = []

    # Find __chkstk import(s) for cross-reference
    chkstk_eas = set()
    for name_ea, name_str in idautils.Names():
        lower = name_str.lower()
        if "chkstk" in lower or "__alloca_probe" in lower:
            chkstk_eas.add(name_ea)

    chkstk_callers = set()
    for chkstk_ea in chkstk_eas:
        for xref in idautils.XrefsTo(chkstk_ea, 0):
            caller = ida_funcs.get_func(xref.frm)
            if caller:
                chkstk_callers.add(caller.start_ea)

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        frame_size = idc.get_func_attr(func_ea, idc.FUNCATTR_FRSIZE)
        if frame_size is None or frame_size == idc.BADADDR:
            continue

        # Only report large frames (> 256 bytes threshold for interest)
        if frame_size < 256:
            continue

        func_name = _get_func_name(func_ea)
        has_chkstk = func_ea in chkstk_callers

        # Check for alloca-style dynamic allocation patterns
        has_alloca = False
        for head, mnem, insn in _iter_func_instructions(func):
            if mnem.lower() == "call":
                target = insn.Op1.addr
                if target and target != idc.BADADDR:
                    target_name = _get_import_name(target)
                    if target_name and ("alloca" in target_name.lower()):
                        has_alloca = True
                        break

        large_frames.append({
            "function_ea": ea_str(func_ea),
            "name": func_name,
            "frame_size": frame_size,
            "has_chkstk": has_chkstk,
            "has_alloca": has_alloca,
            "system": _classify_system(func_name),
        })

    large_frames.sort(key=lambda r: r["frame_size"], reverse=True)
    return large_frames


# ---------------------------------------------------------------------------
# Phase 8: Optimization Level Detection
# ---------------------------------------------------------------------------

def _detect_optimization_patterns():
    """Detect various optimization patterns applied by MSVC:

    - Tail call optimization: function ends with ``jmp`` to another function
      instead of ``call; ret``
    - Dead code: ``nop`` or ``int3`` after unconditional ``jmp`` or ``ret``
    - Inlined functions: functions with no ``call`` instructions that are
      called from many sites (likely inlined everywhere else)

    Returns aggregate statistics.
    """
    stats = {
        "tail_calls": 0,
        "tail_call_functions": [],
        "dead_code_regions": 0,
        "functions_with_no_calls": 0,
        "likely_inlined_count": 0,
        "likely_inlined": [],
    }

    # Pass 1: Count tail calls and dead code
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = _get_func_name(func_ea)

        # Check for tail call: function's last real instruction is a jmp
        # to an address that is another function (not a chunk of this function)
        last_insn_ea = idc.prev_head(func.end_ea)
        if last_insn_ea != idc.BADADDR:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, last_insn_ea) > 0:
                mnem = insn.get_canon_mnem().lower()
                if mnem == "jmp":
                    target = insn.Op1.addr
                    if target and target != idc.BADADDR:
                        target_func = ida_funcs.get_func(target)
                        # Is the target a different function (not a chunk of ours)?
                        if target_func and target_func.start_ea != func_ea:
                            # Verify it's at the function boundary (not mid-func)
                            stats["tail_calls"] += 1
                            if len(stats["tail_call_functions"]) < 500:
                                target_name = _get_func_name(target_func.start_ea)
                                stats["tail_call_functions"].append({
                                    "function_ea": ea_str(func_ea),
                                    "name": func_name,
                                    "tail_target": target_name,
                                    "tail_target_ea": ea_str(target_func.start_ea),
                                })

        # Count functions with zero call instructions (leaf functions)
        has_call = False
        insn_count = 0
        for head, mnem, insn_obj in _iter_func_instructions(func):
            insn_count += 1
            if mnem.lower() == "call":
                has_call = True
                break

        if not has_call and insn_count > 0:
            stats["functions_with_no_calls"] += 1

    # Pass 2: Detect likely inlined functions
    # Small functions (< 20 instructions) with many xrefs-to are candidates
    # that were inlined in most call sites.
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        func_size = func.end_ea - func.start_ea
        if func_size > 64:  # too large to be commonly inlined
            continue

        # Count how many call sites reference this function
        xref_count = 0
        for xref in idautils.XrefsTo(func_ea, 0):
            if xref.type in (idaapi.fl_CN, idaapi.fl_CF):
                xref_count += 1

        # A small function called very few times was likely inlined elsewhere
        # (the remaining call sites are the few that weren't inlined)
        if func_size <= 20 and 1 <= xref_count <= 3:
            func_name = _get_func_name(func_ea)
            # Don't count unnamed stubs
            if not func_name.startswith("0x"):
                stats["likely_inlined_count"] += 1
                if len(stats["likely_inlined"]) < 200:
                    stats["likely_inlined"].append({
                        "function_ea": ea_str(func_ea),
                        "name": func_name,
                        "size": func_size,
                        "remaining_call_sites": xref_count,
                    })

    return stats


# ---------------------------------------------------------------------------
# Phase 9: COMDAT Folding Detection (ICF)
# ---------------------------------------------------------------------------

def _detect_comdat_folding():
    """Find addresses that have multiple symbol names pointing to them.

    MSVC's Identical COMDAT Folding (/OPT:ICF) merges functions with
    identical machine code into a single copy.  The linker keeps all symbol
    names but they map to one address.  This reveals:
      - Template instantiations with identical implementations
      - Virtual thunks that ended up the same
      - Types that share method implementations
    """
    results = []

    # Build address -> [names] map
    addr_names = defaultdict(list)
    for name_ea, name_str in idautils.Names():
        # Skip IDA auto-names
        if name_str.startswith("sub_") or name_str.startswith("loc_"):
            continue
        if name_str.startswith("off_") or name_str.startswith("dword_"):
            continue
        if name_str.startswith("byte_") or name_str.startswith("qword_"):
            continue
        if name_str.startswith("unk_") or name_str.startswith("word_"):
            continue
        addr_names[name_ea].append(name_str)

    for addr, names in addr_names.items():
        if len(names) < 2:
            continue

        # Verify this is actually a function
        func = ida_funcs.get_func(addr)
        if not func:
            continue

        func_size = func.end_ea - func.start_ea

        results.append({
            "address": ea_str(addr),
            "symbols": names,
            "symbol_count": len(names),
            "function_size": func_size,
        })

    results.sort(key=lambda r: r["symbol_count"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def mine_compiler_artifacts(session) -> int:
    """Analyze the binary for MSVC compiler artifacts.

    Scans for:
      1. Hot/cold code splitting (PGO)
      2. /GS security cookie protected functions
      3. SIMD (SSE/AVX) usage patterns
      4. Loop structures (vectorised, unrolled)
      5. Unreachable code markers (__fastfail, ud2, int3)
      6. Alignment and NOP padding
      7. Stack frame analysis
      8. Optimization patterns (tail calls, inlining)
      9. COMDAT folding (ICF)

    Results are stored in session.db.kv_set("compiler_artifacts", {...}).

    Returns the total number of artifacts found.
    """
    db = session.db
    t0 = time.time()

    msg_info("=== Compiler Artifact Mining: Starting analysis ===")

    # -------------------------------------------------------------------
    # Phase 1: Hot / Cold code splitting
    # -------------------------------------------------------------------
    msg_info("Phase 1: Detecting hot/cold code splitting...")
    hot_cold_splits = _detect_hot_cold_splits()
    msg_info(f"  Found {len(hot_cold_splits)} functions with hot/cold splits")
    if hot_cold_splits:
        total_cold = sum(s["cold_size"] for s in hot_cold_splits)
        cross_seg = sum(1 for s in hot_cold_splits if s["cross_segment"])
        msg_info(f"  Total cold code: {total_cold:,} bytes "
                 f"({cross_seg} cross-segment splits)")

    # -------------------------------------------------------------------
    # Phase 2: /GS security cookies
    # -------------------------------------------------------------------
    msg_info("Phase 2: Analyzing /GS security cookies...")
    gs_protected = _find_gs_protected_functions()
    msg_info(f"  Found {len(gs_protected)} /GS protected functions")
    if gs_protected:
        avg_buf = sum(g["buffer_size_estimate"] for g in gs_protected) // max(1, len(gs_protected))
        msg_info(f"  Average estimated buffer size: {avg_buf} bytes")

    # -------------------------------------------------------------------
    # Phase 3: SIMD detection
    # -------------------------------------------------------------------
    msg_info("Phase 3: Scanning for SIMD (SSE/AVX) usage...")
    simd_functions = _detect_simd_functions()
    msg_info(f"  Found {len(simd_functions)} functions with SIMD instructions")
    if simd_functions:
        avx_count = sum(1 for s in simd_functions if s["simd_type"] == "AVX")
        sse_count = len(simd_functions) - avx_count
        msg_info(f"  SSE: {sse_count}, AVX: {avx_count}")
        # Breakdown by purpose
        purpose_counts = defaultdict(int)
        for s in simd_functions:
            purpose_counts[s["purpose"]] += 1
        for purpose, count in sorted(purpose_counts.items(),
                                     key=lambda x: -x[1]):
            msg_info(f"    {purpose}: {count}")

    # -------------------------------------------------------------------
    # Phase 4: Loop analysis
    # -------------------------------------------------------------------
    msg_info("Phase 4: Analyzing loop structures...")
    loops = _analyze_loops()
    msg_info(f"  Found {len(loops)} loops")
    if loops:
        vectorized = sum(1 for l in loops if l["is_vectorized"])
        unrolled = sum(1 for l in loops if l["is_unrolled"])
        prefetched = sum(1 for l in loops if l["has_prefetch"])
        msg_info(f"  Vectorized: {vectorized}, Unrolled: {unrolled}, "
                 f"Prefetched: {prefetched}")

    # -------------------------------------------------------------------
    # Phase 5: Unreachable code markers
    # -------------------------------------------------------------------
    msg_info("Phase 5: Finding unreachable code markers...")
    unreachable_code = _find_unreachable_markers()
    msg_info(f"  Found {len(unreachable_code)} unreachable markers")
    if unreachable_code:
        marker_counts = defaultdict(int)
        for u in unreachable_code:
            marker_counts[u["marker_type"]] += 1
        for mtype, count in sorted(marker_counts.items(), key=lambda x: -x[1]):
            msg_info(f"    {mtype}: {count}")

    # -------------------------------------------------------------------
    # Phase 6: Alignment analysis
    # -------------------------------------------------------------------
    msg_info("Phase 6: Analyzing code alignment and padding...")
    alignment_stats = _analyze_alignment()
    msg_info(f"  NOP sleds: {alignment_stats['nop_sled_count']} "
             f"({alignment_stats['nop_sled_total_bytes']:,} bytes)")
    msg_info(f"  Cache-line aligned (64B) functions: "
             f"{alignment_stats['cache_line_aligned_functions']}")
    if alignment_stats["function_alignments"]:
        msg_info("  Function alignment distribution:")
        for align, count in sorted(alignment_stats["function_alignments"].items(),
                                   key=lambda x: -x[1])[:8]:
            msg_info(f"    {align}-byte: {count}")

    # -------------------------------------------------------------------
    # Phase 7: Stack frame analysis
    # -------------------------------------------------------------------
    msg_info("Phase 7: Analyzing stack frames...")
    large_stack_frames = _analyze_stack_frames()
    msg_info(f"  Found {len(large_stack_frames)} functions with frames > 256 bytes")
    if large_stack_frames:
        chkstk_count = sum(1 for f in large_stack_frames if f["has_chkstk"])
        alloca_count = sum(1 for f in large_stack_frames if f["has_alloca"])
        largest = large_stack_frames[0]
        msg_info(f"  Largest frame: {largest['name']} "
                 f"({largest['frame_size']:,} bytes)")
        msg_info(f"  Functions with __chkstk: {chkstk_count}")
        msg_info(f"  Functions with alloca: {alloca_count}")

    # -------------------------------------------------------------------
    # Phase 8: Optimization patterns
    # -------------------------------------------------------------------
    msg_info("Phase 8: Detecting optimization patterns...")
    optimization_stats = _detect_optimization_patterns()
    msg_info(f"  Tail calls: {optimization_stats['tail_calls']}")
    msg_info(f"  Leaf functions (no calls): "
             f"{optimization_stats['functions_with_no_calls']}")
    msg_info(f"  Likely inlined: {optimization_stats['likely_inlined_count']}")

    # -------------------------------------------------------------------
    # Phase 9: COMDAT folding
    # -------------------------------------------------------------------
    msg_info("Phase 9: Detecting COMDAT folding (ICF)...")
    comdat_folded = _detect_comdat_folding()
    msg_info(f"  Found {len(comdat_folded)} folded address groups")
    if comdat_folded:
        total_symbols = sum(c["symbol_count"] for c in comdat_folded)
        msg_info(f"  Total symbols mapped to shared addresses: {total_symbols}")
        # Show top examples
        for entry in comdat_folded[:5]:
            syms = entry["symbols"]
            preview = ", ".join(syms[:3])
            if len(syms) > 3:
                preview += f", ... (+{len(syms) - 3} more)"
            msg_info(f"    {entry['address']}: {preview}")

    # -------------------------------------------------------------------
    # Build per-system summary for hot/cold, SIMD, and /GS
    # -------------------------------------------------------------------
    system_summary = defaultdict(lambda: {
        "hot_cold_count": 0,
        "gs_count": 0,
        "simd_count": 0,
        "loop_count": 0,
        "vectorized_loops": 0,
        "unreachable_markers": 0,
        "large_frames": 0,
    })

    for s in hot_cold_splits:
        system_summary[s["system"]]["hot_cold_count"] += 1
    for g in gs_protected:
        system_summary[g["system"]]["gs_count"] += 1
    for s in simd_functions:
        system_summary[s["system"]]["simd_count"] += 1
    for l in loops:
        system_summary[l["system"]]["loop_count"] += 1
        if l["is_vectorized"]:
            system_summary[l["system"]]["vectorized_loops"] += 1
    for u in unreachable_code:
        system_summary[u["system"]]["unreachable_markers"] += 1
    for f in large_stack_frames:
        system_summary[f["system"]]["large_frames"] += 1

    system_summary_serializable = dict(system_summary)

    # -------------------------------------------------------------------
    # Compute totals
    # -------------------------------------------------------------------
    total_artifacts = (
        len(hot_cold_splits)
        + len(gs_protected)
        + len(simd_functions)
        + len(loops)
        + len(unreachable_code)
        + len(large_stack_frames)
        + len(comdat_folded)
        + optimization_stats["tail_calls"]
    )

    elapsed = time.time() - t0

    # -------------------------------------------------------------------
    # Store results
    # -------------------------------------------------------------------
    result = {
        "hot_cold_splits": hot_cold_splits,
        "gs_protected": gs_protected,
        "simd_functions": simd_functions,
        "loops": loops,
        "unreachable_code": unreachable_code,
        "alignment": alignment_stats,
        "large_stack_frames": large_stack_frames,
        "comdat_folded": comdat_folded,
        "optimization_stats": optimization_stats,
        "system_summary": system_summary_serializable,
        "total_artifacts": total_artifacts,
        "analysis_time_seconds": round(elapsed, 2),
    }

    db.kv_set("compiler_artifacts", result)

    # Print final summary
    msg_info(f"=== Compiler Artifact Mining: Complete ({elapsed:.1f}s) ===")
    msg_info(f"  Hot/cold splits:       {len(hot_cold_splits)}")
    msg_info(f"  /GS protected funcs:   {len(gs_protected)}")
    msg_info(f"  SIMD functions:        {len(simd_functions)}")
    msg_info(f"  Loops detected:        {len(loops)}")
    msg_info(f"  Unreachable markers:   {len(unreachable_code)}")
    msg_info(f"  NOP alignment sleds:   {alignment_stats['nop_sled_count']}")
    msg_info(f"  Large stack frames:    {len(large_stack_frames)}")
    msg_info(f"  Tail calls:            {optimization_stats['tail_calls']}")
    msg_info(f"  COMDAT folded groups:  {len(comdat_folded)}")
    msg_info(f"  Total artifacts:       {total_artifacts}")

    if system_summary_serializable:
        msg_info("  Per-system breakdown:")
        for system in sorted(system_summary_serializable.keys()):
            s = system_summary_serializable[system]
            parts = []
            if s["hot_cold_count"]:
                parts.append(f"{s['hot_cold_count']} splits")
            if s["gs_count"]:
                parts.append(f"{s['gs_count']} /GS")
            if s["simd_count"]:
                parts.append(f"{s['simd_count']} SIMD")
            if s["loop_count"]:
                parts.append(f"{s['loop_count']} loops")
            if s["vectorized_loops"]:
                parts.append(f"{s['vectorized_loops']} vec-loops")
            if s["large_frames"]:
                parts.append(f"{s['large_frames']} large-frames")
            if parts:
                msg_info(f"    {system}: {', '.join(parts)}")

    return total_artifacts


# ---------------------------------------------------------------------------
# Report accessors
# ---------------------------------------------------------------------------

def get_compiler_artifacts(session):
    """Retrieve the stored compiler artifact analysis data.

    Returns the full analysis dict, or an empty dict if not yet analyzed.
    """
    return session.db.kv_get("compiler_artifacts") or {}


def get_artifact_summary(session):
    """Get a concise summary of compiler artifact findings.

    Returns a dict with high-level counts and key highlights.
    """
    report = get_compiler_artifacts(session)
    if not report:
        return {"status": "not_analyzed"}

    summary = {
        "status": "analyzed",
        "total_artifacts": report.get("total_artifacts", 0),
        "hot_cold_splits": len(report.get("hot_cold_splits", [])),
        "gs_protected": len(report.get("gs_protected", [])),
        "simd_functions": len(report.get("simd_functions", [])),
        "loops": len(report.get("loops", [])),
        "unreachable_markers": len(report.get("unreachable_code", [])),
        "large_stack_frames": len(report.get("large_stack_frames", [])),
        "comdat_folded": len(report.get("comdat_folded", [])),
        "tail_calls": report.get("optimization_stats", {}).get("tail_calls", 0),
        "analysis_time": report.get("analysis_time_seconds", 0),
    }

    # Add SIMD purpose breakdown
    simd = report.get("simd_functions", [])
    if simd:
        purpose_counts = defaultdict(int)
        for s in simd:
            purpose_counts[s["purpose"]] += 1
        summary["simd_purposes"] = dict(
            sorted(purpose_counts.items(), key=lambda x: -x[1])
        )

    # Add top large frames
    frames = report.get("large_stack_frames", [])
    if frames:
        summary["top_large_frames"] = [
            {"name": f["name"], "size": f["frame_size"]}
            for f in frames[:5]
        ]

    # Add system summary
    sys_summary = report.get("system_summary", {})
    if sys_summary:
        notable = []
        for system, info in sys_summary.items():
            if info.get("simd_count", 0) > 0 or info.get("hot_cold_count", 0) > 5:
                notable.append(system)
        summary["notable_systems"] = sorted(notable)

    return summary


def get_simd_functions(session, purpose=None, system=None):
    """Get SIMD functions, optionally filtered by purpose or system.

    Args:
        purpose: e.g. "vector_math", "matrix_math", "batch_float_processing"
        system: e.g. "Rendering", "Combat", "Movement"

    Returns list of SIMD function dicts.
    """
    report = get_compiler_artifacts(session)
    if not report:
        return []

    funcs = report.get("simd_functions", [])
    if purpose:
        funcs = [f for f in funcs if f.get("purpose") == purpose]
    if system:
        funcs = [f for f in funcs
                 if f.get("system", "").upper() == system.upper()]
    return funcs


def get_hot_cold_splits(session, system=None, min_cold_size=0):
    """Get hot/cold split functions, optionally filtered.

    Args:
        system: Filter by game system name.
        min_cold_size: Minimum cold code size in bytes.

    Returns list of split function dicts.
    """
    report = get_compiler_artifacts(session)
    if not report:
        return []

    splits = report.get("hot_cold_splits", [])
    if system:
        splits = [s for s in splits
                  if s.get("system", "").upper() == system.upper()]
    if min_cold_size > 0:
        splits = [s for s in splits if s.get("cold_size", 0) >= min_cold_size]
    return splits


def get_gs_protected(session, system=None, min_buffer_size=0):
    """Get /GS protected functions, optionally filtered.

    Args:
        system: Filter by game system name.
        min_buffer_size: Minimum estimated buffer size.

    Returns list of /GS protected function dicts.
    """
    report = get_compiler_artifacts(session)
    if not report:
        return []

    funcs = report.get("gs_protected", [])
    if system:
        funcs = [f for f in funcs
                 if f.get("system", "").upper() == system.upper()]
    if min_buffer_size > 0:
        funcs = [f for f in funcs
                 if f.get("buffer_size_estimate", 0) >= min_buffer_size]
    return funcs


def get_vectorized_loops(session, system=None):
    """Get all vectorised (SIMD) loops, optionally filtered by system.

    Returns list of loop dicts where is_vectorized is True.
    """
    report = get_compiler_artifacts(session)
    if not report:
        return []

    loops = report.get("loops", [])
    vec_loops = [l for l in loops if l.get("is_vectorized")]
    if system:
        vec_loops = [l for l in vec_loops
                     if l.get("system", "").upper() == system.upper()]
    return vec_loops


def get_comdat_folded(session, min_symbols=2):
    """Get COMDAT-folded address groups.

    Args:
        min_symbols: Minimum number of symbols at one address.

    Returns list of folded group dicts.
    """
    report = get_compiler_artifacts(session)
    if not report:
        return []

    groups = report.get("comdat_folded", [])
    if min_symbols > 2:
        groups = [g for g in groups if g.get("symbol_count", 0) >= min_symbols]
    return groups


def get_unreachable_code(session, marker_type=None):
    """Get unreachable code markers, optionally filtered by type.

    Args:
        marker_type: "fastfail", "ud2_unreachable", "int3_assertion",
                     "hlt_unreachable", "cold_branch"

    Returns list of unreachable marker dicts.
    """
    report = get_compiler_artifacts(session)
    if not report:
        return []

    markers = report.get("unreachable_code", [])
    if marker_type:
        markers = [m for m in markers if m.get("marker_type") == marker_type]
    return markers


def get_large_stack_frames(session, min_size=4096):
    """Get functions with large stack frames.

    Args:
        min_size: Minimum frame size in bytes (default 4096 = page size).

    Returns list of large-frame function dicts, sorted largest first.
    """
    report = get_compiler_artifacts(session)
    if not report:
        return []

    frames = report.get("large_stack_frames", [])
    return [f for f in frames if f.get("frame_size", 0) >= min_size]


def get_optimization_stats(session):
    """Get optimization pattern statistics.

    Returns dict with tail_calls, functions_with_no_calls, etc.
    """
    report = get_compiler_artifacts(session)
    if not report:
        return {}
    return report.get("optimization_stats", {})


def get_alignment_stats(session):
    """Get code alignment and NOP padding statistics.

    Returns dict with function_alignments, nop_sled_count, etc.
    """
    report = get_compiler_artifacts(session)
    if not report:
        return {}
    return report.get("alignment", {})
