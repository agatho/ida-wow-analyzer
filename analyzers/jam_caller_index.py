"""
JAM Caller Index
================
Walks XrefsTo every JAM serializer / deserializer EA known from the
`jam_types` table, attributing the *callers* as packet-construction sites:

  * A caller of `JamClient*_Serialize`   builds an outbound (CMSG) packet
  * A caller of `JamServer*_Serialize`   builds an outbound (SMSG) packet
                                          (rare — only 4 server-message types)
  * A caller of `Jam*_Deserialize`       reads an inbound packet payload

This is the closest viable proxy to a full "CMSG sender sweep" without
having identified WorldPacket / SendPacket helpers — every JAM serializer
caller is by construction a packet builder.

For each unique caller we:
  1. Set `functions.system='network'`, `subsystem='packet_builder'`,
     `confidence=70`.
  2. Add a repeatable comment `[Builds JAM] <Type1>, <Type2>, ...` listing
     every JAM type the function references.
  3. Emit `kv_store["jam_caller_index"] = {caller_ea_hex: {types, kinds}}`.

The output map is consumed downstream by Cross-Analyzer Synthesis and
Handler Scaffolding to enrich CMSG sender code generation.
"""

import time
from collections import defaultdict

import ida_funcs
import idautils

from tc_wow_analyzer.core.utils import msg_info, msg_warn
from tc_wow_analyzer.analyzers.idb_enrichment import (
    _try_set_comment, _try_rename, _safe_struct_name,
)


def _rename_prefix_for_kinds(kinds):
    """Pick the rename prefix based on the unambiguous direction.

    Returns one of "Send", "Recv", or None when ambiguous.
    """
    has_send = "cmsg_sender" in kinds or "smsg_sender" in kinds
    has_recv = "packet_receiver" in kinds
    if has_send and not has_recv:
        return "Send"
    if has_recv and not has_send:
        return "Recv"
    return None


def _classify_jam(name):
    """Return ('cli'|'srv'|'shared', kind_label)."""
    if not name:
        return ("shared", "shared")
    if name.startswith("JamClient") or name.startswith("JamCli"):
        return ("cli", "cmsg_sender")
    if name.startswith("JamServer") or name.startswith("JamSvr"):
        return ("srv", "smsg_sender")
    return ("shared", "shared")


def analyze_jam_caller_index(session):
    db = session.db
    if db is None:
        msg_warn("JAM caller index: no DB")
        return 0

    rows = db.fetchall(
        "SELECT name, serializer_ea, deserializer_ea FROM jam_types "
        "WHERE name IS NOT NULL"
    )
    if not rows:
        msg_warn("JAM caller index: jam_types table empty — run JAM Recovery first")
        return 0

    t0 = time.time()
    msg_info(f"JAM caller index: walking xrefs for {len(rows)} JAM types")

    # caller_ea -> {"types": set[str], "kinds": set[str]}
    caller_map = defaultdict(lambda: {"types": set(), "kinds": set()})
    serializer_skipped = 0  # missing/invalid EAs
    xrefs_walked = 0

    for r in rows:
        jam_name = r["name"]
        cls, kind = _classify_jam(jam_name)

        for col in ("serializer_ea", "deserializer_ea"):
            ea = r[col]
            if not ea:
                continue
            target = ida_funcs.get_func(ea)
            if not target:
                serializer_skipped += 1
                continue
            target_ea = target.start_ea

            for xref in idautils.XrefsTo(target_ea, 0):
                xrefs_walked += 1
                caller = ida_funcs.get_func(xref.frm)
                if not caller:
                    continue
                caller_ea = caller.start_ea
                if caller_ea == target_ea:
                    continue  # self-ref / recursive
                entry = caller_map[caller_ea]
                entry["types"].add(jam_name)
                # If we walked a deserializer xref, the caller is a *receiver*,
                # not a builder. Tag distinctly.
                if col == "deserializer_ea":
                    entry["kinds"].add("packet_receiver")
                else:
                    entry["kinds"].add(kind)

    msg_info(
        f"JAM caller index: walked {xrefs_walked} xrefs, "
        f"{len(caller_map)} unique caller functions "
        f"(skipped {serializer_skipped} invalid serializer EAs)"
    )

    # Apply tags + comments + (where unambiguous) renames
    tagged = 0
    commented = 0
    renamed = 0
    rename_skipped_ambiguous = 0
    rename_skipped_multi_type = 0
    for caller_ea, entry in caller_map.items():
        types = sorted(entry["types"])
        kinds = sorted(entry["kinds"])

        # Pick the most specific subsystem label
        if "cmsg_sender" in kinds:
            subsystem = "cmsg_sender"
        elif "smsg_sender" in kinds:
            subsystem = "smsg_sender"
        elif "packet_receiver" in kinds:
            subsystem = "packet_receiver"
        else:
            subsystem = "packet_builder"

        try:
            db.upsert_function(
                ea=caller_ea,
                rva=session.cfg.ea_to_rva(caller_ea),
                system="network",
                subsystem=subsystem,
                confidence=70,
            )
            tagged += 1
        except Exception:
            pass

        # Comment — list up to 6 JAM types, then count remainder
        head = ", ".join(types[:6])
        if len(types) > 6:
            head += f", +{len(types) - 6} more"
        comment = f"[Builds JAM] {head}"
        if _try_set_comment(caller_ea, comment, repeatable=True):
            commented += 1

        # Rename — only when there's exactly one type AND an unambiguous
        # direction (sender XOR receiver). Skip otherwise.
        if len(types) != 1:
            rename_skipped_multi_type += 1
            continue
        prefix = _rename_prefix_for_kinds(set(kinds))
        if prefix is None:
            rename_skipped_ambiguous += 1
            continue
        safe = _safe_struct_name(types[0])
        if not safe:
            continue
        desired = f"{prefix}_{safe}"
        if _try_rename(caller_ea, desired):
            renamed += 1

    db.commit()

    # Persist the map (hex-string keys; sets become sorted lists for JSON)
    serialized = {
        f"0x{ea:X}": {
            "types": sorted(v["types"]),
            "kinds": sorted(v["kinds"]),
        }
        for ea, v in caller_map.items()
    }
    result = {
        "version": 1,
        "callers_total": len(caller_map),
        "tagged": tagged,
        "comments_set": commented,
        "renamed": renamed,
        "rename_skipped_ambiguous": rename_skipped_ambiguous,
        "rename_skipped_multi_type": rename_skipped_multi_type,
        "xrefs_walked": xrefs_walked,
        "serializer_skipped": serializer_skipped,
        "elapsed_sec": round(time.time() - t0, 2),
        "callers": serialized,
    }
    db.kv_set("jam_caller_index", result)
    db.commit()

    msg_info(
        f"JAM caller index: tagged={tagged} commented={commented} "
        f"renamed={renamed} (skipped {rename_skipped_multi_type} multi-type, "
        f"{rename_skipped_ambiguous} ambiguous-direction) "
        f"({result['elapsed_sec']}s)"
    )
    return tagged
