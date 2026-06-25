"""
Packet field importer — populates jam_types.fields_json (the codegen field
source) from the binary's wow_packet_structures_<build>.json.

WHY this exists (verified against the 67186 DB, 2026-06-25):
  The obvious source — wire_format_recovery, which traces Read/Write calls in
  decompiled serializers — recovers ~0 fields on this client. The WoW client's
  JAM serialization is METADATA/REFLECTION-driven: 0 of 466 JAM serializer
  functions contain a single traceable Read<T>()/ReadBits()/ReadPackedGuid()
  call (268 use WowGetRawTypeName<T> reflection instead). So pseudocode tracing
  cannot recover field layouts here.

  The usable field source is the AutoDump `packet_structures` extractor, which
  reads the binary's serialization-slot metadata directly: 294 packets with
  per-field types, keyed by JAM name (e.g. "JamCliHouse"). This importer maps
  those into jam_types.fields_json so codegen/packet_scaffolding emits non-empty
  structs. (The 67186 packet_structures dump regressed to empty; autodump_candidates
  falls back to the 66838 archive, where the 294 definitions live and whose JAM
  names are stable across builds.)

  The long-term, higher-fidelity path is a JAM reflection-metadata parser that
  walks the WowGetRawTypeName<T> descriptor tables — see PLUGIN_AUDIT_2026-06-25.
"""

import json
import os

from tc_wow_analyzer.core.utils import (
    msg_info, msg_warn, autodump_candidates, first_existing,
)

# packet_structures field type vocabulary -> codegen vocabulary
# (codegen/packet_scaffolding.JAM_TO_CPP_TYPE + the Read()/Write() switch).
_PASSTHROUGH = {
    "uint8", "uint16", "uint32", "uint64",
    "int8", "int16", "int32", "int64", "float", "double", "string",
}


def normalize_field(f, fallback_index=0):
    """Translate one packet_structures / wire-format field dict to the codegen
    schema consumed by packet_scaffolding: {index, name, type, [bit_count]}.

    Handles both the packet_structures vocabulary (uint32/string/struct/...) and
    the wire_format_recovery internal vocabulary (packed_guid/bit/bits/flush)."""
    if not isinstance(f, dict):
        return None
    idx = f.get("index", fallback_index)
    name = f.get("name") or f"Field{idx}"
    raw = (f.get("type") or "").strip()
    t = raw.lower()
    out = {"index": idx, "name": name}
    if t in ("bit", "bits"):
        out["type"] = "bits"
        out["bit_count"] = f.get("bit_count") or f.get("bit_size") or 1
    elif t in ("packed_guid", "packedguid", "packed_guid128", "guid"):
        out["type"] = "PackedGuid"
    elif t in ("objectguid",):
        out["type"] = "ObjectGuid"
    elif t == "flush":
        out["type"] = "flush"
    elif t == "struct":
        out["type"] = "struct"          # nested JAM type; codegen emits a marked stub
        if f.get("struct_name"):
            out["struct_name"] = f["struct_name"]
    elif t in _PASSTHROUGH:
        out["type"] = t
    else:
        out["type"] = "uint32"          # unknown -> safe default
    if f.get("is_optional"):
        out["is_optional"] = True
    if f.get("is_array"):
        out["is_array"] = True
    return out


def to_codegen_fields(fields):
    """Normalize a list of raw field dicts to the codegen schema."""
    out = []
    for i, f in enumerate(fields or []):
        nf = normalize_field(f, fallback_index=i)
        if nf is not None:
            out.append(nf)
    return out


def import_packet_structures(session, build=None):
    """Populate jam_types.fields_json from wow_packet_structures_<build>.json.

    Returns the number of jam_types rows given a non-empty fields_json."""
    db = getattr(session, "db", None)
    if db is None:
        msg_warn("packet_field_import: no DB")
        return 0
    path = first_existing(autodump_candidates("wow_packet_structures"))
    if not path:
        msg_warn("packet_field_import: no wow_packet_structures_*.json found "
                 "(checked current build + 66838/66198 archives)")
        return 0
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception as e:
        msg_warn(f"packet_field_import: failed to read {path}: {e}")
        return 0

    packets = data.get("packets") if isinstance(data, dict) else data
    if not packets:
        msg_warn(f"packet_field_import: {os.path.basename(path)} has 0 packets")
        return 0

    msg_info(f"packet_field_import: reading {os.path.basename(path)} "
             f"({len(packets)} packets)")
    n = 0
    for p in packets:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        fields = p.get("fields") or []
        if not name or not fields:
            continue
        cg = to_codegen_fields(fields)
        if not cg:
            continue
        db.upsert_jam_type(
            name=name,
            field_count=len(cg),
            fields_json=json.dumps(cg),
            status="packet_struct_imported",
        )
        n += 1
    db.commit()
    msg_info(f"packet_field_import: populated fields_json for {n} JAM types "
             f"from {os.path.basename(path)}")
    return n
