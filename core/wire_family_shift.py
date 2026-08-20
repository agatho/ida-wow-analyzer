"""Catalog opcode value <-> value actually on the wire.

WHY THIS EXISTS
---------------
`opcodes.internal_index` is the value our *catalog* gives an opcode. That is a
TrinityCore-side number, and TrinityCore trails retail by a build or two. The
number the client puts on the wire is `family << 16 | index` with a family id
that Blizzard hands out "based on the order in which the protocols were found in
the metadata" (Rumsey, GDC 2013). Insert one protocol and every later family
shifts up by one.

For 12.1 the shift is +1/+2/+3/+4/+5 depending on where the family sits. So the
catalog value and the wire value are simply *different numbers* for the same
message, and `opcodes.wire_opcode` must carry the second one -- it is what
`sniff_conformance_loop`, `sniff_verification`, `symbolic_constraints` and
`cross_analyzer_synthesis` look up when they see a packet:

    by_value[(direction, row["wire_opcode"])] = info

Before this module those analyzers stored the catalog value there, so a 12.1
sniff packet could never hit a row -- every lookup was off by exactly the shift.
That is why "sniff matching" kept landing in the failed-methods pile: not the
method, the values.

PROVENANCE MATTERS
------------------
Every family below carries how we know its shift. Three independent sources
agreed with zero contradictions:

  "wire"  891,725 packets from 10 sniffs across builds 69273 / 69299 / 69382,
          assigned to WowPacketParser's V12_0_7_67808 table under a monotone,
          injective, direction-preserving matching. 25 of 31 observed families
          came out at 100% index coverage; the 6 others are the large families
          where 12.1 genuinely added messages.
  "jam"   the client's own WowGetRawTypeName<struct Jam...> strings, scored
          against catalog opcode names (see core/jam_family.py).
  "interp" not observed itself, but both neighbours are proven with the same
          shift and the shift is monotone non-decreasing, so it is forced.

Two families stay deliberately unmapped: 0x2E (+1 or +2) and 0x35 (+2 or +3) are
never seen on the wire and carry no JAM type names. Six housing CMSGs are
affected. A wrong value there would be worse than a missing one, so callers get
None and must cope.

RUNTIME MAP BEATS THE TABLE
---------------------------
The table below is a *fallback*. When an analyzer has just identified the
families from the open binary it should pass that map in -- it is evidence from
this exact build, whereas the table is evidence from the builds we happened to
have sniffs for.
"""

# catalog family -> (shift, provenance).  None == deliberately unresolved.
SHIFT_12_1 = {
    0x29: (1, "wire"),   0x2B: (1, "wire"),   0x2C: (1, "interp"),
    0x2D: (1, "wire"),   0x2E: (None, "ambiguous: +1 or +2, never observed"),
    0x2F: (2, "wire"),   0x30: (2, "wire"),   0x31: (2, "interp"),
    0x32: (2, "interp"), 0x33: (2, "wire"),
    0x35: (None, "ambiguous: +2 or +3, never observed"),
    0x37: (3, "wire"),   0x38: (3, "interp"), 0x39: (3, "interp"),
    0x3A: (3, "wire"),   0x3B: (3, "wire"),   0x3C: (3, "interp"),
    0x3D: (3, "wire"),   0x3E: (3, "wire"),   0x40: (3, "wire"),
    0x41: (3, "wire"),   0x42: (3, "wire"),   0x43: (3, "interp"),
    0x46: (3, "wire"),   0x47: (3, "wire"),   0x48: (3, "wire"),
    0x49: (3, "wire"),   0x4C: (3, "wire"),   0x4E: (3, "wire"),
    0x50: (4, "wire"),   0x51: (4, "wire"),   0x52: (4, "interp"),
    0x53: (4, "interp"), 0x54: (4, "wire"),   0x55: (4, "interp"),
    0x56: (4, "wire"),   0x58: (4, "wire"),   0x5A: (4, "wire"),
    0x5B: (4, "jam"),    0x5C: (4, "jam"),
    0x5E: (5, "wire"),   0x5F: (5, "wire"),   0x60: (5, "wire"),
    0x62: (5, "wire"),   0x63: (5, "wire"),   0x65: (5, "interp"),
}

# Build ranges the table above is valid for. A build outside this gets no
# fallback map at all -- silence beats a confidently wrong number.
_TABLE_BUILDS = (69214, 69999)

# ---------------------------------------------------------------------------
# Within-family index offsets
# ---------------------------------------------------------------------------
# The family byte is not the only thing that moves. A message inserted into a
# .jam file shifts every later message id in that protocol, so the *index* half
# of the opcode drifts too -- and unlike the family shift this one is piecewise:
# indices before the insertion keep their number.
#
# Measured for 12.1 against WowPacketParser's V12_0_7_67808 table:
#
#   SMSG catalog 0x42  two insertions.  Settled by the client's own JAM type
#       names per switch case, then confirmed on the wire:
#         cat 0x038 JamCliRaidMarkerData -> SMSG_RAID_MARKERS_CHANGED   (+0)
#         cat 0x040 -> client 0x041, 285 pkts SMSG_SUSPEND_TOKEN paired with
#                   292 pkts SMSG_RESUME_TOKEN at 0x042; at +0 SUSPEND_TOKEN
#                   would have 0 packets while RESUME had 285, which cannot be
#         cat 0x05B JamCliVendorItem   -> SMSG_VENDOR_INVENTORY          (+1)
#         cat 0x11A JamLossOfControlInfo -> SMSG_ADD_LOSS_OF_CONTROL     (+1)
#         cat 0x120 ClientCASRefreshRemoteEntry -> SMSG_CAS_REFRESH_REMOTE_DATA
#                   (Dice 1.00 at +2, 0.00 at +1)                        (+2)
#       Wire check: 223 of 225 observed indices get a name, against 197 at +0.
#
#   CMSG catalog 0x3B  constant +2 for the whole family. 45 of 45 observed
#       indices named (35 at +0), and the names snap into place: client 0x031
#       with 1027 packets is CMSG_QUEST_GIVER_STATUS_QUERY (sent for every NPC
#       in range) rather than CMSG_QUEST_CONFIRM_ACCEPT, client 0x0CA with 1211
#       packets is CMSG_SET_SELECTION, client 0x08A is CMSG_GAME_OBJ_REPORT_USE.
#
#   CMSG catalog 0x3A  UNRESOLVED above index 0x0FF. Below it, 21 of 21 observed
#       indices are named at +0 (the whole loot cluster lands correctly). Above
#       it no offset wins: +0 names CMSG_ADD_TOY for 1045 packets, +4 names
#       CMSG_SPELL_EMPOWER_RELEASE/RESTART for a 2386/2294 pair -- both partly
#       plausible, neither supported by type names (send sites carry none).
#       So that half of the family is left out. TrinityCore's own catalog claims
#       +4 from index 0x86, which the wire refutes outright.
#
# Entry: catalog_family -> [(catalog_index_from, offset_or_None), ...] sorted.
# None means "do not translate": the range is genuinely unresolved.
INDEX_OFFSETS = {
    0x42: [(0x000, 0), (0x039, None), (0x040, 1), (0x11B, None), (0x11E, 2)],
    0x3B: [(0x000, 2)],
    0x3A: [(0x000, 0), (0x100, None)],
}


def index_offset(catalog_family, catalog_index):
    """Offset to add to a catalog index for this build, or None if unresolved."""
    plan = INDEX_OFFSETS.get(catalog_family)
    if not plan:
        return 0
    off = 0
    for start, value in plan:
        if catalog_index >= start:
            off = value
        else:
            break
    return off


_ARTIFACT = "wow_family_map_%s.json"


def builtin_family_map(build):
    """{catalog_family: client_family} for `build`, or {} if we have no table."""
    try:
        b = int(build)
    except (TypeError, ValueError):
        return {}
    if not (_TABLE_BUILDS[0] <= b <= _TABLE_BUILDS[1]):
        return {}
    return dict((fam, fam + shift)
                for fam, (shift, _why) in SHIFT_12_1.items()
                if shift is not None)


def provenance(catalog_family):
    """How we know this family's shift ('wire' / 'jam' / 'interp' / ...)."""
    entry = SHIFT_12_1.get(catalog_family)
    return entry[1] if entry else "unknown"


def catalog_to_client(value, family_map):
    """Catalog opcode value -> value on the wire. None when it is not settled.

    Never guesses. Returns None both when the family has no proven client
    counterpart and when the index falls in a range where we could not decide
    the within-family offset, so the caller leaves `wire_opcode` NULL rather
    than writing a number that names a different message.
    """
    if value is None or not family_map:
        return None
    fam = (value >> 16) & 0xFFFF
    client_fam = family_map.get(fam)
    if client_fam is None:
        return None
    idx = value & 0xFFFF
    off = index_offset(fam, idx)
    if off is None:
        return None
    return ((client_fam & 0xFFFF) << 16) | ((idx + off) & 0xFFFF)


def client_to_catalog(value, family_map):
    """Wire opcode value -> catalog value. None when it is not settled."""
    if value is None or not family_map:
        return None
    fam = (value >> 16) & 0xFFFF
    for cat_fam, client_fam in family_map.items():
        if client_fam != fam:
            continue
        idx = value & 0xFFFF
        plan = INDEX_OFFSETS.get(cat_fam)
        if not plan:
            return ((cat_fam & 0xFFFF) << 16) | idx
        # invert: find the catalog index whose forward map lands on idx
        for cand in range(max(0, idx - 8), idx + 1):
            off = index_offset(cat_fam, cand)
            if off is not None and cand + off == idx:
                return ((cat_fam & 0xFFFF) << 16) | cand
        return None
    return None


def merge_family_map(discovered, build):
    """Prefer families identified from the open binary, fall back to the table.

    `discovered` is {catalog_family: client_family} as produced by
    core.jam_family.resolve_via_jam_typenames on THIS build. Anything it found
    wins; the table only fills the gaps.
    """
    merged = builtin_family_map(build)
    for cat_fam, client_fam in (discovered or {}).items():
        try:
            merged[int(cat_fam)] = int(client_fam)
        except (TypeError, ValueError):
            continue
    return merged


def save_family_map(dumps_dir, build, family_map, source="analyzer"):
    """Persist the map next to the other per-build artifacts. Returns the path."""
    import json
    import os
    path = os.path.join(dumps_dir, _ARTIFACT % build)
    payload = {
        "build": build,
        "source": source,
        "note": ("catalog family -> client family. client_value = "
                 "(client_family << 16) | (catalog_value & 0xFFFF)"),
        "families": dict(("0x%02X" % k, "0x%02X" % v)
                         for k, v in sorted(family_map.items())),
        "provenance": dict(("0x%02X" % k, provenance(k))
                           for k in sorted(family_map)),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=1, sort_keys=True)
    return path


def _as_int(value):
    text = str(value)
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def load_family_map(dumps_dir, build):
    """Read a persisted map, or fall back to the built-in table.

    Two on-disk shapes are accepted: this module's own artifact, and the
    `family_map_<build>.json` that analyzers/opcode_dispatcher.py has been
    writing since it was ported to the JAM method. Reading both means the
    analyzers cannot silently disagree about which family is which.
    """
    import json
    import os

    candidates = (
        (os.path.join(dumps_dir, _ARTIFACT % build), "dict"),
        (os.path.join(dumps_dir, "family_map_%s.json" % build), "list"),
    )
    for path, shape in candidates:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            fams = data.get("families") or {}
            out = {}
            if shape == "dict" and isinstance(fams, dict):
                for k, v in fams.items():
                    out[_as_int(k)] = _as_int(v)
            elif shape == "list" and isinstance(fams, list):
                for row in fams:
                    out[_as_int(row["catalog_family"])] = _as_int(
                        row["client_family"])
            if out:
                return out
        except Exception:
            continue
    return builtin_family_map(build)
