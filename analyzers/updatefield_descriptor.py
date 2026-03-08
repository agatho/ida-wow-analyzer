"""
UpdateField Descriptor Table Analyzer
Directly parses UpdateField descriptor tables from the .rdata section of the
WoW x64 binary to extract field names, offsets, types, sizes, and visibility
flags for every object type.

UpdateFields are the mechanism by which the server sends object state (health,
position, equipped items, auras, etc.) to the client.  Each object type
(Object, Item, Unit, Player, GameObject, ...) has a descriptor table in .rdata
consisting of an array of fixed-size entries.  Each entry describes one field:

    struct DescriptorEntry {
        const char* name;       // 8 bytes - pointer to ASCII field name
        uint32_t    offset;     // 4 bytes - byte offset in the update block
        uint32_t    size;       // 4 bytes - size in 32-bit (4-byte) units
        uint32_t    type_flags; // 4 bytes - packed type + visibility flags
    };

Tables are terminated by an entry with a null name pointer.

This analyzer:
  1. Locates descriptor tables via known string references in .rdata
  2. Parses every entry in every table
  3. Classifies fields by object type prefix
  4. Detects dynamic (variable-length) update fields (WoW 12.x)
  5. Optionally compares results against TrinityCore UpdateFields source
  6. Exports C++ header/enum code for TrinityCore integration

Results are stored in both the ``update_fields`` SQL table and the
``updatefield_descriptors`` key-value blob for downstream consumers.
"""

import json
import os
import re
import struct
import time

import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import ida_xref
import idaapi
import idc
import idautils

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Size of one descriptor entry in bytes: 8 (ptr) + 4 + 4 + 4 = 20
DESCRIPTOR_ENTRY_SIZE = 20

# Maximum sane field count per object type (safety bound)
MAX_FIELDS_PER_TYPE = 2048

# Maximum number of object types we expect to find
MAX_OBJECT_TYPES = 32

# Maximum bytes to scan when searching for table start from a string xref
MAX_SCAN_BACKWARDS = 0x10000

# Maximum bytes to scan forward when walking a table
MAX_TABLE_BYTES = DESCRIPTOR_ENTRY_SIZE * MAX_FIELDS_PER_TYPE

# ---------------------------------------------------------------------------
# Field type constants (lower 8 bits of type_flags)
# ---------------------------------------------------------------------------
FIELD_TYPE_INT32          = 0
FIELD_TYPE_UINT32         = 1
FIELD_TYPE_FLOAT          = 2
FIELD_TYPE_INT64          = 3
FIELD_TYPE_UINT64         = 4
FIELD_TYPE_BYTES          = 5
FIELD_TYPE_GUID           = 6     # 128-bit ObjectGuid
FIELD_TYPE_TWO_SHORT      = 7     # Two packed 16-bit values in one uint32
FIELD_TYPE_CUSTOM         = 8     # Struct/nested type

FIELD_TYPE_NAMES = {
    FIELD_TYPE_INT32:     "int32",
    FIELD_TYPE_UINT32:    "uint32",
    FIELD_TYPE_FLOAT:     "float",
    FIELD_TYPE_INT64:     "int64",
    FIELD_TYPE_UINT64:    "uint64",
    FIELD_TYPE_BYTES:     "bytes",
    FIELD_TYPE_GUID:      "guid",
    FIELD_TYPE_TWO_SHORT: "two_short",
    FIELD_TYPE_CUSTOM:    "custom",
}

# ---------------------------------------------------------------------------
# Visibility flag constants (bits 8-15 of type_flags)
# ---------------------------------------------------------------------------
FLAG_PUBLIC   = 0x0001   # Visible to everyone in range
FLAG_PRIVATE  = 0x0002   # Only visible to the owning player
FLAG_OWNER    = 0x0004   # Visible to owner (items/pets)
FLAG_UNK1     = 0x0008
FLAG_UNK2     = 0x0010
FLAG_EMPATH   = 0x0020   # Beast Lore / empathic bond
FLAG_PARTY    = 0x0040   # Visible to party members
FLAG_UNK3     = 0x0080
FLAG_DYNAMIC  = 0x0100   # Dynamic (variable-length) field

FLAG_NAMES = {
    FLAG_PUBLIC:  "PUBLIC",
    FLAG_PRIVATE: "PRIVATE",
    FLAG_OWNER:   "OWNER",
    FLAG_UNK1:    "UNK1",
    FLAG_UNK2:    "UNK2",
    FLAG_EMPATH:  "EMPATH",
    FLAG_PARTY:   "PARTY",
    FLAG_UNK3:    "UNK3",
    FLAG_DYNAMIC: "DYNAMIC",
}

# ---------------------------------------------------------------------------
# Object type classification by field name prefix
# ---------------------------------------------------------------------------
OBJECT_TYPE_PREFIXES = [
    # Order matters: more specific prefixes first
    ("ACTIVEPLAYERDATA_FIELD_",   "ACTIVE_PLAYER"),
    ("ACTIVEPLAYERDATA_",         "ACTIVE_PLAYER"),
    ("ACTIVE_PLAYER_FIELD_",      "ACTIVE_PLAYER"),
    ("PLAYER_FIELD_",             "PLAYER"),
    ("PLAYER_",                   "PLAYER"),
    ("UNIT_FIELD_",               "UNIT"),
    ("UNIT_",                     "UNIT"),
    ("ITEM_FIELD_",               "ITEM"),
    ("ITEM_",                     "ITEM"),
    ("CONTAINER_FIELD_",          "CONTAINER"),
    ("CONTAINER_",                "CONTAINER"),
    ("GAMEOBJECT_FIELD_",         "GAMEOBJECT"),
    ("GAMEOBJECT_",               "GAMEOBJECT"),
    ("DYNAMICOBJECT_FIELD_",      "DYNAMICOBJECT"),
    ("DYNAMICOBJECT_",            "DYNAMICOBJECT"),
    ("CORPSE_FIELD_",             "CORPSE"),
    ("CORPSE_",                   "CORPSE"),
    ("AREATRIGGER_FIELD_",        "AREATRIGGER"),
    ("AREATRIGGER_",              "AREATRIGGER"),
    ("SCENEOBJECT_FIELD_",        "SCENEOBJECT"),
    ("SCENEOBJECT_",              "SCENEOBJECT"),
    ("CONVERSATION_FIELD_",       "CONVERSATION"),
    ("CONVERSATION_",             "CONVERSATION"),
    ("OBJECT_FIELD_",             "OBJECT"),
    ("OBJECT_",                   "OBJECT"),
    ("AZERITE_EMPOWERED_ITEM_",   "AZERITE_EMPOWERED_ITEM"),
    ("AZERITE_ITEM_",             "AZERITE_ITEM"),
]

# Modern WoW 12.x also uses C++ namespace-style descriptor class names
DESCRIPTOR_CLASS_PREFIXES = [
    ("ObjectField::",             "OBJECT"),
    ("ItemField::",               "ITEM"),
    ("ContainerField::",          "CONTAINER"),
    ("UnitField::",               "UNIT"),
    ("PlayerField::",             "PLAYER"),
    ("ActivePlayerField::",       "ACTIVE_PLAYER"),
    ("GameObjectField::",         "GAMEOBJECT"),
    ("DynamicObjectField::",      "DYNAMICOBJECT"),
    ("CorpseField::",             "CORPSE"),
    ("AreaTriggerField::",        "AREATRIGGER"),
    ("SceneObjectField::",        "SCENEOBJECT"),
    ("ConversationField::",       "CONVERSATION"),
    ("AzeriteEmpoweredItemField::","AZERITE_EMPOWERED_ITEM"),
    ("AzeriteItemField::",        "AZERITE_ITEM"),
]

# Seed strings to locate descriptor tables.  We search .rdata for pointers
# to any of these; the pointer is part of a descriptor entry, from which we
# can derive the table start.
SEED_STRINGS = [
    "OBJECT_FIELD_GUID",
    "OBJECT_FIELD_ENTRY_ID",
    "OBJECT_FIELD_TYPE",
    "OBJECT_FIELD_SCALE",
    "UNIT_FIELD_HEALTH",
    "UNIT_FIELD_MAXHEALTH",
    "UNIT_FIELD_LEVEL",
    "UNIT_FIELD_FACTIONTEMPLATE",
    "PLAYER_FIELD_XP",
    "PLAYER_FIELD_NEXT_LEVEL_XP",
    "ITEM_FIELD_OWNER",
    "ITEM_FIELD_STACKCOUNT",
    "GAMEOBJECT_FIELD_CREATED_BY",
    "CORPSE_FIELD_OWNER",
    "CONTAINER_FIELD_NUM_SLOTS",
    "DYNAMICOBJECT_FIELD_CASTER",
    "AREATRIGGER_FIELD_CASTER",
    # Modern 12.x names
    "ObjectField::Guid",
    "ObjectField::EntryID",
    "UnitField::Health",
    "UnitField::MaxHealth",
    "PlayerField::XP",
    "ItemField::Owner",
    "GameObjectField::CreatedBy",
    "ActivePlayerField::Coinage",
]

# TrinityCore type mapping for C++ codegen
TC_CPP_TYPE_MAP = {
    "int32":     ("int32",      "UF_TYPE_INT"),
    "uint32":    ("uint32",     "UF_TYPE_INT"),
    "float":     ("float",      "UF_TYPE_FLOAT"),
    "int64":     ("int64",      "UF_TYPE_TWO_SHORT"),
    "uint64":    ("uint64",     "UF_TYPE_TWO_SHORT"),
    "bytes":     ("uint32",     "UF_TYPE_BYTES"),
    "guid":      ("ObjectGuid", "UF_TYPE_GUID"),
    "two_short": ("uint32",     "UF_TYPE_TWO_SHORT"),
    "custom":    ("uint32",     "UF_TYPE_INT"),
}


# ===================================================================
# Main entry point
# ===================================================================

def extract_updatefield_descriptors(session) -> int:
    """Parse UpdateField descriptor tables from the WoW binary.

    Scans .rdata for known field name strings, locates the descriptor
    tables that reference them, parses every entry, classifies fields
    by object type, detects dynamic fields, optionally compares against
    TrinityCore source, and stores the results.

    Args:
        session: The PluginSession instance (provides .db and .cfg).

    Returns:
        Total number of fields extracted.
    """
    t0 = time.time()
    db = session.db
    cfg = session.cfg

    msg_info("UpdateField Descriptor Analyzer starting...")

    # Step 1: Find .rdata segment bounds
    rdata_start, rdata_end = _find_rdata_segment()
    if rdata_start is None:
        msg_error("Could not locate .rdata segment")
        return 0
    msg_info(f".rdata segment: {ea_str(rdata_start)} - {ea_str(rdata_end)} "
             f"({(rdata_end - rdata_start) / 1024:.0f} KB)")

    # Step 2: Find seed string addresses in the binary
    seed_string_eas = _find_seed_strings(rdata_start, rdata_end)
    if not seed_string_eas:
        msg_warn("No seed strings found in .rdata, trying full binary scan")
        seed_string_eas = _find_seed_strings_fullscan()
    if not seed_string_eas:
        msg_error("Could not locate any UpdateField name strings in the binary")
        return 0
    msg_info(f"Found {len(seed_string_eas)} seed string(s)")

    # Step 3: From seed strings, locate descriptor table base addresses
    table_bases = _find_table_bases(seed_string_eas, rdata_start, rdata_end)
    if not table_bases:
        msg_error("Could not locate any descriptor tables from seed strings")
        return 0
    msg_info(f"Located {len(table_bases)} descriptor table(s)")

    # Step 4: Parse all descriptor tables
    all_fields = []
    all_dynamic_fields = []
    tables_info = []

    for table_ea in sorted(table_bases):
        fields, dynamic_fields = _parse_descriptor_table(table_ea, rdata_start, rdata_end)
        if not fields:
            continue

        # Classify fields into object types
        type_groups = _classify_fields_by_type(fields)
        for obj_type, typed_fields in type_groups.items():
            total_size = 0
            if typed_fields:
                last = typed_fields[-1]
                total_size = last["offset"] + last["size"] * 4

            tables_info.append({
                "type_name": obj_type,
                "field_count": len(typed_fields),
                "total_size": total_size,
                "fields": typed_fields,
                "table_ea": ea_str(table_ea),
            })
            all_fields.extend(typed_fields)

        all_dynamic_fields.extend(dynamic_fields)

    if not all_fields:
        msg_warn("Parsed descriptor tables but found no valid fields")
        return 0

    # Deduplicate: if multiple tables yielded the same field, keep first
    seen = set()
    unique_fields = []
    for f in all_fields:
        key = (f.get("object_type", "UNKNOWN"), f["name"])
        if key not in seen:
            seen.add(key)
            unique_fields.append(f)
    all_fields = unique_fields

    msg_info(f"Extracted {len(all_fields)} unique fields across "
             f"{len(tables_info)} object type(s)")

    # Step 5: Store fields in the update_fields SQL table
    _store_fields_sql(db, all_fields)

    # Step 6: Build dynamic field summary
    dynamic_summary = _build_dynamic_summary(all_dynamic_fields)

    # Step 7: TC comparison (optional)
    tc_comparison = _compare_with_trinitycore(cfg, all_fields)

    # Step 8: Determine the primary descriptor table address
    primary_table_ea = ea_str(sorted(table_bases)[0]) if table_bases else "0x0"

    # Step 9: Store results in KV store
    result = {
        "object_types": tables_info,
        "dynamic_fields": dynamic_summary,
        "tc_comparison": tc_comparison,
        "total_fields": len(all_fields),
        "descriptor_table_ea": primary_table_ea,
        "extraction_time": time.time() - t0,
    }
    db.kv_set("updatefield_descriptors", result)
    db.commit()

    elapsed = time.time() - t0
    msg_info(f"UpdateField Descriptor Analyzer complete: "
             f"{len(all_fields)} fields in {elapsed:.2f}s")

    # Print summary
    _print_summary(tables_info, dynamic_summary, tc_comparison)

    return len(all_fields)


def get_updatefield_descriptors(session):
    """Retrieve previously extracted descriptor data from the KV store.

    Returns:
        dict with keys: object_types, dynamic_fields, tc_comparison,
        total_fields, descriptor_table_ea.  Returns None if no data stored.
    """
    return session.db.kv_get("updatefield_descriptors")


# ===================================================================
# Segment helpers
# ===================================================================

def _find_rdata_segment():
    """Find the .rdata segment boundaries.

    Returns:
        (start_ea, end_ea) or (None, None) if not found.
    """
    seg = ida_segment.get_segm_by_name(".rdata")
    if seg:
        return seg.start_ea, seg.end_ea

    # Fallback: iterate segments looking for one named rdata or with
    # read-only data characteristics
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        name = ida_segment.get_segm_name(seg)
        if name and "rdata" in name.lower():
            return seg.start_ea, seg.end_ea
        # Check for read-only data segment (perm = read, no write, no exec)
        if seg.perm & 1:
            # Executable segment — not a data segment, skip
            continue

    # Another fallback: try ".rodata" (Linux) or "CONST" (some builds)
    for name_try in [".rodata", "CONST", ".text"]:
        seg = ida_segment.get_segm_by_name(name_try)
        if seg:
            return seg.start_ea, seg.end_ea

    return None, None


def _find_text_segment():
    """Find the .text segment boundaries for code scanning.

    Returns:
        (start_ea, end_ea) or (None, None) if not found.
    """
    seg = ida_segment.get_segm_by_name(".text")
    if seg:
        return seg.start_ea, seg.end_ea
    return None, None


# ===================================================================
# Seed string location
# ===================================================================

def _find_seed_strings(rdata_start, rdata_end):
    """Search .rdata for known UpdateField name strings.

    Returns:
        dict mapping string_value -> ea (address of the string in the binary).
    """
    found = {}

    for seed in SEED_STRINGS:
        # Search for the string as bytes in .rdata
        seed_bytes = seed.encode("ascii") + b"\x00"
        ea = rdata_start
        while ea < rdata_end:
            ea = ida_bytes.bin_search(
                ea, rdata_end, seed_bytes, None,
                idaapi.BIN_SEARCH_FORWARD | idaapi.BIN_SEARCH_NOCASE,
                0
            )
            if ea == idaapi.BADADDR:
                break

            # Verify it's a proper null-terminated string
            actual = _read_string_at(ea)
            if actual == seed:
                found[seed] = ea
                break

            ea += 1

    # Also search by IDA name index for any strings that IDA auto-detected
    for seed in SEED_STRINGS:
        if seed in found:
            continue
        # Try to find by searching IDA's string list
        ea = idc.get_name_ea_simple(f'a{seed.replace(":", "").replace("_", "")}')
        if ea != idaapi.BADADDR:
            actual = _read_string_at(ea)
            if actual and seed.lower() in actual.lower():
                found[seed] = ea

    return found


def _find_seed_strings_fullscan():
    """Fallback: scan ALL segments for seed strings.

    Returns:
        dict mapping string_value -> ea.
    """
    found = {}

    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        # Skip executable segments (we want data)
        if seg.perm & 1:  # execute permission
            continue

        for seed in SEED_STRINGS:
            if seed in found:
                continue
            seed_bytes = seed.encode("ascii") + b"\x00"
            ea = ida_bytes.bin_search(
                seg.start_ea, seg.end_ea, seed_bytes, None,
                idaapi.BIN_SEARCH_FORWARD, 0
            )
            if ea != idaapi.BADADDR:
                actual = _read_string_at(ea)
                if actual == seed:
                    found[seed] = ea

    return found


def _read_string_at(ea, max_len=512):
    """Read a null-terminated ASCII string at the given address.

    Returns:
        The string, or None if the address doesn't contain valid ASCII.
    """
    chars = []
    for i in range(max_len):
        byte = ida_bytes.get_byte(ea + i)
        if byte == 0:
            break
        if byte < 0x20 or byte > 0x7E:
            return None  # non-printable
        chars.append(chr(byte))
    if not chars:
        return None
    return "".join(chars)


# ===================================================================
# Descriptor table location
# ===================================================================

def _find_table_bases(seed_string_eas, rdata_start, rdata_end):
    """From seed string addresses, find the base addresses of descriptor tables.

    Strategy:
      1. For each seed string EA, find all data cross-references to it.
      2. Each xref is a pointer inside a descriptor entry (the name_ptr field).
      3. The entry is DESCRIPTOR_ENTRY_SIZE bytes; the name_ptr is at offset 0.
      4. Walk backwards from the entry to find the table start (first entry
         whose name_ptr points to a valid string).
      5. Collect unique table base addresses.

    Returns:
        set of table base EAs.
    """
    table_bases = set()
    visited_entries = set()

    for seed_str, string_ea in seed_string_eas.items():
        # Find all data xrefs TO this string (pointers in .rdata that hold
        # the address of this string)
        xref_eas = _find_data_xrefs_to(string_ea, rdata_start, rdata_end)

        if not xref_eas:
            # Try scanning .rdata for the 8-byte pointer value
            xref_eas = _scan_for_pointer(string_ea, rdata_start, rdata_end)

        for xref_ea in xref_eas:
            if xref_ea in visited_entries:
                continue
            visited_entries.add(xref_ea)

            # xref_ea should be the name_ptr field (offset 0) of a descriptor entry.
            # Verify this is a valid entry.
            if not _is_valid_descriptor_entry(xref_ea, rdata_start, rdata_end):
                continue

            # Walk backwards to find the table start
            table_start = _find_table_start(xref_ea, rdata_start, rdata_end)
            if table_start is not None:
                table_bases.add(table_start)
                msg(f"  Table at {ea_str(table_start)} "
                    f"(found via '{seed_str}' at {ea_str(string_ea)})")

    # Deduplicate tables that are very close together (within one entry size)
    # This handles cases where we found the same table from different seeds
    if len(table_bases) > 1:
        sorted_bases = sorted(table_bases)
        merged = [sorted_bases[0]]
        for base in sorted_bases[1:]:
            if base - merged[-1] > DESCRIPTOR_ENTRY_SIZE:
                merged.append(base)
        table_bases = set(merged)

    return table_bases


def _find_data_xrefs_to(target_ea, rdata_start, rdata_end):
    """Find all data cross-references to target_ea within .rdata.

    Returns:
        list of EAs in .rdata that contain a pointer to target_ea.
    """
    xrefs = []
    for xref in idautils.XrefsTo(target_ea, 0):
        if rdata_start <= xref.frm < rdata_end:
            xrefs.append(xref.frm)
    return xrefs


def _scan_for_pointer(target_ea, rdata_start, rdata_end):
    """Brute-force scan .rdata for 8-byte pointers holding target_ea.

    This is the fallback when IDA hasn't created xrefs (common for raw
    data tables).

    Returns:
        list of EAs where the pointer was found.
    """
    results = []
    target_bytes = struct.pack("<Q", target_ea)

    ea = rdata_start
    while ea < rdata_end - 8:
        ea = ida_bytes.bin_search(
            ea, rdata_end, target_bytes, None,
            idaapi.BIN_SEARCH_FORWARD, 0
        )
        if ea == idaapi.BADADDR:
            break
        # Ensure alignment (descriptor entries should be at least 4-byte aligned)
        if ea % 4 == 0:
            results.append(ea)
        ea += 8

    return results


def _is_valid_descriptor_entry(ea, rdata_start, rdata_end):
    """Check if EA points to a valid descriptor entry.

    A valid entry has:
      - name_ptr (8 bytes): points to a readable ASCII string
      - offset (4 bytes): reasonable value (0 - 0x10000)
      - size (4 bytes): reasonable value (1 - 256)
      - type_flags (4 bytes): type in known range

    Returns:
        True if the entry looks valid.
    """
    if ea < rdata_start or ea + DESCRIPTOR_ENTRY_SIZE > rdata_end:
        return False

    name_ptr = ida_bytes.get_qword(ea)
    if name_ptr == 0:
        return False

    # Verify name_ptr points to a valid string
    name = _read_string_at(name_ptr)
    if not name or len(name) < 2:
        return False

    # Check that the name looks like an update field name
    if not _looks_like_field_name(name):
        return False

    offset = ida_bytes.get_dword(ea + 8)
    size = ida_bytes.get_dword(ea + 12)
    type_flags = ida_bytes.get_dword(ea + 16)

    # Sanity checks
    if offset > 0x10000:
        return False
    if size == 0 or size > 256:
        return False

    field_type = type_flags & 0xFF
    if field_type > 15:  # reasonable upper bound for type enum
        return False

    return True


def _looks_like_field_name(name):
    """Check if a string looks like an UpdateField name.

    Valid patterns:
      - OBJECT_FIELD_GUID
      - UnitField::Health
      - m_maxHealth
      - Any CamelCase or UPPER_SNAKE_CASE identifier
    """
    if not name:
        return False

    # Classic style: OBJECT_FIELD_GUID, UNIT_FIELD_HEALTH
    if re.match(r'^[A-Z][A-Z0-9_]+$', name):
        return True

    # Modern style: ObjectField::Guid, UnitField::Health
    if re.match(r'^[A-Za-z]+::[A-Za-z][A-Za-z0-9_]*$', name):
        return True

    # C++ member style: m_health, m_maxHealth, health
    if re.match(r'^m?_?[a-zA-Z][a-zA-Z0-9_]*$', name):
        return True

    return False


def _find_table_start(entry_ea, rdata_start, rdata_end):
    """Walk backwards from a known-valid entry to find the table start.

    The table start is the first entry in the contiguous array.  We walk
    backwards by DESCRIPTOR_ENTRY_SIZE checking each potential entry.

    Returns:
        EA of the first entry, or None if we can't determine it.
    """
    current = entry_ea
    first_valid = entry_ea

    # Walk backwards
    steps = 0
    max_steps = MAX_FIELDS_PER_TYPE
    while steps < max_steps:
        prev = current - DESCRIPTOR_ENTRY_SIZE
        if prev < rdata_start:
            break
        if not _is_valid_descriptor_entry(prev, rdata_start, rdata_end):
            break
        first_valid = prev
        current = prev
        steps += 1

    return first_valid


# ===================================================================
# Descriptor table parsing
# ===================================================================

def _parse_descriptor_table(table_ea, rdata_start, rdata_end):
    """Parse a descriptor table starting at table_ea.

    Reads entries sequentially until a null name_ptr or invalid entry
    is encountered.

    Returns:
        (fields, dynamic_fields) where each is a list of field dicts.
    """
    fields = []
    dynamic_fields = []
    ea = table_ea
    idx = 0

    while ea + DESCRIPTOR_ENTRY_SIZE <= rdata_end and idx < MAX_FIELDS_PER_TYPE:
        name_ptr = ida_bytes.get_qword(ea)

        # Null terminator
        if name_ptr == 0:
            break

        name = _read_string_at(name_ptr)
        if not name:
            # Could be end of table or corrupt entry; try one more
            if idx > 0:
                break
            ea += DESCRIPTOR_ENTRY_SIZE
            idx += 1
            continue

        if not _looks_like_field_name(name):
            break

        offset_val = ida_bytes.get_dword(ea + 8)
        size_val = ida_bytes.get_dword(ea + 12)
        type_flags = ida_bytes.get_dword(ea + 16)

        # Sanity check mid-table
        if size_val == 0 or size_val > 256 or offset_val > 0x10000:
            break

        # Decode type and flags
        field_type_id = type_flags & 0xFF
        visibility_flags = (type_flags >> 8) & 0xFF
        extra_flags = (type_flags >> 16) & 0xFFFF

        field_type_name = FIELD_TYPE_NAMES.get(field_type_id, f"unk_{field_type_id}")
        flag_list = _decode_flags(visibility_flags)
        is_dynamic = bool(visibility_flags & (FLAG_DYNAMIC >> 8)) or \
                     bool(extra_flags & 0x01)

        # Classify object type from name
        obj_type = _classify_field_object_type(name)

        field_entry = {
            "name": name,
            "offset": offset_val,
            "size": size_val,
            "type": field_type_name,
            "type_id": field_type_id,
            "flags": ",".join(flag_list) if flag_list else "NONE",
            "flags_raw": type_flags,
            "is_dynamic": is_dynamic,
            "object_type": obj_type,
            "table_index": idx,
            "entry_ea": ea_str(ea),
        }

        if is_dynamic:
            dynamic_fields.append(field_entry)
        fields.append(field_entry)

        # Label the entry in IDA for navigation
        _label_descriptor_entry(ea, name, idx)

        ea += DESCRIPTOR_ENTRY_SIZE
        idx += 1

    if fields:
        msg(f"  Parsed {len(fields)} fields from table at {ea_str(table_ea)} "
            f"({len(dynamic_fields)} dynamic)")

    return fields, dynamic_fields


def _decode_flags(flag_byte):
    """Decode visibility flag byte into a list of flag names.

    Args:
        flag_byte: The visibility flags byte (bits 8-15 of type_flags, shifted down).

    Returns:
        list of flag name strings.
    """
    names = []
    for bit_val, name in sorted(FLAG_NAMES.items()):
        # FLAG_NAMES keys use the original bit position; shift to match flag_byte
        check_bit = bit_val
        if check_bit >= 0x0100:
            check_bit = check_bit >> 8
        if flag_byte & check_bit:
            names.append(name)
    if not names:
        names.append("NONE")
    return names


def _classify_field_object_type(name):
    """Determine the object type from a field name.

    Checks against known prefixes in priority order.

    Returns:
        Object type string (e.g., "UNIT", "PLAYER", "OBJECT").
    """
    upper = name.upper()
    for prefix, obj_type in OBJECT_TYPE_PREFIXES:
        if upper.startswith(prefix.upper()):
            return obj_type

    # Check modern C++ namespace style
    for prefix, obj_type in DESCRIPTOR_CLASS_PREFIXES:
        if name.startswith(prefix):
            return obj_type

    return "UNKNOWN"


def _label_descriptor_entry(ea, field_name, index):
    """Add an IDA name/comment to a descriptor entry for navigation.

    Does not overwrite user-defined names.
    """
    current_name = ida_name.get_name(ea)
    if current_name and not current_name.startswith("uf_"):
        return  # Don't overwrite existing meaningful names

    # Sanitize for IDA name requirements
    safe_name = re.sub(r'[^A-Za-z0-9_]', '_', field_name)
    label = f"uf_{safe_name}"

    ida_name.set_name(ea, label, ida_name.SN_NOCHECK | ida_name.SN_NOWARN)

    # Also set a repeatable comment
    comment = f"UpdateField [{index}]: {field_name}"
    idc.set_cmt(ea, comment, 1)  # 1 = repeatable


# ===================================================================
# Field classification and grouping
# ===================================================================

def _classify_fields_by_type(fields):
    """Group a flat list of fields by their object type.

    Returns:
        dict mapping object_type -> list of field dicts, sorted by offset.
    """
    groups = {}
    for field in fields:
        obj_type = field.get("object_type", "UNKNOWN")
        if obj_type not in groups:
            groups[obj_type] = []
        groups[obj_type].append(field)

    # Sort each group by offset
    for obj_type in groups:
        groups[obj_type].sort(key=lambda f: f["offset"])

    return groups


# ===================================================================
# SQL storage
# ===================================================================

def _store_fields_sql(db, fields):
    """Store parsed fields into the update_fields SQL table.

    Clears existing data first to avoid stale entries from previous runs.
    """
    # Clear old data
    db.execute("DELETE FROM update_fields")

    for field in fields:
        obj_type = field.get("object_type", "UNKNOWN")
        fname = field["name"]
        foffset = field["offset"]
        fsize = field["size"]
        ftype = field["type"]
        fflags = field["flags"]
        is_dynamic = 1 if field.get("is_dynamic") else 0

        # Determine array count: if multiple consecutive fields have the
        # same base name with [N] suffix, they form an array
        array_count = 1
        match = re.match(r'^(.+)\[(\d+)\]$', fname)
        if match:
            fname = match.group(1)
            # The array_count is determined by how many [N] entries exist
            # with the same base name. For now store 1; we fix up later.
            array_count = 1

        db.execute(
            """INSERT OR REPLACE INTO update_fields
               (object_type, field_name, field_offset, field_size,
                field_type, field_flags, array_count, is_dynamic)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (obj_type, fname, foffset, fsize, ftype, fflags,
             array_count, is_dynamic),
        )

    # Fix up array counts: find fields with the same base name and
    # consecutive offsets
    _fixup_array_counts(db)

    db.commit()
    msg_info(f"Stored {len(fields)} fields in update_fields table")


def _fixup_array_counts(db):
    """Detect array fields and update their array_count.

    Array fields have names like "PLAYER_FIELD_EXPLORED_ZONES" with multiple
    entries at consecutive offsets.  We group by (object_type, field_name)
    and count.
    """
    rows = db.fetchall(
        """SELECT object_type, field_name, COUNT(*) as cnt
           FROM update_fields
           GROUP BY object_type, field_name
           HAVING cnt > 1
           ORDER BY object_type, field_name"""
    )

    for row in rows:
        obj_type = row["object_type"]
        fname = row["field_name"]
        count = row["cnt"]

        # Get the first occurrence and update its array_count
        first = db.fetchone(
            """SELECT rowid FROM update_fields
               WHERE object_type = ? AND field_name = ?
               ORDER BY field_offset
               LIMIT 1""",
            (obj_type, fname)
        )
        if first:
            db.execute(
                """UPDATE update_fields SET array_count = ?
                   WHERE object_type = ? AND field_name = ?
                   AND rowid = ?""",
                (count, obj_type, fname, first["rowid"])
            )
            # Delete duplicate entries (keep only the first)
            db.execute(
                """DELETE FROM update_fields
                   WHERE object_type = ? AND field_name = ?
                   AND rowid != ?""",
                (obj_type, fname, first["rowid"])
            )


# ===================================================================
# Dynamic field handling
# ===================================================================

def _build_dynamic_summary(dynamic_fields):
    """Build a summary of dynamic (variable-length) fields by object type.

    Returns:
        list of dicts: [{type_name, field_count, fields}]
    """
    if not dynamic_fields:
        return []

    groups = {}
    for field in dynamic_fields:
        obj_type = field.get("object_type", "UNKNOWN")
        if obj_type not in groups:
            groups[obj_type] = []
        groups[obj_type].append({
            "name": field["name"],
            "offset": field["offset"],
            "size": field["size"],
            "type": field["type"],
            "flags": field["flags"],
        })

    summary = []
    for obj_type, typed_fields in sorted(groups.items()):
        summary.append({
            "type_name": obj_type,
            "field_count": len(typed_fields),
            "fields": typed_fields,
        })

    return summary


# ===================================================================
# TrinityCore comparison
# ===================================================================

def _compare_with_trinitycore(cfg, binary_fields):
    """Compare extracted fields against TrinityCore's UpdateFields source.

    Looks for UpdateFields.h and UpdateFieldsArray.cpp in the TC source tree.

    Returns:
        dict with comparison results, or empty dict if TC source not available.
    """
    tc_source = cfg.tc_source_dir
    if not tc_source:
        msg("Skipping TC comparison (tc_source_dir not configured)")
        return {
            "matching": 0,
            "missing_from_tc": 0,
            "missing_from_binary": 0,
            "type_mismatch": 0,
            "offset_mismatch": 0,
            "mismatches": [],
            "status": "skipped",
        }

    # Search for UpdateFields header(s) in TC source tree
    tc_fields = _parse_tc_updatefields(tc_source)
    if not tc_fields:
        msg_warn("Could not parse TrinityCore UpdateFields source")
        return {
            "matching": 0,
            "missing_from_tc": len(binary_fields),
            "missing_from_binary": 0,
            "type_mismatch": 0,
            "offset_mismatch": 0,
            "mismatches": [],
            "status": "tc_parse_failed",
        }

    # Build lookup by (object_type, field_name)
    tc_by_name = {}
    for f in tc_fields:
        key = (f.get("object_type", ""), f.get("name", ""))
        tc_by_name[key] = f

    binary_by_name = {}
    for f in binary_fields:
        key = (f.get("object_type", ""), f.get("name", ""))
        binary_by_name[key] = f

    matching = 0
    missing_from_tc = 0
    missing_from_binary = 0
    type_mismatch = 0
    offset_mismatch = 0
    mismatches = []

    # Check binary fields against TC
    for key, bf in binary_by_name.items():
        tf = tc_by_name.get(key)
        if tf is None:
            missing_from_tc += 1
            mismatches.append({
                "field": bf["name"],
                "object_type": bf.get("object_type", ""),
                "issue": "missing_from_tc",
                "binary_offset": bf["offset"],
                "binary_type": bf["type"],
            })
            continue

        issues = []
        if bf["type"] != tf.get("type", ""):
            type_mismatch += 1
            issues.append(f"type: binary={bf['type']} tc={tf.get('type', '?')}")

        if bf["offset"] != tf.get("offset", -1):
            offset_mismatch += 1
            issues.append(f"offset: binary={bf['offset']} tc={tf.get('offset', '?')}")

        if issues:
            mismatches.append({
                "field": bf["name"],
                "object_type": bf.get("object_type", ""),
                "issue": "; ".join(issues),
                "binary_offset": bf["offset"],
                "binary_type": bf["type"],
                "tc_offset": tf.get("offset"),
                "tc_type": tf.get("type"),
            })
        else:
            matching += 1

    # Check TC fields not in binary
    for key, tf in tc_by_name.items():
        if key not in binary_by_name:
            missing_from_binary += 1
            mismatches.append({
                "field": tf["name"],
                "object_type": tf.get("object_type", ""),
                "issue": "missing_from_binary",
                "tc_offset": tf.get("offset"),
                "tc_type": tf.get("type"),
            })

    result = {
        "matching": matching,
        "missing_from_tc": missing_from_tc,
        "missing_from_binary": missing_from_binary,
        "type_mismatch": type_mismatch,
        "offset_mismatch": offset_mismatch,
        "mismatches": mismatches[:200],  # Cap stored mismatches
        "total_tc_fields": len(tc_fields),
        "total_binary_fields": len(binary_fields),
        "status": "complete",
    }

    msg_info(f"TC comparison: {matching} matching, {missing_from_tc} missing from TC, "
             f"{missing_from_binary} missing from binary, "
             f"{type_mismatch} type mismatches, {offset_mismatch} offset mismatches")

    return result


def _parse_tc_updatefields(tc_source_dir):
    """Parse TrinityCore UpdateFields.h to extract field definitions.

    Searches multiple possible paths for the UpdateFields header and parses
    UpdateField<T, block, index> declarations.

    Returns:
        list of field dicts, or empty list on failure.
    """
    candidate_paths = [
        os.path.join(tc_source_dir, "src", "server", "game", "Entities",
                     "Object", "UpdateFields.h"),
        os.path.join(tc_source_dir, "src", "server", "game",
                     "UpdateFields.h"),
        os.path.join(tc_source_dir, "src", "server", "game", "Entities",
                     "Object", "UpdateFieldFlags.h"),
    ]

    header_path = None
    for path in candidate_paths:
        if os.path.isfile(path):
            header_path = path
            break

    if not header_path:
        # Try recursive search
        header_path = _find_file_recursive(tc_source_dir, "UpdateFields.h")
        if not header_path:
            return []

    msg_info(f"Parsing TC UpdateFields from {header_path}")

    try:
        with open(header_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        msg_error(f"Failed to read {header_path}: {e}")
        return []

    return _parse_updatefields_header_content(content)


def _find_file_recursive(base_dir, filename, max_depth=6):
    """Recursively search for a file by name.

    Returns:
        Full path to the file, or None.
    """
    for root, dirs, files in os.walk(base_dir):
        depth = root.replace(base_dir, "").count(os.sep)
        if depth > max_depth:
            dirs.clear()
            continue
        if filename in files:
            return os.path.join(root, filename)
    return None


def _parse_updatefields_header_content(content):
    """Parse UpdateFields.h content to extract field definitions.

    Handles multiple struct definition styles:

    Style 1 (modern TC):
        struct ObjectData : public HasChangesMask<4>
        {
            UpdateField<int32, 0, 1> EntryID;
            UpdateField<ObjectGuid, 0, 2> Owner;
            DynamicUpdateField<int32, 0, 5> DynamicFlags;
        };

    Style 2 (enum-based):
        enum ObjectFields
        {
            OBJECT_FIELD_GUID = 0x0,
            OBJECT_FIELD_TYPE = 0x4,
        };

    Returns:
        list of field dicts.
    """
    fields = []

    # Pattern 1: struct XxxData with UpdateField members
    struct_pattern = re.compile(
        r'struct\s+(\w+)Data\s*:\s*public\s+HasChangesMask',
        re.MULTILINE
    )

    field_pattern = re.compile(
        r'(?:UpdateField|DynamicUpdateField|UpdateFieldArray)\s*<\s*'
        r'([^,>]+)'       # type
        r'\s*,\s*'
        r'(\d+)'          # block index
        r'\s*,\s*'
        r'(\d+)'          # field index
        r'(?:\s*,\s*(\d+))?' # optional array size
        r'\s*>\s*'
        r'(\w+)'          # field name
        r'\s*;'
    )

    dynamic_pattern = re.compile(
        r'DynamicUpdateField\s*<\s*'
        r'([^,>]+)'
        r'\s*,\s*(\d+)\s*,\s*(\d+)\s*>\s*'
        r'(\w+)\s*;'
    )

    current_struct = None
    current_obj_type = None
    brace_depth = 0
    in_struct = False

    for line in content.split('\n'):
        stripped = line.strip()

        # Check for struct start
        struct_match = struct_pattern.search(stripped)
        if struct_match:
            current_struct = struct_match.group(1)
            current_obj_type = _tc_struct_to_object_type(current_struct)
            in_struct = False  # wait for opening brace
            continue

        if current_struct and '{' in stripped:
            in_struct = True
            brace_depth += stripped.count('{') - stripped.count('}')
            continue

        if in_struct:
            brace_depth += stripped.count('{') - stripped.count('}')
            if brace_depth <= 0:
                current_struct = None
                current_obj_type = None
                in_struct = False
                continue

            # Parse UpdateField member
            fm = field_pattern.search(stripped)
            if fm:
                cpp_type = fm.group(1).strip()
                block_idx = int(fm.group(2))
                field_idx = int(fm.group(3))
                array_size = int(fm.group(4)) if fm.group(4) else 1
                field_name = fm.group(5)
                is_dynamic = "DynamicUpdateField" in stripped

                field_type = _cpp_type_to_field_type(cpp_type)

                fields.append({
                    "name": field_name,
                    "offset": field_idx * 4,  # approximate
                    "size": _type_size_in_dwords(field_type),
                    "type": field_type,
                    "flags": "PUBLIC",
                    "object_type": current_obj_type or "UNKNOWN",
                    "is_dynamic": is_dynamic,
                    "array_count": array_size,
                    "tc_index": field_idx,
                })
                continue

    # Pattern 2: Enum-style fields
    enum_pattern = re.compile(
        r'enum\s+(\w*Fields?\w*)\s*\{([^}]+)\}',
        re.MULTILINE | re.DOTALL
    )

    for match in enum_pattern.finditer(content):
        enum_name = match.group(1)
        enum_body = match.group(2)
        obj_type = _enum_name_to_object_type(enum_name)

        for line in enum_body.split('\n'):
            line = line.strip().rstrip(',')
            if not line or line.startswith('//') or line.startswith('#'):
                continue
            eq_match = re.match(r'(\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)', line)
            if eq_match:
                fname = eq_match.group(1)
                foffset = int(eq_match.group(2), 0)
                fields.append({
                    "name": fname,
                    "offset": foffset,
                    "size": 1,
                    "type": "uint32",
                    "flags": "PUBLIC",
                    "object_type": obj_type,
                    "is_dynamic": False,
                    "array_count": 1,
                })

    return fields


def _tc_struct_to_object_type(struct_name):
    """Convert TC struct name like 'Object' or 'ActivePlayer' to type string."""
    mapping = {
        "Object": "OBJECT",
        "Item": "ITEM",
        "Container": "CONTAINER",
        "Unit": "UNIT",
        "Player": "PLAYER",
        "ActivePlayer": "ACTIVE_PLAYER",
        "GameObject": "GAMEOBJECT",
        "DynamicObject": "DYNAMICOBJECT",
        "Corpse": "CORPSE",
        "AreaTrigger": "AREATRIGGER",
        "SceneObject": "SCENEOBJECT",
        "Conversation": "CONVERSATION",
        "AzeriteEmpoweredItem": "AZERITE_EMPOWERED_ITEM",
        "AzeriteItem": "AZERITE_ITEM",
    }
    return mapping.get(struct_name, struct_name.upper())


def _enum_name_to_object_type(enum_name):
    """Convert an enum name like 'ObjectFields' to an object type string."""
    name = enum_name.replace("Fields", "").replace("Field", "")
    return _tc_struct_to_object_type(name)


def _cpp_type_to_field_type(cpp_type):
    """Convert a C++ type name to our field type string."""
    cpp_type = cpp_type.strip()
    mapping = {
        "int32": "int32",
        "uint32": "uint32",
        "int64": "int64",
        "uint64": "uint64",
        "float": "float",
        "ObjectGuid": "guid",
        "GUID": "guid",
    }
    return mapping.get(cpp_type, "uint32")


def _type_size_in_dwords(field_type):
    """Return the size of a field type in 32-bit (dword) units."""
    sizes = {
        "int32": 1,
        "uint32": 1,
        "float": 1,
        "int64": 2,
        "uint64": 2,
        "guid": 4,
        "bytes": 1,
        "two_short": 1,
        "custom": 1,
    }
    return sizes.get(field_type, 1)


# ===================================================================
# Export functions
# ===================================================================

def export_updatefields_header(session) -> str:
    """Generate a complete C++ header with all UpdateField structs.

    Produces output compatible with TrinityCore's UpdateFields.h format:

        struct ObjectData : public HasChangesMask<N>
        {
            UpdateField<int32, 0, 1> EntryID;
            UpdateField<ObjectGuid, 0, 2> Owner;
            ...
        };

    Args:
        session: The PluginSession instance.

    Returns:
        String containing the generated C++ header content.
    """
    data = get_updatefield_descriptors(session)
    if not data:
        return "// No UpdateField data available. Run extract_updatefield_descriptors() first.\n"

    lines = [
        "// Auto-generated by TC WoW Binary Analyzer - UpdateField Descriptor Analyzer",
        "// DO NOT EDIT - regenerate from binary analysis",
        f"// Total fields: {data.get('total_fields', 0)}",
        f"// Descriptor table: {data.get('descriptor_table_ea', '?')}",
        "",
        "#ifndef TRINITYCORE_UPDATEFIELDS_GENERATED_H",
        "#define TRINITYCORE_UPDATEFIELDS_GENERATED_H",
        "",
        '#include "UpdateField.h"',
        '#include "ObjectGuid.h"',
        "",
        "namespace UF",
        "{",
        "",
    ]

    object_types = data.get("object_types", [])
    for obj_info in object_types:
        type_name = obj_info["type_name"]
        type_fields = obj_info["fields"]
        field_count = obj_info["field_count"]

        if not type_fields:
            continue

        # Calculate change mask size
        mask_size = max(1, (field_count + 31) // 32)

        # Struct name: ObjectData, UnitData, PlayerData, etc.
        struct_name = _object_type_to_struct_name(type_name)

        lines.append(f"struct {struct_name} : public HasChangesMask<{mask_size}>")
        lines.append("{")

        for i, field in enumerate(type_fields):
            fname = _sanitize_field_name(field["name"])
            ftype = field["type"]
            is_dynamic = field.get("is_dynamic", False)

            cpp_type, _ = TC_CPP_TYPE_MAP.get(ftype, ("int32", "UF_TYPE_INT"))

            if is_dynamic:
                lines.append(f"    DynamicUpdateField<{cpp_type}, 0, {i}> {fname};")
            else:
                lines.append(f"    UpdateField<{cpp_type}, 0, {i}> {fname};")

        lines.append("};")
        lines.append("")

    lines.append("} // namespace UF")
    lines.append("")
    lines.append("#endif // TRINITYCORE_UPDATEFIELDS_GENERATED_H")
    lines.append("")

    return "\n".join(lines)


def export_updatefields_enum(session, object_type) -> str:
    """Generate a C++ enum for one object type's update fields.

    Produces output like:

        enum ObjectFields
        {
            OBJECT_FIELD_GUID          = 0x0000, // guid, PUBLIC
            OBJECT_FIELD_ENTRY_ID      = 0x0004, // uint32, PUBLIC
            ...
            OBJECT_END                 = 0x0010,
        };

    Args:
        session: The PluginSession instance.
        object_type: The object type string (e.g., "OBJECT", "UNIT").

    Returns:
        String containing the generated C++ enum.
    """
    data = get_updatefield_descriptors(session)
    if not data:
        return f"// No data for {object_type}\n"

    # Find the matching object type entry
    target_fields = None
    for obj_info in data.get("object_types", []):
        if obj_info["type_name"] == object_type:
            target_fields = obj_info["fields"]
            break

    if not target_fields:
        # Fallback: query SQL table directly
        db = session.db
        rows = db.fetchall(
            """SELECT * FROM update_fields
               WHERE object_type = ?
               ORDER BY field_offset""",
            (object_type,)
        )
        if not rows:
            return f"// No fields found for object type '{object_type}'\n"

        target_fields = [
            {
                "name": row["field_name"],
                "offset": row["field_offset"],
                "size": row["field_size"],
                "type": row["field_type"],
                "flags": row["field_flags"],
            }
            for row in rows
        ]

    # Generate enum
    enum_name = f"{object_type.replace('_', '')}Fields"
    if object_type == "ACTIVE_PLAYER":
        enum_name = "ActivePlayerFields"

    lines = [
        f"// Auto-generated UpdateField enum for {object_type}",
        f"enum {enum_name}",
        "{",
    ]

    max_name_len = max((len(f["name"]) for f in target_fields), default=20)

    end_offset = 0
    for field in target_fields:
        fname = field["name"]
        foffset = field["offset"]
        fsize = field.get("size", 1)
        ftype = field.get("type", "uint32")
        fflags = field.get("flags", "PUBLIC")

        padding = " " * (max_name_len - len(fname) + 4)
        lines.append(
            f"    {fname}{padding}= 0x{foffset:04X}, "
            f"// {ftype}, size={fsize}, {fflags}"
        )

        field_end = foffset + fsize * 4
        if field_end > end_offset:
            end_offset = field_end

    # Add END marker
    end_name = f"{object_type}_END"
    padding = " " * (max_name_len - len(end_name) + 4)
    lines.append(f"    {end_name}{padding}= 0x{end_offset:04X},")

    lines.append("};")
    lines.append("")

    return "\n".join(lines)


def get_field_by_name(session, name) -> dict:
    """Look up a specific UpdateField by name.

    Searches both the SQL table and the KV store for the field.

    Args:
        session: The PluginSession instance.
        name: The field name to search for (case-insensitive).

    Returns:
        dict with field data, or None if not found.
    """
    db = session.db

    # Try exact match first
    row = db.fetchone(
        "SELECT * FROM update_fields WHERE field_name = ?",
        (name,)
    )
    if row:
        return dict(row)

    # Case-insensitive search
    row = db.fetchone(
        "SELECT * FROM update_fields WHERE UPPER(field_name) = UPPER(?)",
        (name,)
    )
    if row:
        return dict(row)

    # Partial match
    rows = db.fetchall(
        "SELECT * FROM update_fields WHERE field_name LIKE ?",
        (f"%{name}%",)
    )
    if rows:
        # Return the best match (shortest name containing the search term)
        best = min(rows, key=lambda r: len(r["field_name"]))
        return dict(best)

    # Check KV store
    data = get_updatefield_descriptors(session)
    if data:
        for obj_info in data.get("object_types", []):
            for field in obj_info.get("fields", []):
                if field["name"].upper() == name.upper():
                    return field

    return None


# ===================================================================
# Naming / formatting helpers
# ===================================================================

def _object_type_to_struct_name(object_type):
    """Convert object type string to TrinityCore struct name.

    "OBJECT" -> "ObjectData"
    "ACTIVE_PLAYER" -> "ActivePlayerData"
    "GAMEOBJECT" -> "GameObjectData"
    """
    mapping = {
        "OBJECT":                 "ObjectData",
        "ITEM":                   "ItemData",
        "CONTAINER":              "ContainerData",
        "UNIT":                   "UnitData",
        "PLAYER":                 "PlayerData",
        "ACTIVE_PLAYER":          "ActivePlayerData",
        "GAMEOBJECT":             "GameObjectData",
        "DYNAMICOBJECT":          "DynamicObjectData",
        "CORPSE":                 "CorpseData",
        "AREATRIGGER":            "AreaTriggerData",
        "SCENEOBJECT":            "SceneObjectData",
        "CONVERSATION":           "ConversationData",
        "AZERITE_EMPOWERED_ITEM": "AzeriteEmpoweredItemData",
        "AZERITE_ITEM":           "AzeriteItemData",
    }
    if object_type in mapping:
        return mapping[object_type]

    # Generic fallback: CamelCase + "Data"
    parts = object_type.split("_")
    camel = "".join(p.capitalize() for p in parts)
    return f"{camel}Data"


def _sanitize_field_name(name):
    """Sanitize a field name for use as a C++ identifier.

    Strips common prefixes and converts to PascalCase if needed.

    "OBJECT_FIELD_GUID" -> "Guid"  (for struct member usage)
    "ObjectField::Guid" -> "Guid"
    "UNIT_FIELD_HEALTH" -> "Health"
    """
    # Strip namespace prefix
    for prefix, _ in DESCRIPTOR_CLASS_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]

    # Strip OBJECT_TYPE_FIELD_ prefix
    for prefix, _ in OBJECT_TYPE_PREFIXES:
        upper = name.upper()
        if upper.startswith(prefix.upper()):
            remainder = name[len(prefix):]
            if remainder:
                # Convert UPPER_SNAKE to PascalCase
                return _snake_to_pascal(remainder)

    # Already a valid C++ identifier
    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name):
        return name

    # Fallback: replace invalid chars
    return re.sub(r'[^A-Za-z0-9_]', '_', name)


def _snake_to_pascal(name):
    """Convert UPPER_SNAKE_CASE to PascalCase.

    "HEALTH" -> "Health"
    "MAX_HEALTH" -> "MaxHealth"
    "CREATED_BY" -> "CreatedBy"
    """
    parts = name.split("_")
    return "".join(p.capitalize() for p in parts if p)


# ===================================================================
# Summary output
# ===================================================================

def _print_summary(tables_info, dynamic_summary, tc_comparison):
    """Print a human-readable summary to the IDA output window."""
    msg("")
    msg("=" * 70)
    msg("  UpdateField Descriptor Analysis Summary")
    msg("=" * 70)

    total_fields = sum(t["field_count"] for t in tables_info)
    msg(f"  Total fields: {total_fields}")
    msg(f"  Object types: {len(tables_info)}")
    msg("")

    for t in sorted(tables_info, key=lambda x: x["type_name"]):
        msg(f"  {t['type_name']:30s}  {t['field_count']:4d} fields  "
            f"({t['total_size']:5d} bytes)  table={t.get('table_ea', '?')}")

    if dynamic_summary:
        msg("")
        msg(f"  Dynamic fields: {sum(d['field_count'] for d in dynamic_summary)}")
        for d in dynamic_summary:
            msg(f"    {d['type_name']:30s}  {d['field_count']:4d} dynamic fields")

    if tc_comparison and tc_comparison.get("status") == "complete":
        msg("")
        msg("  TrinityCore Comparison:")
        msg(f"    Matching:              {tc_comparison['matching']}")
        msg(f"    Missing from TC:       {tc_comparison['missing_from_tc']}")
        msg(f"    Missing from binary:   {tc_comparison['missing_from_binary']}")
        msg(f"    Type mismatches:       {tc_comparison['type_mismatch']}")
        msg(f"    Offset mismatches:     {tc_comparison['offset_mismatch']}")

        if tc_comparison.get("mismatches"):
            msg("")
            msg("  First 10 mismatches:")
            for m in tc_comparison["mismatches"][:10]:
                msg(f"    [{m.get('object_type', '?')}] {m['field']}: {m['issue']}")

    elif tc_comparison and tc_comparison.get("status") == "skipped":
        msg("")
        msg("  TC comparison skipped (configure tc_source_dir in settings)")

    msg("")
    msg("=" * 70)


# ===================================================================
# Alternative table discovery strategies
# ===================================================================

def _find_tables_via_init_functions(rdata_start, rdata_end):
    """Alternative strategy: find descriptor tables by locating
    CGObject_C::InitDescriptorFields and similar initialization functions.

    In the binary, these functions typically:
      1. Load a pointer to the descriptor table from .rdata
      2. Store it in a global variable
      3. Iterate the table to register fields

    We find these by looking for functions named *InitDescriptor* or
    *InitUpdateField* in IDA's name list.

    Returns:
        set of table base EAs.
    """
    table_bases = set()

    # Search for known init function name patterns
    init_patterns = [
        "InitDescriptorFields",
        "InitUpdateField",
        "RegisterUpdateFields",
        "SetupDescriptors",
        "CGObject_C::InitDescriptor",
        "CGUnit_C::InitDescriptor",
        "CGPlayer_C::InitDescriptor",
    ]

    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if not name:
            continue

        for pattern in init_patterns:
            if pattern.lower() in name.lower():
                msg(f"  Found init function: {name} at {ea_str(ea)}")
                # Analyze the function to find table pointer loads
                tables = _extract_table_ptrs_from_function(ea, rdata_start, rdata_end)
                table_bases.update(tables)
                break

    return table_bases


def _extract_table_ptrs_from_function(func_ea, rdata_start, rdata_end):
    """Analyze a function to find pointers to descriptor tables.

    Looks for LEA instructions that load .rdata addresses, then checks
    if those addresses point to valid descriptor tables.

    Returns:
        set of table base EAs.
    """
    tables = set()
    func = ida_funcs.get_func(func_ea)
    if not func:
        return tables

    for head in idautils.Heads(func.start_ea, func.end_ea):
        # Check all data references from this instruction
        for xref in idautils.DataRefsFrom(head):
            if rdata_start <= xref < rdata_end:
                # Check if this rdata address is a valid descriptor table
                if _is_valid_descriptor_entry(xref, rdata_start, rdata_end):
                    table_start = _find_table_start(xref, rdata_start, rdata_end)
                    if table_start is not None:
                        tables.add(table_start)

    return tables


def _find_tables_via_string_xrefs(rdata_start, rdata_end):
    """Alternative strategy: find descriptor tables by searching for
    cross-references to UpdateField-like string constants.

    Scans all strings in the binary for patterns matching field names,
    then traces their data xrefs back to descriptor table entries.

    Returns:
        set of table base EAs.
    """
    table_bases = set()
    field_string_eas = {}

    # Scan all defined strings in .rdata
    for ea in idautils.Strings():
        s = ida_bytes.get_strlit_contents(ea, -1, idc.STRTYPE_C)
        if s is None:
            continue
        try:
            text = s.decode("utf-8", errors="replace")
        except Exception:
            continue

        if not _looks_like_field_name(text):
            continue

        # Check for UpdateField-specific patterns
        is_uf = False
        for prefix, _ in OBJECT_TYPE_PREFIXES:
            if text.upper().startswith(prefix.upper()):
                is_uf = True
                break
        if not is_uf:
            for prefix, _ in DESCRIPTOR_CLASS_PREFIXES:
                if text.startswith(prefix):
                    is_uf = True
                    break

        if is_uf:
            field_string_eas[text] = ea

    if field_string_eas:
        msg(f"  Found {len(field_string_eas)} field-like strings")

    # For each string, find data xrefs and trace to table entries
    for text, string_ea in field_string_eas.items():
        xrefs = _find_data_xrefs_to(string_ea, rdata_start, rdata_end)
        if not xrefs:
            xrefs = _scan_for_pointer(string_ea, rdata_start, rdata_end)

        for xref_ea in xrefs:
            if _is_valid_descriptor_entry(xref_ea, rdata_start, rdata_end):
                table_start = _find_table_start(xref_ea, rdata_start, rdata_end)
                if table_start is not None:
                    table_bases.add(table_start)

    return table_bases


# ===================================================================
# Additional descriptor entry format detection
# ===================================================================

def _detect_entry_format(sample_ea, rdata_start, rdata_end):
    """Try to detect the descriptor entry struct format at sample_ea.

    Different WoW builds use slightly different descriptor entry layouts.
    This function reads a few potential entries and determines the format.

    Known formats:
      - Classic (pre-8.x): {name_ptr:8, offset:4, size:4, type_flags:4} = 20 bytes
      - Modern (8.x+):     {name_ptr:8, offset:2, size:2, type:2, flags:2} = 16 bytes
      - 12.x:              {name_ptr:8, offset:4, size:4, type_flags:4} = 20 bytes
                            (but may have additional padding to 24 bytes)

    Returns:
        Entry size in bytes, or DESCRIPTOR_ENTRY_SIZE if detection fails.
    """
    # Try standard 20-byte format
    if _is_valid_descriptor_entry(sample_ea, rdata_start, rdata_end):
        # Check if the NEXT entry at +20 bytes is also valid
        next_ea = sample_ea + 20
        if next_ea + 20 <= rdata_end:
            next_ptr = ida_bytes.get_qword(next_ea)
            if next_ptr != 0:
                next_name = _read_string_at(next_ptr)
                if next_name and _looks_like_field_name(next_name):
                    return 20

    # Try 24-byte format (with 4 bytes padding)
    if sample_ea + 24 <= rdata_end:
        next_ea = sample_ea + 24
        next_ptr = ida_bytes.get_qword(next_ea)
        if next_ptr != 0:
            next_name = _read_string_at(next_ptr)
            if next_name and _looks_like_field_name(next_name):
                return 24

    # Try 16-byte format
    if sample_ea + 16 <= rdata_end:
        next_ea = sample_ea + 16
        next_ptr = ida_bytes.get_qword(next_ea)
        if next_ptr != 0:
            next_name = _read_string_at(next_ptr)
            if next_name and _looks_like_field_name(next_name):
                return 16

    # Try 32-byte format (heavily padded/extended entries)
    if sample_ea + 32 <= rdata_end:
        next_ea = sample_ea + 32
        next_ptr = ida_bytes.get_qword(next_ea)
        if next_ptr != 0:
            next_name = _read_string_at(next_ptr)
            if next_name and _looks_like_field_name(next_name):
                return 32

    return DESCRIPTOR_ENTRY_SIZE


def _parse_descriptor_table_adaptive(table_ea, rdata_start, rdata_end):
    """Parse a descriptor table with adaptive entry size detection.

    First detects the entry format, then parses all entries.
    Falls back to _parse_descriptor_table if auto-detection fails.

    Returns:
        (fields, dynamic_fields) tuple.
    """
    entry_size = _detect_entry_format(table_ea, rdata_start, rdata_end)

    if entry_size == DESCRIPTOR_ENTRY_SIZE:
        return _parse_descriptor_table(table_ea, rdata_start, rdata_end)

    msg(f"  Detected non-standard entry size: {entry_size} bytes at {ea_str(table_ea)}")

    fields = []
    dynamic_fields = []
    ea = table_ea
    idx = 0

    while ea + entry_size <= rdata_end and idx < MAX_FIELDS_PER_TYPE:
        name_ptr = ida_bytes.get_qword(ea)
        if name_ptr == 0:
            break

        name = _read_string_at(name_ptr)
        if not name or not _looks_like_field_name(name):
            break

        # Read fields based on detected format
        if entry_size == 16:
            # Compact format: {ptr:8, offset:2, size:2, type:1, flags:1, pad:2}
            offset_val = ida_bytes.get_word(ea + 8)
            size_val = ida_bytes.get_word(ea + 10)
            field_type_id = ida_bytes.get_byte(ea + 12)
            visibility_byte = ida_bytes.get_byte(ea + 13)
            type_flags = (visibility_byte << 8) | field_type_id
        elif entry_size == 24:
            # Extended format: standard 20 + 4 bytes extra data
            offset_val = ida_bytes.get_dword(ea + 8)
            size_val = ida_bytes.get_dword(ea + 12)
            type_flags = ida_bytes.get_dword(ea + 16)
            # extra_data = ida_bytes.get_dword(ea + 20)  # purpose TBD
        elif entry_size == 32:
            # Wide format
            offset_val = ida_bytes.get_dword(ea + 8)
            size_val = ida_bytes.get_dword(ea + 12)
            type_flags = ida_bytes.get_dword(ea + 16)
        else:
            # Fallback to standard layout
            offset_val = ida_bytes.get_dword(ea + 8)
            size_val = ida_bytes.get_dword(ea + 12)
            type_flags = ida_bytes.get_dword(ea + 16)

        if size_val == 0 or size_val > 256 or offset_val > 0x10000:
            break

        field_type_id = type_flags & 0xFF
        visibility_flags = (type_flags >> 8) & 0xFF
        field_type_name = FIELD_TYPE_NAMES.get(field_type_id, f"unk_{field_type_id}")
        flag_list = _decode_flags(visibility_flags)
        is_dynamic = bool(visibility_flags & (FLAG_DYNAMIC >> 8))

        obj_type = _classify_field_object_type(name)

        field_entry = {
            "name": name,
            "offset": offset_val,
            "size": size_val,
            "type": field_type_name,
            "type_id": field_type_id,
            "flags": ",".join(flag_list) if flag_list else "NONE",
            "flags_raw": type_flags,
            "is_dynamic": is_dynamic,
            "object_type": obj_type,
            "table_index": idx,
            "entry_ea": ea_str(ea),
        }

        if is_dynamic:
            dynamic_fields.append(field_entry)
        fields.append(field_entry)

        _label_descriptor_entry(ea, name, idx)

        ea += entry_size
        idx += 1

    if fields:
        msg(f"  Parsed {len(fields)} fields (entry_size={entry_size}) "
            f"from table at {ea_str(table_ea)}")

    return fields, dynamic_fields


# ===================================================================
# Batch / convenience wrappers
# ===================================================================

def run_full_analysis(session) -> int:
    """Run the complete UpdateField descriptor analysis pipeline.

    This is a convenience wrapper that:
      1. Extracts descriptors from the binary
      2. Attempts alternative strategies if the primary one finds nothing
      3. Returns the total field count

    Args:
        session: The PluginSession instance.

    Returns:
        Total number of fields extracted.
    """
    count = extract_updatefield_descriptors(session)

    if count == 0:
        msg_warn("Primary extraction found no fields; trying alternative strategies")

        rdata_start, rdata_end = _find_rdata_segment()
        if rdata_start is None:
            return 0

        # Strategy 2: search via init functions
        table_bases = _find_tables_via_init_functions(rdata_start, rdata_end)

        # Strategy 3: search via all field-like strings
        if not table_bases:
            table_bases = _find_tables_via_string_xrefs(rdata_start, rdata_end)

        if not table_bases:
            msg_error("All UpdateField extraction strategies failed")
            return 0

        msg_info(f"Alternative strategies found {len(table_bases)} table(s)")

        all_fields = []
        all_dynamic = []
        tables_info = []

        for table_ea in sorted(table_bases):
            # Try adaptive parsing first
            fields, dynamic = _parse_descriptor_table_adaptive(
                table_ea, rdata_start, rdata_end)
            if not fields:
                fields, dynamic = _parse_descriptor_table(
                    table_ea, rdata_start, rdata_end)

            if fields:
                type_groups = _classify_fields_by_type(fields)
                for obj_type, typed_fields in type_groups.items():
                    total_size = 0
                    if typed_fields:
                        last = typed_fields[-1]
                        total_size = last["offset"] + last["size"] * 4
                    tables_info.append({
                        "type_name": obj_type,
                        "field_count": len(typed_fields),
                        "total_size": total_size,
                        "fields": typed_fields,
                        "table_ea": ea_str(table_ea),
                    })
                    all_fields.extend(typed_fields)
                all_dynamic.extend(dynamic)

        if all_fields:
            # Deduplicate
            seen = set()
            unique = []
            for f in all_fields:
                key = (f.get("object_type", "UNKNOWN"), f["name"])
                if key not in seen:
                    seen.add(key)
                    unique.append(f)

            _store_fields_sql(session.db, unique)
            dynamic_summary = _build_dynamic_summary(all_dynamic)
            tc_comparison = _compare_with_trinitycore(session.cfg, unique)

            primary_ea = ea_str(sorted(table_bases)[0])
            result = {
                "object_types": tables_info,
                "dynamic_fields": dynamic_summary,
                "tc_comparison": tc_comparison,
                "total_fields": len(unique),
                "descriptor_table_ea": primary_ea,
            }
            session.db.kv_set("updatefield_descriptors", result)
            session.db.commit()

            count = len(unique)
            _print_summary(tables_info, dynamic_summary, tc_comparison)

    return count
