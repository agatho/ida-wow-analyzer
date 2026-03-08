"""
Update Field Analyzer
Identifies WoW client object update field descriptor tables and extracts
field names, offsets, types, and sizes for TrinityCore UpdateFields generation.

Supports importing from existing wow_updatefields JSON extraction
and binary scanning for descriptor table pointers.
"""

import json
import os

import ida_bytes
import ida_name
import ida_segment
import ida_xref
import idaapi
import idc
import idautils

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str


# Known WoW object types and their update field class names
OBJECT_TYPE_CLASSES = {
    "CGObject_C": "OBJECT",
    "CGItem_C": "ITEM",
    "CGContainer_C": "CONTAINER",
    "CGAzeriteEmpoweredItem_C": "AZERITE_EMPOWERED_ITEM",
    "CGAzeriteItem_C": "AZERITE_ITEM",
    "CGUnit_C": "UNIT",
    "CGPlayer_C": "PLAYER",
    "CGActivePlayer_C": "ACTIVE_PLAYER",
    "CGGameObject_C": "GAMEOBJECT",
    "CGDynamicObject_C": "DYNAMICOBJECT",
    "CGCorpse_C": "CORPSE",
    "CGAreaTrigger_C": "AREATRIGGER",
    "CGSceneObject_C": "SCENEOBJECT",
    "CGConversation_C": "CONVERSATION",
}

# TrinityCore update field type names
TC_UF_TYPES = {
    "int8": "UF_TYPE_INT",
    "int16": "UF_TYPE_INT",
    "int32": "UF_TYPE_INT",
    "int64": "UF_TYPE_TWO_SHORT",
    "uint8": "UF_TYPE_INT",
    "uint16": "UF_TYPE_INT",
    "uint32": "UF_TYPE_INT",
    "uint64": "UF_TYPE_TWO_SHORT",
    "float": "UF_TYPE_FLOAT",
    "guid": "UF_TYPE_GUID",
    "bytes": "UF_TYPE_BYTES",
}


def analyze_update_fields(session):
    """Discover update field descriptors from the binary.

    Strategy:
      1. Check if update fields were already imported from JSON
      2. Import from existing wow_updatefields JSON if available
      3. Try wow_object_layouts JSON as fallback
      4. Otherwise, scan for descriptor table patterns in .rdata
    """
    db = session.db
    cfg = session.cfg

    # If update_fields were already imported, report the count
    existing = db.count("update_fields")
    if existing > 0:
        msg_info(f"Update fields: {existing} fields already in DB "
                 f"(from JSON import)")
        return existing

    ext_dir = cfg.extraction_dir
    if ext_dir:
        for filename in [f"wow_updatefields_{cfg.build_number}.json", "wow_updatefields.json"]:
            filepath = os.path.join(ext_dir, filename)
            if os.path.isfile(filepath):
                return _import_update_fields_json(session, filepath)
        for filename in [f"wow_object_layouts_{cfg.build_number}.json", "wow_object_layouts.json"]:
            filepath = os.path.join(ext_dir, filename)
            if os.path.isfile(filepath):
                return _import_object_layouts_json(session, filepath)

    msg_warn("No update field data found — configure extraction_dir in settings")
    return _scan_for_descriptor_tables(session)


def _import_update_fields_json(session, uf_file):
    """Import update field data from existing extraction."""
    db = session.db
    cfg = session.cfg

    msg_info(f"Importing update fields from {uf_file}")
    with open(uf_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    classes = data.get("classes", [])
    count = 0

    for cls in classes:
        name = cls.get("name", "")
        if not name:
            continue

        obj_type = OBJECT_TYPE_CLASSES.get(name, name)
        fields = cls.get("fields", [])

        for field in fields:
            fname = field.get("name", f"field_{count}")
            ftype = field.get("type", "int32")
            foffset = field.get("offset", 0)
            fsize = field.get("size", 4)
            fflags = field.get("flags", "PUBLIC")
            array_count = field.get("array_size", field.get("array_count", 1))
            is_dynamic = 1 if field.get("is_dynamic") or "dynamic" in ftype else 0

            db.execute(
                """INSERT OR REPLACE INTO update_fields
                   (object_type, field_name, field_offset, field_size,
                    field_type, field_flags, array_count, is_dynamic)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (obj_type, fname, foffset, fsize, ftype, fflags,
                 array_count, is_dynamic),
            )
            count += 1

    db.commit()
    msg_info(f"Imported {count} update fields from {len(classes)} classes")
    return count


def _import_object_layouts_json(session, layout_file):
    """Import from wow_object_layouts JSON (alternative format)."""
    db = session.db

    msg_info(f"Importing object layouts from {layout_file}")
    with open(layout_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    layouts = data if isinstance(data, list) else data.get("layouts", [])
    count = 0

    for layout in layouts:
        name = layout.get("name", layout.get("class_name", ""))
        if not name:
            continue

        obj_type = OBJECT_TYPE_CLASSES.get(name, name)
        fields = layout.get("fields", layout.get("members", []))

        for field in fields:
            fname = field.get("name", f"field_{count}")
            ftype = field.get("type", "int32")
            foffset = field.get("offset", 0)
            fsize = field.get("size", 4)
            fflags = field.get("flags", "PUBLIC")

            db.execute(
                """INSERT OR REPLACE INTO update_fields
                   (object_type, field_name, field_offset, field_size,
                    field_type, field_flags, array_count, is_dynamic)
                   VALUES (?, ?, ?, ?, ?, ?, 1, 0)""",
                (obj_type, fname, foffset, fsize, ftype, fflags),
            )
            count += 1

    db.commit()
    msg_info(f"Imported {count} fields from object layouts")
    return count


def _scan_for_descriptor_tables(session):
    """Scan the binary for update field descriptor table patterns.

    Descriptor tables are arrays of {name_ptr, type, offset, size} structs
    in .rdata, typically referenced from CGObject_C::InitDescriptorFields
    and similar initialization functions.

    Strategy:
      1. Find known update field name strings in the binary (e.g. "m_guid",
         "m_health", "m_level").
      2. Follow cross-references from each string back to data section
         pointers — these are entries in a descriptor table.
      3. Walk backwards from the discovered entry to find the table start,
         then walk forward to parse every entry.
      4. Determine the object type for each table by matching its field
         names against known per-type field signatures.
      5. Insert all discovered fields into the update_fields table.
    """
    db = session.db
    count = 0

    # ------------------------------------------------------------------
    # Known field names and their characteristic object type.  We search
    # for a representative subset; the full table is parsed once we find
    # any entry.
    # ------------------------------------------------------------------
    _SEED_FIELDS = {
        # OBJECT fields
        "m_guid": "OBJECT",
        "m_entryID": "OBJECT",
        "m_dynamicFlags": "OBJECT",
        "m_scale": "OBJECT",
        # ITEM fields
        "m_owner": "ITEM",
        "m_stackCount": "ITEM",
        "m_durability": "ITEM",
        "m_maxDurability": "ITEM",
        # UNIT fields
        "m_health": "UNIT",
        "m_maxHealth": "UNIT",
        "m_level": "UNIT",
        "m_displayID": "UNIT",
        "m_factionTemplate": "UNIT",
        "m_npcFlags": "UNIT",
        "m_attackPower": "UNIT",
        # PLAYER fields
        "m_playerBytes": "PLAYER",
        "m_playerBytes2": "PLAYER",
        "m_xp": "PLAYER",
        "m_nextLevelXP": "PLAYER",
        "m_currentSpecID": "PLAYER",
        # GAMEOBJECT fields
        "m_createdBy": "GAMEOBJECT",
        "m_displayInfo": "GAMEOBJECT",
        "m_parentRotation": "GAMEOBJECT",
        # ACTIVE_PLAYER fields
        "m_invSlots": "ACTIVE_PLAYER",
        "m_coinage": "ACTIVE_PLAYER",
        # DYNAMICOBJECT fields
        "m_caster": "DYNAMICOBJECT",
        "m_spellXSpellVisualID": "DYNAMICOBJECT",
        # CORPSE fields
        "m_guildID": "CORPSE",
        # AREATRIGGER fields
        "m_overrideScaleCurve": "AREATRIGGER",
        # CONVERSATION fields
        "m_lastLineEndTime": "CONVERSATION",
    }

    # Broader set of field name prefixes that characterise each type.
    _TYPE_SIGNATURES = {
        "OBJECT": {"m_guid", "m_entryID", "m_dynamicFlags", "m_scale",
                    "m_objectType"},
        "ITEM": {"m_owner", "m_contained", "m_stackCount", "m_durability",
                 "m_maxDurability", "m_flags", "m_enchantment",
                 "m_propertyData"},
        "CONTAINER": {"m_slots", "m_numSlots"},
        "UNIT": {"m_health", "m_maxHealth", "m_level", "m_displayID",
                 "m_factionTemplate", "m_npcFlags", "m_attackPower",
                 "m_power", "m_maxPower", "m_auras", "m_combatReach"},
        "PLAYER": {"m_playerBytes", "m_xp", "m_nextLevelXP",
                   "m_currentSpecID", "m_playerBytes2"},
        "ACTIVE_PLAYER": {"m_invSlots", "m_coinage", "m_knownTitles",
                          "m_restInfo", "m_backpackAutoSortDisabled"},
        "GAMEOBJECT": {"m_createdBy", "m_displayInfo", "m_parentRotation",
                       "m_typeID", "m_artKit"},
        "DYNAMICOBJECT": {"m_caster", "m_spellXSpellVisualID", "m_radius"},
        "CORPSE": {"m_guildID", "m_displayID", "m_items", "m_factionTemplate"},
        "AREATRIGGER": {"m_overrideScaleCurve", "m_extraScaleCurve",
                        "m_caster"},
        "SCENEOBJECT": {"m_createdBy", "m_rndSeedVal", "m_scriptPackageID"},
        "CONVERSATION": {"m_lastLineEndTime", "m_progress"},
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_rdata_segments():
        """Return list of (seg, name) for readable, non-executable segments."""
        result = []
        seen = set()
        for name in (".rdata", ".data"):
            seg = ida_segment.get_segm_by_name(name)
            if seg and seg.start_ea not in seen:
                result.append((seg, name))
                seen.add(seg.start_ea)
        n = ida_segment.get_segm_qty()
        for i in range(n):
            seg = ida_segment.getnseg(i)
            if not seg or seg.start_ea in seen:
                continue
            sname = ida_segment.get_segm_name(seg) or ""
            if sname in (".text", ".pdata", ".rsrc", ".reloc", ".idata", ".tls"):
                continue
            if (seg.perm & 4) and not (seg.perm & 1):
                result.append((seg, sname))
                seen.add(seg.start_ea)
        return result

    def _ea_in_segments(ea, segments):
        for seg, _ in segments:
            if seg.start_ea <= ea < seg.end_ea:
                return True
        return False

    def _read_cstring(ea, max_len=512):
        """Read a null-terminated C string at ea."""
        if not ida_bytes.is_loaded(ea):
            return None
        s = idc.get_strlit_contents(ea, max_len, idc.STRTYPE_C)
        if s:
            try:
                return s.decode("utf-8", errors="replace")
            except Exception:
                return None
        return None

    def _read_qword_safe(ea):
        if not ida_bytes.is_loaded(ea):
            return None
        return ida_bytes.get_qword(ea)

    def _read_dword_safe(ea):
        if not ida_bytes.is_loaded(ea):
            return None
        return ida_bytes.get_dword(ea)

    def _read_word_safe(ea):
        if not ida_bytes.is_loaded(ea):
            return None
        return ida_bytes.get_word(ea)

    # ------------------------------------------------------------------
    # Step 1: Locate known field name strings and gather data xrefs
    # ------------------------------------------------------------------
    msg_info("Scanning binary for update field descriptor tables...")

    data_segs = _get_rdata_segments()
    if not data_segs:
        msg_warn("No readable data segments found")
        return 0

    # Collect (string_ea, string_value) for known field names
    string_hits = {}  # field_name -> [ea_of_string, ...]
    all_strings = idautils.Strings()
    all_strings.setup(strtypes=[idc.STRTYPE_C], minlen=4)

    for s in all_strings:
        val = str(s)
        if val in _SEED_FIELDS:
            string_hits.setdefault(val, []).append(s.ea)

    if not string_hits:
        msg_warn("No known update field strings found in binary — "
                 "trying direct .rdata scan for field name patterns")
        # Fallback: scan .rdata for any "m_" prefixed strings referenced
        # as pointers in potential table structures.
        return _scan_rdata_for_descriptor_patterns(
            session, data_segs, _read_cstring, _read_qword_safe,
            _read_dword_safe, _read_word_safe, _ea_in_segments,
            _TYPE_SIGNATURES)

    msg_info(f"Found {len(string_hits)} known field name strings "
             f"({sum(len(v) for v in string_hits.values())} instances)")

    # ------------------------------------------------------------------
    # Step 2: From each string, follow data xrefs to find table entries
    #         that contain a pointer to this string.
    # ------------------------------------------------------------------
    # A descriptor table entry looks like:
    #   +0x00: qword  name_ptr  (points to a C string)
    #   +0x08: dword  field_type_enum
    #   +0x0C: dword  field_offset (or size, or combined)
    #
    # Or alternatively:
    #   +0x00: qword  name_ptr
    #   +0x08: word   field_type
    #   +0x0A: word   field_size
    #   +0x0C: dword  field_offset
    #
    # Or 24-byte entries:
    #   +0x00: qword  name_ptr
    #   +0x08: dword  field_type
    #   +0x0C: dword  field_offset
    #   +0x10: dword  field_size
    #   +0x14: dword  field_flags
    #
    # We probe for multiple entry sizes.

    candidate_table_eas = set()  # set of (entry_ea, entry_size)

    for field_name, str_eas in string_hits.items():
        for str_ea in str_eas:
            # Find data cross-references to this string
            for xref in idautils.XrefsTo(str_ea, 0):
                ref_ea = xref.frm
                if ref_ea == idaapi.BADADDR:
                    continue
                if not _ea_in_segments(ref_ea, data_segs):
                    continue
                # This ref_ea is in .rdata and points to our field name string.
                # It is likely the name_ptr field of a descriptor entry.
                candidate_table_eas.add(ref_ea)

    if not candidate_table_eas:
        msg_warn("No data-section references to field name strings found")
        return 0

    msg_info(f"Found {len(candidate_table_eas)} candidate descriptor "
             f"table entry locations")

    # ------------------------------------------------------------------
    # Step 3: Determine entry size and find table boundaries.
    #         Group nearby candidate entries to identify distinct tables.
    # ------------------------------------------------------------------

    def _probe_entry_size(entry_ea):
        """Try to determine the entry size by looking at the next entry.

        We try 16, 20, and 24-byte strides from the given entry.
        The next entry should also start with a valid string pointer.
        """
        for stride in (16, 20, 24, 32):
            next_ea = entry_ea + stride
            ptr = _read_qword_safe(next_ea)
            if ptr is not None and ptr != 0:
                s = _read_cstring(ptr)
                if s and len(s) >= 2 and s.startswith("m_"):
                    return stride
        # Also try checking if this entry is NOT the first — look backwards
        for stride in (16, 20, 24, 32):
            prev_ea = entry_ea - stride
            ptr = _read_qword_safe(prev_ea)
            if ptr is not None and ptr != 0:
                s = _read_cstring(ptr)
                if s and len(s) >= 2 and s.startswith("m_"):
                    return stride
        return None

    # Determine the dominant entry size across all candidates
    size_votes = {}
    for entry_ea in sorted(candidate_table_eas):
        es = _probe_entry_size(entry_ea)
        if es is not None:
            size_votes[es] = size_votes.get(es, 0) + 1

    if not size_votes:
        msg_warn("Could not determine descriptor table entry size")
        return 0

    entry_size = max(size_votes, key=size_votes.get)
    msg_info(f"Detected descriptor table entry size: {entry_size} bytes "
             f"(votes: {size_votes})")

    # ------------------------------------------------------------------
    # Step 4: Walk each table from its beginning to its end.
    # ------------------------------------------------------------------

    def _find_table_start(any_entry_ea, stride):
        """Walk backwards from a known entry to find the table start."""
        ea = any_entry_ea
        while True:
            prev_ea = ea - stride
            ptr = _read_qword_safe(prev_ea)
            if ptr is None or ptr == 0:
                break
            s = _read_cstring(ptr)
            if not s or not _is_plausible_field_name(s):
                break
            ea = prev_ea
        return ea

    def _is_plausible_field_name(s):
        """Check if a string looks like a WoW update field name."""
        if not s:
            return False
        # Common prefixes: m_, has, is, num, modded, current, override
        if s.startswith("m_"):
            return True
        if s.startswith(("has", "is", "num", "override", "current",
                         "modded", "bonus", "quest", "skill", "spell",
                         "aura", "known", "explored", "daily", "weekly",
                         "profession", "pvp", "honor", "arena", "craft",
                         "research", "rest", "self")):
            return True
        # Also accept CamelCase names that are at least 3 chars
        if len(s) >= 3 and s[0].isupper() and any(c.islower() for c in s):
            return True
        return False

    def _walk_table(start_ea, stride):
        """Walk a descriptor table from start, returning list of field dicts."""
        fields = []
        ea = start_ea
        max_fields = 2000  # safety limit

        while len(fields) < max_fields:
            name_ptr = _read_qword_safe(ea)
            if name_ptr is None or name_ptr == 0:
                break

            name = _read_cstring(name_ptr)
            if not name or not _is_plausible_field_name(name):
                break

            # Parse the remaining entry fields based on stride
            field_info = {"name": name, "ea": ea}

            if stride == 16:
                # {qword name_ptr, dword type_or_flags, dword offset_or_size}
                val1 = _read_dword_safe(ea + 8) or 0
                val2 = _read_dword_safe(ea + 12) or 0
                field_info["raw_type"] = val1
                field_info["raw_offset"] = val2

            elif stride == 20:
                # {qword name_ptr, dword type, dword offset, dword size}
                val1 = _read_dword_safe(ea + 8) or 0
                val2 = _read_dword_safe(ea + 12) or 0
                val3 = _read_dword_safe(ea + 16) or 0
                field_info["raw_type"] = val1
                field_info["raw_offset"] = val2
                field_info["raw_size"] = val3

            elif stride == 24:
                # {qword name_ptr, dword type, dword offset, dword size,
                #  dword flags}
                val1 = _read_dword_safe(ea + 8) or 0
                val2 = _read_dword_safe(ea + 12) or 0
                val3 = _read_dword_safe(ea + 16) or 0
                val4 = _read_dword_safe(ea + 20) or 0
                field_info["raw_type"] = val1
                field_info["raw_offset"] = val2
                field_info["raw_size"] = val3
                field_info["raw_flags"] = val4

            elif stride == 32:
                # Wider variant with possible padding or extra fields
                val1 = _read_dword_safe(ea + 8) or 0
                val2 = _read_dword_safe(ea + 12) or 0
                val3 = _read_dword_safe(ea + 16) or 0
                val4 = _read_dword_safe(ea + 20) or 0
                val5 = _read_dword_safe(ea + 24) or 0
                field_info["raw_type"] = val1
                field_info["raw_offset"] = val2
                field_info["raw_size"] = val3
                field_info["raw_flags"] = val4
                field_info["raw_extra"] = val5

            fields.append(field_info)
            ea += stride

        return fields

    # Group candidate entries into distinct tables.
    # Entries in the same table will be within stride*N of each other.
    sorted_candidates = sorted(candidate_table_eas)
    visited = set()
    tables = []  # list of (table_start_ea, fields_list)

    for cand_ea in sorted_candidates:
        if cand_ea in visited:
            continue

        table_start = _find_table_start(cand_ea, entry_size)
        if table_start in visited:
            continue

        fields = _walk_table(table_start, entry_size)
        if len(fields) < 2:
            continue

        # Mark all entry addresses as visited
        for i, f in enumerate(fields):
            visited.add(table_start + i * entry_size)

        tables.append((table_start, fields))

    msg_info(f"Discovered {len(tables)} descriptor tables")

    # ------------------------------------------------------------------
    # Step 5: Classify each table by object type using field signatures.
    # ------------------------------------------------------------------

    def _classify_table(fields):
        """Determine the object type of a descriptor table from its fields."""
        field_names = {f["name"] for f in fields}

        best_type = "UNKNOWN"
        best_score = 0

        for obj_type, sig_fields in _TYPE_SIGNATURES.items():
            overlap = field_names & sig_fields
            score = len(overlap)
            if score > best_score:
                best_score = score
                best_type = obj_type

        # Also check OBJECT_TYPE_CLASSES for class name strings near table
        if best_score == 0:
            # If no signature matches, try to infer from the first field
            first = fields[0]["name"] if fields else ""
            if "guid" in first.lower():
                best_type = "OBJECT"

        return best_type

    # ------------------------------------------------------------------
    # Step 6: Interpret raw type/offset/size values and insert into DB.
    # ------------------------------------------------------------------

    # Common type enum mapping (heuristic — varies by build)
    _RAW_TYPE_MAP = {
        0: "int32",
        1: "uint32",
        2: "int64",
        3: "uint64",
        4: "float",
        5: "bytes",
        6: "guid",
        7: "two_short",
    }

    _RAW_FLAGS_MAP = {
        0: "NONE",
        1: "PUBLIC",
        2: "PRIVATE",
        3: "OWNER",
        4: "UNK1",
        5: "UNK2",
        0x10: "URGENT",
        0x100: "PUBLIC",
    }

    for table_ea, fields in tables:
        obj_type = _classify_table(fields)
        msg_info(f"Table at {ea_str(table_ea)}: {len(fields)} fields, "
                 f"type={obj_type}")

        # Determine if offsets are sequential (auto-increment) or explicit
        # by checking if raw_offset values are monotonically increasing
        offsets = [f.get("raw_offset", 0) for f in fields]
        is_sequential = all(
            offsets[i] <= offsets[i + 1]
            for i in range(len(offsets) - 1)
        ) if len(offsets) > 1 else True

        for idx, field in enumerate(fields):
            fname = field["name"]
            raw_type = field.get("raw_type", 0)
            raw_offset = field.get("raw_offset", idx * 4)
            raw_size = field.get("raw_size", 0)
            raw_flags = field.get("raw_flags", 0)

            # Map raw type to string
            ftype = _RAW_TYPE_MAP.get(raw_type, f"unk_{raw_type}")

            # Infer size from type if not explicitly provided
            if raw_size == 0:
                if ftype in ("guid",):
                    fsize = 16
                elif ftype in ("int64", "uint64"):
                    fsize = 8
                elif ftype in ("float", "int32", "uint32", "two_short"):
                    fsize = 4
                elif ftype == "bytes":
                    fsize = 4
                else:
                    fsize = 4
            else:
                fsize = raw_size

            # If offsets are not sequential, use them directly;
            # otherwise use the index-based offset.
            if is_sequential and raw_offset > 0:
                foffset = raw_offset
            else:
                foffset = idx * fsize

            # Map flags
            fflags = _RAW_FLAGS_MAP.get(raw_flags, "PUBLIC")

            # Detect arrays: consecutive fields with same base name + index
            array_count = 1
            is_dynamic = 0
            if "dynamic" in ftype.lower() or "dynamic" in fname.lower():
                is_dynamic = 1

            db.execute(
                """INSERT OR REPLACE INTO update_fields
                   (object_type, field_name, field_offset, field_size,
                    field_type, field_flags, array_count, is_dynamic)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (obj_type, fname, foffset, fsize, ftype, fflags,
                 array_count, is_dynamic),
            )
            count += 1

    db.commit()
    msg_info(f"Scan complete: {count} update fields from "
             f"{len(tables)} descriptor tables")
    return count


def _scan_rdata_for_descriptor_patterns(
        session, data_segs, read_cstring, read_qword, read_dword,
        read_word, ea_in_segs, type_signatures):
    """Fallback scanner: walk .rdata looking for pointer-to-string arrays
    where strings match the ``m_`` prefix pattern of WoW update fields.

    This is used when idautils.Strings() does not contain the seed fields
    (e.g. because IDA has not yet created string items for them).
    """
    db = session.db
    count = 0

    msg_info("Fallback: scanning .rdata for m_ string pointer arrays...")

    for seg, seg_name in data_segs:
        if seg_name not in (".rdata",):
            continue

        ea = seg.start_ea
        end = seg.end_ea
        msg_info(f"  Scanning {seg_name} "
                 f"({ea_str(ea)} - {ea_str(end)}, "
                 f"{(end - ea) // 1024}KB)")

        # Walk qword-aligned addresses looking for sequences of valid
        # string pointers that all resolve to m_-prefixed names.
        scan_ea = ea
        while scan_ea + 16 <= end:
            ptr = read_qword(scan_ea)
            if ptr is None or ptr == 0:
                scan_ea += 8
                continue

            s = read_cstring(ptr)
            if not s or not s.startswith("m_"):
                scan_ea += 8
                continue

            # Found a potential first entry.  Probe strides.
            best_stride = None
            best_count = 0

            for stride in (16, 20, 24, 32):
                n = 0
                probe_ea = scan_ea
                while probe_ea + stride <= end:
                    p = read_qword(probe_ea)
                    if p is None or p == 0:
                        break
                    ps = read_cstring(p)
                    if not ps or len(ps) < 2:
                        break
                    # Accept m_ prefixed or other plausible names
                    if not (ps.startswith("m_") or
                            (len(ps) >= 3 and ps[0].isupper()
                             and any(c.islower() for c in ps))):
                        break
                    n += 1
                    probe_ea += stride

                if n > best_count:
                    best_count = n
                    best_stride = stride

            if best_count < 3 or best_stride is None:
                scan_ea += 8
                continue

            # Parse this table
            msg_info(f"  Found candidate table at {ea_str(scan_ea)}: "
                     f"{best_count} fields, stride={best_stride}")

            field_names_in_table = set()
            table_fields = []
            parse_ea = scan_ea

            for idx in range(best_count):
                name_ptr = read_qword(parse_ea)
                fname = read_cstring(name_ptr) if name_ptr else None
                if not fname:
                    break

                raw_type = read_dword(parse_ea + 8) or 0
                raw_offset = read_dword(parse_ea + 12) or 0
                raw_size = 0
                raw_flags = 0
                if best_stride >= 20:
                    raw_size = read_dword(parse_ea + 16) or 0
                if best_stride >= 24:
                    raw_flags = read_dword(parse_ea + 20) or 0

                field_names_in_table.add(fname)
                table_fields.append({
                    "name": fname,
                    "raw_type": raw_type,
                    "raw_offset": raw_offset,
                    "raw_size": raw_size,
                    "raw_flags": raw_flags,
                })
                parse_ea += best_stride

            # Classify object type
            best_type = "UNKNOWN"
            best_score = 0
            for obj_type, sig_fields in type_signatures.items():
                overlap = field_names_in_table & sig_fields
                if len(overlap) > best_score:
                    best_score = len(overlap)
                    best_type = obj_type

            _RAW_TYPE_MAP = {
                0: "int32", 1: "uint32", 2: "int64", 3: "uint64",
                4: "float", 5: "bytes", 6: "guid", 7: "two_short",
            }
            _RAW_FLAGS_MAP = {
                0: "NONE", 1: "PUBLIC", 2: "PRIVATE", 3: "OWNER",
                0x10: "URGENT", 0x100: "PUBLIC",
            }

            for idx, f in enumerate(table_fields):
                ftype = _RAW_TYPE_MAP.get(f["raw_type"], f"unk_{f['raw_type']}")
                fsize = f["raw_size"] if f["raw_size"] > 0 else 4
                foffset = f["raw_offset"] if f["raw_offset"] > 0 else idx * fsize
                fflags = _RAW_FLAGS_MAP.get(f["raw_flags"], "PUBLIC")

                db.execute(
                    """INSERT OR REPLACE INTO update_fields
                       (object_type, field_name, field_offset, field_size,
                        field_type, field_flags, array_count, is_dynamic)
                       VALUES (?, ?, ?, ?, ?, ?, 1, 0)""",
                    (best_type, f["name"], foffset, fsize, ftype, fflags),
                )
                count += 1

            # Advance past this table
            scan_ea = parse_ea

    db.commit()
    if count > 0:
        msg_info(f"Fallback scan: discovered {count} update fields")
    else:
        msg_warn("Fallback scan found no descriptor tables")
    return count


def generate_update_fields_header(session, object_type):
    """Generate TrinityCore-style UpdateFields.h entries for an object type.

    Example output:
        struct ObjectData : public HasChangesMask<4>
        {
            UpdateField<int32, 0, 1> EntryID;
            UpdateField<int32, 0, 2> DynamicFlags;
            ...
        };
    """
    db = session.db
    rows = db.fetchall(
        """SELECT * FROM update_fields
           WHERE object_type = ?
           ORDER BY field_offset""",
        (object_type,),
    )

    if not rows:
        return f"// {object_type}: no field data available\n"

    mask_bits = max(1, len(rows) // 32 + 1)
    lines = [
        f"struct {object_type}Data : public HasChangesMask<{mask_bits}>",
        "{",
    ]

    for i, row in enumerate(rows):
        tc_type = TC_UF_TYPES.get(row["field_type"], "UF_TYPE_INT")
        fname = row["field_name"]

        if row["array_count"] and row["array_count"] > 1:
            lines.append(f"    UpdateFieldArray<{tc_type}, {i}, "
                         f"{row['array_count']}> {fname};")
        elif row["is_dynamic"]:
            lines.append(f"    DynamicUpdateField<{tc_type}, 0, {i}> {fname};")
        else:
            lines.append(f"    UpdateField<{tc_type}, 0, {i}> {fname};")

    lines.append("};")
    return "\n".join(lines) + "\n"
