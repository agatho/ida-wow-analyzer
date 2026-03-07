"""
DB2 Metadata Deep Analyzer
Parses DB2Meta structures from the WoW binary to extract complete
field type information for TrinityCore LoadInfo generation.
"""

import json
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


# DB2Meta field type constants (from WoW binary)
DB2_FIELD_TYPE_INT8 = 0
DB2_FIELD_TYPE_INT16 = 1
DB2_FIELD_TYPE_INT32 = 2
DB2_FIELD_TYPE_INT64 = 3
DB2_FIELD_TYPE_FLOAT = 4
DB2_FIELD_TYPE_STRING = 5

FIELD_TYPE_NAMES = {
    DB2_FIELD_TYPE_INT8: "int8",
    DB2_FIELD_TYPE_INT16: "int16",
    DB2_FIELD_TYPE_INT32: "int32",
    DB2_FIELD_TYPE_INT64: "int64",
    DB2_FIELD_TYPE_FLOAT: "float",
    DB2_FIELD_TYPE_STRING: "string",
}

# TrinityCore FMeta type chars
TC_TYPE_CHARS = {
    DB2_FIELD_TYPE_INT8: "b",
    DB2_FIELD_TYPE_INT16: "h",
    DB2_FIELD_TYPE_INT32: "i",
    DB2_FIELD_TYPE_INT64: "l",
    DB2_FIELD_TYPE_FLOAT: "f",
    DB2_FIELD_TYPE_STRING: "s",
}


def analyze_db2_metadata(session):
    """Scan for DB2Meta structures in the binary and extract field metadata.

    DB2Meta structures are typically referenced by string names in .rdata.
    We locate them by finding functions that load DB2 tables and extracting
    the metadata pointer from the initialization calls.
    """
    db = session.db
    cfg = session.cfg

    # Strategy: Find all named DB2 metadata addresses from existing extractions
    extraction_dir = cfg.get("builds", str(cfg.build_number), "extraction_dir")
    if not extraction_dir:
        msg_warn("No extraction directory configured for current build")
        return _scan_for_db2_meta_patterns(session)

    import os
    meta_file = os.path.join(extraction_dir,
                             f"wow_db2_metadata_{cfg.build_number}.json")
    if not os.path.isfile(meta_file):
        msg_warn(f"DB2 metadata file not found: {meta_file}")
        return _scan_for_db2_meta_patterns(session)

    return _import_db2_metadata_json(session, meta_file)


def _import_db2_metadata_json(session, meta_file):
    """Import DB2 metadata from the existing extraction JSON."""
    db = session.db
    cfg = session.cfg

    msg_info(f"Importing DB2 metadata from {meta_file}")
    with open(meta_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    tables = data.get("tables", [])
    count = 0

    for table in tables:
        name = table.get("name", "")
        if not name:
            continue

        meta_rva = table.get("meta_rva")
        meta_ea = None
        if meta_rva:
            if isinstance(meta_rva, str):
                meta_rva = int(meta_rva, 16)
            meta_ea = cfg.rva_to_ea(meta_rva)

        db.upsert_db2_table(
            name=name,
            file_data_id=table.get("file_data_id"),
            layout_hash=table.get("layout_hash", 0),
            meta_rva=meta_rva,
            meta_ea=meta_ea,
            field_count=table.get("field_count", 0),
            record_size=table.get("record_size", 0),
            index_field=table.get("index_field", -1),
        )
        count += 1

    db.commit()
    msg_info(f"Imported {count} DB2 table definitions")
    return count


def _scan_for_db2_meta_patterns(session):
    """Scan the binary for DB2Meta structures using pattern matching.

    Discovers DB2Meta structures by:
      1. Scanning all strings for DB2 table name candidates (PascalCase names
         and strings ending in ".db2").
      2. Following xrefs from those strings into code to find initialization
         call sites where a meta pointer and the name string are loaded
         together.
      3. Parsing the candidate meta struct with ``parse_db2meta_at`` and
         storing validated results via ``db.upsert_db2_table``.
    """
    db = session.db
    cfg = session.cfg
    count = 0
    start_time = time.time()

    msg_info("DB2Meta pattern scan: beginning binary analysis...")

    # ------------------------------------------------------------------
    # Phase 1 — Collect DB2 table name strings
    # ------------------------------------------------------------------
    # A DB2 table name is a PascalCase identifier such as "SpellName",
    # "AreaTable", "ChrRaces".  We also accept strings ending with
    # ".db2" (e.g. "SpellName.db2") and strip the extension.
    # ------------------------------------------------------------------

    # Known DB2 table names to boost confidence — these will always be
    # searched even if the heuristic skips them.
    KNOWN_DB2_NAMES = {
        "Achievement", "Achievement_Category", "AnimKit", "AreaTable",
        "AreaTrigger", "Armor", "AzeriteEssence", "AzeriteEssencePower",
        "AzeriteItem", "AzeritePower", "BankBagSlotPrices", "BarberShopStyle",
        "BattlePetBreedQuality", "BattlePetBreedState", "BattlePetSpecies",
        "BattlePetSpeciesState", "BattlemasterList", "ChrClasses",
        "ChrClassesXPowerTypes", "ChrCustomizationChoice",
        "ChrCustomizationOption", "ChrCustomizationReq", "ChrRaces",
        "ChrSpecialization", "CinematicCamera", "CinematicSequences",
        "ContentTuning", "Creature", "CreatureDisplayInfo",
        "CreatureDisplayInfoExtra", "CreatureFamily", "CreatureModelData",
        "CreatureType", "Criteria", "CriteriaTree", "CurrencyContainer",
        "CurrencyTypes", "Curve", "CurvePoint", "DestructibleModelData",
        "Difficulty", "DungeonEncounter", "DurabilityQuality",
        "EmotesText", "EmotesTextSound", "ExpectedStat",
        "ExpectedStatMod", "Faction", "FactionTemplate",
        "FriendshipRepReaction", "FriendshipReputation",
        "GameObjectDisplayInfo", "GameObjects",
        "GarrAbility", "GarrBuilding", "GarrBuildingPlotInst",
        "GarrClassSpec", "GarrFollower", "GarrFollowerXAbility",
        "GarrMission", "GarrPlot", "GarrPlotBuilding", "GarrSiteLevelPlotInst",
        "GemProperties", "GlobalCurve", "GlyphBindableSpell",
        "GlyphProperties", "GlyphRequiredSpec",
        "GtBattlePetTypeDamageMod", "GtCombatRatings",
        "GtHpPerSta", "GtSpellScaling",
        "Heirloom", "ImportPriceArmor", "ImportPriceQuality",
        "ImportPriceShield", "ImportPriceWeapon",
        "Item", "ItemAppearance", "ItemArmorQuality", "ItemArmorShield",
        "ItemArmorTotal", "ItemBagFamily", "ItemBonus", "ItemBonusListLevelDelta",
        "ItemBonusTreeNode", "ItemChildEquipment", "ItemClass",
        "ItemCurrencyCost", "ItemDamageAmmo", "ItemDamageOneHand",
        "ItemDamageOneHandCaster", "ItemDamageTwoHand",
        "ItemDamageTwoHandCaster", "ItemDisenchantLoot",
        "ItemEffect", "ItemExtendedCost", "ItemLevelSelector",
        "ItemLimitCategory", "ItemModifiedAppearance",
        "ItemNameDescription", "ItemPriceBase", "ItemSearchName",
        "ItemSet", "ItemSetSpell", "ItemSparse", "ItemSpec",
        "ItemSpecOverride", "ItemXBonusTree",
        "JournalEncounter", "JournalEncounterSection",
        "JournalInstance", "JournalTier",
        "KeystoneAffix", "LanguageWords", "Languages",
        "LFGDungeons", "Light", "LiquidType", "Lock",
        "MailTemplate", "Map", "MapDifficulty", "ModifierTree",
        "Mount", "MountCapability", "MountTypeXCapability",
        "MountXDisplay", "Movie",
        "NameGen", "NamesProfanity", "NamesReserved",
        "NumTalentsAtLevel",
        "PhaseXPhaseGroup", "PlayerCondition", "PowerDisplay",
        "PowerType", "PrestigeLevelInfo", "PvpDifficulty",
        "PvpItem", "PvpTalent", "PvpTalentSlotUnlock",
        "QuestFactionReward", "QuestInfo", "QuestLineXQuest",
        "QuestMoneyReward", "QuestPackageItem", "QuestSort",
        "QuestV2", "QuestXP",
        "RandPropPoints", "RewardPack", "RewardPackXCurrencyType",
        "RewardPackXItem", "Scenario", "ScenarioStep",
        "ScalingStatDistribution", "SkillLine", "SkillLineAbility",
        "SkillRaceClassInfo", "SoundKit", "SpecSetMember",
        "Spell", "SpellAuraOptions", "SpellAuraRestrictions",
        "SpellCastTimes", "SpellCastingRequirements", "SpellCategories",
        "SpellCategory", "SpellClassOptions", "SpellCooldowns",
        "SpellDuration", "SpellEffect", "SpellEquippedItems",
        "SpellFocusObject", "SpellInterrupts", "SpellItemEnchantment",
        "SpellItemEnchantmentCondition", "SpellLabel", "SpellLearnSpell",
        "SpellLevels", "SpellMisc", "SpellName", "SpellPower",
        "SpellPowerDifficulty", "SpellProcsPerMinute",
        "SpellProcsPerMinuteMod", "SpellRadius", "SpellRange",
        "SpellReagents", "SpellReagentsCurrency", "SpellScaling",
        "SpellShapeshift", "SpellShapeshiftForm", "SpellTargetRestrictions",
        "SpellTotems", "SpellVisual", "SpellVisualKitModelAttach",
        "SpellXSpellVisual",
        "SummonProperties",
        "Talent", "TalentTab", "TaxiNodes", "TaxiPath", "TaxiPathNode",
        "TotemCategory", "Toy", "TransmogHoliday", "TransmogSet",
        "TransmogSetGroup", "TransmogSetItem", "TransportAnimation",
        "TransportRotation",
        "UiMap", "UiMapAssignment", "UiMapLink", "UiMapXMapArt",
        "UnitPowerBar", "Vehicle", "VehicleSeat",
        "WMOAreaTable", "WorldEffect", "WorldMapOverlay",
        "WorldSafeLocs", "WorldStateExpression",
    }

    # Regex for PascalCase DB2-style names: starts uppercase, 3-60 chars,
    # letters/digits/underscores only, at least one lowercase letter.
    _DB2_NAME_RE = re.compile(
        r"^[A-Z][A-Za-z0-9_]{2,59}$"
    )

    db2_name_strings = {}  # name -> string_ea

    msg_info("  Phase 1: Scanning strings for DB2 table names...")
    string_count = 0

    for s in idautils.Strings():
        string_count += 1
        val = str(s)
        if not val:
            continue

        db2_name = None

        # Check for ".db2" suffix
        if val.endswith(".db2"):
            db2_name = val[:-4]
        # Check against known names (exact match)
        elif val in KNOWN_DB2_NAMES:
            db2_name = val
        # Heuristic: PascalCase, reasonable length, no spaces/slashes/dots
        elif (_DB2_NAME_RE.match(val)
              and any(c.islower() for c in val)
              and "/" not in val
              and "\\" not in val
              and " " not in val
              and "." not in val):
            # Additional filter: reject strings that look like error messages,
            # file paths, or other non-DB2 identifiers.
            # DB2 names don't usually start with common prefixes like "Get",
            # "Set", "Is", "Has", "Can", "On", "Do" unless they're known.
            if val not in KNOWN_DB2_NAMES:
                first_word_prefixes = (
                    "Get", "Set", "Is", "Has", "Can", "On", "Do", "Try",
                    "Send", "Handle", "Process", "Create", "Delete", "Update",
                    "Init", "Load", "Save", "Parse", "Build", "Find",
                    "Check", "Validate", "Reset", "Clear", "Add", "Remove",
                    "Enable", "Disable", "Show", "Hide", "Open", "Close",
                )
                if any(val.startswith(p) and len(val) > len(p) and val[len(p)].isupper()
                       for p in first_word_prefixes):
                    continue
            db2_name = val

        if db2_name and db2_name not in db2_name_strings:
            db2_name_strings[db2_name] = s.ea

        if string_count % 100000 == 0:
            msg(f"    Scanned {string_count} strings, "
                f"{len(db2_name_strings)} DB2 name candidates...")

    msg_info(f"  Phase 1 complete: {len(db2_name_strings)} DB2 name candidates "
             f"from {string_count} strings")

    # ------------------------------------------------------------------
    # Phase 2 — Follow xrefs from name strings to find meta struct ptrs
    # ------------------------------------------------------------------
    # The WoW client initializes DB2 stores roughly like:
    #     lea  rdx, aSpellName          ; "SpellName"
    #     lea  rcx, DB2Storage_SpellName
    #     lea  r8,  SpellNameMeta        ; <-- the meta struct
    #     call DB2StorageBase::Load
    #
    # We look for data xrefs TO the string that land in .rdata (a pointer
    # to the string inside an initialization record), and also code xrefs
    # where the string address is loaded via LEA into a register.  For
    # each xref site we scan the surrounding area for pointers into
    # .rdata that could be the meta struct.
    # ------------------------------------------------------------------

    msg_info("  Phase 2: Following xrefs to locate DB2Meta structs...")

    # Pre-compute .rdata segment bounds for fast membership checks.
    rdata_ranges = []
    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        if seg_name in (".rdata", ".rodata", "__const", "__DATA.__const"):
            rdata_ranges.append((seg.start_ea, seg.end_ea))

    def _in_rdata(ea):
        for start, end in rdata_ranges:
            if start <= ea < end:
                return True
        return False

    # Collect text segment bounds for code checks
    text_ranges = []
    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        if seg_name in (".text", "__text", "__TEXT.__text"):
            text_ranges.append((seg.start_ea, seg.end_ea))

    def _in_text(ea):
        for start, end in text_ranges:
            if start <= ea < end:
                return True
        return False

    ptr_size = 8  # x86_64

    discovered = {}  # db2_name -> {"meta_ea": ..., "source": ...}
    xref_count = 0

    for db2_name, string_ea in db2_name_strings.items():
        # Gather all xrefs to this string
        xrefs_to_string = []
        for xref in idautils.XrefsTo(string_ea, 0):
            xrefs_to_string.append(xref.frm)
        xref_count += len(xrefs_to_string)

        if not xrefs_to_string:
            continue

        meta_ea = _find_meta_from_xrefs(
            string_ea, xrefs_to_string, cfg, _in_rdata, _in_text, ptr_size
        )
        if meta_ea is not None:
            discovered[db2_name] = {"meta_ea": meta_ea, "source": "xref"}

    msg_info(f"  Phase 2 complete: {len(discovered)} meta structs located "
             f"from {xref_count} xrefs")

    # ------------------------------------------------------------------
    # Phase 3 — Scan .rdata for adjacent (name_ptr, meta_ptr) pairs
    # ------------------------------------------------------------------
    # Some builds use static initialization records in .rdata that
    # contain a pointer to the name string followed by (or near) a
    # pointer to the meta struct.  We scan .rdata for pointers to our
    # known name strings and then check nearby qwords for meta pointers.
    # ------------------------------------------------------------------

    msg_info("  Phase 3: Scanning .rdata for name/meta pointer pairs...")
    phase3_found = 0

    # Build reverse map: string_ea -> db2_name (only for names not yet found)
    string_ea_to_name = {}
    for db2_name, str_ea in db2_name_strings.items():
        if db2_name not in discovered:
            string_ea_to_name[str_ea] = db2_name

    if string_ea_to_name:
        for rdata_start, rdata_end in rdata_ranges:
            ea = rdata_start
            while ea < rdata_end - ptr_size:
                qval = ida_bytes.get_qword(ea)
                if qval in string_ea_to_name:
                    db2_name = string_ea_to_name[qval]
                    # Check surrounding qwords for a meta pointer
                    meta_ea = _probe_nearby_for_meta(
                        ea, ptr_size, cfg, _in_rdata
                    )
                    if meta_ea is not None and db2_name not in discovered:
                        discovered[db2_name] = {
                            "meta_ea": meta_ea,
                            "source": "rdata_pair",
                        }
                        phase3_found += 1
                ea += ptr_size

    msg_info(f"  Phase 3 complete: {phase3_found} additional meta structs")

    # ------------------------------------------------------------------
    # Phase 4 — Parse and store all discovered meta structs
    # ------------------------------------------------------------------

    msg_info("  Phase 4: Parsing and storing DB2Meta structures...")

    for db2_name, info in discovered.items():
        meta_ea = info["meta_ea"]
        parsed = parse_db2meta_at(meta_ea, cfg)
        if parsed is None:
            continue

        field_count = parsed.get("field_count", 0)
        record_size = parsed.get("record_size", 0)
        index_field = parsed.get("index_field", -1)

        # Sanity: record_size should be reasonable (4..10000)
        if record_size < 4 or record_size > 10000:
            continue

        meta_rva = cfg.ea_to_rva(meta_ea)

        db.upsert_db2_table(
            name=db2_name,
            meta_ea=meta_ea,
            meta_rva=meta_rva,
            field_count=field_count,
            record_size=record_size,
            index_field=index_field,
        )
        count += 1

    db.commit()
    elapsed = time.time() - start_time
    msg_info(f"DB2Meta pattern scan complete: {count} tables discovered "
             f"in {elapsed:.1f}s")
    return count


def _find_meta_from_xrefs(string_ea, xrefs, cfg, in_rdata, in_text, ptr_size):
    """Given xrefs to a DB2 name string, try to find the associated meta struct.

    For each code xref (inside .text), we scan the surrounding instructions
    for LEA instructions that load a .rdata pointer.  That pointer is then
    tested as a candidate DB2Meta via ``parse_db2meta_at``.

    For data xrefs (inside .rdata), we check nearby qwords for meta pointers.
    """
    candidates = []

    for xref_ea in xrefs:
        if in_text(xref_ea):
            # Code xref — scan a window of bytes around the xref for
            # RIP-relative LEA patterns that reference .rdata addresses.
            # x86_64 LEA Rxx, [rip+disp32] is 7 bytes: 48/4C 8D xx dd dd dd dd
            # We look in a generous +-96 byte window.
            scan_start = max(xref_ea - 96, 0)
            scan_end = xref_ea + 96
            ea = scan_start
            while ea < scan_end:
                # Quick check for LEA opcode prefix (REX.W + 0x8D)
                b0 = ida_bytes.get_byte(ea)
                b1 = ida_bytes.get_byte(ea + 1)
                if b1 == 0x8D and b0 in (0x48, 0x4C):
                    # modrm byte
                    modrm = ida_bytes.get_byte(ea + 2)
                    mod = (modrm >> 6) & 3
                    rm = modrm & 7
                    if mod == 0 and rm == 5:
                        # RIP-relative: disp32 at ea+3
                        disp = struct.unpack_from(
                            "<i",
                            ida_bytes.get_bytes(ea + 3, 4)
                        )[0]
                        target = (ea + 7) + disp  # RIP = ea + 7 (instr len)
                        if in_rdata(target) and target != string_ea:
                            parsed = parse_db2meta_at(target, cfg)
                            if parsed is not None:
                                candidates.append(target)
                    ea += 3  # skip past this instruction start
                else:
                    ea += 1
                continue

        elif in_rdata(xref_ea):
            # Data xref — check nearby qwords
            meta_ea = _probe_nearby_for_meta(
                xref_ea, ptr_size, cfg, in_rdata
            )
            if meta_ea is not None:
                candidates.append(meta_ea)

    # Return the most common candidate (if any)
    if not candidates:
        return None
    # De-duplicate and prefer most frequent
    from collections import Counter
    counts = Counter(candidates)
    return counts.most_common(1)[0][0]


def _probe_nearby_for_meta(base_ea, ptr_size, cfg, in_rdata):
    """Check qwords near *base_ea* in .rdata for a valid DB2Meta pointer.

    We check offsets -4*ptr_size .. +4*ptr_size (excluding 0) relative to
    base_ea.  Each qword is dereferenced and tested as a meta struct.
    """
    for offset in (ptr_size, -ptr_size,
                   2 * ptr_size, -2 * ptr_size,
                   3 * ptr_size, -3 * ptr_size,
                   4 * ptr_size, -4 * ptr_size):
        candidate_ea = base_ea + offset
        qval = ida_bytes.get_qword(candidate_ea)
        if in_rdata(qval):
            parsed = parse_db2meta_at(qval, cfg)
            if parsed is not None:
                return qval
        # Also try: the qword itself IS the meta address (inline struct, not pointer)
        if in_rdata(candidate_ea):
            parsed = parse_db2meta_at(candidate_ea, cfg)
            if parsed is not None:
                return candidate_ea
    return None


def parse_db2meta_at(ea, cfg):
    """Parse a DB2Meta structure at the given address.

    DB2Meta layout (approximate, may vary by build):
        uint32 fieldCount
        uint32 recordSize
        uint32 hotfixFieldCount
        uint32 indexField
        uint32 parentIndexField
        uint32 fieldOffsetsOffs  (relative pointer to field offsets array)
        uint32 fieldTypesOffs    (relative pointer to field types array)
        uint32 arraySizesOffs    (relative pointer to array sizes)
        uint32 flagsOffs         (relative pointer to signed flags)
    """
    fields = []

    try:
        field_count = ida_bytes.get_dword(ea)
        if field_count == 0 or field_count > 500:
            return None

        record_size = ida_bytes.get_dword(ea + 4)
        index_field = ida_bytes.get_dword(ea + 16)

        # This is a simplified parser — the exact offsets depend on the build
        # For a full implementation, we need to reverse the DB2Meta struct layout
        # for the specific build being analyzed

        return {
            "field_count": field_count,
            "record_size": record_size,
            "index_field": index_field,
            "fields": fields,
        }
    except Exception:
        return None


def generate_loadinfo(table_name, fields):
    """Generate TrinityCore LoadInfo C++ code for a DB2 table.

    Example output:
        static char const* const types = "iisfi";
        static uint8 const arraySizes[5] = {1, 1, 1, 1, 1};
    """
    if not fields:
        return f"// {table_name}: no field data available"

    type_chars = []
    array_sizes = []
    for f in fields:
        ftype = f.get("type", DB2_FIELD_TYPE_INT32)
        type_chars.append(TC_TYPE_CHARS.get(ftype, "i"))
        array_sizes.append(str(f.get("array_size", 1)))

    types_str = "".join(type_chars)
    arrays_str = ", ".join(array_sizes)

    return (
        f'// LoadInfo for {table_name}\n'
        f'static char const* const types = "{types_str}";\n'
        f'static uint8 const arraySizes[{len(fields)}] = {{{arrays_str}}};\n'
    )
