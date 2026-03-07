"""
Cross-Build Auto-Migration Pipeline

When Blizzard ships a new WoW build, this analyzer automatically:
  1. Loads the previous build's knowledge DB (SQLite)
  2. Matches functions across builds using multiple strategies
  3. Diffs matched pairs semantically
  4. Assesses impact and priority of each change
  5. Generates TrinityCore migration patches
  6. Produces a comprehensive migration report

Entry points:
  generate_migration(session, old_db_path=None) -> int   # returns count of migration items
  get_migration_report(session)                          # retrieve stored results

Storage: kv_store key "cross_build_migration"
"""

import json
import re
import time
import os
import sqlite3
import difflib
import hashlib
from collections import defaultdict, OrderedDict

import ida_funcs
import ida_name
import ida_bytes
import idautils
import idaapi

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KV_KEY = "cross_build_migration"
KV_PREV_DB_PATH = "previous_build_db_path"

# Match strategy names and their base confidence scores
STRATEGY_EXACT_NAME       = "exact_name"
STRATEGY_OPCODE_HANDLER   = "opcode_handler"
STRATEGY_STRING_REF       = "string_ref"
STRATEGY_SIGNATURE        = "signature"
STRATEGY_NGRAM_SIMILARITY = "ngram_similarity"
STRATEGY_CALL_GRAPH       = "call_graph"
STRATEGY_SIZE_BB          = "size_bb"

STRATEGY_CONFIDENCE = {
    STRATEGY_EXACT_NAME:       100,
    STRATEGY_OPCODE_HANDLER:   95,
    STRATEGY_STRING_REF:       90,
    STRATEGY_SIGNATURE:        85,
    STRATEGY_NGRAM_SIMILARITY: 78,   # midpoint of 70-85 range
    STRATEGY_CALL_GRAPH:       65,
    STRATEGY_SIZE_BB:          50,
}

# Semantic diff change types
CHANGE_ADDED_VALIDATION    = "ADDED_VALIDATION"
CHANGE_REMOVED_VALIDATION  = "REMOVED_VALIDATION"
CHANGE_ADDED_LOGIC         = "ADDED_LOGIC"
CHANGE_REMOVED_LOGIC       = "REMOVED_LOGIC"
CHANGE_CHANGED_CONSTANT    = "CHANGED_CONSTANT"
CHANGE_CHANGED_ENUM_VALUE  = "CHANGED_ENUM_VALUE"
CHANGE_ADDED_PACKET_FIELD  = "ADDED_PACKET_FIELD"
CHANGE_REMOVED_PACKET_FIELD = "REMOVED_PACKET_FIELD"
CHANGE_RESTRUCTURED        = "RESTRUCTURED"
CHANGE_UNCHANGED           = "UNCHANGED"

# Impact priorities
PRIORITY_CRITICAL = "CRITICAL"
PRIORITY_HIGH     = "HIGH"
PRIORITY_MEDIUM   = "MEDIUM"
PRIORITY_LOW      = "LOW"

# N-gram similarity threshold for function matching
NGRAM_JACCARD_THRESHOLD = 0.70

# Signature comparison: first N bytes (ignoring relocations)
SIGNATURE_BYTES_COUNT = 32

# Structural diff threshold: ratio above which we call it RESTRUCTURED
RESTRUCTURED_THRESHOLD = 0.50

# Maximum number of functions to attempt decompilation on
MAX_DECOMP_ATTEMPTS = 3000

# Progress reporting interval
PROGRESS_INTERVAL = 100

# System classification from opcode names
_SYSTEM_PREFIXES = OrderedDict([
    ("HOUSING",       "housing"),
    ("NEIGHBORHOOD",  "neighborhood"),
    ("GARRISON",      "garrison"),
    ("QUEST",         "quest"),
    ("GUILD",         "guild"),
    ("AUCTION",       "auction"),
    ("ACHIEVEMENT",   "achievement"),
    ("PET_BATTLE",    "pet_battle"),
    ("BATTLE_PET",    "pet_battle"),
    ("BATTLEGROUND",  "pvp"),
    ("BATTLEFIELD",   "pvp"),
    ("ARENA",         "pvp"),
    ("MYTHIC_PLUS",   "mythic_plus"),
    ("CHALLENGE",     "mythic_plus"),
    ("DELVES",        "delves"),
    ("CLUB",          "social"),
    ("SOCIAL",        "social"),
    ("CHAT",          "social"),
    ("VOICE",         "social"),
    ("CALENDAR",      "calendar"),
    ("EQUIPMENT",     "inventory"),
    ("ITEM",          "inventory"),
    ("LOOT",          "loot"),
    ("SPELL",         "combat"),
    ("CAST",          "combat"),
    ("ATTACK",        "combat"),
    ("AURA",          "combat"),
    ("MOVE",          "movement"),
    ("CHARACTER",     "character"),
    ("CHAR",          "character"),
    ("TALENT",        "talent"),
    ("TRADE_SKILL",   "profession"),
    ("CRAFT",         "profession"),
    ("LFG",           "lfg"),
    ("TAXI",          "travel"),
    ("VEHICLE",       "vehicle"),
    ("PET",           "pet"),
    ("NPC",           "npc"),
    ("TRAINER",       "npc"),
    ("GOSSIP",        "npc"),
    ("MAIL",          "mail"),
    ("WARBAND",       "warband"),
    ("ACCOUNT",       "account"),
    ("TOKEN",         "token"),
    ("COLLECTION",    "collection"),
    ("TRANSMOG",      "collection"),
])

# Map of TC opcode name prefix -> likely source file paths
_TC_FILE_MAP = {
    "housing":       ["src/server/game/Handlers/HousingHandler.cpp",
                      "src/server/game/Housing/Housing.cpp"],
    "neighborhood":  ["src/server/game/Handlers/NeighborhoodHandler.cpp",
                      "src/server/game/Housing/Neighborhood.cpp"],
    "quest":         ["src/server/game/Handlers/QuestHandler.cpp"],
    "guild":         ["src/server/game/Handlers/GuildHandler.cpp"],
    "auction":       ["src/server/game/Handlers/AuctionHouseHandler.cpp"],
    "achievement":   ["src/server/game/Handlers/AchievementHandler.cpp"],
    "pet_battle":    ["src/server/game/Handlers/PetBattleHandler.cpp"],
    "pvp":           ["src/server/game/Handlers/BattleGroundHandler.cpp"],
    "mythic_plus":   ["src/server/game/Handlers/MythicPlusHandler.cpp"],
    "delves":        ["src/server/game/Handlers/DelvesHandler.cpp"],
    "social":        ["src/server/game/Handlers/SocialHandler.cpp",
                      "src/server/game/Handlers/ChatHandler.cpp"],
    "inventory":     ["src/server/game/Handlers/ItemHandler.cpp"],
    "loot":          ["src/server/game/Handlers/LootHandler.cpp"],
    "combat":        ["src/server/game/Handlers/SpellHandler.cpp",
                      "src/server/game/Handlers/CombatHandler.cpp"],
    "movement":      ["src/server/game/Handlers/MovementHandler.cpp"],
    "character":     ["src/server/game/Handlers/CharacterHandler.cpp"],
    "talent":        ["src/server/game/Handlers/TalentHandler.cpp"],
    "profession":    ["src/server/game/Handlers/TradeSkillHandler.cpp"],
    "lfg":           ["src/server/game/Handlers/LFGHandler.cpp"],
    "travel":        ["src/server/game/Handlers/TaxiHandler.cpp"],
    "vehicle":       ["src/server/game/Handlers/VehicleHandler.cpp"],
    "pet":           ["src/server/game/Handlers/PetHandler.cpp"],
    "npc":           ["src/server/game/Handlers/NPCHandler.cpp",
                      "src/server/game/Handlers/GossipHandler.cpp"],
    "mail":          ["src/server/game/Handlers/MailHandler.cpp"],
    "warband":       ["src/server/game/Handlers/WarbandHandler.cpp"],
    "collection":    ["src/server/game/Handlers/CollectionHandler.cpp",
                      "src/server/game/Handlers/TransmogrificationHandler.cpp"],
}


# ---------------------------------------------------------------------------
# Relocation mask for signature comparison
# ---------------------------------------------------------------------------

# Bytes at these offsets within a 32-byte window are likely to contain
# RIP-relative displacement values and should be masked when comparing
# function prologues across builds.  We use a simple heuristic: after
# any E8 (CALL near) or 0F 8x (Jcc near) we mask the next 4 bytes.
def _mask_relocations(raw_bytes):
    """Return a masked copy of raw_bytes with relocation targets zeroed."""
    buf = bytearray(raw_bytes)
    i = 0
    while i < len(buf):
        b = buf[i]
        # E8 xx xx xx xx  — CALL rel32
        # E9 xx xx xx xx  — JMP  rel32
        if b in (0xE8, 0xE9) and i + 4 < len(buf):
            buf[i+1:i+5] = b'\x00\x00\x00\x00'
            i += 5
            continue
        # 0F 8x xx xx xx xx — Jcc rel32
        if b == 0x0F and i + 1 < len(buf) and 0x80 <= buf[i+1] <= 0x8F:
            if i + 5 < len(buf):
                buf[i+2:i+6] = b'\x00\x00\x00\x00'
            i += 6
            continue
        # 48 8D 05/0D/15/1D/25/2D/35/3D xx xx xx xx — LEA reg, [rip+disp32]
        if b == 0x48 and i + 2 < len(buf) and buf[i+1] == 0x8D:
            modrm = buf[i+2]
            if (modrm & 0xC7) == 0x05:  # mod=00, rm=101 (RIP-relative)
                if i + 6 < len(buf):
                    buf[i+3:i+7] = b'\x00\x00\x00\x00'
                i += 7
                continue
        i += 1
    return bytes(buf)


# ---------------------------------------------------------------------------
# System classification helper
# ---------------------------------------------------------------------------

def _classify_system(name):
    """Classify a function or opcode name into a game system."""
    if not name:
        return "unknown"
    upper = name.upper()
    # Strip direction prefix
    for prefix in ("CMSG_", "SMSG_", "MSG_", "HANDLE"):
        if upper.startswith(prefix):
            upper = upper[len(prefix):]
            break
    for pfx, system in _SYSTEM_PREFIXES.items():
        if pfx in upper:
            return system
    return "unknown"


# ---------------------------------------------------------------------------
# Phase 1: Old Build Loading
# ---------------------------------------------------------------------------

class OldBuildData:
    """Container for data loaded from a previous build's knowledge DB."""

    def __init__(self):
        self.build_number = 0
        self.opcodes = {}           # tc_name -> row dict
        self.jam_types = {}         # name -> row dict
        self.functions = {}         # name -> row dict
        self.wire_formats = {}      # opcode_name -> fields list
        self.validations = {}       # handler_name -> rules list
        self.conformance = {}       # handler_name -> score dict
        self.ngram_data = {}        # func_name -> ngram set
        self.decompiled_cache = {}  # func_name -> pseudocode text
        self.strings_by_func = {}   # func_name -> set of string values


def _load_old_build(db_path):
    """Open a previous build's knowledge DB and extract all relevant data.

    Args:
        db_path: Path to the old build's .tc_wow.db SQLite file.

    Returns:
        OldBuildData instance, or None on failure.
    """
    if not os.path.isfile(db_path):
        msg_error(f"Old build DB not found: {db_path}")
        return None

    data = OldBuildData()

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
        conn.row_factory = sqlite3.Row
    except Exception as e:
        msg_error(f"Cannot open old build DB: {e}")
        return None

    try:
        # Build number
        _load_build_number(conn, data)

        # Opcodes
        _load_opcodes(conn, data)

        # JAM types
        _load_jam_types(conn, data)

        # Functions
        _load_functions(conn, data)

        # Wire formats from kv_store
        _load_wire_formats(conn, data)

        # Validations from kv_store
        _load_validations(conn, data)

        # Conformance from kv_store
        _load_conformance(conn, data)

        # N-gram data from kv_store
        _load_ngram_data(conn, data)

        # Decompiled pseudocode cache from kv_store
        _load_decompiled_cache(conn, data)

        # String references per function
        _load_string_refs(conn, data)

    except Exception as e:
        msg_error(f"Error reading old build DB: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

    msg_info(f"Loaded old build {data.build_number}: "
             f"{len(data.opcodes)} opcodes, {len(data.functions)} functions, "
             f"{len(data.wire_formats)} wire formats, "
             f"{len(data.decompiled_cache)} decompiled functions")
    return data


def _load_build_number(conn, data):
    """Extract build number from the old DB."""
    try:
        row = conn.execute(
            "SELECT build_number FROM builds ORDER BY build_number DESC LIMIT 1"
        ).fetchone()
        if row:
            data.build_number = row["build_number"]
            return
    except Exception:
        pass

    try:
        row = conn.execute(
            "SELECT value FROM kv_store WHERE key = 'build_number'"
        ).fetchone()
        if row:
            data.build_number = int(json.loads(row["value"]))
            return
    except Exception:
        pass

    # Try to detect from db path
    match = re.search(r'(\d{5,6})', os.path.basename(
        conn.execute("PRAGMA database_list").fetchone()["file"] or ""))
    if match:
        data.build_number = int(match.group(1))


def _load_opcodes(conn, data):
    """Load all opcodes from the old DB."""
    try:
        rows = conn.execute("SELECT * FROM opcodes").fetchall()
        for row in rows:
            tc_name = row["tc_name"]
            if tc_name:
                data.opcodes[tc_name] = dict(row)
    except Exception:
        pass


def _load_jam_types(conn, data):
    """Load JAM types from the old DB."""
    try:
        rows = conn.execute("SELECT * FROM jam_types").fetchall()
        for row in rows:
            data.jam_types[row["name"]] = dict(row)
    except Exception:
        pass


def _load_functions(conn, data):
    """Load functions from the old DB."""
    try:
        rows = conn.execute(
            "SELECT * FROM functions WHERE name IS NOT NULL"
        ).fetchall()
        for row in rows:
            data.functions[row["name"]] = dict(row)
    except Exception:
        pass


def _load_wire_formats(conn, data):
    """Load wire format data from the old DB's kv_store."""
    try:
        row = conn.execute(
            "SELECT value FROM kv_store WHERE key = 'wire_formats'"
        ).fetchone()
        if row:
            data.wire_formats = json.loads(row["value"]) or {}
    except Exception:
        pass


def _load_validations(conn, data):
    """Load validation data from the old DB's kv_store."""
    try:
        rows = conn.execute(
            "SELECT key, value FROM kv_store WHERE key LIKE 'validations:%'"
        ).fetchall()
        for row in rows:
            handler_name = row["key"].split(":", 1)[1]
            try:
                data.validations[handler_name] = json.loads(row["value"])
            except (json.JSONDecodeError, TypeError):
                pass
    except Exception:
        pass


def _load_conformance(conn, data):
    """Load conformance scores from the old DB's kv_store."""
    try:
        row = conn.execute(
            "SELECT value FROM kv_store WHERE key = 'conformance_scores'"
        ).fetchone()
        if row:
            data.conformance = json.loads(row["value"]) or {}
    except Exception:
        pass


def _load_ngram_data(conn, data):
    """Load instruction n-gram data from the old DB's kv_store."""
    try:
        row = conn.execute(
            "SELECT value FROM kv_store WHERE key = 'instruction_ngrams'"
        ).fetchone()
        if row:
            ngram_report = json.loads(row["value"]) or {}
            # Extract per-function n-gram sets if available
            func_ngrams = ngram_report.get("function_ngrams", {})
            for func_name, ngrams in func_ngrams.items():
                if isinstance(ngrams, list):
                    data.ngram_data[func_name] = set(ngrams)
                elif isinstance(ngrams, dict):
                    # Could be {ngram_str: count} format
                    data.ngram_data[func_name] = set(ngrams.keys())
    except Exception:
        pass


def _load_decompiled_cache(conn, data):
    """Load cached decompilation results from the old DB."""
    try:
        # Check for per-function decompilation cache
        rows = conn.execute(
            "SELECT key, value FROM kv_store WHERE key LIKE 'decomp:%'"
        ).fetchall()
        for row in rows:
            func_name = row["key"].split(":", 1)[1]
            data.decompiled_cache[func_name] = row["value"]
    except Exception:
        pass

    # Also check for bulk decompilation export
    if not data.decompiled_cache:
        try:
            row = conn.execute(
                "SELECT value FROM kv_store WHERE key = 'decompiled_functions'"
            ).fetchone()
            if row:
                bulk = json.loads(row["value"]) or {}
                for func_name, pseudocode in bulk.items():
                    if isinstance(pseudocode, str):
                        data.decompiled_cache[func_name] = pseudocode
        except Exception:
            pass


def _load_string_refs(conn, data):
    """Load string references per function from the old DB."""
    try:
        # Join functions with strings via xrefs if available
        rows = conn.execute("""
            SELECT f.name as func_name, s.value as str_value
            FROM functions f
            JOIN annotations a ON a.ea = f.ea AND a.ann_type = 'string_ref'
            JOIN strings s ON s.ea = CAST(a.value AS INTEGER)
            WHERE f.name IS NOT NULL
        """).fetchall()
        for row in rows:
            data.strings_by_func.setdefault(row["func_name"], set()).add(
                row["str_value"])
    except Exception:
        pass

    # Fallback: load from kv_store
    if not data.strings_by_func:
        try:
            row = conn.execute(
                "SELECT value FROM kv_store WHERE key = 'function_string_refs'"
            ).fetchone()
            if row:
                mapping = json.loads(row["value"]) or {}
                for func_name, strs in mapping.items():
                    if isinstance(strs, list):
                        data.strings_by_func[func_name] = set(strs)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Phase 2: Function Matching
# ---------------------------------------------------------------------------

class FunctionMatch:
    """Represents a matched function pair between old and new builds."""

    __slots__ = ("old_name", "new_name", "old_ea", "new_ea", "strategy",
                 "confidence", "ambiguous", "alternatives")

    def __init__(self, old_name, new_name, old_ea, new_ea, strategy,
                 confidence, ambiguous=False, alternatives=None):
        self.old_name = old_name
        self.new_name = new_name
        self.old_ea = old_ea
        self.new_ea = new_ea
        self.strategy = strategy
        self.confidence = confidence
        self.ambiguous = ambiguous
        self.alternatives = alternatives or []

    def to_dict(self):
        d = {
            "old_name": self.old_name,
            "new_name": self.new_name,
            "old_ea": self.old_ea,
            "new_ea": self.new_ea,
            "strategy": self.strategy,
            "confidence": self.confidence,
        }
        if self.ambiguous:
            d["ambiguous"] = True
            d["alternatives"] = self.alternatives
        return d


def _build_new_function_index(session):
    """Build lookup structures for functions in the current (new) IDB.

    Returns:
        dict with keys:
          - by_name: {name: ea}
          - by_ea: {ea: name}
          - strings_by_func: {name: set(string_values)}
          - signature_by_name: {name: masked_bytes}
          - callers_by_name: {name: set(caller_names)}
          - callees_by_name: {name: set(callee_names)}
          - size_bb_by_name: {name: (size, bb_count)}
    """
    db = session.db
    index = {
        "by_name": {},
        "by_ea": {},
        "strings_by_func": defaultdict(set),
        "signature_by_name": {},
        "callers_by_name": defaultdict(set),
        "callees_by_name": defaultdict(set),
        "size_bb_by_name": {},
    }

    # Load from DB
    rows = db.fetchall("SELECT * FROM functions WHERE name IS NOT NULL")
    for row in rows:
        name = row["name"]
        ea = row["ea"]
        index["by_name"][name] = ea
        index["by_ea"][ea] = name

    # If DB is sparse, also scan IDA
    if len(index["by_name"]) < 1000:
        for seg_ea in idautils.Segments():
            for func_ea in idautils.Functions(seg_ea, idaapi.get_segm_end(seg_ea)):
                name = ida_name.get_name(func_ea)
                if name and not name.startswith("sub_"):
                    if name not in index["by_name"]:
                        index["by_name"][name] = func_ea
                        index["by_ea"][func_ea] = name

    msg_info(f"New build function index: {len(index['by_name'])} named functions")

    # Build string reference index
    try:
        str_rows = db.fetchall("SELECT * FROM strings WHERE value IS NOT NULL")
        str_by_ea = {row["ea"]: row["value"] for row in str_rows}

        for str_ea, str_val in str_by_ea.items():
            for xref in idautils.XrefsTo(str_ea, 0):
                func = ida_funcs.get_func(xref.frm)
                if func:
                    fname = index["by_ea"].get(func.start_ea)
                    if fname:
                        index["strings_by_func"][fname].add(str_val)
    except Exception:
        pass

    # Build signatures, call graphs, and size/BB counts
    count = 0
    for name, ea in index["by_name"].items():
        func = ida_funcs.get_func(ea)
        if not func:
            continue

        # Signature: first N bytes, masked
        try:
            raw = ida_bytes.get_bytes(ea, min(SIGNATURE_BYTES_COUNT, func.size()))
            if raw and len(raw) >= 8:
                index["signature_by_name"][name] = _mask_relocations(raw)
        except Exception:
            pass

        # Size and basic block count
        try:
            bb_count = 0
            flow = idaapi.FlowChart(func)
            for _ in flow:
                bb_count += 1
            index["size_bb_by_name"][name] = (func.size(), bb_count)
        except Exception:
            index["size_bb_by_name"][name] = (func.size(), 0)

        # Call graph: callees
        try:
            for item_ea in idautils.FuncItems(ea):
                for xref in idautils.XrefsFrom(item_ea, 0):
                    if xref.type in (idaapi.fl_CN, idaapi.fl_CF):
                        callee_func = ida_funcs.get_func(xref.to)
                        if callee_func:
                            callee_name = index["by_ea"].get(callee_func.start_ea)
                            if callee_name:
                                index["callees_by_name"][name].add(callee_name)
                                index["callers_by_name"][callee_name].add(name)
        except Exception:
            pass

        count += 1
        if count % PROGRESS_INTERVAL == 0:
            msg(f"  Indexed {count}/{len(index['by_name'])} functions...")

    return index


def _match_functions(old_data, new_index, session):
    """Match functions between old and new builds using multiple strategies.

    Strategies are applied in priority order; once a function is matched
    by a higher-confidence strategy, lower strategies skip it.

    Args:
        old_data: OldBuildData from Phase 1
        new_index: dict from _build_new_function_index()
        session: PluginSession

    Returns:
        tuple of:
          - matched: dict {old_name: FunctionMatch}
          - unmatched_old: list of old function names not matched
          - unmatched_new: list of new function names not matched
    """
    matched = {}
    matched_new_names = set()

    # Strategy 1: Exact name match
    msg_info("Strategy 1: Exact name match...")
    exact_count = 0
    for old_name, old_info in old_data.functions.items():
        if old_name in new_index["by_name"]:
            new_ea = new_index["by_name"][old_name]
            matched[old_name] = FunctionMatch(
                old_name=old_name,
                new_name=old_name,
                old_ea=old_info["ea"],
                new_ea=new_ea,
                strategy=STRATEGY_EXACT_NAME,
                confidence=STRATEGY_CONFIDENCE[STRATEGY_EXACT_NAME],
            )
            matched_new_names.add(old_name)
            exact_count += 1
    msg_info(f"  Exact name: {exact_count} matches")

    # Strategy 2: Opcode handler match
    msg_info("Strategy 2: Opcode handler match...")
    opcode_count = 0
    db = session.db
    new_opcodes = {}
    try:
        rows = db.fetchall(
            "SELECT * FROM opcodes WHERE handler_ea IS NOT NULL AND tc_name IS NOT NULL"
        )
        for row in rows:
            new_opcodes[row["tc_name"]] = {
                "handler_ea": row["handler_ea"],
                "tc_name": row["tc_name"],
            }
    except Exception:
        pass

    for tc_name, old_op in old_data.opcodes.items():
        old_handler_ea = old_op.get("handler_ea")
        if not old_handler_ea:
            continue
        # Find old function name at that handler ea
        old_func_name = None
        for fname, finfo in old_data.functions.items():
            if finfo["ea"] == old_handler_ea:
                old_func_name = fname
                break
        if not old_func_name or old_func_name in matched:
            continue

        if tc_name in new_opcodes:
            new_handler_ea = new_opcodes[tc_name]["handler_ea"]
            new_func_name = new_index["by_ea"].get(new_handler_ea)
            if new_func_name and new_func_name not in matched_new_names:
                matched[old_func_name] = FunctionMatch(
                    old_name=old_func_name,
                    new_name=new_func_name,
                    old_ea=old_handler_ea,
                    new_ea=new_handler_ea,
                    strategy=STRATEGY_OPCODE_HANDLER,
                    confidence=STRATEGY_CONFIDENCE[STRATEGY_OPCODE_HANDLER],
                )
                matched_new_names.add(new_func_name)
                opcode_count += 1
    msg_info(f"  Opcode handler: {opcode_count} matches")

    # Strategy 3: String reference match
    msg_info("Strategy 3: String reference match...")
    string_count = 0
    # Build unique string -> func mapping for new build
    new_unique_strings = {}
    for fname, strs in new_index["strings_by_func"].items():
        for s in strs:
            if s not in new_unique_strings:
                new_unique_strings[s] = fname
            else:
                new_unique_strings[s] = None  # not unique

    old_unique_strings = {}
    for fname, strs in old_data.strings_by_func.items():
        for s in strs:
            if s not in old_unique_strings:
                old_unique_strings[s] = fname
            else:
                old_unique_strings[s] = None  # not unique

    # Match by shared unique strings
    string_candidates = defaultdict(lambda: defaultdict(int))
    for string_val, old_func in old_unique_strings.items():
        if old_func is None or old_func in matched:
            continue
        new_func = new_unique_strings.get(string_val)
        if new_func is not None and new_func not in matched_new_names:
            string_candidates[old_func][new_func] += 1

    for old_func, new_funcs in string_candidates.items():
        if old_func in matched:
            continue
        # Pick the candidate with the most shared unique strings
        best_new = max(new_funcs, key=new_funcs.get)
        shared_count = new_funcs[best_new]
        if shared_count >= 1 and best_new not in matched_new_names:
            ambiguous = len(new_funcs) > 1
            alternatives = []
            if ambiguous:
                alternatives = [
                    {"name": n, "shared_strings": c}
                    for n, c in sorted(new_funcs.items(),
                                       key=lambda x: -x[1])[:5]
                    if n != best_new
                ]
            confidence = STRATEGY_CONFIDENCE[STRATEGY_STRING_REF]
            if shared_count >= 3:
                confidence = min(confidence + 5, 95)
            if ambiguous:
                confidence = max(confidence - 10, 50)

            old_info = old_data.functions.get(old_func, {})
            matched[old_func] = FunctionMatch(
                old_name=old_func,
                new_name=best_new,
                old_ea=old_info.get("ea", 0),
                new_ea=new_index["by_name"].get(best_new, 0),
                strategy=STRATEGY_STRING_REF,
                confidence=confidence,
                ambiguous=ambiguous,
                alternatives=alternatives,
            )
            matched_new_names.add(best_new)
            string_count += 1
    msg_info(f"  String reference: {string_count} matches")

    # Strategy 4: Signature match (first 32 bytes, relocation-masked)
    msg_info("Strategy 4: Signature match...")
    sig_count = 0
    # Build old signature index
    old_signatures = {}
    for old_name, old_info in old_data.functions.items():
        if old_name in matched:
            continue
        old_ea = old_info.get("ea", 0)
        old_size = old_info.get("size", 0)
        # We cannot read old build bytes from IDA, so check if we have
        # a stored signature hash in the old DB's decompiled_hash
        decompiled_hash = old_info.get("decompiled_hash")
        if decompiled_hash:
            old_signatures.setdefault(decompiled_hash, []).append(old_name)

    # For new functions, compute signature hashes
    new_sig_hashes = {}
    for name, masked_bytes in new_index["signature_by_name"].items():
        if name in matched_new_names:
            continue
        sig_hash = hashlib.md5(masked_bytes).hexdigest()
        new_sig_hashes.setdefault(sig_hash, []).append(name)

    for sig_hash, old_names in old_signatures.items():
        new_names = new_sig_hashes.get(sig_hash, [])
        if len(old_names) == 1 and len(new_names) == 1:
            old_n = old_names[0]
            new_n = new_names[0]
            if old_n not in matched and new_n not in matched_new_names:
                old_info = old_data.functions.get(old_n, {})
                matched[old_n] = FunctionMatch(
                    old_name=old_n,
                    new_name=new_n,
                    old_ea=old_info.get("ea", 0),
                    new_ea=new_index["by_name"].get(new_n, 0),
                    strategy=STRATEGY_SIGNATURE,
                    confidence=STRATEGY_CONFIDENCE[STRATEGY_SIGNATURE],
                )
                matched_new_names.add(new_n)
                sig_count += 1
    msg_info(f"  Signature: {sig_count} matches")

    # Strategy 5: N-gram similarity
    msg_info("Strategy 5: N-gram similarity...")
    ngram_count = 0
    new_ngram_data = _load_new_ngram_data(session)

    for old_name, old_ngrams in old_data.ngram_data.items():
        if old_name in matched or not old_ngrams:
            continue
        best_match = None
        best_jaccard = 0.0
        candidates = []

        for new_name, new_ngrams in new_ngram_data.items():
            if new_name in matched_new_names or not new_ngrams:
                continue
            intersection = len(old_ngrams & new_ngrams)
            union = len(old_ngrams | new_ngrams)
            if union == 0:
                continue
            jaccard = intersection / union
            if jaccard > NGRAM_JACCARD_THRESHOLD:
                candidates.append((new_name, jaccard))
                if jaccard > best_jaccard:
                    best_jaccard = jaccard
                    best_match = new_name

        if best_match and best_match not in matched_new_names:
            ambiguous = len(candidates) > 1
            alternatives = []
            if ambiguous:
                alternatives = [
                    {"name": n, "jaccard": round(j, 4)}
                    for n, j in sorted(candidates, key=lambda x: -x[1])[:5]
                    if n != best_match
                ]
            # Scale confidence: 0.70 -> 70, 0.85 -> 85
            confidence = int(best_jaccard * 100)
            confidence = max(STRATEGY_CONFIDENCE[STRATEGY_NGRAM_SIMILARITY] - 8,
                             min(confidence, STRATEGY_CONFIDENCE[STRATEGY_NGRAM_SIMILARITY] + 7))
            if ambiguous:
                confidence = max(confidence - 10, 50)

            old_info = old_data.functions.get(old_name, {})
            matched[old_name] = FunctionMatch(
                old_name=old_name,
                new_name=best_match,
                old_ea=old_info.get("ea", 0),
                new_ea=new_index["by_name"].get(best_match, 0),
                strategy=STRATEGY_NGRAM_SIMILARITY,
                confidence=confidence,
                ambiguous=ambiguous,
                alternatives=alternatives,
            )
            matched_new_names.add(best_match)
            ngram_count += 1
    msg_info(f"  N-gram similarity: {ngram_count} matches")

    # Strategy 6: Call graph topology
    msg_info("Strategy 6: Call graph topology...")
    cg_count = 0
    # Build old call graph from kv_store
    old_callees = defaultdict(set)
    old_callers = defaultdict(set)
    for handler_name, cg_data in _iter_old_call_graphs(old_data):
        if isinstance(cg_data, list):
            for entry in cg_data:
                callee = entry.get("name") or entry.get("callee")
                if callee:
                    old_callees[handler_name].add(callee)
                    old_callers[callee].add(handler_name)

    for old_name in list(old_data.functions.keys()):
        if old_name in matched:
            continue
        old_cl = old_callees.get(old_name, set())
        old_cr = old_callers.get(old_name, set())
        if not old_cl and not old_cr:
            continue

        best_match = None
        best_score = 0.0
        candidates = []

        for new_name in new_index["by_name"]:
            if new_name in matched_new_names:
                continue
            new_cl = new_index["callees_by_name"].get(new_name, set())
            new_cr = new_index["callers_by_name"].get(new_name, set())
            if not new_cl and not new_cr:
                continue

            # Jaccard on callees
            cl_inter = len(old_cl & new_cl)
            cl_union = len(old_cl | new_cl)
            callee_sim = cl_inter / cl_union if cl_union else 0.0

            # Jaccard on callers
            cr_inter = len(old_cr & new_cr)
            cr_union = len(old_cr | new_cr)
            caller_sim = cr_inter / cr_union if cr_union else 0.0

            # Combined score (weighted toward callees)
            score = 0.6 * callee_sim + 0.4 * caller_sim

            if score > 0.5:
                candidates.append((new_name, score))
                if score > best_score:
                    best_score = score
                    best_match = new_name

        if best_match and best_score > 0.5 and best_match not in matched_new_names:
            ambiguous = len(candidates) > 1
            alternatives = []
            if ambiguous:
                alternatives = [
                    {"name": n, "score": round(s, 4)}
                    for n, s in sorted(candidates, key=lambda x: -x[1])[:5]
                    if n != best_match
                ]
            confidence = STRATEGY_CONFIDENCE[STRATEGY_CALL_GRAPH]
            if best_score > 0.8:
                confidence = min(confidence + 10, 80)
            if ambiguous:
                confidence = max(confidence - 10, 40)

            old_info = old_data.functions.get(old_name, {})
            matched[old_name] = FunctionMatch(
                old_name=old_name,
                new_name=best_match,
                old_ea=old_info.get("ea", 0),
                new_ea=new_index["by_name"].get(best_match, 0),
                strategy=STRATEGY_CALL_GRAPH,
                confidence=confidence,
                ambiguous=ambiguous,
                alternatives=alternatives,
            )
            matched_new_names.add(best_match)
            cg_count += 1
    msg_info(f"  Call graph topology: {cg_count} matches")

    # Strategy 7: Size + basic block count
    msg_info("Strategy 7: Size + BB count...")
    size_bb_count = 0
    # Build old size/BB index
    old_size_bb = {}
    for old_name, old_info in old_data.functions.items():
        if old_name in matched:
            continue
        size = old_info.get("size", 0)
        # We do not have BB count from the old DB directly, but we have size
        if size > 0:
            bucket = size // 64
            old_size_bb.setdefault(bucket, []).append((old_name, size))

    # New build size/BB index
    new_size_bb_buckets = defaultdict(list)
    for name, (size, bb) in new_index["size_bb_by_name"].items():
        if name in matched_new_names or size == 0:
            continue
        bucket = size // 64
        new_size_bb_buckets[bucket].append((name, size, bb))

    for bucket, old_entries in old_size_bb.items():
        new_entries = new_size_bb_buckets.get(bucket, [])
        if not new_entries:
            continue
        for old_name, old_size in old_entries:
            if old_name in matched:
                continue
            # Find new functions in same size bucket
            candidates = []
            for new_name, new_size, new_bb in new_entries:
                if new_name in matched_new_names:
                    continue
                # Allow 20% size variance
                if abs(new_size - old_size) / max(old_size, 1) < 0.20:
                    # Verify with partial signature if available
                    partial_match = False
                    old_hash = old_data.functions.get(old_name, {}).get(
                        "decompiled_hash")
                    new_sig = new_index["signature_by_name"].get(new_name)
                    if old_hash and new_sig:
                        new_hash = hashlib.md5(new_sig[:16]).hexdigest()
                        # Partial match: first 16 bytes
                        if old_hash[:8] == new_hash[:8]:
                            partial_match = True
                    candidates.append((new_name, new_size, new_bb, partial_match))

            if not candidates:
                continue

            # Prefer partial signature matches
            partial_candidates = [c for c in candidates if c[3]]
            if len(partial_candidates) == 1:
                best = partial_candidates[0]
                confidence = STRATEGY_CONFIDENCE[STRATEGY_SIZE_BB] + 10
            elif partial_candidates:
                best = partial_candidates[0]
                confidence = STRATEGY_CONFIDENCE[STRATEGY_SIZE_BB]
            elif len(candidates) == 1:
                best = candidates[0]
                confidence = STRATEGY_CONFIDENCE[STRATEGY_SIZE_BB]
            else:
                continue  # Too ambiguous without partial signature

            new_name = best[0]
            if new_name in matched_new_names:
                continue

            ambiguous = len(candidates) > 1
            alternatives = [
                {"name": c[0], "size": c[1], "bb_count": c[2]}
                for c in candidates[:5] if c[0] != new_name
            ] if ambiguous else []

            old_info = old_data.functions.get(old_name, {})
            matched[old_name] = FunctionMatch(
                old_name=old_name,
                new_name=new_name,
                old_ea=old_info.get("ea", 0),
                new_ea=new_index["by_name"].get(new_name, 0),
                strategy=STRATEGY_SIZE_BB,
                confidence=confidence,
                ambiguous=ambiguous,
                alternatives=alternatives,
            )
            matched_new_names.add(new_name)
            size_bb_count += 1
    msg_info(f"  Size + BB: {size_bb_count} matches")

    # Compute unmatched
    unmatched_old = [n for n in old_data.functions if n not in matched]
    unmatched_new = [n for n in new_index["by_name"] if n not in matched_new_names]

    total = len(matched)
    msg_info(f"Total matched: {total}, unmatched old: {len(unmatched_old)}, "
             f"unmatched new: {len(unmatched_new)}")

    return matched, unmatched_old, unmatched_new


def _load_new_ngram_data(session):
    """Load n-gram data for the current (new) build from kv_store."""
    result = {}
    try:
        ngram_report = session.db.kv_get("instruction_ngrams") or {}
        func_ngrams = ngram_report.get("function_ngrams", {})
        for func_name, ngrams in func_ngrams.items():
            if isinstance(ngrams, list):
                result[func_name] = set(ngrams)
            elif isinstance(ngrams, dict):
                result[func_name] = set(ngrams.keys())
    except Exception:
        pass
    return result


def _iter_old_call_graphs(old_data):
    """Iterate over old build's call graph data.

    Yields (handler_name, call_graph_list) pairs.
    """
    # Check direct attribute first
    if hasattr(old_data, '_call_graphs'):
        for name, cg in old_data._call_graphs.items():
            yield name, cg
        return

    # Build from functions + opcodes
    for tc_name, op_info in old_data.opcodes.items():
        handler_ea = op_info.get("handler_ea")
        if not handler_ea:
            continue
        # Find function name for this handler
        func_name = None
        for fname, finfo in old_data.functions.items():
            if finfo["ea"] == handler_ea:
                func_name = fname
                break
        if func_name:
            # We don't have actual call graph data from old build's DB in
            # the general case, so yield empty.  The call graph strategy
            # works better when the old DB has kv_store call_graph entries.
            yield func_name, []


# ---------------------------------------------------------------------------
# Phase 3: Semantic Diff
# ---------------------------------------------------------------------------

class SemanticChange:
    """Represents a single semantic change between matched functions."""

    __slots__ = ("change_type", "description", "old_code", "new_code",
                 "priority", "system", "tc_files", "breaking", "line_range")

    def __init__(self, change_type, description, old_code=None, new_code=None,
                 priority=PRIORITY_LOW, system="unknown", tc_files=None,
                 breaking=False, line_range=None):
        self.change_type = change_type
        self.description = description
        self.old_code = old_code
        self.new_code = new_code
        self.priority = priority
        self.system = system
        self.tc_files = tc_files or []
        self.breaking = breaking
        self.line_range = line_range

    def to_dict(self):
        return {
            "type": self.change_type,
            "priority": self.priority,
            "description": self.description,
            "old_code": self.old_code,
            "new_code": self.new_code,
            "system": self.system,
            "tc_files_affected": self.tc_files,
            "breaking": self.breaking,
            "line_range": self.line_range,
        }


def _normalize_pseudocode(text):
    """Normalize decompiled pseudocode for diffing.

    Strips auto-generated names, normalizes types, removes comments, and
    standardizes whitespace so that trivial differences (renamed locals,
    recompiler artifacts) do not pollute the diff.
    """
    if not text:
        return ""

    lines = text.split('\n')
    normalized = []

    for line in lines:
        # Remove IDA-generated comments
        line = re.sub(r'//.*$', '', line)
        line = re.sub(r'/\*.*?\*/', '', line)

        # Normalize auto-names: v1, v2, ... -> _var
        line = re.sub(r'\bv(\d+)\b', '_var', line)
        # Normalize argument names: a1, a2, ... -> _arg
        line = re.sub(r'\ba(\d+)\b', '_arg', line)
        # Normalize result variable: result -> _result
        line = re.sub(r'\bresult\b', '_result', line)

        # Normalize hex addresses to ADDR
        line = re.sub(r'0x[0-9A-Fa-f]{6,16}', 'ADDR', line)

        # Normalize pointer casts: (__int64 *) -> (TYPE *)
        line = re.sub(r'\(\s*(?:unsigned\s+)?(?:__int64|__int32|__int16|__int8'
                       r'|_DWORD|_WORD|_BYTE|_QWORD)\s*\*?\s*\)', '(TYPE)', line)

        # Normalize integer types
        line = re.sub(r'\b(?:unsigned\s+)?(?:__int64|__int32|__int16|__int8)\b',
                       'INT', line)
        line = re.sub(r'\b(?:_DWORD|_WORD|_BYTE|_QWORD)\b', 'INT', line)

        # Collapse whitespace
        line = re.sub(r'\s+', ' ', line).strip()

        if line:
            normalized.append(line)

    return '\n'.join(normalized)


def _classify_diff_block(old_lines, new_lines):
    """Classify a block of changed lines into a semantic change type.

    Examines the content of changed lines to determine what kind of
    change occurred.
    """
    old_text = '\n'.join(old_lines) if old_lines else ""
    new_text = '\n'.join(new_lines) if new_lines else ""

    # Check for packet field read/write patterns
    read_pattern = re.compile(
        r'Read\s*<|ReadBit|ReadBits|ReadPackedGuid|ReadString|'
        r'operator\s*>>', re.IGNORECASE)
    write_pattern = re.compile(
        r'Write\s*<|WriteBit|WriteBits|WritePackedGuid|WriteString|'
        r'operator\s*<<', re.IGNORECASE)

    old_has_read = bool(read_pattern.search(old_text))
    new_has_read = bool(read_pattern.search(new_text))
    old_has_write = bool(write_pattern.search(old_text))
    new_has_write = bool(write_pattern.search(new_text))

    # Packet field additions/removals
    if new_has_read and not old_has_read:
        return CHANGE_ADDED_PACKET_FIELD
    if old_has_read and not new_has_read:
        return CHANGE_REMOVED_PACKET_FIELD
    if new_has_write and not old_has_write:
        return CHANGE_ADDED_PACKET_FIELD
    if old_has_write and not new_has_write:
        return CHANGE_REMOVED_PACKET_FIELD

    # Validation patterns (if/return, if/goto error)
    validation_pattern = re.compile(
        r'if\s*\(.*(?:return|goto|SendError|SendResult|HOUSING_RESULT|'
        r'ERR_|ERROR_|RESULT_)', re.IGNORECASE)

    if not old_lines and new_lines:
        if validation_pattern.search(new_text):
            return CHANGE_ADDED_VALIDATION
        return CHANGE_ADDED_LOGIC
    if old_lines and not new_lines:
        if validation_pattern.search(old_text):
            return CHANGE_REMOVED_VALIDATION
        return CHANGE_REMOVED_LOGIC

    # Constant changes: same structure, different numbers
    old_nums = set(re.findall(r'\b(?:0x[0-9A-Fa-f]+|\d{2,})\b', old_text))
    new_nums = set(re.findall(r'\b(?:0x[0-9A-Fa-f]+|\d{2,})\b', new_text))
    if old_nums != new_nums:
        # Check if structure is similar
        old_stripped = re.sub(r'\b(?:0x[0-9A-Fa-f]+|\d+)\b', 'NUM', old_text)
        new_stripped = re.sub(r'\b(?:0x[0-9A-Fa-f]+|\d+)\b', 'NUM', new_text)
        if old_stripped == new_stripped:
            # Check if it looks like an enum (small ints near each other)
            old_ints = sorted(_parse_ints(old_nums))
            new_ints = sorted(_parse_ints(new_nums))
            if old_ints and new_ints and all(abs(a - b) < 100
                                              for a, b in zip(old_ints, new_ints)):
                return CHANGE_CHANGED_ENUM_VALUE
            return CHANGE_CHANGED_CONSTANT

    # Check if both have validation patterns
    if validation_pattern.search(new_text):
        if validation_pattern.search(old_text):
            return CHANGE_CHANGED_CONSTANT  # validation threshold changed
        return CHANGE_ADDED_VALIDATION

    # Default: added or removed logic
    if not old_lines and new_lines:
        return CHANGE_ADDED_LOGIC
    if old_lines and not new_lines:
        return CHANGE_REMOVED_LOGIC

    return CHANGE_ADDED_LOGIC  # catch-all for modified blocks


def _parse_ints(num_strings):
    """Parse a set of number strings (decimal or hex) to integers."""
    result = []
    for s in num_strings:
        try:
            if s.startswith("0x") or s.startswith("0X"):
                result.append(int(s, 16))
            else:
                result.append(int(s))
        except ValueError:
            pass
    return result


def _diff_function_pair(match, old_data, session):
    """Perform semantic diff on a matched function pair.

    Args:
        match: FunctionMatch
        old_data: OldBuildData
        session: PluginSession

    Returns:
        list of SemanticChange instances
    """
    changes = []

    # Get pseudocode from both builds
    old_code = old_data.decompiled_cache.get(match.old_name)
    new_code = None

    if match.new_ea:
        new_code = get_decompiled_text(match.new_ea)
        if new_code:
            # Cache the new decompilation
            try:
                session.db.execute(
                    "INSERT OR REPLACE INTO kv_store (key, value, updated_at) "
                    "VALUES (?, ?, ?)",
                    (f"decomp:{match.new_name}", new_code, time.time()))
            except Exception:
                pass

    if not old_code and not new_code:
        return changes

    if not old_code:
        changes.append(SemanticChange(
            change_type=CHANGE_ADDED_LOGIC,
            description=f"No old decompilation available for {match.old_name}; "
                        f"cannot diff",
            new_code=new_code[:500] if new_code else None,
            priority=PRIORITY_LOW,
            system=_classify_system(match.old_name),
        ))
        return changes

    if not new_code:
        changes.append(SemanticChange(
            change_type=CHANGE_REMOVED_LOGIC,
            description=f"Cannot decompile new version of {match.new_name}",
            old_code=old_code[:500],
            priority=PRIORITY_LOW,
            system=_classify_system(match.old_name),
        ))
        return changes

    # Normalize both
    old_norm = _normalize_pseudocode(old_code)
    new_norm = _normalize_pseudocode(new_code)

    if old_norm == new_norm:
        return changes  # No meaningful change

    # Structural diff
    old_lines = old_norm.split('\n')
    new_lines = new_norm.split('\n')

    matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
    ratio = matcher.ratio()

    if ratio < (1.0 - RESTRUCTURED_THRESHOLD):
        # Major restructuring
        system = _classify_system(match.old_name)
        tc_files = _TC_FILE_MAP.get(system, [])
        changes.append(SemanticChange(
            change_type=CHANGE_RESTRUCTURED,
            description=(f"Major restructuring of {match.old_name} "
                         f"(similarity: {ratio:.1%})"),
            old_code=old_code[:1000],
            new_code=new_code[:1000],
            priority=PRIORITY_HIGH,
            system=system,
            tc_files=tc_files,
            breaking=True,
        ))
        return changes

    # Fine-grained diff
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue

        old_block = old_lines[i1:i2]
        new_block = new_lines[j1:j2]

        change_type = _classify_diff_block(
            old_block if tag in ("replace", "delete") else [],
            new_block if tag in ("replace", "insert") else [],
        )

        description = _describe_change(change_type, old_block, new_block,
                                        match.old_name)
        priority = _assess_priority(change_type, old_block, new_block)
        system = _classify_system(match.old_name)
        tc_files = _TC_FILE_MAP.get(system, [])
        breaking = priority in (PRIORITY_CRITICAL, PRIORITY_HIGH)

        changes.append(SemanticChange(
            change_type=change_type,
            description=description,
            old_code='\n'.join(old_block) if old_block else None,
            new_code='\n'.join(new_block) if new_block else None,
            priority=priority,
            system=system,
            tc_files=tc_files,
            breaking=breaking,
            line_range=(j1, j2),
        ))

    return changes


def _describe_change(change_type, old_block, new_block, func_name):
    """Generate a human-readable description of a change."""
    descriptions = {
        CHANGE_ADDED_VALIDATION:
            "Added validation check",
        CHANGE_REMOVED_VALIDATION:
            "Removed validation check",
        CHANGE_ADDED_LOGIC:
            "Added new code block",
        CHANGE_REMOVED_LOGIC:
            "Removed code block",
        CHANGE_CHANGED_CONSTANT:
            "Changed constant value",
        CHANGE_CHANGED_ENUM_VALUE:
            "Enum value shifted",
        CHANGE_ADDED_PACKET_FIELD:
            "Added packet field read/write",
        CHANGE_REMOVED_PACKET_FIELD:
            "Removed packet field read/write",
        CHANGE_RESTRUCTURED:
            "Major structural change",
        CHANGE_UNCHANGED:
            "No meaningful change",
    }
    base = descriptions.get(change_type, "Unknown change")

    # Try to extract a meaningful summary from the changed code
    code = '\n'.join(new_block or old_block or [])
    if not code:
        return f"{base} in {func_name}"

    # Look for if-condition
    cond_match = re.search(r'if\s*\(([^)]{1,120})\)', code)
    if cond_match and change_type in (CHANGE_ADDED_VALIDATION,
                                       CHANGE_REMOVED_VALIDATION):
        return f"{base}: {cond_match.group(1)[:100]}"

    # Look for function calls
    call_match = re.search(r'(\w+)\s*\(', code)
    if call_match and change_type in (CHANGE_ADDED_LOGIC, CHANGE_REMOVED_LOGIC):
        return f"{base}: {call_match.group(1)}"

    # Look for constants
    const_match = re.findall(r'\b(0x[0-9A-Fa-f]+|\d{3,})\b', code)
    if const_match and change_type in (CHANGE_CHANGED_CONSTANT,
                                        CHANGE_CHANGED_ENUM_VALUE):
        return f"{base}: {', '.join(const_match[:3])}"

    # Summarize by first line
    first_line = code.split('\n')[0][:100]
    return f"{base}: {first_line}"


# ---------------------------------------------------------------------------
# Phase 4: Impact Assessment
# ---------------------------------------------------------------------------

def _assess_priority(change_type, old_block, new_block):
    """Determine the priority/severity of a change.

    Returns one of PRIORITY_CRITICAL, PRIORITY_HIGH, PRIORITY_MEDIUM, PRIORITY_LOW.
    """
    code = '\n'.join(new_block or old_block or [])

    # CRITICAL: Security validation changes
    security_patterns = [
        r'CheckPermission', r'IsAdmin', r'HasAuthority', r'CanModify',
        r'IsOwner', r'GetSecurity', r'SEC_', r'RBAC_', r'CheckAccess',
        r'ValidateToken', r'Authenticate', r'IsGM', r'GetAccess',
    ]
    for pat in security_patterns:
        if re.search(pat, code, re.IGNORECASE):
            if change_type in (CHANGE_ADDED_VALIDATION, CHANGE_REMOVED_VALIDATION):
                return PRIORITY_CRITICAL
            return PRIORITY_HIGH

    # HIGH: Core logic changes (packet fields, state changes)
    if change_type in (CHANGE_ADDED_PACKET_FIELD, CHANGE_REMOVED_PACKET_FIELD):
        return PRIORITY_HIGH
    if change_type == CHANGE_RESTRUCTURED:
        return PRIORITY_HIGH
    if change_type in (CHANGE_ADDED_VALIDATION, CHANGE_REMOVED_VALIDATION):
        return PRIORITY_HIGH

    # MEDIUM: Constants and enums
    if change_type in (CHANGE_CHANGED_CONSTANT, CHANGE_CHANGED_ENUM_VALUE):
        return PRIORITY_MEDIUM

    # LOW: Everything else
    return PRIORITY_LOW


def _assess_impact(changes, match, old_data):
    """Enrich changes with impact assessment details.

    Modifies changes in place, adding system, tc_files, and breaking fields
    where they can be refined.
    """
    system = _classify_system(match.old_name)

    # Check if this is an opcode handler
    is_handler = False
    opcode_info = None
    for tc_name, op in old_data.opcodes.items():
        handler_ea = op.get("handler_ea")
        if handler_ea and handler_ea == match.old_ea:
            is_handler = True
            opcode_info = op
            break

    for change in changes:
        # Upgrade priority if handler is well-known
        if is_handler and change.priority == PRIORITY_MEDIUM:
            change.priority = PRIORITY_HIGH

        # Set TC files
        if not change.tc_files:
            change.tc_files = _TC_FILE_MAP.get(system, [])

        # Set system
        change.system = system

        # Mark breaking changes
        if change.change_type in (CHANGE_ADDED_PACKET_FIELD,
                                   CHANGE_REMOVED_PACKET_FIELD,
                                   CHANGE_RESTRUCTURED):
            change.breaking = True
        elif change.change_type in (CHANGE_ADDED_VALIDATION,
                                     CHANGE_REMOVED_VALIDATION):
            change.breaking = True


# ---------------------------------------------------------------------------
# Phase 5: TC Patch Generation
# ---------------------------------------------------------------------------

def _generate_patch(change, match, tc_source_dir=None):
    """Generate a unified diff patch for a single change.

    Args:
        change: SemanticChange
        match: FunctionMatch
        tc_source_dir: Optional path to TC source for real file context

    Returns:
        str: Unified diff patch text, or None if no patch applicable.
    """
    if change.change_type == CHANGE_UNCHANGED:
        return None

    # Determine the likely TC source file
    tc_files = change.tc_files or _TC_FILE_MAP.get(change.system, [])
    if not tc_files:
        tc_files = [f"src/server/game/Handlers/UnknownHandler.cpp"]

    primary_file = tc_files[0]

    # Try to load actual TC source for context
    real_context = None
    if tc_source_dir:
        full_path = os.path.join(tc_source_dir, primary_file)
        if os.path.isfile(full_path):
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    real_context = f.read()
            except Exception:
                pass

    # Generate patch based on change type
    handler_name = _tc_handler_name(match.old_name)
    patch_lines = []
    patch_lines.append(f"--- a/{primary_file}")
    patch_lines.append(f"+++ b/{primary_file}")

    if change.change_type == CHANGE_ADDED_VALIDATION:
        patch_lines.extend(_patch_added_validation(change, handler_name,
                                                    real_context))
    elif change.change_type == CHANGE_REMOVED_VALIDATION:
        patch_lines.extend(_patch_removed_validation(change, handler_name,
                                                      real_context))
    elif change.change_type == CHANGE_ADDED_PACKET_FIELD:
        patch_lines.extend(_patch_added_packet_field(change, handler_name,
                                                      real_context))
    elif change.change_type == CHANGE_REMOVED_PACKET_FIELD:
        patch_lines.extend(_patch_removed_packet_field(change, handler_name,
                                                        real_context))
    elif change.change_type == CHANGE_CHANGED_CONSTANT:
        patch_lines.extend(_patch_changed_constant(change, handler_name,
                                                    real_context))
    elif change.change_type == CHANGE_CHANGED_ENUM_VALUE:
        patch_lines.extend(_patch_changed_enum(change, handler_name,
                                                real_context))
    elif change.change_type == CHANGE_ADDED_LOGIC:
        patch_lines.extend(_patch_added_logic(change, handler_name,
                                               real_context))
    elif change.change_type == CHANGE_REMOVED_LOGIC:
        patch_lines.extend(_patch_removed_logic(change, handler_name,
                                                 real_context))
    elif change.change_type == CHANGE_RESTRUCTURED:
        patch_lines.extend(_patch_restructured(change, handler_name))
    else:
        return None

    if len(patch_lines) <= 2:
        return None

    return '\n'.join(patch_lines) + '\n'


def _tc_handler_name(func_name):
    """Convert a binary function name to the likely TC handler method name.

    Example: 'HandleHousingPlaceDecor' -> 'WorldSession::HandleHousingPlaceDecor'
    """
    if not func_name:
        return "UnknownHandler"
    # If it starts with Handle, wrap in WorldSession
    if func_name.startswith("Handle"):
        return f"WorldSession::{func_name}"
    # If it looks like a CMSG name, convert
    if func_name.startswith("CMSG_"):
        parts = func_name[5:].split('_')
        camel = 'Handle' + ''.join(p.capitalize() for p in parts)
        return f"WorldSession::{camel}"
    return func_name


def _find_handler_in_source(handler_name, source_text):
    """Find the line range of a handler function in TC source text.

    Returns (start_line, end_line, context_lines) or None.
    """
    if not source_text or not handler_name:
        return None

    # Strip WorldSession:: for matching
    method = handler_name.split("::")[-1] if "::" in handler_name else handler_name

    lines = source_text.split('\n')
    for i, line in enumerate(lines):
        if method in line and '{' in line or (method in line and i + 1 < len(lines)
                                               and '{' in lines[i + 1]):
            # Found function definition
            start = i
            # Find the end
            brace_depth = 0
            for j in range(i, len(lines)):
                brace_depth += lines[j].count('{') - lines[j].count('}')
                if brace_depth == 0 and j > i:
                    return (start, j, lines[max(0, start-2):j+3])
            return (start, min(start + 50, len(lines)), lines[start:start+50])
    return None


def _patch_added_validation(change, handler_name, real_context):
    """Generate patch lines for an added validation."""
    lines = []
    new_code = change.new_code or "// NEW validation check"

    # Try to find insertion point in real source
    context_line = "    // Packet parsing"
    if real_context:
        handler_info = _find_handler_in_source(handler_name, real_context)
        if handler_info:
            start, end, ctx = handler_info
            # Insert after last existing validation
            context_line = ctx[2] if len(ctx) > 2 else ctx[0] if ctx else context_line

    lines.append(f"@@ -1,0 +1,0 @@ void {handler_name}(...)")
    # Format the new code as a C++ validation block
    validation_code = _format_cpp_validation(new_code, change.description)
    for vc_line in validation_code:
        lines.append(f"+{vc_line}")
    lines.append("+")

    return lines


def _patch_removed_validation(change, handler_name, real_context):
    """Generate patch lines for a removed validation."""
    lines = []
    old_code = change.old_code or "// removed validation"

    lines.append(f"@@ -1,0 +1,0 @@ void {handler_name}(...)")
    lines.append(f"-    // Validation that was removed in new build:")
    for oc_line in (old_code.split('\n') if old_code else ["// removed"]):
        lines.append(f"-    {oc_line.strip()}")

    return lines


def _patch_added_packet_field(change, handler_name, real_context):
    """Generate patch lines for an added packet field."""
    lines = []
    new_code = change.new_code or "// new packet field"

    lines.append(f"@@ -1,0 +1,0 @@ void {handler_name}(...)")
    lines.append(f"+    // NEW in this build: Added packet field")
    # Attempt to parse the Read<> type from pseudocode
    read_match = re.search(r'Read\s*<\s*(\w+)\s*>', new_code)
    if read_match:
        field_type = read_match.group(1)
        lines.append(f"+    {field_type} newField = recv_data.Read<{field_type}>();")
    else:
        for nc_line in new_code.split('\n')[:5]:
            lines.append(f"+    {nc_line.strip()}")

    return lines


def _patch_removed_packet_field(change, handler_name, real_context):
    """Generate patch lines for a removed packet field."""
    lines = []
    old_code = change.old_code or "// removed field"

    lines.append(f"@@ -1,0 +1,0 @@ void {handler_name}(...)")
    lines.append(f"-    // REMOVED: Packet field no longer present")
    read_match = re.search(r'Read\s*<\s*(\w+)\s*>', old_code)
    if read_match:
        field_type = read_match.group(1)
        lines.append(f"-    {field_type} removedField = recv_data.Read<{field_type}>();")
    else:
        for oc_line in old_code.split('\n')[:5]:
            lines.append(f"-    {oc_line.strip()}")

    return lines


def _patch_changed_constant(change, handler_name, real_context):
    """Generate patch lines for a changed constant."""
    lines = []
    old_code = change.old_code or ""
    new_code = change.new_code or ""

    old_nums = re.findall(r'\b(0x[0-9A-Fa-f]+|\d{2,})\b', old_code)
    new_nums = re.findall(r'\b(0x[0-9A-Fa-f]+|\d{2,})\b', new_code)

    lines.append(f"@@ -1,0 +1,0 @@ void {handler_name}(...)")
    if old_nums and new_nums:
        for old_n, new_n in zip(old_nums, new_nums):
            if old_n != new_n:
                lines.append(f"-    // Old constant: {old_n}")
                lines.append(f"+    // New constant: {new_n}")
    else:
        for oc_line in old_code.split('\n')[:3]:
            lines.append(f"-    {oc_line.strip()}")
        for nc_line in new_code.split('\n')[:3]:
            lines.append(f"+    {nc_line.strip()}")

    return lines


def _patch_changed_enum(change, handler_name, real_context):
    """Generate patch lines for a changed enum value."""
    lines = []
    old_code = change.old_code or ""
    new_code = change.new_code or ""

    lines.append(f"@@ -1,0 +1,0 @@ // Enum value update")
    lines.append(f" // {change.description}")
    for oc_line in old_code.split('\n')[:5]:
        lines.append(f"-{oc_line}")
    for nc_line in new_code.split('\n')[:5]:
        lines.append(f"+{nc_line}")

    return lines


def _patch_added_logic(change, handler_name, real_context):
    """Generate patch lines for added logic."""
    lines = []
    new_code = change.new_code or "// new logic"

    lines.append(f"@@ -1,0 +1,0 @@ void {handler_name}(...)")
    lines.append(f"+    // NEW: {change.description}")
    for nc_line in new_code.split('\n')[:10]:
        lines.append(f"+    {nc_line.strip()}")

    return lines


def _patch_removed_logic(change, handler_name, real_context):
    """Generate patch lines for removed logic."""
    lines = []
    old_code = change.old_code or "// removed logic"

    lines.append(f"@@ -1,0 +1,0 @@ void {handler_name}(...)")
    lines.append(f"-    // REMOVED: {change.description}")
    for oc_line in old_code.split('\n')[:10]:
        lines.append(f"-    {oc_line.strip()}")

    return lines


def _patch_restructured(change, handler_name):
    """Generate advisory patch for a major restructuring."""
    lines = []
    lines.append(f"@@ -1,0 +1,0 @@ void {handler_name}(...)")
    lines.append(f" // WARNING: {handler_name} has been SIGNIFICANTLY restructured.")
    lines.append(f" // Similarity is below {int((1-RESTRUCTURED_THRESHOLD)*100)}%.")
    lines.append(f" // Manual review required. See migration report for details.")
    if change.old_code:
        lines.append(f" //")
        lines.append(f" // OLD (first 5 lines):")
        for oc_line in change.old_code.split('\n')[:5]:
            lines.append(f" // - {oc_line.strip()}")
    if change.new_code:
        lines.append(f" //")
        lines.append(f" // NEW (first 5 lines):")
        for nc_line in change.new_code.split('\n')[:5]:
            lines.append(f" // + {nc_line.strip()}")

    return lines


def _format_cpp_validation(pseudocode, description):
    """Convert pseudocode of a validation into C++ style code."""
    lines = []
    lines.append(f"    // NEW: {description}")

    # Try to parse the if-condition from pseudocode
    cond_match = re.search(r'if\s*\(([^)]+)\)', pseudocode)
    if cond_match:
        condition = cond_match.group(1).strip()
        lines.append(f"    if ({condition})")
        lines.append("    {")
        # Try to find the return/error
        ret_match = re.search(r'return\s+([\w_]+)', pseudocode)
        if ret_match:
            lines.append(f"        // Return: {ret_match.group(1)}")
            lines.append(f"        return;")
        else:
            lines.append(f"        return;")
        lines.append("    }")
    else:
        # Fallback: include raw pseudocode as comment
        for pc_line in pseudocode.split('\n')[:5]:
            stripped = pc_line.strip()
            if stripped:
                lines.append(f"    // {stripped}")

    return lines


# ---------------------------------------------------------------------------
# Phase 6: Migration Report Generation
# ---------------------------------------------------------------------------

def _build_migration_report(old_data, new_build, matched, unmatched_old,
                             unmatched_new, handler_changes, wire_format_changes,
                             constant_changes, enum_shifts, opcode_diff, elapsed):
    """Build the comprehensive migration report dictionary."""

    # Count by priority
    priority_counts = {
        PRIORITY_CRITICAL: 0,
        PRIORITY_HIGH: 0,
        PRIORITY_MEDIUM: 0,
        PRIORITY_LOW: 0,
    }
    all_changes = []
    for handler_name, changes in handler_changes.items():
        for c in changes:
            p = c.get("priority", PRIORITY_LOW) if isinstance(c, dict) else c.priority
            if p in priority_counts:
                priority_counts[p] += 1

    # Count unchanged vs changed
    unchanged_count = 0
    changed_count = 0
    for handler_name, changes in handler_changes.items():
        if not changes:
            unchanged_count += 1
        else:
            changed_count += 1

    # Build opcode diff
    new_opcodes = opcode_diff.get("new", [])
    removed_opcodes = opcode_diff.get("removed", [])

    # Build handler change list
    changed_handlers = []
    for handler_name, changes_list in handler_changes.items():
        if not changes_list:
            continue
        match_info = matched.get(handler_name)
        if not match_info:
            continue
        match_dict = match_info.to_dict() if hasattr(match_info, 'to_dict') else match_info

        # Determine opcode name
        opcode_name = None
        for tc_name, op in old_data.opcodes.items():
            if op.get("handler_ea") == match_dict.get("old_ea"):
                opcode_name = tc_name
                break
        if not opcode_name:
            opcode_name = handler_name

        # Determine system
        system = _classify_system(opcode_name)

        handler_entry = {
            "handler": handler_name,
            "opcode": opcode_name,
            "match_confidence": match_dict.get("confidence", 0),
            "match_strategy": match_dict.get("strategy", "unknown"),
            "changes": changes_list,
            "system": system,
        }
        changed_handlers.append(handler_entry)

    # Sort by priority (critical first)
    priority_order = {PRIORITY_CRITICAL: 0, PRIORITY_HIGH: 1,
                      PRIORITY_MEDIUM: 2, PRIORITY_LOW: 3}
    changed_handlers.sort(
        key=lambda h: min(
            (priority_order.get(
                c.get("priority", PRIORITY_LOW) if isinstance(c, dict)
                else PRIORITY_LOW, 3)
             for c in h["changes"]),
            default=3,
        )
    )

    report = {
        "old_build": old_data.build_number,
        "new_build": new_build,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_seconds": round(elapsed, 1),
        "summary": {
            "total_functions_matched": len(matched),
            "unmatched_old": len(unmatched_old),
            "unmatched_new": len(unmatched_new),
            "unchanged": unchanged_count,
            "changed": changed_count,
            "critical_changes": priority_counts[PRIORITY_CRITICAL],
            "high_changes": priority_counts[PRIORITY_HIGH],
            "medium_changes": priority_counts[PRIORITY_MEDIUM],
            "low_changes": priority_counts[PRIORITY_LOW],
        },
        "new_opcodes": new_opcodes,
        "removed_opcodes": removed_opcodes,
        "changed_handlers": changed_handlers,
        "wire_format_changes": wire_format_changes,
        "constant_changes": constant_changes,
        "enum_shifts": enum_shifts,
        "match_strategy_breakdown": _strategy_breakdown(matched),
        "unmatched_old_sample": unmatched_old[:50],
        "unmatched_new_sample": unmatched_new[:50],
    }

    return report


def _strategy_breakdown(matched):
    """Count matches by strategy."""
    counts = defaultdict(int)
    for name, m in matched.items():
        strategy = m.strategy if hasattr(m, 'strategy') else m.get("strategy", "unknown")
        counts[strategy] += 1
    return dict(counts)


def _diff_opcodes(old_data, session):
    """Diff opcodes between old and new builds.

    Returns dict with 'new', 'removed', and 'changed' lists.
    """
    db = session.db
    result = {"new": [], "removed": [], "changed": []}

    new_opcodes = {}
    try:
        rows = db.fetchall("SELECT * FROM opcodes WHERE tc_name IS NOT NULL")
        for row in rows:
            new_opcodes[row["tc_name"]] = dict(row)
    except Exception:
        pass

    old_names = set(old_data.opcodes.keys())
    new_names = set(new_opcodes.keys())

    for name in sorted(new_names - old_names):
        op = new_opcodes[name]
        result["new"].append({
            "tc_name": name,
            "direction": op.get("direction"),
            "internal_index": op.get("internal_index"),
            "wire_opcode": op.get("wire_opcode"),
            "system": _classify_system(name),
        })

    for name in sorted(old_names - new_names):
        op = old_data.opcodes[name]
        result["removed"].append({
            "tc_name": name,
            "direction": op.get("direction"),
            "internal_index": op.get("internal_index"),
            "wire_opcode": op.get("wire_opcode"),
            "system": _classify_system(name),
        })

    for name in sorted(old_names & new_names):
        old_op = old_data.opcodes[name]
        new_op = new_opcodes[name]
        changes = []

        if old_op.get("wire_opcode") != new_op.get("wire_opcode"):
            changes.append({
                "field": "wire_opcode",
                "old": old_op.get("wire_opcode"),
                "new": new_op.get("wire_opcode"),
            })

        if old_op.get("internal_index") != new_op.get("internal_index"):
            changes.append({
                "field": "internal_index",
                "old": old_op.get("internal_index"),
                "new": new_op.get("internal_index"),
            })

        if changes:
            result["changed"].append({
                "tc_name": name,
                "direction": new_op.get("direction"),
                "changes": changes,
                "system": _classify_system(name),
            })

    return result


def _diff_wire_formats_cross_build(old_data, session):
    """Diff wire format definitions between builds.

    Returns a list of change dicts.
    """
    changes = []
    new_wire_formats = session.db.kv_get("wire_formats") or {}

    all_opcodes = set(old_data.wire_formats.keys()) | set(new_wire_formats.keys())

    for opcode_name in sorted(all_opcodes):
        old_fmt = old_data.wire_formats.get(opcode_name, {})
        new_fmt = new_wire_formats.get(opcode_name, {})

        old_fields = old_fmt.get("fields", []) if isinstance(old_fmt, dict) else []
        new_fields = new_fmt.get("fields", []) if isinstance(new_fmt, dict) else []

        if old_fields == new_fields:
            continue

        if not old_fields and new_fields:
            changes.append({
                "opcode": opcode_name,
                "type": "new_format",
                "field_count": len(new_fields),
                "system": _classify_system(opcode_name),
            })
        elif old_fields and not new_fields:
            changes.append({
                "opcode": opcode_name,
                "type": "removed_format",
                "field_count": len(old_fields),
                "system": _classify_system(opcode_name),
            })
        else:
            # Detail changes
            old_types = [_field_type_str(f) for f in old_fields]
            new_types = [_field_type_str(f) for f in new_fields]
            if old_types != new_types:
                changes.append({
                    "opcode": opcode_name,
                    "type": "changed_layout",
                    "old_fields": len(old_fields),
                    "new_fields": len(new_fields),
                    "old_signature": ", ".join(old_types),
                    "new_signature": ", ".join(new_types),
                    "system": _classify_system(opcode_name),
                })

    return changes


def _field_type_str(field):
    """Generate a concise type string for a wire format field."""
    if isinstance(field, dict):
        ftype = field.get("type", "?")
        if ftype == "bits":
            return f"bits({field.get('bit_size', '?')})"
        return ftype
    return str(field)


def _collect_constant_changes(handler_changes):
    """Extract all constant changes from handler changes."""
    constants = []
    for handler_name, changes in handler_changes.items():
        for c in changes:
            ct = c.get("type") if isinstance(c, dict) else getattr(c, "change_type", None)
            if ct == CHANGE_CHANGED_CONSTANT:
                entry = c if isinstance(c, dict) else c.to_dict()
                entry["handler"] = handler_name
                constants.append(entry)
    return constants


def _collect_enum_shifts(handler_changes):
    """Extract all enum value shifts from handler changes."""
    enums = []
    for handler_name, changes in handler_changes.items():
        for c in changes:
            ct = c.get("type") if isinstance(c, dict) else getattr(c, "change_type", None)
            if ct == CHANGE_CHANGED_ENUM_VALUE:
                entry = c if isinstance(c, dict) else c.to_dict()
                entry["handler"] = handler_name
                enums.append(entry)
    return enums


# ---------------------------------------------------------------------------
# Phase 7: Export Functions
# ---------------------------------------------------------------------------

def export_migration_patches(session, output_dir):
    """Write all generated patches to individual .patch files.

    Args:
        session: PluginSession
        output_dir: Directory to write patches into

    Returns:
        int: Number of patch files written
    """
    report = get_migration_report(session)
    if not report:
        msg_error("No migration report available. Run generate_migration() first.")
        return 0

    os.makedirs(output_dir, exist_ok=True)

    count = 0
    for handler_entry in report.get("changed_handlers", []):
        handler_name = handler_entry.get("handler", "unknown")
        for i, change in enumerate(handler_entry.get("changes", [])):
            patch = change.get("tc_patch")
            if not patch:
                continue
            safe_name = re.sub(r'[^\w\-.]', '_', handler_name)
            filename = f"{safe_name}_{i:02d}.patch"
            filepath = os.path.join(output_dir, filename)
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(patch)
                count += 1
            except Exception as e:
                msg_warn(f"Could not write patch {filepath}: {e}")

    # Also write a combined patch
    if count > 0:
        combined_path = os.path.join(output_dir, "combined_migration.patch")
        try:
            with open(combined_path, "w", encoding="utf-8") as f:
                f.write(f"# Cross-build migration patches\n")
                f.write(f"# Old build: {report.get('old_build', '?')}\n")
                f.write(f"# New build: {report.get('new_build', '?')}\n")
                f.write(f"# Generated: {report.get('timestamp', '')}\n\n")
                for handler_entry in report.get("changed_handlers", []):
                    for change in handler_entry.get("changes", []):
                        patch = change.get("tc_patch")
                        if patch:
                            f.write(f"# Handler: {handler_entry.get('handler')}\n")
                            f.write(f"# Priority: {change.get('priority', '?')}\n")
                            f.write(patch)
                            f.write("\n")
            count += 1
        except Exception as e:
            msg_warn(f"Could not write combined patch: {e}")

    msg_info(f"Wrote {count} patch files to {output_dir}")
    return count


def export_migration_report(session, output_path):
    """Write the full migration report as JSON.

    Args:
        session: PluginSession
        output_path: File path to write the report to

    Returns:
        bool: True on success
    """
    report = get_migration_report(session)
    if not report:
        msg_error("No migration report available. Run generate_migration() first.")
        return False

    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        msg_info(f"Migration report written to {output_path}")
        return True
    except Exception as e:
        msg_error(f"Could not write report: {e}")
        return False


def get_critical_changes(session):
    """Return only CRITICAL and HIGH priority changes.

    Returns:
        list of change dicts, or empty list
    """
    report = get_migration_report(session)
    if not report:
        return []

    critical = []
    for handler_entry in report.get("changed_handlers", []):
        for change in handler_entry.get("changes", []):
            priority = change.get("priority", PRIORITY_LOW)
            if priority in (PRIORITY_CRITICAL, PRIORITY_HIGH):
                entry = dict(change)
                entry["handler"] = handler_entry.get("handler")
                entry["opcode"] = handler_entry.get("opcode")
                critical.append(entry)

    return critical


def get_new_opcodes(session):
    """Return opcodes that exist in the new build but not the old.

    Returns:
        list of opcode info dicts, or empty list
    """
    report = get_migration_report(session)
    if not report:
        return []
    return report.get("new_opcodes", [])


def get_wire_format_changes(session):
    """Return wire format (packet structure) changes between builds.

    Returns:
        list of change dicts, or empty list
    """
    report = get_migration_report(session)
    if not report:
        return []
    return report.get("wire_format_changes", [])


def get_handler_changes(session, handler_name):
    """Return changes for a specific handler.

    Args:
        session: PluginSession
        handler_name: The handler/opcode name to look up

    Returns:
        dict with handler info and changes, or None
    """
    report = get_migration_report(session)
    if not report:
        return None

    for handler_entry in report.get("changed_handlers", []):
        if (handler_entry.get("handler") == handler_name or
                handler_entry.get("opcode") == handler_name):
            return handler_entry

    return None


def print_migration_summary(session):
    """Print a human-readable migration summary to IDA output window."""
    report = get_migration_report(session)
    if not report:
        msg_error("No migration data. Run generate_migration() first.")
        return

    summary = report.get("summary", {})
    msg("")
    msg("=" * 70)
    msg(f"  CROSS-BUILD MIGRATION REPORT")
    msg(f"  Build {report.get('old_build', '?')} -> {report.get('new_build', '?')}")
    msg(f"  Generated: {report.get('timestamp', 'unknown')}")
    msg(f"  Elapsed: {report.get('elapsed_seconds', 0):.1f}s")
    msg("=" * 70)
    msg("")

    msg(f"  Functions matched:    {summary.get('total_functions_matched', 0)}")
    msg(f"  Unmatched (old):      {summary.get('unmatched_old', 0)}")
    msg(f"  Unmatched (new):      {summary.get('unmatched_new', 0)}")
    msg(f"  Unchanged handlers:   {summary.get('unchanged', 0)}")
    msg(f"  Changed handlers:     {summary.get('changed', 0)}")
    msg("")

    msg(f"  CRITICAL changes:     {summary.get('critical_changes', 0)}")
    msg(f"  HIGH changes:         {summary.get('high_changes', 0)}")
    msg(f"  MEDIUM changes:       {summary.get('medium_changes', 0)}")
    msg(f"  LOW changes:          {summary.get('low_changes', 0)}")
    msg("")

    # Strategy breakdown
    breakdown = report.get("match_strategy_breakdown", {})
    if breakdown:
        msg("  Match strategy breakdown:")
        for strategy, count in sorted(breakdown.items(), key=lambda x: -x[1]):
            msg(f"    {strategy}: {count}")
        msg("")

    # New opcodes
    new_ops = report.get("new_opcodes", [])
    if new_ops:
        msg(f"  NEW OPCODES ({len(new_ops)}):")
        for op in new_ops[:20]:
            msg(f"    + {op.get('tc_name', '?')} ({op.get('direction', '?')}) "
                f"[{op.get('system', 'unknown')}]")
        if len(new_ops) > 20:
            msg(f"    ... and {len(new_ops) - 20} more")
        msg("")

    # Removed opcodes
    removed_ops = report.get("removed_opcodes", [])
    if removed_ops:
        msg(f"  REMOVED OPCODES ({len(removed_ops)}):")
        for op in removed_ops[:20]:
            msg(f"    - {op.get('tc_name', '?')} ({op.get('direction', '?')}) "
                f"[{op.get('system', 'unknown')}]")
        if len(removed_ops) > 20:
            msg(f"    ... and {len(removed_ops) - 20} more")
        msg("")

    # Critical/High changes detail
    critical = get_critical_changes(session)
    if critical:
        msg(f"  CRITICAL/HIGH PRIORITY CHANGES ({len(critical)}):")
        msg("-" * 70)
        for i, c in enumerate(critical[:30]):
            priority_marker = "!!!" if c.get("priority") == PRIORITY_CRITICAL else " ! "
            msg(f"  {priority_marker} [{c.get('priority', '?')}] "
                f"{c.get('handler', '?')}")
            msg(f"       {c.get('type', '?')}: {c.get('description', '')[:80]}")
            if c.get("breaking"):
                msg(f"       ** BREAKING CHANGE **")
            if c.get("tc_files_affected"):
                msg(f"       Files: {', '.join(c['tc_files_affected'][:3])}")
            msg("")
        if len(critical) > 30:
            msg(f"  ... and {len(critical) - 30} more critical/high changes")
        msg("")

    # Wire format changes
    wire_changes = report.get("wire_format_changes", [])
    if wire_changes:
        msg(f"  WIRE FORMAT CHANGES ({len(wire_changes)}):")
        for wc in wire_changes[:15]:
            msg(f"    {wc.get('opcode', '?')}: {wc.get('type', '?')} "
                f"[{wc.get('system', 'unknown')}]")
        if len(wire_changes) > 15:
            msg(f"    ... and {len(wire_changes) - 15} more")
        msg("")

    msg("=" * 70)
    msg(f"  Use export_migration_patches() to write .patch files")
    msg(f"  Use export_migration_report() to write full JSON report")
    msg("=" * 70)
    msg("")


# ---------------------------------------------------------------------------
# Main Entry Points
# ---------------------------------------------------------------------------

def generate_migration(session, old_db_path=None):
    """Run the full cross-build migration pipeline.

    Args:
        session: PluginSession with an initialized knowledge DB
        old_db_path: Path to a previous build's .tc_wow.db file.
                     If None, checks kv_store for 'previous_build_db_path'.
                     If still None, scans for .sqlite/.db files near the IDB.

    Returns:
        int: Total number of migration items (changes) found
    """
    db = session.db
    cfg = session.cfg
    start = time.time()

    msg("")
    msg("=" * 70)
    msg("  CROSS-BUILD MIGRATION PIPELINE")
    msg("=" * 70)
    msg("")

    # ── Resolve old DB path ──────────────────────────────────────
    if not old_db_path:
        old_db_path = db.kv_get(KV_PREV_DB_PATH)
        if old_db_path:
            msg_info(f"Using stored previous build DB: {old_db_path}")

    if not old_db_path:
        old_db_path = _auto_discover_old_db(session)

    if not old_db_path:
        msg_error("No old build database found. Pass old_db_path explicitly, "
                  "or set kv_store key 'previous_build_db_path'.")
        return 0

    # Store for future runs
    db.kv_set(KV_PREV_DB_PATH, old_db_path)
    db.commit()

    # ── Phase 1: Load old build ─────────────────────────────────
    msg_info("Phase 1: Loading old build data...")
    phase1_start = time.time()
    old_data = _load_old_build(old_db_path)
    if not old_data:
        msg_error("Failed to load old build data.")
        return 0
    msg_info(f"Phase 1 complete in {time.time() - phase1_start:.1f}s")

    # ── Phase 2: Function matching ──────────────────────────────
    msg_info("Phase 2: Building function index and matching...")
    phase2_start = time.time()
    new_index = _build_new_function_index(session)
    matched, unmatched_old, unmatched_new = _match_functions(
        old_data, new_index, session)
    msg_info(f"Phase 2 complete in {time.time() - phase2_start:.1f}s")

    # Store matches in diffing table
    for old_name, match in matched.items():
        try:
            db.execute(
                """INSERT OR REPLACE INTO diffing
                   (old_ea, new_ea, match_type, confidence,
                    old_build, new_build)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (match.old_ea, match.new_ea, match.strategy,
                 match.confidence / 100.0,
                 old_data.build_number, cfg.build_number))
        except Exception:
            pass
    db.commit()

    # ── Phase 3: Semantic diff ──────────────────────────────────
    msg_info("Phase 3: Semantic diffing of matched functions...")
    phase3_start = time.time()
    handler_changes = {}
    decomp_count = 0

    for old_name, match in matched.items():
        if decomp_count >= MAX_DECOMP_ATTEMPTS:
            msg_warn(f"Reached decompilation limit ({MAX_DECOMP_ATTEMPTS}). "
                     f"Skipping remaining functions.")
            break

        changes = _diff_function_pair(match, old_data, session)
        if changes:
            handler_changes[old_name] = [c.to_dict() for c in changes]
        else:
            handler_changes[old_name] = []
        decomp_count += 1

        if decomp_count % PROGRESS_INTERVAL == 0:
            msg(f"  Diffed {decomp_count}/{len(matched)} functions...")

    msg_info(f"Phase 3 complete in {time.time() - phase3_start:.1f}s "
             f"({decomp_count} functions diffed)")

    # ── Phase 4: Impact assessment ──────────────────────────────
    msg_info("Phase 4: Impact assessment...")
    phase4_start = time.time()
    for old_name, match in matched.items():
        changes_list = handler_changes.get(old_name)
        if not changes_list:
            continue
        # Re-wrap as SemanticChange objects for assessment
        semantic_changes = []
        for cd in changes_list:
            sc = SemanticChange(
                change_type=cd.get("type", CHANGE_UNCHANGED),
                description=cd.get("description", ""),
                old_code=cd.get("old_code"),
                new_code=cd.get("new_code"),
                priority=cd.get("priority", PRIORITY_LOW),
                system=cd.get("system", "unknown"),
                tc_files=cd.get("tc_files_affected", []),
                breaking=cd.get("breaking", False),
            )
            semantic_changes.append(sc)
        _assess_impact(semantic_changes, match, old_data)
        # Write back
        handler_changes[old_name] = [sc.to_dict() for sc in semantic_changes]
    msg_info(f"Phase 4 complete in {time.time() - phase4_start:.1f}s")

    # ── Phase 5: Patch generation ───────────────────────────────
    msg_info("Phase 5: Generating TC patches...")
    phase5_start = time.time()
    tc_source_dir = cfg.tc_source_dir or None
    patch_count = 0

    for old_name, match in matched.items():
        changes_list = handler_changes.get(old_name, [])
        for change_dict in changes_list:
            sc = SemanticChange(
                change_type=change_dict.get("type", CHANGE_UNCHANGED),
                description=change_dict.get("description", ""),
                old_code=change_dict.get("old_code"),
                new_code=change_dict.get("new_code"),
                priority=change_dict.get("priority", PRIORITY_LOW),
                system=change_dict.get("system", "unknown"),
                tc_files=change_dict.get("tc_files_affected", []),
                breaking=change_dict.get("breaking", False),
            )
            patch = _generate_patch(sc, match, tc_source_dir)
            if patch:
                change_dict["tc_patch"] = patch
                patch_count += 1
    msg_info(f"Phase 5 complete in {time.time() - phase5_start:.1f}s "
             f"({patch_count} patches generated)")

    # ── Phase 6: Report assembly ────────────────────────────────
    msg_info("Phase 6: Building migration report...")
    phase6_start = time.time()

    opcode_diff = _diff_opcodes(old_data, session)
    wire_format_changes = _diff_wire_formats_cross_build(old_data, session)
    constant_changes = _collect_constant_changes(handler_changes)
    enum_shifts = _collect_enum_shifts(handler_changes)

    elapsed = time.time() - start
    report = _build_migration_report(
        old_data=old_data,
        new_build=cfg.build_number,
        matched=matched,
        unmatched_old=unmatched_old,
        unmatched_new=unmatched_new,
        handler_changes=handler_changes,
        wire_format_changes=wire_format_changes,
        constant_changes=constant_changes,
        enum_shifts=enum_shifts,
        opcode_diff=opcode_diff,
        elapsed=elapsed,
    )

    # Store in kv_store
    db.kv_set(KV_KEY, report)
    db.commit()

    msg_info(f"Phase 6 complete in {time.time() - phase6_start:.1f}s")

    total_changes = sum(
        len(changes) for changes in handler_changes.values() if changes
    )

    msg("")
    msg_info(f"Migration pipeline complete: {total_changes} changes found "
             f"in {elapsed:.1f}s")
    msg("")

    # Print summary
    print_migration_summary(session)

    return total_changes


def get_migration_report(session):
    """Retrieve the stored migration report from the knowledge DB.

    Args:
        session: PluginSession

    Returns:
        dict: The migration report, or None if not available
    """
    if not session.db:
        return None
    return session.db.kv_get(KV_KEY)


# ---------------------------------------------------------------------------
# Auto-discovery
# ---------------------------------------------------------------------------

def _auto_discover_old_db(session):
    """Try to find a previous build's knowledge DB automatically.

    Search strategy:
      1. Look for .tc_wow.db files in the same directory as the current IDB
      2. Look for .sqlite files in the same directory
      3. Look in the extraction directory
      4. Look in parent directories

    Returns:
        str: Path to the old DB, or None
    """
    current_db = session.db.path if session.db else None
    if not current_db:
        return None

    current_dir = os.path.dirname(current_db)
    current_build = session.cfg.build_number

    msg_info(f"Auto-discovering previous build DB near {current_dir}...")

    candidates = []

    # Search current directory and parent
    search_dirs = [current_dir]
    parent = os.path.dirname(current_dir)
    if parent != current_dir:
        search_dirs.append(parent)

    # Also check extraction directory
    ext_dir = session.cfg.extraction_dir
    if ext_dir and os.path.isdir(ext_dir):
        search_dirs.append(ext_dir)

    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        try:
            for fname in os.listdir(search_dir):
                fpath = os.path.join(search_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                if fpath == current_db:
                    continue

                _, ext = os.path.splitext(fname)
                if ext not in (".db", ".sqlite", ".sqlite3"):
                    continue

                # Check if it looks like a knowledge DB
                if ".tc_wow." in fname or "knowledge" in fname.lower():
                    # Try to detect build number
                    build_match = re.search(r'(\d{5,6})', fname)
                    build_num = int(build_match.group(1)) if build_match else 0
                    if build_num and build_num != current_build:
                        candidates.append((fpath, build_num))
                    elif not build_num:
                        # Try opening and checking
                        try:
                            test_conn = sqlite3.connect(
                                f"file:{fpath}?mode=ro", uri=True, timeout=5)
                            test_conn.row_factory = sqlite3.Row
                            # Check if it has our tables
                            tables = [r[0] for r in test_conn.execute(
                                "SELECT name FROM sqlite_master "
                                "WHERE type='table'").fetchall()]
                            if "opcodes" in tables and "functions" in tables:
                                candidates.append((fpath, 0))
                            test_conn.close()
                        except Exception:
                            pass
        except Exception:
            pass

    if not candidates:
        msg_warn("No previous build DB found automatically.")
        return None

    # Sort by build number (descending), prefer the most recent old build
    candidates.sort(key=lambda x: x[1], reverse=True)

    chosen = candidates[0][0]
    build = candidates[0][1]
    msg_info(f"Auto-discovered old build DB: {chosen} (build {build})")
    return chosen
