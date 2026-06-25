"""
Subsystem Catalog Analyzer

Tags every named function with a subsystem (housing, garrison, auction, quest,
guild, achievement, etc.) using multiple signals fused with confidence scoring.

Why this exists: "show me everything related to housing in this build" used to
require grepping strings + RTTI + opcode names by hand. This analyzer turns that
into a first-class kv lookup with stats per subsystem.

Signals (each contributes weighted votes):
  1. Function name keyword matching (e.g. "HandleHousingPlot...")
  2. Opcode dispatcher routing (which opcodes does this handler serve)
  3. RTTI class name (vtables -> class_name pattern matching)
  4. String literal references (functions referencing housing-tagged strings)
  5. Call graph cluster (function calls into other already-classified funcs)

Outputs:
  kv_store["subsystem_catalog"] = {
      "version": 1,
      "by_function": {ea: {"subsystem": str, "confidence": float, "signals": [...]}},
      "by_subsystem": {name: {
          "function_count": int,
          "entry_points": [ea, ...],     # opcode handlers + RTTI roots
          "opcodes": [name, ...],
          "vtable_classes": [name, ...],
          "total_size_bytes": int,
      }}
  }
"""

import time
from collections import defaultdict

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn

# Subsystem keyword patterns. Keys are subsystem ids; values are case-insensitive
# substrings that, if found in a function name / string ref / RTTI class name,
# vote for that subsystem.
SUBSYSTEM_KEYWORDS = {
    "housing":       ["housing", "neighborhood", "plot", "decor"],
    "garrison":      ["garrison", "shipyard", "follower"],
    "auction":       ["auction", "ahbid", "auctionhouse", "ahbidder"],
    "quest":         ["quest", "objective", "questgiver", "questlog"],
    "guild":         ["guild", "guildbank", "guildperk", "guildachievement"],
    "achievement":   ["achievement", "criteria", "criteriaobjective"],
    "battleground":  ["battleground", "bg_", "arena", "rated_"],
    "calendar":      ["calendar", "calendarevent", "rsvp"],
    "lfg":           ["lfg", "lfgrole", "groupfinder", "dungeonfinder"],
    "mail":          ["mail", "mailbox", "cod_"],
    "social":        ["social", "friend", "ignore", "battlenet", "bnet"],
    "trade":         ["trade", "tradeskill", "barter"],
    "spell":         ["spell", "aura", "cast", "spelleffect"],
    "combat":        ["combat", "damage", "threat", "hostility"],
    "movement":      ["movement", "moveinfo", "transport", "vehicle"],
    "loot":          ["loot", "lootitem", "rolloff"],
    "talent":        ["talent", "specialization", "glyph"],
    "pet":           ["pet_", "pets_", "petname", "petbattle"],
    "currency":      ["currency", "coin", "honorpoint", "conquestpoint"],
    "inventory":     ["inventory", "bag_", "container", "equipment"],
    "auth":          ["auth", "logon", "session", "realm", "handshake"],
    "world":         ["world", "worldsession", "worldpacket"],
    "chat":          ["chat", "chatfilter", "whisper", "addonmsg"],
    "trainer":       ["trainer", "training"],
    "questturn":     ["questreward", "questturnin"],
    "warcampaign":   ["warcampaign", "campaign"],
    "covenant":      ["covenant", "soulbind", "anima", "conduit"],
    "torghast":      ["torghast", "jailer", "anima"],
    "mythic":        ["mythicplus", "keystone", "challengemode"],
    "transmog":      ["transmog", "wardrobe", "appearance"],
    "mount":         ["mount_", "mountcollection", "mountspecial"],
    "toy":           ["toy_", "toybox"],
    "pvp":           ["pvp", "honorlevel", "conquest", "warmode"],
}

# Strong direct hits get full weight; weak (sub-string within a longer name)
# get half. Multiple signals sum.
WEIGHT_NAME_DIRECT = 4
WEIGHT_NAME_FUZZY = 2
WEIGHT_OPCODE = 5         # opcode dispatcher routing is the strongest signal
WEIGHT_RTTI = 4
WEIGHT_STRING_REF = 1     # weakest — strings can be misleading
WEIGHT_CALL_GRAPH = 1     # propagation from already-classified callees

# Minimum total weight required before we tag a function. Lower -> more aggressive.
MIN_CONFIDENCE_WEIGHT = 4


def _classify_name(name: str):
    """Return list of (subsystem, weight) votes from a function/string/class name."""
    if not name:
        return []
    lower = name.lower()
    votes = []
    for subsys, kws in SUBSYSTEM_KEYWORDS.items():
        for kw in kws:
            kwl = kw.lower()
            if kwl in lower:
                # "Direct" if keyword appears at a word boundary; cheap heuristic:
                # bordering char before/after is not alphanumeric.
                idx = lower.find(kwl)
                left_ok = idx == 0 or not lower[idx - 1].isalnum()
                right_idx = idx + len(kwl)
                right_ok = right_idx >= len(lower) or not lower[right_idx].isalnum()
                w = WEIGHT_NAME_DIRECT if (left_ok and right_ok) else WEIGHT_NAME_FUZZY
                votes.append((subsys, w))
                break  # one keyword hit per subsystem is enough
    return votes


def build_subsystem_catalog(session):
    """Main entry point. Builds the catalog and stores it in kv_store."""
    db = session.db
    if db is None:
        msg_warn("Subsystem Catalog: no DB")
        return 0

    t0 = time.time()
    msg_info("Subsystem Catalog: classifying named functions...")

    # ── Pass 1: collect all named functions ──
    try:
        fn_rows = db.fetchall(
            "SELECT ea, name, system FROM functions "
            "WHERE name IS NOT NULL AND name NOT LIKE 'sub_%' AND name NOT LIKE 'j_%'"
        )
    except Exception as e:
        msg_warn(f"Subsystem Catalog: function query failed: {e}")
        return 0

    fn_count = len(fn_rows)
    msg_info(f"  Classifying {fn_count} named functions")

    # subsystem votes per function
    votes_by_ea = defaultdict(lambda: defaultdict(int))     # ea -> {subsys -> weight}
    signals_by_ea = defaultdict(list)                        # ea -> [signal strings]
    name_by_ea = {}

    for row in fn_rows:
        ea = row["ea"]
        name = row["name"]
        name_by_ea[ea] = name
        for subsys, w in _classify_name(name):
            votes_by_ea[ea][subsys] += w
            signals_by_ea[ea].append(f"name:{subsys}({w})")

    # ── Pass 2: opcode dispatcher routing (column is tc_name, not name) ──
    opcode_to_handler = {}
    try:
        for row in db.fetchall(
            "SELECT tc_name, handler_ea FROM opcodes "
            "WHERE handler_ea IS NOT NULL AND tc_name IS NOT NULL"
        ):
            opcode_to_handler[row["tc_name"]] = row["handler_ea"]
    except Exception:
        pass

    for opc_name, handler_ea in opcode_to_handler.items():
        for subsys, w in _classify_name(opc_name):
            votes_by_ea[handler_ea][subsys] += WEIGHT_OPCODE
            signals_by_ea[handler_ea].append(f"opcode:{opc_name}->{subsys}")

    # ── Pass 3: RTTI / vtable class names ──
    vt_classes_by_subsys = defaultdict(list)
    try:
        vt_rows = db.fetchall(
            "SELECT class_name, vtable_ea FROM vtables "
            "WHERE class_name IS NOT NULL AND class_name != ''"
        )
    except Exception:
        vt_rows = []

    for row in vt_rows:
        cname = row["class_name"]
        vt_ea = row["vtable_ea"]
        cls_votes = _classify_name(cname)
        if cls_votes:
            # Pick the strongest subsystem for this class
            cls_votes.sort(key=lambda x: -x[1])
            best_sub = cls_votes[0][0]
            vt_classes_by_subsys[best_sub].append(cname)
        # Vote for every vtable method (functions in vtable_entries)
        try:
            for ent in db.fetchall(
                "SELECT func_ea FROM vtable_entries WHERE vtable_ea = ?",
                (vt_ea,)
            ):
                fn_ea = ent["func_ea"]
                for subsys, w in cls_votes:
                    votes_by_ea[fn_ea][subsys] += WEIGHT_RTTI
                    signals_by_ea[fn_ea].append(f"rtti:{cname}->{subsys}")
        except Exception:
            continue

    # ── Pass 4: per-string subsystem tag (autodump pre-tagged 23K strings) ──
    # We can't xref strings -> functions without a string_xrefs table, but we
    # can use the autodump's already-classified `strings.system` to amplify
    # subsystem signals on functions whose name matches a tagged string token.
    try:
        str_rows = db.fetchall(
            "SELECT value, system FROM strings "
            "WHERE system IS NOT NULL AND length(value) BETWEEN 4 AND 80"
        )
    except Exception:
        str_rows = []

    # Build a subsystem -> set of distinctive tokens map
    tag_tokens = defaultdict(set)
    for row in str_rows:
        sub = row["system"] or ""
        if sub not in SUBSYSTEM_KEYWORDS:
            continue
        for tok in (row["value"] or "").split():
            tok = tok.strip(",.;:!?[](){}<>\"'").lower()
            if 4 <= len(tok) <= 30:
                tag_tokens[sub].add(tok)

    # Cross-reference function names against these subsystem-distinctive tokens
    for ea, fname in name_by_ea.items():
        if not fname:
            continue
        lname = fname.lower()
        for sub, toks in tag_tokens.items():
            for tok in toks:
                if tok in lname:
                    votes_by_ea[ea][sub] += WEIGHT_STRING_REF
                    signals_by_ea[ea].append(f"strtok:{sub}")
                    break

    # ── Resolve votes: each function gets the highest-scoring subsystem if it
    # exceeds MIN_CONFIDENCE_WEIGHT, with confidence = winner_weight / total_weight ──
    by_function = {}
    by_subsystem_funcs = defaultdict(list)

    for ea, subsys_weights in votes_by_ea.items():
        if not subsys_weights:
            continue
        total = sum(subsys_weights.values())
        winner = max(subsys_weights.items(), key=lambda x: x[1])
        if winner[1] < MIN_CONFIDENCE_WEIGHT:
            continue
        confidence = round(winner[1] / total, 2)
        by_function[ea] = {
            "subsystem": winner[0],
            "confidence": confidence,
            "signals": signals_by_ea[ea][:6],   # cap signals for storage
        }
        by_subsystem_funcs[winner[0]].append(ea)

    # ── Build per-subsystem stats ──
    by_subsystem = {}
    for subsys, eas in by_subsystem_funcs.items():
        # Entry points: opcode handlers tagged with this subsystem
        entrypoints = [
            handler_ea for opc, handler_ea in opcode_to_handler.items()
            if any(s == subsys for s, _ in _classify_name(opc))
            and handler_ea in by_function
        ]
        opcodes_for = sorted({
            opc for opc, handler_ea in opcode_to_handler.items()
            if handler_ea in by_function and by_function[handler_ea]["subsystem"] == subsys
        })
        by_subsystem[subsys] = {
            "function_count": len(eas),
            "entry_points": entrypoints[:200],
            "opcodes": opcodes_for[:200],
            "vtable_classes": sorted(set(vt_classes_by_subsys.get(subsys, [])))[:200],
        }

    # ── Persist ──
    catalog = {
        "version": 1,
        "by_function": by_function,
        "by_subsystem": by_subsystem,
        "elapsed_sec": round(time.time() - t0, 2),
        "generated_at": time.time(),
    }
    db.kv_set("subsystem_catalog", catalog)
    db.commit()

    # Also propagate to functions.subsystem column for SQL queries
    try:
        for ea, info in by_function.items():
            db.execute(
                "UPDATE functions SET subsystem = ?, confidence = ? WHERE ea = ?",
                (info["subsystem"], int(info["confidence"] * 100), ea),
            )
        db.commit()
    except Exception as e:
        msg_warn(f"Subsystem Catalog: failed to update functions.subsystem: {e}")

    msg_info(
        f"Subsystem Catalog: tagged {len(by_function)} functions across "
        f"{len(by_subsystem)} subsystems in {catalog['elapsed_sec']}s"
    )
    # Top 10 subsystems by size
    top = sorted(by_subsystem.items(), key=lambda x: -x[1]["function_count"])[:10]
    for sub, stats in top:
        msg(f"  {sub}: {stats['function_count']} fns, "
            f"{len(stats['opcodes'])} opcodes, "
            f"{len(stats['vtable_classes'])} classes")

    return len(by_function)


def get_catalog(session):
    return session.db.kv_get("subsystem_catalog")


def get_functions_in_subsystem(session, subsystem_name):
    cat = get_catalog(session)
    if not cat:
        return []
    return [
        ea for ea, info in cat.get("by_function", {}).items()
        if info.get("subsystem") == subsystem_name
    ]
