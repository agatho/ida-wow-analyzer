"""
TC Opcode Cross-Reference
=========================
Parses TrinityCore source `Opcodes.h` from the master worktree and any feature
branches present, extracts CMSG_/SMSG_ name → TC value mappings, and produces:

  - `tc_opcodes_<build>.json` — full multi-branch opcode catalog
  - per-topic Markdown digests (delve / garrison / housing / warband /
    neighborhood / follower) under `c:/dumps/TC_<TOPIC>_OPCODES.md`
  - kv_store["tc_opcode_xref"] with totals

The plugin's `opcodes` SQLite table holds binary-side opcode handlers; this
analyzer is the source-side counterpart. Cross-referencing the two by name
match yields a binary handler ↔ TC name map that gets used by Cross-Analyzer
Synthesis and Handler Scaffolding.

Idempotent. No IDA writes — pure file I/O + DB kv_store update.
"""
import json
import os
import re
import time

from tc_wow_analyzer.core.utils import msg_info, msg_warn

_OPCODE_RE = re.compile(
    r"^\s*(CMSG|SMSG)_([A-Z][A-Z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|UNKNOWN_OPCODE)",
    re.M,
)
_TOPIC_PATTERNS = {
    "delve":        re.compile(r"DELVE", re.I),
    "garrison":     re.compile(r"GARRISON", re.I),
    "housing":      re.compile(r"HOUSING", re.I),
    "warband":      re.compile(r"WARBAND", re.I),
    "neighborhood": re.compile(r"NEIGHBORHOOD", re.I),
    "follower":     re.compile(r"FOLLOWER", re.I),
}

_TC_BRANCH_CANDIDATES = [
    ("master",      r"c:/TrinityBots/wt/master/src/server/game/Server/Protocol/Opcodes.h"),
    ("delves",      r"L:/TrinityCore/delves/TrinityCore/src/server/game/Server/Protocol/Opcodes.h"),
    ("garrison",    r"L:/TrinityCore/garrison/TrinityCore/src/server/game/Server/Protocol/Opcodes.h"),
    ("housing",     r"L:/TrinityCore/housing/TrinityCore/src/server/game/Server/Protocol/Opcodes.h"),
    ("playerbot",   r"L:/TrinityCore/playerbot-dev/TrinityCore/src/server/game/Server/Protocol/Opcodes.h"),
    ("pet-battles", r"L:/TrinityCore/pet-battles/TrinityCore/src/server/game/Server/Protocol/Opcodes.h"),
    ("encounter",   r"L:/TrinityCore/encounter/TrinityCore/src/server/game/Server/Protocol/Opcodes.h"),
    ("skyriding",   r"L:/TrinityCore/skyriding/TrinityCore/src/server/game/Server/Protocol/Opcodes.h"),
    ("chromie",     r"L:/TrinityCore/chromie/TrinityCore/src/server/game/Server/Protocol/Opcodes.h"),
]


def _parse_branch(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return None
    out = {}
    for m in _OPCODE_RE.finditer(text):
        opname = f"{m.group(1)}_{m.group(2)}"
        if opname not in out:
            out[opname] = {
                "direction": m.group(1),
                "value": m.group(3),
            }
    return out


def analyze_tc_opcode_xref(session):
    t0 = time.time()
    db = session.db
    build = getattr(session, "build_number", None) or "67186"

    branch_data = {}
    for name, path in _TC_BRANCH_CANDIDATES:
        d = _parse_branch(path)
        if d is not None:
            for v in d.values():
                v["branch"] = name
            branch_data[name] = d
    if not branch_data:
        msg_warn("TC opcode xref: no TC source trees found")
        return 0
    msg_info(f"TC opcode xref: parsed {len(branch_data)} branches")

    master = branch_data.get("master", {})
    branch_additions = {}
    for name, d in branch_data.items():
        if name == "master": continue
        new_in_branch = {op: meta for op, meta in d.items() if op not in master}
        branch_additions[name] = new_in_branch

    union = dict(master)
    for d in branch_data.values():
        for op, meta in d.items():
            union.setdefault(op, meta)

    topic_opcodes = {}
    for topic, pat in _TOPIC_PATTERNS.items():
        topic_opcodes[topic] = {op: meta for op, meta in union.items() if pat.search(op)}

    payload = {
        "_meta": {
            "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "branches": list(branch_data.keys()),
            "master_total": len(master),
            "union_total": len(union),
            "topic_totals": {t: len(d) for t, d in topic_opcodes.items()},
        },
        "branches": branch_data,
        "branch_additions": branch_additions,
        "by_topic": topic_opcodes,
        "union": union,
    }
    out_path = f"c:/dumps/tc_opcodes_{build}.json"
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
    msg_info(f"TC opcode xref: wrote {out_path}")

    # Per-topic Markdown digests
    for topic, ops in topic_opcodes.items():
        if not ops: continue
        lines = [f"# TC {topic.title()} opcodes\n"]
        lines.append(f"Total: {len(ops)}\n")
        cmsg = sorted(o for o in ops if o.startswith("CMSG_"))
        smsg = sorted(o for o in ops if o.startswith("SMSG_"))
        for label, group in (("CMSG", cmsg), ("SMSG", smsg)):
            if not group: continue
            lines.append(f"## {label} ({len(group)})\n")
            lines.append("| Opcode | TC value | First branch |")
            lines.append("| :----- | :------- | :----------- |")
            for op in group:
                m = ops[op]
                first = "master"
                if op not in master:
                    for bn, bd in branch_data.items():
                        if bn == "master": continue
                        if op in bd:
                            first = bn; break
                lines.append(f"| `{op}` | `{m['value']}` | {first} |")
            lines.append("")
        with open(f"c:/dumps/TC_{topic.upper()}_OPCODES.md", "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    # Cross-ref with binary opcodes (try to match by tc_name)
    if db is not None:
        try:
            tc_name_to_binary = {}
            rows = db.fetchall("SELECT tc_name, wire_opcode, handler_ea FROM opcodes WHERE tc_name IS NOT NULL") or []
            for r in rows:
                tc_name_to_binary[r["tc_name"]] = {
                    "wire_opcode": r["wire_opcode"],
                    "handler_ea": r["handler_ea"],
                }
            matched = sum(1 for op in union if op in tc_name_to_binary)
            msg_info(f"TC opcode xref: {matched} of {len(union)} TC opcodes have binary-side handler in DB")
            db.kv_set("tc_opcode_xref", {
                "build": build,
                "tc_branches": list(branch_data.keys()),
                "tc_total": len(union),
                "binary_matched": matched,
                "topic_totals": {t: len(d) for t, d in topic_opcodes.items()},
            })
        except Exception as e:
            msg_warn(f"TC opcode xref DB step skipped: {e}")

    elapsed = round(time.time() - t0, 2)
    msg_info(f"TC opcode xref: done in {elapsed}s, {len(union)} unique opcodes")
    return len(union)
