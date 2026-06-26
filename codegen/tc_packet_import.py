"""
TrinityCore packet-catalog importer — the CANONICAL named-field source.

Parses TC src/server/game/Server/Packets/*.h into the tc_packets / tc_structs /
tc_opcodes tables. This is the PRIMARY field source for codegen: the WoW client's
JAM serialization is ~92% inlined and not cleanly recoverable (see
jam_field_layouts / wire_format_recovery notes), so TC's hand-maintained, NAMED
packet structs are authoritative. Client recovery only supplements packets TC
lacks (genuinely-new build opcodes).

Also serves as the build-migration coverage gate: an opcode/packet present in
tc_opcodes/tc_packets is already handled by TC and need not be generated.

Field source resolved from (in order):
  1. session.cfg.tc_source_dir
  2. c:/dumps/external/TrinityCore   (the fetched sparse checkout)
"""
import glob
import json
import os
import re

from tc_wow_analyzer.core.utils import msg_info, msg_warn

_DEFAULT_TC = r"c:/dumps/external/TrinityCore"
_PKT_SUBDIR = "src/server/game/Server/Packets"
_OPC_SUBDIR = "src/server/game/Server/Protocol"

# ── header parsing (validated against TC master 2026-06-26) ───────────────────
_SKIP_KW = ("public:", "private:", "protected:", "class ", "struct ", "enum ",
            "namespace", "using ", "static ", "friend ", "template", "typedef",
            "return", "#", "//", "/*", "*", "void ", "WorldPacket")
_FIELD_RE = re.compile(
    r"^\s*(?P<type>[A-Za-z_][\w:]*(?:\s*<[^;{}]*?>)?(?:\s*::\s*\w+)*\s*[*&]?)"
    r"\s+(?P<name>\w+)\s*(?P<arr>\[[^\]]*\])?\s*(?:=\s*[^;]*)?;\s*$")
_CTOR_OPCODE_RE = re.compile(r":\s*(Client|Server)Packet\s*\(\s*(\w+)")
_OPC_RE = re.compile(r"(CMSG_\w+|SMSG_\w+|MSG_\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)")


def _strip_comment(ln):
    i = ln.find("//")
    return ln[:i] if i >= 0 else ln


def _parse_block(lines, start):
    depth = 0
    body, ctor, i, seen_open = [], None, start, False
    while i < len(lines):
        ln = lines[i]
        depth += ln.count("{") - ln.count("}")
        if "{" in ln:
            seen_open = True
        if seen_open and _CTOR_OPCODE_RE.search(ln):
            ctor = ln
        if seen_open and depth <= 0:
            return body, ctor, i
        if seen_open:
            body.append(ln)
        i += 1
    return body, ctor, i


def _extract_fields(body):
    fields, idx = [], 0
    for raw in body:
        ln = _strip_comment(raw).rstrip()
        s = ln.strip()
        if not s or s in ("{", "}", "};", "public:", "private:", "protected:"):
            continue
        if "(" in s or s.startswith(_SKIP_KW):
            continue
        m = _FIELD_RE.match(ln)
        if not m:
            continue
        name = m.group("name")
        if name in ("override", "final", "const"):
            continue
        typ = re.sub(r"\s+", " ", m.group("type").strip())
        f = {"index": idx, "name": name, "type": typ}
        if m.group("arr"):
            f["array"] = m.group("arr").strip("[]").strip() or True
        if typ.startswith("std::vector<") or typ.startswith("std::array<"):
            f["repeated"] = True
        fields.append(f)
        idx += 1
    return fields


def _parse_header(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    packets, structs, ns, i = [], [], [], 0
    while i < len(lines):
        ln = lines[i]
        mns = re.match(r"\s*namespace\s+(\w+)", ln)
        if mns:
            ns.append(mns.group(1))
        mcls = re.search(
            r"\bclass\s+(\w+)\s+final\s*:\s*public\s+(Client|Server)Packet\b", ln)
        mstr = (re.match(r"\s*struct\s+(\w+)\s*$", ln)
                or re.match(r"\s*struct\s+(\w+)\s*\{", ln))
        if mcls:
            body, ctor, end = _parse_block(lines, i)
            opcode = None
            direction = "CMSG" if mcls.group(2) == "Client" else "SMSG"
            if ctor:
                mc = _CTOR_OPCODE_RE.search(ctor)
                if mc:
                    opcode = mc.group(2)
            packets.append({"name": mcls.group(1), "opcode": opcode,
                            "direction": direction, "namespace": "::".join(ns),
                            "file": os.path.basename(path),
                            "fields": _extract_fields(body)})
            i = end + 1
            continue
        if mstr:
            body, _c, end = _parse_block(lines, i)
            structs.append({"name": mstr.group(1), "namespace": "::".join(ns),
                            "file": os.path.basename(path),
                            "fields": _extract_fields(body)})
            i = end + 1
            continue
        i += 1
    return packets, structs


def _parse_opcodes(path):
    opc = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                m = _OPC_RE.match(_strip_comment(ln).strip().rstrip(","))
                if m:
                    opc[m.group(1)] = int(m.group(2), 0)
    return opc


def _resolve_tc_dir(session):
    cfg = getattr(session, "cfg", None)
    cand = []
    if cfg is not None and getattr(cfg, "tc_source_dir", ""):
        cand.append(cfg.tc_source_dir)
    cand.append(_DEFAULT_TC)
    for d in cand:
        if d and os.path.isdir(os.path.join(d, _PKT_SUBDIR)):
            return d
    return None


# ── JAM <-> TC name bridge ────────────────────────────────────────────────────
def jam_to_class(name):
    """JamCliHouseDecorAction -> HouseDecorAction (TC class/struct name)."""
    for pre in ("JamClient", "JamCli", "JamSvcs", "JamSrv", "FJam", "Jam"):
        if name.startswith(pre):
            return name[len(pre):]
    return name


def _name_variants(c):
    yield c
    c2 = re.sub(r"_[A-Z]$", "", c)
    if c2 != c:
        yield c2
    c3 = re.sub(r"_\d+$", "", c)
    if c3 != c:
        yield c3


def tc_fields_for_jam(db, jam_name):
    """Return (kind, tc_name, fields) for a JAM type matched to a TC struct/packet
    by de-prefixed name, or None. Used by codegen to prefer TC's named fields."""
    cls = jam_to_class(jam_name)
    for v in _name_variants(cls):
        row = db.fetchone("SELECT name, fields_json FROM tc_structs WHERE name = ?", (v,))
        if row and row["fields_json"]:
            return ("struct", row["name"], json.loads(row["fields_json"]))
    for v in _name_variants(cls):
        row = db.fetchone("SELECT name, fields_json FROM tc_packets WHERE name = ?", (v,))
        if row and row["fields_json"]:
            return ("packet", row["name"], json.loads(row["fields_json"]))
    return None


def import_tc_catalog(session, tc_dir=None):
    """Parse TC packet headers into tc_packets/tc_structs/tc_opcodes.
    Returns dict of counts. Idempotent (upserts)."""
    db = getattr(session, "db", None)
    if db is None:
        msg_warn("tc_packet_import: no DB")
        return {}
    tc_dir = tc_dir or _resolve_tc_dir(session)
    if not tc_dir:
        msg_warn("tc_packet_import: no TrinityCore source found "
                 "(set cfg.tc_source_dir or place a checkout at %s)" % _DEFAULT_TC)
        return {}

    headers = sorted(glob.glob(os.path.join(tc_dir, _PKT_SUBDIR, "*.h")))
    packets, structs = [], []
    for h in headers:
        try:
            p, s = _parse_header(h)
            packets += p
            structs += s
        except Exception as e:
            msg_warn("tc_packet_import: %s: %s" % (os.path.basename(h), e))
    opcodes = _parse_opcodes(os.path.join(tc_dir, _OPC_SUBDIR, "Opcodes.h"))

    for p in packets:
        db.execute(
            "INSERT INTO tc_packets (name, opcode, direction, namespace, file, "
            "field_count, fields_json) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET opcode=excluded.opcode, "
            "direction=excluded.direction, namespace=excluded.namespace, "
            "file=excluded.file, field_count=excluded.field_count, "
            "fields_json=excluded.fields_json",
            (p["name"], p["opcode"], p["direction"], p["namespace"], p["file"],
             len(p["fields"]), json.dumps(p["fields"])))
    for s in structs:
        db.execute(
            "INSERT INTO tc_structs (name, namespace, file, field_count, fields_json) "
            "VALUES (?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
            "namespace=excluded.namespace, file=excluded.file, "
            "field_count=excluded.field_count, fields_json=excluded.fields_json",
            (s["name"], s["namespace"], s["file"], len(s["fields"]),
             json.dumps(s["fields"])))
    for nm, val in opcodes.items():
        d = "CMSG" if nm.startswith("CMSG") else ("SMSG" if nm.startswith("SMSG") else "MSG")
        db.execute(
            "INSERT INTO tc_opcodes (name, value, direction) VALUES (?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET value=excluded.value, direction=excluded.direction",
            (nm, val, d))
    db.commit()

    # count JAM types now resolvable to a TC definition
    jam_matched = 0
    try:
        for r in db.fetchall("SELECT name FROM jam_types"):
            if tc_fields_for_jam(db, r["name"]):
                jam_matched += 1
    except Exception:
        pass

    counts = {"tc_packets": len(packets), "tc_structs": len(structs),
              "tc_opcodes": len(opcodes), "jam_matched": jam_matched,
              "tc_dir": tc_dir}
    msg_info("tc_packet_import: %d packets, %d structs, %d opcodes from %s "
             "(%d JAM types resolve to a TC def)"
             % (len(packets), len(structs), len(opcodes), tc_dir, jam_matched))
    return counts
