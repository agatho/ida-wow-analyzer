"""
Offline opcode-dispatch recovery.

WHY THIS EXISTS
---------------
On build 12.1.0.69382 the AutoDump ships an EMPTY `wow_opcode_dispatch` file
(0 handlers / 111 bytes). The extractor that fills it lives in AutoDump's
`helper_dll.c` (`ExtractOpcodeDispatchTables`) and only accepts a candidate
table when >=4 of its target RVAs match a JAM handler_rva -- but the JAM
extractor resolved handler_rva for just 2 of 482 messages on this build, so the
corroboration always fails and the file comes out empty.

Fixing that DLL means recompiling ~34k lines of native anti-tamper code and
re-injecting it into a live, self-restarting retail client -- not something the
plugin can verify. But the data it wants is sitting in the STATIC dump:
`wow_dump.bin` .rdata holds the dispatch tables as arrays of absolute VA
pointers into .text. This module reads them straight out of the dump, no
injection, fully checkable here.

It is deliberately CONSERVATIVE. A dense run of code pointers is more often a
vtable or the incremental-link table than an opcode dispatch table, and
emitting a vtable's slot numbers as opcodes fabricates data. So this module:

  * finds every run of >=16 consecutive .rdata qwords that point at a real
    function start (validated against pdata),
  * scores each run (named-target fraction, JAM handler_rva hits, pointer
    stride, uniqueness of targets),
  * writes ALL candidates to kv_store[opcode_dispatch_candidates] and to
    `wow_opcode_dispatch_recovered_<build>.json` for inspection,
  * only writes handler_ea / jam_type back into the `opcodes` table for entries
    whose target RVA actually matches a JAM handler -- never for a bare slot.

Everything it needs (the dump, pdata, the DB) is already on disk, so it runs
with or without a live IDA.
"""

import json
import os
import struct

from tc_wow_analyzer.core.utils import (
    msg_info, msg_warn, msg_error, dumps_dir, dumps_build_path, current_build)
from tc_wow_analyzer.core import kv_keys


MIN_RUN = 16          # a shorter run is too easily a coincidental pointer cluster
MAX_RUN = 4096        # longer than any plausible dispatch table
_MAX_CANDIDATES = 64


# ---------------------------------------------------------------------------
# PE / dump parsing (pure, offline-testable)
# ---------------------------------------------------------------------------

def parse_pe_sections(data):
    """Return (image_base, {name: (start_rva, end_rva)}) for a raw PE dump."""
    if data[:2] != b"MZ":
        raise ValueError("not a PE image (no MZ)")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("no PE signature")
    n_sections = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    image_base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
    sec_off = pe + 24 + opt_size
    sections = {}
    for i in range(n_sections):
        so = sec_off + i * 40
        name = data[so:so + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize = struct.unpack_from("<I", data, so + 8)[0]
        vaddr = struct.unpack_from("<I", data, so + 12)[0]
        sections[name] = (vaddr, vaddr + vsize)
    return image_base, sections


def _function_starts(build):
    """Set of function-start RVAs from wow_pdata_<build>.json (validity set)."""
    starts = set()
    path = dumps_build_path("wow_pdata", build=build)
    if not os.path.isfile(path):
        return starts
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        return starts
    for func in data.get("functions") or data.get("entries") or []:
        rva = func.get("start_rva", func.get("rva", func.get("begin")))
        if isinstance(rva, str):
            try:
                rva = int(rva, 16)
            except ValueError:
                continue
        if isinstance(rva, int):
            starts.add(rva)
    return starts


def find_dispatch_tables(data, image_base, text, rdata, starts,
                         min_run=MIN_RUN, max_run=MAX_RUN):
    """Find runs of consecutive .rdata pointers into valid .text function starts.

    Returns a list of dicts: {table_rva, count, stride, targets:[rva,...]}.
    Pure function -- no IDA, no DB -- so it can be unit-tested on any dump.
    """
    ts, te = text
    rs, re_ = rdata
    re_ = min(re_, len(data))
    tables = []
    p = rs
    while p + 8 <= re_:
        run = 0
        q = p
        targets = []
        while q + 8 <= re_:
            val = struct.unpack_from("<Q", data, q)[0]
            rva = val - image_base
            if ts <= rva < te and rva in starts:
                targets.append(rva)
                run += 1
                q += 8
                if run >= max_run:
                    break
            else:
                break
        if run >= min_run:
            # stride: spacing between the first few targets. A perfectly regular
            # spacing (e.g. +0x60) is a vtable/thunk-array tell; irregular
            # spacing is what a real handler dispatch table looks like.
            stride = None
            if len(targets) >= 2:
                diffs = [targets[i + 1] - targets[i]
                         for i in range(min(8, len(targets) - 1))]
                if diffs and all(d == diffs[0] for d in diffs):
                    stride = diffs[0]
            tables.append({
                "table_rva": p,
                "count": run,
                "stride": stride,
                "targets": targets,
            })
            p = q
        else:
            p += 8
    tables.sort(key=lambda t: -t["count"])
    return tables


# ---------------------------------------------------------------------------
# Scoring against the knowledge DB + JAM entries
# ---------------------------------------------------------------------------

def _jam_handler_rvas(build, cfg):
    """{handler_rva: (name, direction)} from the JAM message dump."""
    from tc_wow_analyzer.core import autodump
    out = {}
    path = dumps_build_path("wow_jam_messages", build=build)
    if not os.path.isfile(path):
        return out
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        return out
    for message, _cat, implied in autodump.iter_jam_messages(data):
        rva = message.get("handler_rva")
        if isinstance(rva, str):
            try:
                rva = int(rva, 16)
            except ValueError:
                continue
        if isinstance(rva, int) and rva:
            out[rva] = (message["name"],
                        autodump.jam_direction(message, implied) or "unknown")
    return out


def _score(table, named_rvas, jam_by_rva):
    """Attach corroboration signals to a candidate table."""
    targets = table["targets"]
    n = len(targets)
    named = sum(1 for r in targets if r in named_rvas)
    jam = sum(1 for r in targets if r in jam_by_rva)
    unique = len(set(targets))
    table["named_hits"] = named
    table["named_pct"] = round(100.0 * named / n, 1) if n else 0.0
    table["jam_hits"] = jam
    table["unique_pct"] = round(100.0 * unique / n, 1) if n else 0.0
    # Uniqueness alone is weak (vtables are unique too); the regular stride is
    # the real vtable tell.
    table["looks_like_vtable"] = table["stride"] is not None
    return table


def analyze_opcode_dispatch_recovery(session):
    """Recover dispatch-table candidates from the static dump.

    Returns the number of candidate tables found. Writes the full candidate set
    to kv + a JSON artifact, and back-fills opcodes.handler_ea only for targets
    that match a real JAM handler.
    """
    db = session.db
    cfg = session.cfg
    build = current_build() or (cfg.build_number if cfg else 0)
    if not build:
        msg_warn("  dispatch recovery: build unknown; skipping")
        return 0

    dump_path = None
    for cand in (getattr(cfg, "binary_path", None),
                 os.path.join(dumps_dir(), "wow_dump.bin"),
                 os.path.join(dumps_dir(), "wow_dump_%s.bin" % build)):
        if cand and os.path.isfile(cand):
            dump_path = cand
            break
    if not dump_path:
        msg_warn("  dispatch recovery: no raw dump found in %s "
                 "(looked for wow_dump.bin) -- skipping" % dumps_dir())
        return 0

    try:
        with open(dump_path, "rb") as handle:
            data = handle.read()
        image_base, sections = parse_pe_sections(data)
    except Exception as exc:
        msg_error("  dispatch recovery: cannot parse %s: %s" % (dump_path, exc))
        return 0

    text = sections.get(".text")
    rdata = sections.get(".rdata")
    if not text or not rdata:
        msg_warn("  dispatch recovery: dump has no .text/.rdata; skipping")
        return 0

    starts = _function_starts(build)
    if not starts:
        msg_warn("  dispatch recovery: no pdata function starts; skipping "
                 "(cannot validate pointer targets)")
        return 0

    msg_info("  dispatch recovery: scanning %s .rdata against %d function starts"
             % (os.path.basename(dump_path), len(starts)))
    tables = find_dispatch_tables(data, image_base, text, rdata, starts)
    if not tables:
        msg_warn("  dispatch recovery: no candidate tables found")
        return 0

    named_rvas = set()
    try:
        for row in db.fetchall(
                "SELECT rva FROM functions "
                "WHERE name IS NOT NULL AND rva IS NOT NULL"):
            named_rvas.add(row["rva"])
    except Exception:
        pass
    jam_by_rva = _jam_handler_rvas(build, cfg)

    for table in tables:
        _score(table, named_rvas, jam_by_rva)

    candidates = tables[:_MAX_CANDIDATES]
    blob_candidates = []
    for t in candidates:
        entry = {k: v for k, v in t.items() if k != "targets"}
        entry["targets_preview"] = ["0x%X" % r for r in t["targets"][:8]]
        blob_candidates.append(entry)
    db.kv_set(kv_keys.OPCODE_DISPATCH_CANDIDATES, {
        "build": build,
        "dump": os.path.basename(dump_path),
        "image_base": image_base,
        "candidate_count": len(tables),
        "candidates": blob_candidates,
    })

    handlers = []
    for t in candidates:
        for j, rva in enumerate(t["targets"]):
            entry = {"opcode_index": j,
                     "handler_rva": "0x%X" % rva,
                     "table_rva": "0x%X" % t["table_rva"]}
            jam = jam_by_rva.get(rva)
            if jam:
                entry["jam_name"], entry["direction"] = jam
            handlers.append(entry)
    artifact = os.path.join(dumps_dir(),
                            "wow_opcode_dispatch_recovered_%s.json" % build)
    try:
        with open(artifact, "w", encoding="utf-8") as handle:
            json.dump({"type": "opcode_dispatch_recovered", "build": build,
                       "source": "static_dump_offline",
                       "total_handlers": len(handlers),
                       "dispatch_tables": len(candidates),
                       "handlers": handlers}, handle, indent=1)
        msg_info("  dispatch recovery: wrote %s" % artifact)
    except Exception as exc:
        msg_warn("  dispatch recovery: could not write artifact: %s" % exc)

    # Back-fill opcodes ONLY where a target matches a real JAM handler -- never
    # a bare slot index, which would fabricate an opcode.
    linked = 0
    if jam_by_rva:
        for t in candidates:
            for rva in t["targets"]:
                jam = jam_by_rva.get(rva)
                if not jam:
                    continue
                name, _direction = jam
                handler_ea = cfg.rva_to_ea(rva)
                row = db.fetchone(
                    "SELECT direction, internal_index FROM opcodes "
                    "WHERE jam_type = ?", (name,))
                if row:
                    db.upsert_opcode(direction=row["direction"],
                                     internal_index=row["internal_index"],
                                     handler_ea=handler_ea)
                    linked += 1
    db.commit()

    best = candidates[0]
    msg_info("  dispatch recovery: %d candidate tables (largest %d entries @ "
             "0x%X, named %s%%, jam hits %d), %d opcode handler_ea back-filled"
             % (len(tables), best["count"], best["table_rva"],
                best["named_pct"], best["jam_hits"], linked))
    if all(t["jam_hits"] < 4 for t in candidates):
        msg_warn("  dispatch recovery: NO candidate corroborates against JAM "
                 "handler RVAs (only 2 exist on this build). Candidates are "
                 "exported for inspection but NOT written as opcodes -- that "
                 "would fabricate opcode numbers from vtable slots. The real "
                 "fix is a non-empty wow_jam_messages handler_rva set from "
                 "AutoDump.")
    return len(tables)
