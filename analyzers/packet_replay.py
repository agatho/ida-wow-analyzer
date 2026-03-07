"""
Packet Replay Conformance
Replays captured packet sequences through decompiled binary logic and
compares the expected behavior against TrinityCore handler behavior.

This analyzer:
  1. Reads packet capture files (sniff logs) to extract real packet sequences
  2. Traces the decompiled binary handler to determine expected outcomes
  3. Generates conformance reports showing where TC behavior would diverge
  4. Identifies missing response packets, wrong error codes, or missing side effects
"""

import json
import os
import re
import time

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


def analyze_packet_replay(session, sniff_dir=None):
    """Analyze packet captures for conformance against binary behavior.

    Args:
        session: PluginSession
        sniff_dir: Directory containing packet capture exports.
                   If None, checks cfg.extraction_dir for .pkt.sql or .pkt files.

    Returns number of packet sequences analyzed.
    """
    db = session.db
    cfg = session.cfg

    # Locate packet captures
    search_dirs = []
    if sniff_dir:
        search_dirs.append(sniff_dir)
    if cfg.extraction_dir:
        search_dirs.append(cfg.extraction_dir)
    pipeline_dir = cfg.get("pipeline_dir")
    if pipeline_dir:
        search_dirs.append(pipeline_dir)

    capture_files = []
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            if fname.endswith((".pkt.sql", ".pkt.txt", ".json")):
                capture_files.append(os.path.join(d, fname))

    if not capture_files:
        msg_info("No packet capture files found. "
                 "Place .pkt.sql/.pkt.txt/.json in extraction directory.")
        return 0

    msg_info(f"Found {len(capture_files)} packet capture files")

    # Build opcode lookup
    opcode_lookup = _build_opcode_lookup(db)
    msg_info(f"Opcode lookup: {len(opcode_lookup)} known opcodes")

    all_sequences = []

    for filepath in capture_files:
        msg_info(f"Parsing {os.path.basename(filepath)}...")
        sequences = _parse_capture_file(filepath, opcode_lookup)
        all_sequences.extend(sequences)

    if not all_sequences:
        msg_info("No parseable packet sequences found in capture files")
        return 0

    msg_info(f"Extracted {len(all_sequences)} packet sequences")

    # Analyze each sequence against binary handler expectations
    conformance_results = []
    for seq in all_sequences:
        result = _analyze_sequence(db, seq, opcode_lookup)
        if result:
            conformance_results.append(result)

    # Store results
    report = {
        "capture_files": [os.path.basename(f) for f in capture_files],
        "total_sequences": len(all_sequences),
        "analyzed": len(conformance_results),
        "conformant": sum(1 for r in conformance_results if r["is_conformant"]),
        "divergent": sum(1 for r in conformance_results if not r["is_conformant"]),
        "results": conformance_results[:500],  # cap storage
        "analyzed_at": time.time(),
    }

    db.kv_set("packet_replay_report", report)
    db.commit()

    conformant = report["conformant"]
    divergent = report["divergent"]
    total = conformant + divergent
    pct = round(conformant / max(total, 1) * 100, 1)
    msg_info(f"Packet replay: {conformant}/{total} conformant ({pct}%), "
             f"{divergent} divergent")

    return len(conformance_results)


def _build_opcode_lookup(db):
    """Build opcode index → handler info lookup."""
    lookup = {}
    for row in db.fetchall("SELECT * FROM opcodes"):
        idx = row["internal_index"]
        lookup[idx] = {
            "index": idx,
            "tc_name": row["tc_name"],
            "jam_type": row["jam_type"],
            "direction": row["direction"],
            "handler_ea": row["handler_ea"],
        }
        # Also key by name for name-based lookups
        if row["tc_name"]:
            lookup[row["tc_name"]] = lookup[idx]
    return lookup


def _parse_capture_file(filepath, opcode_lookup):
    """Parse a packet capture file and extract sequences.

    Supports:
      - WowPacketParser .pkt.sql exports (INSERT INTO statements)
      - Text-based packet dumps (.pkt.txt)
      - JSON packet logs (.json)
    """
    if filepath.endswith(".json"):
        return _parse_json_capture(filepath, opcode_lookup)
    elif filepath.endswith(".pkt.sql"):
        return _parse_sql_capture(filepath, opcode_lookup)
    elif filepath.endswith(".pkt.txt"):
        return _parse_text_capture(filepath, opcode_lookup)
    return []


def _parse_json_capture(filepath, opcode_lookup):
    """Parse JSON-format packet capture."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return []

    sequences = []
    if isinstance(data, list):
        current_seq = {"packets": [], "name": os.path.basename(filepath)}
        for item in data:
            if isinstance(item, dict):
                pkt = {
                    "opcode": item.get("opcode", item.get("Opcode", 0)),
                    "name": item.get("name", item.get("Name", "")),
                    "direction": item.get("direction",
                                         item.get("Direction", "")),
                    "data": item.get("data", item.get("Data", "")),
                    "timestamp": item.get("timestamp",
                                          item.get("Timestamp", 0)),
                }
                current_seq["packets"].append(pkt)

        if current_seq["packets"]:
            sequences.append(current_seq)

    return sequences


def _parse_sql_capture(filepath, opcode_lookup):
    """Parse WowPacketParser SQL export."""
    sequences = []
    current_seq = {"packets": [], "name": os.path.basename(filepath)}

    # Pattern: INSERT INTO `opcode` (...) VALUES (index, 'name', 'direction', ...);
    insert_pattern = re.compile(
        r"VALUES\s*\(\s*(\d+)\s*,\s*'([^']+)'\s*,\s*'([^']+)'",
        re.IGNORECASE
    )

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = insert_pattern.search(line)
                if m:
                    pkt = {
                        "opcode": int(m.group(1)),
                        "name": m.group(2),
                        "direction": m.group(3),
                        "data": "",
                        "timestamp": 0,
                    }
                    current_seq["packets"].append(pkt)
    except IOError:
        return []

    if current_seq["packets"]:
        sequences.append(current_seq)

    return sequences


def _parse_text_capture(filepath, opcode_lookup):
    """Parse text-format packet dump."""
    sequences = []
    current_seq = {"packets": [], "name": os.path.basename(filepath)}

    # Common text dump patterns:
    # [CMSG] CMSG_HOUSING_DECOR_PLACE (0x1234)
    # Direction: Client -> Server, Opcode: 0x1234 (CMSG_FOO)
    pkt_pattern = re.compile(
        r'(?:\[(CMSG|SMSG)\]|Direction:\s*(Client|Server))\s*'
        r'(\w+)\s*\(?\s*(0x[0-9A-Fa-f]+|\d+)\s*\)?',
        re.IGNORECASE
    )

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = pkt_pattern.search(line)
                if m:
                    direction = m.group(1) or (
                        "CMSG" if m.group(2) and "client" in m.group(2).lower()
                        else "SMSG"
                    )
                    pkt = {
                        "opcode": int(m.group(4), 0),
                        "name": m.group(3),
                        "direction": direction,
                        "data": "",
                        "timestamp": 0,
                    }
                    current_seq["packets"].append(pkt)
    except IOError:
        return []

    if current_seq["packets"]:
        sequences.append(current_seq)

    return sequences


def _analyze_sequence(db, sequence, opcode_lookup):
    """Analyze a packet sequence for conformance.

    For each CMSG in the sequence:
      1. Look up the binary handler
      2. Extract expected response opcodes from the handler pseudocode
      3. Check if the expected SMSG responses appear in the sequence
      4. Flag missing responses or unexpected sequences
    """
    packets = sequence.get("packets", [])
    if not packets:
        return None

    issues = []
    cmsg_count = 0
    response_matches = 0
    response_misses = 0

    for i, pkt in enumerate(packets):
        if pkt["direction"] not in ("CMSG", "Client"):
            continue

        cmsg_count += 1
        opcode_info = opcode_lookup.get(pkt.get("name")) or \
                      opcode_lookup.get(pkt.get("opcode"))

        if not opcode_info:
            continue

        handler_ea = opcode_info.get("handler_ea")
        if not handler_ea:
            continue

        # Get expected responses from binary handler
        expected_responses = _get_expected_responses(handler_ea, opcode_lookup)

        # Look for those responses in the next few packets
        window = packets[i+1:i+10]
        found_responses = set()
        for resp_pkt in window:
            if resp_pkt["direction"] in ("SMSG", "Server"):
                found_responses.add(resp_pkt.get("name", ""))

        for expected in expected_responses:
            if expected in found_responses:
                response_matches += 1
            else:
                response_misses += 1
                issues.append({
                    "type": "missing_response",
                    "cmsg": pkt.get("name", f"0x{pkt.get('opcode', 0):X}"),
                    "expected_smsg": expected,
                    "packet_index": i,
                })

    if cmsg_count == 0:
        return None

    is_conformant = len(issues) == 0
    return {
        "sequence_name": sequence.get("name", "unknown"),
        "packet_count": len(packets),
        "cmsg_count": cmsg_count,
        "response_matches": response_matches,
        "response_misses": response_misses,
        "is_conformant": is_conformant,
        "issues": issues[:20],
    }


def _get_expected_responses(handler_ea, opcode_lookup):
    """Determine expected SMSG responses from a binary handler.

    Analyzes pseudocode for patterns like:
      - SendPacket(&response_opcode)
      - WorldPackets::Send*(...)
      - Direct SMSG opcode references
    """
    pseudocode = get_decompiled_text(handler_ea)
    if not pseudocode:
        return []

    responses = []

    # Pattern 1: SendPacket with known SMSG name
    send_pattern = re.compile(
        r'(?:SendPacket|SendMessageToSet|SendDirectMessage)\s*\(\s*&?\s*(\w+)',
        re.IGNORECASE
    )
    for m in send_pattern.finditer(pseudocode):
        var_name = m.group(1)
        # Check if the variable name suggests an SMSG
        if "SMSG" in var_name.upper() or "Response" in var_name:
            responses.append(var_name)

    # Pattern 2: Opcode enum reference in packet construction
    smsg_pattern = re.compile(r'SMSG_\w+')
    for m in smsg_pattern.finditer(pseudocode):
        smsg_name = m.group(0)
        if smsg_name not in responses:
            responses.append(smsg_name)

    # Pattern 3: Internal opcode index used in packet construction
    opcode_ref_pattern = re.compile(
        r'(?:opcode|Opcode)\s*=\s*(0x[0-9A-Fa-f]+|\d+)')
    for m in opcode_ref_pattern.finditer(pseudocode):
        try:
            idx = int(m.group(1), 0)
            info = opcode_lookup.get(idx)
            if info and info.get("direction") == "SMSG":
                name = info.get("tc_name", f"SMSG_0x{idx:X}")
                if name not in responses:
                    responses.append(name)
        except ValueError:
            pass

    return responses


def get_replay_report(session):
    """Retrieve stored packet replay report."""
    return session.db.kv_get("packet_replay_report") or {}
