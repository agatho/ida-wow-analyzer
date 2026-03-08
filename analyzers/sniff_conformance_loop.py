"""
Sniff Conformance Loop
Replays real packet captures against binary wire formats and TC handler
analysis to detect divergences and generate fixes.

Pipeline:
  1. Sniff File Discovery   — scan for .pkt / .txt / .csv exports
  2. Packet Parsing         — extract raw payloads per opcode
  3. Binary Wire Format Validation — check fields vs symbolic constraints
  4. TC Behavior Comparison — simulate binary vs TC handler outcomes
  5. Divergence Detection   — classify mismatches by type and severity
  6. Auto-Fix Generation    — produce C++ patch suggestions
  7. Statistical Analysis   — per-opcode rates, coverage, confidence
  8. Report Assembly        — full report stored in kv_store

Entry points:
  run_conformance_loop(session, sniff_dir=None) -> int  (divergences found)
  get_conformance_loop_report(session)                  (retrieve stored results)

Export helpers:
  export_fixes(session, output_dir)
  export_divergence_report(session, output_path)
  get_critical_divergences(session)
  get_fix_for_handler(session, handler_name)
  get_coverage_summary(session)
  print_conformance_summary(session)
"""

import json
import re
import time
import os
import struct
import collections

import ida_funcs
import ida_name
import idautils

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str


# ======================================================================
# Constants
# ======================================================================

_KV_KEY = "sniff_conformance_loop"

_BATCH_SIZE = 1000

# PKT file signature bytes
_PKT_SIGNATURE = b"PKT"
_PKT_VERSION_300 = 0x0300
_PKT_VERSION_301 = 0x0301

# Direction constants
_DIR_C2S = 0  # CMSG
_DIR_S2C = 1  # SMSG
_DIR_NAMES = {_DIR_C2S: "CMSG", _DIR_S2C: "SMSG"}

# Fixed-width type sizes in bytes
_FIXED_TYPE_SIZES = {
    "uint8":  1, "int8":   1,
    "uint16": 2, "int16":  2,
    "uint32": 4, "int32":  4,
    "uint64": 8, "int64":  8,
    "float":  4, "double": 8,
}

# struct format chars (little-endian)
_STRUCT_FMTS = {
    "uint8": "<B", "int8": "<b",
    "uint16": "<H", "int16": "<h",
    "uint32": "<I", "int32": "<i",
    "uint64": "<Q", "int64": "<q",
    "float": "<f", "double": "<d",
}

# Divergence type constants
DIV_TC_REJECTS_VALID      = "TC_REJECTS_VALID"
DIV_TC_ACCEPTS_INVALID    = "TC_ACCEPTS_INVALID"
DIV_DIFFERENT_RESPONSE    = "DIFFERENT_RESPONSE"
DIV_MISSING_SIDE_EFFECT   = "MISSING_SIDE_EFFECT"
DIV_EXTRA_SIDE_EFFECT     = "EXTRA_SIDE_EFFECT"
DIV_FIELD_INTERP_DIFF     = "FIELD_INTERPRETATION_DIFF"

# Priority levels
PRI_CRITICAL = "CRITICAL"
PRI_HIGH     = "HIGH"
PRI_MEDIUM   = "MEDIUM"
PRI_LOW      = "LOW"

# Validation status tags
_STATUS_VALID            = "VALID"
_STATUS_UNEXPECTED_VALUE = "UNEXPECTED_VALUE"
_STATUS_PARSE_MISMATCH   = "PARSE_MISMATCH"
_STATUS_UNKNOWN_OPCODE   = "UNKNOWN_OPCODE"

# WowPacketParser text header regex
_TXT_HEADER_RE = re.compile(
    r'^(?:ServerToClient|ClientToServer|Server|Client)(?:Opcode)?:\s*'
    r'(\w+)\s*'
    r'\(0x([0-9A-Fa-f]+)\)\s*'
    r'Length:\s*(\d+)'
    r'(?:\s*ConnIdx:\s*\d+)?'
    r'(?:\s*Time:\s*(.+))?$',
    re.IGNORECASE,
)
_TXT_DIRECTION_RE = re.compile(
    r'^(ServerToClient|ClientToServer|Server|Client)', re.IGNORECASE
)
_TXT_FIELD_RE = re.compile(
    r'^\s*(?:\[(\d+)\]\s+)?(\w[\w\s]*?):\s*(.+)$'
)
_TXT_HEX_RE = re.compile(
    r'^[0-9A-Fa-f]{4,8}:\s+((?:[0-9A-Fa-f]{2}\s*)+)'
)

# CSV header detection
_CSV_HEADER_RE = re.compile(
    r'^(?:direction|opcode|timestamp|data)', re.IGNORECASE
)


# ======================================================================
# Data Classes
# ======================================================================

class PktHeader:
    """Parsed .pkt file header."""
    __slots__ = ("version", "build", "locale", "session_key",
                 "sniff_time", "header_size", "valid")

    def __init__(self):
        self.version = 0
        self.build = 0
        self.locale = ""
        self.session_key = b""
        self.sniff_time = 0
        self.header_size = 0
        self.valid = False


class PacketRecord:
    """Single captured packet."""
    __slots__ = ("direction", "opcode", "timestamp", "data", "size",
                 "opcode_name", "fields")

    def __init__(self, direction, opcode, timestamp, data,
                 opcode_name="", fields=None):
        self.direction = direction
        self.opcode = opcode
        self.timestamp = timestamp
        self.data = data
        self.size = len(data) if data else 0
        self.opcode_name = opcode_name
        self.fields = fields or {}


class ParsedPacket:
    """Packet after wire format parsing."""
    __slots__ = ("record", "opcode_name", "handler_name", "field_values",
                 "parse_success", "parse_error", "bytes_consumed",
                 "validation_status", "constraint_violations")

    def __init__(self, record):
        self.record = record
        self.opcode_name = record.opcode_name
        self.handler_name = ""
        self.field_values = {}
        self.parse_success = False
        self.parse_error = ""
        self.bytes_consumed = 0
        self.validation_status = _STATUS_UNKNOWN_OPCODE
        self.constraint_violations = []


class DivergenceFix:
    """Generated fix for a conformance divergence."""
    __slots__ = ("handler_name", "divergence_type", "priority",
                 "description", "evidence_packets", "tc_file",
                 "fix_code", "fix_type")

    def __init__(self, handler_name, divergence_type, priority,
                 description, evidence_packets=None, tc_file="",
                 fix_code="", fix_type=""):
        self.handler_name = handler_name
        self.divergence_type = divergence_type
        self.priority = priority
        self.description = description
        self.evidence_packets = evidence_packets or []
        self.tc_file = tc_file
        self.fix_code = fix_code
        self.fix_type = fix_type

    def to_dict(self):
        return {
            "handler_name": self.handler_name,
            "divergence_type": self.divergence_type,
            "priority": self.priority,
            "description": self.description,
            "evidence_count": len(self.evidence_packets),
            "evidence_samples": self.evidence_packets[:5],
            "tc_file": self.tc_file,
            "fix_code": self.fix_code,
            "fix_type": self.fix_type,
        }


class Divergence:
    """Single detected divergence between binary and TC."""
    __slots__ = ("handler_name", "opcode_name", "div_type", "priority",
                 "description", "evidence", "binary_behavior",
                 "tc_behavior", "field_name", "field_value")

    def __init__(self, **kwargs):
        self.handler_name = kwargs.get("handler_name", "")
        self.opcode_name = kwargs.get("opcode_name", "")
        self.div_type = kwargs.get("div_type", "")
        self.priority = kwargs.get("priority", PRI_MEDIUM)
        self.description = kwargs.get("description", "")
        self.evidence = kwargs.get("evidence", [])
        self.binary_behavior = kwargs.get("binary_behavior", "")
        self.tc_behavior = kwargs.get("tc_behavior", "")
        self.field_name = kwargs.get("field_name", "")
        self.field_value = kwargs.get("field_value", None)

    def to_dict(self):
        return {
            "handler_name": self.handler_name,
            "opcode_name": self.opcode_name,
            "type": self.div_type,
            "priority": self.priority,
            "description": self.description,
            "evidence_count": len(self.evidence),
            "binary_behavior": self.binary_behavior,
            "tc_behavior": self.tc_behavior,
            "field_name": self.field_name,
            "field_value": _json_safe(self.field_value),
        }


# ======================================================================
# BitReader (borrowed from sniff_verification, duplicated for isolation)
# ======================================================================

class _BitReader:
    """Reads data from a byte buffer with bit-level granularity,
    matching WoW's ByteBuffer bit-packing semantics."""

    def __init__(self, data):
        self._data = data
        self._byte_pos = 0
        self._bit_pos = 8
        self._current_byte = 0

    @property
    def bytes_read(self):
        if self._bit_pos < 8:
            return self._byte_pos
        return self._byte_pos

    @property
    def remaining(self):
        return len(self._data) - self._byte_pos

    def _ensure_bit_byte(self):
        if self._bit_pos >= 8:
            if self._byte_pos >= len(self._data):
                raise BufferError("No more data for bit reading")
            self._current_byte = self._data[self._byte_pos]
            self._byte_pos += 1
            self._bit_pos = 0

    def read_bit(self):
        self._ensure_bit_byte()
        value = (self._current_byte >> (7 - self._bit_pos)) & 1
        self._bit_pos += 1
        return value

    def read_bits(self, count):
        if count == 0:
            return 0
        if count > 64:
            raise ValueError(f"Cannot read more than 64 bits: {count}")
        value = 0
        for _ in range(count):
            value = (value << 1) | self.read_bit()
        return value

    def flush_bits(self):
        self._bit_pos = 8

    def read_bytes(self, count):
        self.flush_bits()
        if self._byte_pos + count > len(self._data):
            raise BufferError(
                f"Need {count} bytes, have {len(self._data) - self._byte_pos}")
        result = self._data[self._byte_pos:self._byte_pos + count]
        self._byte_pos += count
        return result

    def read_uint8(self):
        return struct.unpack("<B", self.read_bytes(1))[0]

    def read_int8(self):
        return struct.unpack("<b", self.read_bytes(1))[0]

    def read_uint16(self):
        return struct.unpack("<H", self.read_bytes(2))[0]

    def read_int16(self):
        return struct.unpack("<h", self.read_bytes(2))[0]

    def read_uint32(self):
        return struct.unpack("<I", self.read_bytes(4))[0]

    def read_int32(self):
        return struct.unpack("<i", self.read_bytes(4))[0]

    def read_uint64(self):
        return struct.unpack("<Q", self.read_bytes(8))[0]

    def read_int64(self):
        return struct.unpack("<q", self.read_bytes(8))[0]

    def read_float(self):
        return struct.unpack("<f", self.read_bytes(4))[0]

    def read_double(self):
        return struct.unpack("<d", self.read_bytes(8))[0]

    def read_packed_guid(self):
        self.flush_bits()
        if self._byte_pos + 2 > len(self._data):
            raise BufferError("Not enough data for PackedGuid128 bitmask")
        lo_mask = self._data[self._byte_pos]
        hi_mask = self._data[self._byte_pos + 1]
        self._byte_pos += 2
        guid_bytes = bytearray(16)
        for i in range(8):
            if lo_mask & (1 << i):
                if self._byte_pos >= len(self._data):
                    raise BufferError("Not enough data for PackedGuid128")
                guid_bytes[i] = self._data[self._byte_pos]
                self._byte_pos += 1
        for i in range(8):
            if hi_mask & (1 << i):
                if self._byte_pos >= len(self._data):
                    raise BufferError("Not enough data for PackedGuid128")
                guid_bytes[8 + i] = self._data[self._byte_pos]
                self._byte_pos += 1
        low = struct.unpack("<Q", bytes(guid_bytes[:8]))[0]
        high = struct.unpack("<Q", bytes(guid_bytes[8:]))[0]
        return (low, high)

    def read_string(self, length):
        raw = self.read_bytes(length)
        return raw.decode("utf-8", errors="replace").rstrip("\x00")

    def read_cstring(self):
        self.flush_bits()
        result = bytearray()
        while self._byte_pos < len(self._data):
            b = self._data[self._byte_pos]
            self._byte_pos += 1
            if b == 0:
                break
            result.append(b)
        return result.decode("utf-8", errors="replace")


# ======================================================================
# Phase 1: Sniff File Discovery
# ======================================================================

def _discover_sniff_files(session, sniff_dir=None):
    """Scan configured directories for sniff capture files.

    Returns list of (filepath, file_type) tuples.
    file_type is one of: 'pkt', 'txt', 'csv'
    """
    search_dirs = []

    if sniff_dir and os.path.isdir(sniff_dir):
        search_dirs.append(sniff_dir)

    cfg_sniff_dir = session.cfg.sniff_dir or None
    if cfg_sniff_dir and os.path.isdir(cfg_sniff_dir):
        search_dirs.append(cfg_sniff_dir)

    extraction_dir = getattr(session.cfg, "extraction_dir", None)
    if extraction_dir and os.path.isdir(extraction_dir):
        search_dirs.append(extraction_dir)

    pipeline_dir = session.cfg.get("pipeline_dir") if hasattr(session.cfg, "get") else None
    if pipeline_dir and os.path.isdir(pipeline_dir):
        search_dirs.append(pipeline_dir)

    found = []
    seen = set()

    for d in search_dirs:
        try:
            for entry in os.listdir(d):
                full_path = os.path.join(d, entry)
                if not os.path.isfile(full_path):
                    continue
                norm = os.path.normpath(full_path).lower()
                if norm in seen:
                    continue
                seen.add(norm)

                lower = entry.lower()
                if lower.endswith(".pkt"):
                    found.append((full_path, "pkt"))
                elif lower.endswith(".csv") and _is_packet_csv(full_path):
                    found.append((full_path, "csv"))
                elif lower.endswith(".txt") and _is_packet_txt(full_path):
                    found.append((full_path, "txt"))
                elif lower.endswith(".pkt.txt"):
                    found.append((full_path, "txt"))
                elif lower.endswith(".pkt.sql"):
                    found.append((full_path, "txt"))
        except OSError as e:
            msg_warn(f"Cannot scan directory {d}: {e}")

    return found


def _is_packet_csv(filepath):
    """Heuristic check: does this CSV look like a packet export?"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            header = f.readline()
            return bool(_CSV_HEADER_RE.search(header))
    except (IOError, OSError):
        return False


def _is_packet_txt(filepath):
    """Heuristic check: does this TXT look like WowPacketParser output?"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for _ in range(20):
                line = f.readline()
                if not line:
                    break
                if _TXT_HEADER_RE.search(line):
                    return True
                if "ServerToClient" in line or "ClientToServer" in line:
                    return True
    except (IOError, OSError):
        pass
    return False


# ======================================================================
# Phase 2: Packet Parsing
# ======================================================================

def _parse_sniff_file(filepath, file_type):
    """Parse a single sniff file into PacketRecord objects.

    Returns list of PacketRecord.
    """
    if file_type == "pkt":
        return _parse_pkt_file(filepath)
    elif file_type == "txt":
        return _parse_txt_file(filepath)
    elif file_type == "csv":
        return _parse_csv_file(filepath)
    return []


# -- PKT binary format --------------------------------------------------

def _parse_pkt_header(fp):
    """Parse PKT file header. Returns PktHeader."""
    hdr = PktHeader()

    sig = fp.read(3)
    if sig != _PKT_SIGNATURE:
        return hdr

    ver_raw = fp.read(2)
    if len(ver_raw) < 2:
        return hdr
    hdr.version = struct.unpack(">H", ver_raw)[0]

    if hdr.version == _PKT_VERSION_300:
        # v3.0: 3+2+1+4+4+40+4+4+4 = 66 bytes header
        sniffer_id = fp.read(1)
        if len(sniffer_id) < 1:
            return hdr
        build_raw = fp.read(4)
        if len(build_raw) < 4:
            return hdr
        hdr.build = struct.unpack("<I", build_raw)[0]
        locale_raw = fp.read(4)
        if len(locale_raw) < 4:
            return hdr
        hdr.locale = locale_raw.decode("ascii", errors="replace").rstrip("\x00")
        hdr.session_key = fp.read(40)
        time_raw = fp.read(4)
        if len(time_raw) < 4:
            return hdr
        hdr.sniff_time = struct.unpack("<I", time_raw)[0]
        fp.read(4)  # start ticks
        opt_len_raw = fp.read(4)
        if len(opt_len_raw) >= 4:
            opt_len = struct.unpack("<I", opt_len_raw)[0]
            if opt_len > 0:
                fp.read(opt_len)
        hdr.header_size = fp.tell()
        hdr.valid = True

    elif hdr.version == _PKT_VERSION_301:
        # v3.1: 3+2+1+4+4+16+4+4+4 = 42 bytes header
        sniffer_id = fp.read(1)
        if len(sniffer_id) < 1:
            return hdr
        build_raw = fp.read(4)
        if len(build_raw) < 4:
            return hdr
        hdr.build = struct.unpack("<I", build_raw)[0]
        locale_raw = fp.read(4)
        if len(locale_raw) < 4:
            return hdr
        hdr.locale = locale_raw.decode("ascii", errors="replace").rstrip("\x00")
        hdr.session_key = fp.read(16)
        time_raw = fp.read(4)
        if len(time_raw) < 4:
            return hdr
        hdr.sniff_time = struct.unpack("<I", time_raw)[0]
        fp.read(4)  # start ticks
        opt_len_raw = fp.read(4)
        if len(opt_len_raw) >= 4:
            opt_len = struct.unpack("<I", opt_len_raw)[0]
            if opt_len > 0:
                fp.read(opt_len)
        hdr.header_size = fp.tell()
        hdr.valid = True

    else:
        msg_warn(f"Unknown PKT version: 0x{hdr.version:04X}")

    return hdr


def _parse_pkt_file(filepath):
    """Parse a .pkt binary sniff capture into PacketRecords.

    Per-packet record layout (v3.0/3.1):
      4 bytes  direction (0=CMSG, 1=SMSG) [LE]
      4 bytes  connection_id              [LE]
      4 bytes  timestamp (ticks)          [LE]
      4 bytes  optional_data_len          [LE]
      4 bytes  data_len                   [LE]
      4 bytes  opcode                     [LE]
      N bytes  data payload
    """
    records = []
    try:
        with open(filepath, "rb") as fp:
            hdr = _parse_pkt_header(fp)
            if not hdr.valid:
                msg_warn(f"Invalid PKT header in {os.path.basename(filepath)}")
                return records

            file_size = fp.seek(0, 2)
            fp.seek(hdr.header_size)

            while fp.tell() < file_size:
                rec_hdr = fp.read(24)
                if len(rec_hdr) < 24:
                    break

                direction, conn_id, timestamp, opt_len, data_len, opcode = \
                    struct.unpack("<IIIIII", rec_hdr)

                if opt_len > 0:
                    skipped = fp.read(opt_len)
                    if len(skipped) < opt_len:
                        break

                if data_len > 0x1000000:
                    msg_warn(f"Suspiciously large packet ({data_len} bytes), "
                             f"opcode=0x{opcode:04X}, stopping parse")
                    break

                data = fp.read(data_len) if data_len > 0 else b""
                if len(data) < data_len:
                    break

                dir_str = _DIR_NAMES.get(direction, "UNKNOWN")
                records.append(PacketRecord(dir_str, opcode, timestamp, data))

    except Exception as e:
        msg_error(f"Failed to parse PKT file {filepath}: {e}")

    return records


# -- TXT (WowPacketParser text export) -----------------------------------

def _parse_txt_file(filepath):
    """Parse WowPacketParser text export into PacketRecords."""
    records = []
    current_direction = ""
    current_opcode_name = ""
    current_opcode = 0
    current_length = 0
    current_timestamp = ""
    current_fields = {}
    current_hex = bytearray()
    in_packet = False

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fp:
            for line in fp:
                line = line.rstrip("\n\r")

                hdr_match = _TXT_HEADER_RE.search(line)
                if hdr_match:
                    # Finalize previous packet
                    if in_packet:
                        data = bytes(current_hex) if current_hex else b""
                        records.append(PacketRecord(
                            current_direction, current_opcode,
                            0, data, current_opcode_name, current_fields))

                    current_opcode_name = hdr_match.group(1)
                    current_opcode = int(hdr_match.group(2), 16)
                    current_length = int(hdr_match.group(3))
                    current_timestamp = (hdr_match.group(4) or "").strip()
                    current_fields = {}
                    current_hex = bytearray()
                    in_packet = True

                    dir_match = _TXT_DIRECTION_RE.search(line)
                    if dir_match:
                        d = dir_match.group(1).lower()
                        current_direction = ("CMSG" if "client" in d
                                             else "SMSG")
                    continue

                if not in_packet:
                    continue

                field_match = _TXT_FIELD_RE.search(line)
                if field_match:
                    name = field_match.group(2).strip()
                    value = field_match.group(3).strip()
                    current_fields[name] = value
                    continue

                hex_match = _TXT_HEX_RE.search(line)
                if hex_match:
                    hex_str = hex_match.group(1).strip()
                    try:
                        current_hex.extend(bytes.fromhex(
                            hex_str.replace(" ", "")))
                    except ValueError:
                        pass

        # Finalize last packet
        if in_packet:
            data = bytes(current_hex) if current_hex else b""
            records.append(PacketRecord(
                current_direction, current_opcode,
                0, data, current_opcode_name, current_fields))

    except Exception as e:
        msg_error(f"Failed to parse TXT file {filepath}: {e}")

    return records


# -- CSV export -----------------------------------------------------------

def _parse_csv_file(filepath):
    """Parse a CSV packet export.

    Expected columns (flexible ordering):
      direction, opcode, opcode_name, timestamp, data (hex)
    """
    records = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fp:
            header_line = fp.readline().strip()
            if not header_line:
                return records

            sep = "," if "," in header_line else "\t"
            columns = [c.strip().lower().strip('"').strip("'")
                       for c in header_line.split(sep)]

            col_map = {}
            for i, col in enumerate(columns):
                if "direction" in col or "dir" == col:
                    col_map["direction"] = i
                elif col in ("opcode", "opcode_id", "opcodeid"):
                    col_map["opcode"] = i
                elif col in ("opcode_name", "opcodename", "name"):
                    col_map["name"] = i
                elif "timestamp" in col or "time" in col:
                    col_map["timestamp"] = i
                elif col in ("data", "payload", "hex", "hex_data"):
                    col_map["data"] = i

            if "opcode" not in col_map and "name" not in col_map:
                return records

            for line_num, line in enumerate(fp, start=2):
                line = line.strip()
                if not line:
                    continue

                parts = line.split(sep)

                direction = "CMSG"
                if "direction" in col_map and col_map["direction"] < len(parts):
                    d = parts[col_map["direction"]].strip().strip('"').upper()
                    if "SMSG" in d or "SERVER" in d:
                        direction = "SMSG"

                opcode = 0
                if "opcode" in col_map and col_map["opcode"] < len(parts):
                    raw = parts[col_map["opcode"]].strip().strip('"')
                    try:
                        opcode = int(raw, 0)
                    except ValueError:
                        continue

                opcode_name = ""
                if "name" in col_map and col_map["name"] < len(parts):
                    opcode_name = parts[col_map["name"]].strip().strip('"')

                data = b""
                if "data" in col_map and col_map["data"] < len(parts):
                    hex_str = parts[col_map["data"]].strip().strip('"')
                    hex_str = hex_str.replace(" ", "").replace("0x", "")
                    try:
                        data = bytes.fromhex(hex_str) if hex_str else b""
                    except ValueError:
                        data = b""

                records.append(PacketRecord(
                    direction, opcode, 0, data, opcode_name))

    except Exception as e:
        msg_error(f"Failed to parse CSV file {filepath}: {e}")

    return records


# ======================================================================
# Phase 2 continued: Group and count packets by opcode
# ======================================================================

def _group_packets_by_opcode(records):
    """Group PacketRecords by opcode.

    Returns dict of opcode -> list[PacketRecord].
    """
    grouped = collections.defaultdict(list)
    for rec in records:
        grouped[rec.opcode].append(rec)
    return dict(grouped)


def _count_packet_frequency(grouped):
    """Compute frequency table: opcode -> count."""
    return {opcode: len(pkts) for opcode, pkts in grouped.items()}


# ======================================================================
# Phase 3: Binary Wire Format Validation
# ======================================================================

def _load_wire_formats(db):
    """Load wire formats from kv_store.

    Returns dict of opcode_name -> wire_format_dict.
    """
    data = db.kv_get("wire_formats")
    if data and isinstance(data, dict):
        return data
    return {}


def _load_symbolic_constraints(db):
    """Load symbolic constraints from kv_store.

    Returns dict of handler_name -> {field_name -> constraint_dict}.
    """
    data = db.kv_get("symbolic_constraints")
    if data and isinstance(data, dict):
        return data
    return {}


def _build_opcode_lookup(db):
    """Build opcode index -> handler info lookup from the opcodes table.

    Returns:
      by_value: dict of (direction, opcode_int) -> info_dict
      by_name:  dict of opcode_name -> opcode_int
      name_to_info: dict of opcode_name -> info_dict
    """
    by_value = {}
    by_name = {}
    name_to_info = {}

    try:
        rows = db.fetchall("SELECT * FROM opcodes")
    except Exception:
        return by_value, by_name, name_to_info

    for row in rows:
        direction = row["direction"]
        idx = row["internal_index"]
        wire = row["wire_opcode"]
        tc_name = row["tc_name"] or f"opcode_{idx}"
        handler_ea = row["handler_ea"]

        info = {
            "direction": direction,
            "internal_index": idx,
            "wire_opcode": wire,
            "tc_name": tc_name,
            "handler_ea": handler_ea,
        }

        if wire:
            by_value[(direction, wire)] = info
        by_value[(direction, idx)] = info

        if tc_name:
            by_name[tc_name] = wire or idx
            name_to_info[tc_name] = info

    return by_value, by_name, name_to_info


def _resolve_opcode_name(record, by_value, by_name):
    """Resolve a PacketRecord to its TC opcode name, if known.

    Returns (opcode_name, handler_info_or_None).
    """
    # Try by name first (from txt/csv parsed field)
    if record.opcode_name:
        name = record.opcode_name
        if name in by_name:
            key = (record.direction, by_name[name])
            info = by_value.get(key)
            return name, info
        # Try with prefix
        for prefix in ("CMSG_", "SMSG_"):
            candidate = prefix + name
            if candidate in by_name:
                key = (record.direction, by_name[candidate])
                info = by_value.get(key)
                return candidate, info

    # Try by opcode value
    key = (record.direction, record.opcode)
    info = by_value.get(key)
    if info:
        return info["tc_name"], info

    return record.opcode_name or f"0x{record.opcode:04X}", None


def _decode_packet_fields(data, wire_format):
    """Attempt to decode raw packet data using wire format fields.

    Returns (success, field_values, bytes_consumed, error_msg).
    """
    fields = wire_format.get("fields", [])
    if not fields:
        return True, {}, 0, ""

    if not data:
        if fields:
            return False, {}, 0, "Empty packet but format expects fields"
        return True, {}, 0, ""

    reader = _BitReader(data)
    decoded = {}
    bit_flags = {}
    bit_counts = {}

    for i, field in enumerate(fields):
        ftype = field.get("type", "uint32")
        fname = field.get("name", f"field_{i}")
        is_optional = field.get("is_optional", False)
        condition = field.get("condition", "")
        is_array = field.get("is_array", False)
        array_size_field = field.get("array_size_field", "")
        bit_size = field.get("bit_size", 0)

        # Handle optional fields
        if is_optional and condition:
            if _should_skip_field(condition, bit_flags):
                continue

        # Array count
        array_count = 1
        if is_array and array_size_field:
            count_val = bit_counts.get(array_size_field,
                                       decoded.get(array_size_field))
            if count_val is not None:
                array_count = int(count_val)
                if array_count > 10000:
                    return (False, decoded, reader.bytes_read,
                            f"Array count {array_count} too large "
                            f"for '{fname}'")
            else:
                array_count = 1

        try:
            values = []
            for _ in range(array_count):
                val = _read_field(reader, ftype, bit_size)
                values.append(val)

            if is_array:
                decoded[fname] = values
            else:
                val = values[0] if values else None
                decoded[fname] = val
                if ftype == "bit" and val is not None:
                    bit_flags[fname] = bool(val)
                elif ftype == "bits" and val is not None:
                    bit_counts[fname] = int(val)
                elif ftype in ("uint8", "uint16", "uint32") and val is not None:
                    bit_counts[fname] = int(val)

        except (BufferError, struct.error, ValueError, OverflowError) as e:
            return (False, decoded, reader.bytes_read,
                    f"Field '{fname}' (type={ftype}): {e}")

    remaining = len(data) - reader.bytes_read
    error_msg = ""
    if remaining > 0:
        error_msg = f"{remaining} unconsumed bytes"

    return True, decoded, reader.bytes_read, error_msg


def _read_field(reader, ftype, bit_size=0):
    """Read a single field value from the BitReader."""
    if ftype == "bit":
        return reader.read_bit()
    elif ftype == "bits":
        return reader.read_bits(bit_size)
    elif ftype == "uint8":
        return reader.read_uint8()
    elif ftype == "int8":
        return reader.read_int8()
    elif ftype == "uint16":
        return reader.read_uint16()
    elif ftype == "int16":
        return reader.read_int16()
    elif ftype == "uint32":
        return reader.read_uint32()
    elif ftype == "int32":
        return reader.read_int32()
    elif ftype == "uint64":
        return reader.read_uint64()
    elif ftype == "int64":
        return reader.read_int64()
    elif ftype == "float":
        return reader.read_float()
    elif ftype == "double":
        return reader.read_double()
    elif ftype in ("packed_guid", "ObjectGuid"):
        low, high = reader.read_packed_guid()
        return f"0x{high:016X}{low:016X}"
    elif ftype == "string":
        return reader.read_cstring()
    elif ftype == "flush":
        reader.flush_bits()
        return None
    else:
        return reader.read_uint32()


def _should_skip_field(condition, bit_flags):
    """Evaluate optional-field condition. Returns True to SKIP."""
    if not condition or not bit_flags:
        return False

    negated = False
    check = condition.strip()
    if check.startswith("!"):
        negated = True
        check = check[1:].strip()

    # Handle comparison: "var != 0", "var == 1"
    cmp_match = re.match(r'(\w+)\s*([!=<>]+)\s*(\d+)', check)
    if cmp_match:
        var_name = cmp_match.group(1)
        op = cmp_match.group(2)
        cmp_val = int(cmp_match.group(3))
        flag_val = bit_flags.get(var_name)
        if flag_val is None:
            return False
        actual = 1 if flag_val else 0
        if op in ("==", "="):
            return not (actual == cmp_val)
        elif op in ("!=", "<>"):
            return not (actual != cmp_val)
        elif op == ">":
            return not (actual > cmp_val)
        elif op == "<":
            return not (actual < cmp_val)

    flag_val = bit_flags.get(check)
    if flag_val is None:
        for k, v in bit_flags.items():
            if k in check or check in k:
                flag_val = v
                break

    if flag_val is None:
        return False

    cond_met = bool(flag_val) if not negated else not bool(flag_val)
    return not cond_met


def _validate_field_against_constraint(field_name, value, constraints):
    """Check a single field value against its symbolic constraint.

    Returns (is_valid, violation_description).
    """
    if not constraints or field_name not in constraints:
        return True, ""

    constraint = constraints[field_name]
    ctype = constraint.get("ctype", constraint.get("type", "unconstrained"))

    if ctype == "unconstrained":
        return True, ""

    if ctype == "range":
        lo = constraint.get("min_val", constraint.get("min"))
        hi = constraint.get("max_val", constraint.get("max"))
        if lo is not None and hi is not None:
            if isinstance(value, (int, float)):
                if value < lo or value > hi:
                    return (False,
                            f"{field_name}={value} outside range "
                            f"[{lo}, {hi}]")
        return True, ""

    if ctype == "set":
        valid_values = constraint.get("values", [])
        if valid_values and isinstance(value, (int, float, str)):
            # Allow both int and string comparison
            if value not in valid_values and str(value) not in valid_values:
                return (False,
                        f"{field_name}={value} not in allowed set "
                        f"{list(valid_values)[:10]}")
        return True, ""

    if ctype == "bitmask":
        mask = constraint.get("mask")
        expected = constraint.get("expected")
        if mask is not None and expected is not None:
            if isinstance(value, int):
                if (value & mask) != expected:
                    return (False,
                            f"{field_name}={value:#x}: "
                            f"({value:#x} & {mask:#x}) != {expected:#x}")
        return True, ""

    return True, ""


def _validate_parsed_packet(parsed, wire_format, constraints):
    """Validate a parsed packet against symbolic constraints.

    Sets parsed.validation_status and parsed.constraint_violations.
    """
    if not parsed.parse_success:
        parsed.validation_status = _STATUS_PARSE_MISMATCH
        return

    handler_constraints = {}
    if constraints and parsed.handler_name:
        handler_constraints = constraints.get(parsed.handler_name, {})
        if not handler_constraints and parsed.opcode_name:
            handler_constraints = constraints.get(parsed.opcode_name, {})

    violations = []
    for fname, value in parsed.field_values.items():
        if value is None:
            continue
        if isinstance(value, list):
            for i, v in enumerate(value):
                is_valid, desc = _validate_field_against_constraint(
                    fname, v, handler_constraints)
                if not is_valid:
                    violations.append(f"[{i}] {desc}")
        else:
            is_valid, desc = _validate_field_against_constraint(
                fname, value, handler_constraints)
            if not is_valid:
                violations.append(desc)

    parsed.constraint_violations = violations

    if violations:
        parsed.validation_status = _STATUS_UNEXPECTED_VALUE
    else:
        parsed.validation_status = _STATUS_VALID


# ======================================================================
# Phase 4: TC Behavior Comparison
# ======================================================================

def _load_behavioral_specs(db):
    """Load behavioral specs from kv_store.

    Returns dict of handler_name -> spec_dict.
    """
    data = db.kv_get("behavioral_spec")
    if data and isinstance(data, dict):
        return data
    return {}


def _load_tc_alignment(db):
    """Load binary-TC alignment data from kv_store.

    Returns dict with handler-level alignment info.
    """
    data = db.kv_get("binary_tc_alignment")
    if data and isinstance(data, dict):
        return data
    return {}


def _simulate_binary_path(parsed, spec):
    """Given a parsed packet and a behavioral spec, determine which
    execution path the binary would take.

    Returns dict with:
      accepted: bool
      path_id: str (identifier for the path taken)
      response_opcode: str or None
      side_effects: list[str]
      error_code: int or None
    """
    result = {
        "accepted": True,
        "path_id": "default",
        "response_opcode": None,
        "side_effects": [],
        "error_code": None,
    }

    if not spec:
        return result

    # Walk the spec's execution paths to find a match
    paths = spec.get("paths", spec.get("execution_paths", []))
    if not paths:
        return result

    for path in paths:
        conditions = path.get("conditions", [])
        if _evaluate_path_conditions(conditions, parsed.field_values):
            result["path_id"] = path.get("id", path.get("name", "matched"))
            outcome = path.get("outcome", {})
            result["accepted"] = outcome.get("accepted",
                                              outcome.get("success", True))
            result["response_opcode"] = outcome.get("response",
                                                     outcome.get("response_opcode"))
            result["side_effects"] = outcome.get("side_effects", [])
            result["error_code"] = outcome.get("error_code",
                                                outcome.get("error"))
            break

    return result


def _evaluate_path_conditions(conditions, field_values):
    """Check whether all conditions of a behavioral path are satisfied
    by the given field values.

    Each condition is a dict like:
      {"field": "decorEntryId", "op": ">", "value": 0}
    or a string like "decorEntryId > 0".
    """
    if not conditions:
        return True

    for cond in conditions:
        if isinstance(cond, str):
            if not _eval_string_condition(cond, field_values):
                return False
        elif isinstance(cond, dict):
            field = cond.get("field", "")
            op = cond.get("op", "==")
            target = cond.get("value", 0)
            actual = field_values.get(field)
            if actual is None:
                return False
            if not _compare(actual, op, target):
                return False
        # else skip unknown format

    return True


def _eval_string_condition(cond_str, field_values):
    """Evaluate a string condition like 'decorEntryId > 0'."""
    m = re.match(r'(\w+)\s*([!=<>]+)\s*(.+)', cond_str.strip())
    if not m:
        return True  # Cannot parse, assume satisfied

    field = m.group(1)
    op = m.group(2)
    target_str = m.group(3).strip()

    actual = field_values.get(field)
    if actual is None:
        return False

    try:
        target = int(target_str, 0)
    except ValueError:
        try:
            target = float(target_str)
        except ValueError:
            target = target_str

    return _compare(actual, op, target)


def _compare(actual, op, target):
    """Compare actual value against target using the given operator."""
    try:
        if op in ("==", "="):
            return actual == target
        elif op in ("!=", "<>"):
            return actual != target
        elif op == ">":
            return actual > target
        elif op == ">=":
            return actual >= target
        elif op == "<":
            return actual < target
        elif op == "<=":
            return actual <= target
    except TypeError:
        return False
    return True


def _simulate_tc_behavior(parsed, alignment_data, name_to_info):
    """Simulate what TC's handler would do with this packet.

    Uses alignment data to check:
      - TC validation patterns
      - TC response generation
      - TC side effects

    Returns dict similar to _simulate_binary_path output.
    """
    result = {
        "accepted": True,
        "path_id": "tc_default",
        "response_opcode": None,
        "side_effects": [],
        "error_code": None,
    }

    if not alignment_data:
        return result

    # Look up handler-specific alignment
    handlers = alignment_data.get("handlers", alignment_data.get("results", []))

    handler_entry = None
    for h in handlers if isinstance(handlers, list) else []:
        if h.get("tc_name") == parsed.handler_name:
            handler_entry = h
            break
        if h.get("tc_name") == parsed.opcode_name:
            handler_entry = h
            break

    if isinstance(handlers, dict):
        handler_entry = handlers.get(parsed.handler_name,
                                     handlers.get(parsed.opcode_name))

    if not handler_entry:
        return result

    # Check TC validations against field values
    tc_validations = handler_entry.get("validations",
                                       handler_entry.get("tc_validations", []))
    for validation in tc_validations:
        vfield = validation.get("field", "")
        vop = validation.get("op", validation.get("operator", ""))
        vtarget = validation.get("value", validation.get("threshold"))
        rejection = validation.get("rejection",
                                   validation.get("rejects_if", False))

        actual = parsed.field_values.get(vfield)
        if actual is None:
            continue

        if vtarget is not None and vop:
            check = _compare(actual, vop, vtarget)
            if rejection and check:
                result["accepted"] = False
                result["error_code"] = validation.get("error_code")
                result["path_id"] = f"tc_reject_{vfield}"
                break
            elif not rejection and not check:
                result["accepted"] = False
                result["error_code"] = validation.get("error_code")
                result["path_id"] = f"tc_reject_{vfield}"
                break

    # Gather TC side effects
    result["side_effects"] = handler_entry.get("side_effects",
                                               handler_entry.get("tc_side_effects", []))
    result["response_opcode"] = handler_entry.get("response",
                                                  handler_entry.get("response_opcode"))

    return result


# ======================================================================
# Phase 5: Divergence Detection
# ======================================================================

def _detect_divergences(parsed_packets, binary_results, tc_results):
    """Compare binary vs TC behavior for all parsed packets.

    Args:
        parsed_packets: list of ParsedPacket
        binary_results: dict of opcode_name -> [binary_sim_result, ...]
        tc_results:     dict of opcode_name -> [tc_sim_result, ...]

    Returns list of Divergence objects.
    """
    divergences = []

    for opname in binary_results:
        bin_list = binary_results[opname]
        tc_list = tc_results.get(opname, [])

        if not tc_list:
            continue

        # Pair up results (they are produced in the same packet order)
        for i, (bin_res, tc_res) in enumerate(zip(bin_list, tc_list)):
            divs = _compare_behaviors(opname, bin_res, tc_res, i)
            divergences.extend(divs)

    return divergences


def _compare_behaviors(opcode_name, bin_res, tc_res, packet_idx):
    """Compare a single packet's binary vs TC simulation result.

    Returns list of Divergence objects (may be empty).
    """
    divs = []

    bin_accepted = bin_res.get("accepted", True)
    tc_accepted = tc_res.get("accepted", True)

    # TC rejects what binary accepts
    if bin_accepted and not tc_accepted:
        divs.append(Divergence(
            opcode_name=opcode_name,
            div_type=DIV_TC_REJECTS_VALID,
            priority=PRI_HIGH,
            description=(
                f"Binary accepts packet #{packet_idx} for {opcode_name} "
                f"but TC rejects it (TC path: {tc_res.get('path_id', '?')})"
            ),
            binary_behavior=f"accepted, path={bin_res.get('path_id', '?')}",
            tc_behavior=f"rejected, error={tc_res.get('error_code', '?')}",
            evidence=[packet_idx],
        ))

    # TC accepts what binary rejects
    elif not bin_accepted and tc_accepted:
        divs.append(Divergence(
            opcode_name=opcode_name,
            div_type=DIV_TC_ACCEPTS_INVALID,
            priority=PRI_HIGH,
            description=(
                f"Binary rejects packet #{packet_idx} for {opcode_name} "
                f"but TC accepts it (binary path: {bin_res.get('path_id', '?')})"
            ),
            binary_behavior=f"rejected, error={bin_res.get('error_code', '?')}",
            tc_behavior=f"accepted, path={tc_res.get('path_id', '?')}",
            evidence=[packet_idx],
        ))

    # Both accept but different responses
    elif bin_accepted and tc_accepted:
        bin_resp = bin_res.get("response_opcode")
        tc_resp = tc_res.get("response_opcode")
        if bin_resp and tc_resp and bin_resp != tc_resp:
            divs.append(Divergence(
                opcode_name=opcode_name,
                div_type=DIV_DIFFERENT_RESPONSE,
                priority=PRI_MEDIUM,
                description=(
                    f"Different response for {opcode_name} packet #{packet_idx}: "
                    f"binary sends {bin_resp}, TC sends {tc_resp}"
                ),
                binary_behavior=f"response={bin_resp}",
                tc_behavior=f"response={tc_resp}",
                evidence=[packet_idx],
            ))

        # Check side effects
        bin_fx = set(bin_res.get("side_effects", []))
        tc_fx = set(tc_res.get("side_effects", []))

        missing = bin_fx - tc_fx
        extra = tc_fx - bin_fx

        if missing:
            divs.append(Divergence(
                opcode_name=opcode_name,
                div_type=DIV_MISSING_SIDE_EFFECT,
                priority=PRI_MEDIUM,
                description=(
                    f"TC missing side effects for {opcode_name}: "
                    f"{', '.join(sorted(missing))}"
                ),
                binary_behavior=f"effects={sorted(bin_fx)}",
                tc_behavior=f"effects={sorted(tc_fx)}",
                evidence=[packet_idx],
            ))

        if extra:
            divs.append(Divergence(
                opcode_name=opcode_name,
                div_type=DIV_EXTRA_SIDE_EFFECT,
                priority=PRI_LOW,
                description=(
                    f"TC has extra side effects for {opcode_name}: "
                    f"{', '.join(sorted(extra))}"
                ),
                binary_behavior=f"effects={sorted(bin_fx)}",
                tc_behavior=f"effects={sorted(tc_fx)}",
                evidence=[packet_idx],
            ))

    # Different error codes on rejection
    elif not bin_accepted and not tc_accepted:
        bin_err = bin_res.get("error_code")
        tc_err = tc_res.get("error_code")
        if bin_err is not None and tc_err is not None and bin_err != tc_err:
            divs.append(Divergence(
                opcode_name=opcode_name,
                div_type=DIV_DIFFERENT_RESPONSE,
                priority=PRI_MEDIUM,
                description=(
                    f"Both reject {opcode_name} packet #{packet_idx} but "
                    f"with different error codes: "
                    f"binary={bin_err}, TC={tc_err}"
                ),
                binary_behavior=f"error_code={bin_err}",
                tc_behavior=f"error_code={tc_err}",
                evidence=[packet_idx],
            ))

    return divs


def _detect_field_interpretation_diffs(parsed_packets, wire_formats,
                                       alignment_data):
    """Detect cases where binary and TC interpret the same field differently.

    E.g., binary reads uint16 but TC reads uint32.

    Returns list of Divergence objects.
    """
    divs = []

    if not alignment_data:
        return divs

    handlers = alignment_data.get("handlers",
                                  alignment_data.get("results", {}))

    for opname, fmt in wire_formats.items():
        binary_fields = fmt.get("fields", [])
        if not binary_fields:
            continue

        handler_entry = None
        if isinstance(handlers, list):
            for h in handlers:
                if h.get("tc_name") == opname:
                    handler_entry = h
                    break
        elif isinstance(handlers, dict):
            handler_entry = handlers.get(opname)

        if not handler_entry:
            continue

        tc_fields = handler_entry.get("fields",
                                      handler_entry.get("tc_fields", []))
        if not tc_fields:
            continue

        # Compare field by field where names can be matched
        tc_field_map = {}
        for tf in tc_fields:
            name = tf.get("name", "")
            if name:
                tc_field_map[name.lower()] = tf

        for bf in binary_fields:
            bname = bf.get("name", "")
            btype = bf.get("type", "")
            if not bname:
                continue

            tc_f = tc_field_map.get(bname.lower())
            if not tc_f:
                continue

            tc_type = tc_f.get("type", "")
            if tc_type and btype and tc_type != btype:
                # Size mismatch
                bsize = _FIXED_TYPE_SIZES.get(btype, 0)
                tsize = _FIXED_TYPE_SIZES.get(tc_type, 0)
                if bsize > 0 and tsize > 0 and bsize != tsize:
                    divs.append(Divergence(
                        opcode_name=opname,
                        div_type=DIV_FIELD_INTERP_DIFF,
                        priority=(PRI_HIGH if abs(bsize - tsize) >= 2
                                  else PRI_MEDIUM),
                        description=(
                            f"Field '{bname}' in {opname}: binary reads "
                            f"{btype} ({bsize}B) but TC reads "
                            f"{tc_type} ({tsize}B)"
                        ),
                        field_name=bname,
                        binary_behavior=f"type={btype}",
                        tc_behavior=f"type={tc_type}",
                    ))

    return divs


def _assign_priorities(divergences):
    """Refine priorities based on divergence aggregation.

    Divergences confirmed by many packets get higher priority.
    """
    # Group by (opcode, type, field)
    groups = collections.defaultdict(list)
    for div in divergences:
        key = (div.opcode_name, div.div_type, div.field_name)
        groups[key].append(div)

    for key, group in groups.items():
        count = len(group)
        if count >= 10:
            for div in group:
                if div.priority == PRI_MEDIUM:
                    div.priority = PRI_HIGH
                elif div.priority == PRI_HIGH:
                    div.priority = PRI_CRITICAL
        elif count >= 5:
            for div in group:
                if div.priority == PRI_LOW:
                    div.priority = PRI_MEDIUM


# ======================================================================
# Phase 6: Auto-Fix Generation
# ======================================================================

def _generate_fixes(divergences, wire_formats, constraints, tc_source_dir):
    """Generate DivergenceFix objects for each divergence cluster.

    Groups divergences by handler and produces one fix per unique issue.
    """
    fixes = []

    # Group divergences by (handler, type, field)
    grouped = collections.defaultdict(list)
    for div in divergences:
        key = (div.handler_name or div.opcode_name,
               div.div_type, div.field_name)
        grouped[key].append(div)

    for (handler, div_type, field), divs in grouped.items():
        representative = divs[0]
        evidence = []
        for d in divs[:20]:
            evidence.extend(d.evidence[:3])

        fix = _create_fix_for_divergence(
            handler, div_type, field, divs, evidence,
            wire_formats, constraints, tc_source_dir)
        if fix:
            fixes.append(fix)

    return fixes


def _create_fix_for_divergence(handler, div_type, field, divs, evidence,
                               wire_formats, constraints, tc_source_dir):
    """Create a single DivergenceFix for a cluster of divergences."""
    representative = divs[0]
    count = len(divs)

    # Determine TC source file
    tc_file = _guess_tc_source_file(handler, tc_source_dir)

    # Priority is the max across the group
    priority_order = {PRI_CRITICAL: 4, PRI_HIGH: 3, PRI_MEDIUM: 2, PRI_LOW: 1}
    best_pri = max(divs, key=lambda d: priority_order.get(d.priority, 0))
    priority = best_pri.priority

    fix_type, fix_code, description = _generate_fix_code(
        handler, div_type, field, divs, wire_formats, constraints)

    return DivergenceFix(
        handler_name=handler,
        divergence_type=div_type,
        priority=priority,
        description=description,
        evidence_packets=evidence[:10],
        tc_file=tc_file,
        fix_code=fix_code,
        fix_type=fix_type,
    )


def _generate_fix_code(handler, div_type, field, divs, wire_formats,
                       constraints):
    """Generate C++ fix code for a divergence.

    Returns (fix_type, fix_code, description).
    """
    count = len(divs)
    rep = divs[0]

    if div_type == DIV_TC_REJECTS_VALID:
        # Binary accepts but TC rejects -- widen TC validation
        fix_type = "WIDEN_VALIDATION"
        description = (
            f"TC rejects valid packets for {handler} "
            f"({count} evidence packets). "
            f"{rep.description}"
        )

        if field:
            # Try to get the binary's constraint for this field
            bin_constraint = _get_binary_constraint(handler, field, constraints)
            if bin_constraint:
                fix_code = (
                    f"// DIVERGENCE: TC rejects packets that binary accepts\n"
                    f"// Evidence: {count} packets show binary accepts "
                    f"wider range for '{field}'\n"
                    f"// Binary constraint: {bin_constraint}\n"
                    f"// Fix: Widen validation in {handler}\n"
                    f"//\n"
                    f"// Update the validation check for '{field}' to match "
                    f"binary behavior:\n"
                    f"//   {bin_constraint}\n"
                )
            else:
                fix_code = (
                    f"// DIVERGENCE: TC rejects packets that binary accepts\n"
                    f"// Evidence: {count} packets\n"
                    f"// Fix: Review validation of '{field}' in {handler}\n"
                    f"// TC may have an overly strict check\n"
                )
        else:
            fix_code = (
                f"// DIVERGENCE: TC rejects valid packets for {handler}\n"
                f"// Evidence: {count} packets were accepted by binary "
                f"but would be rejected by TC\n"
                f"// Fix: Review all validation checks in {handler}\n"
            )
        return fix_type, fix_code, description

    elif div_type == DIV_TC_ACCEPTS_INVALID:
        fix_type = "ADD_VALIDATION"
        description = (
            f"TC accepts invalid packets for {handler} "
            f"({count} evidence packets). "
            f"{rep.description}"
        )
        fix_code = (
            f"// DIVERGENCE: TC accepts packets that binary rejects\n"
            f"// Evidence: {count} packets rejected by binary "
            f"but TC would accept\n"
            f"// Fix: Add missing validation in {handler}\n"
        )
        if field:
            fix_code += (
                f"// Add validation for field '{field}' matching binary behavior\n"
            )
        return fix_type, fix_code, description

    elif div_type == DIV_DIFFERENT_RESPONSE:
        fix_type = "FIX_RESPONSE"
        description = (
            f"Different response for {handler} ({count} evidence). "
            f"{rep.description}"
        )
        fix_code = (
            f"// DIVERGENCE: Different response between binary and TC\n"
            f"// Binary: {rep.binary_behavior}\n"
            f"// TC:     {rep.tc_behavior}\n"
            f"// Evidence: {count} packets\n"
            f"// Fix: Update response in {handler} to match binary\n"
        )
        return fix_type, fix_code, description

    elif div_type == DIV_MISSING_SIDE_EFFECT:
        fix_type = "ADD_SIDE_EFFECT"
        description = (
            f"TC missing side effects for {handler} ({count} evidence). "
            f"{rep.description}"
        )
        fix_code = (
            f"// DIVERGENCE: TC is missing side effects that binary performs\n"
            f"// Binary: {rep.binary_behavior}\n"
            f"// TC:     {rep.tc_behavior}\n"
            f"// Fix: Add missing side effects in {handler}\n"
        )
        return fix_type, fix_code, description

    elif div_type == DIV_EXTRA_SIDE_EFFECT:
        fix_type = "REMOVE_SIDE_EFFECT"
        description = (
            f"TC has extra side effects for {handler} ({count} evidence). "
            f"{rep.description}"
        )
        fix_code = (
            f"// DIVERGENCE: TC performs extra side effects not in binary\n"
            f"// Binary: {rep.binary_behavior}\n"
            f"// TC:     {rep.tc_behavior}\n"
            f"// Fix: Remove extra side effects from {handler}\n"
        )
        return fix_type, fix_code, description

    elif div_type == DIV_FIELD_INTERP_DIFF:
        fix_type = "FIX_FIELD_TYPE"
        description = (
            f"Field type mismatch in {handler}: {rep.description}"
        )
        fix_code = (
            f"// DIVERGENCE: Field interpretation differs\n"
            f"// Binary: {rep.binary_behavior}\n"
            f"// TC:     {rep.tc_behavior}\n"
            f"// Fix: Update field type in {handler} packet struct\n"
        )
        if field:
            fix_code += f"// Change type of '{field}' to match binary\n"
        return fix_type, fix_code, description

    # Fallback
    fix_type = "REVIEW"
    description = f"Divergence in {handler}: {rep.description}"
    fix_code = (
        f"// DIVERGENCE: {div_type} in {handler}\n"
        f"// {rep.description}\n"
        f"// Evidence: {count} packets\n"
        f"// Fix: Manual review required\n"
    )
    return fix_type, fix_code, description


def _get_binary_constraint(handler, field, constraints):
    """Look up the binary's constraint for a field in a handler."""
    if not constraints:
        return None

    handler_c = constraints.get(handler, {})
    if not handler_c:
        return None

    field_c = handler_c.get(field)
    if not field_c:
        return None

    ctype = field_c.get("ctype", field_c.get("type", ""))
    if ctype == "range":
        lo = field_c.get("min_val", field_c.get("min"))
        hi = field_c.get("max_val", field_c.get("max"))
        return f"{field} in [{lo}, {hi}]"
    elif ctype == "set":
        vals = field_c.get("values", [])
        return f"{field} in {{{', '.join(str(v) for v in list(vals)[:10])}}}"
    elif ctype == "bitmask":
        mask = field_c.get("mask")
        expected = field_c.get("expected")
        return f"({field} & {mask:#x}) == {expected:#x}"

    return str(field_c)


def _guess_tc_source_file(handler, tc_source_dir):
    """Guess the TrinityCore source file for a handler."""
    if not tc_source_dir:
        return ""

    # Derive from handler name: HandleHousingFoo -> HousingHandler.cpp
    m = re.match(r'Handle(\w+?)(?:Opcode|Callback|Result)?$', handler)
    if m:
        system = m.group(1)
        # Try common patterns
        for suffix in ("Handler.cpp", "Handlers.cpp", ".cpp"):
            candidate = os.path.join(
                tc_source_dir, "src", "server", "game", "Handlers",
                f"{system}{suffix}")
            if os.path.isfile(candidate):
                return candidate

        # Try first word
        first_word_m = re.match(r'([A-Z][a-z]+)', system)
        if first_word_m:
            first_word = first_word_m.group(1)
            handlers_dir = os.path.join(
                tc_source_dir, "src", "server", "game", "Handlers")
            if os.path.isdir(handlers_dir):
                for fname in os.listdir(handlers_dir):
                    if first_word.lower() in fname.lower() and fname.endswith(".cpp"):
                        return os.path.join(handlers_dir, fname)

    return ""


# ======================================================================
# Phase 7: Statistical Analysis
# ======================================================================

def _compute_statistics(parsed_packets, divergences, opcode_lookup_by_value,
                        grouped_by_opcode):
    """Compute comprehensive statistics.

    Returns a dict of statistical summaries.
    """
    total_packets = len(parsed_packets)
    cmsg_packets = sum(1 for p in parsed_packets
                       if p.record.direction == "CMSG")
    smsg_packets = total_packets - cmsg_packets

    # Per-opcode stats
    opcodes_seen = set()
    per_opcode = collections.defaultdict(lambda: {
        "total": 0, "parsed_ok": 0, "valid": 0,
        "unexpected": 0, "mismatch": 0, "divergences": 0,
    })

    for p in parsed_packets:
        opcodes_seen.add(p.opcode_name)
        stats = per_opcode[p.opcode_name]
        stats["total"] += 1
        if p.parse_success:
            stats["parsed_ok"] += 1
        if p.validation_status == _STATUS_VALID:
            stats["valid"] += 1
        elif p.validation_status == _STATUS_UNEXPECTED_VALUE:
            stats["unexpected"] += 1
        elif p.validation_status == _STATUS_PARSE_MISMATCH:
            stats["mismatch"] += 1

    for div in divergences:
        per_opcode[div.opcode_name]["divergences"] += 1

    # Count total known CMSG opcodes
    total_cmsg_opcodes = 0
    for (direction, _), info in opcode_lookup_by_value.items():
        if direction == "CMSG":
            total_cmsg_opcodes += 1
    # Deduplicate (by_value has both wire and internal index keys)
    known_cmsg = set()
    for (direction, _), info in opcode_lookup_by_value.items():
        if direction == "CMSG":
            known_cmsg.add(info["tc_name"])
    total_cmsg_opcodes = len(known_cmsg)

    covered_opcodes = set()
    for p in parsed_packets:
        if p.record.direction == "CMSG":
            covered_opcodes.add(p.opcode_name)

    coverage_pct = (len(covered_opcodes) / max(total_cmsg_opcodes, 1)) * 100

    # Uncovered opcodes
    uncovered = sorted(known_cmsg - covered_opcodes)

    # Divergence type counts
    div_by_type = collections.Counter(d.div_type for d in divergences)
    div_by_priority = collections.Counter(d.priority for d in divergences)

    # Most problematic handlers
    handler_div_counts = collections.Counter(
        d.handler_name or d.opcode_name for d in divergences)
    top_problematic = handler_div_counts.most_common(20)

    # Time-based patterns
    time_buckets = collections.defaultdict(int)
    for p in parsed_packets:
        ts = p.record.timestamp
        if ts > 0:
            # Bucket by 60-second intervals
            bucket = (ts // 60000) * 60000  # millisecond ticks
            time_buckets[bucket] += 1

    return {
        "total_packets": total_packets,
        "cmsg_packets": cmsg_packets,
        "smsg_packets": smsg_packets,
        "opcodes_seen": len(opcodes_seen),
        "opcodes_total": total_cmsg_opcodes,
        "coverage_pct": round(coverage_pct, 1),
        "covered_opcodes": len(covered_opcodes),
        "uncovered_opcodes": uncovered[:100],
        "per_opcode": {k: dict(v) for k, v in per_opcode.items()},
        "divergence_by_type": dict(div_by_type),
        "divergence_by_priority": dict(div_by_priority),
        "top_problematic_handlers": top_problematic,
        "time_bucket_count": len(time_buckets),
    }


# ======================================================================
# Phase 8: Report Assembly
# ======================================================================

def _assemble_report(sniff_files, parsed_packets, divergences, fixes,
                     statistics, elapsed):
    """Assemble the full conformance loop report.

    Returns a dict suitable for kv_set storage.
    """
    # Per-handler sub-reports
    per_handler = collections.defaultdict(lambda: {
        "packets_seen": 0,
        "divergences": [],
        "fixes": [],
    })

    for p in parsed_packets:
        handler = p.handler_name or p.opcode_name
        per_handler[handler]["packets_seen"] += 1

    for div in divergences:
        handler = div.handler_name or div.opcode_name
        per_handler[handler]["divergences"].append(div.to_dict())

    for fix in fixes:
        per_handler[fix.handler_name]["fixes"].append(fix.to_dict())

    # Cap per-handler divergences for storage
    for handler, data in per_handler.items():
        if len(data["divergences"]) > 50:
            data["divergences"] = data["divergences"][:50]

    report = {
        "timestamp": time.time(),
        "elapsed_seconds": round(elapsed, 2),
        "sniff_files_processed": len(sniff_files),
        "total_packets": statistics["total_packets"],
        "cmsg_packets": statistics["cmsg_packets"],
        "opcodes_covered": statistics["covered_opcodes"],
        "opcodes_total": statistics["opcodes_total"],
        "coverage_pct": statistics["coverage_pct"],
        "total_divergences": len(divergences),
        "divergences_by_type": statistics["divergence_by_type"],
        "divergences_by_priority": statistics["divergence_by_priority"],
        "fixes": [f.to_dict() for f in fixes],
        "per_handler": dict(per_handler),
        "uncovered_opcodes": statistics["uncovered_opcodes"],
        "top_problematic_handlers": statistics["top_problematic_handlers"],
    }

    return report


# ======================================================================
# JSON serialization helper
# ======================================================================

def _json_safe(val):
    """Convert a value to something JSON-serializable."""
    if val is None:
        return None
    if isinstance(val, float):
        if val != val:
            return "NaN"
        if val == float("inf"):
            return "Inf"
        if val == float("-inf"):
            return "-Inf"
        return round(val, 6)
    if isinstance(val, (int, bool, str)):
        return val
    if isinstance(val, (bytes, bytearray)):
        return val.hex()
    if isinstance(val, (list, tuple)):
        return [_json_safe(x) for x in val]
    if isinstance(val, dict):
        return {str(k): _json_safe(v) for k, v in val.items()}
    if isinstance(val, set):
        return sorted(str(x) for x in val)
    return str(val)


# ======================================================================
# Main Entry Points
# ======================================================================

def run_conformance_loop(session, sniff_dir=None):
    """Run the full sniff conformance loop pipeline.

    Discovers sniff files, parses packets, validates against binary wire
    formats and symbolic constraints, compares binary vs TC behavior,
    detects divergences, generates fixes, and stores the report.

    Args:
        session: PluginSession with .db and .cfg access.
        sniff_dir: Optional directory to scan for sniff files.

    Returns:
        Number of divergences found.
    """
    db = session.db
    start_time = time.time()

    msg_info("=" * 60)
    msg_info("Starting Sniff Conformance Loop")
    msg_info("=" * 60)

    # -- Phase 1: Discover sniff files --
    msg_info("Phase 1: Discovering sniff files...")
    sniff_files = _discover_sniff_files(session, sniff_dir)

    if not sniff_files:
        msg_warn("No sniff files found. Configure 'sniff_dir' in settings "
                 "or place .pkt/.txt/.csv files in the extraction directory.")
        db.kv_set(_KV_KEY, _empty_report())
        db.commit()
        return 0

    msg_info(f"  Found {len(sniff_files)} sniff file(s):")
    for path, ftype in sniff_files:
        msg(f"    [{ftype.upper():3s}] {os.path.basename(path)}")

    # -- Phase 2: Parse packets --
    msg_info("Phase 2: Parsing packets...")
    all_records = []
    for filepath, ftype in sniff_files:
        msg_info(f"  Parsing {os.path.basename(filepath)}...")
        records = _parse_sniff_file(filepath, ftype)
        msg_info(f"    {len(records)} packets extracted")
        all_records.extend(records)

    if not all_records:
        msg_warn("No packets found in any sniff file.")
        db.kv_set(_KV_KEY, _empty_report())
        db.commit()
        return 0

    grouped = _group_packets_by_opcode(all_records)
    freq = _count_packet_frequency(grouped)
    msg_info(f"  Total: {len(all_records)} packets across "
             f"{len(grouped)} opcodes")

    # Filter to CMSG only for conformance analysis
    cmsg_records = [r for r in all_records if r.direction == "CMSG"]
    msg_info(f"  CMSG packets for analysis: {len(cmsg_records)}")

    # -- Load analyzer data --
    msg_info("Loading analyzer data...")
    wire_formats = _load_wire_formats(db)
    constraints = _load_symbolic_constraints(db)
    behavioral_specs = _load_behavioral_specs(db)
    alignment_data = _load_tc_alignment(db)
    by_value, by_name, name_to_info = _build_opcode_lookup(db)

    msg_info(f"  Wire formats: {len(wire_formats)}")
    msg_info(f"  Symbolic constraints: {len(constraints)}")
    msg_info(f"  Behavioral specs: {len(behavioral_specs)}")
    msg_info(f"  Opcode lookup: {len(by_name)} names")

    has_wire = bool(wire_formats)
    has_constraints = bool(constraints)
    has_specs = bool(behavioral_specs)
    has_alignment = bool(alignment_data)

    if not has_wire:
        msg_warn("No wire formats available. Run wire_format_recovery first "
                 "for full analysis. Proceeding with limited validation.")

    # -- Phase 3: Binary wire format validation --
    msg_info("Phase 3: Validating packets against binary wire formats...")
    parsed_packets = []
    batch_count = 0

    for i, record in enumerate(cmsg_records):
        if i > 0 and i % _BATCH_SIZE == 0:
            batch_count += 1
            msg_info(f"  Progress: {i}/{len(cmsg_records)} packets "
                     f"(batch {batch_count})")

        opcode_name, handler_info = _resolve_opcode_name(
            record, by_value, by_name)

        parsed = ParsedPacket(record)
        parsed.opcode_name = opcode_name
        if handler_info:
            parsed.handler_name = handler_info.get("tc_name", opcode_name)
        else:
            parsed.handler_name = opcode_name

        # Try to decode against wire format
        wire_fmt = wire_formats.get(opcode_name)
        if not wire_fmt and handler_info:
            wire_fmt = wire_formats.get(handler_info.get("tc_name", ""))

        if wire_fmt and record.data:
            success, field_values, consumed, error = \
                _decode_packet_fields(record.data, wire_fmt)
            parsed.field_values = field_values
            parsed.parse_success = success
            parsed.parse_error = error
            parsed.bytes_consumed = consumed

            # Validate against symbolic constraints
            if has_constraints:
                _validate_parsed_packet(parsed, wire_fmt, constraints)
            elif success:
                parsed.validation_status = _STATUS_VALID
        elif record.fields:
            # Use pre-parsed fields from TXT export
            parsed.field_values = _coerce_txt_fields(record.fields)
            parsed.parse_success = True
            parsed.validation_status = _STATUS_VALID
            if has_constraints:
                _validate_parsed_packet(parsed, {}, constraints)
        elif not wire_fmt:
            parsed.validation_status = _STATUS_UNKNOWN_OPCODE
            parsed.parse_success = False
            parsed.parse_error = "No wire format available"
        else:
            # Empty packet, format expects nothing
            parsed.parse_success = True
            parsed.validation_status = _STATUS_VALID

        parsed_packets.append(parsed)

    valid_count = sum(1 for p in parsed_packets
                      if p.validation_status == _STATUS_VALID)
    unexpected_count = sum(1 for p in parsed_packets
                           if p.validation_status == _STATUS_UNEXPECTED_VALUE)
    mismatch_count = sum(1 for p in parsed_packets
                         if p.validation_status == _STATUS_PARSE_MISMATCH)
    unknown_count = sum(1 for p in parsed_packets
                        if p.validation_status == _STATUS_UNKNOWN_OPCODE)

    msg_info(f"  Validation results:")
    msg_info(f"    VALID:            {valid_count}")
    msg_info(f"    UNEXPECTED_VALUE: {unexpected_count}")
    msg_info(f"    PARSE_MISMATCH:   {mismatch_count}")
    msg_info(f"    UNKNOWN_OPCODE:   {unknown_count}")

    # -- Phase 4: TC behavior comparison --
    msg_info("Phase 4: Comparing binary vs TC behavior...")
    binary_results = collections.defaultdict(list)
    tc_results = collections.defaultdict(list)
    compared = 0

    for parsed in parsed_packets:
        if not parsed.parse_success:
            continue

        # Binary simulation
        spec = behavioral_specs.get(parsed.handler_name,
                                    behavioral_specs.get(parsed.opcode_name))
        bin_result = _simulate_binary_path(parsed, spec)
        binary_results[parsed.opcode_name].append(bin_result)

        # TC simulation
        tc_result = _simulate_tc_behavior(parsed, alignment_data, name_to_info)
        tc_results[parsed.opcode_name].append(tc_result)

        compared += 1

    msg_info(f"  Compared {compared} packets across "
             f"{len(binary_results)} opcodes")

    # -- Phase 5: Divergence detection --
    msg_info("Phase 5: Detecting divergences...")
    divergences = _detect_divergences(
        parsed_packets, binary_results, tc_results)

    # Also check field interpretation differences
    field_divs = _detect_field_interpretation_diffs(
        parsed_packets, wire_formats, alignment_data)
    divergences.extend(field_divs)

    # Refine priorities
    _assign_priorities(divergences)

    msg_info(f"  Found {len(divergences)} divergences")

    # Count by type
    type_counts = collections.Counter(d.div_type for d in divergences)
    for dtype, count in sorted(type_counts.items()):
        msg_info(f"    {dtype}: {count}")

    # Count by priority
    pri_counts = collections.Counter(d.priority for d in divergences)
    for pri in (PRI_CRITICAL, PRI_HIGH, PRI_MEDIUM, PRI_LOW):
        if pri in pri_counts:
            msg_info(f"    {pri}: {pri_counts[pri]}")

    # -- Phase 6: Auto-fix generation --
    msg_info("Phase 6: Generating auto-fixes...")
    tc_source_dir = getattr(session.cfg, "tc_source_dir", None)
    fixes = _generate_fixes(
        divergences, wire_formats, constraints, tc_source_dir)
    msg_info(f"  Generated {len(fixes)} fix suggestions")

    for fix in fixes:
        if fix.priority in (PRI_CRITICAL, PRI_HIGH):
            msg_info(f"    [{fix.priority}] {fix.handler_name}: "
                     f"{fix.fix_type} - {fix.description[:80]}")

    # -- Phase 7: Statistical analysis --
    msg_info("Phase 7: Computing statistics...")
    statistics = _compute_statistics(
        parsed_packets, divergences, by_value, grouped)

    msg_info(f"  Coverage: {statistics['coverage_pct']}% "
             f"({statistics['covered_opcodes']}/{statistics['opcodes_total']} "
             f"CMSG opcodes)")

    if statistics["top_problematic_handlers"]:
        msg_info("  Most problematic handlers:")
        for handler, count in statistics["top_problematic_handlers"][:5]:
            msg_info(f"    {handler}: {count} divergences")

    # -- Phase 8: Report assembly --
    msg_info("Phase 8: Assembling report...")
    elapsed = time.time() - start_time
    report = _assemble_report(
        sniff_files, parsed_packets, divergences, fixes,
        statistics, elapsed)

    db.kv_set(_KV_KEY, report)
    db.commit()

    msg_info("=" * 60)
    msg_info(f"Sniff Conformance Loop complete in {elapsed:.1f}s")
    msg_info(f"  Packets analyzed:  {len(parsed_packets)}")
    msg_info(f"  Divergences found: {len(divergences)}")
    msg_info(f"  Fixes generated:   {len(fixes)}")
    msg_info(f"  Coverage:          {statistics['coverage_pct']}%")
    msg_info("=" * 60)

    return len(divergences)


def _empty_report():
    """Return an empty report structure."""
    return {
        "timestamp": time.time(),
        "elapsed_seconds": 0.0,
        "sniff_files_processed": 0,
        "total_packets": 0,
        "cmsg_packets": 0,
        "opcodes_covered": 0,
        "opcodes_total": 0,
        "coverage_pct": 0.0,
        "total_divergences": 0,
        "divergences_by_type": {},
        "divergences_by_priority": {},
        "fixes": [],
        "per_handler": {},
        "uncovered_opcodes": [],
        "top_problematic_handlers": [],
    }


def _coerce_txt_fields(fields):
    """Convert WowPacketParser text field strings to typed values."""
    result = {}
    for name, value in fields.items():
        # Try integer
        try:
            result[name] = int(value, 0)
            continue
        except (ValueError, TypeError):
            pass
        # Try float
        try:
            result[name] = float(value)
            continue
        except (ValueError, TypeError):
            pass
        # Keep as string
        result[name] = value
    return result


# ======================================================================
# Retrieval / Export Functions
# ======================================================================

def get_conformance_loop_report(session):
    """Retrieve the stored conformance loop report.

    Returns the report dict, or None if not yet run.
    """
    return session.db.kv_get(_KV_KEY)


def export_fixes(session, output_dir):
    """Write fix suggestions as .cpp patch files to output_dir.

    Creates one file per handler with all fixes for that handler.
    Returns number of files written.
    """
    report = get_conformance_loop_report(session)
    if not report:
        msg_warn("No conformance loop report found. Run the loop first.")
        return 0

    fixes = report.get("fixes", [])
    if not fixes:
        msg_info("No fixes to export.")
        return 0

    os.makedirs(output_dir, exist_ok=True)

    # Group fixes by handler
    by_handler = collections.defaultdict(list)
    for fix in fixes:
        by_handler[fix["handler_name"]].append(fix)

    files_written = 0
    for handler, handler_fixes in sorted(by_handler.items()):
        safe_name = re.sub(r'[^\w]', '_', handler)
        filepath = os.path.join(output_dir, f"fix_{safe_name}.cpp")

        lines = []
        lines.append(f"// Auto-generated fix suggestions for {handler}")
        lines.append(f"// Generated by Sniff Conformance Loop")
        lines.append(f"// Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"// Total fixes: {len(handler_fixes)}")
        lines.append("")

        for i, fix in enumerate(handler_fixes, 1):
            lines.append(f"// === Fix {i}/{len(handler_fixes)}: "
                         f"{fix['fix_type']} ({fix['priority']}) ===")
            lines.append(f"// Divergence: {fix['divergence_type']}")
            lines.append(f"// {fix['description']}")
            if fix.get("tc_file"):
                lines.append(f"// Source file: {fix['tc_file']}")
            lines.append(f"// Evidence: {fix.get('evidence_count', 0)} packets")
            lines.append("")
            lines.append(fix.get("fix_code", "// No fix code generated"))
            lines.append("")
            lines.append("")

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            files_written += 1
        except IOError as e:
            msg_error(f"Failed to write {filepath}: {e}")

    msg_info(f"Exported {files_written} fix files to {output_dir}")
    return files_written


def export_divergence_report(session, output_path):
    """Export full divergence report as markdown.

    Returns True on success.
    """
    report = get_conformance_loop_report(session)
    if not report:
        msg_warn("No conformance loop report found. Run the loop first.")
        return False

    lines = []
    lines.append("# Sniff Conformance Loop Report")
    lines.append("")
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Elapsed: {report.get('elapsed_seconds', 0):.1f}s")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Sniff files processed | {report.get('sniff_files_processed', 0)} |")
    lines.append(f"| Total packets | {report.get('total_packets', 0)} |")
    lines.append(f"| CMSG packets | {report.get('cmsg_packets', 0)} |")
    lines.append(f"| Opcodes covered | {report.get('opcodes_covered', 0)} |")
    lines.append(f"| Total CMSG opcodes | {report.get('opcodes_total', 0)} |")
    lines.append(f"| Coverage | {report.get('coverage_pct', 0)}% |")
    lines.append(f"| Total divergences | {report.get('total_divergences', 0)} |")
    lines.append("")

    # Divergences by type
    div_types = report.get("divergences_by_type", {})
    if div_types:
        lines.append("## Divergences by Type")
        lines.append("")
        lines.append("| Type | Count |")
        lines.append("|------|-------|")
        for dtype, count in sorted(div_types.items(),
                                    key=lambda x: -x[1]):
            lines.append(f"| {dtype} | {count} |")
        lines.append("")

    # Divergences by priority
    div_pris = report.get("divergences_by_priority", {})
    if div_pris:
        lines.append("## Divergences by Priority")
        lines.append("")
        lines.append("| Priority | Count |")
        lines.append("|----------|-------|")
        for pri in (PRI_CRITICAL, PRI_HIGH, PRI_MEDIUM, PRI_LOW):
            if pri in div_pris:
                lines.append(f"| {pri} | {div_pris[pri]} |")
        lines.append("")

    # Most problematic handlers
    top = report.get("top_problematic_handlers", [])
    if top:
        lines.append("## Most Problematic Handlers")
        lines.append("")
        lines.append("| Handler | Divergences |")
        lines.append("|---------|-------------|")
        for handler, count in top[:20]:
            lines.append(f"| {handler} | {count} |")
        lines.append("")

    # Fixes
    fixes = report.get("fixes", [])
    if fixes:
        lines.append("## Fix Suggestions")
        lines.append("")
        for i, fix in enumerate(fixes, 1):
            lines.append(f"### {i}. [{fix['priority']}] "
                         f"{fix['handler_name']} - {fix['fix_type']}")
            lines.append("")
            lines.append(f"**Divergence:** {fix['divergence_type']}")
            lines.append(f"**Description:** {fix['description']}")
            if fix.get("tc_file"):
                lines.append(f"**File:** `{fix['tc_file']}`")
            lines.append(f"**Evidence:** {fix.get('evidence_count', 0)} packets")
            lines.append("")
            if fix.get("fix_code"):
                lines.append("```cpp")
                lines.append(fix["fix_code"])
                lines.append("```")
            lines.append("")

    # Uncovered opcodes
    uncovered = report.get("uncovered_opcodes", [])
    if uncovered:
        lines.append("## Uncovered CMSG Opcodes")
        lines.append("")
        lines.append(f"Total uncovered: {len(uncovered)}")
        lines.append("")
        # Show first 50
        for op in uncovered[:50]:
            lines.append(f"- {op}")
        if len(uncovered) > 50:
            lines.append(f"- ... and {len(uncovered) - 50} more")
        lines.append("")

    try:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        msg_info(f"Divergence report exported to {output_path}")
        return True
    except IOError as e:
        msg_error(f"Failed to write report to {output_path}: {e}")
        return False


def get_critical_divergences(session):
    """Return only CRITICAL and HIGH priority divergences.

    Returns list of divergence dicts, or empty list.
    """
    report = get_conformance_loop_report(session)
    if not report:
        return []

    critical = []
    per_handler = report.get("per_handler", {})
    for handler, data in per_handler.items():
        for div in data.get("divergences", []):
            if div.get("priority") in (PRI_CRITICAL, PRI_HIGH):
                critical.append(div)

    # Sort by priority (CRITICAL first)
    priority_order = {PRI_CRITICAL: 0, PRI_HIGH: 1, PRI_MEDIUM: 2, PRI_LOW: 3}
    critical.sort(key=lambda d: priority_order.get(d.get("priority", ""), 99))

    return critical


def get_fix_for_handler(session, handler_name):
    """Return fixes for a specific handler.

    Args:
        session: PluginSession
        handler_name: TC handler name (e.g., 'HandleHousingPlaceDecor')

    Returns list of fix dicts.
    """
    report = get_conformance_loop_report(session)
    if not report:
        return []

    handler_data = report.get("per_handler", {}).get(handler_name)
    if handler_data:
        return handler_data.get("fixes", [])

    # Also check the top-level fixes list
    return [f for f in report.get("fixes", [])
            if f.get("handler_name") == handler_name]


def get_coverage_summary(session):
    """Return a summary of which opcodes have/lack sniff coverage.

    Returns dict with 'covered' and 'uncovered' lists plus stats.
    """
    report = get_conformance_loop_report(session)
    if not report:
        return {
            "covered": [],
            "uncovered": [],
            "coverage_pct": 0.0,
            "opcodes_total": 0,
        }

    # Extract covered opcodes from per_handler
    covered = sorted(report.get("per_handler", {}).keys())

    return {
        "covered": covered,
        "uncovered": report.get("uncovered_opcodes", []),
        "coverage_pct": report.get("coverage_pct", 0.0),
        "opcodes_total": report.get("opcodes_total", 0),
        "opcodes_covered": report.get("opcodes_covered", 0),
    }


def print_conformance_summary(session):
    """Print a human-readable summary of the conformance loop results."""
    report = get_conformance_loop_report(session)
    if not report:
        msg_info("No conformance loop report found. "
                 "Run run_conformance_loop() first.")
        return

    msg_info("=" * 60)
    msg_info("SNIFF CONFORMANCE LOOP SUMMARY")
    msg_info("=" * 60)

    msg_info(f"  Sniff files:       {report.get('sniff_files_processed', 0)}")
    msg_info(f"  Total packets:     {report.get('total_packets', 0)}")
    msg_info(f"  CMSG analyzed:     {report.get('cmsg_packets', 0)}")
    msg_info(f"  Opcodes covered:   {report.get('opcodes_covered', 0)}"
             f"/{report.get('opcodes_total', 0)} "
             f"({report.get('coverage_pct', 0)}%)")
    msg_info(f"  Divergences:       {report.get('total_divergences', 0)}")
    msg_info(f"  Fixes generated:   {len(report.get('fixes', []))}")
    msg_info(f"  Elapsed:           {report.get('elapsed_seconds', 0):.1f}s")

    div_types = report.get("divergences_by_type", {})
    if div_types:
        msg_info("")
        msg_info("  Divergences by type:")
        for dtype, count in sorted(div_types.items(), key=lambda x: -x[1]):
            msg_info(f"    {dtype:30s} {count}")

    div_pris = report.get("divergences_by_priority", {})
    if div_pris:
        msg_info("")
        msg_info("  Divergences by priority:")
        for pri in (PRI_CRITICAL, PRI_HIGH, PRI_MEDIUM, PRI_LOW):
            if pri in div_pris:
                msg_info(f"    {pri:10s} {div_pris[pri]}")

    top = report.get("top_problematic_handlers", [])
    if top:
        msg_info("")
        msg_info("  Most problematic handlers:")
        for handler, count in top[:10]:
            msg_info(f"    {handler:40s} {count} divergences")

    fixes = report.get("fixes", [])
    critical_fixes = [f for f in fixes
                      if f.get("priority") in (PRI_CRITICAL, PRI_HIGH)]
    if critical_fixes:
        msg_info("")
        msg_info(f"  Critical/High priority fixes ({len(critical_fixes)}):")
        for fix in critical_fixes[:10]:
            msg_info(f"    [{fix['priority']}] {fix['handler_name']}: "
                     f"{fix['fix_type']}")
            desc = fix.get("description", "")
            if len(desc) > 80:
                desc = desc[:77] + "..."
            msg_info(f"      {desc}")

    msg_info("=" * 60)
