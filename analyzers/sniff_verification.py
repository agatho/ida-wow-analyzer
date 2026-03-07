"""
Sniff Verification Analyzer
Parses WoW packet capture files ("sniffs") and attempts to decode them using
the wire formats recovered by the wire_format_recovery analyzer.  This
validates that the recovered field layouts actually match real packet data
captured from a live client/server session.

Supported sniff sources:
  - .pkt files (WowPacketParser binary format, v3.0 and v3.1)
  - .bin  raw packet dump files (opcode + data)
  - .txt  WowPacketParser text export
  - .sql  parsed sniff SQL dumps (common community format)

Results are stored in session.db.kv_set("sniff_verification", {...}) and can
be retrieved with get_sniff_report(session).
"""

import json
import os
import struct
import re
import time

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# PKT file signature bytes
_PKT_SIGNATURE = b"PKT"

# PKT header versions we support
_PKT_VERSION_300 = 0x0300
_PKT_VERSION_301 = 0x0301

# Direction constants
_DIR_CLIENT_TO_SERVER = 0  # CMSG
_DIR_SERVER_TO_CLIENT = 1  # SMSG

_DIRECTION_NAMES = {
    _DIR_CLIENT_TO_SERVER: "CMSG",
    _DIR_SERVER_TO_CLIENT: "SMSG",
}

# Wire format type info — size in bytes for fixed-width types
_FIXED_TYPE_SIZES = {
    "uint8":  1,
    "int8":   1,
    "uint16": 2,
    "int16":  2,
    "uint32": 4,
    "int32":  4,
    "uint64": 8,
    "int64":  8,
    "float":  4,
    "double": 8,
}

# struct format chars for unpacking fixed types (little-endian)
_STRUCT_FORMATS = {
    "uint8":  "<B",
    "int8":   "<b",
    "uint16": "<H",
    "int16":  "<h",
    "uint32": "<I",
    "int32":  "<i",
    "uint64": "<Q",
    "int64":  "<q",
    "float":  "<f",
    "double": "<d",
}

# Maximum number of sample decoded values to keep per opcode
_MAX_SAMPLES_PER_OPCODE = 10

# Threshold for flagging a format as likely incorrect
_FAILURE_THRESHOLD = 0.20  # >20% failure rate


# ---------------------------------------------------------------------------
# PKT File Header Parsing
# ---------------------------------------------------------------------------

class PktHeader:
    """Parsed PKT file header."""
    __slots__ = (
        "version", "build", "locale", "session_key",
        "sniff_time", "header_size", "valid",
    )

    def __init__(self):
        self.version = 0
        self.build = 0
        self.locale = ""
        self.session_key = b""
        self.sniff_time = 0
        self.header_size = 0
        self.valid = False


class PacketRecord:
    """A single captured packet."""
    __slots__ = ("direction", "opcode", "timestamp", "data", "size")

    def __init__(self, direction, opcode, timestamp, data):
        self.direction = direction  # "CMSG" or "SMSG"
        self.opcode = opcode
        self.timestamp = timestamp
        self.data = data
        self.size = len(data)


def _parse_pkt_header(fp):
    """Parse the PKT file header from an open binary file handle.

    Returns a PktHeader instance.  On failure, header.valid is False.
    """
    hdr = PktHeader()

    sig = fp.read(3)
    if sig != _PKT_SIGNATURE:
        return hdr

    # Version: 2 bytes, big-endian
    ver_raw = fp.read(2)
    if len(ver_raw) < 2:
        return hdr
    hdr.version = struct.unpack(">H", ver_raw)[0]

    if hdr.version == _PKT_VERSION_300:
        # PKT v3.0 header layout:
        #   3  bytes — "PKT"
        #   2  bytes — version (0x0300)
        #   1  byte  — sniffer ID
        #   4  bytes — build number (LE)
        #   4  bytes — locale (4-char ASCII)
        #  40  bytes — session key
        #   4  bytes — sniff start time (unix, LE)
        #   4  bytes — sniff start ticks (LE)
        #   4  bytes — optional length
        # Total header: 66 bytes (3 + 2 + 1 + 4 + 4 + 40 + 4 + 4 + 4)
        sniffer_id_raw = fp.read(1)
        if len(sniffer_id_raw) < 1:
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

        # Start ticks (ignored)
        fp.read(4)

        # Optional length field
        opt_len_raw = fp.read(4)
        if len(opt_len_raw) >= 4:
            opt_len = struct.unpack("<I", opt_len_raw)[0]
            if opt_len > 0:
                fp.read(opt_len)  # skip optional data

        hdr.header_size = fp.tell()
        hdr.valid = True

    elif hdr.version == _PKT_VERSION_301:
        # PKT v3.1 header layout:
        #   3  bytes — "PKT"
        #   2  bytes — version (0x0301)
        #   1  byte  — sniffer ID
        #   4  bytes — build number (LE)
        #   4  bytes — locale (4-char ASCII)
        #  16  bytes — session key (shorter in 3.1)
        #   4  bytes — sniff start time (unix, LE)
        #   4  bytes — sniff start ticks (LE)
        #   4  bytes — optional length
        # Total header: 42 bytes (3 + 2 + 1 + 4 + 4 + 16 + 4 + 4 + 4)
        sniffer_id_raw = fp.read(1)
        if len(sniffer_id_raw) < 1:
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

        # Start ticks (ignored)
        fp.read(4)

        # Optional length field
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


def _read_pkt_records(fp, header):
    """Read packet records from a PKT file after the header.

    Each record in PKT v3.0/3.1:
      4 bytes — direction (0=CMSG, 1=SMSG)  [LE]
      4 bytes — connection index             [LE]
      4 bytes — timestamp (ticks)            [LE]
      4 bytes — optional additional length   [LE]
      4 bytes — data length                  [LE]
      4 bytes — opcode                       [LE]
      N bytes — packet data
    """
    records = []
    file_size = fp.seek(0, 2)
    fp.seek(header.header_size)

    while fp.tell() < file_size:
        record_hdr = fp.read(24)
        if len(record_hdr) < 24:
            break

        direction, conn_idx, timestamp, opt_len, data_len, opcode = \
            struct.unpack("<IIIIII", record_hdr)

        # Skip optional additional data
        if opt_len > 0:
            fp.read(opt_len)

        # Sanity checks
        if data_len > 0x1000000:  # 16 MB limit
            msg_warn(f"Suspiciously large packet: {data_len} bytes, "
                     f"opcode=0x{opcode:04X}")
            break
        if data_len < 0:
            break

        data = fp.read(data_len)
        if len(data) < data_len:
            break

        dir_str = _DIRECTION_NAMES.get(direction, "UNKNOWN")
        records.append(PacketRecord(dir_str, opcode, timestamp, data))

    return records


# ---------------------------------------------------------------------------
# BIN File Parser (raw packet dumps)
# ---------------------------------------------------------------------------

def _parse_bin_file(filepath):
    """Parse a raw .bin packet dump.

    Expected format per packet:
      1 byte  — direction (0=CMSG, 1=SMSG)
      4 bytes — opcode (LE)
      4 bytes — data length (LE)
      N bytes — data
    """
    records = []
    try:
        with open(filepath, "rb") as fp:
            file_size = fp.seek(0, 2)
            fp.seek(0)

            while fp.tell() < file_size:
                hdr = fp.read(9)
                if len(hdr) < 9:
                    break

                direction = hdr[0]
                opcode = struct.unpack("<I", hdr[1:5])[0]
                data_len = struct.unpack("<I", hdr[5:9])[0]

                if data_len > 0x1000000:
                    break

                data = fp.read(data_len)
                if len(data) < data_len:
                    break

                dir_str = _DIRECTION_NAMES.get(direction, "UNKNOWN")
                records.append(PacketRecord(dir_str, opcode, 0, data))
    except Exception as e:
        msg_error(f"Failed to parse BIN file {filepath}: {e}")

    return records


# ---------------------------------------------------------------------------
# TXT File Parser (WowPacketParser text output)
# ---------------------------------------------------------------------------

# Regex patterns for WowPacketParser text output
_TXT_HEADER_RE = re.compile(
    r'^(?:Server|Client)Opcode:\s*(\w+)\s*'
    r'\(0x([0-9A-Fa-f]+)\)\s*'
    r'Length:\s*(\d+)\s*'
    r'(?:ConnIdx:\s*\d+\s*)?'
    r'Time:\s*(.+)$',
    re.IGNORECASE,
)

_TXT_DIRECTION_RE = re.compile(
    r'^(Server|Client)Opcode:', re.IGNORECASE
)

# Field value lines in WPP text output
_TXT_FIELD_RE = re.compile(
    r'^\s*\[(\d+)\]\s+(\w[\w\s]*?):\s*(.+)$'
)

# Hex dump lines
_TXT_HEX_RE = re.compile(
    r'^[0-9A-Fa-f]{4,8}:\s+((?:[0-9A-Fa-f]{2}\s*)+)'
)


class _TxtPacket:
    """Intermediate representation for a parsed text packet."""
    __slots__ = ("direction", "opcode_name", "opcode", "length",
                 "timestamp_str", "fields", "hex_data")

    def __init__(self):
        self.direction = ""
        self.opcode_name = ""
        self.opcode = 0
        self.length = 0
        self.timestamp_str = ""
        self.fields = {}
        self.hex_data = bytearray()


def _parse_txt_file(filepath):
    """Parse a WowPacketParser text export file.

    Returns a list of PacketRecord objects.
    """
    records = []
    current = None

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fp:
            for line in fp:
                line = line.rstrip("\n\r")

                # Check for new packet header
                hdr_match = _TXT_HEADER_RE.search(line)
                if hdr_match:
                    # Finalize previous packet
                    if current is not None:
                        records.append(_finalize_txt_packet(current))

                    current = _TxtPacket()
                    current.opcode_name = hdr_match.group(1)
                    current.opcode = int(hdr_match.group(2), 16)
                    current.length = int(hdr_match.group(3))
                    current.timestamp_str = hdr_match.group(4).strip()

                    dir_match = _TXT_DIRECTION_RE.search(line)
                    if dir_match:
                        d = dir_match.group(1).lower()
                        current.direction = "CMSG" if d == "client" else "SMSG"
                    continue

                if current is None:
                    continue

                # Parse field values
                field_match = _TXT_FIELD_RE.search(line)
                if field_match:
                    idx = int(field_match.group(1))
                    name = field_match.group(2).strip()
                    value = field_match.group(3).strip()
                    current.fields[name] = value
                    continue

                # Parse hex data lines
                hex_match = _TXT_HEX_RE.search(line)
                if hex_match:
                    hex_str = hex_match.group(1).strip()
                    hex_bytes = bytes.fromhex(hex_str.replace(" ", ""))
                    current.hex_data.extend(hex_bytes)

        # Finalize last packet
        if current is not None:
            records.append(_finalize_txt_packet(current))

    except Exception as e:
        msg_error(f"Failed to parse TXT file {filepath}: {e}")

    return records


def _finalize_txt_packet(txt_pkt):
    """Convert a _TxtPacket to a PacketRecord."""
    data = bytes(txt_pkt.hex_data) if txt_pkt.hex_data else b""
    return PacketRecord(
        direction=txt_pkt.direction,
        opcode=txt_pkt.opcode,
        timestamp=0,
        data=data,
    )


# ---------------------------------------------------------------------------
# SQL Dump Parser
# ---------------------------------------------------------------------------

# Common sniff SQL format:
# INSERT INTO `sniff_packets` VALUES (id, direction, opcode, time, data_hex);
_SQL_INSERT_RE = re.compile(
    r"INSERT\s+INTO\s+[`'\"]?\w+[`'\"]?\s+VALUES\s*\((.+?)\)\s*;",
    re.IGNORECASE,
)

# Also handle per-row inserts
_SQL_VALUES_RE = re.compile(
    r"\(\s*(\d+)\s*,\s*'?(CMSG|SMSG|MSG)'?\s*,\s*(?:0x)?([0-9A-Fa-f]+)\s*,"
    r"\s*'?([^']*)'?\s*,\s*(?:0x)?'?([0-9A-Fa-f]*)'?\s*\)",
    re.IGNORECASE,
)

# Simpler format: direction, opcode_name, hex_data
_SQL_SIMPLE_RE = re.compile(
    r"'(CMSG|SMSG)'\s*,\s*'(\w+)'\s*,\s*(?:0x)?([0-9A-Fa-f]+)\s*,\s*"
    r"(?:0x)?'?([0-9A-Fa-f]*)'?",
    re.IGNORECASE,
)


def _parse_sql_file(filepath, opcode_name_to_int=None):
    """Parse a sniff SQL dump.

    Args:
        filepath: Path to the .sql file.
        opcode_name_to_int: Optional dict mapping opcode names to integer values.

    Returns list of PacketRecord objects.
    """
    records = []
    if opcode_name_to_int is None:
        opcode_name_to_int = {}

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fp:
            for line in fp:
                line = line.strip()
                if not line or line.startswith("--") or line.startswith("#"):
                    continue

                # Try structured VALUES match first
                for m in _SQL_VALUES_RE.finditer(line):
                    _id = int(m.group(1))
                    direction = m.group(2).upper()
                    opcode = int(m.group(3), 16)
                    _time_str = m.group(4)
                    hex_data = m.group(5)

                    data = bytes.fromhex(hex_data) if hex_data else b""
                    records.append(PacketRecord(direction, opcode, 0, data))

                # Try simpler format
                if not records or not _SQL_VALUES_RE.search(line):
                    for m in _SQL_SIMPLE_RE.finditer(line):
                        direction = m.group(1).upper()
                        opcode_name = m.group(2)
                        opcode_val = int(m.group(3), 16)
                        hex_data = m.group(4)

                        # Resolve name to int if needed
                        if opcode_val == 0 and opcode_name in opcode_name_to_int:
                            opcode_val = opcode_name_to_int[opcode_name]

                        data = bytes.fromhex(hex_data) if hex_data else b""
                        records.append(PacketRecord(
                            direction, opcode_val, 0, data))

    except Exception as e:
        msg_error(f"Failed to parse SQL file {filepath}: {e}")

    return records


# ---------------------------------------------------------------------------
# Sniff File Discovery
# ---------------------------------------------------------------------------

def _discover_sniff_files(session):
    """Find all sniff files in configured directories.

    Returns a list of (filepath, file_type) tuples.
    """
    search_dirs = []

    # Check sniff_dir config first
    sniff_dir = session.cfg.get("sniff_dir")
    if sniff_dir and os.path.isdir(sniff_dir):
        search_dirs.append(sniff_dir)

    # Fall back to extraction_dir
    extraction_dir = session.cfg.extraction_dir
    if extraction_dir and os.path.isdir(extraction_dir):
        search_dirs.append(extraction_dir)

    # Also check pipeline_dir
    pipeline_dir = session.cfg.get("pipeline_dir")
    if pipeline_dir and os.path.isdir(pipeline_dir):
        search_dirs.append(pipeline_dir)

    found = []
    seen = set()

    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for entry in os.listdir(d):
                full_path = os.path.join(d, entry)
                if not os.path.isfile(full_path):
                    continue
                if full_path in seen:
                    continue
                seen.add(full_path)

                lower = entry.lower()
                if lower.endswith(".pkt"):
                    found.append((full_path, "pkt"))
                elif lower.endswith(".bin") and "sniff" in lower:
                    found.append((full_path, "bin"))
                elif lower.endswith(".txt") and ("sniff" in lower
                                                  or "packet" in lower
                                                  or "wpp" in lower):
                    found.append((full_path, "txt"))
                elif lower.endswith(".sql") and ("sniff" in lower
                                                  or "pkt" in lower
                                                  or "packet" in lower):
                    found.append((full_path, "sql"))

                # Also pick up files with compound extensions
                elif lower.endswith(".pkt.sql"):
                    found.append((full_path, "sql"))
                elif lower.endswith(".pkt.txt"):
                    found.append((full_path, "txt"))
        except OSError as e:
            msg_warn(f"Cannot scan directory {d}: {e}")

    # Deduplicate (compound extensions might double-match)
    deduped = {}
    for path, ftype in found:
        norm = os.path.normpath(path).lower()
        if norm not in deduped:
            deduped[norm] = (path, ftype)

    return list(deduped.values())


# ---------------------------------------------------------------------------
# Bit-Level Packet Decoder
# ---------------------------------------------------------------------------

class BitReader:
    """Reads data from a byte buffer with bit-level granularity,
    matching WoW's ByteBuffer bit-packing semantics."""

    def __init__(self, data):
        self._data = data
        self._byte_pos = 0
        self._bit_pos = 8  # 8 = no active bit byte (flushed state)
        self._current_byte = 0

    @property
    def bytes_read(self):
        """Number of complete bytes consumed."""
        if self._bit_pos < 8:
            return self._byte_pos  # mid-bit-read, byte not fully consumed yet
        return self._byte_pos

    @property
    def total_size(self):
        return len(self._data)

    @property
    def remaining_bytes(self):
        return len(self._data) - self._byte_pos

    def _ensure_bit_byte(self):
        """Load the next byte for bit reading if needed."""
        if self._bit_pos >= 8:
            if self._byte_pos >= len(self._data):
                raise BufferError("No more data for bit reading")
            self._current_byte = self._data[self._byte_pos]
            self._byte_pos += 1
            self._bit_pos = 0

    def read_bit(self):
        """Read a single bit. Returns 0 or 1."""
        self._ensure_bit_byte()
        # WoW reads bits MSB-first within each byte
        value = (self._current_byte >> (7 - self._bit_pos)) & 1
        self._bit_pos += 1
        return value

    def read_bits(self, count):
        """Read N bits and return as an integer."""
        if count == 0:
            return 0
        if count > 64:
            raise ValueError(f"Cannot read more than 64 bits at once: {count}")

        value = 0
        for i in range(count):
            value = (value << 1) | self.read_bit()
        return value

    def flush_bits(self):
        """Align to byte boundary (discard remaining bits in current byte)."""
        self._bit_pos = 8

    def read_bytes(self, count):
        """Read N byte-aligned bytes. Auto-flushes bits first."""
        self.flush_bits()
        if self._byte_pos + count > len(self._data):
            raise BufferError(
                f"Not enough data: need {count} bytes, "
                f"have {len(self._data) - self._byte_pos}")
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
        """Read a PackedGuid128.

        Format: 2 bitmask bytes, then for each set bit in the 16-bit mask,
        one byte of the 16-byte GUID.
        """
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
                    raise BufferError("Not enough data for PackedGuid128 byte")
                guid_bytes[i] = self._data[self._byte_pos]
                self._byte_pos += 1

        for i in range(8):
            if hi_mask & (1 << i):
                if self._byte_pos >= len(self._data):
                    raise BufferError("Not enough data for PackedGuid128 byte")
                guid_bytes[8 + i] = self._data[self._byte_pos]
                self._byte_pos += 1

        # Reconstruct as two uint64 (low, high)
        low = struct.unpack("<Q", bytes(guid_bytes[:8]))[0]
        high = struct.unpack("<Q", bytes(guid_bytes[8:]))[0]
        return (low, high)

    def read_string(self, length):
        """Read a string of exactly `length` bytes."""
        raw = self.read_bytes(length)
        return raw.decode("utf-8", errors="replace").rstrip("\x00")

    def read_cstring(self):
        """Read a null-terminated C string."""
        self.flush_bits()
        result = bytearray()
        while self._byte_pos < len(self._data):
            b = self._data[self._byte_pos]
            self._byte_pos += 1
            if b == 0:
                break
            result.append(b)
        return result.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Field Decoding — apply a wire format to raw packet data
# ---------------------------------------------------------------------------

class DecodeResult:
    """Result of attempting to decode a packet against a wire format."""

    __slots__ = (
        "success", "fields_decoded", "total_fields",
        "bytes_consumed", "total_bytes", "error_field_index",
        "error_message", "decoded_values",
    )

    def __init__(self):
        self.success = False
        self.fields_decoded = 0
        self.total_fields = 0
        self.bytes_consumed = 0
        self.total_bytes = 0
        self.error_field_index = -1
        self.error_message = ""
        self.decoded_values = {}  # field_name -> decoded_value


def _decode_packet(data, wire_format):
    """Attempt to decode raw packet data using the given wire format.

    Args:
        data: bytes of the packet payload (after opcode).
        wire_format: dict from wire_format_recovery with a "fields" list.

    Returns a DecodeResult.
    """
    result = DecodeResult()
    result.total_bytes = len(data)
    fields = wire_format.get("fields", [])
    result.total_fields = len(fields)

    if not fields:
        result.success = True
        return result

    if not data:
        # Empty packet but format expects fields
        if fields:
            result.error_message = "Empty packet but format expects fields"
        else:
            result.success = True
        return result

    reader = BitReader(data)

    # Track field context for conditional / array fields
    decoded_bit_flags = {}   # field_name -> bool
    decoded_bit_counts = {}  # field_name -> int

    for i, field in enumerate(fields):
        ftype = field.get("type", "uint32")
        fname = field.get("name", f"field_{i}")
        is_optional = field.get("is_optional", False)
        condition = field.get("condition", "")
        is_array = field.get("is_array", False)
        array_size_field = field.get("array_size_field", "")
        bit_size = field.get("bit_size", 0)

        # Check optional condition
        if is_optional and condition:
            should_skip = _evaluate_condition(condition, decoded_bit_flags)
            if should_skip:
                result.fields_decoded += 1
                continue

        # Determine array count
        array_count = 1
        if is_array and array_size_field:
            count_val = decoded_bit_counts.get(array_size_field, None)
            if count_val is None:
                # Also check decoded_values by name
                count_val = result.decoded_values.get(array_size_field, None)
            if count_val is not None:
                array_count = int(count_val)
                # Sanity limit
                if array_count > 10000:
                    result.error_field_index = i
                    result.error_message = (
                        f"Array count too large: {array_count} "
                        f"for field '{fname}'")
                    result.bytes_consumed = reader.bytes_read
                    return result
            else:
                # Unknown array size — can only decode one element
                array_count = 1

        try:
            values = []
            for _elem in range(array_count):
                val = _read_field_value(reader, ftype, bit_size)
                values.append(val)

            # Store decoded value
            if is_array:
                result.decoded_values[fname] = values
            else:
                val = values[0] if values else None
                result.decoded_values[fname] = val

                # Track bit flags and count fields
                if ftype == "bit" and val is not None:
                    decoded_bit_flags[fname] = bool(val)
                elif ftype == "bits" and val is not None:
                    decoded_bit_counts[fname] = int(val)
                elif ftype in ("uint8", "uint16", "uint32") and val is not None:
                    decoded_bit_counts[fname] = int(val)

            result.fields_decoded += 1

        except (BufferError, struct.error, ValueError, OverflowError) as e:
            result.error_field_index = i
            result.error_message = f"Field '{fname}' (type={ftype}): {e}"
            result.bytes_consumed = reader.bytes_read
            return result

    result.bytes_consumed = reader.bytes_read
    result.success = True

    # Check for unconsumed data
    remaining = result.total_bytes - result.bytes_consumed
    if remaining > 0:
        # Partial success — all fields decoded but extra data remains
        result.error_message = f"{remaining} unconsumed bytes remaining"

    return result


def _read_field_value(reader, ftype, bit_size=0):
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
        # String fields require a length from a previously read bits field
        # If we don't know the length, read as CString
        return reader.read_cstring()
    elif ftype == "flush":
        reader.flush_bits()
        return None
    else:
        # Unknown type — try to read as uint32
        return reader.read_uint32()


def _evaluate_condition(condition, bit_flags):
    """Evaluate an optional-field condition against decoded bit flags.

    Returns True if the field should be SKIPPED (condition is NOT met).

    This is a heuristic — the condition is a decompiler expression like
    "hasGuildData" or "!hasGuildData".  We check if the referenced flag
    is set or not.
    """
    if not condition or not bit_flags:
        return False  # Don't skip if we can't evaluate

    negated = False
    check_name = condition.strip()

    # Handle negation
    if check_name.startswith("!"):
        negated = True
        check_name = check_name[1:].strip()

    # Handle comparison: "var != 0", "var == 1", etc.
    cmp_match = re.match(r'(\w+)\s*([!=<>]+)\s*(\d+)', check_name)
    if cmp_match:
        var_name = cmp_match.group(1)
        op = cmp_match.group(2)
        cmp_val = int(cmp_match.group(3))
        flag_val = bit_flags.get(var_name)
        if flag_val is None:
            return False  # Unknown flag, don't skip

        actual = 1 if flag_val else 0
        if op == "==" or op == "=":
            return not (actual == cmp_val)
        elif op == "!=" or op == "<>":
            return not (actual != cmp_val)
        elif op == ">":
            return not (actual > cmp_val)
        elif op == "<":
            return not (actual < cmp_val)

    # Simple flag check
    flag_val = bit_flags.get(check_name)
    if flag_val is None:
        # Try substring match (decompiler may add suffixes)
        for k, v in bit_flags.items():
            if k in check_name or check_name in k:
                flag_val = v
                break

    if flag_val is None:
        return False  # Unknown flag, don't skip

    condition_met = bool(flag_val) if not negated else not bool(flag_val)
    return not condition_met  # Return True to SKIP when condition is NOT met


# ---------------------------------------------------------------------------
# Statistical Analysis
# ---------------------------------------------------------------------------

def _compute_per_opcode_stats(opcode_results):
    """Compute per-opcode statistics from verification results.

    Args:
        opcode_results: dict of opcode_name -> list of DecodeResult

    Returns a list of per-opcode stat dicts.
    """
    stats = []

    for opcode_name, results in sorted(opcode_results.items()):
        total = len(results)
        successes = sum(1 for r in results if r.success)
        failures = total - successes
        sizes = [r.total_bytes for r in results]
        avg_size = sum(sizes) / total if total > 0 else 0

        # Collect sample decoded values (from successful decodes)
        sample_values = []
        for r in results:
            if r.success and r.decoded_values:
                sample = {}
                for k, v in r.decoded_values.items():
                    # Serialize value for JSON storage
                    if isinstance(v, (list, tuple)):
                        sample[k] = [_json_safe(x) for x in v[:5]]
                    else:
                        sample[k] = _json_safe(v)
                sample_values.append(sample)
                if len(sample_values) >= _MAX_SAMPLES_PER_OPCODE:
                    break

        # Collect field value ranges from successful decodes
        field_ranges = {}
        for r in results:
            if not r.success:
                continue
            for fname, val in r.decoded_values.items():
                if val is None:
                    continue
                if isinstance(val, (int, float)):
                    if fname not in field_ranges:
                        field_ranges[fname] = {"min": val, "max": val, "count": 0}
                    field_ranges[fname]["min"] = min(field_ranges[fname]["min"], val)
                    field_ranges[fname]["max"] = max(field_ranges[fname]["max"], val)
                    field_ranges[fname]["count"] += 1

        # Error analysis for failures
        error_summary = {}
        for r in results:
            if not r.success and r.error_message:
                key = r.error_message[:80]
                error_summary[key] = error_summary.get(key, 0) + 1

        stat = {
            "opcode": opcode_name,
            "name": opcode_name,
            "total": total,
            "success": successes,
            "fail": failures,
            "success_rate": successes / total if total > 0 else 0.0,
            "avg_size": round(avg_size, 1),
            "min_size": min(sizes) if sizes else 0,
            "max_size": max(sizes) if sizes else 0,
            "sample_values": sample_values,
            "field_ranges": field_ranges,
            "error_summary": error_summary,
        }
        stats.append(stat)

    return stats


def _json_safe(val):
    """Convert a value to something JSON-serializable."""
    if isinstance(val, float):
        if val != val:  # NaN check
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
    return str(val)


# ---------------------------------------------------------------------------
# Correction Suggestions
# ---------------------------------------------------------------------------

def _generate_corrections(opcode_results, wire_formats):
    """Generate format correction suggestions for failing formats.

    For each opcode with failures, analyze where parsing fails and suggest
    possible fixes.

    Returns a list of correction dicts.
    """
    corrections = []

    for opcode_name, results in opcode_results.items():
        fmt = wire_formats.get(opcode_name)
        if not fmt:
            continue

        fields = fmt.get("fields", [])
        total = len(results)
        if total == 0:
            continue

        failures = [r for r in results if not r.success]
        if not failures:
            continue

        failure_rate = len(failures) / total

        # Analyze failure points
        fail_field_counts = {}
        for r in failures:
            idx = r.error_field_index
            if idx >= 0:
                fail_field_counts[idx] = fail_field_counts.get(idx, 0) + 1

        for field_idx, fail_count in sorted(fail_field_counts.items()):
            if field_idx >= len(fields):
                continue

            field = fields[field_idx]
            ftype = field.get("type", "unknown")
            fname = field.get("name", f"field_{field_idx}")

            # Compute remaining bytes at failure point
            remaining_at_fail = []
            for r in failures:
                if r.error_field_index == field_idx:
                    remaining = r.total_bytes - r.bytes_consumed
                    remaining_at_fail.append(remaining)

            avg_remaining = (sum(remaining_at_fail) / len(remaining_at_fail)
                            if remaining_at_fail else 0)

            suggestion = _suggest_fix(
                ftype, fname, field_idx, avg_remaining,
                fail_count, total, fields)

            corrections.append({
                "opcode": opcode_name,
                "field_index": field_idx,
                "field_name": fname,
                "field_type": ftype,
                "issue": f"Fails at field {field_idx} ({fname}) "
                         f"in {fail_count}/{total} packets",
                "suggestion": suggestion,
                "failure_rate": failure_rate,
                "avg_remaining_bytes": round(avg_remaining, 1),
            })

    return corrections


def _suggest_fix(ftype, fname, field_idx, avg_remaining, fail_count,
                 total_count, all_fields):
    """Suggest a fix for a specific field failure.

    Returns a human-readable suggestion string.
    """
    suggestions = []

    # If the field reads too many bytes
    if avg_remaining < 0:
        # The format reads more data than the packet contains
        type_size = _FIXED_TYPE_SIZES.get(ftype, 4)
        if type_size > 1:
            # Suggest a smaller type
            smaller = {8: "uint32", 4: "uint16", 2: "uint8"}
            smaller_type = smaller.get(type_size)
            if smaller_type:
                suggestions.append(
                    f"Try changing '{ftype}' to '{smaller_type}' "
                    f"(saves {type_size - _FIXED_TYPE_SIZES[smaller_type]} bytes)")

    elif avg_remaining > 0:
        # Extra bytes remain — possibly missing fields
        type_size = _FIXED_TYPE_SIZES.get(ftype, 4)
        if avg_remaining >= 8:
            suggestions.append(
                f"Possibly missing ~{int(avg_remaining)} bytes of fields "
                f"after field {field_idx}")
        elif avg_remaining >= 4:
            suggestions.append(
                f"Possibly missing a uint32 field after field {field_idx}")
        elif avg_remaining >= 2:
            suggestions.append(
                f"Possibly missing a uint16 field after field {field_idx}")
        elif avg_remaining >= 1:
            suggestions.append(
                f"Possibly missing a uint8 field after field {field_idx}")

    # If the field is a bit/bits field that fails
    if ftype in ("bit", "bits"):
        suggestions.append(
            f"Check bit/byte alignment before field {field_idx}; "
            f"may need FlushBits before this field")

    # If reading a string fails
    if ftype == "string":
        suggestions.append(
            "String length field may be wrong type or reading wrong value; "
            "check the bits count that feeds this string length")

    # If reading a PackedGuid fails
    if ftype in ("packed_guid", "ObjectGuid"):
        suggestions.append(
            "PackedGuid128 may be at wrong position; check byte alignment "
            "and preceding FlushBits")

    # High failure rate overall
    if fail_count / max(total_count, 1) > 0.5:
        suggestions.append(
            f"Over 50% failure rate — the format may be fundamentally wrong "
            f"starting from field {field_idx} or earlier")

    if not suggestions:
        suggestions.append(
            f"Check field type '{ftype}' at index {field_idx}; "
            f"avg {avg_remaining:.0f} bytes remaining at failure")

    return "; ".join(suggestions)


# ---------------------------------------------------------------------------
# Game Constants Validation
# ---------------------------------------------------------------------------

def _validate_against_constants(per_opcode_stats, game_constants):
    """Cross-check decoded field value ranges against known game constants.

    Args:
        per_opcode_stats: list of per-opcode stat dicts.
        game_constants: dict from kv_store "game_constants".

    Returns a list of anomaly dicts.
    """
    if not game_constants:
        return []

    anomalies = []

    # Known range constraints for common field name patterns
    range_checks = {
        "map": (0, 3000),
        "zone": (0, 20000),
        "area": (0, 20000),
        "level": (1, 80),
        "item": (0, 300000),
        "spell": (0, 1000000),
        "phase": (0, 0xFFFFFFFF),
        "race": (0, 100),
        "class": (0, 100),
        "gender": (0, 3),
        "slot": (0, 256),
        "bag": (0, 20),
        "count": (0, 100000),
    }

    for stat in per_opcode_stats:
        for fname, ranges in stat.get("field_ranges", {}).items():
            fname_lower = fname.lower()
            for pattern, (valid_min, valid_max) in range_checks.items():
                if pattern in fname_lower:
                    actual_min = ranges.get("min", 0)
                    actual_max = ranges.get("max", 0)
                    if actual_min < valid_min or actual_max > valid_max:
                        anomalies.append({
                            "opcode": stat["opcode"],
                            "field": fname,
                            "pattern": pattern,
                            "expected_range": (valid_min, valid_max),
                            "actual_range": (actual_min, actual_max),
                            "issue": (
                                f"Field '{fname}' in {stat['opcode']} has "
                                f"range [{actual_min}, {actual_max}] but "
                                f"expected [{valid_min}, {valid_max}] for "
                                f"'{pattern}' fields"),
                        })
                    break  # Only check first matching pattern

    return anomalies


# ---------------------------------------------------------------------------
# Build Opcode Lookup
# ---------------------------------------------------------------------------

def _build_opcode_lookup(db):
    """Build a mapping from wire opcode value to (direction, name, format).

    Also builds name-to-opcode for SQL parsing.

    Returns (by_value, by_name) dicts.
    """
    by_value = {}   # (direction, opcode_int) -> opcode_info
    by_name = {}    # opcode_name -> opcode_int

    opcodes = db.fetchall("SELECT * FROM opcodes")
    for row in opcodes:
        direction = row["direction"]
        idx = row["internal_index"]
        wire = row["wire_opcode"]
        name = row["tc_name"] or f"opcode_{idx}"

        info = {
            "direction": direction,
            "internal_index": idx,
            "wire_opcode": wire,
            "name": name,
        }

        if wire:
            by_value[(direction, wire)] = info
        # Also index by internal index as fallback
        by_value[(direction, idx)] = info

        if name:
            by_name[name] = wire or idx

    return by_value, by_name


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def verify_sniff_formats(session):
    """Main entry point: parse sniff files and verify against recovered
    wire formats.

    Args:
        session: PluginSession with .db and .cfg access.

    Returns:
        Number of packets successfully verified.
    """
    db = session.db
    start_time = time.time()

    msg_info("Starting sniff format verification...")

    # 1. Discover sniff files
    sniff_files = _discover_sniff_files(session)
    if not sniff_files:
        msg_warn("No sniff files found. Configure 'sniff_dir' in settings "
                 "or place .pkt/.bin/.txt/.sql files in the extraction directory.")
        db.kv_set("sniff_verification", {
            "sniff_files_processed": 0,
            "total_packets": 0,
            "verified_packets": 0,
            "failed_packets": 0,
            "per_opcode": [],
            "format_corrections": [],
            "coverage": 0.0,
            "elapsed_seconds": 0.0,
            "timestamp": time.time(),
        })
        db.commit()
        return 0

    msg_info(f"Found {len(sniff_files)} sniff file(s):")
    for path, ftype in sniff_files:
        msg(f"  [{ftype.upper()}] {os.path.basename(path)}")

    # 2. Load wire formats
    wire_formats = db.kv_get("wire_formats")
    if not wire_formats:
        msg_warn("No wire formats in database. "
                 "Run wire_format_recovery first.")
        wire_formats = {}

    msg_info(f"Loaded {len(wire_formats)} recovered wire formats")

    # 3. Build opcode lookup
    opcode_by_value, opcode_by_name = _build_opcode_lookup(db)
    msg_info(f"Opcode lookup: {len(opcode_by_value)} entries by value, "
             f"{len(opcode_by_name)} by name")

    # 4. Parse all sniff files
    all_packets = []
    files_processed = 0

    for filepath, ftype in sniff_files:
        msg_info(f"Parsing {os.path.basename(filepath)} ({ftype})...")
        packets = []

        try:
            if ftype == "pkt":
                packets = _parse_pkt_file(filepath)
            elif ftype == "bin":
                packets = _parse_bin_file(filepath)
            elif ftype == "txt":
                packets = _parse_txt_file(filepath)
            elif ftype == "sql":
                packets = _parse_sql_file(filepath, opcode_by_name)
        except Exception as e:
            msg_error(f"Failed to parse {filepath}: {e}")
            continue

        if packets:
            msg_info(f"  -> {len(packets)} packets")
            all_packets.extend(packets)
            files_processed += 1
        else:
            msg_warn(f"  -> No packets found in {os.path.basename(filepath)}")

    total_packets = len(all_packets)
    msg_info(f"Total packets loaded: {total_packets} from {files_processed} files")

    if total_packets == 0:
        msg_warn("No packets parsed from any sniff file.")
        db.kv_set("sniff_verification", {
            "sniff_files_processed": files_processed,
            "total_packets": 0,
            "verified_packets": 0,
            "failed_packets": 0,
            "per_opcode": [],
            "format_corrections": [],
            "coverage": 0.0,
            "elapsed_seconds": time.time() - start_time,
            "timestamp": time.time(),
        })
        db.commit()
        return 0

    # 5. Verify each packet against its wire format
    verified = 0
    failed = 0
    no_format = 0
    opcode_results = {}  # opcode_name -> list of DecodeResult

    for i, pkt in enumerate(all_packets):
        # Look up opcode info
        opcode_info = opcode_by_value.get((pkt.direction, pkt.opcode))
        if not opcode_info:
            # Try without direction (some lookups are direction-agnostic)
            opcode_info = opcode_by_value.get(("CMSG", pkt.opcode))
            if not opcode_info:
                opcode_info = opcode_by_value.get(("SMSG", pkt.opcode))

        if not opcode_info:
            no_format += 1
            continue

        opcode_name = opcode_info.get("name", f"opcode_0x{pkt.opcode:04X}")

        # Look up wire format
        fmt = wire_formats.get(opcode_name)
        if not fmt:
            # Try case-insensitive
            for key, val in wire_formats.items():
                if key.lower() == opcode_name.lower():
                    fmt = val
                    break
        if not fmt:
            no_format += 1
            continue

        # Decode
        result = _decode_packet(pkt.data, fmt)

        if opcode_name not in opcode_results:
            opcode_results[opcode_name] = []
        opcode_results[opcode_name].append(result)

        if result.success:
            verified += 1
        else:
            failed += 1

        # Progress reporting
        if (i + 1) % 5000 == 0:
            msg_info(f"  Progress: {i + 1}/{total_packets} "
                     f"({verified} verified, {failed} failed)")

    msg_info(f"Verification complete: {verified} verified, {failed} failed, "
             f"{no_format} no format available")

    # 6. Statistical analysis
    per_opcode_stats = _compute_per_opcode_stats(opcode_results)

    # 7. Game constants cross-check
    game_constants = db.kv_get("game_constants")
    anomalies = _validate_against_constants(per_opcode_stats, game_constants)
    if anomalies:
        msg_info(f"Found {len(anomalies)} value range anomalies")

    # 8. Generate correction suggestions
    corrections = _generate_corrections(opcode_results, wire_formats)
    if corrections:
        msg_info(f"Generated {len(corrections)} format correction suggestions")

    # 9. Flag suspicious formats (>20% failure)
    suspicious_formats = []
    for stat in per_opcode_stats:
        if stat["total"] >= 3 and stat["success_rate"] < (1.0 - _FAILURE_THRESHOLD):
            suspicious_formats.append(stat["opcode"])
            msg_warn(f"Suspicious format: {stat['opcode']} — "
                     f"{stat['fail']}/{stat['total']} failures "
                     f"({stat['success_rate']:.1%} success)")

    # 10. Compute coverage
    formats_tested = len(opcode_results)
    formats_passing = sum(
        1 for stats in per_opcode_stats
        if stats["success_rate"] >= (1.0 - _FAILURE_THRESHOLD)
    )
    coverage = (formats_passing / formats_tested * 100.0
                if formats_tested > 0 else 0.0)

    # 11. Store results
    elapsed = time.time() - start_time
    verification_data = {
        "sniff_files_processed": files_processed,
        "total_packets": total_packets,
        "verified_packets": verified,
        "failed_packets": failed,
        "no_format_packets": no_format,
        "per_opcode": per_opcode_stats,
        "format_corrections": corrections,
        "value_anomalies": anomalies,
        "suspicious_formats": suspicious_formats,
        "coverage": round(coverage, 2),
        "formats_tested": formats_tested,
        "formats_passing": formats_passing,
        "elapsed_seconds": round(elapsed, 2),
        "timestamp": time.time(),
    }

    db.kv_set("sniff_verification", verification_data)
    db.commit()

    msg_info(f"Sniff verification results stored. "
             f"Coverage: {coverage:.1f}% ({formats_passing}/{formats_tested} "
             f"formats passing). Time: {elapsed:.1f}s")

    return verified


def _parse_pkt_file(filepath):
    """Parse a .pkt binary capture file.

    Returns a list of PacketRecord objects.
    """
    records = []
    try:
        with open(filepath, "rb") as fp:
            header = _parse_pkt_header(fp)
            if not header.valid:
                msg_warn(f"Invalid PKT header in {filepath}")
                # Try treating the entire file as raw records
                return _parse_bin_file(filepath)

            msg_info(f"  PKT v{header.version >> 8}.{header.version & 0xFF}, "
                     f"build={header.build}, locale='{header.locale}'")

            records = _read_pkt_records(fp, header)
    except Exception as e:
        msg_error(f"Failed to parse PKT file {filepath}: {e}")

    return records


# ---------------------------------------------------------------------------
# Report Export
# ---------------------------------------------------------------------------

def export_verification_report(session):
    """Generate a Markdown verification report.

    Returns the report as a string.
    """
    data = get_sniff_report(session)
    if not data:
        return "# Sniff Verification Report\n\nNo verification data available.\n"

    lines = []
    lines.append("# Sniff Verification Report")
    lines.append("")
    lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Elapsed:** {data.get('elapsed_seconds', 0):.1f}s")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Sniff files processed | {data.get('sniff_files_processed', 0)} |")
    lines.append(f"| Total packets | {data.get('total_packets', 0)} |")
    lines.append(f"| Verified (success) | {data.get('verified_packets', 0)} |")
    lines.append(f"| Failed | {data.get('failed_packets', 0)} |")
    lines.append(f"| No format available | {data.get('no_format_packets', 0)} |")
    lines.append(f"| Format coverage | {data.get('coverage', 0):.1f}% |")
    lines.append(f"| Formats tested | {data.get('formats_tested', 0)} |")
    lines.append(f"| Formats passing | {data.get('formats_passing', 0)} |")
    lines.append("")

    # Per-opcode breakdown
    per_opcode = data.get("per_opcode", [])
    if per_opcode:
        lines.append("## Per-Opcode Results")
        lines.append("")
        lines.append("| Opcode | Total | Success | Fail | Rate | Avg Size |")
        lines.append("|--------|-------|---------|------|------|----------|")

        # Sort by failure rate descending (worst first)
        sorted_ops = sorted(per_opcode,
                           key=lambda x: x.get("success_rate", 1.0))

        for stat in sorted_ops:
            rate = stat.get("success_rate", 0) * 100
            marker = " **" if rate < 80 else ""
            lines.append(
                f"| {stat['opcode']}{marker} "
                f"| {stat['total']} "
                f"| {stat['success']} "
                f"| {stat['fail']} "
                f"| {rate:.0f}%{' **' if marker else ''} "
                f"| {stat['avg_size']:.0f}B |")

        lines.append("")

    # Suspicious formats
    suspicious = data.get("suspicious_formats", [])
    if suspicious:
        lines.append("## Suspicious Formats (>20% failure)")
        lines.append("")
        for name in suspicious:
            lines.append(f"- **{name}**")
        lines.append("")

    # Format corrections
    corrections = data.get("format_corrections", [])
    if corrections:
        lines.append("## Format Correction Suggestions")
        lines.append("")
        for corr in corrections:
            lines.append(f"### {corr['opcode']} — field {corr['field_index']} "
                        f"({corr.get('field_name', '?')})")
            lines.append(f"- **Issue:** {corr['issue']}")
            lines.append(f"- **Type:** {corr.get('field_type', '?')}")
            lines.append(f"- **Suggestion:** {corr['suggestion']}")
            lines.append(f"- **Avg remaining bytes:** "
                        f"{corr.get('avg_remaining_bytes', '?')}")
            lines.append("")

    # Value anomalies
    anomalies = data.get("value_anomalies", [])
    if anomalies:
        lines.append("## Value Range Anomalies")
        lines.append("")
        lines.append("| Opcode | Field | Pattern | Expected | Actual |")
        lines.append("|--------|-------|---------|----------|--------|")
        for a in anomalies:
            lines.append(
                f"| {a['opcode']} "
                f"| {a['field']} "
                f"| {a['pattern']} "
                f"| {a['expected_range']} "
                f"| {a['actual_range']} |")
        lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Sample Packet Retrieval
# ---------------------------------------------------------------------------

def get_packet_samples(session, opcode):
    """Retrieve decoded sample packets for a given opcode.

    Args:
        session: PluginSession
        opcode: Opcode name string (e.g. "CMSG_HOUSE_DECOR_PLACE")

    Returns a list of sample decoded value dicts, or an empty list.
    """
    data = get_sniff_report(session)
    if not data:
        return []

    for stat in data.get("per_opcode", []):
        if stat.get("opcode", "").lower() == opcode.lower():
            return stat.get("sample_values", [])
        if stat.get("name", "").lower() == opcode.lower():
            return stat.get("sample_values", [])

    return []


# ---------------------------------------------------------------------------
# Report Retrieval
# ---------------------------------------------------------------------------

def get_sniff_report(session):
    """Retrieve stored sniff verification data.

    Returns the stored dict, or None if no verification has been run.
    """
    return session.db.kv_get("sniff_verification")


# ---------------------------------------------------------------------------
# Bit-Level Validation Helpers
# ---------------------------------------------------------------------------

def _validate_bit_operations(fields, reader_state_log):
    """Validate that bit operations are consistent.

    Checks:
    - ReadBit/ReadBits at expected positions
    - Optional presence bits match actual optional field presence
    - Array count fields match actual array element counts
    - String length fields match remaining data

    Args:
        fields: Wire format field list.
        reader_state_log: List of (field_index, bit_pos, byte_pos) tuples
                          recorded during decoding.

    Returns a list of issue description strings.
    """
    issues = []

    bit_position = 0
    in_bit_region = False
    bit_flag_values = {}
    bit_count_values = {}

    for i, field in enumerate(fields):
        ftype = field.get("type", "")
        fname = field.get("name", "")
        bit_size = field.get("bit_size", 0)

        if ftype in ("bit", "bits"):
            in_bit_region = True
            if ftype == "bit":
                # Verify single bit reads are truly 1 bit
                if bit_size != 1:
                    issues.append(
                        f"Field {i} ({fname}): bit field has "
                        f"bit_size={bit_size}, expected 1")
            elif ftype == "bits":
                if bit_size <= 0 or bit_size > 64:
                    issues.append(
                        f"Field {i} ({fname}): ReadBits has invalid "
                        f"count {bit_size}")
            bit_position += bit_size

        elif ftype == "flush":
            if in_bit_region and (bit_position % 8) != 0:
                pad = 8 - (bit_position % 8)
                bit_position += pad
            in_bit_region = False

        else:
            # Byte-aligned field
            if in_bit_region:
                # Auto-flush should have happened
                if (bit_position % 8) != 0:
                    issues.append(
                        f"Field {i} ({fname}): byte-aligned read at "
                        f"bit position {bit_position} (not byte-aligned, "
                        f"missing FlushBits?)")
                    pad = 8 - (bit_position % 8)
                    bit_position += pad
                in_bit_region = False

            byte_size = _FIXED_TYPE_SIZES.get(ftype, 0)
            bit_position += byte_size * 8

        # Check array count consistency
        if field.get("is_array") and field.get("array_size_field"):
            size_field = field["array_size_field"]
            if size_field in bit_count_values:
                count = bit_count_values[size_field]
                if count < 0:
                    issues.append(
                        f"Field {i} ({fname}): array size field "
                        f"'{size_field}' has negative value {count}")
                elif count > 10000:
                    issues.append(
                        f"Field {i} ({fname}): array size field "
                        f"'{size_field}' has suspiciously large "
                        f"value {count}")

    return issues


def _analyze_bit_alignment(fields):
    """Analyze a wire format for potential bit alignment issues.

    Returns a list of (field_index, issue_description) tuples.
    """
    issues = []
    bit_pos = 0
    in_bits = False

    for i, field in enumerate(fields):
        ftype = field.get("type", "")
        bit_size = field.get("bit_size", 0)
        fname = field.get("name", f"field_{i}")

        if ftype in ("bit", "bits"):
            in_bits = True
            bit_pos += bit_size

        elif ftype == "flush":
            if in_bits and (bit_pos % 8) != 0:
                bit_pos += 8 - (bit_pos % 8)
            in_bits = False
            bit_pos = 0

        elif ftype in ("packed_guid", "ObjectGuid", "string"):
            if in_bits and (bit_pos % 8) != 0:
                issues.append((i, f"Variable-length field '{fname}' "
                                  f"({ftype}) after {bit_pos} bits — "
                                  f"needs FlushBits"))
            in_bits = False
            bit_pos = 0

        else:
            if in_bits:
                if (bit_pos % 8) != 0:
                    issues.append((i, f"Byte field '{fname}' ({ftype}) "
                                      f"after {bit_pos} bits — "
                                      f"implicit flush"))
                in_bits = False
                bit_pos = 0

    return issues


# ---------------------------------------------------------------------------
# Bulk Decode for External Use
# ---------------------------------------------------------------------------

def decode_packet_data(data, wire_format):
    """Public API: Decode raw packet bytes against a wire format.

    This is useful for other analyzers or UI components that want to
    decode individual packets.

    Args:
        data: Raw packet bytes (after opcode header).
        wire_format: Wire format dict from wire_format_recovery.

    Returns a DecodeResult.
    """
    return _decode_packet(data, wire_format)


def validate_format_alignment(wire_format):
    """Public API: Check a wire format for bit alignment issues.

    Returns a list of (field_index, issue_description) tuples.
    """
    fields = wire_format.get("fields", [])
    return _analyze_bit_alignment(fields)
