"""
DB2 Data Content Analyzer
Reads actual DB2 file rows (not just schema/metadata) to extract game data
values from WoW's client database files (.db2).  This complements the
db2_metadata analyzer which recovers *structure* from the binary — here we
parse the on-disk DB2 files themselves to obtain concrete row data.

Supported formats: WDC3 (0x33434457) and WDC5 (0x35434457).

Results are stored in session.db.kv_set("db2_data_content", {...}) and
include per-table statistics, cross-table foreign key relationships,
enum/flag field inference, and optional TC source cross-checks.
"""

import json
import os
import struct
import re
import time

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error


# ---------------------------------------------------------------------------
# DB2 format constants
# ---------------------------------------------------------------------------

MAGIC_WDC3 = 0x33434457  # 'WDC3'
MAGIC_WDC4 = 0x34434457  # 'WDC4'
MAGIC_WDC5 = 0x35434457  # 'WDC5'

SUPPORTED_MAGICS = {MAGIC_WDC3, MAGIC_WDC4, MAGIC_WDC5}

MAGIC_NAMES = {
    MAGIC_WDC3: "WDC3",
    MAGIC_WDC4: "WDC4",
    MAGIC_WDC5: "WDC5",
}

# Field storage types (storage_type in FieldStorageInfo)
STORAGE_TYPE_NONE = 0           # Inline / not compressed
STORAGE_TYPE_BITPACKED = 1      # Bitpacked integer
STORAGE_TYPE_COMMON_DATA = 2    # Common data (lookup table)
STORAGE_TYPE_BITPACKED_INDEXED = 3       # Bitpacked via pallet
STORAGE_TYPE_BITPACKED_INDEXED_ARRAY = 4  # Bitpacked pallet array
STORAGE_TYPE_BITPACKED_SIGNED = 5        # Bitpacked signed integer

STORAGE_TYPE_NAMES = {
    STORAGE_TYPE_NONE: "none",
    STORAGE_TYPE_BITPACKED: "bitpacked",
    STORAGE_TYPE_COMMON_DATA: "common_data",
    STORAGE_TYPE_BITPACKED_INDEXED: "bitpacked_indexed",
    STORAGE_TYPE_BITPACKED_INDEXED_ARRAY: "bitpacked_indexed_array",
    STORAGE_TYPE_BITPACKED_SIGNED: "bitpacked_signed",
}

# Heuristic thresholds
MAX_ENUM_DISTINCT_VALUES = 64
FLAG_FIELD_MIN_POWER2_RATIO = 0.6
FK_CONFIDENCE_MIN_OVERLAP = 0.5
FK_MIN_MATCHING_VALUES = 5


# ---------------------------------------------------------------------------
# DB2 Header parsing
# ---------------------------------------------------------------------------

class DB2Header:
    """Parsed DB2 file header (WDC3/WDC4/WDC5 common header)."""

    # WDC3/4/5 header is 72 bytes
    HEADER_SIZE = 72

    def __init__(self):
        self.magic = 0
        self.record_count = 0
        self.field_count = 0
        self.record_size = 0
        self.string_table_size = 0
        self.table_hash = 0
        self.layout_hash = 0
        self.min_id = 0
        self.max_id = 0
        self.locale = 0
        self.flags = 0
        self.id_index = 0
        self.total_field_count = 0
        self.bitpacked_data_offset = 0
        self.lookup_column_count = 0
        self.field_storage_info_size = 0
        self.common_data_size = 0
        self.pallet_data_size = 0
        self.section_count = 0

    @classmethod
    def from_bytes(cls, data):
        """Parse a DB2 header from raw bytes."""
        if len(data) < cls.HEADER_SIZE:
            return None

        h = cls()
        (
            h.magic,
            h.record_count,
            h.field_count,
            h.record_size,
            h.string_table_size,
            h.table_hash,
            h.layout_hash,
            h.min_id,
            h.max_id,
            h.locale,
            h.flags,
            h.id_index,
            h.total_field_count,
            h.bitpacked_data_offset,
            h.lookup_column_count,
            h.field_storage_info_size,
            h.common_data_size,
            h.pallet_data_size,
            h.section_count,
        ) = struct.unpack_from("<IIIIIIIIIHHHI I I III I", data, 0)

        if h.magic not in SUPPORTED_MAGICS:
            return None

        return h

    @property
    def magic_name(self):
        return MAGIC_NAMES.get(self.magic, f"0x{self.magic:08X}")

    @property
    def has_offset_map(self):
        return (self.flags & 0x01) != 0

    @property
    def has_relationship_data(self):
        return (self.flags & 0x02) != 0

    @property
    def has_offset_map_id_list(self):
        return (self.flags & 0x04) != 0

    def __repr__(self):
        return (f"DB2Header({self.magic_name}, records={self.record_count}, "
                f"fields={self.field_count}, recSize={self.record_size}, "
                f"sections={self.section_count})")


class DB2SectionHeader:
    """A single section header within a WDC3/4/5 file."""

    # WDC3: 40 bytes per section header; WDC5: same layout
    SIZE = 40

    def __init__(self):
        self.tact_key_hash = 0
        self.file_offset = 0
        self.record_count = 0
        self.string_table_size = 0
        self.offset_records_end = 0
        self.id_list_size = 0
        self.relationship_data_size = 0
        self.offset_map_id_count = 0
        self.copy_table_count = 0

    @classmethod
    def from_bytes(cls, data, offset):
        if offset + cls.SIZE > len(data):
            return None
        s = cls()
        (
            s.tact_key_hash,
            s.file_offset,
            s.record_count,
            s.string_table_size,
            s.offset_records_end,
            s.id_list_size,
            s.relationship_data_size,
            s.offset_map_id_count,
            s.copy_table_count,
        ) = struct.unpack_from("<QIIIIIIIH", data, offset)
        # Pad to 40 bytes (struct is actually 38; two bytes padding)
        return s

    @property
    def is_encrypted(self):
        return self.tact_key_hash != 0


class DB2FieldStructure:
    """Per-field size and offset info from the field_structure array."""

    SIZE = 4  # 2 bytes size, 2 bytes offset

    def __init__(self, size_bits=0, offset_bits=0):
        self.size_bits = size_bits
        self.offset_bits = offset_bits

    @classmethod
    def from_bytes(cls, data, offset):
        if offset + cls.SIZE > len(data):
            return None
        size_bits, offset_bits = struct.unpack_from("<hH", data, offset)
        return cls(size_bits, offset_bits)


class DB2FieldStorageInfo:
    """Per-field storage info describing how to decode each field."""

    SIZE = 24

    def __init__(self):
        self.field_offset_bits = 0
        self.field_size_bits = 0
        self.additional_data_size = 0
        self.storage_type = 0
        # Union: interpretation depends on storage_type
        self.val1 = 0  # bitpacking_offset_bits / default_value / ...
        self.val2 = 0  # bitpacking_size_bits / ...
        self.val3 = 0  # flags / array_count / ...

    @classmethod
    def from_bytes(cls, data, offset):
        if offset + cls.SIZE > len(data):
            return None
        info = cls()
        (
            info.field_offset_bits,
            info.field_size_bits,
            info.additional_data_size,
            info.storage_type,
            info.val1,
            info.val2,
            info.val3,
        ) = struct.unpack_from("<HHIII II", data, offset)
        return info

    @property
    def storage_type_name(self):
        return STORAGE_TYPE_NAMES.get(self.storage_type,
                                      f"unknown({self.storage_type})")


# ---------------------------------------------------------------------------
# DB2 File Parser
# ---------------------------------------------------------------------------

class DB2File:
    """Full parser for a WDC3/WDC4/WDC5 DB2 file.

    Reads the header, section headers, field structures, field storage info,
    pallet data, common data, string block, ID list, copy table, and finally
    the actual record data.  Returns rows as lists of decoded field values.
    """

    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.table_name = os.path.splitext(self.filename)[0]
        self.header = None
        self.section_headers = []
        self.field_structures = []
        self.field_storage_infos = []
        self.pallet_data = b""
        self.common_data = b""
        self._raw = b""
        self._rows = {}      # id -> [field_values]
        self._strings = {}   # offset -> string
        self._id_list = []
        self._parsed = False

    def parse(self):
        """Parse the entire DB2 file.  Returns True on success."""
        try:
            with open(self.filepath, "rb") as f:
                self._raw = f.read()
        except OSError as e:
            msg_error(f"Cannot read {self.filepath}: {e}")
            return False

        if len(self._raw) < DB2Header.HEADER_SIZE:
            msg_warn(f"{self.filename}: file too small ({len(self._raw)} bytes)")
            return False

        self.header = DB2Header.from_bytes(self._raw)
        if self.header is None:
            return False

        pos = DB2Header.HEADER_SIZE
        pos = self._parse_section_headers(pos)
        pos = self._parse_field_structures(pos)
        pos = self._parse_field_storage_info(pos)
        pos = self._parse_pallet_data(pos)
        pos = self._parse_common_data(pos)
        self._parse_sections()

        self._parsed = True
        return True

    def _parse_section_headers(self, pos):
        """Parse all section headers."""
        self.section_headers = []
        for _ in range(self.header.section_count):
            # WDC3/4/5 section header: read raw 40 bytes
            if pos + 40 > len(self._raw):
                break
            sh = DB2SectionHeader()
            # Parse the 38-byte core fields
            (
                sh.tact_key_hash,
                sh.file_offset,
                sh.record_count,
                sh.string_table_size,
                sh.offset_records_end,
                sh.id_list_size,
                sh.relationship_data_size,
                sh.offset_map_id_count,
                sh.copy_table_count,
            ) = struct.unpack_from("<QIIIIIIIH", self._raw, pos)
            self.section_headers.append(sh)
            pos += 40
        return pos

    def _parse_field_structures(self, pos):
        """Parse the field_structure array (field_count entries)."""
        self.field_structures = []
        for _ in range(self.header.field_count):
            fs = DB2FieldStructure.from_bytes(self._raw, pos)
            if fs is None:
                break
            self.field_structures.append(fs)
            pos += DB2FieldStructure.SIZE
        return pos

    def _parse_field_storage_info(self, pos):
        """Parse field storage info entries."""
        self.field_storage_infos = []
        count = self.header.field_storage_info_size // DB2FieldStorageInfo.SIZE
        for _ in range(count):
            fsi = DB2FieldStorageInfo.from_bytes(self._raw, pos)
            if fsi is None:
                break
            self.field_storage_infos.append(fsi)
            pos += DB2FieldStorageInfo.SIZE
        return pos

    def _parse_pallet_data(self, pos):
        """Read the pallet data block."""
        size = self.header.pallet_data_size
        if size > 0 and pos + size <= len(self._raw):
            self.pallet_data = self._raw[pos:pos + size]
        else:
            self.pallet_data = b""
        return pos + size

    def _parse_common_data(self, pos):
        """Read the common data block."""
        size = self.header.common_data_size
        if size > 0 and pos + size <= len(self._raw):
            self.common_data = self._raw[pos:pos + size]
        else:
            self.common_data = b""
        return pos + size

    def _parse_sections(self):
        """Parse record data from each section."""
        self._rows = {}
        self._strings = {}

        for sec_idx, sh in enumerate(self.section_headers):
            if sh.is_encrypted:
                continue  # skip encrypted sections
            if sh.record_count == 0:
                continue

            sec_start = sh.file_offset
            if sec_start <= 0 or sec_start >= len(self._raw):
                continue

            if self.header.has_offset_map:
                self._parse_offset_map_section(sh, sec_start, sec_idx)
            else:
                self._parse_inline_section(sh, sec_start, sec_idx)

    def _parse_inline_section(self, sh, sec_start, sec_idx):
        """Parse a standard inline-record section."""
        rec_size = self.header.record_size
        if rec_size == 0:
            return

        rec_data_end = sec_start + sh.record_count * rec_size

        # String table follows record data
        str_start = rec_data_end
        str_end = str_start + sh.string_table_size
        self._parse_string_block(str_start, str_end, str_start)

        # ID list follows string table (if not embedded)
        id_list_start = str_end
        id_list = []
        if sh.id_list_size > 0:
            id_count = sh.id_list_size // 4
            for i in range(id_count):
                off = id_list_start + i * 4
                if off + 4 <= len(self._raw):
                    id_list.append(struct.unpack_from("<I", self._raw, off)[0])

        # Copy table follows ID list
        copy_start = id_list_start + sh.id_list_size
        copy_table = {}
        if sh.copy_table_count > 0:
            for i in range(sh.copy_table_count):
                off = copy_start + i * 8
                if off + 8 <= len(self._raw):
                    new_id, src_id = struct.unpack_from("<II", self._raw, off)
                    copy_table[new_id] = src_id

        # Parse each record
        for rec_idx in range(sh.record_count):
            rec_offset = sec_start + rec_idx * rec_size
            if rec_offset + rec_size > len(self._raw):
                break

            rec_bytes = self._raw[rec_offset:rec_offset + rec_size]

            # Determine the row ID
            if id_list and rec_idx < len(id_list):
                row_id = id_list[rec_idx]
            elif self.header.id_index < self.header.field_count:
                # ID is embedded in record at field[id_index]
                row_id = self._read_id_from_record(rec_bytes)
            else:
                row_id = self.header.min_id + rec_idx

            fields = self._decode_record_fields(rec_bytes, row_id, str_start)
            self._rows[row_id] = fields

        # Apply copy table
        for new_id, src_id in copy_table.items():
            if src_id in self._rows and new_id not in self._rows:
                self._rows[new_id] = list(self._rows[src_id])

    def _parse_offset_map_section(self, sh, sec_start, sec_idx):
        """Parse an offset-map (variable-length record) section."""
        # For offset-map tables, records have variable size.
        # The offset_records_end marks where the variable data ends.
        # Each "record" starts with a 4-byte offset and 2-byte size.
        if sh.offset_map_id_count == 0:
            return

        # Read the offset map entries
        # Located at sec_start: record_count entries of raw variable-length data
        # Then at offset_records_end: the offset_map_id_list
        id_start = sh.offset_records_end
        entries = []

        for i in range(sh.offset_map_id_count):
            id_off = id_start + i * 4
            if id_off + 4 > len(self._raw):
                break
            row_id = struct.unpack_from("<I", self._raw, id_off)[0]
            entries.append(row_id)

        # Variable-length records are read from sec_start.
        # Each record's offset/size is given by the catalog at end of section.
        # For simplicity, try to read fixed-size portion of each record.
        offset = sec_start
        for idx, row_id in enumerate(entries):
            if offset >= sh.offset_records_end:
                break
            # Read record_size bytes if available
            remain = sh.offset_records_end - offset
            chunk = min(remain, self.header.record_size) if self.header.record_size > 0 else remain
            if chunk <= 0:
                break
            rec_bytes = self._raw[offset:offset + chunk]
            fields = self._decode_record_fields(rec_bytes, row_id, 0)
            self._rows[row_id] = fields
            offset += chunk

    def _read_id_from_record(self, rec_bytes):
        """Read the ID field from a record's raw bytes."""
        idx = self.header.id_index
        if idx < len(self.field_structures):
            fs = self.field_structures[idx]
            byte_offset = fs.offset_bits // 8
            byte_size = (32 - fs.size_bits) // 8
            if byte_size <= 0:
                byte_size = 4
            if byte_offset + byte_size <= len(rec_bytes):
                if byte_size == 4:
                    return struct.unpack_from("<I", rec_bytes, byte_offset)[0]
                elif byte_size == 2:
                    return struct.unpack_from("<H", rec_bytes, byte_offset)[0]
                elif byte_size == 1:
                    return rec_bytes[byte_offset]
                elif byte_size == 3:
                    b = rec_bytes[byte_offset:byte_offset + 3]
                    return b[0] | (b[1] << 8) | (b[2] << 16)
        # Fallback: first 4 bytes
        if len(rec_bytes) >= 4:
            return struct.unpack_from("<I", rec_bytes, 0)[0]
        return 0

    def _decode_record_fields(self, rec_bytes, row_id, string_block_offset):
        """Decode all fields from a record using field_structures and
        field_storage_info.  Returns a list of decoded values."""
        fields = []
        total = self.header.total_field_count or self.header.field_count

        for fi in range(total):
            value = self._decode_field(rec_bytes, fi, row_id, string_block_offset)
            fields.append(value)

        return fields

    def _decode_field(self, rec_bytes, field_index, row_id, string_block_offset):
        """Decode a single field from a record."""
        # Use FieldStorageInfo if available (compressed data)
        if field_index < len(self.field_storage_infos):
            fsi = self.field_storage_infos[field_index]
            return self._decode_field_by_storage(
                rec_bytes, fsi, field_index, row_id, string_block_offset)

        # Fallback to FieldStructure
        if field_index < len(self.field_structures):
            fs = self.field_structures[field_index]
            return self._decode_field_inline(rec_bytes, fs, string_block_offset)

        return 0

    def _decode_field_by_storage(self, rec_bytes, fsi, field_index,
                                  row_id, string_block_offset):
        """Decode a field using its FieldStorageInfo."""
        st = fsi.storage_type

        if st == STORAGE_TYPE_NONE:
            # Inline field — read from record at bit offset
            return self._read_inline_bits(rec_bytes, fsi.field_offset_bits,
                                           fsi.field_size_bits,
                                           string_block_offset)

        elif st == STORAGE_TYPE_BITPACKED or st == STORAGE_TYPE_BITPACKED_SIGNED:
            return self._read_bitpacked(rec_bytes, fsi)

        elif st == STORAGE_TYPE_COMMON_DATA:
            return self._read_common_data(fsi, row_id)

        elif st == STORAGE_TYPE_BITPACKED_INDEXED:
            return self._read_pallet_value(rec_bytes, fsi)

        elif st == STORAGE_TYPE_BITPACKED_INDEXED_ARRAY:
            return self._read_pallet_array(rec_bytes, fsi)

        # Unknown storage type — try inline
        return self._read_inline_bits(rec_bytes, fsi.field_offset_bits,
                                       fsi.field_size_bits, string_block_offset)

    def _read_inline_bits(self, rec_bytes, offset_bits, size_bits,
                           string_block_offset):
        """Read an inline field value from the record at the given bit offset."""
        byte_offset = offset_bits // 8
        byte_size = (size_bits + 7) // 8

        if byte_size == 0:
            byte_size = 4

        if byte_offset + byte_size > len(rec_bytes):
            return 0

        if byte_size == 1:
            return rec_bytes[byte_offset]
        elif byte_size == 2:
            return struct.unpack_from("<H", rec_bytes, byte_offset)[0]
        elif byte_size == 4:
            val = struct.unpack_from("<I", rec_bytes, byte_offset)[0]
            # Check if this might be a string offset
            if string_block_offset > 0 and self._is_possible_string_offset(val):
                s = self._read_string_at(string_block_offset + val)
                if s is not None:
                    return s
            return val
        elif byte_size == 8:
            return struct.unpack_from("<Q", rec_bytes, byte_offset)[0]
        elif byte_size == 3:
            b = rec_bytes[byte_offset:byte_offset + 3]
            return b[0] | (b[1] << 8) | (b[2] << 16)
        else:
            # Generic: read as little-endian integer
            val = 0
            for i in range(byte_size):
                if byte_offset + i < len(rec_bytes):
                    val |= rec_bytes[byte_offset + i] << (8 * i)
            return val

    def _read_bitpacked(self, rec_bytes, fsi):
        """Read a bitpacked integer from the record."""
        bitpacking_offset = fsi.val1
        bitpacking_size = fsi.val2

        if bitpacking_size == 0:
            return 0

        byte_pos = (fsi.field_offset_bits + bitpacking_offset) // 8
        bit_pos = (fsi.field_offset_bits + bitpacking_offset) % 8

        # Read enough bytes to cover the bits
        bytes_needed = (bit_pos + bitpacking_size + 7) // 8
        if byte_pos + bytes_needed > len(rec_bytes):
            return 0

        val = 0
        for i in range(bytes_needed):
            if byte_pos + i < len(rec_bytes):
                val |= rec_bytes[byte_pos + i] << (8 * i)

        val >>= bit_pos
        val &= (1 << bitpacking_size) - 1

        # Sign extend for signed bitpacked
        if fsi.storage_type == STORAGE_TYPE_BITPACKED_SIGNED:
            if bitpacking_size > 0 and (val & (1 << (bitpacking_size - 1))):
                val -= (1 << bitpacking_size)

        return val

    def _read_common_data(self, fsi, row_id):
        """Read from the common data block.  The common data block contains
        {id, value} pairs for rows that differ from the default value."""
        default_value = fsi.val1
        if not self.common_data or fsi.additional_data_size == 0:
            return default_value

        # Each entry is 8 bytes: (uint32 id, uint32 value)
        # The common data for this field starts at sum of additional_data_size
        # of all prior common-data fields.
        offset = self._get_common_data_offset(fsi)
        count = fsi.additional_data_size // 8

        for i in range(count):
            entry_off = offset + i * 8
            if entry_off + 8 > len(self.common_data):
                break
            cid, cval = struct.unpack_from("<II", self.common_data, entry_off)
            if cid == row_id:
                return cval

        return default_value

    def _get_common_data_offset(self, target_fsi):
        """Calculate the offset within common_data for a specific field."""
        offset = 0
        for fsi in self.field_storage_infos:
            if fsi is target_fsi:
                return offset
            if fsi.storage_type == STORAGE_TYPE_COMMON_DATA:
                offset += fsi.additional_data_size
        return offset

    def _read_pallet_value(self, rec_bytes, fsi):
        """Read a value from the pallet (indexed bitpacked)."""
        # First read the pallet index from the record
        idx = self._read_bitpacked(rec_bytes, fsi)

        # Then look up in pallet data
        pallet_offset = self._get_pallet_data_offset(fsi)
        entry_off = pallet_offset + idx * 4
        if entry_off + 4 <= len(self.pallet_data):
            return struct.unpack_from("<I", self.pallet_data, entry_off)[0]
        return 0

    def _read_pallet_array(self, rec_bytes, fsi):
        """Read an array of values from the pallet."""
        idx = self._read_bitpacked(rec_bytes, fsi)
        array_count = fsi.val3 if fsi.val3 > 0 else 1

        pallet_offset = self._get_pallet_data_offset(fsi)
        entry_off = pallet_offset + idx * 4 * array_count

        values = []
        for i in range(array_count):
            off = entry_off + i * 4
            if off + 4 <= len(self.pallet_data):
                values.append(
                    struct.unpack_from("<I", self.pallet_data, off)[0])
            else:
                values.append(0)
        return values

    def _get_pallet_data_offset(self, target_fsi):
        """Calculate the offset within pallet_data for a specific field."""
        offset = 0
        for fsi in self.field_storage_infos:
            if fsi is target_fsi:
                return offset
            if fsi.storage_type in (STORAGE_TYPE_BITPACKED_INDEXED,
                                     STORAGE_TYPE_BITPACKED_INDEXED_ARRAY):
                offset += fsi.additional_data_size
        return offset

    def _is_possible_string_offset(self, val):
        """Heuristic: could this uint32 be a string block offset?"""
        if val == 0:
            return False
        if self.header.string_table_size == 0:
            return False
        return val < self.header.string_table_size

    def _read_string_at(self, abs_offset):
        """Read a null-terminated string from the raw file data."""
        if abs_offset < 0 or abs_offset >= len(self._raw):
            return None
        end = self._raw.find(b'\x00', abs_offset)
        if end < 0:
            end = min(abs_offset + 256, len(self._raw))
        try:
            s = self._raw[abs_offset:end].decode("utf-8", errors="replace")
            # Reject if it looks like garbage
            if len(s) > 0 and all(c == '\x00' or c == '\ufffd' for c in s):
                return None
            return s
        except Exception:
            return None

    def _parse_string_block(self, start, end, base_offset):
        """Parse the string block and cache offset->string mapping."""
        if start >= end or start >= len(self._raw):
            return
        block = self._raw[start:min(end, len(self._raw))]
        pos = 0
        while pos < len(block):
            nul = block.find(b'\x00', pos)
            if nul < 0:
                break
            try:
                s = block[pos:nul].decode("utf-8", errors="replace")
                self._strings[pos] = s
            except Exception:
                pass
            pos = nul + 1

    @property
    def rows(self):
        return self._rows

    @property
    def row_count(self):
        return len(self._rows)

    def get_field_count(self):
        """Return the effective field count for data rows."""
        return self.header.total_field_count or self.header.field_count


# ---------------------------------------------------------------------------
# Data analysis helpers
# ---------------------------------------------------------------------------

def _compute_field_statistics(rows, field_index):
    """Compute statistics for a single field across all rows.

    Returns a dict with min, max, distinct_count, most_common, value_type,
    is_possible_enum, is_possible_flags, sample_values.
    """
    values = []
    str_count = 0
    int_count = 0
    float_count = 0
    list_count = 0

    for row_id, fields in rows.items():
        if field_index < len(fields):
            v = fields[field_index]
            values.append(v)
            if isinstance(v, str):
                str_count += 1
            elif isinstance(v, float):
                float_count += 1
            elif isinstance(v, list):
                list_count += 1
            else:
                int_count += 1

    if not values:
        return {
            "distinct_count": 0,
            "value_type": "empty",
            "is_possible_enum": False,
            "is_possible_flags": False,
        }

    # Determine dominant type
    total = len(values)
    if str_count > total * 0.5:
        return _analyze_string_field(values)
    if list_count > total * 0.5:
        return _analyze_array_field(values)

    # Numeric analysis
    numeric = []
    for v in values:
        if isinstance(v, (int, float)):
            numeric.append(v)
        elif isinstance(v, str):
            pass  # skip strings in numeric analysis
        elif isinstance(v, list):
            pass

    if not numeric:
        return {
            "distinct_count": len(set(str(v) for v in values)),
            "value_type": "mixed",
            "is_possible_enum": False,
            "is_possible_flags": False,
        }

    distinct = set(numeric)
    distinct_count = len(distinct)

    # Value frequency
    freq = {}
    for v in numeric:
        freq[v] = freq.get(v, 0) + 1
    most_common = sorted(freq.items(), key=lambda x: -x[1])[:10]

    min_val = min(numeric)
    max_val = max(numeric)

    # Float detection
    is_float = float_count > int_count

    # Enum detection: small distinct value set
    is_possible_enum = (
        not is_float
        and 2 <= distinct_count <= MAX_ENUM_DISTINCT_VALUES
        and distinct_count < total * 0.3
    )

    # Flag field detection: values that are powers of 2 or combinations
    is_possible_flags = False
    if not is_float and min_val >= 0 and distinct_count >= 2:
        power2_count = sum(1 for v in distinct
                           if v > 0 and (v & (v - 1)) == 0)
        if distinct_count > 0:
            ratio = power2_count / distinct_count
            if ratio >= FLAG_FIELD_MIN_POWER2_RATIO and power2_count >= 2:
                is_possible_flags = True
            # Also check if values look like bitmask combinations
            if not is_possible_flags and max_val < 65536:
                # Check if all values can be expressed as OR of small set of bits
                all_bits = 0
                for v in numeric:
                    if isinstance(v, int):
                        all_bits |= v
                bit_count = bin(all_bits).count('1')
                if 2 <= bit_count <= 16 and distinct_count > bit_count:
                    is_possible_flags = True

    # Sample values
    sample = sorted(distinct)[:20]

    return {
        "min": min_val,
        "max": max_val,
        "distinct_count": distinct_count,
        "most_common": [(v, c) for v, c in most_common],
        "value_type": "float" if is_float else "int",
        "is_possible_enum": is_possible_enum,
        "is_possible_flags": is_possible_flags,
        "sample_values": sample,
        "total_rows": total,
        "zero_count": freq.get(0, 0),
    }


def _analyze_string_field(values):
    """Analyze a string-typed field."""
    strings = [v for v in values if isinstance(v, str)]
    distinct = set(strings)
    lengths = [len(s) for s in strings]

    # Classify: names, descriptions, file paths
    path_count = sum(1 for s in strings if '/' in s or '\\' in s or '.' in s)
    long_count = sum(1 for s in strings if len(s) > 80)

    if len(strings) > 0:
        path_ratio = path_count / len(strings)
        long_ratio = long_count / len(strings)
    else:
        path_ratio = 0.0
        long_ratio = 0.0

    if path_ratio > 0.5:
        classification = "filepath"
    elif long_ratio > 0.3:
        classification = "description"
    else:
        classification = "name"

    samples = sorted(distinct)[:10]

    return {
        "distinct_count": len(distinct),
        "value_type": "string",
        "string_classification": classification,
        "avg_length": sum(lengths) / len(lengths) if lengths else 0,
        "max_length": max(lengths) if lengths else 0,
        "is_possible_enum": False,
        "is_possible_flags": False,
        "sample_values": samples,
        "total_rows": len(values),
        "empty_count": sum(1 for s in strings if not s),
    }


def _analyze_array_field(values):
    """Analyze an array-typed field."""
    arrays = [v for v in values if isinstance(v, list)]
    if not arrays:
        return {
            "distinct_count": 0,
            "value_type": "array",
            "is_possible_enum": False,
            "is_possible_flags": False,
        }

    lengths = [len(a) for a in arrays]
    return {
        "distinct_count": len(set(tuple(a) for a in arrays)),
        "value_type": "array",
        "array_size": max(lengths) if lengths else 0,
        "is_possible_enum": False,
        "is_possible_flags": False,
        "total_rows": len(values),
    }


# ---------------------------------------------------------------------------
# Foreign key detection
# ---------------------------------------------------------------------------

def _detect_foreign_keys(all_table_data):
    """Detect foreign key relationships between tables.

    For each integer field in each table, check if its values are a subset
    of the ID values of some other table.

    Args:
        all_table_data: dict of {table_name: DB2File}

    Returns:
        List of {from_table, from_field, to_table, confidence, overlap_ratio}
    """
    # Build ID sets for all tables
    id_sets = {}
    for tname, db2 in all_table_data.items():
        ids = set(db2.rows.keys())
        if ids:
            id_sets[tname] = ids

    if not id_sets:
        return []

    relationships = []

    for tname, db2 in all_table_data.items():
        if db2.row_count == 0:
            continue
        field_count = db2.get_field_count()

        for fi in range(field_count):
            # Collect non-zero integer values for this field
            field_vals = set()
            for row_id, fields in db2.rows.items():
                if fi < len(fields):
                    v = fields[fi]
                    if isinstance(v, int) and v > 0:
                        field_vals.add(v)

            if len(field_vals) < FK_MIN_MATCHING_VALUES:
                continue

            # Don't check if it's the table's own ID set
            own_ids = set(db2.rows.keys())
            if field_vals == own_ids:
                continue

            # Compare against all other tables' ID sets
            for other_name, other_ids in id_sets.items():
                if other_name == tname:
                    continue

                overlap = field_vals & other_ids
                if len(overlap) < FK_MIN_MATCHING_VALUES:
                    continue

                overlap_ratio = len(overlap) / len(field_vals)
                if overlap_ratio < FK_CONFIDENCE_MIN_OVERLAP:
                    continue

                # Confidence is based on overlap ratio and number of matches
                confidence = min(1.0, overlap_ratio * (1.0 +
                    min(len(overlap), 100) / 100.0) / 2.0)

                relationships.append({
                    "from_table": tname,
                    "from_field": fi,
                    "to_table": other_name,
                    "confidence": round(confidence, 3),
                    "overlap_ratio": round(overlap_ratio, 3),
                    "matching_count": len(overlap),
                    "total_values": len(field_vals),
                })

    # Sort by confidence descending, deduplicate near-identical entries
    relationships.sort(key=lambda r: -r["confidence"])

    # Keep only the best match for each (from_table, from_field)
    seen = set()
    deduped = []
    for r in relationships:
        key = (r["from_table"], r["from_field"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    return deduped


# ---------------------------------------------------------------------------
# Cross-table relationship graph
# ---------------------------------------------------------------------------

def _build_relationship_graph(relationships, all_table_data):
    """Build a graph of table relationships and classify table roles.

    Returns a dict with:
      - adjacency: {table: [{target, field, confidence, direction}]}
      - table_roles: {table: "primary" | "lookup" | "junction" | "child"}
    """
    adjacency = {}
    incoming = {}  # table -> count of FK references pointing to it
    outgoing = {}  # table -> count of FK references pointing away

    for r in relationships:
        src = r["from_table"]
        dst = r["to_table"]

        adjacency.setdefault(src, []).append({
            "target": dst,
            "field": r["from_field"],
            "confidence": r["confidence"],
            "direction": "outgoing",
        })
        adjacency.setdefault(dst, []).append({
            "target": src,
            "field": r["from_field"],
            "confidence": r["confidence"],
            "direction": "incoming",
        })

        outgoing[src] = outgoing.get(src, 0) + 1
        incoming[dst] = incoming.get(dst, 0) + 1

    # Classify table roles
    table_roles = {}
    for tname, db2 in all_table_data.items():
        inc = incoming.get(tname, 0)
        out = outgoing.get(tname, 0)
        row_count = db2.row_count

        if inc > 2 and out == 0 and row_count < 500:
            table_roles[tname] = "lookup"
        elif out >= 2 and inc == 0:
            table_roles[tname] = "junction"
        elif inc > 0 and out > 0:
            # Check for parent-child based on name patterns
            for r in relationships:
                if r["to_table"] == tname:
                    # Something references us — we might be a parent
                    table_roles.setdefault(tname, "primary")
                if r["from_table"] == tname:
                    table_roles.setdefault(tname, "child")
        else:
            table_roles[tname] = "primary"

    return {
        "adjacency": {k: v for k, v in sorted(adjacency.items())},
        "table_roles": table_roles,
    }


# ---------------------------------------------------------------------------
# Hierarchical relationship detection
# ---------------------------------------------------------------------------

def _detect_hierarchical_relationships(all_table_data, db_tables_metadata):
    """Detect parent-child relationships using ParentIndexField from metadata.

    Args:
        all_table_data: dict of {table_name: DB2File}
        db_tables_metadata: list of dicts from the db2_tables knowledge DB

    Returns:
        List of {parent, child, parent_field_index}
    """
    hierarchies = []

    meta_by_name = {}
    for m in db_tables_metadata:
        name = m.get("name", "")
        if name:
            meta_by_name[name] = m

    for tname, meta in meta_by_name.items():
        parent_idx = meta.get("parent_index_field", -1)
        if parent_idx is None or parent_idx < 0:
            continue

        # The parent_index_field points to a field that contains the parent ID.
        # Try to identify which table the parent IDs belong to.
        if tname not in all_table_data:
            continue

        db2 = all_table_data[tname]
        parent_ids = set()
        for row_id, fields in db2.rows.items():
            if parent_idx < len(fields):
                v = fields[parent_idx]
                if isinstance(v, int) and v > 0:
                    parent_ids.add(v)

        if not parent_ids:
            continue

        # Find the best matching parent table
        best_match = None
        best_overlap = 0

        for other_name, other_db2 in all_table_data.items():
            if other_name == tname:
                continue
            other_ids = set(other_db2.rows.keys())
            overlap = len(parent_ids & other_ids)
            if overlap > best_overlap:
                best_overlap = overlap
                best_match = other_name

        if best_match and best_overlap >= max(1, len(parent_ids) * 0.3):
            hierarchies.append({
                "parent": best_match,
                "child": tname,
                "parent_field_index": parent_idx,
                "matching_ids": best_overlap,
                "total_parent_ids": len(parent_ids),
            })

    return hierarchies


# ---------------------------------------------------------------------------
# TC source comparison
# ---------------------------------------------------------------------------

def _compare_with_tc_source(all_table_data, tc_source_dir):
    """Compare DB2 file data against TrinityCore source expectations.

    Checks:
      - Row counts vs what TC expects
      - Specific row IDs referenced in TC source
      - Tables TC loads but we don't have data for

    Returns a list of mismatch dicts.
    """
    mismatches = []

    if not tc_source_dir or not os.path.isdir(tc_source_dir):
        return mismatches

    # Find DB2Store loading code
    store_file = os.path.join(tc_source_dir, "src", "server", "game",
                               "DataStores", "DB2Stores.cpp")
    if not os.path.isfile(store_file):
        # Try alternate location
        for root, dirs, files in os.walk(
                os.path.join(tc_source_dir, "src", "server")):
            if "DB2Stores.cpp" in files:
                store_file = os.path.join(root, "DB2Stores.cpp")
                break
        else:
            return mismatches

    try:
        with open(store_file, "r", encoding="utf-8", errors="ignore") as f:
            store_code = f.read()
    except OSError:
        return mismatches

    # Find all DB2Storage declarations: DB2Storage<XxxEntry> sXxxStore("Xxx.db2")
    store_pattern = re.compile(
        r'DB2Storage<(\w+)Entry>\s+s(\w+)Store\s*\(\s*"([^"]+)"',
    )
    tc_stores = {}
    for m in store_pattern.finditer(store_code):
        entry_type = m.group(1)
        store_name = m.group(2)
        db2_filename = m.group(3)
        table_name = os.path.splitext(db2_filename)[0]
        tc_stores[table_name] = {
            "entry_type": entry_type,
            "store_name": store_name,
            "filename": db2_filename,
        }

    # Compare loaded tables
    for tc_name, tc_info in tc_stores.items():
        if tc_name in all_table_data:
            db2 = all_table_data[tc_name]
            if db2.row_count == 0:
                mismatches.append({
                    "table": tc_name,
                    "issue": "empty_data",
                    "details": (f"TC loads {tc_name} via s{tc_info['store_name']}"
                                f"Store but DB2 file has 0 rows"),
                })
        else:
            mismatches.append({
                "table": tc_name,
                "issue": "missing_file",
                "details": (f"TC loads {tc_info['filename']} but no DB2 file "
                            f"found in data directory"),
            })

    # Find specific row ID references in TC source code
    # Pattern: sXxxStore[123] or sXxxStore.LookupEntry(123)
    id_ref_pattern = re.compile(
        r's(\w+)Store\s*[\[\.](?:LookupEntry\s*\(\s*)?(\d+)\s*[\])]'
    )
    for m in id_ref_pattern.finditer(store_code):
        store_name = m.group(1)
        row_id = int(m.group(2))
        if row_id == 0:
            continue

        # Find matching table
        matching_table = None
        for tc_name, tc_info in tc_stores.items():
            if tc_info["store_name"] == store_name:
                matching_table = tc_name
                break

        if matching_table and matching_table in all_table_data:
            db2 = all_table_data[matching_table]
            if row_id not in db2.rows:
                mismatches.append({
                    "table": matching_table,
                    "issue": "missing_row",
                    "details": (f"TC references s{store_name}Store[{row_id}] "
                                f"but row {row_id} not found in DB2 data"),
                })

    # Also scan for ID references in other game source files
    _scan_source_for_id_refs(tc_source_dir, all_table_data, tc_stores,
                              mismatches)

    return mismatches


def _scan_source_for_id_refs(tc_source_dir, all_table_data, tc_stores,
                              mismatches):
    """Scan broader TC source for hardcoded DB2 row ID references."""
    game_dir = os.path.join(tc_source_dir, "src", "server", "game")
    if not os.path.isdir(game_dir):
        return

    # Limit scan to key directories
    scan_dirs = [
        os.path.join(game_dir, "Spells"),
        os.path.join(game_dir, "Entities"),
        os.path.join(game_dir, "Handlers"),
        os.path.join(game_dir, "Combat"),
        os.path.join(game_dir, "Quests"),
    ]

    id_ref_pattern = re.compile(
        r's(\w+)Store\s*[\[\.](?:LookupEntry\s*\(\s*)?(\d+)\s*[\])]'
    )

    scanned = 0
    max_scan = 500  # limit for performance

    for scan_dir in scan_dirs:
        if not os.path.isdir(scan_dir):
            continue
        for root, dirs, files in os.walk(scan_dir):
            for fname in files:
                if not fname.endswith((".cpp", ".h")):
                    continue
                if scanned >= max_scan:
                    return

                filepath = os.path.join(root, fname)
                try:
                    with open(filepath, "r", encoding="utf-8",
                              errors="ignore") as f:
                        code = f.read()
                except OSError:
                    continue
                scanned += 1

                for m in id_ref_pattern.finditer(code):
                    store_name = m.group(1)
                    row_id = int(m.group(2))
                    if row_id == 0:
                        continue

                    matching_table = None
                    for tc_name, tc_info in tc_stores.items():
                        if tc_info["store_name"] == store_name:
                            matching_table = tc_name
                            break

                    if matching_table and matching_table in all_table_data:
                        db2 = all_table_data[matching_table]
                        if row_id not in db2.rows:
                            entry = {
                                "table": matching_table,
                                "issue": "missing_row_ref",
                                "details": (
                                    f"{os.path.basename(filepath)}: "
                                    f"s{store_name}Store[{row_id}] — row "
                                    f"not found in DB2 data"
                                ),
                            }
                            # Avoid duplicates
                            if entry not in mismatches:
                                mismatches.append(entry)


# ---------------------------------------------------------------------------
# Export functions
# ---------------------------------------------------------------------------

def export_table_data(session, table_name):
    """Export a single DB2 table's data as CSV text.

    Args:
        session: PluginSession
        table_name: Name of the DB2 table (e.g. "SpellName")

    Returns:
        CSV text as a string, or an error message.
    """
    content = session.db.kv_get("db2_data_content")
    if not content:
        return f"# No DB2 content data available. Run analyze_db2_content first."

    db2_dir = _resolve_db2_dir(session)
    if not db2_dir:
        return f"# Cannot locate DB2 data directory."

    # Find the file
    filepath = _find_db2_file(db2_dir, table_name)
    if not filepath:
        return f"# DB2 file for '{table_name}' not found in {db2_dir}"

    db2 = DB2File(filepath)
    if not db2.parse():
        return f"# Failed to parse {filepath}"

    if db2.row_count == 0:
        return f"# {table_name}: 0 rows"

    field_count = db2.get_field_count()

    # Build CSV
    lines = []

    # Header row
    header_parts = ["ID"]
    for fi in range(field_count):
        header_parts.append(f"Field{fi}")
    lines.append(",".join(header_parts))

    # Data rows
    for row_id in sorted(db2.rows.keys()):
        fields = db2.rows[row_id]
        parts = [str(row_id)]
        for fi in range(field_count):
            if fi < len(fields):
                v = fields[fi]
                if isinstance(v, str):
                    # Escape CSV string
                    escaped = v.replace('"', '""')
                    parts.append(f'"{escaped}"')
                elif isinstance(v, list):
                    parts.append(f'"{v}"')
                else:
                    parts.append(str(v))
            else:
                parts.append("")
        lines.append(",".join(parts))

    return "\n".join(lines)


def get_table_statistics(session, table_name):
    """Get per-field statistics for a specific DB2 table.

    Args:
        session: PluginSession
        table_name: Name of the DB2 table

    Returns:
        Dict with field-level statistics, or None if not available.
    """
    content = session.db.kv_get("db2_data_content")
    if not content:
        return None

    table_stats = content.get("table_stats", [])
    for ts in table_stats:
        if ts.get("name") == table_name:
            return ts

    return None


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _resolve_db2_dir(session):
    """Determine the directory containing DB2 files.

    Priority:
      1. session.cfg.get("db2_data_dir")
      2. session.cfg.get("builds", build, "db2_data_dir")
      3. Auto-detect from extraction_dir
    """
    cfg = session.cfg

    # Direct config
    db2_dir = cfg.db2_data_dir
    if db2_dir and os.path.isdir(db2_dir):
        return db2_dir

    # Per-build config
    build = str(cfg.build_number)
    if build and build != "0":
        db2_dir = cfg.get("builds", build, "db2_data_dir")
        if db2_dir and os.path.isdir(db2_dir):
            return db2_dir

    # Auto-detect: look for common subdirectories
    extraction_dir = cfg.extraction_dir
    if extraction_dir and os.path.isdir(extraction_dir):
        candidates = [
            os.path.join(extraction_dir, "dbfilesclient"),
            os.path.join(extraction_dir, "DBFilesClient"),
            os.path.join(extraction_dir, "db2"),
            os.path.join(extraction_dir, "DB2"),
            extraction_dir,  # files might be directly in extraction_dir
        ]
        for c in candidates:
            if os.path.isdir(c):
                # Verify it contains .db2 files
                try:
                    for f in os.listdir(c):
                        if f.lower().endswith(".db2"):
                            return c
                except OSError:
                    pass

    return None


def _find_db2_file(db2_dir, table_name):
    """Find a DB2 file by table name, case-insensitive."""
    target = table_name.lower() + ".db2"
    try:
        for f in os.listdir(db2_dir):
            if f.lower() == target:
                return os.path.join(db2_dir, f)
    except OSError:
        pass
    return None


def _discover_db2_files(db2_dir):
    """Discover all .db2 files in a directory.

    Returns a list of (table_name, filepath) tuples.
    """
    results = []
    try:
        for f in sorted(os.listdir(db2_dir)):
            if f.lower().endswith(".db2"):
                table_name = os.path.splitext(f)[0]
                results.append((table_name, os.path.join(db2_dir, f)))
    except OSError as e:
        msg_error(f"Cannot list directory {db2_dir}: {e}")
    return results


# ---------------------------------------------------------------------------
# Main analyzer entry point
# ---------------------------------------------------------------------------

def analyze_db2_content(session):
    """Parse DB2 files and extract game data content with statistics.

    Main entry point for the analyzer. Reads all DB2 files from the
    configured data directory, decodes their records, computes field-level
    statistics, detects foreign keys and enum/flag fields, and optionally
    compares against TrinityCore source.

    Args:
        session: PluginSession with .db (KnowledgeDB) and .cfg (PluginConfig)

    Returns:
        int: Number of tables successfully analyzed.
    """
    db = session.db
    cfg = session.cfg

    start_time = time.time()

    # Resolve DB2 file directory
    db2_dir = _resolve_db2_dir(session)
    if not db2_dir:
        msg_warn("DB2 data directory not found. Configure 'db2_data_dir' in "
                 "settings or ensure extraction_dir contains a dbfilesclient/ "
                 "subdirectory.")
        db.kv_set("db2_data_content", {
            "tables_analyzed": 0,
            "total_rows_read": 0,
            "table_stats": [],
            "relationships": [],
            "tc_mismatches": [],
            "error": "db2_data_dir not configured or not found",
        })
        db.commit()
        return 0

    msg_info(f"DB2 data directory: {db2_dir}")

    # Discover DB2 files
    db2_files = _discover_db2_files(db2_dir)
    if not db2_files:
        msg_warn(f"No .db2 files found in {db2_dir}")
        db.kv_set("db2_data_content", {
            "tables_analyzed": 0,
            "total_rows_read": 0,
            "table_stats": [],
            "relationships": [],
            "tc_mismatches": [],
            "error": f"No .db2 files in {db2_dir}",
        })
        db.commit()
        return 0

    msg_info(f"Found {len(db2_files)} DB2 files to analyze")

    # Load known table metadata from knowledge DB
    db_tables_metadata = []
    try:
        rows = db.fetchall("SELECT * FROM db2_tables")
        db_tables_metadata = [dict(r) for r in rows]
    except Exception:
        pass

    meta_by_name = {}
    for m in db_tables_metadata:
        name = m.get("name", "")
        if name:
            meta_by_name[name] = m

    # Parse all DB2 files
    all_table_data = {}     # table_name -> DB2File
    table_stats_list = []   # per-table stats
    total_rows = 0
    tables_analyzed = 0
    parse_errors = 0
    encrypted_count = 0

    for table_name, filepath in db2_files:
        db2 = DB2File(filepath)
        if not db2.parse():
            parse_errors += 1
            continue

        if db2.row_count == 0:
            # Check if all sections are encrypted
            all_encrypted = all(sh.is_encrypted
                                for sh in db2.section_headers
                                if sh.record_count > 0)
            if all_encrypted and db2.section_headers:
                encrypted_count += 1
            continue

        all_table_data[table_name] = db2
        total_rows += db2.row_count
        tables_analyzed += 1

        # Validate against known metadata
        meta = meta_by_name.get(table_name)
        validation_notes = []
        if meta:
            expected_fields = meta.get("field_count", 0)
            actual_fields = db2.get_field_count()
            if expected_fields and actual_fields != expected_fields:
                validation_notes.append(
                    f"field_count: expected {expected_fields}, got {actual_fields}")
            expected_rec_size = meta.get("record_size", 0)
            if expected_rec_size and db2.header.record_size != expected_rec_size:
                validation_notes.append(
                    f"record_size: expected {expected_rec_size}, "
                    f"got {db2.header.record_size}")

        # Compute per-field statistics
        field_count = db2.get_field_count()
        field_stats = []
        enum_fields = []
        flag_fields = []
        string_fields = []

        for fi in range(field_count):
            stats = _compute_field_statistics(db2.rows, fi)
            stats["field_index"] = fi
            field_stats.append(stats)

            if stats.get("is_possible_enum"):
                enum_fields.append(fi)
            if stats.get("is_possible_flags"):
                flag_fields.append(fi)
            if stats.get("value_type") == "string":
                string_fields.append({
                    "index": fi,
                    "classification": stats.get("string_classification", "unknown"),
                })

        table_stat = {
            "name": table_name,
            "row_count": db2.row_count,
            "field_count": field_count,
            "record_size": db2.header.record_size,
            "format": db2.header.magic_name,
            "layout_hash": f"0x{db2.header.layout_hash:08X}",
            "id_range": [db2.header.min_id, db2.header.max_id],
            "section_count": db2.header.section_count,
            "has_offset_map": db2.header.has_offset_map,
            "foreign_keys": [],  # filled in later
            "enum_fields": enum_fields,
            "flag_fields": flag_fields,
            "string_fields": string_fields,
            "field_stats": field_stats,
            "validation_notes": validation_notes,
        }
        table_stats_list.append(table_stat)

        # Progress logging every 50 tables
        if tables_analyzed % 50 == 0:
            msg(f"  Parsed {tables_analyzed} tables, "
                f"{total_rows} total rows...")

    msg_info(f"Parsed {tables_analyzed} tables ({total_rows} total rows, "
             f"{parse_errors} errors, {encrypted_count} encrypted)")

    # Detect foreign key relationships
    msg(f"  Detecting foreign key relationships...")
    relationships = _detect_foreign_keys(all_table_data)
    msg_info(f"Found {len(relationships)} potential foreign key relationships")

    # Annotate table stats with their foreign keys
    fk_by_table = {}
    for r in relationships:
        fk_by_table.setdefault(r["from_table"], []).append({
            "field": r["from_field"],
            "target_table": r["to_table"],
            "confidence": r["confidence"],
        })

    for ts in table_stats_list:
        ts["foreign_keys"] = fk_by_table.get(ts["name"], [])

    # Build relationship graph
    msg(f"  Building relationship graph...")
    rel_graph = _build_relationship_graph(relationships, all_table_data)

    # Detect hierarchical relationships
    hierarchies = _detect_hierarchical_relationships(
        all_table_data, db_tables_metadata)
    msg_info(f"Found {len(hierarchies)} hierarchical (parent-child) relationships")

    # TC source comparison
    tc_mismatches = []
    tc_source_dir = cfg.tc_source_dir
    if tc_source_dir and os.path.isdir(tc_source_dir):
        msg(f"  Comparing with TrinityCore source at {tc_source_dir}...")
        tc_mismatches = _compare_with_tc_source(all_table_data, tc_source_dir)
        msg_info(f"Found {len(tc_mismatches)} TC comparison mismatches")
    else:
        msg(f"  Skipping TC source comparison (tc_source_dir not configured)")

    # Prepare serializable relationship list
    serializable_relationships = []
    for r in relationships:
        serializable_relationships.append({
            "from_table": r["from_table"],
            "from_field": r["from_field"],
            "to_table": r["to_table"],
            "confidence": r["confidence"],
        })

    # Summarize field stats to avoid storing excessive data in kv_store
    # Keep only the summary; full field stats available via get_table_statistics
    summary_table_stats = []
    for ts in table_stats_list:
        summary = {
            "name": ts["name"],
            "row_count": ts["row_count"],
            "field_count": ts["field_count"],
            "record_size": ts["record_size"],
            "format": ts["format"],
            "layout_hash": ts["layout_hash"],
            "id_range": ts["id_range"],
            "foreign_keys": ts["foreign_keys"],
            "enum_fields": ts["enum_fields"],
            "flag_fields": ts["flag_fields"],
            "string_fields": ts["string_fields"],
            "validation_notes": ts["validation_notes"],
        }
        summary_table_stats.append(summary)

    # Prepare full stats (with field_stats) for separate storage
    # Store per-table detailed stats individually
    for ts in table_stats_list:
        db.kv_set(f"db2_content_fields_{ts['name']}", ts["field_stats"])

    elapsed = time.time() - start_time

    # Store main results
    result = {
        "tables_analyzed": tables_analyzed,
        "total_rows_read": total_rows,
        "parse_errors": parse_errors,
        "encrypted_tables": encrypted_count,
        "table_stats": summary_table_stats,
        "relationships": serializable_relationships,
        "hierarchies": hierarchies,
        "relationship_graph": {
            "table_roles": rel_graph.get("table_roles", {}),
        },
        "tc_mismatches": tc_mismatches,
        "analysis_time_seconds": round(elapsed, 2),
        "db2_data_dir": db2_dir,
    }

    db.kv_set("db2_data_content", result)
    db.commit()

    msg_info(f"DB2 content analysis complete: {tables_analyzed} tables, "
             f"{total_rows} rows, {len(relationships)} relationships, "
             f"{len(tc_mismatches)} TC mismatches "
             f"({elapsed:.1f}s)")

    return tables_analyzed


# ---------------------------------------------------------------------------
# Report retrieval
# ---------------------------------------------------------------------------

def get_db2_content_report(session):
    """Retrieve the stored DB2 content analysis report.

    Args:
        session: PluginSession

    Returns:
        Dict with analysis results, or empty dict if not run yet.
    """
    return session.db.kv_get("db2_data_content") or {}


def get_field_details(session, table_name):
    """Retrieve detailed per-field statistics for a table.

    Args:
        session: PluginSession
        table_name: DB2 table name

    Returns:
        List of field stat dicts, or None.
    """
    return session.db.kv_get(f"db2_content_fields_{table_name}")


def get_relationships_for_table(session, table_name):
    """Get all foreign key relationships involving a specific table.

    Args:
        session: PluginSession
        table_name: DB2 table name

    Returns:
        Dict with 'outgoing' and 'incoming' relationship lists.
    """
    report = get_db2_content_report(session)
    if not report:
        return {"outgoing": [], "incoming": []}

    outgoing = []
    incoming = []

    for r in report.get("relationships", []):
        if r["from_table"] == table_name:
            outgoing.append(r)
        if r["to_table"] == table_name:
            incoming.append(r)

    return {"outgoing": outgoing, "incoming": incoming}


def get_enum_candidates(session):
    """Get all fields across all tables that look like enums.

    Returns:
        List of {table, field_index, distinct_count, sample_values}
    """
    report = get_db2_content_report(session)
    if not report:
        return []

    candidates = []
    for ts in report.get("table_stats", []):
        for fi in ts.get("enum_fields", []):
            # Load detailed stats if available
            field_stats = get_field_details(session, ts["name"])
            detail = {}
            if field_stats and fi < len(field_stats):
                detail = field_stats[fi]

            candidates.append({
                "table": ts["name"],
                "field_index": fi,
                "distinct_count": detail.get("distinct_count", 0),
                "sample_values": detail.get("sample_values", []),
                "most_common": detail.get("most_common", []),
            })

    return candidates


def get_flag_candidates(session):
    """Get all fields across all tables that look like bitmask flags.

    Returns:
        List of {table, field_index, distinct_count, max_value, sample_values}
    """
    report = get_db2_content_report(session)
    if not report:
        return []

    candidates = []
    for ts in report.get("table_stats", []):
        for fi in ts.get("flag_fields", []):
            field_stats = get_field_details(session, ts["name"])
            detail = {}
            if field_stats and fi < len(field_stats):
                detail = field_stats[fi]

            candidates.append({
                "table": ts["name"],
                "field_index": fi,
                "distinct_count": detail.get("distinct_count", 0),
                "max": detail.get("max", 0),
                "sample_values": detail.get("sample_values", []),
            })

    return candidates


def search_tables_by_value(session, value, max_results=50):
    """Search all analyzed tables for rows containing a specific value.

    Useful for finding which DB2 tables reference a specific spell ID,
    item ID, creature entry, etc.

    Args:
        session: PluginSession
        value: The value to search for (int or string)
        max_results: Maximum number of results to return

    Returns:
        List of {table, row_id, field_index, field_value}
    """
    db2_dir = _resolve_db2_dir(session)
    if not db2_dir:
        return []

    report = get_db2_content_report(session)
    if not report:
        return []

    results = []

    for ts in report.get("table_stats", []):
        if len(results) >= max_results:
            break

        table_name = ts["name"]
        filepath = _find_db2_file(db2_dir, table_name)
        if not filepath:
            continue

        db2 = DB2File(filepath)
        if not db2.parse():
            continue

        # Check if value is a row ID
        if isinstance(value, int) and value in db2.rows:
            results.append({
                "table": table_name,
                "row_id": value,
                "field_index": -1,  # ID match
                "field_value": value,
                "match_type": "id",
            })

        # Check field values
        for row_id, fields in db2.rows.items():
            if len(results) >= max_results:
                break
            for fi, fv in enumerate(fields):
                if fv == value:
                    results.append({
                        "table": table_name,
                        "row_id": row_id,
                        "field_index": fi,
                        "field_value": fv,
                        "match_type": "field",
                    })
                elif isinstance(value, str) and isinstance(fv, str):
                    if value.lower() in fv.lower():
                        results.append({
                            "table": table_name,
                            "row_id": row_id,
                            "field_index": fi,
                            "field_value": fv,
                            "match_type": "substring",
                        })

    return results


def get_table_summary(session):
    """Get a concise summary of all analyzed tables for display.

    Returns:
        List of {name, rows, fields, enums, flags, fks, format}
    """
    report = get_db2_content_report(session)
    if not report:
        return []

    summary = []
    for ts in report.get("table_stats", []):
        summary.append({
            "name": ts["name"],
            "rows": ts["row_count"],
            "fields": ts["field_count"],
            "enums": len(ts.get("enum_fields", [])),
            "flags": len(ts.get("flag_fields", [])),
            "fks": len(ts.get("foreign_keys", [])),
            "strings": len(ts.get("string_fields", [])),
            "format": ts.get("format", "?"),
        })

    return summary
