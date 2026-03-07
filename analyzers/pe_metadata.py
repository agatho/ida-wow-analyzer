"""
PE Metadata Intelligence Extractor

Extracts low-level PE structural intelligence that IDA does not surface in its
standard analysis: exception tables (.pdata / .xdata unwind info), Control Flow
Guard (CFG) target tables, Load Config directory details, debug directory entries
(CodeView PDB info, POGO profile-guided layout data), TLS callback arrays, and
full section-level characteristics with entropy.

Key capabilities:
  - Discovers functions IDA missed by diffing .pdata RUNTIME_FUNCTION entries
    against IDA's function database
  - Identifies all indirect-call-valid targets from CFG tables and correlates
    them with known vtable entries to separate virtual-dispatch targets from
    standalone callback / function-pointer targets
  - Recovers original .obj file groupings from POGO (Profile Guided Optimization)
    debug data, enabling source-file-level provenance recovery
  - Parses TLS callbacks that execute before main() — critical for anti-tamper
    and initialization analysis
  - Computes per-section entropy to flag packed or encrypted regions

Results are stored in the knowledge DB under kv_store key "pe_metadata".
"""

import json
import math
import re
import struct
import time
from collections import defaultdict

import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import idautils
import idaapi
import idc

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error, ea_str


# ---------------------------------------------------------------------------
# PE structure constants
# ---------------------------------------------------------------------------

IMAGE_DOS_SIGNATURE = 0x5A4D          # "MZ"
IMAGE_NT_SIGNATURE = 0x00004550       # "PE\0\0"

# Optional header magic
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B

# Machine types
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

MACHINE_NAMES = {
    IMAGE_FILE_MACHINE_I386: "x86",
    IMAGE_FILE_MACHINE_AMD64: "x64",
    IMAGE_FILE_MACHINE_ARM64: "ARM64",
}

# DLL Characteristics bit flags
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040     # ASLR
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100        # DEP
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000          # CFG
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000

DLL_CHAR_FLAGS = {
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: "HIGH_ENTROPY_VA",
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: "ASLR",
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: "FORCE_INTEGRITY",
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT: "DEP",
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: "NO_ISOLATION",
    IMAGE_DLLCHARACTERISTICS_NO_SEH: "NO_SEH",
    IMAGE_DLLCHARACTERISTICS_NO_BIND: "NO_BIND",
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER: "APPCONTAINER",
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: "WDM_DRIVER",
    IMAGE_DLLCHARACTERISTICS_GUARD_CF: "GUARD_CF",
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: "TERMINAL_SERVER_AWARE",
}

# Data directory indices
IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

# Debug types
IMAGE_DEBUG_TYPE_UNKNOWN = 0
IMAGE_DEBUG_TYPE_COFF = 1
IMAGE_DEBUG_TYPE_CODEVIEW = 2
IMAGE_DEBUG_TYPE_FPO = 3
IMAGE_DEBUG_TYPE_MISC = 4
IMAGE_DEBUG_TYPE_EXCEPTION = 5
IMAGE_DEBUG_TYPE_FIXUP = 6
IMAGE_DEBUG_TYPE_BORLAND = 9
IMAGE_DEBUG_TYPE_REPRO = 16
IMAGE_DEBUG_TYPE_POGO = 13
IMAGE_DEBUG_TYPE_ILTCG = 14
IMAGE_DEBUG_TYPE_MPX = 15
IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20

DEBUG_TYPE_NAMES = {
    IMAGE_DEBUG_TYPE_UNKNOWN: "UNKNOWN",
    IMAGE_DEBUG_TYPE_COFF: "COFF",
    IMAGE_DEBUG_TYPE_CODEVIEW: "CODEVIEW",
    IMAGE_DEBUG_TYPE_FPO: "FPO",
    IMAGE_DEBUG_TYPE_MISC: "MISC",
    IMAGE_DEBUG_TYPE_EXCEPTION: "EXCEPTION",
    IMAGE_DEBUG_TYPE_FIXUP: "FIXUP",
    IMAGE_DEBUG_TYPE_BORLAND: "BORLAND",
    IMAGE_DEBUG_TYPE_POGO: "POGO",
    IMAGE_DEBUG_TYPE_ILTCG: "ILTCG",
    IMAGE_DEBUG_TYPE_MPX: "MPX",
    IMAGE_DEBUG_TYPE_REPRO: "REPRO",
    IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS: "EX_DLLCHARACTERISTICS",
}

# Section characteristics
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# UNWIND_INFO flags
UNW_FLAG_NHANDLER = 0x0
UNW_FLAG_EHANDLER = 0x1
UNW_FLAG_UHANDLER = 0x2
UNW_FLAG_CHAININFO = 0x4

# UNWIND_CODE operations
UWOP_PUSH_NONVOL = 0
UWOP_ALLOC_LARGE = 1
UWOP_ALLOC_SMALL = 2
UWOP_SET_FPREG = 3
UWOP_SAVE_NONVOL = 4
UWOP_SAVE_NONVOL_FAR = 5
UWOP_EPILOG = 6
UWOP_SPARE_CODE = 7
UWOP_SAVE_XMM128 = 8
UWOP_SAVE_XMM128_FAR = 9
UWOP_PUSH_MACHFRAME = 10

UWOP_NAMES = {
    UWOP_PUSH_NONVOL: "PUSH_NONVOL",
    UWOP_ALLOC_LARGE: "ALLOC_LARGE",
    UWOP_ALLOC_SMALL: "ALLOC_SMALL",
    UWOP_SET_FPREG: "SET_FPREG",
    UWOP_SAVE_NONVOL: "SAVE_NONVOL",
    UWOP_SAVE_NONVOL_FAR: "SAVE_NONVOL_FAR",
    UWOP_EPILOG: "EPILOG",
    UWOP_SPARE_CODE: "SPARE_CODE",
    UWOP_SAVE_XMM128: "SAVE_XMM128",
    UWOP_SAVE_XMM128_FAR: "SAVE_XMM128_FAR",
    UWOP_PUSH_MACHFRAME: "PUSH_MACHFRAME",
}

# x64 register names for unwind info
UNWIND_REGISTER_NAMES = {
    0: "RAX", 1: "RCX", 2: "RDX", 3: "RBX",
    4: "RSP", 5: "RBP", 6: "RSI", 7: "RDI",
    8: "R8",  9: "R9",  10: "R10", 11: "R11",
    12: "R12", 13: "R13", 14: "R14", 15: "R15",
}

# Guard flags from Load Config
IMAGE_GUARD_CF_INSTRUMENTED = 0x00000100
IMAGE_GUARD_CFW_INSTRUMENTED = 0x00000200
IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x00000400
IMAGE_GUARD_SECURITY_COOKIE_UNUSED = 0x00000800
IMAGE_GUARD_PROTECT_DELAYLOAD_IAT = 0x00001000
IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 0x00002000
IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT = 0x00004000
IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION = 0x00008000
IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT = 0x00010000
IMAGE_GUARD_RF_INSTRUMENTED = 0x00020000
IMAGE_GUARD_RF_ENABLE = 0x00040000
IMAGE_GUARD_RF_STRICT = 0x00080000
IMAGE_GUARD_RETPOLINE_PRESENT = 0x00100000
IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT = 0x00400000
IMAGE_GUARD_XFG_ENABLED = 0x00800000

GUARD_FLAG_NAMES = {
    IMAGE_GUARD_CF_INSTRUMENTED: "CF_INSTRUMENTED",
    IMAGE_GUARD_CFW_INSTRUMENTED: "CFW_INSTRUMENTED",
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: "CF_FUNCTION_TABLE_PRESENT",
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED: "SECURITY_COOKIE_UNUSED",
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT: "PROTECT_DELAYLOAD_IAT",
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION: "DELAYLOAD_IAT_OWN_SECTION",
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT: "CF_EXPORT_SUPPRESSION_INFO",
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION: "CF_ENABLE_EXPORT_SUPPRESSION",
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT: "CF_LONGJUMP_TABLE",
    IMAGE_GUARD_RF_INSTRUMENTED: "RF_INSTRUMENTED",
    IMAGE_GUARD_RF_ENABLE: "RF_ENABLE",
    IMAGE_GUARD_RF_STRICT: "RF_STRICT",
    IMAGE_GUARD_RETPOLINE_PRESENT: "RETPOLINE_PRESENT",
    IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT: "EH_CONTINUATION_TABLE",
    IMAGE_GUARD_XFG_ENABLED: "XFG_ENABLED",
}

# CodeView signature
CV_SIGNATURE_RSDS = 0x53445352   # "RSDS"
CV_SIGNATURE_NB10 = 0x3031424E   # "NB10"

# POGO signature
POGO_SIGNATURE_LTCG = 0x4C544347  # "LTCG"
POGO_SIGNATURE_PGU  = 0x50475500  # "PGU\0"


# ---------------------------------------------------------------------------
# IDB byte reading helpers
# ---------------------------------------------------------------------------

def _read_byte(ea):
    """Read a single byte from the IDB."""
    return ida_bytes.get_byte(ea)


def _read_word(ea):
    """Read a 16-bit little-endian word from the IDB."""
    return ida_bytes.get_word(ea)


def _read_dword(ea):
    """Read a 32-bit little-endian dword from the IDB."""
    return ida_bytes.get_dword(ea)


def _read_qword(ea):
    """Read a 64-bit little-endian qword from the IDB."""
    return ida_bytes.get_qword(ea)


def _read_bytes(ea, size):
    """Read a block of bytes from the IDB. Returns bytes object."""
    return ida_bytes.get_bytes(ea, size)


def _read_cstring(ea, max_len=1024):
    """Read a null-terminated C string from the IDB."""
    result = []
    for i in range(max_len):
        b = ida_bytes.get_byte(ea + i)
        if b == 0:
            break
        result.append(b)
    return bytes(result).decode("utf-8", errors="replace")


def _read_guid(ea):
    """Read a 16-byte GUID from the IDB and format as standard GUID string."""
    raw = _read_bytes(ea, 16)
    if raw is None or len(raw) < 16:
        return None
    # GUID layout: Data1(4) Data2(2) Data3(2) Data4(8)
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    d4 = raw[8:16]
    return (
        f"{d1:08X}-{d2:04X}-{d3:04X}-"
        f"{d4[0]:02X}{d4[1]:02X}-"
        f"{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}"
    )


# ---------------------------------------------------------------------------
# Section entropy calculation
# ---------------------------------------------------------------------------

def _compute_entropy(ea, size, sample_size=65536):
    """Compute Shannon entropy for a memory region.

    Samples up to *sample_size* bytes to avoid extremely slow reads on
    multi-hundred-MB sections.  Returns a float in [0.0, 8.0].
    """
    if size <= 0:
        return 0.0
    actual_size = min(size, sample_size)
    raw = _read_bytes(ea, actual_size)
    if raw is None or len(raw) == 0:
        return 0.0
    freq = [0] * 256
    for b in raw:
        freq[b] += 1
    total = len(raw)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# ---------------------------------------------------------------------------
# PE header parsing
# ---------------------------------------------------------------------------

def _parse_pe_header(image_base):
    """Parse DOS/PE/Optional headers and return a structured dict.

    Returns ``(header_info, data_dirs, section_headers)`` or ``(None, None, None)``
    on failure.  *data_dirs* is a list of ``(rva, size)`` tuples indexed by
    directory entry constant.  *section_headers* is a list of dicts.
    """
    # DOS header
    dos_sig = _read_word(image_base)
    if dos_sig != IMAGE_DOS_SIGNATURE:
        msg_error(f"Invalid DOS signature at {ea_str(image_base)}: 0x{dos_sig:04X}")
        return None, None, None

    e_lfanew = _read_dword(image_base + 0x3C)
    pe_ea = image_base + e_lfanew

    # PE signature
    pe_sig = _read_dword(pe_ea)
    if pe_sig != IMAGE_NT_SIGNATURE:
        msg_error(f"Invalid PE signature at {ea_str(pe_ea)}: 0x{pe_sig:08X}")
        return None, None, None

    # COFF header (20 bytes starting at pe_ea + 4)
    coff_ea = pe_ea + 4
    machine = _read_word(coff_ea + 0)
    num_sections = _read_word(coff_ea + 2)
    timestamp = _read_dword(coff_ea + 4)
    ptr_symbol_table = _read_dword(coff_ea + 8)
    num_symbols = _read_dword(coff_ea + 12)
    size_optional_header = _read_word(coff_ea + 16)
    characteristics = _read_word(coff_ea + 18)

    # Optional header
    opt_ea = coff_ea + 20
    opt_magic = _read_word(opt_ea)
    is_pe64 = (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)

    if is_pe64:
        # PE32+ optional header
        major_linker = _read_byte(opt_ea + 2)
        minor_linker = _read_byte(opt_ea + 3)
        size_of_code = _read_dword(opt_ea + 4)
        size_of_init_data = _read_dword(opt_ea + 8)
        size_of_uninit_data = _read_dword(opt_ea + 12)
        entry_point_rva = _read_dword(opt_ea + 16)
        base_of_code = _read_dword(opt_ea + 20)
        image_base_field = _read_qword(opt_ea + 24)
        section_alignment = _read_dword(opt_ea + 32)
        file_alignment = _read_dword(opt_ea + 36)
        major_os_version = _read_word(opt_ea + 40)
        minor_os_version = _read_word(opt_ea + 42)
        major_image_version = _read_word(opt_ea + 44)
        minor_image_version = _read_word(opt_ea + 46)
        major_subsys_version = _read_word(opt_ea + 48)
        minor_subsys_version = _read_word(opt_ea + 50)
        win32_version_value = _read_dword(opt_ea + 52)
        size_of_image = _read_dword(opt_ea + 56)
        size_of_headers = _read_dword(opt_ea + 60)
        checksum = _read_dword(opt_ea + 64)
        subsystem = _read_word(opt_ea + 68)
        dll_characteristics = _read_word(opt_ea + 70)
        # Stack/heap sizes are qwords in PE32+
        size_of_stack_reserve = _read_qword(opt_ea + 72)
        size_of_stack_commit = _read_qword(opt_ea + 80)
        size_of_heap_reserve = _read_qword(opt_ea + 88)
        size_of_heap_commit = _read_qword(opt_ea + 96)
        loader_flags = _read_dword(opt_ea + 104)
        number_of_rva_and_sizes = _read_dword(opt_ea + 108)
        data_dir_ea = opt_ea + 112
    else:
        # PE32 optional header
        major_linker = _read_byte(opt_ea + 2)
        minor_linker = _read_byte(opt_ea + 3)
        size_of_code = _read_dword(opt_ea + 4)
        size_of_init_data = _read_dword(opt_ea + 8)
        size_of_uninit_data = _read_dword(opt_ea + 12)
        entry_point_rva = _read_dword(opt_ea + 16)
        base_of_code = _read_dword(opt_ea + 20)
        image_base_field = _read_dword(opt_ea + 28)  # base_of_data at +24
        section_alignment = _read_dword(opt_ea + 32)
        file_alignment = _read_dword(opt_ea + 36)
        major_os_version = _read_word(opt_ea + 40)
        minor_os_version = _read_word(opt_ea + 42)
        major_image_version = _read_word(opt_ea + 44)
        minor_image_version = _read_word(opt_ea + 46)
        major_subsys_version = _read_word(opt_ea + 48)
        minor_subsys_version = _read_word(opt_ea + 50)
        win32_version_value = _read_dword(opt_ea + 52)
        size_of_image = _read_dword(opt_ea + 56)
        size_of_headers = _read_dword(opt_ea + 60)
        checksum = _read_dword(opt_ea + 64)
        subsystem = _read_word(opt_ea + 68)
        dll_characteristics = _read_word(opt_ea + 70)
        # Stack/heap sizes are dwords in PE32
        size_of_stack_reserve = _read_dword(opt_ea + 72)
        size_of_stack_commit = _read_dword(opt_ea + 76)
        size_of_heap_reserve = _read_dword(opt_ea + 80)
        size_of_heap_commit = _read_dword(opt_ea + 84)
        loader_flags = _read_dword(opt_ea + 88)
        number_of_rva_and_sizes = _read_dword(opt_ea + 92)
        data_dir_ea = opt_ea + 96

    # Decode DLL characteristics flags
    dll_char_names = []
    for bit, name in DLL_CHAR_FLAGS.items():
        if dll_characteristics & bit:
            dll_char_names.append(name)

    # Subsystem name
    subsystem_names = {
        1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
        5: "OS2_CUI", 7: "POSIX_CUI", 8: "NATIVE_WINDOWS",
        9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION",
        11: "EFI_BOOT_SERVICE_DRIVER", 12: "EFI_RUNTIME_DRIVER",
        13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION",
    }

    header_info = {
        "machine": machine,
        "machine_name": MACHINE_NAMES.get(machine, f"UNKNOWN(0x{machine:04X})"),
        "is_pe64": is_pe64,
        "number_of_sections": num_sections,
        "timestamp": timestamp,
        "timestamp_hex": f"0x{timestamp:08X}",
        "characteristics": characteristics,
        "linker_version": f"{major_linker}.{minor_linker}",
        "size_of_code": size_of_code,
        "entry_point_rva": entry_point_rva,
        "image_base": image_base_field,
        "image_base_hex": f"0x{image_base_field:X}",
        "section_alignment": section_alignment,
        "file_alignment": file_alignment,
        "os_version": f"{major_os_version}.{minor_os_version}",
        "image_version": f"{major_image_version}.{minor_image_version}",
        "subsystem_version": f"{major_subsys_version}.{minor_subsys_version}",
        "size_of_image": size_of_image,
        "size_of_headers": size_of_headers,
        "checksum": checksum,
        "checksum_hex": f"0x{checksum:08X}",
        "subsystem": subsystem,
        "subsystem_name": subsystem_names.get(subsystem, f"UNKNOWN({subsystem})"),
        "dll_characteristics": dll_characteristics,
        "dll_characteristics_hex": f"0x{dll_characteristics:04X}",
        "dll_characteristics_flags": dll_char_names,
        "size_of_stack_reserve": size_of_stack_reserve,
        "size_of_heap_reserve": size_of_heap_reserve,
        "number_of_rva_and_sizes": number_of_rva_and_sizes,
    }

    # Parse data directories
    data_dirs = []
    for i in range(min(number_of_rva_and_sizes, 16)):
        dd_rva = _read_dword(data_dir_ea + i * 8)
        dd_size = _read_dword(data_dir_ea + i * 8 + 4)
        data_dirs.append((dd_rva, dd_size))

    # Parse section headers
    sections_ea = data_dir_ea + number_of_rva_and_sizes * 8
    section_headers = []
    for i in range(num_sections):
        sec_ea = sections_ea + i * 40
        name_bytes = _read_bytes(sec_ea, 8)
        if name_bytes is None:
            continue
        sec_name = name_bytes.split(b'\x00')[0].decode("utf-8", errors="replace")
        virtual_size = _read_dword(sec_ea + 8)
        virtual_address = _read_dword(sec_ea + 12)
        raw_size = _read_dword(sec_ea + 16)
        raw_offset = _read_dword(sec_ea + 20)
        ptr_relocations = _read_dword(sec_ea + 24)
        ptr_linenumbers = _read_dword(sec_ea + 28)
        num_relocations = _read_word(sec_ea + 32)
        num_linenumbers = _read_word(sec_ea + 34)
        sec_characteristics = _read_dword(sec_ea + 36)

        section_headers.append({
            "name": sec_name,
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": raw_size,
            "raw_offset": raw_offset,
            "characteristics": sec_characteristics,
        })

    return header_info, data_dirs, section_headers


# ---------------------------------------------------------------------------
# Section analysis with entropy
# ---------------------------------------------------------------------------

def _analyze_sections(image_base, section_headers):
    """Analyze each PE section: map to IDA segments, compute entropy, flag
    suspicious properties.  Returns a list of section info dicts."""
    results = []

    for sec in section_headers:
        sec_ea = image_base + sec["virtual_address"]
        chars = sec["characteristics"]

        is_code = bool(chars & IMAGE_SCN_CNT_CODE)
        is_exec = bool(chars & IMAGE_SCN_MEM_EXECUTE)
        is_read = bool(chars & IMAGE_SCN_MEM_READ)
        is_write = bool(chars & IMAGE_SCN_MEM_WRITE)
        is_init_data = bool(chars & IMAGE_SCN_CNT_INITIALIZED_DATA)
        is_uninit_data = bool(chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA)

        # Build permissions string
        perms = ""
        if is_read:
            perms += "R"
        if is_write:
            perms += "W"
        if is_exec:
            perms += "X"

        # Suspicious: writable + executable
        is_suspicious = is_write and is_exec

        # Compute entropy on the virtual content
        vsize = sec["virtual_size"]
        entropy = _compute_entropy(sec_ea, vsize)

        # Map to IDA segment
        ida_seg = ida_segment.getseg(sec_ea)
        ida_seg_name = ""
        if ida_seg:
            ida_seg_name = ida_segment.get_segm_name(ida_seg)

        results.append({
            "name": sec["name"],
            "va": sec["virtual_address"],
            "va_hex": f"0x{sec['virtual_address']:X}",
            "ea": sec_ea,
            "ea_hex": ea_str(sec_ea),
            "vsize": vsize,
            "rawsize": sec["raw_size"],
            "characteristics": chars,
            "characteristics_hex": f"0x{chars:08X}",
            "permissions": perms,
            "is_code": is_code,
            "is_writable_executable": is_suspicious,
            "entropy": entropy,
            "ida_segment_name": ida_seg_name,
        })

    return results


# ---------------------------------------------------------------------------
# Exception table (.pdata) parsing
# ---------------------------------------------------------------------------

def _parse_exception_table(image_base, data_dirs, is_pe64):
    """Parse .pdata exception directory (RUNTIME_FUNCTION entries) and their
    associated UNWIND_INFO structures.

    Returns ``(entries_list, ida_missed_list, total_count)``.
    """
    if IMAGE_DIRECTORY_ENTRY_EXCEPTION >= len(data_dirs):
        msg_warn("No exception directory entry in data directories")
        return [], [], 0

    exc_rva, exc_size = data_dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
    if exc_rva == 0 or exc_size == 0:
        msg_warn("Exception directory is empty")
        return [], [], 0

    exc_ea = image_base + exc_rva
    msg_info(f"Exception directory at {ea_str(exc_ea)}, size {exc_size} bytes")

    if not is_pe64:
        msg_warn("Exception table parsing only supported for x64 PE")
        return [], [], 0

    # Each RUNTIME_FUNCTION is 12 bytes: begin_rva(4), end_rva(4), unwind_info_rva(4)
    entry_size = 12
    num_entries = exc_size // entry_size

    msg_info(f"Parsing {num_entries} RUNTIME_FUNCTION entries...")

    # Build IDA function set for comparison
    ida_func_starts = set()
    for func_ea in idautils.Functions():
        ida_func_starts.add(func_ea)

    entries = []
    ida_missed = []
    seh_count = 0
    parse_errors = 0

    # Process entries in batches to manage output
    progress_interval = max(1, num_entries // 20)

    for i in range(num_entries):
        entry_ea = exc_ea + i * entry_size

        begin_rva = _read_dword(entry_ea)
        end_rva = _read_dword(entry_ea + 4)
        unwind_info_rva = _read_dword(entry_ea + 8)

        if begin_rva == 0 and end_rva == 0:
            continue

        func_ea = image_base + begin_rva
        func_end_ea = image_base + end_rva
        func_size = end_rva - begin_rva

        # Parse UNWIND_INFO
        unwind_ea = image_base + unwind_info_rva
        unwind_data = _parse_unwind_info(image_base, unwind_ea)

        has_seh = False
        if unwind_data:
            has_seh = unwind_data.get("has_handler", False)
            if has_seh:
                seh_count += 1

        entry_info = {
            "begin_rva": begin_rva,
            "begin_rva_hex": f"0x{begin_rva:X}",
            "end_rva": end_rva,
            "end_rva_hex": f"0x{end_rva:X}",
            "size": func_size,
            "has_seh": has_seh,
        }

        if unwind_data:
            entry_info["frame_size"] = unwind_data.get("frame_size", 0)
            entry_info["saved_regs"] = unwind_data.get("saved_regs", [])
            entry_info["prolog_size"] = unwind_data.get("size_of_prolog", 0)
            entry_info["frame_register"] = unwind_data.get("frame_register", "")
            entry_info["frame_offset"] = unwind_data.get("frame_offset", 0)
            entry_info["chained"] = unwind_data.get("chained", False)

        entries.append(entry_info)

        # Check if IDA missed this function
        if func_ea not in ida_func_starts:
            ida_missed.append({
                "rva": begin_rva,
                "rva_hex": f"0x{begin_rva:X}",
                "ea": func_ea,
                "ea_hex": ea_str(func_ea),
                "size": func_size,
            })

        if (i + 1) % progress_interval == 0:
            msg(f"  .pdata progress: {i + 1}/{num_entries} "
                f"({(i + 1) * 100 // num_entries}%)")

    msg_info(f"Parsed {len(entries)} RUNTIME_FUNCTION entries, "
             f"{seh_count} with SEH handlers, "
             f"{len(ida_missed)} functions IDA missed")

    return entries, ida_missed, len(entries)


def _parse_unwind_info(image_base, unwind_ea):
    """Parse an x64 UNWIND_INFO structure at the given EA.

    Layout (packed):
      byte 0: Version:3 | Flags:5
      byte 1: SizeOfProlog
      byte 2: CountOfCodes
      byte 3: FrameRegister:4 | FrameOffset:4
      then: UNWIND_CODE array[CountOfCodes]
      then (if flags have EHANDLER/UHANDLER): handler RVA + data
      then (if flags have CHAININFO): chained RUNTIME_FUNCTION

    Returns a dict with parsed data, or None on failure.
    """
    try:
        ver_flags = _read_byte(unwind_ea)
    except Exception:
        return None

    version = ver_flags & 0x07
    flags = (ver_flags >> 3) & 0x1F

    if version > 2:
        # Unknown unwind version
        return None

    size_of_prolog = _read_byte(unwind_ea + 1)
    count_of_codes = _read_byte(unwind_ea + 2)
    frame_reg_offset = _read_byte(unwind_ea + 3)
    frame_register = frame_reg_offset & 0x0F
    frame_offset = (frame_reg_offset >> 4) & 0x0F

    # Parse unwind codes to compute stack frame size and saved registers
    saved_regs = []
    frame_size = 0
    codes_ea = unwind_ea + 4

    i = 0
    while i < count_of_codes:
        code_ea = codes_ea + i * 2
        code_offset = _read_byte(code_ea)
        code_info = _read_byte(code_ea + 1)

        op = code_info & 0x0F
        op_info = (code_info >> 4) & 0x0F

        if op == UWOP_PUSH_NONVOL:
            reg_name = UNWIND_REGISTER_NAMES.get(op_info, f"REG{op_info}")
            saved_regs.append(reg_name)
            frame_size += 8  # Each push is 8 bytes on x64
            i += 1

        elif op == UWOP_ALLOC_LARGE:
            if op_info == 0:
                # Next slot is allocation size / 8 (16-bit)
                if i + 1 < count_of_codes:
                    alloc = _read_word(codes_ea + (i + 1) * 2) * 8
                    frame_size += alloc
                i += 2
            else:
                # Next two slots are full 32-bit size
                if i + 2 < count_of_codes:
                    alloc = _read_dword(codes_ea + (i + 1) * 2)
                    frame_size += alloc
                i += 3

        elif op == UWOP_ALLOC_SMALL:
            alloc = (op_info * 8) + 8
            frame_size += alloc
            i += 1

        elif op == UWOP_SET_FPREG:
            # Frame pointer established
            i += 1

        elif op == UWOP_SAVE_NONVOL:
            reg_name = UNWIND_REGISTER_NAMES.get(op_info, f"REG{op_info}")
            saved_regs.append(reg_name)
            i += 2  # Next slot has offset / 8

        elif op == UWOP_SAVE_NONVOL_FAR:
            reg_name = UNWIND_REGISTER_NAMES.get(op_info, f"REG{op_info}")
            saved_regs.append(reg_name)
            i += 3  # Next two slots have full 32-bit offset

        elif op == UWOP_EPILOG:
            i += 1  # Epilog descriptor (Win10+)

        elif op == UWOP_SPARE_CODE:
            i += 2  # Reserved

        elif op == UWOP_SAVE_XMM128:
            saved_regs.append(f"XMM{op_info}")
            i += 2  # Next slot has offset / 16

        elif op == UWOP_SAVE_XMM128_FAR:
            saved_regs.append(f"XMM{op_info}")
            i += 3  # Next two slots have full 32-bit offset

        elif op == UWOP_PUSH_MACHFRAME:
            frame_size += 40 if op_info else 32  # Machine frame with/without error code
            i += 1

        else:
            # Unknown op, skip one slot
            i += 1

    # Determine if there is a handler or chain
    has_handler = bool(flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))
    chained = bool(flags & UNW_FLAG_CHAININFO)

    handler_rva = 0
    if has_handler:
        # Handler RVA follows the unwind code array (aligned to DWORD)
        handler_offset = 4 + count_of_codes * 2
        if handler_offset % 4 != 0:
            handler_offset += 2  # Align to 4 bytes
        handler_rva = _read_dword(unwind_ea + handler_offset)

    return {
        "version": version,
        "flags": flags,
        "size_of_prolog": size_of_prolog,
        "count_of_codes": count_of_codes,
        "frame_register": UNWIND_REGISTER_NAMES.get(frame_register, "") if frame_register != 0 else "",
        "frame_offset": frame_offset * 16,  # Offset is in units of 16 bytes
        "saved_regs": saved_regs,
        "frame_size": frame_size,
        "has_handler": has_handler,
        "handler_rva": handler_rva,
        "chained": chained,
    }


# ---------------------------------------------------------------------------
# Control Flow Guard (CFG) table parsing
# ---------------------------------------------------------------------------

def _parse_cfg_tables(image_base, data_dirs, is_pe64, vtable_rvas):
    """Parse CFG function table from Load Config Directory.

    The Load Config contains:
      - GuardCFCheckFunctionPointer
      - GuardCFDispatchFunctionPointer
      - GuardCFFunctionTable (array of RVAs for valid indirect call targets)
      - GuardCFFunctionCount

    Cross-references each CFG entry against *vtable_rvas* to classify targets.

    Returns ``(cfg_targets, cfg_unresolved, load_config_info, total_count)``.
    """
    if IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG >= len(data_dirs):
        msg_warn("No Load Config directory entry")
        return [], [], {}, 0

    lc_rva, lc_size = data_dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
    if lc_rva == 0:
        msg_warn("Load Config directory RVA is zero")
        return [], [], {}, 0

    lc_ea = image_base + lc_rva
    msg_info(f"Load Config directory at {ea_str(lc_ea)}, size {lc_size}")

    # Parse the Load Config structure
    # Layout depends on PE32 vs PE32+ and the structure size field
    lc_struct_size = _read_dword(lc_ea)
    msg(f"  Load Config structure size: {lc_struct_size}")

    load_config = {}

    if is_pe64:
        # IMAGE_LOAD_CONFIG_DIRECTORY64
        load_config["size"] = lc_struct_size
        load_config["time_date_stamp"] = _read_dword(lc_ea + 4)

        if lc_struct_size >= 96:
            load_config["security_cookie"] = _read_qword(lc_ea + 88)
            load_config["security_cookie_hex"] = f"0x{load_config['security_cookie']:X}"

        # GuardCFCheckFunctionPointer at offset 112
        # GuardCFDispatchFunctionPointer at offset 120
        # GuardCFFunctionTable at offset 128
        # GuardCFFunctionCount at offset 136
        # GuardFlags at offset 144
        guard_cf_check = 0
        guard_cf_dispatch = 0
        guard_cf_table = 0
        guard_cf_count = 0
        guard_flags = 0

        if lc_struct_size >= 120:
            guard_cf_check = _read_qword(lc_ea + 112)
            load_config["guard_cf_check_function_pointer"] = guard_cf_check
            load_config["guard_cf_check_function_pointer_hex"] = f"0x{guard_cf_check:X}"

        if lc_struct_size >= 128:
            guard_cf_dispatch = _read_qword(lc_ea + 120)
            load_config["guard_cf_dispatch_function_pointer"] = guard_cf_dispatch
            load_config["guard_cf_dispatch_function_pointer_hex"] = f"0x{guard_cf_dispatch:X}"

        if lc_struct_size >= 136:
            guard_cf_table = _read_qword(lc_ea + 128)
            load_config["guard_cf_function_table"] = guard_cf_table
            load_config["guard_cf_function_table_hex"] = f"0x{guard_cf_table:X}"

        if lc_struct_size >= 144:
            guard_cf_count = _read_qword(lc_ea + 136)
            load_config["guard_cf_function_count"] = guard_cf_count

        if lc_struct_size >= 148:
            guard_flags = _read_dword(lc_ea + 144)
            load_config["guard_flags"] = guard_flags
            load_config["guard_flags_hex"] = f"0x{guard_flags:08X}"

            # Decode guard flags
            flag_names = []
            for bit, name in GUARD_FLAG_NAMES.items():
                if guard_flags & bit:
                    flag_names.append(name)
            load_config["guard_flag_names"] = flag_names

        # Extended fields for newer Load Config versions
        if lc_struct_size >= 192:
            # GuardCFLongJumpTargetTable at offset 168 (PE32+)
            lj_table = _read_qword(lc_ea + 168)
            lj_count = _read_qword(lc_ea + 176)
            if lj_table != 0:
                load_config["guard_longjump_table"] = lj_table
                load_config["guard_longjump_table_hex"] = f"0x{lj_table:X}"
                load_config["guard_longjump_count"] = lj_count

        # Volatile metadata pointer (offset varies by version)
        if lc_struct_size >= 232:
            volatile_meta = _read_qword(lc_ea + 224)
            if volatile_meta != 0:
                load_config["volatile_metadata_pointer"] = volatile_meta
                load_config["volatile_metadata_pointer_hex"] = f"0x{volatile_meta:X}"

        # Enclave config pointer
        if lc_struct_size >= 216:
            enclave_cfg = _read_qword(lc_ea + 208)
            if enclave_cfg != 0:
                load_config["enclave_config_pointer"] = enclave_cfg
                load_config["enclave_config_pointer_hex"] = f"0x{enclave_cfg:X}"

        # EH continuation table
        if lc_struct_size >= 256:
            eh_cont_table = _read_qword(lc_ea + 240)
            eh_cont_count = _read_qword(lc_ea + 248)
            if eh_cont_table != 0:
                load_config["eh_continuation_table"] = eh_cont_table
                load_config["eh_continuation_table_hex"] = f"0x{eh_cont_table:X}"
                load_config["eh_continuation_count"] = eh_cont_count

    else:
        # IMAGE_LOAD_CONFIG_DIRECTORY32
        load_config["size"] = lc_struct_size
        load_config["time_date_stamp"] = _read_dword(lc_ea + 4)

        if lc_struct_size >= 64:
            load_config["security_cookie"] = _read_dword(lc_ea + 60)
            load_config["security_cookie_hex"] = f"0x{load_config['security_cookie']:X}"

        guard_cf_check = 0
        guard_cf_dispatch = 0
        guard_cf_table = 0
        guard_cf_count = 0
        guard_flags = 0

        if lc_struct_size >= 76:
            guard_cf_check = _read_dword(lc_ea + 68)
            load_config["guard_cf_check_function_pointer"] = guard_cf_check

        if lc_struct_size >= 80:
            guard_cf_dispatch = _read_dword(lc_ea + 72)
            load_config["guard_cf_dispatch_function_pointer"] = guard_cf_dispatch

        if lc_struct_size >= 84:
            guard_cf_table = _read_dword(lc_ea + 76)
            load_config["guard_cf_function_table"] = guard_cf_table

        if lc_struct_size >= 88:
            guard_cf_count = _read_dword(lc_ea + 80)
            load_config["guard_cf_function_count"] = guard_cf_count

        if lc_struct_size >= 92:
            guard_flags = _read_dword(lc_ea + 84)
            load_config["guard_flags"] = guard_flags
            flag_names = []
            for bit, name in GUARD_FLAG_NAMES.items():
                if guard_flags & bit:
                    flag_names.append(name)
            load_config["guard_flag_names"] = flag_names

    # Parse the CFG function table
    cfg_targets = []
    cfg_unresolved = []

    if guard_cf_table != 0 and guard_cf_count > 0:
        msg_info(f"Parsing CFG function table: {guard_cf_count} entries "
                 f"at {ea_str(guard_cf_table)}")

        # Determine stride: each entry is a 4-byte RVA, optionally followed
        # by metadata bytes when certain guard flags indicate extended entries.
        # The low 4 bits of GuardFlags encode (stride - 1) in bits [28:31]
        # of the GuardFlags field when CF_FUNCTION_TABLE_PRESENT is set.
        stride = 4
        if guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT:
            # Extract stride from bits [28:31] of guard_flags
            extra = (guard_flags >> 28) & 0x0F
            stride = 4 + extra

        progress_interval = max(1, guard_cf_count // 10)

        for i in range(guard_cf_count):
            entry_ea = guard_cf_table + i * stride
            target_rva = _read_dword(entry_ea)

            if target_rva == 0:
                continue

            target_ea = image_base + target_rva
            func_name = ida_name.get_name(target_ea)
            if not func_name:
                func_name = ""

            # Classify: is this RVA in a known vtable?
            is_vtable_member = target_rva in vtable_rvas
            is_callback = False

            # If it has a name suggesting callback/handler pattern
            if func_name and not is_vtable_member:
                name_lower = func_name.lower()
                if any(pat in name_lower for pat in
                       ("callback", "handler", "hook", "notify",
                        "timer_proc", "wndproc", "dlgproc", "threadproc",
                        "completion", "apc_routine")):
                    is_callback = True

            target_info = {
                "rva": target_rva,
                "rva_hex": f"0x{target_rva:X}",
                "function_name": func_name,
                "is_vtable_member": is_vtable_member,
                "is_callback": is_callback,
            }
            cfg_targets.append(target_info)

            # Track unresolved: not in any known category
            if not is_vtable_member and not is_callback and not func_name:
                cfg_unresolved.append({
                    "rva": target_rva,
                    "rva_hex": f"0x{target_rva:X}",
                })

            if (i + 1) % progress_interval == 0:
                msg(f"  CFG progress: {i + 1}/{guard_cf_count} "
                    f"({(i + 1) * 100 // guard_cf_count}%)")

        msg_info(f"Parsed {len(cfg_targets)} CFG targets, "
                 f"{sum(1 for t in cfg_targets if t['is_vtable_member'])} vtable members, "
                 f"{sum(1 for t in cfg_targets if t['is_callback'])} callbacks, "
                 f"{len(cfg_unresolved)} unresolved")
    else:
        msg_warn("No CFG function table found or count is zero")

    return cfg_targets, cfg_unresolved, load_config, len(cfg_targets)


# ---------------------------------------------------------------------------
# Debug directory parsing
# ---------------------------------------------------------------------------

def _parse_debug_directory(image_base, data_dirs):
    """Parse the debug directory and extract CodeView PDB info, POGO data,
    and other debug entries.

    Returns a dict with debug information.
    """
    if IMAGE_DIRECTORY_ENTRY_DEBUG >= len(data_dirs):
        msg_warn("No debug directory entry")
        return {}

    dbg_rva, dbg_size = data_dirs[IMAGE_DIRECTORY_ENTRY_DEBUG]
    if dbg_rva == 0 or dbg_size == 0:
        msg_warn("Debug directory is empty")
        return {}

    dbg_ea = image_base + dbg_rva
    msg_info(f"Debug directory at {ea_str(dbg_ea)}, size {dbg_size}")

    # Each IMAGE_DEBUG_DIRECTORY entry is 28 bytes
    entry_size = 28
    num_entries = dbg_size // entry_size

    debug_info = {
        "entries": [],
        "pdb_path": "",
        "pdb_guid": "",
        "pdb_age": 0,
        "pogo_sections": [],
    }

    for i in range(num_entries):
        entry_ea = dbg_ea + i * entry_size

        dd_characteristics = _read_dword(entry_ea + 0)
        dd_timestamp = _read_dword(entry_ea + 4)
        dd_major_version = _read_word(entry_ea + 8)
        dd_minor_version = _read_word(entry_ea + 10)
        dd_type = _read_dword(entry_ea + 12)
        dd_size_of_data = _read_dword(entry_ea + 16)
        dd_address_of_raw_data = _read_dword(entry_ea + 20)  # RVA
        dd_pointer_to_raw_data = _read_dword(entry_ea + 24)  # File offset

        type_name = DEBUG_TYPE_NAMES.get(dd_type, f"TYPE_{dd_type}")

        entry_info = {
            "type": dd_type,
            "type_name": type_name,
            "timestamp": dd_timestamp,
            "version": f"{dd_major_version}.{dd_minor_version}",
            "size": dd_size_of_data,
            "rva": dd_address_of_raw_data,
            "rva_hex": f"0x{dd_address_of_raw_data:X}",
        }

        # Parse CodeView (Type 2)
        if dd_type == IMAGE_DEBUG_TYPE_CODEVIEW and dd_address_of_raw_data != 0:
            cv_result = _parse_codeview(image_base, dd_address_of_raw_data,
                                        dd_size_of_data)
            if cv_result:
                debug_info["pdb_path"] = cv_result.get("pdb_path", "")
                debug_info["pdb_guid"] = cv_result.get("guid", "")
                debug_info["pdb_age"] = cv_result.get("age", 0)
                entry_info["codeview"] = cv_result

        # Parse POGO (Type 13)
        if dd_type == IMAGE_DEBUG_TYPE_POGO and dd_address_of_raw_data != 0:
            pogo_result = _parse_pogo(image_base, dd_address_of_raw_data,
                                      dd_size_of_data)
            if pogo_result:
                debug_info["pogo_sections"] = pogo_result
                entry_info["pogo_section_count"] = len(pogo_result)

        # Extended DLL Characteristics (Type 20)
        if dd_type == IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS and dd_address_of_raw_data != 0:
            ex_chars = _parse_ex_dll_characteristics(image_base,
                                                     dd_address_of_raw_data,
                                                     dd_size_of_data)
            if ex_chars:
                entry_info["ex_dll_characteristics"] = ex_chars

        debug_info["entries"].append(entry_info)

    msg_info(f"Parsed {len(debug_info['entries'])} debug directory entries")
    if debug_info["pdb_path"]:
        msg_info(f"  PDB: {debug_info['pdb_path']}")
        msg_info(f"  GUID: {debug_info['pdb_guid']}, Age: {debug_info['pdb_age']}")
    if debug_info["pogo_sections"]:
        msg_info(f"  POGO sections: {len(debug_info['pogo_sections'])}")

    return debug_info


def _parse_codeview(image_base, cv_rva, cv_size):
    """Parse a CodeView debug info record.

    Supports RSDS (CV7) format:
      Signature(4) GUID(16) Age(4) PdbFileName(variable)
    """
    cv_ea = image_base + cv_rva

    signature = _read_dword(cv_ea)

    if signature == CV_SIGNATURE_RSDS:
        # RSDS format: modern PDB reference
        guid = _read_guid(cv_ea + 4)
        age = _read_dword(cv_ea + 20)
        pdb_path = _read_cstring(cv_ea + 24, max_len=min(cv_size - 24, 512))

        return {
            "format": "RSDS",
            "guid": guid or "",
            "age": age,
            "pdb_path": pdb_path,
        }

    elif signature == CV_SIGNATURE_NB10:
        # NB10 format: older PDB reference
        offset = _read_dword(cv_ea + 4)
        timestamp = _read_dword(cv_ea + 8)
        age = _read_dword(cv_ea + 12)
        pdb_path = _read_cstring(cv_ea + 16, max_len=min(cv_size - 16, 512))

        return {
            "format": "NB10",
            "guid": "",
            "age": age,
            "timestamp": timestamp,
            "pdb_path": pdb_path,
        }

    else:
        msg_warn(f"Unknown CodeView signature: 0x{signature:08X}")
        return None


def _parse_pogo(image_base, pogo_rva, pogo_size):
    """Parse POGO (Profile Guided Optimization) debug data.

    POGO data contains a header signature followed by entries that map binary
    regions back to their original .obj file sections.  Each entry:
      RVA(4) Size(4) Name(null-terminated string, padded to 4-byte alignment)

    This data reveals the original source file / compilation unit groupings.
    """
    pogo_ea = image_base + pogo_rva

    # Read and validate signature
    pogo_sig = _read_dword(pogo_ea)

    # Known POGO signatures: "LTCG" and "PGU\0"
    if pogo_sig not in (POGO_SIGNATURE_LTCG, POGO_SIGNATURE_PGU, 0x50474900):
        # Some binaries use other signatures or have no signature at all
        # Try to parse as raw entries starting from offset 0
        sig_name = "UNKNOWN"
        entries_start = pogo_ea
        remaining = pogo_size
    else:
        sig_name = {
            POGO_SIGNATURE_LTCG: "LTCG",
            POGO_SIGNATURE_PGU: "PGU",
        }.get(pogo_sig, f"0x{pogo_sig:08X}")
        entries_start = pogo_ea + 4
        remaining = pogo_size - 4

    msg(f"  POGO signature: {sig_name}")

    sections = []
    offset = 0
    max_entries = 100000  # Safety limit

    while offset < remaining and len(sections) < max_entries:
        entry_ea = entries_start + offset

        # Need at least 8 bytes for RVA + Size
        if offset + 8 > remaining:
            break

        sec_rva = _read_dword(entry_ea)
        sec_size = _read_dword(entry_ea + 4)

        # Read null-terminated name
        name_ea = entry_ea + 8
        name = _read_cstring(name_ea, max_len=256)

        if not name:
            # Empty name likely means we've hit the end
            break

        # Advance past name + null + padding to 4-byte alignment
        name_bytes_len = len(name.encode("utf-8")) + 1  # +1 for null
        total_entry_size = 8 + name_bytes_len
        # Align to 4 bytes
        if total_entry_size % 4 != 0:
            total_entry_size += 4 - (total_entry_size % 4)

        sections.append({
            "name": name,
            "rva": sec_rva,
            "rva_hex": f"0x{sec_rva:X}",
            "size": sec_size,
        })

        offset += total_entry_size

    return sections


def _parse_ex_dll_characteristics(image_base, ex_rva, ex_size):
    """Parse Extended DLL Characteristics (Debug type 20).

    Contains a DWORD of extended flags (CET Shadow Stack, etc.).
    """
    ex_ea = image_base + ex_rva
    if ex_size < 4:
        return None

    ex_chars = _read_dword(ex_ea)

    # Known extended DLL characteristic flags
    EX_CET_COMPAT = 0x01
    EX_CET_COMPAT_STRICT = 0x02
    EX_CET_SET_CONTEXT_IP = 0x04
    EX_CET_RELAXED_MODE = 0x08

    flags = []
    if ex_chars & EX_CET_COMPAT:
        flags.append("CET_COMPAT")
    if ex_chars & EX_CET_COMPAT_STRICT:
        flags.append("CET_COMPAT_STRICT")
    if ex_chars & EX_CET_SET_CONTEXT_IP:
        flags.append("CET_SET_CONTEXT_IP")
    if ex_chars & EX_CET_RELAXED_MODE:
        flags.append("CET_RELAXED_MODE")

    return {
        "value": ex_chars,
        "value_hex": f"0x{ex_chars:08X}",
        "flags": flags,
    }


# ---------------------------------------------------------------------------
# TLS directory parsing
# ---------------------------------------------------------------------------

def _parse_tls_directory(image_base, data_dirs, is_pe64):
    """Parse the TLS directory to extract callback addresses and TLS slot info.

    IMAGE_TLS_DIRECTORY64 layout:
      StartAddressOfRawData (8)
      EndAddressOfRawData (8)
      AddressOfIndex (8)
      AddressOfCallBacks (8)  -- pointer to null-terminated array of callback VAs
      SizeOfZeroFill (4)
      Characteristics (4)

    Returns a dict with TLS information.
    """
    if IMAGE_DIRECTORY_ENTRY_TLS >= len(data_dirs):
        return {}

    tls_rva, tls_size = data_dirs[IMAGE_DIRECTORY_ENTRY_TLS]
    if tls_rva == 0:
        return {}

    tls_ea = image_base + tls_rva
    msg_info(f"TLS directory at {ea_str(tls_ea)}, size {tls_size}")

    tls_info = {}
    callbacks = []

    if is_pe64:
        tls_data_start = _read_qword(tls_ea + 0)
        tls_data_end = _read_qword(tls_ea + 8)
        tls_index_addr = _read_qword(tls_ea + 16)
        tls_callbacks_addr = _read_qword(tls_ea + 24)
        tls_zero_fill_size = _read_dword(tls_ea + 32)
        tls_characteristics = _read_dword(tls_ea + 36)

        tls_info = {
            "raw_data_start": tls_data_start,
            "raw_data_start_hex": f"0x{tls_data_start:X}",
            "raw_data_end": tls_data_end,
            "raw_data_end_hex": f"0x{tls_data_end:X}",
            "raw_data_size": tls_data_end - tls_data_start if tls_data_end > tls_data_start else 0,
            "index_address": tls_index_addr,
            "index_address_hex": f"0x{tls_index_addr:X}",
            "callbacks_address": tls_callbacks_addr,
            "callbacks_address_hex": f"0x{tls_callbacks_addr:X}",
            "zero_fill_size": tls_zero_fill_size,
            "characteristics": tls_characteristics,
        }

        # Parse callback array: null-terminated list of 64-bit VAs
        if tls_callbacks_addr != 0:
            cb_ea = tls_callbacks_addr
            max_callbacks = 256  # Safety limit
            for _ in range(max_callbacks):
                cb_func = _read_qword(cb_ea)
                if cb_func == 0:
                    break
                func_name = ida_name.get_name(cb_func)
                if not func_name:
                    func_name = ea_str(cb_func)
                callbacks.append({
                    "ea": cb_func,
                    "ea_hex": ea_str(cb_func),
                    "rva": cb_func - image_base,
                    "rva_hex": f"0x{cb_func - image_base:X}",
                    "function_name": func_name,
                })
                cb_ea += 8

    else:
        tls_data_start = _read_dword(tls_ea + 0)
        tls_data_end = _read_dword(tls_ea + 4)
        tls_index_addr = _read_dword(tls_ea + 8)
        tls_callbacks_addr = _read_dword(tls_ea + 12)
        tls_zero_fill_size = _read_dword(tls_ea + 16)
        tls_characteristics = _read_dword(tls_ea + 20)

        tls_info = {
            "raw_data_start": tls_data_start,
            "raw_data_start_hex": f"0x{tls_data_start:X}",
            "raw_data_end": tls_data_end,
            "raw_data_end_hex": f"0x{tls_data_end:X}",
            "raw_data_size": tls_data_end - tls_data_start if tls_data_end > tls_data_start else 0,
            "index_address": tls_index_addr,
            "index_address_hex": f"0x{tls_index_addr:X}",
            "callbacks_address": tls_callbacks_addr,
            "callbacks_address_hex": f"0x{tls_callbacks_addr:X}",
            "zero_fill_size": tls_zero_fill_size,
            "characteristics": tls_characteristics,
        }

        if tls_callbacks_addr != 0:
            cb_ea = tls_callbacks_addr
            max_callbacks = 256
            for _ in range(max_callbacks):
                cb_func = _read_dword(cb_ea)
                if cb_func == 0:
                    break
                func_name = ida_name.get_name(cb_func)
                if not func_name:
                    func_name = ea_str(cb_func)
                callbacks.append({
                    "ea": cb_func,
                    "ea_hex": ea_str(cb_func),
                    "rva": cb_func - image_base,
                    "rva_hex": f"0x{cb_func - image_base:X}",
                    "function_name": func_name,
                })
                cb_ea += 4

    tls_info["callbacks"] = callbacks

    if callbacks:
        msg_info(f"Found {len(callbacks)} TLS callbacks:")
        for cb in callbacks:
            msg(f"  TLS callback: {cb['ea_hex']} ({cb['function_name']})")
    else:
        msg(f"  No TLS callbacks found")

    return tls_info


# ---------------------------------------------------------------------------
# VTable RVA set builder (for CFG cross-referencing)
# ---------------------------------------------------------------------------

def _build_vtable_rva_set(session):
    """Build a set of all RVAs that appear in known vtable entries.

    Reads from the knowledge DB vtable_entries table and any existing
    vtable data in kv_store.  Returns a set of integer RVAs.
    """
    vtable_rvas = set()
    db = session.db
    cfg = session.cfg

    # Method 1: Read from vtable_entries table
    try:
        rows = db.fetchall(
            "SELECT DISTINCT func_ea FROM vtable_entries WHERE func_ea != 0"
        )
        for row in rows:
            func_ea = row["func_ea"]
            if func_ea and func_ea > 0:
                rva = cfg.ea_to_rva(func_ea)
                vtable_rvas.add(rva)
    except Exception:
        pass  # Table may not exist yet

    # Method 2: Read from kv_store vtable data
    try:
        vtable_data = db.kv_get("vtable_master")
        if isinstance(vtable_data, dict):
            vtables = vtable_data.get("vtables", [])
        elif isinstance(vtable_data, list):
            vtables = vtable_data
        else:
            vtables = []

        for vt in vtables:
            entries = vt.get("entries", [])
            for entry in entries:
                func_ea = entry.get("address") or entry.get("ea")
                if func_ea:
                    if isinstance(func_ea, str):
                        func_ea = int(func_ea, 16)
                    rva = cfg.ea_to_rva(func_ea)
                    vtable_rvas.add(rva)
    except Exception:
        pass

    msg(f"  Built vtable RVA set: {len(vtable_rvas)} entries")
    return vtable_rvas


# ---------------------------------------------------------------------------
# Statistics and summary helpers
# ---------------------------------------------------------------------------

def _build_pdata_statistics(exception_entries):
    """Compute aggregate statistics from parsed .pdata entries."""
    if not exception_entries:
        return {}

    sizes = [e["size"] for e in exception_entries if "size" in e]
    frame_sizes = [e.get("frame_size", 0) for e in exception_entries
                   if e.get("frame_size", 0) > 0]
    seh_count = sum(1 for e in exception_entries if e.get("has_seh", False))
    chained_count = sum(1 for e in exception_entries if e.get("chained", False))

    # Collect saved register frequency
    reg_freq = defaultdict(int)
    for e in exception_entries:
        for reg in e.get("saved_regs", []):
            reg_freq[reg] += 1

    stats = {
        "total_entries": len(exception_entries),
        "with_seh_handler": seh_count,
        "chained": chained_count,
    }

    if sizes:
        stats["function_size_min"] = min(sizes)
        stats["function_size_max"] = max(sizes)
        stats["function_size_avg"] = round(sum(sizes) / len(sizes), 1)
        stats["function_size_median"] = sorted(sizes)[len(sizes) // 2]

    if frame_sizes:
        stats["frame_size_min"] = min(frame_sizes)
        stats["frame_size_max"] = max(frame_sizes)
        stats["frame_size_avg"] = round(sum(frame_sizes) / len(frame_sizes), 1)

    if reg_freq:
        stats["saved_register_frequency"] = dict(
            sorted(reg_freq.items(), key=lambda x: -x[1])
        )

    return stats


def _build_cfg_statistics(cfg_targets):
    """Compute aggregate statistics from parsed CFG targets."""
    if not cfg_targets:
        return {}

    vtable_count = sum(1 for t in cfg_targets if t.get("is_vtable_member", False))
    callback_count = sum(1 for t in cfg_targets if t.get("is_callback", False))
    named_count = sum(1 for t in cfg_targets if t.get("function_name", ""))
    unnamed_count = len(cfg_targets) - named_count

    return {
        "total_targets": len(cfg_targets),
        "vtable_members": vtable_count,
        "callbacks": callback_count,
        "named": named_count,
        "unnamed": unnamed_count,
        "unclassified": len(cfg_targets) - vtable_count - callback_count,
    }


def _build_section_statistics(sections):
    """Compute aggregate section statistics."""
    if not sections:
        return {}

    total_vsize = sum(s.get("vsize", 0) for s in sections)
    total_rawsize = sum(s.get("rawsize", 0) for s in sections)
    code_sections = [s for s in sections if s.get("is_code", False)]
    wx_sections = [s for s in sections if s.get("is_writable_executable", False)]
    high_entropy = [s for s in sections if s.get("entropy", 0) >= 7.0]

    return {
        "total_sections": len(sections),
        "total_virtual_size": total_vsize,
        "total_raw_size": total_rawsize,
        "code_sections": len(code_sections),
        "writable_executable_sections": len(wx_sections),
        "high_entropy_sections": len(high_entropy),
        "writable_executable_names": [s["name"] for s in wx_sections],
        "high_entropy_names": [s["name"] for s in high_entropy],
    }


# ---------------------------------------------------------------------------
# Limit list sizes for storage (keep top N, store total count)
# ---------------------------------------------------------------------------

def _cap_list(items, max_count, sort_key=None, reverse=True):
    """Return a tuple of (capped_list, total_count).

    If *sort_key* is provided, sorts by that key before capping.
    """
    total = len(items)
    if sort_key and items:
        items = sorted(items, key=lambda x: x.get(sort_key, 0), reverse=reverse)
    if total > max_count:
        return items[:max_count], total
    return items, total


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_pe_metadata(session) -> int:
    """Extract PE metadata intelligence from the loaded binary.

    Parses PE headers, exception tables (.pdata), CFG tables, debug directory,
    TLS directory, Load Config, and section characteristics from the IDB.

    Results are stored in the knowledge DB under kv_store key ``"pe_metadata"``.

    Args:
        session: The PluginSession instance providing db and cfg access.

    Returns:
        Total number of items extracted (sum of exception entries, CFG targets,
        debug entries, TLS callbacks, and sections).
    """
    db = session.db
    cfg = session.cfg
    image_base = cfg.image_base

    start_time = time.time()
    msg_info("=" * 60)
    msg_info("PE Metadata Intelligence Extractor")
    msg_info("=" * 60)
    msg_info(f"Image base: {ea_str(image_base)}")

    total_items = 0

    # -----------------------------------------------------------------------
    # 1. Parse PE headers
    # -----------------------------------------------------------------------
    msg_info("--- Phase 1: PE Header Parsing ---")
    header_info, data_dirs, section_headers = _parse_pe_header(image_base)

    if header_info is None:
        msg_error("Failed to parse PE headers — aborting analysis")
        return 0

    msg_info(f"Machine: {header_info['machine_name']}")
    msg_info(f"Sections: {header_info['number_of_sections']}")
    msg_info(f"Timestamp: {header_info['timestamp_hex']}")
    msg_info(f"Image size: {header_info['size_of_image']} bytes "
             f"({header_info['size_of_image'] / (1024 * 1024):.1f} MB)")
    msg_info(f"Subsystem: {header_info['subsystem_name']}")
    msg_info(f"DLL characteristics: {', '.join(header_info['dll_characteristics_flags'])}")

    is_pe64 = header_info["is_pe64"]

    # -----------------------------------------------------------------------
    # 2. Analyze sections with entropy
    # -----------------------------------------------------------------------
    msg_info("--- Phase 2: Section Analysis ---")
    sections = _analyze_sections(image_base, section_headers)
    total_items += len(sections)

    for sec in sections:
        flags = []
        if sec["is_code"]:
            flags.append("CODE")
        if sec["is_writable_executable"]:
            flags.append("W+X!")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        msg(f"  {sec['name']:8s} VA={sec['va_hex']:>10s} "
            f"VSize={sec['vsize']:>10,} Raw={sec['rawsize']:>10,} "
            f"Perms={sec['permissions']:3s} Entropy={sec['entropy']:.2f}{flag_str}")

    section_stats = _build_section_statistics(sections)
    if section_stats.get("writable_executable_sections", 0) > 0:
        msg_warn(f"Found {section_stats['writable_executable_sections']} "
                 f"writable+executable sections: "
                 f"{section_stats['writable_executable_names']}")

    # -----------------------------------------------------------------------
    # 3. Parse exception table (.pdata)
    # -----------------------------------------------------------------------
    msg_info("--- Phase 3: Exception Table (.pdata) ---")
    exception_entries, ida_missed, pdata_total = _parse_exception_table(
        image_base, data_dirs, is_pe64
    )
    total_items += pdata_total

    pdata_stats = _build_pdata_statistics(exception_entries)
    if pdata_stats:
        msg_info(f"  Function size range: "
                 f"{pdata_stats.get('function_size_min', 0)} - "
                 f"{pdata_stats.get('function_size_max', 0)} bytes "
                 f"(avg {pdata_stats.get('function_size_avg', 0)})")
        if pdata_stats.get("saved_register_frequency"):
            top_regs = list(pdata_stats["saved_register_frequency"].items())[:5]
            msg(f"  Most saved registers: "
                f"{', '.join(f'{r}({c})' for r, c in top_regs)}")

    if ida_missed:
        msg_warn(f"IDA missed {len(ida_missed)} functions that .pdata knows about!")
        # Show first 20 examples
        for missed in ida_missed[:20]:
            msg(f"    Missed: {missed['ea_hex']} (size {missed['size']})")
        if len(ida_missed) > 20:
            msg(f"    ... and {len(ida_missed) - 20} more")

    # -----------------------------------------------------------------------
    # 4. Build vtable RVA set for CFG cross-referencing
    # -----------------------------------------------------------------------
    msg_info("--- Phase 4: Building VTable RVA cross-reference ---")
    vtable_rvas = _build_vtable_rva_set(session)

    # -----------------------------------------------------------------------
    # 5. Parse CFG tables
    # -----------------------------------------------------------------------
    msg_info("--- Phase 5: Control Flow Guard (CFG) Tables ---")
    cfg_targets, cfg_unresolved, load_config, cfg_total = _parse_cfg_tables(
        image_base, data_dirs, is_pe64, vtable_rvas
    )
    total_items += cfg_total

    cfg_stats = _build_cfg_statistics(cfg_targets)
    if cfg_stats:
        msg_info(f"  CFG classification: "
                 f"{cfg_stats.get('vtable_members', 0)} vtable, "
                 f"{cfg_stats.get('callbacks', 0)} callbacks, "
                 f"{cfg_stats.get('unclassified', 0)} unclassified")

    # -----------------------------------------------------------------------
    # 6. Parse debug directory
    # -----------------------------------------------------------------------
    msg_info("--- Phase 6: Debug Directory ---")
    debug_info = _parse_debug_directory(image_base, data_dirs)
    total_items += len(debug_info.get("entries", []))

    if debug_info.get("pogo_sections"):
        msg_info(f"  POGO reveals {len(debug_info['pogo_sections'])} "
                 f"original .obj section groupings")
        # Show first 10 POGO sections
        for pogo in debug_info["pogo_sections"][:10]:
            msg(f"    {pogo['name']:40s} RVA={pogo['rva_hex']:>10s} "
                f"Size={pogo['size']:>8,}")
        if len(debug_info["pogo_sections"]) > 10:
            msg(f"    ... and {len(debug_info['pogo_sections']) - 10} more")

    # -----------------------------------------------------------------------
    # 7. Parse TLS directory
    # -----------------------------------------------------------------------
    msg_info("--- Phase 7: TLS Directory ---")
    tls_info = _parse_tls_directory(image_base, data_dirs, is_pe64)
    tls_callbacks = tls_info.get("callbacks", [])
    total_items += len(tls_callbacks)

    if tls_info and tls_info.get("raw_data_size", 0) > 0:
        msg_info(f"  TLS data: {tls_info['raw_data_size']} bytes")

    # -----------------------------------------------------------------------
    # 8. Cap large lists for storage
    # -----------------------------------------------------------------------
    # Exception entries: keep first 50000 (most binaries have < 200K)
    exception_entries_capped, exception_entries_total = _cap_list(
        exception_entries, 50000
    )

    # IDA missed: keep all (typically < 10K)
    ida_missed_capped, ida_missed_total = _cap_list(ida_missed, 50000)

    # CFG targets: keep first 50000
    cfg_targets_capped, cfg_targets_total = _cap_list(cfg_targets, 50000)

    # CFG unresolved: keep first 10000
    cfg_unresolved_capped, cfg_unresolved_total = _cap_list(cfg_unresolved, 10000)

    # POGO sections: keep all (typically < 10K)
    pogo_capped, pogo_total = _cap_list(
        debug_info.get("pogo_sections", []), 50000
    )

    # -----------------------------------------------------------------------
    # 9. Assemble final results
    # -----------------------------------------------------------------------
    results = {
        "pe_header": header_info,
        "sections": sections,
        "section_statistics": section_stats,
        "exception_functions": exception_entries_capped,
        "exception_statistics": pdata_stats,
        "ida_missed_functions": ida_missed_capped,
        "cfg_targets": cfg_targets_capped,
        "cfg_unresolved": cfg_unresolved_capped,
        "cfg_statistics": cfg_stats,
        "load_config": load_config,
        "debug_info": {
            "entries": debug_info.get("entries", []),
            "pdb_path": debug_info.get("pdb_path", ""),
            "pdb_guid": debug_info.get("pdb_guid", ""),
            "pdb_age": debug_info.get("pdb_age", 0),
            "pogo_sections": pogo_capped,
        },
        "tls_info": tls_info,
        "tls_callbacks": tls_callbacks,
        "total_pdata_entries": exception_entries_total,
        "total_cfg_targets": cfg_targets_total,
        "total_cfg_unresolved": cfg_unresolved_total,
        "ida_missed_count": ida_missed_total,
        "total_pogo_sections": pogo_total,
        "analysis_time_seconds": round(time.time() - start_time, 2),
    }

    # -----------------------------------------------------------------------
    # 10. Store results in knowledge DB
    # -----------------------------------------------------------------------
    msg_info("--- Storing results ---")
    db.kv_set("pe_metadata", results)
    db.commit()

    elapsed = time.time() - start_time
    msg_info("=" * 60)
    msg_info("PE Metadata Extraction Complete")
    msg_info(f"  Total items extracted: {total_items}")
    msg_info(f"  .pdata entries: {exception_entries_total}")
    msg_info(f"  IDA missed functions: {ida_missed_total}")
    msg_info(f"  CFG targets: {cfg_targets_total}")
    msg_info(f"  CFG unresolved: {cfg_unresolved_total}")
    msg_info(f"  Debug entries: {len(debug_info.get('entries', []))}")
    msg_info(f"  POGO sections: {pogo_total}")
    msg_info(f"  TLS callbacks: {len(tls_callbacks)}")
    msg_info(f"  Sections: {len(sections)}")
    msg_info(f"  Time: {elapsed:.1f}s")
    msg_info("=" * 60)

    return total_items


# ---------------------------------------------------------------------------
# Convenience accessor
# ---------------------------------------------------------------------------

def get_pe_metadata(session):
    """Retrieve stored PE metadata results from the knowledge DB.

    Returns the full results dict, or an empty dict if no analysis has been run.
    """
    return session.db.kv_get("pe_metadata") or {}
