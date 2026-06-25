"""
Minimal parser for WoWDBDefs `.dbd` files. Extracts COLUMNS + per-LAYOUT
field lists with sizes. Avoids the official modgrammar-based parser to
keep dependencies headless-friendly.

DBD format (simplified):
  COLUMNS
  <type>[<foreign>] <name>[?] [// comment]
  ...
  <blank line>
  LAYOUT <hash>
  BUILD <build>[, <build> ...]
  COMMENT [...]
  $tag$<name>[<size>][@offset]
  ...
"""
import os
import re

# Type tokens that appear in COLUMNS section
_BASE_TYPE_RE = re.compile(
    r'^\s*([a-zA-Z_]+)'             # base type (int, uint, byte, locstring, ...)
    r'(?:<([^>]+)>)?'               # optional foreign ref or width
    r'\s+([A-Za-z_][\w]*)'          # field name
    r'(\??)'                        # optional ? meaning "uncertain name"
    r'(?:\s*//\s*(.*))?$'           # optional comment
)

# LAYOUT entry: $tag$Name<size>[arr]
_LAYOUT_ENTRY_RE = re.compile(
    r'^\s*(?:\$([a-z_]+)\$)?'       # optional $id$ / $relation$ tag
    r'([A-Za-z_][\w]*)'             # field name
    r'(?:<([^>]+)>)?'               # optional size in bits
    r'(?:\[(\d+)\])?'               # optional array size
    r'\s*$'
)


class Column:
    def __init__(self, base_type, foreign, name, uncertain, comment):
        self.base_type = base_type        # 'int', 'uint', 'byte', 'locstring', etc.
        self.foreign = foreign            # 'Map::ID' or None
        self.name = name
        self.uncertain = uncertain
        self.comment = comment


class LayoutField:
    def __init__(self, name, bit_size, is_signed, array_size, tag):
        self.name = name
        self.bit_size = bit_size          # e.g. 32, 16, 8 (in bits)
        self.is_signed = is_signed        # False if size token starts with 'u'
        self.array_size = array_size
        self.tag = tag                    # 'id', 'relation', 'noninline', None


class Layout:
    def __init__(self):
        self.hash = None
        self.builds = []                  # list of (major, minor, patch, build) tuples
        self.fields = []                  # list[LayoutField]


class DBDFile:
    def __init__(self):
        self.columns = {}                 # name -> Column
        self.layouts = []                 # list[Layout]


def parse_dbd_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    return parse_dbd(text)


def parse_dbd(text):
    out = DBDFile()
    state = "preamble"
    current_layout = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()

        if state == "preamble":
            if line.strip() == "COLUMNS":
                state = "columns"
            continue

        if state == "columns":
            if line.strip() == "":
                state = "between"
                continue
            m = _BASE_TYPE_RE.match(line)
            if m:
                base_type, foreign, name, q, comment = m.groups()
                out.columns[name] = Column(
                    base_type=base_type,
                    foreign=foreign,
                    name=name,
                    uncertain=bool(q),
                    comment=(comment or "").strip(),
                )
            continue

        if state == "between":
            stripped = line.strip()
            if stripped.startswith("LAYOUT "):
                current_layout = Layout()
                current_layout.hash = stripped.split(None, 1)[1].strip()
                out.layouts.append(current_layout)
                state = "layout"
            continue

        if state == "layout":
            stripped = line.strip()
            if stripped == "":
                # blank line ends a layout block
                state = "between"
                current_layout = None
                continue
            if stripped.startswith("LAYOUT "):
                current_layout = Layout()
                current_layout.hash = stripped.split(None, 1)[1].strip()
                out.layouts.append(current_layout)
                continue
            if stripped.startswith("BUILD "):
                # Parse build list: "BUILD a.b.c.d, a.b.c.d, ..."
                builds_str = stripped[len("BUILD "):].strip()
                for raw_b in builds_str.split(","):
                    raw_b = raw_b.strip()
                    parts = raw_b.split(".")
                    if len(parts) == 4:
                        try:
                            current_layout.builds.append(tuple(int(x) for x in parts))
                        except ValueError:
                            continue
                continue
            if stripped.startswith("COMMENT") or stripped.startswith("//"):
                continue
            # Otherwise it's a field entry
            m = _LAYOUT_ENTRY_RE.match(line)
            if not m:
                continue
            tag, name, size_token, array_size, *_ = m.groups()
            bit_size = 32
            is_signed = True
            if size_token:
                # Examples: '32', '16', '8', 'u32', 'u16'
                if size_token.startswith("u"):
                    is_signed = False
                    size_token = size_token[1:]
                try:
                    bit_size = int(size_token)
                except ValueError:
                    bit_size = 32
            arr = None
            if array_size:
                try:
                    arr = int(array_size)
                except ValueError:
                    arr = None
            current_layout.fields.append(LayoutField(
                name=name,
                bit_size=bit_size,
                is_signed=is_signed,
                array_size=arr,
                tag=tag,
            ))

    return out


def find_layout_for_build(dbd, build_tuple):
    """Return the Layout matching `build_tuple = (major, minor, patch, build)`,
    or the closest by build number, or None."""
    for layout in dbd.layouts:
        if build_tuple in layout.builds:
            return layout
    # Fallback: highest build number
    best_layout = None
    best_build = -1
    for layout in dbd.layouts:
        for b in layout.builds:
            if b[3] > best_build:
                best_build = b[3]
                best_layout = layout
    return best_layout


def column_to_ctype(col, layout_field, locale_count=8):
    """Convert a Column + LayoutField pair to a C type declaration.

    Returns (ctype_string, total_bytes).
    """
    base = (col.base_type or "int").lower()
    bits = layout_field.bit_size if layout_field else 32
    signed = layout_field.is_signed if layout_field else True

    if base == "float":
        return "float", 4
    if base == "double":
        return "double", 8
    if base == "string" or base == "string_lang":
        # In-record offset to a string heap
        return "unsigned __int32", 4
    if base == "locstring":
        # Localized string is per-locale strings + flags
        return f"unsigned __int32[{locale_count + 1}]", 4 * (locale_count + 1)

    # Integer types
    byte_size = max(1, bits // 8)
    if signed:
        if bits == 8: return "__int8", 1
        if bits == 16: return "__int16", 2
        if bits == 32: return "__int32", 4
        if bits == 64: return "__int64", 8
    else:
        if bits == 8: return "unsigned __int8", 1
        if bits == 16: return "unsigned __int16", 2
        if bits == 32: return "unsigned __int32", 4
        if bits == 64: return "unsigned __int64", 8
    return "unsigned __int32", 4
