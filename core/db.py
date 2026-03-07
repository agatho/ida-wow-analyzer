"""
Persistent SQLite knowledge database for the TC WoW Analyzer.
Stores all analysis results in a single file alongside the IDB.
Replaces the fragmented 60+ JSON export approach.
"""

import sqlite3
import os
import json
import time


SCHEMA_VERSION = 1

SCHEMA_SQL = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_info (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Build metadata
CREATE TABLE IF NOT EXISTS builds (
    build_number INTEGER PRIMARY KEY,
    image_base INTEGER,
    binary_path TEXT,
    extraction_date TEXT,
    notes TEXT
);

-- Functions: every function in the binary
CREATE TABLE IF NOT EXISTS functions (
    ea INTEGER PRIMARY KEY,
    rva INTEGER,
    name TEXT,
    size INTEGER DEFAULT 0,
    system TEXT,          -- top-level system: housing, combat, quest, etc.
    subsystem TEXT,       -- e.g. neighborhood, interior, decor
    confidence INTEGER DEFAULT 0,  -- 0-100
    decompiled_hash TEXT, -- hash of last decompilation for change detection
    flags INTEGER DEFAULT 0,
    created_at REAL,
    updated_at REAL
);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
CREATE INDEX IF NOT EXISTS idx_functions_system ON functions(system);
CREATE INDEX IF NOT EXISTS idx_functions_rva ON functions(rva);

-- Opcodes: CMSG/SMSG handler mapping
CREATE TABLE IF NOT EXISTS opcodes (
    internal_index INTEGER,  -- dispatch table index (e.g. 0x420127)
    wire_opcode INTEGER,     -- actual wire protocol value
    direction TEXT NOT NULL,  -- 'CMSG' or 'SMSG'
    tc_name TEXT,            -- TrinityCore opcode name
    handler_ea INTEGER,      -- handler function address
    deserializer_ea INTEGER, -- JAM deserializer address
    jam_type TEXT,           -- JAM type name
    status TEXT DEFAULT 'unknown',  -- matched/unknown/new/removed
    notes TEXT,
    PRIMARY KEY (direction, internal_index)
);
CREATE INDEX IF NOT EXISTS idx_opcodes_tc_name ON opcodes(tc_name);
CREATE INDEX IF NOT EXISTS idx_opcodes_handler ON opcodes(handler_ea);

-- JAM message types and their field layouts
CREATE TABLE IF NOT EXISTS jam_types (
    name TEXT PRIMARY KEY,
    serializer_ea INTEGER,
    deserializer_ea INTEGER,
    field_count INTEGER DEFAULT 0,
    fields_json TEXT,  -- JSON array of field definitions
    wire_size INTEGER, -- estimated wire size in bytes
    status TEXT DEFAULT 'discovered',  -- discovered/fields_extracted/verified
    notes TEXT
);

-- DB2 table metadata from the binary
CREATE TABLE IF NOT EXISTS db2_tables (
    name TEXT PRIMARY KEY,
    file_data_id INTEGER,
    layout_hash INTEGER,
    meta_rva INTEGER,
    meta_ea INTEGER,
    field_count INTEGER DEFAULT 0,
    record_size INTEGER DEFAULT 0,
    index_field INTEGER DEFAULT -1,
    parent_index_field INTEGER DEFAULT -1,
    flags INTEGER DEFAULT 0,
    fields_json TEXT,  -- JSON array of {type, size, is_signed, array_size}
    loadinfo_generated INTEGER DEFAULT 0,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_db2_meta_ea ON db2_tables(meta_ea);

-- Virtual tables
CREATE TABLE IF NOT EXISTS vtables (
    ea INTEGER PRIMARY KEY,
    rva INTEGER,
    class_name TEXT,
    entry_count INTEGER DEFAULT 0,
    source TEXT,  -- rtti/constructor/string/propagation/clustering
    parent_class TEXT,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_vtables_class ON vtables(class_name);

-- Virtual table entries (individual function slots)
CREATE TABLE IF NOT EXISTS vtable_entries (
    vtable_ea INTEGER,
    slot_index INTEGER,
    func_ea INTEGER,
    func_name TEXT,
    PRIMARY KEY (vtable_ea, slot_index),
    FOREIGN KEY (vtable_ea) REFERENCES vtables(ea)
);
CREATE INDEX IF NOT EXISTS idx_vte_func ON vtable_entries(func_ea);

-- Lua API functions
CREATE TABLE IF NOT EXISTS lua_api (
    namespace TEXT,
    method TEXT,
    handler_ea INTEGER,
    arg_count INTEGER DEFAULT -1,
    args_json TEXT,    -- JSON array of {name, type}
    returns_json TEXT, -- JSON array of {type}
    is_protected INTEGER DEFAULT 0,
    PRIMARY KEY (namespace, method)
);
CREATE INDEX IF NOT EXISTS idx_lua_handler ON lua_api(handler_ea);

-- Update fields (object descriptors)
CREATE TABLE IF NOT EXISTS update_fields (
    object_type TEXT,   -- Object, Item, Unit, Player, GameObject, etc.
    field_name TEXT,
    field_offset INTEGER,
    field_size INTEGER,
    field_type TEXT,     -- INT32, UINT32, FLOAT, GUID, TWO_SHORT, BYTES
    field_flags TEXT,    -- PUBLIC, PRIVATE, OWNER, etc.
    array_count INTEGER DEFAULT 1,
    is_dynamic INTEGER DEFAULT 0,
    PRIMARY KEY (object_type, field_name)
);

-- Annotations (comments, renames, type changes) with provenance
CREATE TABLE IF NOT EXISTS annotations (
    ea INTEGER,
    ann_type TEXT,  -- comment/name/type/system_label
    value TEXT,
    source TEXT,    -- auto/manual/import/ai
    confidence INTEGER DEFAULT 100,
    created_at REAL,
    PRIMARY KEY (ea, ann_type)
);

-- Cross-build diffing results
CREATE TABLE IF NOT EXISTS diffing (
    old_ea INTEGER,
    new_ea INTEGER,
    match_type TEXT,   -- exact/signature/callgraph/string/opcode/simhash
    confidence REAL,
    old_build INTEGER,
    new_build INTEGER,
    PRIMARY KEY (old_ea, new_ea)
);

-- Strings: important strings with cross-references
CREATE TABLE IF NOT EXISTS strings (
    ea INTEGER PRIMARY KEY,
    value TEXT,
    encoding TEXT DEFAULT 'utf-8',
    system TEXT,
    xref_count INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_strings_system ON strings(system);

-- Key-value store for arbitrary plugin state
CREATE TABLE IF NOT EXISTS kv_store (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at REAL
);
"""


class KnowledgeDB:
    """Persistent per-IDB SQLite knowledge database."""

    def __init__(self, db_path):
        self._path = db_path
        self._conn = None

    @property
    def path(self):
        return self._path

    @property
    def conn(self):
        if self._conn is None:
            self.open()
        return self._conn

    def open(self):
        """Open (or create) the database."""
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        self._conn = sqlite3.connect(self._path, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_schema()
        return self

    def close(self):
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def _create_schema(self):
        """Create tables if they don't exist. Migrate if schema version changed."""
        cur = self._conn.executescript(SCHEMA_SQL)
        # Set schema version
        self._conn.execute(
            "INSERT OR REPLACE INTO schema_info (key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION))
        )
        self._conn.commit()

    # ─── Convenience Methods ──────────────────────────────────────

    def execute(self, sql, params=()):
        return self.conn.execute(sql, params)

    def executemany(self, sql, params_list):
        return self.conn.executemany(sql, params_list)

    def commit(self):
        self.conn.commit()

    def fetchone(self, sql, params=()):
        return self.conn.execute(sql, params).fetchone()

    def fetchall(self, sql, params=()):
        return self.conn.execute(sql, params).fetchall()

    def count(self, table):
        row = self.fetchone(f"SELECT COUNT(*) as cnt FROM {table}")
        return row["cnt"] if row else 0

    # ─── Function Operations ──────────────────────────────────────

    def upsert_function(self, ea, rva=None, name=None, size=0,
                        system=None, subsystem=None, confidence=0, flags=0):
        now = time.time()
        self.execute("""
            INSERT INTO functions (ea, rva, name, size, system, subsystem,
                                   confidence, flags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ea) DO UPDATE SET
                rva = COALESCE(excluded.rva, rva),
                name = COALESCE(excluded.name, name),
                size = CASE WHEN excluded.size > 0 THEN excluded.size ELSE size END,
                system = COALESCE(excluded.system, system),
                subsystem = COALESCE(excluded.subsystem, subsystem),
                confidence = MAX(excluded.confidence, confidence),
                flags = excluded.flags | flags,
                updated_at = excluded.updated_at
        """, (ea, rva, name, size, system, subsystem, confidence, flags, now, now))

    def get_function(self, ea):
        return self.fetchone("SELECT * FROM functions WHERE ea = ?", (ea,))

    def get_functions_by_system(self, system):
        return self.fetchall(
            "SELECT * FROM functions WHERE system = ? ORDER BY ea", (system,))

    # ─── Opcode Operations ────────────────────────────────────────

    def upsert_opcode(self, direction, internal_index, **kwargs):
        cols = ["direction", "internal_index"]
        vals = [direction, internal_index]
        updates = []
        for k, v in kwargs.items():
            if v is not None:
                cols.append(k)
                vals.append(v)
                updates.append(f"{k} = excluded.{k}")
        placeholders = ", ".join(["?"] * len(vals))
        col_str = ", ".join(cols)
        update_str = ", ".join(updates) if updates else "direction = excluded.direction"
        self.execute(f"""
            INSERT INTO opcodes ({col_str}) VALUES ({placeholders})
            ON CONFLICT(direction, internal_index) DO UPDATE SET {update_str}
        """, vals)

    def get_opcodes(self, direction=None):
        if direction:
            return self.fetchall(
                "SELECT * FROM opcodes WHERE direction = ? ORDER BY internal_index",
                (direction,))
        return self.fetchall("SELECT * FROM opcodes ORDER BY direction, internal_index")

    # ─── JAM Type Operations ──────────────────────────────────────

    def upsert_jam_type(self, name, **kwargs):
        cols = ["name"]
        vals = [name]
        updates = []
        for k, v in kwargs.items():
            if v is not None:
                cols.append(k)
                vals.append(v)
                updates.append(f"{k} = excluded.{k}")
        placeholders = ", ".join(["?"] * len(vals))
        col_str = ", ".join(cols)
        update_str = ", ".join(updates) if updates else "name = excluded.name"
        self.execute(f"""
            INSERT INTO jam_types ({col_str}) VALUES ({placeholders})
            ON CONFLICT(name) DO UPDATE SET {update_str}
        """, vals)

    # ─── DB2 Table Operations ─────────────────────────────────────

    def upsert_db2_table(self, name, **kwargs):
        cols = ["name"]
        vals = [name]
        updates = []
        for k, v in kwargs.items():
            if v is not None:
                cols.append(k)
                vals.append(v)
                updates.append(f"{k} = excluded.{k}")
        placeholders = ", ".join(["?"] * len(vals))
        col_str = ", ".join(cols)
        update_str = ", ".join(updates) if updates else "name = excluded.name"
        self.execute(f"""
            INSERT INTO db2_tables ({col_str}) VALUES ({placeholders})
            ON CONFLICT(name) DO UPDATE SET {update_str}
        """, vals)

    # ─── VTable Operations ────────────────────────────────────────

    def upsert_vtable(self, ea, rva=None, class_name=None,
                      entry_count=0, source=None, parent_class=None):
        self.execute("""
            INSERT INTO vtables (ea, rva, class_name, entry_count, source, parent_class)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ea) DO UPDATE SET
                rva = COALESCE(excluded.rva, rva),
                class_name = COALESCE(excluded.class_name, class_name),
                entry_count = MAX(excluded.entry_count, entry_count),
                source = COALESCE(excluded.source, source),
                parent_class = COALESCE(excluded.parent_class, parent_class)
        """, (ea, rva, class_name, entry_count, source, parent_class))

    def upsert_vtable_entry(self, vtable_ea, slot_index, func_ea, func_name=None):
        self.execute("""
            INSERT INTO vtable_entries (vtable_ea, slot_index, func_ea, func_name)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(vtable_ea, slot_index) DO UPDATE SET
                func_ea = excluded.func_ea,
                func_name = COALESCE(excluded.func_name, func_name)
        """, (vtable_ea, slot_index, func_ea, func_name))

    # ─── Lua API Operations ───────────────────────────────────────

    def upsert_lua_api(self, namespace, method, handler_ea, **kwargs):
        cols = ["namespace", "method", "handler_ea"]
        vals = [namespace, method, handler_ea]
        updates = ["handler_ea = excluded.handler_ea"]
        for k, v in kwargs.items():
            if v is not None:
                cols.append(k)
                vals.append(v)
                updates.append(f"{k} = excluded.{k}")
        placeholders = ", ".join(["?"] * len(vals))
        col_str = ", ".join(cols)
        update_str = ", ".join(updates)
        self.execute(f"""
            INSERT INTO lua_api ({col_str}) VALUES ({placeholders})
            ON CONFLICT(namespace, method) DO UPDATE SET {update_str}
        """, vals)

    # ─── KV Store ─────────────────────────────────────────────────

    def kv_set(self, key, value):
        if not isinstance(value, str):
            value = json.dumps(value)
        self.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, time.time()))

    def kv_get(self, key, default=None):
        row = self.fetchone("SELECT value FROM kv_store WHERE key = ?", (key,))
        if row:
            try:
                return json.loads(row["value"])
            except (json.JSONDecodeError, TypeError):
                return row["value"]
        return default

    # ─── Statistics ───────────────────────────────────────────────

    def get_stats(self):
        """Return a dict of table counts for the dashboard."""
        tables = [
            "functions", "opcodes", "jam_types", "db2_tables",
            "vtables", "vtable_entries", "lua_api", "update_fields",
            "annotations", "strings", "diffing"
        ]
        stats = {}
        for t in tables:
            try:
                stats[t] = self.count(t)
            except Exception:
                stats[t] = 0
        return stats
