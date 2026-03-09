"""
Configuration system for TC WoW Analyzer.

Loads settings from tc_wow_config.json with multi-source priority:
  1. Pipeline directory config (if pipeline_dir is set)
  2. Plugin directory config (next to the tc_wow_analyzer package)
  3. IDB directory config (next to the currently open .idb/.i64)

All paths and build-specific data default to empty/None so the plugin
works cleanly on a fresh install.  Users configure via the settings GUI
or by placing a tc_wow_config.json next to their IDB.
"""

import json
import os

import ida_loader


# ---------------------------------------------------------------------------
# Defaults -- no hardcoded paths, no build-specific data
# ---------------------------------------------------------------------------
_DEFAULTS = {
    "ida_path": None,
    "binary_path": None,
    "pipeline_dir": None,

    # Per-build data keyed by build number string, e.g.
    # "66198": {
    #     "image_base": 0x7FF7245E0000,
    #     "extraction_dir": "C:\\dumps",
    #     "enriched_dir": "C:\\dumps\\pipeline\\output"
    # }
    "builds": {},

    # TrinityCore source tree (optional, used by cross-ref tools)
    "tc_source_dir": None,

    # Global extraction directory fallback (when not set per-build)
    "extraction_dir": None,

    # Directory containing packet sniff files (*.pkt or parsed sniff output)
    "sniff_dir": None,

    # Directory containing DB2 client data files (dbfilesclient)
    "db2_data_dir": None,

    "known_rvas": {
        "main_dispatcher": 0,
        "mem_alloc": 0,
        "byte_obfuscate_ror7": None,
        "write_uint32": 0,
        "write_uint8": 0,
        "write_float": 0,
        "write_object_guid": 0,
        "write_bits": 0,
        "flush_bits": 0,
    },

    "dispatch_range": {
        "start": 0,
        "end": 0,
        "count": 0,
    },

    "serializer_rvas": {},

    "llm": {
        "url": "http://127.0.0.1:1234/v1/chat/completions",
        "model": "local-model",
    },

    "mcp": {
        "host": "127.0.0.1",
        "port": 13337,
    },

    "db_path": None,  # auto-computed from IDB path if not set
}


# ---------------------------------------------------------------------------
# PluginConfig
# ---------------------------------------------------------------------------
class PluginConfig:
    """Configuration with defaults, multi-source file loading, and save support."""

    def __init__(self):
        self._data = json.loads(json.dumps(_DEFAULTS))  # deep copy
        self._load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self):
        """Load config from multiple sources with increasing priority."""

        # Priority 1: Pipeline config (existing infrastructure)
        pipeline_dir = self._data.get("pipeline_dir")
        if pipeline_dir:
            pipeline_cfg = os.path.join(pipeline_dir, "pipeline_config.json")
            self._merge_file(pipeline_cfg)

        # Priority 2: Plugin-specific config next to this package
        module_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        plugin_cfg = os.path.join(module_dir, "tc_wow_config.json")
        self._merge_file(plugin_cfg)

        # Priority 3: Config next to the IDB (per-database overrides)
        idb_path = self._idb_path()
        if idb_path:
            idb_dir = os.path.dirname(idb_path)
            idb_cfg = os.path.join(idb_dir, "tc_wow_config.json")
            self._merge_file(idb_cfg)

            # Auto-compute DB path if not explicitly set
            if not self._data.get("db_path"):
                base = os.path.splitext(idb_path)[0]
                self._data["db_path"] = base + ".tc_wow.db"

    def _merge_file(self, path):
        """Merge a JSON config file into current data."""
        if not path or not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._deep_merge(self._data, data)
        except Exception as e:
            print(f"[TC-WoW] Config warning: could not load {path}: {e}")

    @staticmethod
    def _deep_merge(base, override):
        """Recursively merge *override* dict into *base* dict in-place."""
        for key, value in override.items():
            if key.startswith("_"):
                continue  # skip _comment keys
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                PluginConfig._deep_merge(base[key], value)
            else:
                base[key] = value

    @staticmethod
    def _idb_path():
        """Return the current IDB path, or None."""
        try:
            return ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Generic get / set
    # ------------------------------------------------------------------

    def get(self, *keys, default=None):
        """Get a nested config value: ``cfg.get('builds', '66198', 'image_base')``"""
        node = self._data
        for k in keys:
            if isinstance(node, dict) and k in node:
                node = node[k]
            else:
                return default
        return node

    def set(self, *keys_and_value):
        """Set a nested config value programmatically.

        Usage::

            cfg.set('builds', '66198', 'image_base', 0x7FF7245E0000)
            cfg.set('tc_source_dir', '/home/user/TrinityCore')

        The last positional argument is the value; all preceding arguments
        are dict keys forming the path.
        """
        if len(keys_and_value) < 2:
            raise ValueError("set() requires at least a key and a value")
        *keys, value = keys_and_value
        node = self._data
        for k in keys[:-1]:
            if k not in node or not isinstance(node[k], dict):
                node[k] = {}
            node = node[k]
        node[keys[-1]] = value

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def save(self, path=None):
        """Write current config to a JSON file.

        If *path* is ``None``, writes ``tc_wow_config.json`` next to the
        currently open IDB.  Returns the path written, or ``None`` on failure.
        """
        if path is None:
            idb = self._idb_path()
            if not idb:
                print("[TC-WoW] Config: cannot save — no IDB path available")
                return None
            path = os.path.join(os.path.dirname(idb), "tc_wow_config.json")

        try:
            # Build a clean copy, converting any 0-valued RVAs to 0 (not None)
            out = json.loads(json.dumps(self._data, default=str))
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, sort_keys=False)
            print(f"[TC-WoW] Config saved to {path}")
            return path
        except Exception as e:
            print(f"[TC-WoW] Config save failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def db_path(self):
        """Path to the per-IDB SQLite database.

        Dynamically computes from the IDB path if not already set,
        since the config singleton may be created before the IDB is loaded.
        """
        path = self._data.get("db_path")
        if not path:
            idb_path = self._idb_path()
            if idb_path:
                path = os.path.splitext(idb_path)[0] + ".tc_wow.db"
                self._data["db_path"] = path
        return path or ""

    @property
    def image_base(self):
        """Image base for the currently loaded IDB (page-aligned)."""
        import ida_ida
        return ida_ida.inf_get_min_ea() & ~0xFFF

    @property
    def build_number(self):
        """Detect build number from image_base match or explicit ``build_number`` key."""
        # Explicit override takes priority
        explicit = self._data.get("build_number")
        if explicit:
            return int(explicit)

        # Match by image_base
        current_base = self.image_base
        for build_str, info in self._data.get("builds", {}).items():
            if isinstance(info, dict) and info.get("image_base") == current_base:
                return int(build_str)
        return 0

    @property
    def extraction_dir(self):
        """Extraction directory: build-specific first, then global fallback."""
        bn = self.build_number
        if bn:
            build_info = self._data.get("builds", {}).get(str(bn), {})
            build_dir = build_info.get("extraction_dir")
            if build_dir:
                return build_dir
        return self._data.get("extraction_dir") or ""

    @property
    def tc_source_dir(self):
        """TrinityCore source tree path."""
        return self._data.get("tc_source_dir") or ""

    @property
    def sniff_dir(self):
        """Directory containing packet sniff files."""
        return self._data.get("sniff_dir") or ""

    @property
    def db2_data_dir(self):
        """Directory containing DB2 client data files (dbfilesclient)."""
        return self._data.get("db2_data_dir") or ""

    @property
    def known_rvas(self):
        return self._data.get("known_rvas", {})

    @property
    def dispatch_range(self):
        return self._data.get("dispatch_range", {})

    @property
    def serializer_rvas(self):
        """Return known serializer function RVAs."""
        # Check for explicit serializer_rvas section first
        explicit = self._data.get("serializer_rvas")
        if explicit:
            return explicit
        # Fall back to building from known_rvas
        rvas = self.known_rvas
        return {
            "WriteUInt32": rvas.get("write_uint32"),
            "WriteUInt8": rvas.get("write_uint8"),
            "WriteFloat": rvas.get("write_float"),
            "WriteObjectGuid": rvas.get("write_object_guid"),
            "WriteBits": rvas.get("write_bits"),
            "FlushBits": rvas.get("flush_bits"),
        }

    @property
    def is_configured(self):
        """True if at least one build entry has an extraction_dir set."""
        for _build_str, info in self._data.get("builds", {}).items():
            if isinstance(info, dict) and info.get("extraction_dir"):
                return True
        return False

    # ------------------------------------------------------------------
    # Address conversion helpers
    # ------------------------------------------------------------------

    def rva_to_ea(self, rva):
        """Convert an RVA to an effective address using the current image base."""
        if isinstance(rva, str):
            rva = int(rva, 16) if rva.startswith("0x") else int(rva)
        return self.image_base + rva

    def ea_to_rva(self, ea):
        """Convert an effective address to an RVA."""
        return ea - self.image_base


# ---------------------------------------------------------------------------
# Singleton — import as: from tc_wow_analyzer.core.config import cfg
# ---------------------------------------------------------------------------
cfg = PluginConfig()
