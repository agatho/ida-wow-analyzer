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
        "provider": "claude-cli",
        "model": "sonnet",
        "max_tokens": 8192,
        "timeout": 180,
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
        self._detected_build = None  # cache for build_number (see property)
        self._load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self):
        """Load config from multiple sources with increasing priority."""

        # Priority 2 first: the plugin-level config is where `pipeline_dir`
        # actually comes from. Reading `pipeline_dir` out of `_data` before any
        # file had been merged meant it was ALWAYS None on the constructor run,
        # so the documented "priority 1" source never applied.
        module_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        plugin_cfg = os.path.join(module_dir, "tc_wow_config.json")
        self._merge_file(plugin_cfg)

        # Priority 3: Config next to the IDB (per-database overrides)
        idb_path = self._idb_path()
        if idb_path:
            idb_dir = os.path.dirname(idb_path)
            idb_cfg = os.path.join(idb_dir, "tc_wow_config.json")
            self._merge_file(idb_cfg)

        # Priority 1 (lowest, applied last only for keys still unset): the
        # pipeline config, now that pipeline_dir is known.
        pipeline_dir = self._data.get("pipeline_dir")
        if pipeline_dir:
            pipeline_cfg = os.path.join(pipeline_dir, "pipeline_config.json")
            existing = json.loads(json.dumps(self._data))
            self._merge_file(pipeline_cfg)
            # keys already set by the higher-priority files win
            self._deep_merge(self._data, existing)

        # NOTE: db_path is NOT frozen here. It is computed by the property so
        # that it always carries the *current* build number — see `db_path`.

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
            # save() writes the fully MERGED config, so a build_number inherited
            # from the plugin-level file used to be copied into the IDB-local
            # file too and outlived any cleanup at the source. Persist the
            # *validated* build instead, and never persist a stale db_path.
            detected = self.build_number
            if detected:
                out["build_number"] = detected
            else:
                out.pop("build_number", None)
            out.pop("db_path", None)
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
        """Path to the per-BUILD SQLite knowledge database.

        The path carries the build number: ``wow_dump.bin.69382.tc_wow.db``.

        WHY: AutoDump always overwrites ``wow_dump.bin`` (and therefore the
        ``.i64``), so a build-agnostic name meant one single database served
        every build ever analysed. None of `functions`/`opcodes`/`vtables`/
        `strings` carries a build column, so 12.0.5 EAs and 12.1.0 EAs ended up
        side by side, unmarked — and the many
        ``if db.count(t) > 0: return "already in DB"`` early-outs then reported
        the *previous* build's addresses as a fresh, successful extraction.

        An explicit ``db_path`` in the config still wins, but only if it already
        refers to this build; a stale one is ignored with a warning rather than
        silently reused.
        """
        idb_path = self._idb_path()
        build = self.build_number
        explicit = self._data.get("db_path")

        if explicit:
            if not build or str(build) in os.path.basename(explicit):
                return explicit
            print(f"[TC-WoW] Config: ignoring db_path {explicit!r} — it does "
                  f"not belong to build {build}. Using the per-build path "
                  f"instead; set db_path explicitly to override.")

        if not idb_path:
            return explicit or ""

        base = os.path.splitext(idb_path)[0]
        return f"{base}.{build}.tc_wow.db" if build else base + ".tc_wow.db"

    @property
    def image_base(self):
        """Image base for the currently loaded IDB (page-aligned)."""
        import ida_ida
        return ida_ida.inf_get_min_ea() & ~0xFFF

    @property
    def build_number(self):
        """Build number of the CURRENTLY LOADED image.

        Detection order is deliberate: the image base of the open IDB decides,
        and a configured ``build_number`` is only a fallback.

        WHY THIS ORDER: it used to be the other way round. ``tc_wow_config.json``
        carried ``"build_number": 67186``, so opening the freshly built
        12.1.0.69382 IDB still reported 67186 — which made
        ``dumps_build_path()`` and ``autodump_candidates()`` load
        ``wow_*_67186.json`` and apply 12.0.5 RVAs to the 12.1 image. Silently.
        An explicit value that contradicts the image base is now a loud warning,
        not the answer.
        """
        if self._detected_build is not None:
            return self._detected_build

        explicit = self._data.get("build_number")
        try:
            explicit = int(explicit) if explicit else 0
        except (TypeError, ValueError):
            explicit = 0

        builds = self._data.get("builds", {})
        current_base = None
        try:
            current_base = self.image_base
        except Exception:
            pass  # no IDB open yet (config singleton built at import time)

        matched = 0
        if current_base:
            for build_str, info in builds.items():
                if isinstance(info, dict) and info.get("image_base") == current_base:
                    try:
                        matched = int(build_str)
                    except (TypeError, ValueError):
                        continue
                    break

        if matched:
            if explicit and explicit != matched:
                print(f"[TC-WoW] Config WARNING: build_number={explicit} in the "
                      f"config contradicts the loaded image base "
                      f"0x{current_base:X}, which belongs to build {matched}. "
                      f"Using {matched}. Fix build_number to silence this.")
            self._detected_build = matched
            return matched

        if explicit:
            expected = builds.get(str(explicit), {}).get("image_base") \
                if isinstance(builds.get(str(explicit)), dict) else None
            if current_base and expected and expected != current_base:
                print(f"[TC-WoW] Config WARNING: build {explicit} is configured "
                      f"with image base 0x{expected:X} but the loaded image is "
                      f"at 0x{current_base:X}. Build-specific dumps and RVAs "
                      f"will NOT match this binary.")
            elif current_base and not expected:
                print(f"[TC-WoW] Config: using configured build_number "
                      f"{explicit} (no image_base recorded for it — add one "
                      f"under builds[\"{explicit}\"].image_base so mismatches "
                      f"can be detected).")
            self._detected_build = explicit
            return explicit

        if current_base:
            print(f"[TC-WoW] Config WARNING: unknown build. No builds[] entry "
                  f"matches image base 0x{current_base:X} and no build_number "
                  f"is set. Build-scoped lookups (AutoDump files, yields, "
                  f"regression detection) are DISABLED until this is fixed.")
        self._detected_build = 0
        return 0

    def invalidate_build_cache(self):
        """Forget the detected build (call after editing builds/build_number)."""
        self._detected_build = None

    @property
    def dumps_dir(self):
        """Directory holding the AutoDump artifacts for the current build.

        Replaces the hardcoded ``C:\\dumps`` in core/utils.py, which made every
        build-resolved input path machine-specific.
        """
        bn = self.build_number
        if bn:
            info = self._data.get("builds", {}).get(str(bn), {})
            if isinstance(info, dict) and info.get("extraction_dir"):
                return info["extraction_dir"]
        return self._data.get("extraction_dir") or r"C:\dumps"

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

    def _build_scoped(self, key, default):
        """Read ``builds.<build>.<key>``, falling back to the global section.

        WHY: RVAs are build-specific by definition. ``known_rvas`` and
        ``dispatch_range`` were stored globally and then re-applied through
        ``rva_to_ea()`` against the NEXT build's image base — pointing the
        "main dispatcher" at whatever happens to live at that offset now.
        Build-scoped values are preferred; the global section is kept as a
        fallback so existing configs keep working.
        """
        bn = self.build_number
        if bn:
            info = self._data.get("builds", {}).get(str(bn))
            if isinstance(info, dict) and isinstance(info.get(key), dict) \
                    and info[key]:
                return info[key]
        return self._data.get(key, default)

    def set_build_scoped(self, key, value):
        """Write ``builds.<build>.<key>`` (falls back to global if build is 0)."""
        bn = self.build_number
        if bn:
            self.set("builds", str(bn), key, value)
        else:
            self.set(key, value)

    @property
    def known_rvas(self):
        return self._build_scoped("known_rvas", {})

    @property
    def dispatch_range(self):
        return self._build_scoped("dispatch_range", {})

    @property
    def serializer_rvas(self):
        """Return known serializer function RVAs."""
        # Build-scoped section first, then the global one.
        explicit = self._build_scoped("serializer_rvas", {})
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
        """True if any extraction directory is known.

        Used to gate the "please configure me" first-run banner, which used to
        show forever whenever only the global `extraction_dir` was set.
        """
        if self._data.get("extraction_dir"):
            return True
        for _build_str, info in self._data.get("builds", {}).items():
            if isinstance(info, dict) and info.get("extraction_dir"):
                return True
        return False

    # ------------------------------------------------------------------
    # Address conversion helpers
    # ------------------------------------------------------------------

    def rva_to_ea(self, rva):
        """Convert an RVA to an effective address using the current image base.

        Accepts int, "0x1D9E00" and bare "1D9E00" -- AutoDump JSON mixes the
        prefixed and unprefixed forms, and the old int(rva) path raised
        ValueError on the latter.
        """
        if isinstance(rva, str):
            text = rva.strip()
            if text.lower().startswith("0x"):
                rva = int(text, 16)
            else:
                try:
                    rva = int(text)
                except ValueError:
                    rva = int(text, 16)
        return self.image_base + rva

    def ea_to_rva(self, ea):
        """Convert an effective address to an RVA."""
        return ea - self.image_base


# ---------------------------------------------------------------------------
# Singleton — import as: from tc_wow_analyzer.core.config import cfg
# ---------------------------------------------------------------------------
cfg = PluginConfig()
