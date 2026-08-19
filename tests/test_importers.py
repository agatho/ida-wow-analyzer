"""
Run the AutoDump importers against REAL dump files, without IDA.

Static checks prove the code is well-formed; this proves it actually reads the
data. It exercises every registered importer against whatever
``wow_*_<build>.json`` files are present and reports the row counts, so a
degenerate AutoDump output (69382 shipped several) is visible as a number
rather than as silence.

Usage:
    python tests/test_importers.py                     # auto-detect dumps dir
    python tests/test_importers.py C:\\dumps 69382
Exit code is non-zero if an importer raises.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

from tests import ida_stub  # noqa: E402


def _detect(dumps_dir):
    """Newest build number present in *dumps_dir*, or None."""
    import re
    builds = set()
    for name in os.listdir(dumps_dir):
        match = re.search(r"_(\d{5,6})\.json$", name)
        if match:
            builds.add(int(match.group(1)))
    return max(builds) if builds else None


def _image_base(dumps_dir, build):
    """Image base from wow_debug_<build>.json, so the stub matches the data."""
    path = os.path.join(dumps_dir, f"wow_debug_{build}.json")
    if not os.path.isfile(path):
        return ida_stub.IMAGE_BASE
    try:
        with open(path, encoding="utf-8") as handle:
            header = (json.load(handle) or {}).get("pe_header") or {}
        base = header.get("image_base")
        return int(base, 16) if isinstance(base, str) else base
    except Exception:
        return ida_stub.IMAGE_BASE


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    dumps_dir = argv[0] if argv else (
        r"C:\dumps" if os.name == "nt" else "/mnt/dumps")
    if not os.path.isdir(dumps_dir):
        print(f"dumps dir not found: {dumps_dir}")
        return 2

    build = int(argv[1]) if len(argv) > 1 else _detect(dumps_dir)
    if not build:
        print(f"no wow_*_<build>.json in {dumps_dir}")
        return 2

    base = _image_base(dumps_dir, build)
    print(f"dumps dir : {dumps_dir}")
    print(f"build     : {build}")
    print(f"image base: 0x{base:X}\n")

    ida_stub.install(image_base=base)

    from tc_wow_analyzer.core.db import KnowledgeDB
    from tc_wow_analyzer.core.config import cfg
    from tc_wow_analyzer.core import utils
    import tc_wow_analyzer.batch.importer as importer

    cfg.set("builds", str(build), "image_base", base)
    cfg.set("builds", str(build), "extraction_dir", dumps_dir)
    cfg.set("extraction_dir", dumps_dir)
    cfg.set("build_number", build)
    cfg.invalidate_build_cache()
    utils.set_build_number(build)

    db_path = os.path.join(
        os.environ.get("TMPDIR", "/tmp"), f"tc_import_test_{build}.db")
    if os.path.isfile(db_path):
        os.remove(db_path)
    db = KnowledgeDB(db_path)
    db.open()

    class _Session:
        pass

    session = _Session()
    session.db = db
    session.cfg = cfg

    # Same list run_import() uses, so this cannot drift from production.
    names = [
        ("wow_offsets", importer._import_offsets),
        ("wow_functions", importer._import_functions),
        ("wow_jam_messages", importer._import_jam_types),
        ("wow_rtti", importer._import_rtti),
        ("wow_ctor_dtor", importer._import_ctor_dtor),
        ("wow_globals", importer._import_globals),
        ("wow_enums", importer._import_enums),
        ("wow_raw_opcode_table", importer._import_raw_opcode_table),
        ("wow_spell_effects", importer._import_spell_effects),
        ("wow_string_enums", importer._import_string_enums),
        ("wow_switch_enums", importer._import_switch_enums),
        ("wow_cvars", importer._import_cvars),
        ("wow_event_registrations", importer._import_event_registrations),
        ("wow_lua_metatables", importer._import_lua_metatables),
    ]

    failures = 0
    print(f"{'source':<28} {'rows':>10}  note")
    print("-" * 64)
    for stem, func in names:
        path = os.path.join(dumps_dir, f"{stem}_{build}.json")
        if not os.path.isfile(path):
            print(f"{stem:<28} {'-':>10}  file absent")
            continue
        size = os.path.getsize(path)
        try:
            count = func(session, path)
        except Exception as exc:
            failures += 1
            print(f"{stem:<28} {'FAIL':>10}  {type(exc).__name__}: {exc}")
            import traceback
            traceback.print_exc()
            continue
        note = "" if count else f"EMPTY ({size:,} B on disk)"
        print(f"{stem:<28} {count:>10,}  {note}")

    print("\nResulting table counts:")
    for table, count in sorted(db.get_stats().items()):
        if count:
            print(f"  {table:<20} {count:>10,}")

    db.close()
    print(f"\ntest database: {db_path}")
    if failures:
        print(f"{failures} importer(s) raised.")
        return 1
    print("All importers ran.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
