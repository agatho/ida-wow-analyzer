"""
Offline test of the opcode-dispatch recovery core, against a real dump.

Proves the static-dump recovery finds the dispatch tables the AutoDump
extractor missed, without IDA and without injection.

    python tests/test_dispatch_recovery.py /mnt/dumps 69382
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

from tests import ida_stub  # noqa: E402
ida_stub.install()

from tc_wow_analyzer.analyzers import opcode_dispatch_recovery as odr  # noqa: E402


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    dumps = argv[0] if argv else "/mnt/dumps"
    build = int(argv[1]) if len(argv) > 1 else 69382
    dump = os.path.join(dumps, "wow_dump.bin")
    if not os.path.isfile(dump):
        print("dump not found:", dump)
        return 2

    with open(dump, "rb") as handle:
        data = handle.read()
    image_base, sections = odr.parse_pe_sections(data)
    print("image base 0x%X" % image_base)
    text, rdata = sections[".text"], sections[".rdata"]

    # function starts straight from pdata (same source the analyzer uses)
    import json
    pdata = os.path.join(dumps, "wow_pdata_%d.json" % build)
    starts = set()
    if os.path.isfile(pdata):
        with open(pdata, encoding="utf-8") as handle:
            pj = json.load(handle)
        for f in pj.get("functions") or pj.get("entries") or []:
            r = f.get("start_rva", f.get("rva", f.get("begin")))
            if isinstance(r, str):
                r = int(r, 16)
            if isinstance(r, int):
                starts.add(r)
    print("function starts:", len(starts))

    tables = odr.find_dispatch_tables(data, image_base, text, rdata, starts)
    print("candidate tables:", len(tables))
    total = sum(t["count"] for t in tables)
    print("total entries across candidates:", total)
    print("\n%-14s %6s %8s %s" % ("table_rva", "count", "stride", "first target"))
    for t in tables[:10]:
        stride = ("0x%X" % t["stride"]) if t["stride"] is not None else "irregular"
        first = ("0x%X" % t["targets"][0]) if t["targets"] else "-"
        print("0x%-12X %6d %8s %s" % (t["table_rva"], t["count"], stride, first))

    assert tables, "no dispatch tables recovered"
    assert total > 1000, "suspiciously few entries: %d" % total
    print("\nOK: dispatch tables recoverable offline from the static dump.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
