# -*- coding: utf-8 -*-
"""dump_fam45_readers.py -- die Reader/Dispatch-Funktionen der offenen 0x45-Opcodes."""
import json
import idaapi, idc, idautils, ida_bytes, ida_funcs, ida_name, ida_hexrays
BASE = 0x7FF780FD0000
OUT  = "C:/dumps/famwire/fam_45_readers.json"
NAMES = open("C:/dumps/fam45_targets.txt").read().strip().split(",")
def dec(ea):
    try:
        cf = ida_hexrays.decompile(ea); return str(cf) if cf else None
    except Exception as e: return "/* FAIL %s */" % e
R = {}
for nm in NAMES:
    nm = nm.strip()
    if not nm: continue
    ea = ida_name.get_name_ea(idaapi.BADADDR, nm)
    if ea == idaapi.BADADDR: R[nm] = {"err": "nf"}; continue
    f = ida_funcs.get_func(ea)
    if not f: R[nm] = {"err": "nofunc"}; continue
    sz = f.end_ea - f.start_ea
    R[nm] = {"rva": "0x%X" % (ea - BASE), "size": sz,
             "code": (dec(ea) or "")[:12000] if sz < 24000 else "TOO_BIG"}
json.dump(R, open(OUT, "w"), indent=1)
print("WROTE", OUT, len(R))
idc.qexit(0)
