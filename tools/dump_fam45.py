# -*- coding: utf-8 -*-
"""dump_fam45.py -- die Sammelfamilie 0x45 (903 Cases, 62 KB Dispatcher)."""
import os, re, json
import idaapi, idc, idautils, ida_bytes, ida_funcs, ida_name, ida_hexrays
BASE = 0x7FF780FD0000
OUTDIR = "C:/dumps/famwire"
def dec(ea):
    try:
        cf = ida_hexrays.decompile(ea); return str(cf) if cf else None
    except Exception as e: return "/* FAIL %s */" % e
ea = ida_name.get_name_ea(idaapi.BADADDR, "SMSG_Dispatch_fam_45")
f = ida_funcs.get_func(ea)
code = dec(f.start_ea) or ""
open("%s/fam_45_dispatcher.txt" % OUTDIR, "w").write(code)
# Hook-Globals je Case einsammeln
meta = {"dispatcher": "0x%X" % (f.start_ea - BASE), "size": f.end_ea - f.start_ea,
        "n_cases": len(re.findall(r'case (\d+):', code))}
json.dump(meta, open("%s/fam_45_meta.json" % OUTDIR, "w"), indent=1)
print("WROTE", meta)
idc.qexit(0)
