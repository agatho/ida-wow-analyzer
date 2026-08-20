# -*- coding: utf-8 -*-
"""dump_handlers_w1.py -- Handler der offenen Welle-1-Opcodes + zweite Hook-Tabelle."""
import json, collections
import idaapi, idc, idautils, ida_bytes, ida_funcs, ida_name, ida_hexrays
BASE = 0x7FF780FD0000
OUT  = "C:/dumps/handlers_w1.json"
NAMES = open("C:/dumps/handlers_w1_list.txt").read().strip().split(",")

def dec(ea):
    try:
        cf = ida_hexrays.decompile(ea); return str(cf) if cf else None
    except Exception as e: return "FAIL %s" % e

R = {"handlers": {}, "table2": {}, "registrars2": {}}
for nm in NAMES:
    nm = nm.strip()
    if not nm: continue
    ea = ida_name.get_name_ea(idaapi.BADADDR, nm)
    if ea == idaapi.BADADDR:
        R["handlers"][nm] = {"err": "not found"}; continue
    f = ida_funcs.get_func(ea)
    R["handlers"][nm] = {"rva": "0x%X" % (ea - BASE),
                         "size": (f.end_ea - f.start_ea) if f else None,
                         "code": (dec(ea) or "")[:20000]}

# zweite Hook-Tabelle (Stride 0x50, Bereich um 0x785370000)
w = collections.Counter()
for g in range(0x7FF785370000, 0x7FF785390000, 8):
    xr = list(idautils.XrefsTo(g, 0))
    if not xr: continue
    v = ida_bytes.get_qword(g)
    e = {"rva": "0x%X" % (g - BASE), "value": "0x%X" % v, "n": len(xr), "w": [], "r": []}
    if v:
        f = ida_funcs.get_func(v)
        e["target"] = ida_name.get_name(f.start_ea) if f else None
    for x in xr:
        f = ida_funcs.get_func(x.frm)
        rec = {"from": "0x%X" % (x.frm - BASE), "fn": ida_name.get_name(f.start_ea) if f else None}
        (e["w"] if x.type == 2 else e["r"]).append(rec)
        if x.type == 2 and f: w[f.start_ea] += 1
    R["table2"]["0x%X" % (g - BASE)] = e
for ea, cnt in w.most_common(25):
    f = ida_funcs.get_func(ea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    R["registrars2"]["0x%X" % (ea - BASE)] = {"name": ida_name.get_name(ea), "size": sz, "writes": cnt,
                                              "code": (dec(ea) or "")[:150000] if sz < 150000 else "TOO_BIG"}
json.dump(R, open(OUT, "w"), indent=1)
print("WROTE", OUT, len(R["handlers"]), len(R["table2"]), len(R["registrars2"]))
idc.qexit(0)
