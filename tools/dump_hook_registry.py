# -*- coding: utf-8 -*-
"""dump_hook_registry.py
1) Breiter Scan der Handler-Hook-Tabelle.
2) Alle Funktionen, die in diese Tabelle SCHREIBEN (die Registrare), dekompilieren.
   Daraus laesst sich global -> Handler aufloesen, auch wenn der Zeiger im Abbild NULL ist.
"""
import json, collections
import idaapi, idc, idautils, ida_bytes, ida_funcs, ida_name, ida_hexrays

BASE = 0x7FF780FD0000
OUT  = "C:/dumps/hook_registry.json"
LO, HI = 0x7FF7855F0000, 0x7FF785600000

def dec(ea):
    try:
        cf = ida_hexrays.decompile(ea); return str(cf) if cf else None
    except Exception as e: return "FAIL %s" % e

table = {}
writers = collections.Counter()
for g in range(LO, HI, 8):
    xr = list(idautils.XrefsTo(g, 0))
    if not xr: continue
    v = ida_bytes.get_qword(g)
    ent = {"rva": "0x%X" % (g - BASE), "value": "0x%X" % v, "n": len(xr), "readers": [], "writers": []}
    if v:
        f = ida_funcs.get_func(v)
        ent["target"] = ida_name.get_name(f.start_ea) if f else None
        ent["target_rva"] = "0x%X" % (v - BASE) if v > BASE else None
    for x in xr:
        f = ida_funcs.get_func(x.frm)
        nm = ida_name.get_name(f.start_ea) if f else None
        rec = {"from": "0x%X" % (x.frm - BASE), "fn": nm}
        if x.type == 2:
            ent["writers"].append(rec)
            if f: writers[f.start_ea] += 1
        else:
            ent["readers"].append(rec)
    table["0x%X" % (g - BASE)] = ent

regs = {}
for ea, cnt in writers.most_common(60):
    f = ida_funcs.get_func(ea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    regs["0x%X" % (ea - BASE)] = {"name": ida_name.get_name(ea), "size": sz, "writes": cnt,
                                  "code": (dec(ea) or "")[:200000] if sz < 200000 else "TOO_BIG"}

json.dump({"table": table, "registrars": regs}, open(OUT, "w"), indent=1)
print("WROTE", OUT, len(table), "slots,", len(regs), "registrars")
idc.qexit(0)
