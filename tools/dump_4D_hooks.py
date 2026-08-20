# -*- coding: utf-8 -*-
"""dump_4D_hooks.py -- GUID-Reader + Umfeld der Handler-Hook-Tabelle"""
import json
import idaapi, idc, idautils, ida_bytes, ida_funcs, ida_name, ida_hexrays

OUT  = "C:/dumps/fam4D_hooks.json"
BASE = 0x7FF780FD0000
R = {"guid_reader": {}, "hook_table": [], "writers": [], "dispatch_families": {}}

def dec(ea):
    try:
        cf = ida_hexrays.decompile(ea); return str(cf) if cf else None
    except Exception as e: return "FAIL %s" % e

gq = ida_bytes.get_qword

for r in (0x3602D40, 0x35AF230, 0x35AF0F0):
    ea = BASE + r
    f = ida_funcs.get_func(ea)
    R["guid_reader"]["0x%X" % r] = {"name": ida_name.get_name(ea),
        "size": (f.end_ea - f.start_ea) if f else None, "code": (dec(ea) or "")[:6000]}

# Hook-Tabelle: grosszuegig scannen
lo, hi = 0x7FF7855FD000, 0x7FF7855FE800
for g in range(lo, hi, 8):
    v = gq(g)
    xr = list(idautils.XrefsTo(g, 0))
    if not v and not xr: continue
    ent = {"va": "0x%X" % g, "rva": "0x%X" % (g - BASE), "value": "0x%X" % v,
           "n_xrefs": len(xr), "xrefs": []}
    for x in xr[:6]:
        f = ida_funcs.get_func(x.frm)
        ent["xrefs"].append({"from": "0x%X" % x.frm, "type": x.type,
                             "fname": ida_name.get_name(f.start_ea) if f else None})
    if v:
        f = ida_funcs.get_func(v)
        ent["target_fn"] = ida_name.get_name(f.start_ea) if f else None
        ent["target_sz"] = (f.end_ea - f.start_ea) if f else None
    R["hook_table"].append(ent)

# Schreibzugriffe (type 2 = dr_W) irgendwo im Bereich?
for g in range(lo, hi, 8):
    for x in idautils.XrefsTo(g, 0):
        if x.type in (2,):   # dr_W
            f = ida_funcs.get_func(x.frm)
            R["writers"].append({"target": "0x%X" % g, "from": "0x%X" % x.frm,
                                 "fname": ida_name.get_name(f.start_ea) if f else None})

# Vergleich: hat eine andere Familie ueberhaupt gesetzte Hooks?
# -> scanne die 23 Dispatcher-Funktionen auf 'qword_' Referenzen in .data
import re
try:
    fam = json.load(open("C:/dumps/family_switch_cases_69382.json"))
    keys = list(fam.keys())[:0]
except Exception:
    pass

with open(OUT, "w") as fh:
    json.dump(R, fh, indent=1)
print("WROTE", OUT, len(R["hook_table"]), "entries,", len(R["writers"]), "writers")
idc.qexit(0)
