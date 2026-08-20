# -*- coding: utf-8 -*-
"""find_small_dispatchers.py v2 -- Vtable-Basis korrekt bestimmen.
Vom GetMsgId-Slot rueckwaerts in 8-Byte-Schritten; die naechstgelegene Adresse
mit einer CODE-Xref ist die Vtable-Basis, die der Dispatcher laedt.
"""
import json
import idaapi, idc, idautils, ida_bytes, ida_funcs, ida_name, ida_hexrays

BASE = 0x7FF780FD0000
OUT  = "C:/dumps/small_dispatchers2.json"
THUNKS = [0x6133C0, 0x6133D0, 0x6133E0, 0x6133F0, 0x613400, 0x752DE0]

def dec(ea):
    try:
        cf = ida_hexrays.decompile(ea); return str(cf) if cf else None
    except Exception as e: return "FAIL %s" % e

R = {"thunks": {}, "dispatchers": {}}
disp_set = set()
for t in THUNKS:
    tea = BASE + t
    ent = {"thunk": "0x%X" % t, "code": dec(tea), "candidates": []}
    for x in idautils.XrefsTo(tea, 0):
        slot = x.frm
        for back in range(0, 40):
            cand = slot - 8 * back
            refs = []
            for y in idautils.XrefsTo(cand, 0):
                f = ida_funcs.get_func(y.frm)
                if f and idc.is_code(ida_bytes.get_full_flags(y.frm)):
                    refs.append({"from": "0x%X" % (y.frm - BASE),
                                 "func": "0x%X" % (f.start_ea - BASE),
                                 "fname": ida_name.get_name(f.start_ea),
                                 "size": f.end_ea - f.start_ea})
            if refs:
                ent["candidates"].append({"slot": "0x%X" % (slot - BASE),
                                          "vtbl": "0x%X" % (cand - BASE),
                                          "slot_index": back, "refs": refs})
                for r in refs: disp_set.add((r["func"], r["fname"]))
                break
    R["thunks"]["0x%X" % t] = ent

for fr, fn in sorted(disp_set):
    fea = BASE + int(fr, 16)
    f = ida_funcs.get_func(fea)
    if f and (f.end_ea - f.start_ea) < 60000:
        R["dispatchers"][fr] = {"name": fn, "size": f.end_ea - f.start_ea,
                                "code": (dec(fea) or "")[:80000]}
json.dump(R, open(OUT, "w"), indent=1)
print("WROTE", OUT, len(R["dispatchers"]))
idc.qexit(0)
