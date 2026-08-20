# -*- coding: utf-8 -*-
"""find_opcode_sites.py -- findet Handler kleiner Familien ohne Sprungtabelle.

Sucht die Opcode-Immediates im Code (if/else-Ketten statt switch) und
dekompiliert die enthaltenden Funktionen.
"""
import json, re
import idaapi, idc, idautils, ida_bytes, ida_funcs, ida_name, ida_hexrays, ida_search

BASE = 0x7FF780FD0000
OUT  = "C:/dumps/opcode_sites.json"
TARGETS = []
for fam in (0x46, 0x6A, 0x52, 0x53, 0x61, 0x62, 0x66, 0x69, 0x50, 0x5B, 0x5D):
    for idx in range(0, 8):
        TARGETS.append((fam << 16) | idx)

def dec(ea):
    try:
        cf = ida_hexrays.decompile(ea); return str(cf) if cf else None
    except Exception as e: return "FAIL %s" % e

# Immediates im Code suchen
hits = {}
for seg in idautils.Segments():
    s, e = seg, idc.get_segm_end(seg)
    if idc.get_segm_name(seg) not in (".text", "text", "CODE"): 
        pass
    ea = s
    while ea < e and ea != idaapi.BADADDR:
        ea = ida_bytes.next_head(ea, e)
        if ea == idaapi.BADADDR: break
        for op in range(3):
            try: v = idc.get_operand_value(ea, op)
            except Exception: break
            if v in TARGETS and idc.get_operand_type(ea, op) == idaapi.o_imm:
                f = ida_funcs.get_func(ea)
                key = "0x%06X" % v
                hits.setdefault(key, []).append({
                    "ea": "0x%X" % (ea - BASE),
                    "func": "0x%X" % (f.start_ea - BASE) if f else None,
                    "fname": ida_name.get_name(f.start_ea) if f else None,
                    "size": (f.end_ea - f.start_ea) if f else None})

funcs = {}
for k, lst in hits.items():
    for h in lst:
        if h["func"] and h["func"] not in funcs:
            fea = BASE + int(h["func"], 16)
            f = ida_funcs.get_func(fea)
            if f and (f.end_ea - f.start_ea) < 40000:
                funcs[h["func"]] = {"name": h["fname"], "size": f.end_ea - f.start_ea,
                                    "code": (dec(fea) or "")[:60000]}

json.dump({"hits": hits, "funcs": funcs}, open(OUT, "w"), indent=1)
print("WROTE", OUT, len(hits), "opcodes,", len(funcs), "functions")
idc.qexit(0)
