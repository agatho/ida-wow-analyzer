# -*- coding: utf-8 -*-
"""dump_subwriters.py -- gezielt einzelne Serializer-Funktionen dekompilieren.

Liest C:/dumps/subwriter_targets.json (Liste voller IDA-Namen oder VAs als "0x..."),
dekompiliert jede davon plus ihre Callees bis Tiefe 2 und schreibt
C:/dumps/cmsgwire/subwriters_decomp.txt.
"""
import json, os, re
import idaapi, idc, idautils, ida_funcs, ida_name, ida_hexrays

BASE = 0x7FF780FD0000
OUT  = "C:/dumps/cmsgwire"
TGT  = json.load(open("C:/dumps/subwriter_targets.json"))
MAXF = 20000

try: os.makedirs(OUT)
except Exception: pass

def dec(ea):
    try:
        cf = ida_hexrays.decompile(ea)
        return str(cf) if cf else None
    except Exception as e:
        return "/* FAIL %s */" % e

NAMERE = re.compile(r'\b(sub_7FF7[0-9A-F]{8})\(')

todo, done, chunks = [], set(), []
for t in TGT:
    ea = int(t, 16) if t.startswith("0x") else ida_name.get_name_ea(idaapi.BADADDR, t)
    if ea == idaapi.BADADDR:
        chunks.append("\n/* MISSING %s */\n" % t); continue
    todo.append((ea, 0))

while todo:
    cur, d = todo.pop(0)
    if cur in done: continue
    done.add(cur)
    f = ida_funcs.get_func(cur)
    if not f: continue
    sz = f.end_ea - f.start_ea
    if sz > MAXF: continue
    code = dec(f.start_ea) or ""
    nm = ida_name.get_name(f.start_ea)
    chunks.append("\n/* ===== %s  @0x%X  (%d bytes, depth %d) ===== */\n%s\n"
                  % (nm, f.start_ea - BASE, sz, d, code))
    if d < 2:
        for cand in set(NAMERE.findall(code)):
            cea = ida_name.get_name_ea(idaapi.BADADDR, cand)
            if cea == idaapi.BADADDR or cea in done: continue
            cf = ida_funcs.get_func(cea)
            if cf and cf.end_ea - cf.start_ea <= 8000:
                todo.append((cea, d + 1))
    if len(done) > 900: break

open(OUT + "/subwriters_decomp.txt", "w").write("".join(chunks))
print("SUBWRITERS", len(done), "functions")
print("DONE")
idc.qexit(0)
