# -*- coding: utf-8 -*-
"""dump_primitives.py -- die Lese-/Schreibprimitiven des JAM-Streams vollstaendig auflisten.

Dekompiliert jede Funktion in den drei RVA-Baendern, in denen die Primitive liegen:
  0x35AF000..0x35B0400  CDataStore-Lesen/Schreiben
  0x5D4900..0x5D5500    Bit-Sektionen (ReadBits/WriteBits-Leiter)
  0x613600..0x613C00    24-Bit-Laengen
"""
import os
import idaapi, idc, idautils, ida_funcs, ida_name, ida_hexrays

BASE = 0x7FF780FD0000
OUT  = "C:/dumps/cmsgwire"
BANDS = [(0x35AF000, 0x35B0400), (0x5D4900, 0x5D5500), (0x613600, 0x613C00)]

try: os.makedirs(OUT)
except Exception: pass

def dec(ea):
    try:
        cf = ida_hexrays.decompile(ea)
        return str(cf) if cf else None
    except Exception as e:
        return "/* FAIL %s */" % e

chunks, n = [], 0
for lo, hi in BANDS:
    ea = BASE + lo
    end = BASE + hi
    f = ida_funcs.get_func(ea)
    cur = f.start_ea if f else idc.get_next_func(ea)
    while cur != idaapi.BADADDR and cur < end:
        fn = ida_funcs.get_func(cur)
        if fn and fn.end_ea - fn.start_ea <= 3000:
            chunks.append("\n/* ===== %s  @0x%X  (%d bytes) ===== */\n%s\n"
                          % (ida_name.get_name(fn.start_ea), fn.start_ea - BASE,
                             fn.end_ea - fn.start_ea, dec(fn.start_ea) or ""))
            n += 1
        cur = idc.get_next_func(cur)

open(OUT + "/primitives_decomp.txt", "w").write("".join(chunks))
print("PRIMITIVES", n, "functions")
print("DONE")
idc.qexit(0)
