# -*- coding: utf-8 -*-
"""dump_cmsg_family.py -- Sendeseite: CMSG-Familien ueber ihre Immediate-Sites aufschluesseln.

Pro Familie: alle Opcode-Immediate-Stellen -> enthaltende Funktion -> dekompilieren.
Die 10-Byte-Funktionen sind GetMsgId-Vtable-Slots; von dort ueber den Vtable-Slot
zur Vtable-Basis und zu den Referenzierern (Sender/Serializer).
"""
import json, os, re
import idaapi, idc, idautils, ida_bytes, ida_funcs, ida_name, ida_hexrays

BASE = 0x7FF780FD0000
OUTDIR = "C:/dumps/cmsgwire"
SITES = json.load(open("C:/dumps/cmsg_immediate_sites_69382.json"))
FAMS = os.environ.get("TC_CFAMS", "0x2E,0x2C,0x41,0x44,0x2A,0x2D").split(",")
MAXF = 40000

try: os.makedirs(OUTDIR)
except Exception: pass

def dec(ea):
    try:
        cf = ida_hexrays.decompile(ea); return str(cf) if cf else None
    except Exception as e: return "/* FAIL %s */" % e

NAMERE = re.compile(r'\b(sub_7FF7[0-9A-F]+|Jam\w+|Send_\w+|Handle\w+)\s*\(')

for fam in FAMS:
    fam = fam.strip()
    meta = {"family": fam, "opcodes": {}, "functions": []}
    chunks = []
    done = set()
    todo = []
    for op, addrs in sorted(SITES.items()):
        if not op.startswith(fam): continue
        ent = []
        for a in addrs:
            ea = BASE + int(a, 16)
            f = ida_funcs.get_func(ea)
            if not f: continue
            sz = f.end_ea - f.start_ea
            ent.append({"site": a, "func": "0x%X" % (f.start_ea - BASE),
                        "fn": ida_name.get_name(f.start_ea), "size": sz})
            if sz <= 4000:
                todo.append((f.start_ea, 0))
        meta["opcodes"][op] = ent
    # Vtable-Weg: 10-Byte-Thunks -> Slot -> Basis -> Referenzierer
    for op, ent in meta["opcodes"].items():
        for e in ent:
            if e["size"] != 10: continue
            tea = BASE + int(e["func"], 16)
            for x in idautils.XrefsTo(tea, 0):
                slot = x.frm
                for back in range(0, 40):
                    cand = slot - 8 * back
                    refs = [y.frm for y in idautils.XrefsTo(cand, 0)
                            if idc.is_code(ida_bytes.get_full_flags(y.frm))]
                    if refs:
                        e["vtbl"] = "0x%X" % (cand - BASE)
                        e["vtbl_refs"] = []
                        for r in refs[:8]:
                            rf = ida_funcs.get_func(r)
                            if rf:
                                e["vtbl_refs"].append({"func": "0x%X" % (rf.start_ea - BASE),
                                                       "fn": ida_name.get_name(rf.start_ea),
                                                       "size": rf.end_ea - rf.start_ea})
                                if rf.end_ea - rf.start_ea <= MAXF:
                                    todo.append((rf.start_ea, 0))
                        break
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
        meta["functions"].append({"name": nm, "rva": "0x%X" % (f.start_ea - BASE),
                                  "size": sz, "depth": d})
        if d < 2:
            for cand in set(NAMERE.findall(code)):
                cea = ida_name.get_name_ea(idaapi.BADADDR, cand)
                if cea == idaapi.BADADDR or cea in done: continue
                cf = ida_funcs.get_func(cea)
                if cf and cf.end_ea - cf.start_ea <= 6000:
                    todo.append((cea, d + 1))
        if len(done) > 700: break
    open("%s/cmsg_%s_decomp.txt" % (OUTDIR, fam[2:]), "w").write("".join(chunks))
    json.dump(meta, open("%s/cmsg_%s_meta.json" % (OUTDIR, fam[2:]), "w"), indent=1)
    print("FAM", fam, len(meta["opcodes"]), "opcodes,", len(meta["functions"]), "funcs")
print("DONE")
idc.qexit(0)
