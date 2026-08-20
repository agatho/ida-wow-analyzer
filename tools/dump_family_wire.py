# -*- coding: utf-8 -*-
"""
dump_family_wire.py -- generischer Familien-Extraktor (Build 12.1.0.69382)

Fuer jede angegebene Client-SMSG-Familie:
  * Dispatcher finden (SMSG_Dispatch_fam_XX)
  * Dispatcher dekompilieren (enthaelt alle Case-Bodies)
  * alle aufgerufenen Reader transitiv dekompilieren (Tiefe 3)
  * JAM-Typnamen, Handler-Hook-Globals, Stringliterale einsammeln
Ausgabe je Familie: C:/dumps/famwire/fam_XX_decomp.txt + fam_XX_meta.json
"""
import os, re, json
import idaapi, idc, idautils, ida_bytes, ida_funcs, ida_name, ida_hexrays

BASE = 0x7FF780FD0000
OUTDIR = "C:/dumps/famwire"
FAMS = os.environ.get("TC_FAMS", "0x49,0x65,0x67,0x64,0x4B,0x5A,0x63,0x68,0x4C,0x51,0x4A,0x4F,0x5E").split(",")
MAXDEPTH = 3
MAXFUNC  = 30000        # Byte-Obergrenze pro dekompilierter Funktion
BUDGET   = 900          # max. Funktionen pro Familie

try: os.makedirs(OUTDIR)
except Exception: pass

def dec(ea):
    try:
        cf = ida_hexrays.decompile(ea)
        return str(cf) if cf else None
    except Exception as e:
        return "/* DECOMP_FAIL %s */" % e

NAMERE = re.compile(r'\b(sub_7FF7[0-9A-F]+|Jam\w+|Send_\w+|Read_\w+|Handle\w+|SMSG_\w+)\s*\(')
STRRE  = re.compile(r'WowGetRawTypeName<([^>]+)>')
GLOBRE = re.compile(r'\b(qword_7FF7[0-9A-F]+)\b')

summary = {}
for famhex in FAMS:
    famhex = famhex.strip()
    if not famhex: continue
    dispname = "SMSG_Dispatch_fam_%s" % famhex[2:].upper()
    ea = ida_name.get_name_ea(idaapi.BADADDR, dispname)
    if ea == idaapi.BADADDR:
        summary[famhex] = {"error": "dispatcher %s nicht gefunden" % dispname}
        continue
    f = ida_funcs.get_func(ea)
    meta = {"family": famhex, "dispatcher": "0x%X" % (ea - BASE),
            "dispatcher_size": f.end_ea - f.start_ea if f else None,
            "functions": [], "jam_types": {}, "hook_globals": {}, "strings": []}
    todo = [(ea, 0)]
    done = set()
    chunks = []
    while todo and len(done) < BUDGET:
        cur, d = todo.pop(0)
        if cur in done: continue
        done.add(cur)
        fn = ida_funcs.get_func(cur)
        if not fn: continue
        size = fn.end_ea - fn.start_ea
        if size > MAXFUNC and d > 0: continue
        code = dec(fn.start_ea) or ""
        nm = ida_name.get_name(fn.start_ea)
        chunks.append("\n/* ===== %s  @0x%X  (%d bytes, depth %d) ===== */\n%s\n"
                      % (nm, fn.start_ea - BASE, size, d, code))
        meta["functions"].append({"name": nm, "rva": "0x%X" % (fn.start_ea - BASE),
                                  "size": size, "depth": d})
        for t in STRRE.findall(code):
            meta["jam_types"][t] = meta["jam_types"].get(t, 0) + 1
        for gname in set(GLOBRE.findall(code)):
            gea = ida_name.get_name_ea(idaapi.BADADDR, gname)
            if gea != idaapi.BADADDR:
                meta["hook_globals"][gname] = {
                    "rva": "0x%X" % (gea - BASE),
                    "value": "0x%X" % ida_bytes.get_qword(gea),
                    "xrefs": len(list(idautils.XrefsTo(gea, 0)))}
        if d < MAXDEPTH:
            for cand in set(NAMERE.findall(code)):
                cea = ida_name.get_name_ea(idaapi.BADADDR, cand)
                if cea == idaapi.BADADDR or cea in done: continue
                cf = ida_funcs.get_func(cea)
                if not cf: continue
                if cf.end_ea - cf.start_ea > MAXFUNC: continue
                todo.append((cea, d + 1))
    open("%s/fam_%s_decomp.txt" % (OUTDIR, famhex[2:].upper()), "w").write("".join(chunks))
    json.dump(meta, open("%s/fam_%s_meta.json" % (OUTDIR, famhex[2:].upper()), "w"), indent=1)
    summary[famhex] = {"funcs": len(meta["functions"]), "jam_types": len(meta["jam_types"]),
                       "dispatcher": meta["dispatcher"]}
    print("FAM", famhex, summary[famhex])

json.dump(summary, open("%s/_summary.json" % OUTDIR, "w"), indent=1)
print("DONE", json.dumps(summary))
idc.qexit(0)
