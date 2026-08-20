# -*- coding: utf-8 -*-
"""dump_4D_deep.py -- Tiefenanalyse Familie 0x4D, Build 12.1.0.69382 (IDA-EAs == echte VAs)"""
import json
import idaapi, idc, idautils, ida_bytes, ida_funcs, ida_name, ida_hexrays

OUT  = "C:/dumps/fam4D_deep.json"
BASE = 0x7FF780FD0000
def V(r): return BASE + r          # rva -> VA
def Rv(v): return v - BASE         # VA -> rva

R = {"base": "0x%X" % BASE, "vtables": {}, "handler_globals": {}, "registrars": {},
     "primitives": {}, "resizers": {}, "rtti_scan": [], "errors": []}

def dec(ea):
    try:
        cf = ida_hexrays.decompile(ea)
        return str(cf) if cf else None
    except Exception as e:
        return "DECOMP_FAIL: %s" % e

gq = ida_bytes.get_qword
gd = ida_bytes.get_dword
MAXR = 0x6E90000

def cstr(ea, n=192):
    b = ida_bytes.get_bytes(ea, n)
    if not b: return None
    return b.split(b"\x00")[0].decode("utf-8", "replace")

def demangle(m):
    try:
        return idc.demangle_name("??_7" + m[4:] + "6B@", 0x0EA3FFE7) or None
    except Exception:
        return None

def rtti_for_vtbl(vt):
    """vt = VA der ersten Vtable-Slot-Zelle"""
    try:
        col = gq(vt - 8)
        if not col or col < BASE or Rv(col) > MAXR: return None, None
        td_rva = gd(col + 12)
        if td_rva <= 0 or td_rva > MAXR: return None, None
        m = cstr(V(td_rva) + 16)
        if not m or not m.startswith(".?A"): return None, None
        return m, demangle(m)
    except Exception:
        return None, None

def fninfo(p, maxdec=300):
    if not p: return None
    f = ida_funcs.get_func(p)
    d = {"va": "0x%X" % p, "rva": "0x%X" % Rv(p) if p > BASE else None,
         "fn": ida_name.get_name(f.start_ea) if f else None,
         "sz": (f.end_ea - f.start_ea) if f else None}
    if f and (f.end_ea - f.start_ea) <= maxdec:
        d["code"] = dec(f.start_ea)
    return d

# --- 1) die 12 Message-Vtables ---
for vt in range(0x7FF784BC2B20, 0x7FF784BC2CE0, 0x28):
    m, d = rtti_for_vtbl(vt)
    ent = {"vtbl": "0x%X" % vt, "rva": "0x%X" % Rv(vt), "rtti": m, "demangled": d, "slots": []}
    for s in range(6):
        ent["slots"].append(fninfo(gq(vt + 8 * s)))
    R["vtables"]["0x%X" % Rv(vt)] = ent

# --- 2) Handler-Hook-Globals ---
regs = set()
for g in range(0x7FF7855FDC60, 0x7FF7855FDCC0, 8):
    e = {"va": "0x%X" % g, "rva": "0x%X" % Rv(g), "value": "0x%X" % gq(g), "xrefs": []}
    for x in idautils.XrefsTo(g, 0):
        f = ida_funcs.get_func(x.frm)
        fe = "0x%X" % f.start_ea if f else None
        e["xrefs"].append({"from": "0x%X" % x.frm, "type": x.type, "func": fe,
                           "fname": ida_name.get_name(f.start_ea) if f else None})
        if fe: regs.add(fe)
    R["handler_globals"]["0x%X" % Rv(g)] = e

for fe in sorted(regs):
    ea = int(fe, 16)
    f = ida_funcs.get_func(ea)
    cl = []
    for x in idautils.XrefsTo(ea, 0):
        cf = ida_funcs.get_func(x.frm)
        cl.append({"from": "0x%X" % x.frm,
                   "func": ("0x%X" % cf.start_ea) if cf else None,
                   "fname": ida_name.get_name(cf.start_ea) if cf else None})
    R["registrars"][fe] = {"name": ida_name.get_name(ea),
                           "rva": "0x%X" % Rv(ea) if ea > BASE else None,
                           "size": (f.end_ea - f.start_ea) if f else None,
                           "code": (dec(ea) or "")[:20000], "callers": cl[:60]}

# --- 3) Primitives ---
PRIMS = {"READ_u8":0x35AF050, "READ_u16":0x35AF0F0, "READ_u32":0x35AF190,
         "READ_u64":0x35AF230, "READ_blob":0x35AF7D0, "READ_guid":0x36012B0,
         "BITS_5D5340":0x5D5340, "BITS_5D5080":0x5D5080, "HLP_613AC0":0x613AC0,
         "HLP_347D750":0x347D750, "HLP_679EA0":0x679EA0, "HLP_649560":0x649560,
         "HLP_674570":0x674570, "HLP_73FF60":0x73FF60}
for k, r in PRIMS.items():
    ea = V(r); f = ida_funcs.get_func(ea)
    R["primitives"][k] = {"rva": "0x%X" % r, "name": ida_name.get_name(ea),
                          "size": (f.end_ea - f.start_ea) if f else None,
                          "code": (dec(ea) or "")[:8000]}

# --- 4) Resizer ---
RESIZERS = [0x671D60,0x671FC0,0x20A330,0x671820,0x66B3B0,0x671620,0x66B250,0x671AC0,
            0x670DA0,0x66AD50,0x671250,0x670FE0,0x66AF70,0x66A7C0,0x6709C0,0x66AAA0,
            0x66A940,0x6706F0,0x66A660,0x6701F0,0x670480,0x255000,0x66A4F0,0x66FF90,
            0x66F9B0,0x66FBD0,0x66A410,0x66A2F0,0x66FDC0,0x209D10,0x671CE0,0x6717B0,
            0x670C90,0x670D00,0x6708A0,0x66F950,0x671F60,0x670F70,0x6703D0,0x6742B0]
for r in sorted(set(RESIZERS)):
    ea = V(r); f = ida_funcs.get_func(ea)
    if not f:
        R["resizers"]["0x%X" % r] = {"err": "no func"}; continue
    R["resizers"]["0x%X" % r] = {"size": f.end_ea - f.start_ea,
                                 "code": (dec(f.start_ea) or "")[:3000]}

# --- 5) RTTI-Scan der Vtable-Region ---
for vt in range(0x7FF784BC2000, 0x7FF784BC3800, 8):
    m, d = rtti_for_vtbl(vt)
    if m:
        R["rtti_scan"].append({"vtbl": "0x%X" % vt, "rva": "0x%X" % Rv(vt), "rtti": m, "dem": d})

with open(OUT, "w") as fh:
    json.dump(R, fh, indent=1)
print("WROTE", OUT, len(R["rtti_scan"]), "rtti hits")
idc.qexit(0)
