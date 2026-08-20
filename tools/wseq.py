# -*- coding: utf-8 -*-
"""wseq.py -- Schreibfolge einer CMSG-Writer-Funktion aus den Dekompilaten.

Kennt drei Dinge, die eine flache Aufruffolge sonst verschluckt:
  * Bit-Akkumulatoren, die der Compiler eingebettet hat -> 'bitflush' statt 'u8'
  * Schleifen -> [ ... ]* markiert ein Array-Element
  * Allokator/Freigabe -> keine Draht-Operation, wird verworfen
"""
import re, sys
D='/mnt/user-data/uploads/dumps'
W={'57FB40':'u8','57FBC0':'u16','57FC40':'u32','57FDC0':'u64',
   '57FCC0':'f32','57FD40':'f64','5D12E0':'guid',
   '5801C0':'bytes','57FE40':'bytes','5801D0':'reserve',
   '5A4A20':'bits2','5A4AE0':'bits3','5A4BA0':'bits4','5A4C60':'bits5',
   '5A4D20':'bits6','5A4DE0':'bits7','5E3670':'bits24','5A4EA0':'FLUSH'}
SKIP={'513700','57FA60','512440','512CB0','512930','512710','512400'}
CALL=re.compile(r'\b(sub_7FF7[0-9A-F]{8})\(')
BITEXPR=re.compile(r'<<|>>|\bLOBYTE|\bHIBYTE|& \(\(1 <<')
LOOP=re.compile(r'^\s*(for|while)\s*\(|^\s*do$')
chunks={}
for p in ('cmsg_43_decomp.txt','cmsg_3D_decomp.txt','subwriters_decomp.txt'):
    try: src=open('%s/cmsgwire/%s'%(D,p),encoding='utf-8',errors='replace').read()
    except IOError: continue
    for ch in src.split('/* ===== ')[1:]:
        m=re.match(r'(sub_7FF7[0-9A-F]+)\s+@(0x[0-9A-F]+)',ch)
        if m:
            body=ch.split('*/',1)[1] if '*/' in ch else ch
            chunks.setdefault(m.group(1),(m.group(1),body))
            chunks.setdefault(m.group(2),(m.group(1),body))
def argstr(line):
    i=line.find('('); return line[i+1:] if i>=0 else ''
def seq(key, depth=0, seen=frozenset()):
    e=chunks.get(key)
    if e is None: return ['?%s'%str(key)[-6:]]
    name,body=e
    if name in seen: return []
    seen=seen|{name}
    out=[]; lines=body.splitlines()
    dep=0; loopstack=[]   # (brace_depth_at_entry, index_in_out)
    pending_loop=False
    for line in lines:
        stripped=line.strip()
        if LOOP.match(line):
            pending_loop=True
        opens=line.count('{'); closes=line.count('}')
        single=False
        if pending_loop and not LOOP.match(line):
            if opens:
                loopstack.append((dep+opens, len(out))); pending_loop=False
            elif stripped:
                single=True; pending_loop=False; mark=len(out)
        for m in CALL.finditer(line):
            n=m.group(1); t=n[-6:]
            if t in SKIP: continue
            if t in W:
                sym=W[t]
                if sym in ('u8','u32') and BITEXPR.search(argstr(line)): sym='bitflush'
                out.append(sym)
            elif depth<4: out.extend(seq(n,depth+1,seen))
            else: out.append('->'+t)
        if single:
            inner=out[mark:]
            del out[mark:]
            if inner: out.append('['+' '.join(collapse_list(inner))+']*')
        dep+=opens-closes
        while loopstack and dep < loopstack[-1][0]:
            _,at=loopstack.pop()
            inner=out[at:]
            del out[at:]
            if inner: out.append('['+' '.join(collapse_list(inner))+']*')
    return out
def collapse_list(s):
    o=[]
    for x in s:
        if o and o[-1][0]==x: o[-1][1]+=1
        else: o.append([x,1])
    return [a if b==1 else '%s*%d'%(a,b) for a,b in o]
def collapse(s): return ' '.join(collapse_list(s))
if __name__=='__main__':
    for a in sys.argv[1:]: print('%s  %s'%(a, collapse(seq(a))))
