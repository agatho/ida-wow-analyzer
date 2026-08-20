import re, json, sys, collections
D='/mnt/user-data/uploads/dumps'
g=json.load(open(D+'/wpp_work/opcodes_12_1_generation.json'))
NM={}
for d,m in g['emitted'].items():
    for n,v in m.items(): NM[int(v,16)]=n
UN=set(x['name'] for x in json.load(open('/home/claude/work/unimpl.json')))
inv=json.load(open(D+'/wpp_work/wire_inventory_12x.json'))
TR=collections.Counter(); SZ={}
for f,d in inv.items():
    for k,v in d['opcodes'].items():
        w=int(k.split(':')[1],16); TR[w]+=v['n']
        a=SZ.setdefault(w,[10**9,0]); a[0]=min(a[0],v['min']); a[1]=max(a[1],v['max'])
W={'sub_7FF78457FC40':'u32','sub_7FF78457FB40':'u32','sub_7FF78457FDC0':'u64',
   'sub_7FF7845D12E0':'guid','sub_7FF7845801C0':'bytes','sub_7FF7815A4EA0':'FLUSH',
   'sub_7FF7815E3670':'bits24','sub_7FF7815A4DE0':'bitsA','sub_7FF7815A4AE0':'bitsB',
   'sub_7FF7815A4D20':'bitsC','sub_7FF78457FAC0':'u16','sub_7FF78457FA40':'u8',
   'sub_7FF78457FBC0':'u32b'}
for fam in sys.argv[1:]:
    src=open('%s/cmsgwire/cmsg_%s_decomp.txt'%(D,fam),encoding='utf-8',errors='replace').read()
    meta=json.load(open('%s/cmsgwire/cmsg_%s_meta.json'%(D,fam)))
    chunks={}
    for ch in src.split('/* ===== ')[1:]:
        mm=re.match(r'(\S+)\s+@(0x[0-9A-F]+)\s+\((\d+) bytes', ch)
        if mm: chunks[mm.group(2)]=ch
    print('### CMSG 0x%s  (%d Opcodes)'%(fam, len(meta['opcodes'])))
    print('| Opcode | Name | Writer | offen | Sniff | Groesse | Schreibfolge |')
    print('|---|---|---|:-:|---:|---|---|')
    for op in sorted(meta['opcodes']):
        c=int(op,16); n=NM.get(c,'**unbenannt**')
        ent=meta['opcodes'][op]
        wr=None
        for e in ent:
            if e['size']!=10 and e['size']<600:
                ch=chunks.get(e['func'])
                if ch and 'sub_7FF78457FC40(' in ch: wr=e; break
        seq=[]
        if wr:
            ch=chunks[wr['func']]
            for line in ch.splitlines():
                for p,t in W.items():
                    if p+'(' in line: seq.append(t); break
                else:
                    m2=re.search(r'\b(sub_7FF7[0-9A-F]+)\(', line)
                    if m2 and m2.group(1) not in W and 'FC40' not in m2.group(1): seq.append('->'+m2.group(1)[-6:])
        sz=SZ.get(c)
        print('| `%s` | %s | %s | %s | %d | %s | `%s` |'%(op,n,(wr['func'] if wr else '-'),
            ('**ja**' if n in UN else ''), TR.get(c,0), ('%d..%d'%(sz[0],sz[1])) if sz else '-',
            ' '.join(seq[1:22])))
    print()
