import re, json, sys, collections
D='/mnt/user-data/uploads/dumps'
g=json.load(open(D+'/wpp_work/opcodes_12_1_generation.json'))
NM={}
for d,m in g['emitted'].items():
    for n,v in m.items(): NM[int(v,16)]=n
UN=set(x['name'] for x in json.load(open('/home/claude/work/unimpl.json')))
HR=json.load(open(D+'/hook_registry.json'))['table']
HH=json.load(open('/home/claude/work/w1/hook_handlers.json'))
BASE=0x7FF780FD0000
inv=json.load(open(D+'/wpp_work/wire_inventory_12x.json'))
TR=collections.Counter(); SZ={}
for f,d in inv.items():
    for k,v in d['opcodes'].items():
        w=int(k.split(':')[1],16); TR[w]+=v['n']
        a=SZ.setdefault(w,[10**9,0]); a[0]=min(a[0],v['min']); a[1]=max(a[1],v['max'])
PRIM={'sub_7FF78457F050':'u8','sub_7FF78457F0F0':'u16','sub_7FF78457F190':'u32','sub_7FF78457F230':'u64',
      'sub_7FF7845D12B0':'guid','sub_7FF78457F7D0':'blob','sub_7FF78457F730':'raw'}
def ops(body, maxn=20):
    r=[]
    for line in body.splitlines():
        s=line.strip(); hit=None
        for p,t in PRIM.items():
            if p+'(' in s: hit=t; break
        if hit: r.append(hit); continue
        m=re.search(r'\b(sub_7FF7[0-9A-F]+|Jam\w+_Serialize)\(', s)
        if m and m.group(1) not in PRIM: r.append('->'+m.group(1)[-6:])
        mm=re.search(r'WowGetRawTypeName<([^>]+)>', s)
        if mm: r.append('T:'+mm.group(1).replace('struct ','').replace('class ',''))
    return r[:maxn]
for fam in sys.argv[1:]:
    src=open('%s/famwire/fam_%s_decomp.txt'%(D,fam),encoding='utf-8',errors='replace').read()
    d=re.search(r'/\* ===== SMSG_Dispatch_fam_%s.*?\*/\n(.*?)(?=\n/\* ===== )'%fam, src, re.S).group(1)
    parts=re.split(r'\n\s{4}case (\d+):', d)
    print('### 0x%s  (%d Cases)'%(fam,(len(parts)-1)//2))
    print('| Opcode | Name | Hook | Wert | Xrefs | Handler | offen | Sniff | Groesse | Lesefolge |')
    print('|---|---|---|---|---:|---|:-:|---:|---|---|')
    for i in range(1,len(parts),2):
        c=int(parts[i]); b=parts[i+1]
        hk=[h for h in re.findall(r'\b(?:off|qword)_(7FF785[0-9A-F]{6})\b', b)]
        gg='0x'+hk[0] if hk else None
        e=HR.get('0x%X'%(int(gg,16)-BASE)) if gg else None
        hv=e['value'] if e else '?'
        hx=e['n'] if e else ''
        hs=HH.get(gg)
        n=NM.get(c,'**unbenannt**')
        sz=SZ.get(c)
        print('| `0x%06X` | %s | `%s` | %s | %s | %s | %s | %d | %s | `%s` |'%(
            c,n,(gg[-7:] if gg else '-'),
            ('gesetzt' if hv not in ('0x0','?','0x1') else ('EVENT' if hv=='0x1' else ('NULL' if hv=='0x0' else '?'))),
            hx, (hs[0] if hs else '-'), ('**ja**' if n in UN else ''), TR.get(c,0),
            ('%d..%d'%(sz[0],sz[1])) if sz else '-', ' '.join(ops(b))))
    print()

