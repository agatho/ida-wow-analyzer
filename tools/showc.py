import re, sys
D='/mnt/user-data/uploads/dumps/cmsgwire'
fam=sys.argv[1]
src=open('%s/cmsg_%s_decomp.txt'%(D,fam),encoding='utf-8',errors='replace').read()
for a in sys.argv[2:]:
    m=re.search(r'/\* ===== (\S*%s\S*)\s+@(0x[0-9A-F]+)\s+\((\d+) bytes.*?\*/\n(.*?)(?=\n/\* ===== |\Z)'%a, src, re.S)
    if not m: print('%s NOT FOUND'%a); continue
    print('==== %s @%s (%s B)'%(m.group(1),m.group(2),m.group(3)))
    print('\n'.join(l for l in m.group(4).splitlines() if l.strip())[:2200]); print()
