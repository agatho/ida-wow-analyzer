import re, sys
D='/mnt/user-data/uploads/dumps/famwire'
fam=sys.argv[1]
src=open('%s/fam_%s_decomp.txt'%(D,fam),encoding='utf-8',errors='replace').read()
d=re.search(r'/\* ===== SMSG_Dispatch_fam_%s.*?\*/\n(.*?)(?=\n/\* ===== )'%fam, src, re.S).group(1)
for a in sys.argv[2:]:
    if a.startswith('c'):
        c=int(a[1:],16)
        parts=re.split(r'\n\s{4}case (\d+):', d)
        for i in range(1,len(parts),2):
            if int(parts[i])==c:
                print('==== case 0x%06X'%c)
                print('\n'.join(l for l in parts[i+1].splitlines() if l.strip())[:1800]); print()
    else:
        m=re.search(r'/\* ===== (\S*%s\S*)\s+@(0x[0-9A-F]+)\s+\((\d+) bytes.*?\*/\n(.*?)(?=\n/\* ===== |\Z)'%a, src, re.S)
        if not m: print('%s NOT FOUND'%a); continue
        print('==== %s @%s (%s B)'%(m.group(1),m.group(2),m.group(3)))
        print('\n'.join(l for l in m.group(4).splitlines() if l.strip())[:2200]); print()
