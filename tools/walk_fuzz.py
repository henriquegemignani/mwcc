#!/usr/bin/env python3
"""python tools/walk_fuzz.py LINKER_DIR WORK_DIR LO HI [--mwld EXE]: compile random small C++-free programs (seeds LO..HI-1)
with the 2.7 compiler, link them with plain `-r` using the real linker and the replica, and compare the `SYMBOL NOT
FOUND` lists, which show the order the linker walks its atoms in (docs/linker/README.md, "Plain `-r` walk"). Prints the
seeds that differ. Needs the compiler and mwldeppc.exe in LINKER_DIR."""
import argparse
import random,subprocess,sys,os
L = M = ''
def names(map_):
    return [l.split(': ')[1] for l in open(map_,encoding='latin-1').read().replace('\r','').split('\n') if 'NOT FOUND' in l]
def gen(seed):
    rnd=random.Random(seed)
    nobj=rnd.choice([1,2,2,3])
    nf=[rnd.randint(2,6) for _ in range(nobj)]
    nd=[rnd.randint(0,3) for _ in range(nobj)]
    flags=[rnd.random()<0.6 for _ in range(nobj)]
    funcs=[[f'f{o}_{i}' for i in range(nf[o])] for o in range(nobj)]
    datas=[[f'd{o}_{i}' for i in range(nd[o])] for o in range(nobj)]
    allf=[f for fs in funcs for f in fs]; alld=[d for ds in datas for d in ds]
    uc=0
    srcs=[]
    for o in range(nobj):
        s=''
        decl=set()
        body=''
        def ref(kind):
            nonlocal uc
            r=rnd.random()
            if kind=='f':
                if r<0.35:
                    n=rnd.choice(allf)
                elif r<0.5 and alld:
                    n=rnd.choice(alld)
                else:
                    n=f'u{uc}'; uc+=1
            else:
                if r<0.3: n=rnd.choice(allf)
                else: n=f'u{uc}'; uc+=1
            return n
        items=[]
        for i,d in enumerate(datas[o]):
            k=rnd.randint(1,3)
            items.append(('d',d,[ref('d') for _ in range(k)]))
        for f in funcs[o]:
            k=rnd.randint(1,3)
            items.append(('f',f,[ref('f') for _ in range(k)]))
        rnd.shuffle(items) if rnd.random()<0.3 else None
        used=set()
        for kind,n,rs in items:
            for r in rs: used.add(r)
        defined={n for _,n,_ in items}
        for u in sorted(used-defined):
            if u.startswith('d'): s+=f'extern void* {u}[];\n'
            else: s+=f'extern void {u}(void);\n'
        s+=('#pragma force_active on\n' if flags[o] else '')
        for kind,n,rs in items:
            if kind=='d':
                s+='void* %s[]={%s};\n'%(n,','.join(('(void*)%s'%r if not r.startswith('d') else '(void*)%s'%r) for r in rs))
            else:
                s+='void %s(void){ %s }\n'%(n,' '.join(('%s();'%r if not r.startswith('d') else 'use(%s);'%r) for r in rs))
        s='extern void use(void*);\n'+s
        srcs.append(s)
    return srcs
def run(seed):
    srcs=gen(seed)
    for f in ('ro.map','rm.map','r0.o','r1.o','r2.o'):
        if os.path.exists(f): os.remove(f)
    objs=[]
    for i,s in enumerate(srcs):
        open(f'r{i}.c','w').write(s)
        r=subprocess.run([L+'mwcceppc.exe','-c','-proc','gekko',f'r{i}.c','-o',f'r{i}.o'],capture_output=True,text=True)
        if r.returncode or not os.path.exists(f'r{i}.o'): return None
        objs.append(f'r{i}.o')
    subprocess.run([L+'mwldeppc.exe','-nodefaults','-r','-map','ro.map','-o','ro.elf']+objs,capture_output=True)
    subprocess.run([M,'-nodefaults','-r','-map','rm.map','-o','rm.elf']+objs,capture_output=True)
    if not (os.path.exists('ro.map') and os.path.exists('rm.map')): return None
    return names('ro.map'),names('rm.map')
if __name__=='__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('linker_dir'); ap.add_argument('work_dir'); ap.add_argument('lo', type=int); ap.add_argument('hi', type=int)
    ap.add_argument('--mwld', default='mwld/target/release/mwld.exe')
    a = ap.parse_args()
    L = os.path.abspath(a.linker_dir).replace(chr(92), '/') + '/'
    M = os.path.abspath(a.mwld)
    os.makedirs(a.work_dir, exist_ok=True)
    os.chdir(a.work_dir)
    lo,hi=a.lo,a.hi; bad=[]
    for sd in range(lo,hi):
        r=run(sd)
        if r is None: continue
        if r[0]!=r[1]: bad.append(sd)
    print('bad seeds',bad,'of',hi-lo)
