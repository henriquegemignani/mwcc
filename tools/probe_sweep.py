#!/usr/bin/env python3
"""Compile small C and C++ sources with the real compiler and link each with the real linker and the replica (full link,
`-r` and `-r1`), reporting every difference in the exit status, the ELF or the map.

usage: probe_sweep.py [--mwld EXE] LINKER_DIR WORK_DIR
"""
import os, subprocess, sys

args = sys.argv[1:]
M = 'mwld'
if args[:1] == ['--mwld']:
    M, args = args[1], args[2:]
L, work = args
# (`LCF=path` in the environment adds a full link and a `-r1` link with that linker command file)
LCF_MODES = []
if os.environ.get('LCF'):
    LCF_MODES = [('full+lcf', ['-lcf', os.environ['LCF']]), ('-r1+lcf', ['-r1', '-lcf', os.environ['LCF'], '-m', '_start'])]
os.makedirs(work, exist_ok=True)
os.chdir(work)
srcs={
'weak':('c','#pragma weak w\nint w(void){return 1;}\nint _start(void){return w();}\n',''),
'common':('c','int cm[10];\nint _start(void){return cm[3];}\n','-common on'),
'sdata':('c','int a=5; const int b=6; char s[3]; float f=2.0f;\nint _start(void){return a+b+s[1]+(int)f;}\n',''),
'str':('c','const char *p="hello"; int _start(void){return p[0];}\n',''),
'fnptr':('c','void g(void){}\nvoid (*fp)(void)=g;\nint _start(void){fp();return 0;}\n',''),
'static':('c','static int a; static int b=3; static void f(void){a++;}\nint _start(void){f();return a+b;}\n',''),
'cpp_ctor':('cpp','struct A{A(){x=1;} int x;}; A a;\nextern "C" int _start(void){return a.x;}\n','-Cpp_exceptions on'),
'cpp_exc':('cpp','struct E{}; int f(int x){ if(x) throw E(); return 0;}\nextern "C" int _start(void){try{return f(1);}catch(E&){return 2;}}\n','-Cpp_exceptions on'),
'cpp_noexc':('cpp','struct A{A(){x=1;} ~A(){} int x;}; A a;\nextern "C" int _start(void){return a.x;}\n','-Cpp_exceptions off'),
'bss':('c','static char buf[100]; int _start(void){return buf[1];}\n',''),
'switch':('c','int _start(int x){switch(x){case 0:return 1;case 1:return 5;case 2:return 7;case 3:return 9;default:return 0;}}\n',''),
'float':('c','double d=1.5; double _start(void){return d*2;}\n','-fp hardware'),
'sym':('c','int g(int x){return x*2;}\nint _start(void){return g(3);}\n','-sym on'),
'sym_cpp':('cpp','struct A{virtual int f(){return 1;} int x;};\nA a;\nextern "C" int _start(void){return a.f();}\n','-sym on -Cpp_exceptions on'),
'o4':('c','int g(int x){return x*2;}\nint _start(void){return g(3)+g(4);}\n','-O4,p -inline auto'),
'vtable':('cpp','struct B{virtual int f(){return 1;} virtual ~B(){}};\nstruct D:B{int f(){return 2;}};\nD d;\nextern "C" int _start(void){B*b=&d;return b->f();}\n','-Cpp_exceptions on -RTTI on'),
'vtable_noexc':('cpp','struct B{virtual int f(){return 1;}};\nstruct D:B{int f(){return 2;}};\nD d;\nextern "C" int _start(void){B*b=&d;return b->f();}\n','-Cpp_exceptions off'),
'template':('cpp','template<class T> T sq(T x){return x*x;}\nextern "C" int _start(void){return sq(3)+(int)sq(2.0);}\n','-Cpp_exceptions off'),
'tpl_exc':('cpp','template<class T> T sq(T x){if(x>100) throw x; return x*x;}\nextern "C" int _start(void){try{return sq(3);}catch(int){return 0;}}\n','-Cpp_exceptions on'),
'sdata_thr':('c','int a=1,b=2; char c[100]={1};\nint _start(void){return a+b+c[0];}\n','-sdatathreshold 0'),
'sdata_big':('c','int a=1,b=2; char c[100]={1}; int z[50];\nint _start(void){return a+b+c[0]+z[1];}\n','-sdatathreshold 1024'),
'array_init':('c','int t[4]={1,2,3,4}; const int k[3]={5,6,7};\nint _start(void){return t[1]+k[2];}\n',''),
'asm_fn':('c','asm int g(void){\n li r3, 5\n blr\n}\nint _start(void){return g();}\n',''),
'nested_static':('cpp','int f(){static int n=0; return ++n;}\nextern "C" int _start(void){return f();}\n','-Cpp_exceptions off'),
'exc_cls':('cpp','struct S{S(){} ~S(){}};\nint g(int x){S s; return x;}\nextern "C" int _start(void){return g(1);}\n','-Cpp_exceptions on'),
'two_funcs':('c','int g(void){return 1;}\nint h(void){return 2;}\nint _start(void){return g();}\n',''),
}
for name,(ext,code,flags) in srcs.items():
    open(f'{name}.{ext}','w').write(code)
    r=subprocess.run([f'{L}/mwcceppc.exe','-c','-o',f'{name}.o']+flags.split()+[f'{name}.{ext}'],capture_output=True,text=True)
    if not os.path.exists(f'{name}.o'): print(name,'compile failed',r.stdout[-200:]); continue
    for mode,args in (('full',[]),('-r',['-r']),('-r1',['-r1','-m','_start'])) + tuple(LCF_MODES):
        a=args+(['-m','_start'] if mode!='-r1' else [])
        ro=subprocess.run([f'{L}/mwldeppc.exe']+a+['-map','o.map','-o','o.elf',f'{name}.o'],capture_output=True,text=True)
        mo=subprocess.run([M]+a+['-map','m.map','-o','m.elf',f'{name}.o'],capture_output=True,text=True)
        if (ro.returncode==0)!=(mo.returncode==0):
            print(name,mode,'exit differs real',ro.returncode,'mine',mo.returncode,mo.stderr[:100].strip(),ro.stdout[-120:].replace('\n',' ')); continue
        if ro.returncode: continue
        same_elf=open('o.elf','rb').read()==open('m.elf','rb').read()
        same_map=open('o.map','rb').read().replace(b'\r',b'')==open('m.map','rb').read().replace(b'\r',b'')
        if not(same_elf and same_map): print(name,mode,'elf' if not same_elf else '', 'map' if not same_map else '')
        for f in ('o.elf','m.elf','o.map','m.map'): os.path.exists(f) and os.remove(f)
print('done')
