#!/usr/bin/env python3
"""python tools/linker_oracle.py LINKER_DIR OUT_DIR --runtime DIR [NAME...]: link small test programs with the real
mwldeppc.exe (the oracle) and with the replica, tools/mwld.py, and compare the ELF files and the link maps.

LINKER_DIR holds mwcceppc.exe, mwldeppc.exe and lmgr326b.dll (for example build/compilers/GC/2.7). The linker needs the
MSL runtime's `__init_cpp_exceptions` and `global_destructor_chain` objects (--runtime DIR); the runtime's
`__register_fragment` and `__unregister_fragment` are stubbed here. Each program is built by the compiler, linked by both
linkers, and every difference is listed. The exit status is 1 when any program differs.

Each scenario is a set of C or C++ sources and compiler flags, and optionally: an archive made by the real linker's
`-library` of some of the objects, extra flags for one file, and an older compiler (a sibling of LINKER_DIR, such as 1.3.2,
whose objects have another `.comment` version; the linker stays 2.7). Every scenario here is compiled by a Metrowerks
compiler of that kind and linked with the same two MSL runtime objects."""
import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import elf
import elfdiff
import mwld

STUB = "void __register_fragment(void){} void __unregister_fragment(void){}\n"
STUB_CPP = ('extern "C" { void __end__catch(void){} void _savegpr_29(void){} void _restgpr_29(void){} '
            'void __throw(void){} } void operator delete(void*){}\n')

SCENARIOS = {
    "dead-code": ({"a.c": 'int g=5;int h;const int k=7;const char*s="hi";\nint unused(int x){return x*3;}\n'
                          'int f(int x){return x+g+h+k;}\nvoid _start(void){f(1);}\n'}, []),
    "two-units": ({"a.c": "extern int fb(int); extern int bigtab[300]; extern const char name[];\n"
                          "int arr[200]; int init[100]={1,2,3}; static int st=4; const int ro[4]={1,2,3,4};\n"
                          "int (*ptr)(int)=fb; int *pp=&st;\n"
                          "int fa(int x){ return fb(x)+arr[x]+init[x]+st+ro[x&3]+bigtab[x]+name[0]; }\n"
                          "void _start(void){ fa(1); }\n",
                   "b.c": 'int bigtab[300]; const char name[]="hello world, this is a long string";\n'
                          "int fb(int x){ static int cnt; cnt+=x; return cnt+bigtab[1]; }\n"}, []),
    "active-data": ({"a.c": "char c1=1; int unusedA=2; short s1=3; char c2=4; double d1=1.0; char c3=5; int unusedB=7;\n"
                            "int i1=8; int big[10]={1}; char c4=9; int unusedC[3]={1,2,3}; char c5=11;\n"
                            "int f(void){ return c1+s1+c2+(long)&d1+c3+i1+big[0]+c4+c5; }\n"
                            "void _start(void){ f(); }\n"}, ["-sdata", "0"]),
    "small-data": ({"a.c": "char c1=1; int unusedA=2; short s1=3; char c2=4; int unusedB=7; int i1=8;\n"
                           "int f(void){ return c1+s1+c2+i1; }\nvoid _start(void){ f(); }\n"}, []),
    "alignment": ({"a.c": "".join(
        f"char k{i}=1; char drop{i}=9; {t} {n}={'{1}' if '[' in n else '1'};\n"
        for i, (t, n) in enumerate([("short", "s2"), ("int", "i4"), ("double", "d8"), ("char", "c3[3]"),
                                    ("char", "c12[12]"), ("short", "s6[3]"), ("int", "i16[4]"), ("char", "c1")]))
                            + "int f(void){ return " + "+".join(
        f"k{i}+(long)&{n.split('[')[0]}" for i, n in enumerate(["s2", "i4", "d8", "c3", "c12", "s6", "i16", "c1"]))
                            + "; }\nvoid _start(void){ f(); }\n"}, ["-sdata", "64"]),
    "float-switch": ({"a.c": "extern int fb(int); extern float gf; static int tab[4]={1,2,3,4};\n"
                             "float fl(float x){ return x*2.5f+gf+1.25f; }\ndouble dd(double x){ return x*3.0+0.5; }\n"
                             'const char* names[3]={"one","two","three"};\n'
                             "int (*fp)(int)=fb; int *tp=tab; int used_table[3]={10,20,30};\n"
                             "int sw(int x){ switch(x){case 0:return 5;case 1:return 9;case 2:return 17;case 3:return 33;"
                             "case 4:return 65;case 5:return 129;default:return 0;} }\n"
                             "int fa(int x){ return fb(x)+(int)fl(x)+(int)dd(x)+sw(x)+fp(2)+*tp+names[x][0]+used_table[x]; }\n"
                             "void _start(void){ fa(1); }\n",
                      "b.c": "float gf=3.5f; int fb(int x){ return x+1; }\nint unused2(int x){ return x*5; }\n"},
                     ["-O4,p", "-fp", "hard"]),
    "struct-data": ({"a.c": "struct S{int a;char b;short c;}; struct S gs={1,2,3}; struct S gs2;\n"
                            "extern void callee(struct S*);\nint f(void){ callee(&gs); callee(&gs2); return gs.a; }\n"
                            "void _start(void){ f(); }\n",
                     "b.c": "struct S{int a;char b;short c;};\n"
                            "void callee(struct S*s){ static char buf[100]; s->a++; buf[0]=s->b; }\n"}, []),
    "cpp-exceptions": ({"a.cpp": "struct A{ virtual int f(){return 1;} int x; A():x(3){} virtual ~A(){} };\n"
                                 "struct B: A{ int f(){return 2;} };\nA ga; B gb;\nint use(A*a){ return a->f(); }\n"
                                 'extern "C" void _start(void){ try{ use(&gb);}catch(...){} }\n',
                        "stub2.cpp": STUB_CPP}, ["-Cpp_exceptions", "on", "-RTTI", "on"]),
    "cats-off": ({"a.c": "extern int fb(int); int g=5; int fa(int x){ return fb(x)+g; }\nvoid _start(void){ fa(1); }\n",
                  "b.c": "extern int g; int bb; int fb(int x){ bb+=x; return bb+g; }\n"},
                 {"file_flags": {"b.c": ["-pragma", "cats off"]}}),
    "compiler-1.3.2": ({"a.c": "int g=5;int h;\nint unused(int x){return x*2;}\nint f(int x){return x+g+h;}\n"
                               "void _start(void){f(1);}\n"}, {"compiler": "1.3.2"}),
    "archive": ({"a.c": "extern int fb(int); int fa(int x){ return fb(x)+1; }\nvoid _start(void){ fa(1); }\n",
                 "b.c": "int fb(int x){ static int cnt; cnt+=x; return cnt; }\n",
                 "extra.c": "int unusedfn(int x){ return x*9; }\n"}, "archive:b.c,extra.c"),
}


def run(*cmd):
    done = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
    return done.returncode, (done.stdout + done.stderr).strip()


def compare(oracle_elf, mine_elf, oracle_map, mine_map):
    problems = elfdiff.diff(elf.read(oracle_elf), elf.read(mine_elf))
    if not problems and Path(oracle_elf).read_bytes() != Path(mine_elf).read_bytes():
        problems.append("the ELF files differ in their bytes")
    if Path(oracle_map).read_text("latin-1") != Path(mine_map).read_text("latin-1"):
        problems.append("the link maps differ")
    return problems


def scenario(name, linker_dir, out_root, runtime):
    sources, flags = SCENARIOS[name]
    options = flags if isinstance(flags, dict) else {}
    compiler = linker_dir.parent / options["compiler"] if "compiler" in options else linker_dir
    flags = [] if isinstance(flags, dict) else flags
    out = out_root / name
    out.mkdir(parents=True, exist_ok=True)
    sources = {**sources, "stub.c": STUB}
    objects = {}
    for file, text in sources.items():
        (out / file).write_text(text)
        obj = out / (file.rsplit(".", 1)[0] + ".o")
        code, log = run(compiler / "mwcceppc.exe", "-c", "-proc", "gekko",
                        *(flags if isinstance(flags, list) else []), *options.get("file_flags", {}).get(file, []),
                        out / file, "-o", obj)
        if code:
            return [f"compile of {file} failed:\n{log}"]
        objects[file] = obj
    inputs = [objects[f] for f in sources]
    if isinstance(flags, str):          # an archive of some of the objects, made by the real linker
        members = flags.split(":")[1].split(",")
        run(linker_dir / "mwldeppc.exe", "-library", "-o", out / "lib.a", *[objects[m] for m in members])
        first = min(inputs.index(objects[m]) for m in members)
        inputs = [o for o in inputs if o not in [objects[m] for m in members]]
        inputs.insert(min(first, len(inputs)), out / "lib.a")
    inputs += [runtime / "global_destructor_chain.o", runtime / "__init_cpp_exceptions.o"]
    common = ["-nostdlib", "-m", "_start"]
    code, log = run(linker_dir / "mwldeppc.exe", *common, "-map", out / "oracle.map", "-o", out / "oracle.elf", *inputs)
    if code:
        return [f"the real linker failed:\n{log}"]
    try:
        mwld.main([*common, "-map", str(out / "mine.map"), "-o", str(out / "mine.elf"), *map(str, inputs)])
    except SystemExit as exit:
        return [f"the replica stopped: {exit}"]
    return compare(out / "oracle.elf", out / "mine.elf", out / "oracle.map", out / "mine.map")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("linker_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--runtime", type=Path, required=True,
                        help="directory with global_destructor_chain.o and __init_cpp_exceptions.o")
    parser.add_argument("names", nargs="*", help=f"scenarios to run (default all): {', '.join(SCENARIOS)}")
    args = parser.parse_args()
    failed = 0
    for name in args.names or SCENARIOS:
        problems = scenario(name, args.linker_dir, args.out_dir, args.runtime)
        print(f"{name}: {'identical' if not problems else 'DIFFERENT'}")
        for problem in problems:
            print("  " + problem.replace("\n", "\n  "))
        failed += bool(problems)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
