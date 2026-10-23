#!/usr/bin/env python3
"""python tools/linker_oracle.py LINKER_DIR OUT_DIR: link a small test program with the real mwldeppc.exe (the oracle the
linker replica is checked against) and keep the objects, the ELF and the map in OUT_DIR.

LINKER_DIR holds mwcceppc.exe, mwldeppc.exe and lmgr326b.dll (for example build/compilers/GC/2.7). The linker insists on
the MSL runtime's `__init_cpp_exceptions` and `global_destructor_chain` objects, so pass them with --runtime DIR; their
`__register_fragment` and `__unregister_fragment` are stubbed here."""
import argparse
import subprocess
import sys
from pathlib import Path

SOURCES = {
    "a.c": "int g = 5; int h;\nint f(int x){ return x + g + h; }\nvoid _start(void){ f(1); }\n",
    "c.c": "void __register_fragment(void){} void __unregister_fragment(void){}\n",
}


def run(*cmd):
    done = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
    return done.returncode, (done.stdout + done.stderr).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("linker_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--runtime", type=Path, required=True,
                        help="directory with global_destructor_chain.o and __init_cpp_exceptions.o")
    args = parser.parse_args()
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    objects = []
    for name, text in SOURCES.items():
        (out / name).write_text(text)
        obj = out / name.replace(".c", ".o")
        code, log = run(args.linker_dir / "mwcceppc.exe", "-c", "-proc", "gekko", out / name, "-o", obj)
        if code:
            sys.exit(log)
        objects.append(obj)
    objects += [args.runtime / "global_destructor_chain.o", args.runtime / "__init_cpp_exceptions.o"]
    code, log = run(args.linker_dir / "mwldeppc.exe", "-nostdlib", "-m", "_start", "-map", out / "a.map",
                    "-o", out / "a.elf", *objects)
    print(log)
    sys.exit(code)


if __name__ == "__main__":
    main()
