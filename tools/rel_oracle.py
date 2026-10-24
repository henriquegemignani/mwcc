#!/usr/bin/env python3
"""python tools/rel_oracle.py [--mwld EXE] [--ninja FILE] [--step plf|preplf] [--cwd DIR] LINKER_DIR OUT_DIR [MODULE...]:
link the REL modules of a game with the real mwldeppc.exe and with the replica and compare the ELF files and the maps.

The modules come from the project's build.ninja: each `build build\<ver>\<M>\<M>.plf` (or `.preplf`) rule lists its object
files, and its `ldflags` give the options; the `.plf` step is `-sdata 0 -sdata2 0 -r1 -lcf <M>/ldscript.lcf -m _prolog
-strip_partial`, the `.preplf` step `-sdata 0 -sdata2 0 -r`. Run it from the project's directory, which must hold the
objects (the real linker is the oracle, so the objects have to be the ones the reference build used). Prints one line per
module and exits with 1 when any differs. A `.preplf` map has no entry point to start from and its `SYMBOL NOT FOUND`
order is not reproduced yet, so only `.plf` links are expected to match fully."""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent


def rules(ninja, step):
    """module -> (objects, options) for each build rule of the step."""
    # (ninja joins the lines that end in `$`; a rule name can be one of them)
    text = re.sub(r" ?\$\r?\n\s*", " ", Path(ninja).read_text(encoding="utf-8"))
    found = {}
    bs = re.escape(chr(92))
    pattern = rf"^build build{bs}([^{bs} ]+){bs}([^{bs} ]+){bs}" + chr(92) + "2" + rf"\.{step}[ :]"
    for m in re.finditer(pattern, text, re.M):
        version, module = m.group(1), m.group(2)
        if module == "src":
            continue
        end = text.index("ldflags", m.start())
        block = text[m.start():end]
        objects = [o.replace("\\", "/") for o in re.findall(r"build[^ \n$]*\.o", block)]
        flags = text[end:text.index("\n", end)]
        found[module] = (version, objects, flags)
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("linker_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("modules", nargs="*")
    parser.add_argument("--mwld", type=Path, default=Path(os.environ.get("CARGO_TARGET_DIR", HERE.parent / "mwld/target"))
                        / "release/mwld.exe")
    parser.add_argument("--ninja", type=Path, default=Path("build.ninja"))
    parser.add_argument("--step", choices=["plf", "preplf"], default="plf")
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    args = parser.parse_args()
    ninja = args.ninja if args.ninja.is_absolute() else args.cwd / args.ninja
    found = rules(ninja, args.step)
    failed = 0
    for module in args.modules or sorted(found):
        version, objects, _ = found[module]
        options = ["-fp", "hardware", "-nodefaults", "-sdata", "0", "-sdata2", "0"]
        if args.step == "plf":
            options += ["-r1", "-lcf", f"build/{version}/{module}/ldscript.lcf", "-m", "_prolog", "-strip_partial"]
        else:
            options += ["-r"]
        cmd = [sys.executable, str(HERE / "lcf_oracle.py"), "--mwld", str(args.mwld), "--cwd", str(args.cwd),
               str(args.linker_dir), str(args.out_dir / module), *options, *objects]
        done = subprocess.run(cmd, capture_output=True, text=True)
        lines = (done.stdout + done.stderr).strip().splitlines()
        print(f"{module}: {lines[0] if lines else 'no output'}")
        for line in lines[1:4]:
            print("  " + line[:160])
        failed += done.returncode != 0
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
