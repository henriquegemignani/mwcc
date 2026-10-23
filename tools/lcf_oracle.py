#!/usr/bin/env python3
"""python tools/lcf_oracle.py [--mwld EXE] [--cwd DIR] LINKER_DIR OUT_DIR LINK_ARGS...: run one link with the real
mwldeppc.exe (the oracle) and with the replica, with the same arguments, and compare the ELF files and the link maps.

For a whole game, run it from the project's directory and pass the linker command file and the objects as a response
file, for example (Metroid Prime 2 in decomp/echoes):

    python tools/lcf_oracle.py --cwd F:/programming/decomp/echoes build/compilers/GC/2.7 out \\
        -fp hardware -nodefaults -lcf build/G2ME01/ldscript.lcf @objs.rsp

`-map` and `-o` are added here. The exit status is 1 when the links differ. The objects must be the ones the game's
reference link used; a stale `main.elf` is no oracle, which is why the real linker is run again here."""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import linker_oracle as lo


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("linker_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--mwld", type=Path, default=Path(os.environ.get("CARGO_TARGET_DIR", Path(__file__).parent.parent / "mwld/target"))
                        / "release/mwld.exe", help="the replica (default: release/mwld.exe in cargo's target directory)")
    parser.add_argument("--cwd", type=Path, default=Path.cwd(), help="the directory to link in (relative paths are from here)")
    parser.add_argument("link_args", nargs=argparse.REMAINDER, help="the linker's arguments")
    args = parser.parse_args()
    linker = (args.linker_dir / "mwldeppc.exe").resolve()
    mwld, out = args.mwld.resolve(), args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    os.chdir(args.cwd)
    results = {}
    for tag, exe in (("oracle", linker), ("mine", mwld)):
        code, log = lo.run(exe, *args.link_args, "-map", out / f"{tag}.map", "-o", out / f"{tag}.elf")
        if code:
            print(f"{tag} failed:\n{log}")
            sys.exit(2)
        results[tag] = log
    problems = lo.compare(out / "oracle.elf", out / "mine.elf", out / "oracle.map", out / "mine.map")
    print("identical" if not problems else "DIFFERENT")
    for problem in problems[:30]:
        print("  " + problem.replace("\n", "\n  "))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
