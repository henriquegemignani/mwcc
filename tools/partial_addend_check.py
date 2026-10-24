#!/usr/bin/env python3
"""python tools/partial_addend_check.py LINKER_DIR WORK_DIR [--mwld EXE]: write two small hand-made ELF objects, link them
with `-r` using the real linker and the replica and compare the results. The first object has a weak function that the second
one overrides (so the linker drops it from the partial link), a local function after it, and a data word whose relocation is
against the `.text` *section symbol* with the local function's offset as addend; the partial link has to shift that addend
by the size of the dropped function. The compilers never emit section-symbol relocations, hence the hand-made objects."""
import argparse
import os
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import elf
import elfdiff


def strtab(names):
    table, offsets = b"\0", {}
    for name in names:
        offsets[name] = len(table)
        table += name.encode() + b"\0"
    return table, offsets


def obj(text, symbols, data=None, relas=()):
    """symbols: (name, bind, type, shndx, value, size) after the null symbol; relas: (offset, symbol index, addend)."""
    sections = [("", 0, 0, b"", 0, 0, 0, 0)]
    shnames = ["", ".text", ".data", ".rela.data", ".symtab", ".strtab", ".shstrtab", ".comment"]
    names, offsets = strtab(shnames[1:])
    strs, stroff = strtab([s[0] for s in symbols])
    syms = struct.pack(">IIIBBH", 0, 0, 0, 0, 0, 0)
    for name, bind, typ, shndx, value, size in symbols:
        syms += struct.pack(">IIIBBH", stroff.get(name, 0) if typ != 3 else 0, value, size, bind << 4 | typ, 0, shndx)
    # (the compiler's `.comment`: its 44-byte header, then an (alignment, flags) pair for each symbol)
    comment = bytes.fromhex("436f646557617272696f720b02040701010200162c000000").ljust(44, bytes(1))
    comment += struct.pack(">II", 0, 0) + b"".join(struct.pack(">II", 1 if sym[2] == 4 else 4, 0) for sym in symbols)
    rela = b"".join(struct.pack(">IIi", off, sym << 8 | 1, add) for off, sym, add in relas)
    body = [(".text", 1, 6, text, 0, 0, 4, 0), (".data", 1, 3, data or b"\0\0\0\0", 0, 0, 4, 0),
            (".rela.data", 4, 0, rela, 4, 2, 4, 12), (".symtab", 2, 0, syms, 5, 1 + sum(sym[1] == 0 for sym in symbols), 4, 16),
            (".strtab", 3, 0, strs, 0, 0, 1, 0), (".shstrtab", 3, 0, names, 0, 0, 1, 0),
            (".comment", 1, 0, comment, 0, 0, 1, 0)]
    out, headers = b"\0" * 52, [struct.pack(">10I", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, typ, flags, content, link, info, align, entsize in body:
        out += b"\0" * (-len(out) % 4)
        headers.append(struct.pack(">10I", offsets[name], typ, flags, 0, len(out), len(content), link, info, align, entsize))
        out += content
    out += b"\0" * (-len(out) % 4)
    shoff = len(out)
    ident = b"\x7fELF\x01\x02\x01" + b"\0" * 9
    header = ident + struct.pack(">HHIIIIIHHHHHH", 1, 20, 1, 0, 0, shoff, 0, 52, 0, 0, 40, len(headers), 6)
    return header + out[52:] + b"".join(headers)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("linker_dir", type=Path)
    parser.add_argument("work_dir", type=Path)
    parser.add_argument("--mwld", type=Path, default=Path(os.environ.get("CARGO_TARGET_DIR", Path(__file__).parent.parent / "mwld/target"))
                        / "release/mwld.exe")
    args = parser.parse_args()
    args.work_dir.mkdir(parents=True, exist_ok=True)
    blr = struct.pack(">I", 0x4E800020)
    a = obj(blr * 6, [("a.s", 0, 4, 0xfff1, 0, 0), (".text", 0, 3, 1, 0, 0), (".data", 0, 3, 2, 0, 0), ("g", 0, 2, 1, 8, 8), ("fw", 2, 2, 1, 0, 8), ("fa", 1, 2, 1, 16, 8), ("d", 1, 1, 2, 0, 4)],
            relas=[(0, 2, 8)])
    b = obj(blr * 2, [("b.s", 0, 4, 0xfff1, 0, 0), (".text", 0, 3, 1, 0, 0), (".data", 0, 3, 2, 0, 0), ("fw", 1, 2, 1, 0, 8),
                      ("e", 1, 1, 2, 0, 4)])
    (args.work_dir / "a.o").write_bytes(a)
    (args.work_dir / "b.o").write_bytes(b)
    results = {}
    for name, exe in (("oracle", args.linker_dir / "mwldeppc.exe"), ("mine", args.mwld)):
        done = subprocess.run([str(exe), "-nodefaults", "-r", "-map", args.work_dir / f"{name}.map", "-o", args.work_dir / f"{name}.elf",
                               args.work_dir / "a.o", args.work_dir / "b.o"], capture_output=True, text=True)
        if done.returncode:
            sys.exit(f"{name} failed: {done.stdout}{done.stderr}")
        results[name] = elf.read(args.work_dir / f"{name}.elf")
    problems = elfdiff.diff(results["oracle"], results["mine"])
    if not problems and (args.work_dir / "oracle.elf").read_bytes() != (args.work_dir / "mine.elf").read_bytes():
        problems.append("the ELF files differ in their bytes")
    print("partial-addend:", "identical" if not problems else "DIFFERENT")
    for problem in problems:
        print("  " + problem)
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
