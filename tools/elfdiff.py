#!/usr/bin/env python3
"""python tools/elfdiff.py A B: say where two big-endian ELF32 files differ: the header, the section headers, the
section contents (the first differing offsets), the symbol table and the program headers. Exit status 1 if they differ."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import elf


def diff(a, b, limit=8):
    out = []
    if a.header != b.header:
        out.append(f"header: {a.header[1:]} != {b.header[1:]}")
    names_a, names_b = [s.name for s in a.sections], [s.name for s in b.sections]
    if names_a != names_b:
        out.append(f"section order: {names_a} != {names_b}")
    for sa in a.sections:
        sb = b.section(sa.name)
        if sb is None:
            continue
        fields = ("type", "flags", "addr", "offset", "size", "link", "info", "align", "entsize")
        bad = [f"{f} {getattr(sa, f):#x} != {getattr(sb, f):#x}" for f in fields if getattr(sa, f) != getattr(sb, f)]
        if bad:
            out.append(f"section {sa.name} header: " + ", ".join(bad))
        if sa.data != sb.data:
            where = [i for i in range(min(len(sa.data), len(sb.data))) if sa.data[i] != sb.data[i]]
            out.append(f"section {sa.name} data: {len(where)} bytes differ, first at "
                       + ", ".join(f"{i:#x}" for i in where[:limit]) + (" ..." if len(where) > limit else ""))
    if True:
        for i, (x, y) in enumerate(zip(a.symbols, b.symbols)):
            if x != y:
                out.append(f"symbol {i}: {x} != {y}")
                if len([o for o in out if o.startswith("symbol ")]) >= limit:
                    break
        if len(a.symbols) != len(b.symbols):
            out.append(f"symbol count {len(a.symbols)} != {len(b.symbols)}")
    if a.segments != b.segments:
        for i, (x, y) in enumerate(zip(a.segments, b.segments)):
            if x != y:
                out.append(f"segment {i}: {x} != {y}")
        if len(a.segments) != len(b.segments):
            out.append(f"segment count {len(a.segments)} != {len(b.segments)}")
    if not out and a.raw != b.raw:
        out.append("same structure, but the files differ in the bytes between structures (padding)")
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("a", type=Path)
    parser.add_argument("b", type=Path)
    args = parser.parse_args()
    problems = diff(elf.read(args.a), elf.read(args.b))
    print("\n".join(problems) if problems else "identical")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
