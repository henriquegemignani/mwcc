#!/usr/bin/env python3
"""python tools/common_source.py VERSION OUT: the COMMON block of VERSION's executable as assembly source, from
config/VERSION/splits.txt (the "common" unit's .bss ranges) and symbols.txt (the names in them).

The original's uninitialized globals were tentative definitions its linker gathered in .bss, in an order of its own
(by alignment and name hash). The units' code relies on that layout in places: one memset clears a run of variables,
a file spec's name is another name 6 bytes in, the parser's state is cleared from its first variable on. So the block
is written as the original lays it out: each named variable at its offset, as large as the room up to the next name
(the original's unnamed fields included), zeros. The units' own tentative definitions of these names resolve to it.
Assembled by clang for i386 COFF (configure.py, config.json "assembly")."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from split import read_splits


def main():
    version, out = sys.argv[1:]
    sections, units = read_splits(f"config/{version}/splits.txt")
    ranges = [(start, end) for unit, parts in units if unit == "common"
              for section, start, end, _ in parts if section == ".bss"]
    start, end = min(s for s, _ in ranges), max(e for _, e in ranges)
    names = []
    for line in open(f"config/{version}/symbols.txt"):
        m = re.match(r"(_\S+) = \.bss:0x([0-9A-Fa-f]+);", line)
        if m and start <= int(m[2], 16) < end:
            names.append((int(m[2], 16), m[1]))
    names.sort()
    lines = [f"# The {version} executable's COMMON block, as the original lays it out (written by tools/common_source.py",
             f"# from config/{version}/splits.txt and symbols.txt): each name at its offset, as large as the room up to",
             "# the next.", "\t.bss", "\t.p2align 4"]
    cursor = start
    if names and names[0][0] > start:
        lines.append(f"\t.zero {names[0][0] - start}")
    for i, (address, name) in enumerate(names):
        following = names[i + 1][0] if i + 1 < len(names) else end
        lines += [f"\t.globl {name}", f"{name}:", f"\t.zero {following - address}"]
        cursor = following
    Path(out).write_text("\n".join(lines) + "\n")
    print(f"{out}: {len(names)} names, {end - start} bytes")


if __name__ == "__main__":
    main()
