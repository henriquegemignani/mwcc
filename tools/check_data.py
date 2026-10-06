#!/usr/bin/env python3
"""python tools/check_data.py VERSION EXE MAP: the data of a linked EXE against the original's, symbol by symbol.

A word that is an address in EXE must be the address the original has there, by way of the symbol it falls in and the
offset into it. Prints the symbols whose words differ, and how many."""
import bisect
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import compare
import pe as pefile


def main():
    version, exe, linkmap = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    _, original, rows = compare.inventory(version)
    ours = pefile.PEFile(exe)
    bindings = {name: int(value, 0) for name, value in
                json.loads(Path(f"config/{version}/bindings.json").read_text()).items()}
    bindings.update({r["symbol"]: r["address"] for r in rows if "symbol" in r})
    bindings.update({m[0]: int(m[1], 16) for m in re.finditer(r"_data_([0-9a-f]{8})", linkmap.read_text(errors="replace"))})
    placed, module = {}, {}
    for m in re.finditer(r"^([0-9a-f]{8}) (\S+)\s+(\S+)\s*$", linkmap.read_text(errors="replace"), re.M):
        placed.setdefault(m[3], int(m[1], 16))
        module.setdefault(m[3], m[2])
    # (our address of each symbol the original has an address for, and the reverse)
    pairs = sorted((placed[name], bindings[name]) for name in placed if name in bindings)
    addresses = [p[0] for p in pairs]
    everything = sorted(set(placed.values()))

    def translate(value):
        index = bisect.bisect_right(addresses, value) - 1
        if index < 0:
            return None
        return pairs[index][1] + value - pairs[index][0]

    def section_name(image, address):
        try:
            return image.section_for_address(address).name
        except ValueError:
            return None

    fixups = compare.base_relocations(original)
    bad = {}
    names = sorted((bindings[name], name) for name in placed if name in bindings
                   and (len(sys.argv) < 5 or module[name] == sys.argv[4])
                   and section_name(original, bindings[name]) in (".data", ".rdata"))
    for index, (address, name) in enumerate(names):
        end = names[index + 1][0] if index + 1 < len(names) else address + 4
        here = placed[name]
        k = bisect.bisect_right(everything, here)
        size = min(end - address, 4096, (everything[k] if k < len(everything) else here + 4) - here)
        try:
            theirs, mine = original.read(address, size), ours.read(here, size)
        except ValueError:
            continue
        masked = set()
        for fixup in range(bisect.bisect_left(fixups, address), bisect.bisect_left(fixups, address + size)):
            offset = fixups[fixup] - address
            if offset + 4 > size:
                continue
            masked.update(range(offset, offset + 4))
            a, b = struct.unpack_from("<I", theirs, offset)[0], struct.unpack_from("<I", mine, offset)[0]
            if translate(b) != a:
                bad.setdefault(name, []).append((offset, a, b))
        for offset in range(size):
            if offset not in masked and theirs[offset] != mine[offset]:
                bad.setdefault(name, []).append((offset, theirs[offset], mine[offset]))
                break
    for name, diffs in sorted(bad.items(), key=lambda item: bindings[item[0]]):
        print(f"{name} {bindings[name]:x}: {len(diffs)} words differ, first +{diffs[0][0]:x}: {diffs[0][1]:x} vs {diffs[0][2]:x}")
    print(len(bad), "symbols differ of", len(names))


if __name__ == "__main__":
    main()
