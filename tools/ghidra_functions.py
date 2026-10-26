#!/usr/bin/env python3
"""python tools/ghidra_functions.py VERSION LIST: add the function starts of a Ghidra listing to
config/VERSION/functions.json.

LIST has a line per function, `entry end ...` in hexadecimal (end exclusive), as a script printing each function's entry
point and its body's highest address plus one writes it. A start Ghidra has that the list does not is added when it is
in no listed function, or in one without a source (a function found by decoding the code, or one a compiler's list
carries over from a gap of its own): that function then ends where the new one starts, less the padding. A function with
a source is the compiler's and is kept whole. Ghidra's names are not taken (its analysis names no function)."""
import json
import sys
from bisect import bisect_right
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pe import PEFile

PADDING = (0x00, 0xCC)


def main():
    version, listing = sys.argv[1:3]
    path = Path(f"config/{version}/functions.json")
    config = json.loads(Path(f"config/{version}/config.json").read_text())
    pe = PEFile(Path(config["original"]))
    functions = sorted(json.loads(path.read_text()), key=lambda f: int(f["address"], 16))
    ghidra = {}
    for line in Path(listing).read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and all(c in "0123456789abcdef" for c in parts[0] + parts[1]):
            ghidra[int(parts[0], 16)] = int(parts[1], 16)
    added = 0
    for start in sorted(ghidra):
        starts = [int(f["address"], 16) for f in functions]
        if start in starts:
            continue
        k = bisect_right(starts, start) - 1
        holder = functions[k] if k >= 0 and start < starts[k] + functions[k]["size"] else None
        if holder is not None and holder.get("source"):
            continue
        following = starts[k + 1] if k + 1 < len(starts) else None
        end = holder and starts[k] + holder["size"]
        end = end or min(ghidra[start], following or ghidra[start])
        if holder is not None:
            cut = start
            while cut > starts[k] and pe.read(cut - 1, 1)[0] in PADDING:
                cut -= 1
            holder["size"] = cut - starts[k]
        while end > start and pe.read(end - 1, 1)[0] in PADDING:
            end -= 1
        name = f"fn_{start:08x}"
        if any(f["name"] == name for f in functions):
            name = f"auto_fn_{start:08x}"
        functions.insert(k + 1, {"name": name, "address": f"0x{start:08x}", "size": end - start})
        added += 1
    path.write_text(json.dumps(functions, indent=2) + "\n")
    print(f"{added} functions added from Ghidra's {len(ghidra)}")


if __name__ == "__main__":
    main()
