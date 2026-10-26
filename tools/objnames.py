#!/usr/bin/env python3
"""python tools/objnames.py VERSION: name the functions of config/VERSION/functions.json as the compiled objects of
their units do (build/VERSION/compiled, from tools/derive_splits.py's splits).

A unit's compiled object has a section per function. Each of its functions is looked for among the functions in the
unit's code range whose bytes are its own, its relocations' fields left out; a function found once takes the object's
name for it (undecorated: no leading underscore, no stdcall @n) and the unit as its source. This gives the code the
splits name only by address (fn_XXXXXXXX) the names the sources call it by, so that a unit linked from source and the
split units agree on the symbols between them."""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from compare import read_object
from pe import PEFile
from split import read_splits

PADDING = (0x00, 0xCC)


def plain(name):
    return name if name.startswith("?") else re.sub(r"@\d+$", "", name).removeprefix("_")


def object_functions(path):
    """[(name, bytes, masked offsets)] of the functions of a compiled object."""
    symbols, sections = read_object(path)
    out = []
    for symbol in symbols.values():
        if symbol["section"] <= 0 or not symbol["type"] & 0x20:
            continue
        section = sections[symbol["section"] - 1]
        if not section["code"]:
            continue
        begin = symbol["value"]
        ends = [s["value"] for s in symbols.values() if s["section"] == symbol["section"] and s["value"] > begin
                and s["type"] & 0x20]
        end = min(ends, default=len(section["data"]))
        wild = set()
        for at, _, kind in section["relocs"]:
            if begin <= at < end:
                wild.update(range(at - begin, at - begin + 4))
        out.append((symbol["name"], section["data"][begin:end], wild))
    return out


def main():
    version = sys.argv[1]
    path = Path(f"config/{version}/functions.json")
    config = json.loads(Path(f"config/{version}/config.json").read_text())
    pe = PEFile(Path(config["original"]))
    functions = json.loads(path.read_text())
    _, units = read_splits(f"config/{version}/splits.txt")
    named = 0
    for unit, ranges in units:
        compiled = Path(f"build/{version}/compiled/{unit}.obj")
        if not compiled.exists():
            continue
        text = [(start, end) for section, start, end, _ in ranges if section == ".text"]
        here = [f for f in functions if any(lo <= int(f["address"], 16) < hi for lo, hi in text)]
        for name, code, wild in object_functions(compiled):
            size = len(code)
            while size and code[size - 1] in PADDING and size - 1 not in wild:
                size -= 1
            hits = []
            for f in here:
                if f["size"] < size:
                    continue
                address = int(f["address"], 16)
                original = pe.read(address, f["size"])
                if all(original[i] == code[i] for i in range(size) if i not in wild) and \
                        all(b in PADDING for b in original[size:]):
                    hits.append(f)
            if len(hits) == 1 and (hits[0]["name"] != plain(name) or hits[0].get("source") != unit):
                hits[0]["name"] = plain(name)
                hits[0]["source"] = unit
                named += 1
    path.write_text(json.dumps(functions, indent=2) + "\n")
    print(f"{named} functions named after their units' compiled objects")


if __name__ == "__main__":
    main()
