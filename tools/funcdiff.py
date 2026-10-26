#!/usr/bin/env python3
"""python tools/funcdiff.py VERSION SOURCE [FUNCTION...]: compare each function of SOURCE's compiled object
(build/VERSION/compiled, as ninja builds it) with the original's code at the function's address, its relocations'
fields left out, and print the instructions side by side for the FUNCTIONs named (all differing ones with `-a`).

A function's address is the `/* 0xADDRESS */` comment on the line before its definition, else the address in its name
(fn_XXXXXXXX), else config/VERSION/functions.json's address of the function of that name and source (a file shared
with the compilers has no address comments). The size is the original's, from config/VERSION/functions.json. This compares a unit function by function
while it does not link from source yet (tools/probe_units.py checks a whole unit)."""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from objnames import PADDING, object_functions, plain
from pe import PEFile


def addresses(source):
    text = Path(source).read_text()
    return {m.group(2): int(m.group(1), 16)
            for m in re.finditer(r"/\*\s*0x([0-9a-fA-F]+)\s*\*/\s*\n[^\n(]*?(\w+)\s*\(", text)}


def side_by_side(ours, theirs):
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    a, b = list(md.disasm(bytes(ours), 0)), list(md.disasm(bytes(theirs), 0))
    for i in range(max(len(a), len(b))):
        x = f"{a[i].address:4x} {a[i].mnemonic} {a[i].op_str}" if i < len(a) else ""
        y = f"{b[i].address:4x} {b[i].mnemonic} {b[i].op_str}" if i < len(b) else ""
        same = x.split(" ", 1)[-1] == y.split(" ", 1)[-1]
        print(f"  {'  ' if same else '!!'} {x:45} | {y}")


def main():
    args = [a for a in sys.argv[1:] if a != "-a"]
    every = "-a" in sys.argv[1:]
    version, source, *wanted = args
    config = json.loads(Path(f"config/{version}/config.json").read_text())
    pe = PEFile(Path(config["original"]))
    sizes = {int(f["address"], 16): f["size"] for f in json.loads(Path(f"config/{version}/functions.json").read_text())}
    at = addresses(source)
    listed = {f["name"]: int(f["address"], 16)
              for f in json.loads(Path(f"config/{version}/functions.json").read_text()) if f.get("source") == source}
    matched = total = 0
    for name, code, wild in object_functions(Path(f"build/{version}/compiled/{source}.obj")):
        name = plain(name)
        address = at.get(name)
        if address is None and re.fullmatch(r"fn_[0-9a-f]{8}", name):
            address = int(name[3:], 16)
        if address is None:
            address = listed.get(name)
        if address is None:
            print(f"?? {name}: no address")
            continue
        size = len(code)
        while size and code[size - 1] in PADDING and size - 1 not in wild:
            size -= 1
        theirs = pe.read(address, max(size, sizes.get(address, size)))
        length = sizes.get(address, size)
        same = size == length and all(theirs[i] == code[i] for i in range(size) if i not in wild)
        total += 1
        matched += same
        print(f"{'OK' if same else 'XX'} {name} 0x{address:08x} ours {size} original {length}")
        if not same and (every or name in wanted):
            side_by_side(code[:size], theirs[:length])
    print(f"{matched} of {total} functions match")


if __name__ == "__main__":
    main()
