#!/usr/bin/env python3
"""python tools/gen_raw_data.py VERSION LINK_LOG OUTPUT: placeholder definitions of the data the sources reference and
do not yet define.

LINK_LOG is the output of a link of the compiled objects, whose undefined symbols are the data to define. Each is
written as the original's bytes (words, with a pointer as the address of the symbol it points at), under no type: this
is a stand-in until the symbol gets a typed definition in the source that owns it. Nothing here is decompiled."""
import bisect
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import compare

LIMIT = 4096


def main():
    version, log, output = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    _, pe, rows = compare.inventory(version)
    bindings = {name: int(value, 0) for name, value in
                json.loads(Path(f"config/{version}/bindings.json").read_text()).items()}
    bindings.update({r["symbol"]: r["address"] for r in rows if "symbol" in r})
    wanted = sorted({m[1] for m in re.finditer(r"undefined symbol: (\S+)", log.read_text(errors="replace"))
                     if "@" not in m[1]})
    bound = sorted({a for a in bindings.values()})
    # (a name per address: a C identifier, preferably the one a source uses)
    names = {}
    for name, address in sorted(bindings.items()):
        if re.fullmatch(r"_[A-Za-z_]\w*", name):
            names.setdefault(address, name[1:])
        elif re.fullmatch(r"[A-Za-z_]\w*", name):
            names.setdefault(address, name)
    sections = {}

    def section(address):
        if address not in sections:
            try:
                sections[address] = pe.section_for_address(address)
            except ValueError:
                sections[address] = None
        return sections[address]

    def target(value):
        """C expression for VALUE as a pointer, or None."""
        if not 0x401000 <= value < 0x600000:
            return None
        index = bisect.bisect_right(bound, value) - 1
        if index < 0 or section(value) is not section(bound[index]):
            return None
        base = bound[index]
        if base not in names or value - base >= LIMIT:
            return None
        extern.add(names[base])
        expression = names[base] if names[base] not in decorated else f"(char *){names[base]}"
        return f"(unsigned)({expression}" + (f" + {value - base}" if value != base else "") + ")"

    # (a function's decorated COFF name, by its C name: __stdcall _f@N, __fastcall @f@N)
    decorated = {}
    for obj in Path(f"build/{version}/compiled").rglob("*.obj"):
        for symbol in compare.read_object(obj)[0].values():
            m = re.fullmatch(r"([_@])(\w+)@(\d+)", symbol["name"])
            if m and symbol["section"] > 0:
                decorated[m[2]] = ("__stdcall" if m[1] == "_" else "__fastcall", int(m[3]))
    extern, body, skipped = set(), [], []
    for symbol in wanted:
        name = symbol[1:] if symbol.startswith("_") else symbol
        address = bindings.get(symbol, bindings.get(name))
        if address is None or section(address) is None or section(address).name not in (".data", ".bss", ".rdata"):
            skipped.append(symbol)
            continue
        i = bisect.bisect_right(bound, address)
        size = min((bound[i] if i < len(bound) else address + 4) - address, LIMIT)
        section_end = section(address).virtual_address + section(address).virtual_size
        size = min(size, section_end - address)
        if section(address).name == ".bss":
            body.append(f"char {name}[{size}];")
            continue
        data = pe.read(address, size).ljust((size + 3) // 4 * 4, b"\0")
        words = []
        for offset in range(0, len(data), 4):
            value = struct.unpack_from("<I", data, offset)[0]
            words.append((target(value) if offset % 4 == 0 and value >= 0x401000 else None) or f"0x{value:x}")
        body.append(f"unsigned {name}[{len(words)}] = {{" + ", ".join(words) + "};")
    # (the symbols a pointer refers to, and the sources define: declared here without a type)
    defined = {line.split("[")[0].split()[-1]: line.split()[0] for line in body}
    header = ["/* Placeholder data: the original's bytes for the data the sources reference and do not yet define",
              "   (tools/gen_raw_data.py). Each symbol moves to a typed definition in the source that owns it. */"]
    declarations = [f"extern void {decorated[n][0]} {n}({', '.join(['int'] * (decorated[n][1] // 4)) or 'void'});"
                    if n in decorated else f"extern {defined.get(n, 'char')} {n}[];" for n in sorted(extern)]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(header + declarations + body) + "\n")
    print(f"{len(body)} symbols; not defined: {len(skipped)}: {' '.join(skipped[:40])}")


if __name__ == "__main__":
    main()
