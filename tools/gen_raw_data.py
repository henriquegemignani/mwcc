#!/usr/bin/env python3
"""python tools/gen_raw_data.py VERSION LINK_LOG OUTPUT: placeholder definitions of the data the sources reference and
do not yet define.

LINK_LOG is the output of a link of the compiled objects, whose undefined symbols are the data to define. Each is
written as the original's bytes (words, with a pointer as the address of the symbol it points at), under no type: this
is a stand-in until the symbol gets a typed definition in the source that owns it. Nothing here is decompiled."""
import bisect
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import compare

LIMIT = 1 << 16


HEADER_DECL = re.compile(r"^extern\s+([^;(]*?)\b([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*;", re.M)


def declared_sizes(version, names):
    """{name: bytes} of the symbols a header declares with a known size: the compiler's sizeof of each, probed in one
    translation unit per header."""
    wanted, declared = set(names), {}
    for header in sorted(Path("include").rglob("*.h")):
        for m in HEADER_DECL.finditer(header.read_text(errors="replace")):
            if m[2] in wanted and m[2] not in declared:
                declared[m[2]] = (header, m[1], m[3])
    sizes, by_header = {}, {}
    for header in Path("include").rglob("*.h"):
        for m in re.finditer(r"^extern\s+[^;]*?\(\s*\*\s*(\w+)\s*\)[^;]*;", header.read_text(errors="replace"), re.M):
            if m[1] in wanted:
                sizes[m[1]] = (4, False)
    for name, (header, _, array) in declared.items():
        by_header.setdefault(header, []).append((name, array))
    probe = Path(f"build/{version}/probe")
    probe.mkdir(parents=True, exist_ok=True)
    for index, (header, symbols) in enumerate(sorted(by_header.items())):
        source = probe / f"probe{index}.c"
        lines = ['#include "compiler/common.h"', f'#include "{header.relative_to("include").as_posix()}"']
        for name, array in symbols:
            # (an array of unknown length is sized by the caller from its neighbours: only its element is measured)
            lines.append(f"char probe_{name}[sizeof({name}{'[0]' if array == '[]' else ''})];")
        source.write_text("\n".join(lines) + "\n")
        compiler = "build/compilers/pro53/mwcc.exe"
        result = subprocess.run(
            ([] if sys.platform == "win32" else ["build/tools/wibo"]) + [compiler.replace("/", os.sep) if sys.platform == "win32" else compiler,
             "-c", "-DVERSION=0", "-Iinclude", "-i-", "-Iinclude/libc", str(source), "-o", str(source.with_suffix(".obj"))],
            capture_output=True, text=True, env={**os.environ, "MWCIncludes": "include/libc"})
        if result.returncode:
            continue
        for symbol in compare.read_object(source.with_suffix(".obj"))[0].values():
            if symbol["name"].startswith("_probe_"):
                name = symbol["name"][len("_probe_"):]
                sizes[name] = (symbol["value"], dict(symbols)[name] == "[]")
    return sizes


def defined_sizes(version):
    """{name: bytes} of the data symbols the compiled sources define: a symbol extends to the next one of its section."""
    sizes = {}
    for obj in Path(f"build/{version}/compiled").rglob("*.obj"):
        if obj.name == "raw_data.c.obj":
            continue
        symbols, sections = compare.read_object(obj)
        by_section = {}
        for symbol in symbols.values():
            if symbol["section"] > 0 and not sections[symbol["section"] - 1]["code"] and not symbol["name"].startswith("."):
                by_section.setdefault(symbol["section"], []).append(symbol)
            elif symbol["section"] == 0 and symbol["storage"] == 2 and symbol["value"]:
                sizes[symbol["name"].lstrip("_") if symbol["name"].startswith("_") else symbol["name"]] = symbol["value"]
        for index, members in by_section.items():
            members.sort(key=lambda s: s["value"])
            end = len(sections[index - 1]["data"])
            for i, symbol in enumerate(members):
                following = [m["value"] for m in members[i + 1:] if m["value"] > symbol["value"]]
                name = symbol["name"][1:] if symbol["name"].startswith("_") else symbol["name"]
                sizes[name] = (following[0] if following else end) - symbol["value"]
    return sizes


def main():
    version, log, output = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    _, pe, rows = compare.inventory(version)
    bindings = {name: int(value, 0) for name, value in
                json.loads(Path(f"config/{version}/bindings.json").read_text()).items()}
    bindings.update({r["symbol"]: r["address"] for r in rows if "symbol" in r})
    wanted = sorted({m[1] for m in re.finditer(r"(?i)undefined symbol: (\S+)", log.read_text(errors="replace"))
                     if "@" not in m[1]})
    if output.exists():
        # (the symbols the last run defined stay defined: a link log lists only what is still undefined)
        previous = {m[1] or m[2] for m in re.finditer(r"^(?:unsigned|char) (\w+)\[|^struct P_(\w+) \{", output.read_text(), re.M)}
        wanted = sorted(set(wanted) | {"_" + name for name in previous})
        # (and so do the anchors it made: data nothing names that a pointer reaches)
        for name in previous:
            if re.fullmatch(r"data_[0-9a-f]{8}", name) and "_" + name not in bindings:
                bindings["_" + name] = int(name[5:], 16)
    sizes = declared_sizes(version, [w[1:] if w.startswith("_") else w for w in wanted])
    own = defined_sizes(version)
    while True:
        text, found, skipped, count = emit(version, pe, bindings, wanted, sizes, own)
        if not found:
            break
        for address in found:
            bindings[f"_data_{address:08x}"] = address
            wanted = sorted(set(wanted) | {f"_data_{address:08x}"})
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text)
    print(f"{count} symbols; not defined: {len(skipped)}: {' '.join(skipped[:40])}")


def packed_definition(name, data, offsets, target, size=None):
    """A packed structure of NAME's DATA, with a pointer at each of OFFSETS and wherever a word is one."""
    pointers = {}
    for offset in sorted(offsets):
        expression = target(struct.unpack_from("<I", data, offset)[0])
        if expression:
            pointers[offset] = expression
    members, values, position, count = [], [], 0, 0

    def run(start, end):
        nonlocal count
        # (bytes up to a word boundary, then words, then the bytes left)
        while start < end:
            if start % 4 == 0 and end - start >= 4:
                words = (end - start) // 4
                members.append(f"unsigned m{count}[{words}];")
                values.append("{" + ", ".join(f"0x{w:x}" for w in struct.unpack_from(f"<{words}I", data, start)) + "}")
                start += words * 4
            else:
                stop = min(end, (start + 3) // 4 * 4) if start % 4 else end
                members.append(f"unsigned char m{count}[{stop - start}];")
                values.append("{" + ", ".join(f"0x{b:x}" for b in data[start:stop]) + "}")
                start = stop
            count += 1

    for offset in sorted(pointers):
        run(position, offset)
        members.append(f"unsigned m{count};")
        values.append(pointers[offset])
        count += 1
        position = offset + 4
    run(position, len(data) if size is None else size)
    return (f"#pragma pack(push, 1)\nstruct P_{name} {{ " + " ".join(members) + f" }} {name} = {{" + ", ".join(values)
            + "};\n#pragma pack(pop)")


def emit(version, pe, bindings, wanted, sizes, own):
    """(text, anchors, skipped, count): the definitions of WANTED, and the addresses a pointer reaches that no symbol
    covers, which need a definition of their own (ANCHORS non-empty: the text is incomplete)."""
    bound = sorted({a for a in bindings.values()})
    # (a name per address: a C identifier, preferably the one a source uses)
    names = {}
    for name, address in sorted(bindings.items()):
        if re.fullmatch(r"_[A-Za-z_]\w*", name):
            names.setdefault(address, name[1:])
        elif re.fullmatch(r"[A-Za-z_]\w*", name):
            names.setdefault(address, name)
    sections = {}
    placeholder = {w[1:] if w.startswith("_") else w for w in wanted}
    anchors = set()

    def section(address):
        if address not in sections:
            try:
                sections[address] = pe.section_for_address(address)
                if address >= sections[address].virtual_address + sections[address].virtual_size:
                    sections[address] = None
            except ValueError:
                sections[address] = None
        return sections[address]

    def target(value):
        """C expression for VALUE as a pointer, or None."""
        if not 0x401000 <= value < 0x600000:
            return None
        index = bisect.bisect_right(bound, value) - 1
        if index < 0 or section(value) is None:
            return None
        base = bound[index]
        reachable = index >= 0 and section(value) is section(base) and base in names and value - base < LIMIT
        if reachable and names[base] not in placeholder and names[base] in own and value - base >= own[names[base]]:
            reachable = False
        if not reachable:
            # (data that nothing covers: it gets a symbol of its own)
            if section(value).name in (".data", ".rdata", ".bss"):
                anchors.add(value)
            return None
        # (an address inside a function is a jump table entry of another unit; a static function has no symbol to refer to)
        if section(base).name == ".text" and (value != base or not {"_" + names[base], names[base]} & exported
                                              and not names[base] in decorated):
            return None
        extern.add(names[base])
        # (a byte offset: the symbol may be defined as an array of words)
        if names[base] in packed:
            expression = f"(char *)&{names[base]}"
        else:
            expression = names[base] if names[base] not in decorated and value == base else f"(char *){names[base]}"
        return f"(unsigned)({expression}" + (f" + {value - base}" if value != base else "") + ")"

    # (a function's decorated COFF name, by its C name: __stdcall _f@N, __fastcall @f@N)
    decorated = {}
    for obj in Path(f"build/{version}/compiled").rglob("*.obj"):
        for symbol in compare.read_object(obj)[0].values():
            m = re.fullmatch(r"([_@])(\w+)@(\d+)", symbol["name"])
            if m and symbol["section"] > 0:
                decorated[m[2]] = ("__stdcall" if m[1] == "_" else "__fastcall", int(m[3]))
    exported = set()
    for obj in Path(f"build/{version}/compiled").rglob("*.obj"):
        exported |= {symbol["name"] for symbol in compare.read_object(obj)[0].values()
                     if symbol["storage"] == 2 and symbol["section"] > 0}
    # (a pointer at an odd offset, as the packed structures of the plugin interface have: the symbol then is a packed
    # structure of bytes, words and pointers, as an array of words cannot carry it)
    packed, fixups = {}, set(compare.base_relocations(pe))

    def covered(value):
        """Whether VALUE is the address of data a symbol begins or contains (a function only where it begins)."""
        if section(value) is None:
            return False
        base = bound[bisect.bisect_right(bound, value) - 1]
        if section(base) is not section(value) or value - base >= LIMIT:
            return False
        return section(value).name != ".text" or value == base

    for symbol in wanted:
        name = symbol[1:] if symbol.startswith("_") else symbol
        address = bindings.get(symbol, bindings.get(name))
        if address is None or section(address) is None or section(address).name not in (".data", ".rdata"):
            continue
        i = bisect.bisect_right(bound, address)
        size = min((bound[i] if i < len(bound) else address + 4) - address, LIMIT,
                   section(address).virtual_address + section(address).virtual_size - address)
        data = pe.read(address, size)
        found = [o for o in range(0, len(data) - 3) if address + o in fixups]
        if any(o % 4 for o in found) or size % 4 or address % 4:
            packed[name] = found
    extern, body, skipped = set(), [], []
    # (in address order, so that the words of one table stay together)
    for symbol in sorted(wanted, key=lambda s: bindings.get(s, bindings.get(s[1:] if s.startswith("_") else s, 0))):
        name = symbol[1:] if symbol.startswith("_") else symbol
        address = bindings.get(symbol, bindings.get(name))
        if address is None or section(address) is None or section(address).name not in (".data", ".bss", ".rdata"):
            skipped.append(symbol)
            continue
        i = bisect.bisect_right(bound, address)
        gap = min((bound[i] if i < len(bound) else address + 4) - address, LIMIT)
        known = sizes.get(name)
        # (a declared size is the symbol's; an array of unknown length takes its neighbours' gap, whole elements)
        size = gap if known is None else min(gap, known[0] * max(gap // max(known[0], 1), 1)) if known[1] else known[0]
        section_end = section(address).virtual_address + section(address).virtual_size
        size = min(size, section_end - address)
        if section(address).name == ".bss":
            body.append(f"char {name}[{size}];")
            continue
        # (initialized data runs to its neighbour: a declared type is a decompiler's guess, and what follows it is often
        # the rest of the same object)
        size = min(gap, section_end - address)
        data = pe.read(address, size).ljust((size + 3) // 4 * 4, b"\0")
        if name in packed:
            body.append(packed_definition(name, data, packed[name], target, size))
            continue
        words = []
        for offset in range(0, len(data), 4):
            value = struct.unpack_from("<I", data, offset)[0]
            words.append((target(value) if address + offset in fixups else None) or f"0x{value:x}")
        body.append(f"unsigned {name}[{len(words)}] = {{" + ", ".join(words) + "};")
    # (the symbols a pointer refers to, and the sources define: declared here without a type)
    defined = {line.split("[")[0].split()[-1]: line.split()[0] for line in body if not line.startswith("#pragma")}
    header = ["/* Placeholder data: the original's bytes for the data the sources reference and do not yet define",
              "   (tools/gen_raw_data.py). Each symbol moves to a typed definition in the source that owns it. */"]
    declarations = [f"extern void {decorated[n][0]} {n}({', '.join(['int'] * (decorated[n][1] // 4)) or 'void'});"
                    if n in decorated else f"struct P_{n};\nextern struct P_{n} {n};" if n in packed
                    else f"extern {defined.get(n, 'char')} {n}[];" for n in sorted(extern)]
    return "\n".join(header + declarations + body) + "\n", anchors, skipped, len(body)


if __name__ == "__main__":
    main()
