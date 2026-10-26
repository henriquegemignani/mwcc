#!/usr/bin/env python3
"""python tools/import_source.py DEF OUT [--null]: the imports a module-definition file describes, as assembly source
of the import tables themselves, the long form an import library's objects stand for: the DLL's descriptor
(.idata$2), its lookup table (.idata$4), its address table (.idata$5, each entry named __imp__NAME, which the units
call through), and the hints and names (.idata$6). --null adds the null descriptor that ends the descriptors
(.idata$3), once for the executable. An export `name@bytes @hint` is imported by its undecorated name with that hint,
`name @ordinal NONAME` by ordinal. Assembled by clang for i386 COFF (configure.py, config.json "assembly")."""
import re
import sys
from pathlib import Path


def main():
    definition, out, *flags = sys.argv[1:]
    text = Path(definition).read_text()
    dll = re.search(r"^LIBRARY\s+(\S+)", text, re.M)[1]
    dll = dll if "." in dll else dll + ".dll"
    exports = [(m[1], int(m[2]), not m[3]) for m in re.finditer(r"^\s+([\w@]+)\s+@(\d+)(\s+NONAME)?\s*$", text, re.M)]
    base = dll.rsplit(".", 1)[0]
    lines = [f"# {dll}'s imports (written by tools/import_source.py from {Path(definition).as_posix()})",
             "\t.section .idata$2,\"dw\"", "\t.p2align 2", f"\t.globl __IMPORT_DESCRIPTOR_{base}",
             f"__IMPORT_DESCRIPTOR_{base}:", f"\t.rva .Llookup", "\t.long 0", "\t.long 0", "\t.rva .Ldll",
             "\t.rva .Laddresses"]
    if "--null" in flags:
        lines += ["\t.section .idata$3,\"dw\"", "\t.p2align 2", "\t.globl __NULL_IMPORT_DESCRIPTOR",
                  "__NULL_IMPORT_DESCRIPTOR:", "\t.zero 20"]

    def entry(i, ordinal, named):
        return f"\t.rva .Lname{i}" if named else f"\t.long 0x{0x80000000 | ordinal:08x}"

    lines += ["\t.section .idata$4,\"dw\"", "\t.p2align 2", ".Llookup:"]
    lines += [entry(i, ordinal, named) for i, (_, ordinal, named) in enumerate(exports)] + ["\t.long 0"]
    lines += ["\t.section .idata$5,\"dw\"", "\t.p2align 2", ".Laddresses:"]
    for i, (symbol, ordinal, named) in enumerate(exports):
        lines += [f"\t.globl __imp__{symbol}", f"__imp__{symbol}:", entry(i, ordinal, named)]
    lines += ["\t.long 0", "\t.section .idata$6,\"dw\"", "\t.p2align 1"]
    for i, (symbol, ordinal, named) in enumerate(exports):
        if named:
            lines += [f".Lname{i}:", f"\t.short {ordinal}", f"\t.asciz \"{symbol.split('@')[0]}\"", "\t.p2align 1"]
    lines += [".Ldll:", f"\t.asciz \"{dll}\"", "\t.p2align 1"]
    Path(out).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
