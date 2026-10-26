#!/usr/bin/env python3
"""python tools/attribute.py VERSION [DIR]: give the functions of config/VERSION/functions.json that have no source the
source their assertions name.

CodeWarrior's assertions pass the name of the source file (CLPlugins.c, ELF_linker.c...), so a function that refers to
such a string in the data is that file's. The source is the one of config/sources.json with that name (CLFileOps.c is
CLFileOps.cpp), else DIR/<name> (default src/linker): a file of the program the compiler's sources do not have. A
function that refers to the names of two files is left as it is."""
import json
import re
import struct
import sys
from bisect import bisect_right
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pe import PEFile
from split import base_relocations


def main():
    version = sys.argv[1]
    directory = sys.argv[2] if len(sys.argv) > 2 else "src/linker"
    path = Path(f"config/{version}/functions.json")
    config = json.loads(Path(f"config/{version}/config.json").read_text())
    pe = PEFile(Path(config["original"]))
    sources = json.loads(Path("config/sources.json").read_text())
    by_stem = {}
    for source in sources:
        by_stem.setdefault(Path(source).stem, source)
    names = {}
    for section in pe.sections:
        if section.name not in (".data", ".rdata"):
            continue
        data = pe.read(section.virtual_address, section.file_size)
        for m in re.finditer(rb"(?<![\w.])([A-Za-z][\w-]*\.(?:c|cpp))\0", data):
            # (every name the string ends with: a string without its terminator can come just before, as the 2.6
            # linker's "ELF" before "ELF_linker.c"; only the one an assertion points at counts)
            for start in range(m.start(1), m.end(1) - 2):
                name = data[start:m.end(1)].decode()
                if re.fullmatch(r"[A-Za-z][\w-]*\.(?:c|cpp)", name):
                    names[section.virtual_address + start] = by_stem.get(Path(name).stem, f"{directory}/{name}")

    functions = json.loads(path.read_text())
    starts = [int(f["address"], 16) for f in functions]
    named = {}
    for at in base_relocations(pe):
        value = struct.unpack_from("<I", pe.data, pe.address_to_offset(at))[0]
        if value not in names:
            continue
        k = bisect_right(starts, at) - 1
        if k >= 0 and at < starts[k] + functions[k]["size"]:
            named.setdefault(k, set()).add(names[value])
    count = 0
    for k, files in named.items():
        if len(files) == 1 and not functions[k].get("source"):
            functions[k]["source"] = next(iter(files))
            count += 1
    path.write_text(json.dumps(functions, indent=2) + "\n")
    print(f"{count} functions attributed by the file names their assertions give")


if __name__ == "__main__":
    main()
