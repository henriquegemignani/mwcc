#!/usr/bin/env python3
"""python tools/ghidra_names.py VERSION [OUT]: write the names of config/VERSION's functions and data as the argument
lists of the Ghidra catalog script apply-name-list (ApplyNameList.java): one line per chunk, `<payload> <sha1>`, each
small enough for one run.

A payload is `F<address> <name>` (a function, created if Ghidra has none there) and `D<address> <name>` (a data label)
entries joined by ';'; addresses are hexadecimal without the leading 00. Functions named only by an address
(fn_XXXXXXXX) are left out, and so is data named by another executable's address (data_XXXXXXXX, DAT_, PTR_), by a
mangled C++ name or as an import slot."""
import hashlib
import json
import re
import sys
from pathlib import Path

CHUNK = 7800


def main():
    version = sys.argv[1]
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    functions = json.loads(Path(f"config/{version}/functions.json").read_text())
    bindings = json.loads(Path(f"config/{version}/bindings.json").read_text())
    entries = [f"F{int(f['address'], 16):x} {f['name']}" for f in functions
               if not re.fullmatch(r"(auto_)?fn_[0-9a-f]{8}", f["name"])]
    entries += [f"D{int(address, 16):x} {name}" for name, address in bindings.items()
                if not re.fullmatch(r"\??_*(data|DAT|PTR|at)_.*|.*@@3.*|__imp__.*", name)]
    chunks, current = [], []
    for entry in entries:
        if current and len(";".join(current + [entry])) > CHUNK:
            chunks.append(";".join(current))
            current = []
        current.append(entry)
    if current:
        chunks.append(";".join(current))
    lines = [f"{chunk} {hashlib.sha1(chunk.encode()).hexdigest()}" for chunk in chunks]
    text = "\n".join(lines) + "\n"
    if out:
        out.write_text(text)
    else:
        sys.stdout.write(text)
    print(f"{len(entries)} names in {len(chunks)} chunks", file=sys.stderr)


if __name__ == "__main__":
    main()
