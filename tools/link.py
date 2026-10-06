#!/usr/bin/env python3
"""python tools/link.py VERSION [OUTPUT]: link the compiled objects of VERSION into the compiler (default
build/VERSION/mwcceppc.exe), with the Pro 5 linker (build/mwld) and nothing of the original executable but its list
of imports: the exe is made of the sources.

The objects are prepared (tools/prepare_objects.py), the import libraries made (llvm-dlltool of LLVM), and mwld run, under
wibo when this is not Windows. The licensing library is the stand-in of tools/lmgr_stub, beside the exe."""
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import compare
import prepare_objects

# the FlexLM calls the compiler imports by ordinal (LMGR326B.dll)
LMGR = {"lp_checkout": 190, "lp_checkin": 189, "lp_errstring": 191}
RUNTIME = ("cexc.obj", "ccinit.obj", "ctls.obj")


def original_imports(pe):
    """{dll: [names]} the original executable imports by name."""
    base = pe.image_base
    coff = struct.unpack_from("<I", pe.data, 0x3C)[0] + 4
    optional = coff + 20
    rva = struct.unpack_from("<I", pe.data, optional + 96 + 8)[0]
    result, offset = {}, pe.address_to_offset(base + rva)
    while True:
        original, _, _, name, first = struct.unpack_from("<IIIII", pe.data, offset)
        if not name:
            return result
        dll = pe.read(base + name, 64).split(b"\0")[0].decode()
        names, thunk = [], pe.address_to_offset(base + (original or first))
        while True:
            entry = struct.unpack_from("<I", pe.data, thunk)[0]
            if not entry:
                break
            if not entry & 0x80000000:
                names.append(pe.read(base + entry + 2, 128).split(b"\0")[0].decode())
            thunk += 4
        result[dll] = names
        offset += 20


def decorations(paths):
    """{name: bytes} of each __stdcall symbol _name@bytes the objects mention."""
    found = {}
    for path in paths:
        for _, name, _, _, _ in prepare_objects.symbols(path.read_bytes()):
            m = re.fullmatch(r"_(\w+)@(\d+)", name)
            if m:
                found[m[1]] = m[2]
    return found


def import_library(output, dll, entries, tool):
    """An import library for DLL with ENTRIES, each a symbol with an optional ordinal: 'name', 'name@N' or
    ('name', ordinal)."""
    definition = output.with_suffix(".def")
    lines = [f"LIBRARY {dll}", "EXPORTS"]
    for entry in entries:
        lines.append(f"{entry[0]} @{entry[1]}" if isinstance(entry, tuple) else f"    {entry}")
    definition.write_text("\n".join(lines) + "\n")
    subprocess.run([tool, "-m", "i386", "-k", "-d", str(definition), "-l", str(output)], check=True)


def references(names):
    """An object that refers to NAMES and defines nothing: with it, the linker brings in their import thunks (and the
    descriptor of the library they come from)."""
    strings, symbols, relocations = bytearray(), bytearray(), bytearray()
    for index, name in enumerate(names):
        raw = name.encode()
        symbols += struct.pack("<II", 0, 4 + len(strings)) + struct.pack("<IhHBB", 0, 0, 0, 2, 0)
        strings += raw + b"\0"
        relocations += struct.pack("<IIH", 4 * index, index, 6)
    size = 4 * len(names)
    header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 20 + 40 + size + len(relocations), len(names), 0, 0)
    section = struct.pack("<8sIIIIIIHHI", b".data", 0, 0, size, 60, 60 + size, 0, len(names), 0, 0xC0300040)
    return header + section + bytes(size) + bytes(relocations) + bytes(symbols) + struct.pack("<I", 4 + len(strings)) + bytes(strings)


def main():
    version = sys.argv[1]
    output = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(f"build/{version}/mwcceppc.exe")
    linker = Path("build/mwld")
    work = Path(f"build/{version}/link")
    work.mkdir(parents=True, exist_ok=True)
    dlltool = os.environ.get("DLLTOOL") or shutil.which("llvm-dlltool")
    if not dlltool:
        raise SystemExit("llvm-dlltool (LLVM) is required to make the import libraries")
    # (the objects, ready to link)
    objects = prepare_objects.prepare_all(version)
    _, pe, _ = compare.inventory(version)
    imports = original_imports(pe)
    sizes = decorations(objects)
    kernel = [f"{name}@{sizes[name]}" for name in imports["KERNEL32.dll"]]
    import_library(work / "KERNEL32.lib", "KERNEL32.dll", kernel, dlltool)
    import_library(work / "LMGR326B.lib", "LMGR326B.dll", [(name, ordinal) for name, ordinal in LMGR.items()], dlltool)
    (work / "refs.obj").write_bytes(references(["_" + name for name in LMGR]))
    listing = work / "objects.txt"
    listing.write_text("\n".join(str(path) for path in objects) + "\n")
    runtime = [str(linker / "Win32-x86 Support/Libraries/Runtime/(Sources)" / name) for name in RUNTIME]
    command = [str(linker / "Tools/Command Line Tools/mwld.exe"), "-application", "-subsystem", "console", "-nodefaults",
               "-main", "_mainCRTStartup", "-map", str(output.with_suffix(".map")), "-o", str(output), f"@{listing}",
               *runtime, str(work / "refs.obj"), str(work / "KERNEL32.lib"), str(work / "LMGR326B.lib")]
    environment = dict(os.environ, CWFolder=str(linker.resolve()))
    if sys.platform != "win32":
        command.insert(0, os.environ.get("WIBO", "wibo"))
    output.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(command, env=environment, capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode:
        raise SystemExit(result.returncode)
    # (the licensing library the compiler imports, beside it)
    shutil.copy(Path(__file__).parent / "lmgr_stub/lmgr326b.dll", output.parent)


if __name__ == "__main__":
    main()
