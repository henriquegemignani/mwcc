#!/usr/bin/env python3
"""python tools/prepare_objects.py VERSION: copies of the compiled objects, ready to link (build/VERSION/linked).

Several sources compile the same library file under different flags and each keeps only the functions the original took
from it; the others are duplicates. A COMDAT a source compiles twice is marked to keep any one copy."""
import bisect
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import compare

NODUPLICATES, ANY = 1, 2


def symbols(data):
    """(offset, name, section, storage, aux count) of each symbol of an i386 COFF object."""
    _, _, _, symoff, nsym = struct.unpack_from("<HHIII", data)
    strings, index = symoff + nsym * 18, 0
    while index < nsym:
        offset = symoff + index * 18
        raw = data[offset:offset + 8]
        if raw[:4] == b"\0" * 4:
            start = strings + struct.unpack_from("<I", raw, 4)[0]
            name = bytes(data[start:data.index(b"\0", start)]).decode()
        else:
            name = raw.rstrip(b"\0").decode()
        yield offset, name, struct.unpack_from("<h", data, offset + 12)[0], data[offset + 16], data[offset + 17]
        index += 1 + data[offset + 17]


def common_symbols(data):
    """{name: (offset of the symbol, size)} of the uninitialized data an object declares, as COFF common symbols."""
    return {name: (offset, struct.unpack_from("<I", data, offset + 8)[0]) for offset, name, section, storage, aux in symbols(data)
            if storage == 2 and section == 0 and struct.unpack_from("<I", data, offset + 8)[0]}


def bss_image(layout):
    """An object with one uninitialized section, and a symbol at each of LAYOUT {name: offset}."""
    size = max(offset + length for offset, length in layout.values())
    strings, entries = bytearray(), bytearray()
    for name, (offset, _) in sorted(layout.items(), key=lambda item: item[1]):
        raw = name.encode()
        if len(raw) <= 8:
            entries += raw.ljust(8, b"\0")
        else:
            entries += struct.pack("<II", 0, 4 + len(strings))
            strings += raw + b"\0"
        entries += struct.pack("<IhHBB", offset, 1, 0, 2, 0)
    header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 20 + 40, len(layout), 0, 0)
    section = struct.pack("<8sIIIIIIHHI", b".bss", 0, 0, size, 0, 0, 0, 0, 0, 0xC0300080)
    return header + section + bytes(entries) + struct.pack("<I", 4 + len(strings)) + bytes(strings)


def compact_data(data, bindings):
    """DATA, an object whose .data holds the original's bytes under symbols, with the padding the compiler put between
    them taken out: the original's neighbours stay neighbours, and what is at an odd address is still there."""
    data = bytearray(data)
    nsec = struct.unpack_from("<H", data, 2)[0]
    header = next((20 + 40 * i for i in range(nsec) if bytes(data[20 + 40 * i:28 + 40 * i]).rstrip(b"\0") == b".data"), None)
    if header is None:
        return bytes(data)
    section = (header - 20) // 40 + 1
    size, raw, reloc_pointer = struct.unpack_from("<III", data, header + 16)
    count = struct.unpack_from("<H", data, header + 32)[0]
    placed = sorted((struct.unpack_from("<I", data, offset + 8)[0], offset, name) for offset, name, sec, storage, aux
                    in symbols(data) if sec == section and storage == 2 and name in bindings)
    extents = {name: (placed[i + 1][0] if i + 1 < len(placed) else size) - value for i, (value, offset, name) in enumerate(placed)}
    members = sorted(placed, key=lambda member: bindings[member[2]])
    addresses = sorted(set(bindings.values()))
    old = bytes(data[raw:raw + size])
    new, moves, previous_end = bytearray(), [], None
    for index, (value, offset, name) in enumerate(members):
        address = bindings[name]
        following = addresses[bisect.bisect_right(addresses, address):]
        extent = extents[name]
        length = min((following[0] if following else address + 4) - address, extent)
        if previous_end != address:
            # (a new piece: padded to the address's alignment, as it was)
            new += b"\0" * ((address - len(new)) % 4)
        moves.append((value, length, len(new), offset))
        new += old[value:value + length]
        previous_end = address + length
    for value, length, position, offset in moves:
        struct.pack_into("<I", data, offset + 8, position)
    # (each relocation moves with the bytes it patches)
    moves.sort()
    starts = [move[0] for move in moves]
    for index in range(count):
        entry = reloc_pointer + 10 * index
        where = struct.unpack_from("<I", data, entry)[0]
        k = bisect.bisect_right(starts, where) - 1
        if k >= 0 and where < moves[k][0] + moves[k][1]:
            struct.pack_into("<I", data, entry, where - moves[k][0] + moves[k][2])
    data[raw:raw + size] = bytes(new).ljust(size, b"\0")
    struct.pack_into("<I", data, header + 16, len(new))
    # (the section symbol's length)
    for offset, name, sec, storage, aux in symbols(data):
        if sec == section and storage == 3 and aux:
            struct.pack_into("<I", data, offset + 18, len(new))
    return bytes(data)


def prepare(data, shared=(), placed=()):
    """DATA with its duplicate COMDATs made to keep any copy, and the data symbols SHARED defined elsewhere left
    undefined (the first object to define one keeps it)."""
    data = bytearray(data)
    for offset, name, section, storage, aux in symbols(data):
        if name in shared and section > 0 and storage == 2:
            struct.pack_into("<IhH", data, offset + 8, 0, 0, 0)
        elif name in placed and section == 0 and storage == 2:
            struct.pack_into("<I", data, offset + 8, 0)
    machine, nsec, _, symoff, nsym = struct.unpack_from("<HHIII", data)
    if machine != 0x14C:
        raise SystemExit("expected i386 COFF")
    for offset, name, section, storage, aux in symbols(data):
        # (a section symbol's auxiliary record ends with the COMDAT selection)
        if storage == 3 and aux and name.startswith(".") and data[offset + 18 + 14] == NODUPLICATES:
            data[offset + 18 + 14] = ANY
    return bytes(data)


def prepare_all(version):
    """The objects of VERSION prepared to link (build/VERSION/linked): their paths."""
    source, target = Path(f"build/{version}/compiled"), Path(f"build/{version}/linked")
    paths = sorted(source.rglob("*.obj"))
    contents = {path: path.read_bytes() for path in paths}
    # (a data symbol two objects define, outside a function's COMDAT: the later ones refer to the first's)
    owner, shared = {}, {}
    for path in paths:
        sections = {}
        for offset, name, section, storage, aux in symbols(contents[path]):
            if storage == 2 and section > 0 and name not in sections:
                if name in owner:
                    shared.setdefault(path, set()).add(name)
                else:
                    owner[name] = path
    # (the uninitialized data the original names: laid out as it was, in one piece, as the code reads and writes
    # neighbours through a symbol)
    _, pe, _ = compare.inventory(version)
    bss = next(section for section in pe.sections if section.name == ".bss")
    bindings = {name: int(value, 0) for name, value in
                json.loads(Path(f"config/{version}/bindings.json").read_text()).items()}
    sizes = {}
    for path in paths:
        for name, (_, size) in common_symbols(contents[path]).items():
            if bindings.get(name, 0) in range(bss.virtual_address, bss.virtual_address + bss.virtual_size):
                sizes[name] = max(sizes.get(name, 0), size)
    layout = {name: (bindings[name] - bss.virtual_address, size) for name, size in sizes.items()}
    for path in paths:
        output = target / path.relative_to(source)
        output.parent.mkdir(parents=True, exist_ok=True)
        prepared = prepare(contents[path], shared.get(path, ()), layout)
        if path.name == "raw_data.c.obj":
            # (the anchors, data nothing but a pointer reaches, are named by their addresses)
            anchors = {name: int(name[6:], 16) for _, name, _, _, _ in symbols(prepared)
                       if re.fullmatch(r"_data_[0-9a-f]{8}", name)}
            prepared = compact_data(prepared, {**anchors, **bindings})
        output.write_bytes(prepared)
    (target / "bss_image.obj").write_bytes(bss_image(layout))
    return sorted(target.rglob("*.obj"))


def main():
    prepare_all(sys.argv[1])


if __name__ == "__main__":
    main()
