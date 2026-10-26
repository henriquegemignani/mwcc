#!/usr/bin/env python3
"""python tools/derive_splits.py VERSION [--reference VERSION] [--exe PATH] [--out DIR]: write config/VERSION/splits.txt
and symbols.txt (decomp-toolkit's formats, read by tools/split.py) for a version that has only a function list.

The unit boundaries cannot be read from the executable; they are inferred:

- text: each function in config/VERSION/functions.json carries the source it was attributed to (or a "unit" that
  overrides it). The units are put in the reference version's order (a unit the reference has not goes by the median
  address of its functions), and functions are assigned to units in that order, each to the unit of its source or,
  failing that, the one that keeps the sequence monotone and has the fewest changes;
- data: a unit's data is laid out in the link order of its text, so the objects the code references are assigned to
  units by the same monotone assignment (the owner of an object is the unit referencing it most consistently) and each
  unit's range runs up to the next unit's first object;
- the runtime sections (.rdata, .exc, .CRT, .tls) are the reference's, moved by the difference of their addresses.

A symbol is made for every address that a base relocation or a rel32 branch targets, named by bindings.json when it is
bound, else by its address. Nothing here claims a unit is split where the original's translation unit split: the
relink only needs the order and the bytes to be right.
"""
import argparse
import json
import re
import statistics
import struct
import sys
from bisect import bisect_left, bisect_right
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pe import PEFile
from split import base_relocations, branches, read_splits, read_symbols

DATA_SECTIONS = (".data", ".bss")
RUNTIME_SECTIONS = (".rdata", ".exc", ".CRT", ".tls")
EPSILON = 0.01  # (the cost of changing units between two functions with no information)


def folder(version):
    return version if version.startswith(("GC_", "LD_")) else "GC_" + version.replace(".", "_")


def compiled_folder(version):
    """The build folder of the objects compiled for VERSION: a linker's shared sources are the compiler's of its release
    (config.json "compiler_version")."""
    config = json.loads(Path(f"config/{folder(version)}/config.json").read_text())
    return config.get("compiler_version", folder(version))


def monotone_assignment(items, unit_count, cost, free_last=None):
    """The nondecreasing unit index of each item: cost(i, u) is the cost of item i in unit u; changing unit costs
    EPSILON. FREE_LAST, a unit index, is where the cost of every item is FREE_LAST_COST[0] (the common block)."""
    inf = float("inf")
    best = [0.0] * unit_count
    back = []
    for i in range(len(items)):
        prefix, argmin = [0.0] * unit_count, [0] * unit_count
        low, low_at = inf, 0
        for u in range(unit_count):
            if best[u] <= low:
                low, low_at = best[u], u
            prefix[u], argmin[u] = low, low_at
        new = [0.0] * unit_count
        choice = [0] * unit_count
        for u in range(unit_count):
            stay = best[u]
            move = prefix[u] + EPSILON
            if stay <= move:
                new[u], choice[u] = stay + cost(i, u), u
            else:
                new[u], choice[u] = move + cost(i, u), argmin[u]
        best = new
        back.append(choice)
    if not items:
        return []
    u = min(range(unit_count), key=lambda k: (best[k], k))
    owners = [0] * len(items)
    for i in range(len(items) - 1, -1, -1):
        owners[i] = u
        u = back[i][u]
    return owners


class Image:
    """An executable and what its function list, bindings and fixups say about it."""

    def __init__(self, version, exe):
        self.version = version
        config = json.loads(Path(f"config/{folder(version)}/config.json").read_text())
        self.config = config
        self.pe = PEFile(Path(exe or config["original"]))
        self.fixups = base_relocations(self.pe)
        self.functions = sorted(json.loads(Path(f"config/{folder(version)}/functions.json").read_text()),
                                key=lambda f: int(f["address"], 16))
        for f in self.functions:
            f["start"] = int(f["address"], 16)
        self.bindings = {name: int(address, 16) for name, address in json.loads(
            Path(f"config/{folder(version)}/bindings.json").read_text()).items()}
        self.sections = {s.name: s for s in self.pe.sections}
        self.add_missing_functions()

    def add_missing_functions(self):
        """Code the function list leaves out: import thunks (jmp [__imp_x]) and functions it does not list."""
        slots = dict(import_names(self))
        extra = []
        functions = self.functions
        for k, f in enumerate(functions):
            end = f["start"] + f["size"]
            following = functions[k + 1]["start"] if k + 1 < len(functions) else None
            if following is None or following <= end:
                continue
            data = self.pe.read(end, following - end)
            padding = (0, 0xCC)
            if all(b in padding for b in data):
                continue
            aligned = (end + 15) & ~15
            if end != aligned and data[0] not in padding:
                # (the tail of the function that ends here: the bytes up to the first padding)
                run = next((i for i, b in enumerate(data) if b in padding and not self.operand(end + i)), len(data))
                f["size"] += run
                end += run
                aligned = max(aligned, (end + 15) & ~15)
                data = data[run:]
            at = max(aligned, end)
            while at < following:
                chunk = self.pe.read(at, following - at)
                first = next((i for i, b in enumerate(chunk) if b not in padding), None)
                if first is None:
                    break
                at += first
                chunk = chunk[first:]
                if chunk[:2] == bytes([0xFF, 0x25]) and len(chunk) >= 6:
                    slot = struct.unpack_from("<I", chunk, 2)[0]
                    name = slots.get(slot, "__imp__unknown").replace("__imp__", "_", 1)
                    extra.append({"name": name, "address": f"0x{at:08x}", "size": 6, "start": at, "thunk": True})
                    at += 6
                    continue
                last = max(i for i, b in enumerate(chunk) if b not in padding or self.operand(at + i))
                extra.append({"name": f"fn_{at:08x}", "address": f"0x{at:08x}", "size": last + 1, "start": at})
                break
        self.functions = sorted(functions + extra, key=lambda f: f["start"])

    def operand(self, address):
        """Whether the byte at ADDRESS is one of a relocated operand's (a zero in an address is not padding)."""
        k = bisect_right(self.fixups, address) - 1
        return k >= 0 and address < self.fixups[k] + 4

    def section_of(self, address):
        try:
            return self.pe.section_for_address(address).name
        except ValueError:
            return None

    def end_of(self, name):
        section = self.sections[name]
        return section.virtual_address + section.virtual_size


def text_units(image, reference_units):
    """([unit name in order], {function start: unit index}) for the functions."""
    slots = {slot: (symbol, dll) for slot, symbol, dll in import_table(image)}

    def thunk_dll(f):
        """The DLL a jmp [__imp_x] stub of the function list imports from."""
        if f["size"] == 6 and image.pe.read(f["start"], 2) == bytes([0xFF, 0x25]):
            slot = struct.unpack_from("<I", image.pe.read(f["start"], 6), 2)[0]
            return slots[slot][1] if slot in slots else None
        return None

    defined = compiled_definitions(image.version)
    labels, run = [], None
    for f in image.functions:
        dll = thunk_dll(f)
        # (a function's "unit" names its unit outright, for code the compiler's objects have elsewhere; a linker's own
        # unit, src/linker/, is not among the compiler's objects: its functions are where the list puts them, though
        # the compiler's objects define some of their names in their own units)
        if f.get("unit"):
            label = f["unit"]
        elif f.get("source", "").startswith("src/linker/"):
            label = f["source"]
        elif f["name"] in defined:
            label = defined[f["name"]]
        elif f.get("source"):
            label = f["source"]
        elif dll is not None:
            # (each stub run of one library is its own object, but the licensing library is one)
            if dll.upper().startswith("LMGR"):
                label = "lmgr326b"
            else:
                if run is None or run[0] != dll or f["start"] - run[2] > 16:
                    run = (dll, f["start"], f["start"])
                run = (run[0], run[1], f["start"] + 6)
                label = f"{dll.lower()}_stubs_{run[1]:08X}"
        else:
            label = None
        if dll is None:
            run = None
        labels.append(label)
    # (the units' order is that of the addresses of their functions: the reference's order is not kept, as the link
    # order of the version differs)
    median = {}
    for label, f in zip(labels, image.functions):
        if label is not None:
            median.setdefault(label, []).append(f["start"])
    names = sorted(median, key=lambda u: (statistics.median(median[u]), min(median[u])))
    index = {unit: i for i, unit in enumerate(names)}

    def cost(i, u):
        label = labels[i]
        return 0.0 if label is None or index[label] == u else 1.0

    owners = monotone_assignment(labels, len(names), cost)
    return names, {f["start"]: owner for f, owner in zip(image.functions, owners)}


def collect_references(image, owner_of_function):
    """({address: set of unit indices that reference it}, [every address referenced from anywhere]) of the fixups and
    the rel32 branches leaving a function."""
    refs = {}
    pe, fixups = image.pe, image.fixups
    starts = [f["start"] for f in image.functions]
    for f, address in zip(image.functions, starts):
        unit = owner_of_function[address]
        end = address + f["size"]
        for at in fixups[bisect_left(fixups, address):bisect_left(fixups, end)]:
            value = struct.unpack_from("<I", pe.data, pe.address_to_offset(at))[0]
            refs.setdefault(value, set()).add(unit)
        try:
            for field, target in branches(pe.read(address, f["size"]), address):
                if not address <= target < end:
                    refs.setdefault(target, set()).add(unit)
        except (KeyError, IndexError):
            pass
    everywhere = set()
    for at in fixups:
        try:
            everywhere.add(struct.unpack_from("<I", pe.data, pe.address_to_offset(at))[0])
        except ValueError:
            pass
    return refs, everywhere


def data_pointers(image, refs, section, target_section=None):
    """[(where, target)] of the pointers in a section to objects of it (or of TARGET_SECTION) that no code
    references."""
    low, high = image.sections[section].virtual_address, image.end_of(section)
    target = target_section or section
    target_low, target_high = image.sections[target].virtual_address, image.end_of(target)
    found = []
    for at in image.fixups[bisect_left(image.fixups, low):bisect_left(image.fixups, high)]:
        try:
            value = struct.unpack_from("<I", image.pe.data, image.pe.address_to_offset(at))[0]
        except ValueError:
            continue
        if target_low <= value < target_high and value not in refs:
            found.append((at, value))
    return found


def data_owners(image, refs, unit_count, section, common_unit):
    """[(address, owner)] for the referenced objects in a section; COMMON_UNIT is the unit index of the tail block."""
    low, high = image.sections[section].virtual_address, image.end_of(section)
    addresses = sorted(a for a in refs if low <= a < high)

    def cost(i, u):
        if u == common_unit:
            return 0.9 if section == ".bss" else 2.0
        return 0.0 if u in refs[addresses[i]] else 1.0

    owners = monotone_assignment(addresses, unit_count, cost)
    return list(zip(addresses, owners))


def exception_ranges(image, order, ranges, owner_of_function):
    """Lay the units' .rdata and .exc$BBB ranges out again in the units' order here. The runtime sections are the
    reference's, moved by the difference of their addresses, which is right only when their units are in the
    reference's order: a unit that moved (the runtime's operator new before _chkstk in the 1.0 linker) takes its
    exception tables (.exc$BBB, 8 bytes per function: its address and its action table in .rdata) and its .rdata with
    it. The ranges keep their sizes. Kept only when every .exc$BBB entry is then in the unit that has its function."""
    starts = sorted(owner_of_function)
    index = {unit: i for i, unit in enumerate(order)}
    moved = {}
    for section, wanted in ((".rdata", None), (".exc", ".exc$BBB")):
        pieces = [(index[unit], k, unit, r) for unit in order for k, r in enumerate(ranges[unit])
                  if r[0] == section and r[3].get("rename") == wanted]
        if not pieces:
            continue
        at = min(r[1] for *_, r in pieces)
        laid = []
        for *_, unit, r in sorted(pieces, key=lambda p: (p[0], p[1])):
            laid.append((unit, r, (section, at, at + r[2] - r[1], r[3])))
            at += r[2] - r[1]
        moved[section] = laid
    for unit, _, (section, start, end, _) in moved.get(".exc", []):
        for at in range(start, end, 8):
            function = struct.unpack_from("<I", image.pe.read(at, 4))[0]
            k = bisect_right(starts, function) - 1
            if k < 0 or order[owner_of_function[starts[k]]] != unit:
                return
    for laid in moved.values():
        for unit, old, new in laid:
            ranges[unit][ranges[unit].index(old)] = new


def derive(version, reference, exe, out):
    image = Image(version, exe)
    ref_sections, ref_units = read_splits(f"config/{folder(reference)}/splits.txt")
    ref_symbols = read_symbols(f"config/{folder(reference)}/symbols.txt")
    names, owner_of_function = text_units(image, ref_units)

    ref_names = [u for u, _ in ref_units]
    text_names = set(names)
    # data-only units: put each after the nearest preceding reference unit that has code here
    order = list(names)
    for i, unit in enumerate(ref_names):
        if unit in text_names:
            continue
        previous = next((p for p in reversed(ref_names[:i]) if p in order), None)
        position = order.index(previous) + 1 if previous else 0
        order.insert(position, unit)
    if folder(version).startswith("LD_") and "common" in order:
        # (a linker's COMMON block follows the statics of all its units: its own units come after the compiler's
        # last one the reference has)
        order.remove("common")
        order.append("common")
    index = {unit: i for i, unit in enumerate(order)}
    old_to_new = {i: index[unit] for i, unit in enumerate(names)}
    owner_of_function = {a: old_to_new[o] for a, o in owner_of_function.items()}
    unit_count = len(order)
    common_unit = index.get("common", unit_count - 1)

    refs, everywhere = collect_references(image, owner_of_function)

    ranges = {u: [] for u in order}
    # text: from a unit's first function to the next unit's
    text_start = image.sections[".text"].virtual_address
    text_end = text_start + image.sections[".text"].virtual_size
    firsts = {}
    for f in image.functions:
        firsts.setdefault(owner_of_function[f["start"]], f["start"])
    code_units = sorted(firsts)
    for k, u in enumerate(code_units):
        start = text_start if k == 0 else firsts[u]
        end = firsts[code_units[k + 1]] if k + 1 < len(code_units) else text_end
        # (code is linked at an alignment per function: a run of functions not on 16-byte boundaries is its own range,
        # as such a function was assembled packed against its neighbours)
        groups = []
        for f in image.functions:
            if owner_of_function[f["start"]] != u:
                continue
            natural = min(16, f["start"] & -f["start"])
            if not groups or groups[-1][0] != natural:
                groups.append([natural, f["start"]])
        for g, (natural, first) in enumerate(groups):
            lo = start if g == 0 else first
            hi = groups[g + 1][1] if g + 1 < len(groups) else end
            ranges[order[u]].append((".text", lo, hi, {"align": str(natural)} if natural < 16 else {}))

    # the runtime sections, from the reference
    ref_pe = PEFile(Path(json.loads(Path(f"config/{folder(reference)}/config.json").read_text())["original"]))
    ref_base = {s.name: s.virtual_address for s in ref_pe.sections}
    for unit, unit_ranges in ref_units:
        if unit not in index:
            continue
        for section, start, end, options in unit_ranges:
            if section in RUNTIME_SECTIONS or (section in DATA_SECTIONS and False):
                delta = image.sections[section].virtual_address - ref_base[section]
                ranges[unit].append((section, start + delta, end + delta, dict(options)))

    exception_ranges(image, order, ranges, owner_of_function)

    # .data and .bss, from the references
    boundaries = {}
    data_owned = {}
    for section in DATA_SECTIONS:
        owned = data_owners(image, refs, unit_count, section, common_unit if section == ".bss" else -1)
        low, high = image.sections[section].virtual_address, image.end_of(section)
        # (an object only another object points to, at the end of a unit's objects, is the unit's that has the pointer
        # when the pointer is in the next unit: MSL's locale strings, which its tables point to, after DWARF_line.c)
        pointers = data_pointers(image, refs, section)
        if section == ".bss" and ".data" in data_owned:
            # (a static only .data points to is the unit's whose .data has the pointer: ELF_gen.c's buffer)
            addresses = [a for a, _ in data_owned[".data"]]
            extra = {}
            for at, value in data_pointers(image, refs, ".data", ".bss"):
                k = bisect_right(addresses, at) - 1
                if k >= 0:
                    extra.setdefault(value, set()).add(data_owned[".data"][k][1])
            if extra:
                refs = {**refs, **extra}
                owned = data_owners(image, refs, unit_count, section, common_unit)
        if pointers:
            addresses = [a for a, _ in owned]
            extra = {}
            for at, value in pointers:
                k, j = bisect_right(addresses, at) - 1, bisect_right(addresses, value)
                if k >= 0 and j < len(addresses) and owned[k][1] == owned[j][1] and j > 0 and owned[j - 1][1] != owned[j][1]:
                    extra.setdefault(value, set()).add(owned[j][1])
            if extra:
                refs = {**refs, **extra}
                owned = data_owners(image, refs, unit_count, section, common_unit if section == ".bss" else -1)
        data_owned[section] = owned
        by_unit = {}
        for address, owner in owned:
            by_unit.setdefault(owner, []).append(address)
        units_here = sorted(by_unit)
        # (a unit's range ends where the next unit's objects start; the first begins at the section's start)
        starts = [low if k == 0 else min(by_unit[u]) & ~7 for k, u in enumerate(units_here)]
        for k, u in enumerate(units_here):
            end = starts[k + 1] if k + 1 < len(units_here) else high
            if k + 1 == len(units_here) and section == ".bss" and end & 7:
                # (the linker rounds an object up to its alignment: what the section has beyond is one-byte COMMON)
                ranges[order[u]].append((section, starts[k], end & ~7, {}))
                ranges[order[u]].append((section, end & ~7, end, {"common": "1"}))
                continue
            ranges[order[u]].append((section, starts[k], end, {}))

    # a section the reference has not (the resources of a version that has them): in the executable's order, and no unit
    # holds it (tools/split.py writes a .res file the linker makes it from); the linker writes the relocations itself
    sections = {}
    for section in image.pe.sections:
        if section.name in ref_sections:
            sections[section.name] = ref_sections[section.name]
        elif section.name != ".reloc":
            sections[section.name] = {"type": "data", "align": "4"}
    ref_sections = sections

    # (what the 1.2.5 splits have that is not a unit in the text: kept as they are)
    image.deltas = {name: image.sections[name].virtual_address - ref_base[name]
                    for name in RUNTIME_SECTIONS if name in image.sections}
    return image, order, ranges, owner_of_function, refs, everywhere, ref_units, ref_sections


COFF_STORAGE_STATIC = 3


def compiled_definitions(version):
    """{function name: source} of the functions the version's compiled objects define: the unit a function is in is the
    source that has it, whatever the function list attributed it to (the list's sources come from another version's
    layout). A name two sources define is left out."""
    from glob import glob
    root = f"build/{compiled_folder(version)}/compiled/"
    found, clash = {}, set()
    for path in glob(root + "**/*.obj", recursive=True):
        source = path.replace("\\", "/").removeprefix(root).removesuffix(".obj")
        data = Path(path).read_bytes()
        symptr, count = struct.unpack_from("<II", data, 8)
        strings = symptr + count * 18
        sections = struct.unpack_from("<H", data, 2)[0]
        code = set()
        for k in range(sections):
            header = 20 + 40 * k
            if data[header:header + 5] == b".text" and struct.unpack_from("<I", data, header + 36)[0] & 0x20:
                code.add(k + 1)
        i = 0
        while i < count:
            at = symptr + 18 * i
            raw = data[at:at + 8]
            section, kind, storage, aux = struct.unpack_from("<hHBB", data, at + 12)
            i += 1 + aux
            if section not in code or storage not in (2, 3) or kind & 0xF0 != 0x20:
                continue
            if raw[:4] == b"\0\0\0\0":
                offset = struct.unpack_from("<I", raw, 4)[0]
                name = data[strings + offset:data.index(b"\0", strings + offset)].decode("latin-1")
            else:
                name = raw.rstrip(b"\0").decode("latin-1")
            plain = name if name.startswith("?") else re.sub(r"@\d+$", "", name).removeprefix("_")
            if found.setdefault(plain, source) != source:
                clash.add(plain)
    # (a name made from an address names another function in another executable: the compiler's objects for a linker)
    foreign = compiled_folder(version) != folder(version)
    return {k: v for k, v in found.items() if k not in clash and not (foreign and re.fullmatch(r"fn_[0-9a-f]{8}", k))}


def compiled_names(version):
    """{undecorated name: decorated name} of the symbols the version's compiled objects define or reference (names that
    decorate two ways are left out). A linker's are the compiler's objects and its own (the linker's sources)."""
    from glob import glob
    names, clash = {}, set()
    folders = dict.fromkeys([compiled_folder(version), folder(version)])
    paths = [p for f in folders for p in glob(f"build/{f}/compiled/**/*.obj", recursive=True)]
    for path in paths:
        data = Path(path).read_bytes()
        symptr, count = struct.unpack_from("<II", data, 8)
        strings = symptr + count * 18
        i = 0
        while i < count:
            raw = data[symptr + 18 * i:symptr + 18 * i + 8]
            aux = data[symptr + 18 * i + 17]
            # (a static's name decorates nothing: ParserFace.c's own cdecl xmalloc is not the driver's)
            external = data[symptr + 18 * i + 16] == 2
            if raw[:4] == b"\0\0\0\0":
                offset = struct.unpack_from("<I", raw, 4)[0]
                name = data[strings + offset:data.index(b"\0", strings + offset)].decode("latin-1")
            else:
                name = raw.rstrip(b"\0").decode("latin-1")
            i += 1 + aux
            if name.startswith((".", "@", "$")) or name.startswith("?") or name == "" or not external:
                continue
            plain = re.sub(r"@\d+$", "", name).removeprefix("_")
            if names.setdefault(plain, name) != name:
                clash.add(plain)
    return {k: v for k, v in names.items() if k not in clash}


def import_names(image):
    """[(slot address, symbol name)] of the executable's imports, in the order of its import address table."""
    return [(slot, symbol) for slot, symbol, _ in import_table(image)]


def import_table(image):
    """[(slot address, symbol name, DLL name)] of the executable's imports, in the order of its import address table."""
    pe = image.pe
    base = pe.image_base
    directory = struct.unpack_from("<I", pe.data, struct.unpack_from("<I", pe.data, 0x3C)[0] + 24 + 96 + 8)[0]
    decorated = {}
    for library in Path("lib/win32sdk").glob("*.LIB"):
        for found in re.finditer(rb"__imp__([A-Za-z0-9_]+)@(\d+)", library.read_bytes()):
            decorated[found[1].decode()] = f"{found[1].decode()}@{found[2].decode()}"
    # (and the stdcall decorations the definition files give the imports of the libraries that are not in the SDK's)
    for definition in Path("config").glob("*.def"):
        for found in re.finditer(r"^\s+(\w+)@(\d+)\s+@", definition.read_text(), re.M):
            decorated[found[1]] = f"{found[1]}@{found[2]}"
    # (the licensing library is imported by ordinal: the names the .def file gives them)
    ordinals = {}
    for line in Path("config/lmgr326b.def").read_text().splitlines():
        match = re.match(r"\s*(\w+)\s*@(\d+)\s+NONAME", line)
        if match:
            ordinals[int(match[2])] = match[1]
    out, at = [], base + directory
    while True:
        original_first, _, _, name, first = struct.unpack("<IIIII", pe.read(at, 20))
        if not name:
            break
        table = base + (first or original_first)
        dll = pe.read(base + name, 32).split(bytes([0]))[0].decode()
        slot = 0
        while True:
            value = struct.unpack("<I", pe.read(table + 4 * slot, 4))[0]
            if not value:
                break
            if value >> 31:
                symbol = "__imp__" + ordinals[value & 0xFFFF]
            else:
                function = pe.read(base + value + 2, 64).split(b"\0")[0].decode()
                symbol = "__imp__" + decorated.get(function, function)
            out.append((table + 4 * slot, symbol, dll))
            slot += 1
        at += 20
    return out


def pe_thunk(image, address):
    """The import slot a jmp [slot] at ADDRESS goes through, else None."""
    code = image.pe.read(address, 6)
    return struct.unpack_from("<I", code, 2)[0] if code[:2] == bytes([0xFF, 0x25]) else None


def make_symbols(image, order, ranges, owner_of_function, refs, ref_symbols):
    """The lines of symbols.txt."""
    lookup = []
    for unit, unit_ranges in ranges.items():
        for section, start, end, _ in unit_ranges:
            lookup.append((start, end, section, unit))
    lookup.sort()
    starts = [entry[0] for entry in lookup]

    def unit_at(address):
        k = bisect_right(starts, address) - 1
        while k >= 0 and lookup[k][0] <= address:
            if address < lookup[k][1]:
                return lookup[k][3]
            k -= 1
        return None

    index = {unit: i for i, unit in enumerate(order)}
    # (every reference: from which unit to which address)
    sources = {}
    pe, fixups = image.pe, image.fixups
    for at in fixups:
        try:
            value = struct.unpack_from("<I", pe.data, pe.address_to_offset(at))[0]
        except ValueError:
            continue
        unit = unit_at(at)
        if unit is not None:
            sources.setdefault(value, set()).add(unit)
    for address, units in refs.items():
        sources.setdefault(address, set()).update(order[u] for u in units)

    bound = {}
    for name, address in image.bindings.items():
        bound.setdefault(address, name)
    decorated = compiled_names(image.version)
    from_reference = {}
    for name, section, address, options in ref_symbols:
        if options.get("type") == "function":
            from_reference.setdefault(re.sub(r"@\d+$", "", name).removeprefix("_"), name)

    lines = []
    taken = {}

    def unique(name, address):
        if name in taken and taken[name] != address:
            name = f"{name}__{address:08X}"
        taken[name] = address
        return name

    function_starts = {f["start"] for f in image.functions}
    slots = dict(import_names(image))
    functions = []
    for f in image.functions:
        address = f["start"]
        raw = f["name"]
        if f["size"] == 6 and pe_thunk(image, address) in slots:
            name = slots[pe_thunk(image, address)].replace("__imp__", "_", 1)
        elif address in bound:
            name = bound[address]
        elif raw.startswith("?"):
            name = raw
        else:
            name = decorated.get(raw) or from_reference.get(raw) or "_" + raw
        functions.append((address, f["size"], name))
    # (a function the list names as a data object is bound under: the object keeps the name)
    data_names = {name for address, name in bound.items() if address not in function_starts}
    functions = [(a, z, f"{n}__{a:08X}" if n in data_names and bound.get(a) != n else n) for a, z, n in functions]
    counts = {}
    for _, _, name in functions:
        counts[name] = counts.get(name, 0) + 1
    for address, size, name in functions:
        unit = order[owner_of_function[address]]
        shared = sources.get(address, set()) - {unit}
        scope = "global"
        if counts[name] > 1:
            if shared:
                name = f"{name}__{address:08X}"
            else:
                scope = "local"
        lines.append((".text", address, f"{name} = .text:0x{address:08X}; // type:function size:0x{size:X} "
                      f"scope:{scope}"))

    # data objects: every bound or referenced address inside a unit's range of a data section, but for those inside an
    # object of a known size (config.json "object_sizes", by its bound name: a source unit's array that other units
    # read at offsets into it), whose references are then the object's symbol and an offset
    targets = set(bound) | set(sources)
    for name, size in image.config.get("object_sizes", {}).items():
        start = image.bindings[name]
        targets -= {a for a in targets if start < a < start + int(size, 16)}
    for unit, unit_ranges in ranges.items():
        for section, start, end, options in unit_ranges:
            if section == ".text" or section in RUNTIME_SECTIONS:
                continue
            here = sorted(a for a in targets if start <= a < end)
            for k, address in enumerate(here):
                stop = here[k + 1] if k + 1 < len(here) else end
                name = bound.get(address)
                if name is not None and address in function_starts:
                    continue
                shared = sources.get(address, set()) - {unit}
                scope = "global" if name is not None or shared else "local"
                if name is None:
                    name = f"lbl_{address:08X}"
                lines.append((section, address, f"{unique(name, address)} = {section}:0x{address:08X}; // type:object "
                              f"size:0x{stop - address:X} scope:{scope}"))
    # (the runtime sections' symbols are the reference's, moved)
    for name, section, address, options in ref_symbols:
        if section in RUNTIME_SECTIONS:
            moved = address + image.deltas[section]
            kind = " ".join(f"{k}:{v}" for k, v in options.items())
            entry = f"{name} = {section}:0x{moved:08X}; // {kind}"
            if all(text.split(" = ")[0] != name or e != moved for e, _a, text in [(0, 0, "")]) and                     not any(a == moved and t.startswith(name + " = ") for _s, a, t in lines):
                lines.append((section, moved, entry))
    for address, name in import_names(image):
        lines.append((".idata", address, f"{name} = .idata:0x{address:08X}; // type:object size:0x4 scope:global"))
    lines.sort(key=lambda entry: entry[1])
    return [text for _, _, text in lines]


def format_splits(sections, order, ranges):
    lines = ["Sections:"]
    for name, options in sections.items():
        lines.append("\t" + f"{name:<11} " + " ".join(f"{k}:{v}" for k, v in options.items()))
    lines.append("")
    section_order = list(sections)
    for unit in order:
        entries = sorted(ranges[unit], key=lambda r: (section_order.index(r[0]), r[1]))
        if not entries:
            continue
        lines.append(f"{unit}:")
        for section, start, end, options in entries:
            extra = "".join(f" {k}:{v}" for k, v in options.items())
            lines.append(f"\t{section:<11} start:0x{start:08X} end:0x{end:08X}{extra}")
        lines.append("")
    return "\n".join(lines)


def data_units(image, order, ranges):
    """The units of data only that config/VERSION/config.json's "data_units" lists ({"unit": source, "before": unit,
    "ranges": [[section, start, end], ...]}): their ranges cut out of the units that the references gave them to (a unit
    with no code is not one the functions can order: MSL's locale.c and float.c, whose objects only other units'
    code uses), and the unit put before BEFORE. A unit the functions have already (no "before") gets the ranges too:
    data that no code refers to, such as the strings of a function the link dropped (MSL's misc_io.c)."""
    for entry in image.config.get("data_units", []):
        unit = entry["unit"]
        if unit not in order:
            order.insert(order.index(entry["before"]), unit)
            ranges[unit] = []
        for section, start, end in entry["ranges"]:
            start, end = int(start, 16), int(end, 16)
            for other in order:
                for k, (name, low, high, options) in enumerate(ranges.get(other, [])):
                    if name == section and low <= start and end <= high and other != unit:
                        ranges[other][k:k + 1] = [(name, a, b, options) for a, b in ((low, start), (end, high)) if a < b]
                        break
                else:
                    continue
                break
            else:
                raise SystemExit(f"data_units: no unit has {section} {start:#x}-{end:#x}")
            ranges[unit].append((section, start, end, {}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("--reference", default="GC_1_2_5")
    parser.add_argument("--exe")
    parser.add_argument("--out")
    args = parser.parse_args()
    image, order, ranges, owners, refs, everywhere, ref_units, ref_sections = derive(
        args.version, args.reference, args.exe, args.out)
    # (the functions' and references' unit indices are into the order before the data units go in)
    code_order = list(order)
    data_units(image, order, ranges)
    out = Path(args.out or f"config/{folder(args.version)}")
    out.mkdir(parents=True, exist_ok=True)
    (out / "splits.txt").write_text(format_splits(ref_sections, order, ranges))
    ref_symbols = read_symbols(f"config/{folder(args.reference)}/symbols.txt")
    lines = make_symbols(image, code_order, ranges, owners, refs, ref_symbols)
    (out / "symbols.txt").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
