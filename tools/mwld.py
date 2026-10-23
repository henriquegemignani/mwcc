#!/usr/bin/env python3
"""python tools/mwld.py [-nostdlib] -m ENTRY [-map FILE] -o OUTPUT INPUT...: a replica of the GC 2.7 linker (mwldeppc.exe,
Metrowerks Linker 3.0.4) for a link with no linker command file. What it knows was found by linking small programs with
the real linker (docs/linker/README.md); it stops with an error on what it does not know: a linker command file,
overlays, partial links, `-sym`, DWARF merging.

* An input section is cut into atoms, one per sized symbol (the symbol's alignment is in the object's `.comment`); a
  section with a symbol the compiler marked active (`...data.0`) is one atom.
* Atoms nothing refers to are dropped. The roots are the entry point, the `.ctors` and `.dtors` atoms and the
  C++ runtime's `*_reference` symbols.
* The output sections go from 0x10000 in the default order, relocations are applied, and the ELF and the link map are
  written."""
from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import elf

BASE = 0x10000
ORDER = [".compress.init", ".init", ".compress.text", ".text", ".compress.fini", ".fini", ".rodata", ".ctors", ".dtors",
         "extab", "extabindex", ".BINARY", ".data", ".got", ".sdata", ".sbss", ".sdata2", ".sbss2", ".PPC.EMB.sdata0",
         ".PPC.EMB.sbss0", ".bss"]
NOBITS = {".sbss", ".sbss2", ".PPC.EMB.sbss0", ".bss"}
SDA0 = 0xFFFF8000
GENERATED = "Linker Generated Symbol File "
ACTIVE = 0x10
RUNTIME_ROOTS = ("__init_cpp_exceptions_reference", "__fini_cpp_exceptions_reference", "__destroy_global_chain_reference")
LINKER_SYMBOLS = {"_SDA_BASE_", "_SDA2_BASE_", "_ABS_SDA_BASE_", "_ABS_SDA2_BASE_", "_stack_addr", "_stack_end",
                  "_heap_addr", "_heap_end", "_nbfunctions", "SIZEOF_HEADERS", "_eti_init_info", "_ctors", "_ctors$99",
                  "_dtors", "_dtors$99"}


def align(value, to):
    return (value + to - 1) & -to if to > 1 else value


def output_name(name):
    for prefix in (".ctors", ".dtors"):
        if name == prefix or name.startswith(prefix + "$"):
            return prefix
    return name if name in ORDER else None


def fail(*lines):
    sys.exit("\n".join(lines))


@dataclass(eq=False)
class Atom:
    obj: "Obj"
    section: elf.Section
    start: int
    size: int
    align: int
    symbols: list
    forced: bool = False
    live: bool = False
    out_offset: int = 0
    addr: int = 0

    def contains(self, offset):
        return self.start <= offset < self.start + self.size or (self.size == 0 and offset == self.start)

    def where(self, offset):
        return self.addr + offset - self.start


@dataclass(eq=False)
class Obj:
    name: str
    elf: elf.ElfFile
    aligns: list
    flags: list
    archive: str = ""
    atoms: dict = field(default_factory=dict)       # section index -> [Atom]
    lost: set = field(default_factory=set)          # weak definitions another object overrides
    new_index: dict = field(default_factory=dict)   # old symbol index -> output symbol index

    @property
    def label(self):
        """How the map names the object: the member of an archive as 'archive member', else the file."""
        return f"{self.archive} {self.name}" if self.archive else f"{self.name} "

    @property
    def has_cats(self):
        return self.elf.section(".mwcats.text") is not None


def load_object(name, data, archive=""):
    e = elf.parse(data, name)
    comment = e.section(".comment")
    aligns, flags = [0] * len(e.symbols), [0] * len(e.symbols)
    for i in range(len(e.symbols) if comment else 0):
        if 52 + 8 * i <= len(comment.data):
            aligns[i], _, flags[i], _ = struct.unpack_from(">IBBH", comment.data, 44 + 8 * i)
    if comment and comment.data[11] != 0x0B:
        fail(f"{name}: comment section version {comment.data[11]} (the linker treats objects of other versions "
             "differently, as 1.3.2's: not replicated)")
    obj = Obj(name, e, aligns, flags, archive)
    for section in e.sections:
        if not section.flags & 2 or section.type not in (1, 8):
            continue
        if output_name(section.name) is None:
            fail(f"unsupported input section '{section.name}' in {name}")
        here = [s for s in e.symbols if s.shndx == section.index and s.type != 3]
        sized = [s for s in here if s.type in (1, 2) and s.size > 0]
        if not sized or any(flags[s.index] & ACTIVE for s in here):
            atoms = [Atom(obj, section, 0, section.size, section.align, here, True)]
        else:
            atoms = []
            for symbol in sorted(sized, key=lambda s: (s.value, s.index)):
                if atoms and (atoms[-1].start, atoms[-1].size) == (symbol.value, symbol.size):
                    atoms[-1].symbols.append(symbol)
                else:
                    atoms.append(Atom(obj, section, symbol.value, symbol.size, max(aligns[symbol.index], 1), [symbol]))
            for symbol in here:
                if symbol.size == 0:
                    owner = next((a for a in atoms if a.contains(symbol.value)), None)
                    if owner:
                        owner.symbols.append(symbol)
        obj.atoms[section.index] = atoms
    return obj


class Link:
    def __init__(self, entry, inputs):
        self.entry = entry
        self.objs, self.defs, archives = [], {}, []
        for path in inputs:
            data = Path(path).read_bytes()
            if data[:8] == b"!<arch>\n":
                archives.append([(Path(path).name, m) for m in elf.archive_members(data)])
            else:
                self.objs.append(load_object(Path(path).name, data))
        while True:
            self.resolve()
            wanted = {s.name for o in self.objs for s in o.elf.symbols if s.shndx == 0 and s.bind >= 1 and s.name}
            wanted |= {entry, *RUNTIME_ROOTS}
            wanted -= set(self.defs)
            found = next(((members, item) for members in archives for item in members
                          if any(s.bind >= 1 and 0 < s.shndx < 0xFF00 and s.name in wanted
                                 for s in elf.parse(item[1].data, item[1].name).symbols)), None)
            if not found:
                break
            found[0].remove(found[1])
            self.objs.append(load_object(found[1][1].name, found[1][1].data, found[1][0]))
        self.strip()

    def resolve(self):
        self.defs = {}
        for obj in self.objs:
            for s in obj.elf.symbols:
                if s.bind >= 1 and 0 < s.shndx < 0xFF00 and s.name:
                    old = self.defs.get(s.name)
                    if not old or (old[1].bind == 2 and s.bind == 1):
                        self.defs[s.name] = (obj, s)
        for obj in self.objs:
            obj.lost = {s.index for s in obj.elf.symbols
                        if s.bind >= 1 and 0 < s.shndx < 0xFF00 and self.defs[s.name][1] is not s}

    def lookup(self, obj, symbol):
        """The (object, symbol) a symbol of `obj` stands for, or None for a linker symbol."""
        if symbol.shndx == 0 or (symbol.bind >= 1 and symbol.index in obj.lost):
            return self.defs.get(symbol.name)
        return obj, symbol

    def target(self, obj, symbol, addend):
        """The (atom, offset in its section) a relocation against symbol + addend reaches."""
        found = self.lookup(obj, symbol)
        if not found or found[1].shndx >= 0xFF00:
            return None
        obj, symbol = found
        offset = symbol.value + addend if symbol.type == 3 else symbol.value
        return next(((a, offset) for a in obj.atoms.get(symbol.shndx, ()) if a.contains(offset)), None)

    def relocs(self, atom):
        e = atom.obj.elf
        for rela in e.sections:
            if rela.type == 4 and rela.info == atom.section.index:
                for off in range(0, rela.size, 12):
                    r_offset, r_info, addend = struct.unpack_from(">IIi", rela.data, off)
                    if atom.contains(r_offset):
                        yield r_offset, e.symbols[r_info >> 8], r_info & 0xFF, addend

    def strip(self):
        if self.entry not in self.defs:
            fail("### mwldeppc.exe Linker Error:", f"#   undefined: '{self.entry}'", "#   Referenced from <entry point>")
        work = []

        def mark(atom):
            if not atom.live:
                atom.live = True
                work.append(atom)

        for obj in self.objs:
            for atoms in obj.atoms.values():
                for atom in atoms:
                    if atom.forced or (output_name(atom.section.name) in (".ctors", ".dtors")
                                       and not any(s.index in obj.lost for s in atom.symbols)):
                        mark(atom)
        for name in (self.entry, *RUNTIME_ROOTS):
            if name in self.defs:
                mark(self.target(*self.defs[name], 0)[0])
        index = lambda o: next((i for i, s in enumerate(o.elf.sections) if s.name == "extabindex"), -1)
        while True:
            while work:
                atom = work.pop()
                for _, symbol, _, addend in self.relocs(atom):
                    found = self.target(atom.obj, symbol, addend)
                    if found:
                        mark(found[0])
                    elif symbol.shndx == 0 and symbol.name not in self.defs and symbol.bind != 2 \
                            and symbol.name not in LINKER_SYMBOLS and not symbol.name.startswith(("_f_", "_e_")):
                        fail("### mwldeppc.exe Linker Error:", f"#   undefined: '{symbol.name}'",
                             f"#   Referenced from '{atom.symbols[0].name}' in {atom.obj.name}")
            # an extabindex entry lives when the function it describes does
            for obj in self.objs:
                for atom in obj.atoms.get(index(obj), ()):
                    first = next(self.relocs(atom), None)
                    found = first and self.target(obj, first[1], first[3])
                    if found and found[0].live:
                        mark(atom)
            if not work:
                break


@dataclass
class Piece:
    """What an output section holds from one input section (or the linker's own)."""
    name: str
    obj: Obj | None
    section: elf.Section | None
    atoms: list
    start: int = 0
    size: int = 0                # as the map shows it
    addr: int = 0
    gen: list = field(default_factory=list)      # (symbol name, offset, size, type) of a linker-generated piece


class Layout:
    def __init__(self, link):
        self.link = link
        self.pieces = {n: [] for n in ORDER}
        self.addr, self.size, self.align, self.fills = {}, {}, {}, {n: [] for n in ORDER}
        live = lambda o, i: [a for a in o.atoms[i] if a.live]
        for name in ORDER:
            found = [Piece(a[0].section.name, o, a[0].section, a) for o in link.objs for i in o.atoms
                     for a in [live(o, i)] if a and output_name(o.elf.sections[i].name) == name]
            if name in (".ctors", ".dtors"):
                found.sort(key=lambda p: (p.name == name, p.name))     # (an unsuffixed one follows the suffixed)
                found = [Piece(f"{name}$00", None, None, [], gen=[(name[1:].join(("_", "")), 0, 0, 0)])] + found \
                    + [Piece(f"{name}$99", None, None, [], gen=[(f"{name[1:].join(('_', ''))}$99", 0, 4, 1)])]
            self.pieces[name] = found
        # the exception table index info
        self.pieces["extabindex"].append(Piece("extabindex", None, None, [], gen=[("_eti_init_info", 0, 32, 1)]))
        self.nonempty = [n for n in ORDER if any(p.atoms or p.gen for p in self.pieces[n])]
        self.hdr = align(52 + 32 * len(self.nonempty), 16)
        cur = BASE
        for name in ORDER:
            pieces = self.pieces[name]
            if name not in self.nonempty:
                self.addr[name] = SDA0 if name.startswith(".PPC.EMB") else cur
                self.size[name], self.align[name] = 0, 1
                continue
            self.align[name] = max([p.section.align for p in pieces if p.section] + [4 if name in (".ctors", ".dtors", "extabindex") else 1])
            cur = align(cur, self.align[name])
            self.addr[name] = cur
            offset = 0
            for piece in pieces:
                if piece.section:
                    start = align(offset, piece.section.align)
                    if start > offset:
                        self.fills[name].append((offset, start - offset, piece.section.align))
                    offset = start
                piece.start = offset
                piece.addr = cur + offset
                for atom in piece.atoms:
                    offset = align(offset, atom.align)
                    atom.out_offset, atom.addr = offset, cur + offset
                    offset += atom.size
                for _, at, size, _ in piece.gen:
                    offset += size
                piece.size = piece.section.size if piece.section else sum(g[2] for g in piece.gen)
            offset = align(offset, 4)
            self.size[name] = offset
            cur += offset
        # file offsets as the map shows them: a section without contents (or in the bss) starts where the last ended
        self.map_off, pos = {}, self.hdr
        for name in ORDER:
            if name not in self.nonempty:
                self.map_off[name] = pos
            else:
                self.map_off[name] = pos = align(pos, self.align[name])
                if name not in NOBITS:
                    pos += self.size[name]
        self.sda = self.addr[".sdata"] + 0x8000
        self.sda2 = self.addr[".sdata2"] + 0x8000
        self.symbols = self.generated_symbols()

    def gen_addr(self, symbol):
        for name in ORDER:
            for piece in self.pieces[name]:
                for gname, off, size, _ in piece.gen:
                    if gname == symbol:
                        return piece.addr + off
        return None

    def generated_symbols(self):
        syms = {}
        for name in ORDER:
            tag = name.strip(".").replace(".", "_")
            tag = tag if name.startswith(".") else name
            sep = "_" if name.startswith(".") else ""
            f, e = self.addr[name], self.addr[name] + self.size[name]
            syms[f"_f{sep}{tag}"] = f
            if name not in NOBITS:
                # (a ROM address is aligned for the input sections there were, even when all of them were stripped)
                inputs = [sec.align for o in self.link.objs for sec in o.elf.sections
                          if sec.flags & 2 and output_name(sec.name) == name]
                syms[f"_f{sep}{tag}_rom"] = align(f, max(inputs, default=1))
            syms[f"_e{sep}{tag}"] = e
        syms.update({"_stack_addr": 0x3DFFF0, "_stack_end": 0x3CFFF0, "_heap_addr": 0x2CFFF0, "_heap_end": 0x3CFFF0,
                     "_nbfunctions": sum(1 for o in self.link.objs for al in o.atoms.values() for a in al
                                         if a.live and any(s.type == 2 for s in a.symbols)),
                     "SIZEOF_HEADERS": self.hdr, "_SDA_BASE_": self.sda, "_SDA2_BASE_": self.sda2,
                     "_ABS_SDA_BASE_": self.sda, "_ABS_SDA2_BASE_": self.sda2})
        return syms


class Writer:
    def __init__(self, link, layout):
        self.link, self.lay = link, layout
        self.build_symtab()
        self.build_sections()
        self.apply_relocs()
        self.build_extras()
        self.write_file()

    # -- symbols
    def build_symtab(self):
        lay, link = self.lay, self.link
        sec_index = {n: i + 1 for i, n in enumerate(lay.nonempty)}
        self.sec_index = sec_index
        entries = [("", 0, 0, 0, 0, 0)]       # (name, value, size, info, other, shndx)
        total_secs = len(lay.nonempty)
        cats = [o for o in link.objs if o.has_cats and self.cats_entries(o)]
        self.cats_objs = cats
        retained = self.retained_relocs()
        rela_sections = [n for n in lay.nonempty if retained[n]]
        self.rela_sections = rela_sections
        self.retained = retained
        self.cats_shndx = total_secs + len(rela_sections) + 1
        self.symtab_shndx = self.cats_shndx + 1
        for obj in link.objs:
            e = obj.elf
            live_secs = {i for i, atoms in obj.atoms.items() if any(a.live for a in atoms)}
            if not live_secs and obj not in cats:
                continue
            file_sym = next((s for s in e.symbols if s.type == 4), None)
            if file_sym:
                obj.new_index[file_sym.index] = len(entries)
                entries.append((file_sym.name, 0, 0, 4, 0, 0xFFF1))
            for section in e.sections:
                if section.index in live_secs:
                    out = output_name(section.name)
                    piece = next(p for p in lay.pieces[out] if p.section is section)
                    value = 0 if out == "extabindex" else piece.addr
                    sym = next((s for s in e.symbols if s.type == 3 and s.shndx == section.index), None)
                    if sym:
                        obj.new_index[sym.index] = len(entries)
                    entries.append(("", value, 0, 3, 0, sec_index[out]))
                elif section.name == ".mwcats.text" and obj in cats:
                    sym = next((s for s in e.symbols if s.type == 3 and s.shndx == section.index), None)
                    if sym:
                        obj.new_index[sym.index] = len(entries)
                    entries.append(("", 0, 0, 3, 0, self.cats_shndx))
            for s in e.symbols:
                if s.bind == 0 and s.type not in (3, 4) and s.shndx in live_secs:
                    atom = next((a for a in obj.atoms[s.shndx] if a.contains(s.value)), None)
                    if atom and atom.live:
                        obj.new_index[s.index] = len(entries)
                        entries.append((s.name, atom.where(s.value), s.size, s.type | 0, 0, sec_index[output_name(
                            e.sections[s.shndx].name)]))
        # section symbols of the linker's own pieces
        for name in (".ctors", ".dtors"):
            for tag in ("$00", "$99"):
                piece = next((p for p in lay.pieces[name] if p.name == name + tag), None)
                if piece:
                    entries.append(("", piece.addr, 0, 3, 0, sec_index[name]))
        self.first_global = len(entries)
        for obj in link.objs:
            e = obj.elf
            for s in e.symbols:
                if s.bind >= 1 and 0 < s.shndx < 0xFF00 and s.index not in obj.lost:
                    atom = next((a for a in obj.atoms.get(s.shndx, ()) if a.contains(s.value)), None)
                    if atom and atom.live:
                        obj.new_index[s.index] = len(entries)
                        entries.append((s.name, atom.where(s.value), s.size, (s.bind << 4) | s.type, 0,
                                        sec_index[output_name(e.sections[s.shndx].name)]))
        self.gen_index = {}
        for name in (".ctors", ".dtors"):
            for sym, off, size, kind in [g for p in lay.pieces[name] for g in p.gen]:
                self.gen_index[sym] = len(entries)
                entries.append((sym, lay.gen_addr(sym), size, (1 << 4) | kind, 0, sec_index[name]))
        sym = "_eti_init_info"
        self.gen_index[sym] = len(entries)
        entries.append((sym, lay.gen_addr(sym), 32, (1 << 4) | 1, 0, sec_index["extabindex"]))
        self.entries = entries
        entry_obj, entry_sym = link.defs[link.entry]
        atom = next(a for a in entry_obj.atoms[entry_sym.shndx] if a.contains(entry_sym.value))
        self.entry_addr = atom.where(entry_sym.value)

    def cats_entries(self, obj):
        """The live (size word, atom, offset) entries of an object's .mwcats.text."""
        section = obj.elf.section(".mwcats.text")
        rela = next((s for s in obj.elf.sections if s.type == 4 and s.info == section.index), None)
        out = []
        for i in range(section.size // 8):
            word = section.data[8 * i:8 * i + 4]
            target = None
            if rela:
                for off in range(0, rela.size, 12):
                    r_offset, r_info, addend = struct.unpack_from(">IIi", rela.data, off)
                    if r_offset == 8 * i + 4:
                        target = self.link.target(obj, obj.elf.symbols[r_info >> 8], addend)
            if target and target[0].live:
                out.append((word, target[0], target[1]))
        return out

    # -- section contents
    def build_sections(self):
        lay = self.lay
        self.data = {}
        for name in lay.nonempty:
            buf = bytearray(lay.size[name])
            for piece in lay.pieces[name]:
                for atom in piece.atoms:
                    if atom.section.type == 1:
                        buf[atom.out_offset:atom.out_offset + atom.size] = \
                            atom.section.data[atom.start:atom.start + atom.size]
            self.data[name] = buf

    def symbol_addr(self, obj, symbol, addend):
        found = self.link.target(obj, symbol, addend)
        if found:
            atom, offset = found
            return atom.where(offset), output_name(atom.section.name)
        name = symbol.name
        if name in self.lay.symbols:
            return self.lay.symbols[name], None
        if self.lay.gen_addr(name) is not None:
            return self.lay.gen_addr(name), None
        if symbol.bind == 2:
            return 0, None
        fail(f"undefined: '{name}'")

    def apply_relocs(self):
        lay = self.lay
        for name in lay.nonempty:
            for piece in lay.pieces[name]:
                for atom in piece.atoms:
                    for r_offset, symbol, kind, addend in self.link.relocs(atom):
                        S, tsec = self.symbol_addr(atom.obj, symbol, addend)
                        found = self.link.lookup(atom.obj, symbol)
                        if symbol.type != 3 and found:
                            S = self.symbol_addr(atom.obj, symbol, 0)[0]
                        if symbol.type == 3:
                            pass
                        value = S + (addend if symbol.type != 3 else 0)
                        pos = atom.out_offset + r_offset - atom.start
                        buf = self.data[name]
                        P = atom.addr + r_offset - atom.start
                        word = struct.unpack_from(">I", buf, pos)[0] if pos + 4 <= len(buf) else 0
                        if kind == 1:
                            struct.pack_into(">I", buf, pos, value & 0xFFFFFFFF)
                        elif kind == 3:
                            struct.pack_into(">H", buf, pos, value & 0xFFFF)
                        elif kind == 4:
                            struct.pack_into(">H", buf, pos, value & 0xFFFF)
                        elif kind == 5:
                            struct.pack_into(">H", buf, pos, (value >> 16) & 0xFFFF)
                        elif kind == 6:
                            struct.pack_into(">H", buf, pos, ((value + 0x8000) >> 16) & 0xFFFF)
                        elif kind == 10:
                            struct.pack_into(">I", buf, pos, (word & 0xFC000003) | ((value - P) & 0x03FFFFFC))
                        elif kind == 11:
                            struct.pack_into(">I", buf, pos, (word & 0xFFFF0003) | ((value - P) & 0xFFFC))
                        elif kind == 109:
                            if tsec in (".sdata", ".sbss"):
                                reg, base = 13, lay.sda
                            elif tsec in (".sdata2", ".sbss2"):
                                reg, base = 2, lay.sda2
                            elif tsec in (".PPC.EMB.sdata0", ".PPC.EMB.sbss0"):
                                reg, base = 0, 0
                            else:
                                fail(f"R_PPC_EMB_SDA21 to '{symbol.name}' outside the small data sections")
                            struct.pack_into(">I", buf, pos, (word & 0xFFE00000) | (reg << 16) | ((value - base) & 0xFFFF))
                        else:
                            fail(f"unsupported relocation type {kind}")

    def retained_relocs(self):
        """The relocations kept in the output, by output section: those of the objects with a `.mwcats.text`."""
        out = {n: [] for n in ORDER}
        for name in self.lay.nonempty:
            for piece in self.lay.pieces[name]:
                if piece.obj is not None and piece.obj.has_cats:
                    for atom in piece.atoms:
                        for r_offset, symbol, kind, addend in self.link.relocs(atom):
                            out[name].append((atom, r_offset, symbol, kind, addend))
        for entries in out.values():     # (the compiler may write them in any order; the linker's are by address)
            entries.sort(key=lambda r: r[0].where(r[1]))
        return out

    def build_extras(self):
        lay = self.lay
        # the exception table index info: extabindex start/end, the code range it covers
        ex = lay.pieces["extabindex"]
        start = lay.addr["extabindex"]
        n_entries = sum(a.size for p in ex for a in p.atoms) // 12
        end = start + n_entries * 12
        lo, hi = None, 0
        buf = self.data["extabindex"]
        for i in range(n_entries):
            func, size = struct.unpack_from(">II", buf, 12 * i)
            lo = func if lo is None else min(lo, func)
            hi = max(hi, func + size)
        info = struct.pack(">IIII", start, end, lo or 0, (hi - lo) if lo is not None else 0) + bytes(16)
        buf[n_entries * 12:n_entries * 12 + 32] = info
        # .ctors/.dtors have the zero words of $99 already
        # .mwcats.text
        cats = bytearray()
        for obj in self.cats_objs:
            for word, atom, offset in self.cats_entries(obj):
                cats += word + struct.pack(">I", atom.where(offset))
        self.cats = bytes(cats)

    def write_file(self):
        lay = self.lay
        strtab, symtab = bytearray(b"\0"), bytearray()
        for name, value, size, info, other, shndx in self.entries:
            offset = 0
            if name:
                offset = len(strtab)
                strtab += name.encode("latin-1") + b"\0"
            symtab += struct.pack(">IIIBBH", offset, value, size, info, other, shndx)
        # section header table, in order
        headers = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "")]
        names = []
        pos = lay.hdr
        offsets = {}
        for name in lay.nonempty:
            offsets[name] = lay.map_off[name]
            pos = offsets[name] + (0 if name in NOBITS else lay.size[name])
        out_secs = []
        for name in lay.nonempty:
            ins = [p.section for p in lay.pieces[name] if p.section]
            flags = 0
            for s in ins:
                flags |= s.flags
            flags = flags or 2
            kind = 8 if name in NOBITS else 1
            out_secs.append((name, kind, flags, lay.addr[name], offsets[name], lay.size[name], 0, 0, lay.align[name],
                             1 if name in (".ctors", ".dtors") else 0))
        shstr = bytearray(b"\0")

        def name_off(n):
            off = len(shstr)
            shstr.extend(n.encode() + b"\0")
            return off

        rela_names = [".rela" + n for n in self.rela_sections]      # (".rela.text", ".relaextabindex")
        # layout of the non-allocated sections after the loadable ones
        shstr_pos = pos
        # build names first to know sizes
        all_names = [s[0] for s in out_secs] + rela_names + [".mwcats.text", ".symtab", ".shstrtab", ".strtab"]
        shoffs = {n: name_off(n) for n in all_names}
        strtab_pos = shstr_pos + len(shstr)
        symtab_pos = align(strtab_pos + len(strtab), 4)
        pos = symtab_pos + len(symtab)
        rela_data, rela_pos = [], {}
        for n, rn in zip(self.rela_sections, rela_names):
            pos = align(pos, 4)
            data = bytearray()
            for atom, r_offset, symbol, kind, addend in self.retained[n]:
                found = self.link.lookup(atom.obj, symbol)
                idx = atom.obj.new_index.get(symbol.index) if found and found[1] is symbol else \
                    (found[0].new_index.get(found[1].index) if found else None)
                if idx is None:
                    fail(f"no output symbol for '{symbol.name}'")
                data += struct.pack(">IIi", atom.addr + r_offset - atom.start, (idx << 8) | kind, addend)
            rela_data.append(bytes(data))
            rela_pos[rn] = pos
            pos += len(data)
        pos = align(pos, 4)
        cats_pos = pos
        pos += len(self.cats)
        shoff = align(pos, 16)
        n_sections = len(out_secs) + len(rela_names) + 4
        image = bytearray(shoff + 40 * (n_sections + 1))
        # sections
        for (name, kind, flags, addr, off, size, link, info, al, ent) in out_secs:
            if kind == 1:
                image[off:off + size] = self.data[name]
        image[shstr_pos:shstr_pos + len(shstr)] = shstr
        image[strtab_pos:strtab_pos + len(strtab)] = strtab
        image[symtab_pos:symtab_pos + len(symtab)] = symtab
        for rn, data in zip(rela_names, rela_data):
            image[rela_pos[rn]:rela_pos[rn] + len(data)] = data
        image[cats_pos:cats_pos + len(self.cats)] = self.cats
        # headers
        sh = [bytes(40)]
        for (name, kind, flags, addr, off, size, link, info, al, ent) in out_secs:
            sh.append(struct.pack(">IIIIIIIIII", shoffs[name], kind, flags, addr, off, size, 0, 0, al, ent))
        for n, rn, data in zip(self.rela_sections, rela_names, rela_data):
            sh.append(struct.pack(">IIIIIIIIII", shoffs[rn], 4, 0, 0, rela_pos[rn], len(data), self.symtab_shndx,
                                  self.sec_index[n], 4, 12))
        cats_type = next(o.elf.section(".mwcats.text").type for o in self.link.objs if o.has_cats) if self.cats_objs else 0
        sh.append(struct.pack(">IIIIIIIIII", shoffs[".mwcats.text"], cats_type, 0, 0, cats_pos, len(self.cats),
                              self.sec_index[".text"], 0, 4, 1))
        sh.append(struct.pack(">IIIIIIIIII", shoffs[".symtab"], 2, 0, 0, symtab_pos, len(symtab),
                              self.symtab_shndx + 2, self.first_global, 4, 16))
        sh.append(struct.pack(">IIIIIIIIII", shoffs[".shstrtab"], 3, 0, 0, shstr_pos, len(shstr), 0, 0, 1, 1))
        sh.append(struct.pack(">IIIIIIIIII", shoffs[".strtab"], 3, 0, 0, strtab_pos, len(strtab), 0, 0, 1, 1))
        for i, h in enumerate(sh):
            image[shoff + 40 * i:shoff + 40 * i + 40] = h
        # program headers
        phdrs = bytearray()
        for (name, kind, flags, addr, off, size, link, info, al, ent) in out_secs:
            perm = 4 | (2 if flags & 1 else 0) | (1 if flags & 4 else 0)
            phdrs += struct.pack(">IIIIIIII", 1, off, addr, 0, 0 if kind == 8 else size, size, perm, al)
        header = b"\x7fELF\x01\x02\x01" + bytes(9) + struct.pack(">HHIIIIIHHHHHH", 2, 20, 1, self.entry_addr, 52, shoff,
                                                                  0x80000000, 52, 32, len(out_secs), 40,
                                                                  len(sh), n_sections - 1)
        image[:52] = header
        image[52:52 + len(phdrs)] = phdrs
        self.image = bytes(image)


def write_map(link, lay, writer):
    out = [f"Link map of {link.entry}\n"]
    row = "  %08x %06x %08x %08x %2i %s \t%s\n"

    def sections(name, with_section_line=True):
        out.append("\n")
        out.append(f"\n{name} section layout\n  Starting        Virtual  File\n  address  Size   address  offset\n"
                   "  ---------------------------------\n")

    for name in ORDER:
        if name == ".got":
            continue
        sections(name)
        if name == "extabindex":
            continue
        for piece in lay.pieces[name]:
            if not (piece.atoms or piece.gen):
                continue
            fill = next((f for f in lay.fills[name] if f[0] + f[1] == piece.start and piece.section), None)
            if fill:
                out.append("  %08x %06x %08x %08x %2i *fill*\n" % (fill[0], fill[1], lay.addr[name] + piece.start,
                                                                  lay.map_off[name] + piece.start, fill[2]))
            owner = piece.obj.label if piece.obj else GENERATED
            out.append(row % (piece.start, piece.size, piece.addr, lay.map_off[name] + piece.start, 1, piece.name, owner))
            for sym, off, size, kind in piece.gen:
                out.append(row % (piece.start + off, size, piece.addr + off, lay.map_off[name] + piece.start + off, 4,
                                  sym, owner))
            out.extend(symbol_rows(lay, name, piece))
    # the exception table index, after the others
    sections("extabindex")
    end_off = lay.map_off["extabindex"] + lay.size["extabindex"]
    for piece in lay.pieces["extabindex"]:
        owner = piece.obj.label if piece.obj else GENERATED
        for line in symbol_rows(lay, "extabindex", piece, end_off):
            out.append(line)
        for sym, off, size, kind in piece.gen:
            out.append(row % (piece.start + off, size, piece.addr + off, end_off, 4, sym, owner))
    out.append("\n\nMemory map:\n                   Starting Size     File\n                   address           Offset\n")
    for name in ORDER:
        out.append("  %15s  %08x %08x %08x\n" % (name, lay.addr[name], lay.size[name], lay.map_off[name]))
    out.append("\n\nLinker generated symbols:\n")
    for sym, value in lay.symbols.items():
        out.append("%25s %08x\n" % (sym, value))
    return "".join(out)


def symbol_rows(lay, name, piece, file_off=None):
    rows = []
    items = []
    for atom in piece.atoms:
        for s in atom.symbols:
            items.append((atom.out_offset + s.value - atom.start, s.index, s, atom))
    for off, _, s, atom in sorted(items, key=lambda i: (i[0], i[1])):
        fo = file_off if file_off is not None else lay.map_off[name] + off
        if s.size == 0:
            rows.append("  %08x %06x %08x %08x    %s (entry of %s) \t%s\n" % (off, 0, lay.addr[name] + off, fo, s.name,
                                                                            piece.name, piece.obj.label))
        else:
            rows.append("  %08x %06x %08x %08x %2i %s \t%s\n" % (off, s.size, lay.addr[name] + off, fo,
                                                                 max(piece.obj.aligns[s.index], 1), s.name,
                                                                 piece.obj.label))
    return rows


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    entry, mapfile, output, inputs = "__start", None, "a.out", []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-m", "-main"):
            entry, i = args[i + 1], i + 1
        elif a == "-map":
            mapfile, i = args[i + 1], i + 1
        elif a == "-o":
            output, i = args[i + 1], i + 1
        elif a == "-nostdlib":
            pass
        elif a.startswith("-"):
            fail(f"unsupported option '{a}'")
        else:
            inputs.append(a)
        i += 1
    link = Link(entry, inputs)
    lay = Layout(link)
    writer = Writer(link, lay)
    Path(output).write_bytes(writer.image)
    if mapfile:
        Path(mapfile).write_bytes(write_map(link, lay, writer).encode("latin-1"))


if __name__ == "__main__":
    main()
