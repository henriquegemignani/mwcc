"""Big-endian ELF32 relocatable and executable files, and `!<arch>` archives, read into plain structures."""
import struct
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Section:
    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    align: int
    entsize: int
    data: bytes = b""


@dataclass
class Symbol:
    index: int
    name: str
    value: int
    size: int
    bind: int
    type: int
    other: int
    shndx: int


@dataclass
class Reloc:
    offset: int
    sym: int
    type: int
    addend: int


@dataclass
class Segment:
    type: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int
    align: int


@dataclass
class ElfFile:
    path: str
    raw: bytes
    header: tuple
    sections: list = field(default_factory=list)
    symbols: list = field(default_factory=list)
    segments: list = field(default_factory=list)

    @property
    def type(self):
        return self.header[1]

    @property
    def entry(self):
        return self.header[4]

    def section(self, name):
        return next((s for s in self.sections if s.name == name), None)

    def relocs(self, section):
        """The relocations (SHT_RELA) that apply to `section`, in file order."""
        for rela in self.sections:
            if rela.type == 4 and rela.info == section.index:
                for off in range(0, rela.size, 12):
                    r_offset, r_info, addend = struct.unpack_from(">IIi", rela.data, off)
                    yield Reloc(r_offset, r_info >> 8, r_info & 0xFF, addend)


def cstr(table, offset):
    end = table.index(b"\0", offset)
    return table[offset:end].decode("latin-1")


def parse(raw, path=""):
    if raw[:4] != b"\x7fELF" or raw[4] != 1 or raw[5] != 2:
        raise ValueError(f"{path}: not a big-endian ELF32 file")
    header = struct.unpack_from(">16sHHIIIIIHHHHHH", raw, 0)
    _, e_type, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = header
    elf = ElfFile(path, raw, header)
    for i in range(shnum):
        fields = struct.unpack_from(">IIIIIIIIII", raw, shoff + i * shentsize)
        name, typ, flg, addr, offset, size, link, info, align, entsize = fields
        data = b"" if typ == 8 else raw[offset:offset + size]
        elf.sections.append(Section(i, name, typ, flg, addr, offset, size, link, info, align, entsize, data))
    if shnum:
        names = elf.sections[shstrndx].data
        for section in elf.sections:
            section.name = cstr(names, section.name)
    for section in elf.sections:
        if section.type == 2:
            strings = elf.sections[section.link].data
            elf.symbols = []
            for i in range(section.size // 16):
                n, value, size, info, other, shndx = struct.unpack_from(">IIIBBH", section.data, i * 16)
                elf.symbols.append(Symbol(i, cstr(strings, n), value, size, info >> 4, info & 15, other, shndx))
    for i in range(phnum):
        elf.segments.append(Segment(*struct.unpack_from(">IIIIIIII", raw, phoff + i * phentsize)))
    return elf


def read(path):
    return parse(Path(path).read_bytes(), str(path))


@dataclass
class Member:
    name: str
    data: bytes


def archive_members(raw):
    """The members of a `!<arch>` archive (GNU/BSD long names are not used by CodeWarrior's libraries)."""
    if raw[:8] != b"!<arch>\n":
        raise ValueError("not an archive")
    members, pos, longnames = [], 8, b""
    while pos + 60 <= len(raw):
        name, _, _, _, _, size = struct.unpack_from("16s12s6s6s8s10s", raw, pos)
        size = int(size.strip())
        data = raw[pos + 60:pos + 60 + size]
        name = name.decode("latin-1").rstrip()
        if name == "//":
            longnames = data
        elif name.startswith("/") and name[1:].isdigit():
            name = cstr(longnames, int(name[1:])).rstrip("/")
            members.append(Member(name, data))
        elif name not in ("/", "/SYM64/"):
            members.append(Member(name.rstrip("/"), data))
        pos += 60 + size + (size & 1)
    return members
