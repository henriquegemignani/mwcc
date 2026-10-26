#!/usr/bin/env python3
"""python tools/gen_options.py VERSION ROOT [--report] [-o OUT]: the command-line parser's tables of a parser glue unit,
read from the original's data as C: the ParserTool at ROOT (hexadecimal), its preference panels' names and data, its
option lists, their options and the options' parameters (include/driver/Option.h and Parameter.h's types).

The walk follows the pointers the base relocations mark, from the ParserTool down. --report lists the objects found
and the bytes between them it does not explain; otherwise OUT gets the C of the tables (the panels' data as bytes:
their types are the parser's, which the 2.x linker's do not all share), and the glue's code is written by hand around
it. Adapted from mweppc's tools/gen_options.py, which writes the 2.x compilers' tables."""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pe import PEFile
from split import base_relocations, read_symbols

WHICH = {
    0: ("None", []),
    1: ("FTypeCreator", [("fc", "p"), ("iscreator", "b")]),
    2: ("FilePath", [("fflags", "b"), ("defaultstr", "s"), ("filename", "p"), ("maxlen", "i")]),
    3: ("Number", [("size", "b"), ("fit", "b"), ("lo", "i"), ("hi", "i"), ("num", "p")]),
    4: ("String", [("maxlen", "h"), ("pstring", "b"), ("str", "p")]),
    5: ("Id", [("maxlen", "h"), ("pstring", "b"), ("str", "p")]),
    6: ("Sym", [("maxlen", "h"), ("pstring", "b"), ("str", "p")]),
    7: ("OnOff", [("var", "p")]),
    8: ("OffOn", [("var", "p")]),
    9: ("Mask", [("size", "b"), ("ormask", "i"), ("andmask", "i"), ("num", "p")]),
    10: ("Toggle", [("size", "b"), ("mask", "i"), ("num", "p")]),
    11: ("Set", [("size", "b"), ("value", "i"), ("num", "p")]),
    12: ("SetString", [("value", "s"), ("pstring", "b"), ("var", "p")]),
    13: ("Generic", [("parse", "f"), ("var", "p"), ("help", "s")]),
    14: ("IfArg", [("parg", "P"), ("helpa", "s"), ("pnone", "P"), ("helpn", "s")]),
    15: ("Setting", [("parse", "f"), ("valuename", "s")]),
}
SIZES = {"b": 1, "h": 2, "i": 4, "p": 4, "s": 4, "f": 4, "P": 4}
TYPES = {"None": "PARAM_T", "FTypeCreator": "FTYPE_T", "FilePath": "FILEPATH_T", "Number": "NUM_T",
         "String": "STRING_T", "Id": "STRING_T", "Sym": "STRING_T", "OnOff": "ONOFF_T", "OffOn": "OFFON_T",
         "Mask": "MASK_T", "Toggle": "TOGGLE_T", "Set": "SET_T", "SetString": "SETSTRING_T", "Generic": "GENERIC_T",
         "IfArg": "IFARG_T", "Setting": "SETTING_T"}


class Image:
    def __init__(self, version):
        config = json.loads(Path(f"config/{version}/config.json").read_text())
        self.pe = PEFile(Path(config["original"]))
        self.fixups = set(base_relocations(self.pe))
        self.names, self.sizes = {}, {}
        # (a configuration with no symbols of its own, such as a linker built from source alone, names nothing)
        listed = read_symbols(f"config/{version}/symbols.txt") if Path(f"config/{version}/symbols.txt").exists() else []
        for name, section, address, options in listed:
            self.names.setdefault(address, name)
            if "size" in options:
                self.sizes.setdefault(address, int(options["size"], 16))

    def read(self, a, size):
        # (an object in the uninitialized data, such as a parameter the 2.7 linker leaves zero, reads as zeros)
        try:
            return self.pe.read(a, size)
        except ValueError:
            self.pe.section_for_address(a)
            return bytes(size)

    def u8(self, a):
        return self.read(a, 1)[0]

    def u32(self, a):
        return struct.unpack("<I", self.read(a, 4))[0]

    def ptr(self, a):
        return self.u32(a) if a in self.fixups else None

    def cstr(self, a):
        data = self.pe.read(a, 4096)
        return data[: data.index(b"\0")]


class Walk:
    def __init__(self, image):
        self.image = image
        self.objects = {}

    def add(self, address, kind, size, fields):
        if address in self.objects:
            return False
        self.objects[address] = (kind, size, fields)
        return True

    def string(self, address):
        if address is not None and address not in self.objects:
            text = self.image.cstr(address)
            self.add(address, "string", len(text) + 1, text)

    def tool(self, address):
        im = self.image
        f = [im.u32(address + 4 * i) for i in range(15)]
        self.add(address, "ParserTool", 60, f)
        self.string(f[6])
        self.string(f[7])
        self.add(f[5], "prefs", 4 * f[4], [im.u32(f[5] + 4 * i) for i in range(f[4])])
        for i in range(f[4]):
            self.string(im.u32(f[5] + 4 * i))
        lists = [im.u32(f[9] + 4 * i) for i in range(f[8])]
        self.add(f[9], "optLists", 4 * f[8], lists)
        panels = [(im.u32(f[11] + 12 * i), im.u32(f[11] + 12 * i + 4), im.u32(f[11] + 12 * i + 8))
                  for i in range(f[10])]
        self.add(f[11], "prefPanels", 12 * f[10], panels)
        for name, data, size in panels:
            self.string(name)
            self.add(data, "panel", size, im.cstr(name))
        for a in lists:
            self.option_list(a)

    def option_list(self, address):
        if address is None or not self.add(address, "OptionList", 12, None):
            return
        im = self.image
        self.string(im.ptr(address))
        array = im.ptr(address + 8)
        if array is not None:
            entries, a = [], array
            while im.u32(a):
                entries.append(im.u32(a))
                a += 4
            self.add(array, "OptionArray", 4 * len(entries) + 4, entries)
            for e in entries:
                self.option(e)

    def option(self, address):
        if not self.add(address, "Option", 24, None):
            return
        im = self.image
        self.string(im.ptr(address))
        self.param(im.ptr(address + 8))
        self.option_list(im.ptr(address + 12))
        self.option_list(im.ptr(address + 16))
        self.string(im.ptr(address + 20))

    def param(self, address):
        while address is not None and address not in self.objects:
            im = self.image
            kind, layout = WHICH[im.u8(address)]
            self.add(address, "param", 10 + sum(SIZES[t] for _, t in layout), kind)
            self.string(im.ptr(address + 2))
            offset = 10
            for field, t in layout:
                if t == "s":
                    self.string(im.ptr(address + offset))
                elif t == "P":
                    self.param(im.ptr(address + offset))
                offset += SIZES[t]
            address = im.ptr(address + 6)


def report(walk, lo, hi):
    position = lo
    for address in sorted(walk.objects):
        kind, size, fields = walk.objects[address]
        if not lo <= address < hi:
            continue
        if address > position:
            print(f"  {position:08x} {address - position:5} unexplained")
        elif address < position:
            print(f"  {address:08x} overlaps the object before")
        label = fields.decode("latin1")[:60] if kind == "string" else (fields if kind in ("param", "panel") else "")
        print(f"{address:08x} {size:5} {kind:12} {label!r}")
        position = max(position, address + size)
    if position < hi:
        print(f"  {position:08x} {hi - position:5} unexplained")


SCALARS = {"Boolean": 1, "UInt8": 1, "SInt8": 1, "char": 1, "unsigned char": 1, "SInt16": 2, "UInt16": 2, "short": 2,
           "UInt32": 4, "SInt32": 4, "int": 4, "OSType": 4}


def preprocess(text, defines):
    """TEXT's lines that its #if, #ifdef, #ifndef, #elif, #else and #endif keep for DEFINES ({name: value}; a name not
    given is 0)."""
    def value(expression):
        expression = re.sub(r"defined\s*\(\s*(\w+)\s*\)", lambda m: "1" if m.group(1) in defines else "0", expression)
        expression = re.sub(r"[A-Za-z_]\w*", lambda m: str(defines.get(m.group(0), 0)), expression)
        expression = expression.replace("&&", " and ").replace("||", " or ")
        return bool(eval(re.sub(r"!(?!=)", " not ", expression)))
    kept, stack = [], []  # (whether this branch is kept, whether a branch was taken)
    for line in text.split("\n"):
        d = re.match(r"\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)", line)
        if not d:
            if all(s[0] for s in stack):
                kept.append(line)
            continue
        kind, rest = d.group(1), d.group(2).strip()
        if kind in ("if", "ifdef", "ifndef"):
            on = value(rest) if kind == "if" else (rest in defines) == (kind == "ifdef")
            stack.append((on, on))
        elif kind == "elif":
            on = not stack[-1][1] and value(rest)
            stack[-1] = (on, stack[-1][1] or on)
        elif kind == "else":
            stack[-1] = (not stack[-1][1], True)
        else:
            stack.pop()
    return "\n".join(kept)


def struct_layouts(header, defines=None):
    """{struct name: [(offset, size, field, element size or None)]} of HEADER's structs (mac68k alignment), as the
    preprocessor keeps them for DEFINES."""
    layouts = {}
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", Path(header).read_text(), flags=re.DOTALL)
    text = preprocess(text, defines or {})
    for m in re.finditer(r"struct (\w+) \{(.*?)\};", text, re.DOTALL):
        offset, fields = 0, []
        for line in m.group(2).split(";"):
            f = re.match(r"\s*(.*?)\s*(\w+)(?:\[(\d+)\])?\s*$", line)
            if not f or not f.group(2):
                continue
            size = 4 if "*" in f.group(1) else SCALARS[f.group(1).removeprefix("const ")]
            offset += offset % 2 if size > 1 else 0
            count = int(f.group(3)) if f.group(3) else None
            fields.append((offset, size * (count or 1), f.group(2), size if count else None))
            offset += size * (count or 1)
        layouts[m.group(1)] = fields
    return layouts


def c_string(data):
    out = []
    for c in data:
        ch = chr(c)
        out.append({"\n": "\\n", "\t": "\\t", "\b": "\\b", '"': '\\"', "\\": "\\\\"}.get(ch)
                   or (ch if 32 <= c < 127 else f"\\{c:03o}"))
    return '"' + "".join(out) + '"'


def c_name(symbol):
    m = re.fullmatch(r"_(\w+?)(?:@\d+)?", symbol)
    return m.group(1) if m else symbol


class Writer:
    def __init__(self, walk, lists, panels, blobs, layouts):
        self.walk, self.im = walk, walk.image
        self.lists = lists  # [(help prefix, name)]
        self.panel_names = panels  # {panel name: (C variable, struct or None)}
        self.layouts = layouts
        self.names = {}
        self.panels = [(a, o[1], self.panel_names[o[2].decode()]) for a, o in walk.objects.items() if o[0] == "panel"]
        self.panels += [(start, end - start, (name, type_)) for start, end, name, type_ in blobs]

    def name_objects(self, roots):
        im, named = self.im, []
        for root in roots:
            help_ = im.cstr(im.ptr(root)).decode("latin1")
            matches = [n for prefix, n in self.lists if help_.startswith(prefix)]
            if not matches:
                raise SystemExit(f"no name for the option list {help_!r}")
            named.append((root, "optlst" + matches[0]))
        named.sort()
        previous, files = 0, []
        for root, name in named:
            members = [a for a in sorted(self.walk.objects) if previous < a <= root
                       and self.walk.objects[a][0] in ("param", "Option", "OptionArray", "OptionList")]
            for i, a in enumerate(members):
                self.names[a] = name if a == root else f"{name}_{i:03d}"
            files.append((name, members))
            previous = root
        # (an object outside the lists' ranges, such as the 2.7 linker's zero parameter in the uninitialized data, goes
        # with the list whose object refers to it)
        for address, (kind, size, _) in sorted(self.walk.objects.items()):
            if kind not in ("param", "Option", "OptionArray", "OptionList") or address in self.names:
                continue
            for name, members in files:
                user = next((m for m in members if address in referenced(self, m)), None)
                if user is not None:
                    self.names[address] = f"{name}_{address:08X}"
                    members.insert(members.index(user), address)
                    break
        return files

    def ref(self, value, cast=""):
        if value is None:
            return "0"
        kind = self.walk.objects.get(value, (None,))[0]
        if kind == "string":
            return cast + c_string(self.walk.objects[value][2])
        if value in self.names:
            return cast + "&" + self.names[value]
        for start, size, (var, type_) in self.panels:
            if start <= value < start + size:
                offset = value - start
                for f_offset, f_size, field, element in self.layouts.get(type_, []):
                    if f_offset == offset:
                        return cast + f"&{var}.{field}"
                    if element and f_offset < offset < f_offset + f_size:
                        return cast + f"&{var}.{field}[{(offset - f_offset) // element}]"
                return f"{cast}((char *)&{var} + {offset})"
        name = self.im.names.get(value)
        if name:
            text = self.im.pe.section_for_address(value).name == ".text"
            return cast + ("" if text else "&") + c_name(name)
        start = max((a for a in self.im.sizes if a <= value < a + self.im.sizes[a]), default=None)
        if start is None:
            raise SystemExit(f"0x{value:x}: no symbol there or around it")
        return f"{cast}((char *)&{c_name(self.im.names[start])} + {value - start})"

    def param(self, address):
        im = self.im
        kind, layout = WHICH[im.u8(address)]
        fields = [str(im.u8(address)), f"0x{im.u8(address + 1):02X}", self.ref(im.ptr(address + 2)),
                  self.ref(im.ptr(address + 6), "(PARAM_T *)")]
        offset = 10
        for field, t in layout:
            if t == "b":
                fields.append(str(im.u8(address + offset)))
            elif t == "h":
                fields.append(str(struct.unpack("<h", im.pe.read(address + offset, 2))[0]))
            elif t == "i":
                fields.append(f"0x{im.u32(address + offset):X}")
            elif im.ptr(address + offset) is None and im.u32(address + offset):
                fields.append(f"(void *){im.u32(address + offset)}")
            else:
                fields.append(self.ref(im.ptr(address + offset),
                                       "(PARAM_T *)" if t == "P" else "(void *)" if t in "pf" else ""))
            offset += SIZES[t]
        return f"{TYPES[kind]} {self.names[address]} = {{" + ", ".join(fields) + "};"

    def option(self, address):
        im = self.im
        values = [self.ref(im.ptr(address)), f"0x{im.u32(address + 4):X}", self.ref(im.ptr(address + 8), "(PARAM_T *)"),
                  self.ref(im.ptr(address + 12)), self.ref(im.ptr(address + 16)), self.ref(im.ptr(address + 20))]
        return f"Option {self.names[address]} = {{" + ", ".join(values) + "};"

    def declaration(self, address):
        kind = self.walk.objects[address][0]
        name = self.names[address]
        if kind == "param":
            return f"extern {TYPES[WHICH[self.im.u8(address)][0]]} {name};"
        return {"Option": f"extern Option {name};", "OptionArray": f"extern Option *{name}[];",
                "OptionList": f"extern OptionList {name};"}[kind]

    def definition(self, address):
        kind, size, fields = self.walk.objects[address]
        if kind == "param":
            return self.param(address)
        if kind == "Option":
            return self.option(address)
        if kind == "OptionArray":
            items = "".join(f"\n    &{self.names[e]}," for e in fields)
            return f"Option *{self.names[address]}[] = {{{items}\n    0\n}};"
        im = self.im
        return (f"OptionList {self.names[address]} = {{{self.ref(im.ptr(address))}, 0x{im.u32(address + 4):X}, "
                f"{self.names.get(im.ptr(address + 8), '0')}}};")

    def data(self, address, size, var, type_):
        """A panel's or a block's initial bytes, as TYPE_'s fields or as bytes."""
        data = self.im.pe.read(address, size)
        if any(a in self.im.fixups for a in range(address, address + size)):
            raise SystemExit(f"0x{address:x} ({var}) has pointers")
        if type_ is None:
            last = max((i for i, b in enumerate(data) if b), default=-1) + 1
            rows = [", ".join(f"0x{b:02x}" for b in data[i:min(i + 16, last)]) for i in range(0, last, 16)]
            body = ("\n    " + ",\n    ".join(rows) + "\n") if rows else "0"
            return f"unsigned char {var}[{size}] = {{{body}}};"
        values = []
        for offset, f_size, field, element in self.layouts[type_]:
            raw = data[offset:offset + f_size]
            text = raw.rstrip(b"\0")
            if element == 1 and text and b"\0" not in text and all(32 <= c < 127 for c in text):
                values.append(c_string(text))
            elif element:
                items = [int.from_bytes(raw[i:i + element], "little") for i in range(0, f_size, element)]
                values.append("{" + ", ".join(hex(x) for x in items) + "}" if any(items) else "{0}")
            else:
                values.append(hex(int.from_bytes(raw, "little")))
        while values and values[-1] in ("0x0", "{0}"):
            values.pop()
        return f"{type_} {var} = {{" + ", ".join(values) + "};"

    def externals(self, members, local):
        """Declarations of what the tables refer to outside them (other units' functions and data), and the
        definitions of the small data between the tables they refer to (as bytes, up to the next object)."""
        out, inner = {}, {}
        ends = sorted(set(self.walk.objects) | {s for s, _, _ in self.panels})
        low = ends[0]
        high = max(a + o[1] for a, o in self.walk.objects.items())
        for m in members:
            for value in referenced(self, m):
                if value in self.walk.objects or any(s <= value < s + z for s, z, _ in self.panels):
                    continue
                name = self.im.names.get(value)
                if name is None or c_name(name) in local:
                    continue
                try:
                    self.im.pe.address_to_offset(value)
                    initialized = True
                except ValueError:
                    initialized = False
                if low <= value < high and initialized:
                    inner[value] = c_name(name)
                    continue
                text = self.im.pe.section_for_address(value).name == ".text"
                out[c_name(name)] = f"extern int {c_name(name)}();" if text else f"extern char {c_name(name)};"
        definitions = []
        for value in sorted(inner):
            end = min(a for a in ends + sorted(inner) + [high] if a > value)
            data = self.im.pe.read(value, end - value)
            body = ", ".join(f"0x{b:02x}" for b in data)
            definitions.append(f"char {inner[value]}[{end - value}] = {{{body}}};")
        return [out[k] for k in sorted(out)] + [""] + definitions


def referenced(writer, address):
    im = writer.im
    kind, size, _ = writer.walk.objects[address]
    return {im.u32(a) for a in range(address, address + size) if a in im.fixups}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("version")
    parser.add_argument("root", help="the ParserTool's address (hexadecimal)")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--list", action="append", default=[], metavar="PREFIX=NAME",
                        help="an option list's C name (optlstNAME), by the start of its help")
    parser.add_argument("--panel", action="append", default=[], metavar="PANEL=NAME[:STRUCT]",
                        help="a preference panel's data's C name (and its struct in --header, else bytes)")
    parser.add_argument("--block", action="append", default=[], metavar="START:END=NAME[:STRUCT]",
                        help="other data of the unit the tables point into (as STRUCT, else bytes)")
    parser.add_argument("--name", action="append", default=[], metavar="ADDRESS=NAME",
                        help="the C name of a variable at ADDRESS")
    parser.add_argument("--local", action="append", default=[], metavar="NAME",
                        help="a name the glue's own code defines (no extern for it)")
    parser.add_argument("--header", default="include/driver/PrefPanels.h", help="the panels' structs")
    parser.add_argument("--define", action="append", default=[], metavar="NAME=VALUE",
                        help="a macro the header's #if lines test (LINKER=27 for the 2.7 linker's panels)")
    parser.add_argument("-o", "--out")
    args = parser.parse_args()
    walk = Walk(Image(args.version))
    root = int(args.root, 16)
    walk.tool(root)
    if args.report:
        report(walk, min(walk.objects), max(walk.objects) + 60)
        return
    lists = [tuple(item.split("=", 1)) for item in args.list]
    panels = {}
    for item in args.panel:
        panel, spec = item.split("=", 1)
        var, _, type_ = spec.partition(":")
        panels[panel] = (var, type_ or None)
    blobs = []
    for item in args.block:
        span, spec = item.split("=", 1)
        name, _, type_ = spec.partition(":")
        start, end = (int(x, 16) for x in span.split(":"))
        blobs.append((start, end, name, type_ or None))
    for item in args.name:
        address, name = item.split("=", 1)
        walk.image.names[int(address, 16)] = name
    # (data the tables point at that no symbol names, such as an option's extensions string: named by its address)
    im = walk.image
    for address, (kind, size, _) in list(walk.objects.items()):
        for value in {im.u32(a) for a in range(address, address + size) if a in im.fixups}:
            if value in walk.objects or value in im.names:
                continue
            section = im.pe.section_for_address(value)
            if section.name != ".text" and value - section.virtual_address < section.file_size and not any(
                    o[0] == "panel" and a <= value < a + o[1] for a, o in walk.objects.items()):
                im.names[value] = f"lbl_{value:08X}"
    writer = Writer(walk, lists, panels, blobs, struct_layouts(args.header, {d.split("=")[0]: int(d.split("=")[1]) for d in args.define}))
    tool = walk.objects[root][2]
    files = writer.name_objects(walk.objects[tool[9]][2])
    lines = ["/* (written by tools/gen_options.py from the original's tables) */", ""]
    for start, size, (var, type_) in sorted(writer.panels):
        lines.append(writer.data(start, size, var, type_))
    lines.append("")
    every = [m for _, members in files for m in members]
    lines += writer.externals(every, set(args.local))
    lines.append("")
    lines += [writer.declaration(a) for a in every]
    lines.append("")
    for name, members in files:
        lines += [writer.definition(a) for a in members]
        lines.append("")
    Path(args.out).write_text("\n".join(lines))
    print(args.out, len(every), "objects")


if __name__ == "__main__":
    main()
