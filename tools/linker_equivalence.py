#!/usr/bin/env python3
"""python tools/linker_equivalence.py LINKER_DIR REBUILT OUT_DIR --runtime DIR [NAME...]: check that a linker built
from source (REBUILT, for example build/LD_2_6/equivalent/mwldeppc.exe) behaves as the original it replaces
(LINKER_DIR/mwldeppc.exe, for example build/compilers/GC/2.6).

Both link the same programs, and their ELF files, link maps, exit statuses and messages must be the same. The programs
are tools/linker_oracle.py's scenarios and the linker command file scenarios here: the command file's syntax
(MEMORY, SECTIONS, GROUP, the section contents, the lists, comments), its expressions (every operator, ADDR, SIZEOF,
NEXT, symbols, `.`), and files with errors, whose messages are compared, the S-record files of -srec, -sreclength
and -sreceol, programs with debug information,
the archives of -library (and programs linked with them),
the dumps of -dis, the debug information of dead-stripped code, and the objects' loading and the command file's file
lists (duplicates, common symbols, FORCEFILES, EXCLUDEFILES, INCLUDEDWARF, the partial links that use the command
file), and the PowerPC EABI side (the relocations, small data, memory areas, EABI compliance, the kinds of sections
mixed in the command file's output sections, the program's own sections), and the disassembler's sweeps (the
dumps of objects of instruction words that cover its decoding, for each processor mask). LINKER_DIR's mwcceppc.exe compiles them. A
scenario that the original linker itself fails to link without a message to compare (the oracle's cpp-exceptions with
the 2.6 linker) is reported as not applicable. The exit status is 1 when any scenario differs."""
import argparse
import re
import shutil
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import linker_oracle as lo

PROGRAM = {
    "a.c": "int g = 5; int h; const int k = 7; int table[64] = {1, 2, 3};\n"
           "static int counter;\n"
           "int f(int x) { counter += x; return x + g + h + k + table[x & 63]; }\n"
           "int unused(int x) { return x * 3; }\n"
           "void _start(void) { f(1); }\n",
    "b.c": "int bvalue = 9; int bss_b[16];\n"
           "int b(int x) { return x + bvalue + bss_b[x & 15]; }\n",
}

DOLPHIN = """MEMORY
{
    text : origin = 0x80003100
}

SECTIONS
{
    GROUP:
    {
        .init ALIGN(0x4):{}
        extab ALIGN(0x10):{}
        extabindex ALIGN(0x20):{}
        .text ALIGN(0x4):{}
        .ctors ALIGN(0x10):{}
        .dtors ALIGN(0x20):{}
        .rodata ALIGN(0x20):{}
        .data ALIGN(0x20):{}
        .bss ALIGN(0x20):{}
        .sdata ALIGN(0x20):{}
        .sbss ALIGN(0x20):{}
        .sdata2 ALIGN(0x20):{}
        .sbss2 ALIGN(0x4):{}
        .stack ALIGN(0x100):{}
    } > text

    _stack_end = _f_sbss2 + SIZEOF(.sbss2);
    _stack_addr = (_stack_end + 0x16004 + 0x7) & ~0x7;
    _db_stack_addr = (_stack_addr + 0x2000);
    _db_stack_end = _stack_addr;
    __ArenaLo = (_db_stack_addr + 0x1f) & ~0x1f;
    __ArenaHi = 0x81700000;
}

FORCEACTIVE
{
    unused
    b
}
"""

GROUP = """    GROUP:
    {
        .init ALIGN(0x4):{}
        .text ALIGN(0x4):{}
        .ctors ALIGN(0x10):{}
        .dtors ALIGN(0x20):{}
        .rodata ALIGN(0x20):{}
        .data ALIGN(0x20):{}
        .bss ALIGN(0x20):{}
        .sdata ALIGN(0x20):{}
        .sbss ALIGN(0x20):{}
        .sdata2 ALIGN(0x20):{}
        .sbss2 ALIGN(0x4):{}
    } > text
"""

OPERATORS = """MEMORY { text : origin = 0x80003100 }
SECTIONS
{
""" + GROUP + """
    op_add = 1 + 2 * 3 - 4 / 2;
    op_mod = (10 % 3) << 4 >> 1;
    op_bits = 0xF0 & 0x3C | 0x01;
    op_not = ~0x0F;
    op_lnot = !0;
    op_neg = -(5);
    op_pos = +7;
    op_lt = 3 < 4;
    op_gt = 3 > 4;
    op_le = 3 <= 3;
    op_ge = 4 >= 5;
    op_eq = 1 == 1;
    op_ne = 1 != 1;
    op_and = 1 && 0;
    op_or = 1 || 0;
    op_octal = 017 + 0X10 + 10;
    op_nested = ((1 + 2) * (3 + (4 - 1))) / 2;
    op_prec = 1 + 2 << 3 & 0xFF | 4 == 4;
    op_addr = ADDR(.text);
    op_size = SIZEOF(.data) + SIZEOF(.text);
    op_next = NEXT(0x100);
    op_symbol = f + 4;
    op_chain = op_add + op_symbol;
}
FORCEACTIVE { unused }
"""

CONTENTS = """MEMORY { text : origin = 0x80003100 }
SECTIONS
{
    GROUP:
    {
        .init ALIGN(0x4):{}
        .text BIND(0x80004000) ALIGN(0x20):
        {
            *(.init)
            b.o(.text)
            *(.text)
            . = . + 0x10;
            text_end = .;
        }
        .ctors ALIGN(0x10):{}
        .dtors ALIGN(0x20):{}
        .rodata ALIGN(0x20):{ *(.rodata) }
        .data ALIGN(0x20):
        {
            *(.data)
            . = . + 0x20;
            data_pad = .;
        }
        .bss (BSS) ALIGN(0x20):{ *(.bss) }
        .sdata ALIGN(0x20):{}
        .sbss ALIGN(0x20):{}
        .sdata2 ALIGN(0x20):{}
        .sbss2 ALIGN(0x4):{}
    } > text
    after_all = _f_sbss2 + SIZEOF(.sbss2);
}
"""

MEMORY = """MEMORY
{
    low : org = 0x80003100, len = 0x100000
    high : o = 0x80400000, l = 0x10000
    rom : origin = 0x90000000, length = 0x8000
}
SECTIONS
{
    GROUP:
    {
        .init ALIGN(0x4):{}
        .text ALIGN(0x4):{}
        .ctors ALIGN(0x10):{}
        .dtors ALIGN(0x20):{}
        .rodata ALIGN(0x20):{}
    } > low
    GROUP:
    {
        .data ALIGN(0x20):{}
        .bss ALIGN(0x20):{}
        .sdata ALIGN(0x20):{}
        .sbss ALIGN(0x20):{}
        .sdata2 ALIGN(0x20):{}
        .sbss2 ALIGN(0x4):{}
    } > high
    low_size = SIZEOF(.text);
    high_start = ADDR(.data);
}
"""

COMMENTS = """// a command file with comments, tabs and odd spacing
MEMORY{text : origin = 0x80003100 }   /* one line */
SECTIONS
{
\t/* a
\t   block comment over
\t   lines */
\tGROUP :
\t{
\t\t.init ALIGN(0x4) : {}   // trailing
\t\t.text   ALIGN(0x4) :{}
\t\t.ctors ALIGN(0x10):{}
\t\t.dtors ALIGN(0x20):{}
\t\t.rodata ALIGN(0x20):{}
\t\t.data ALIGN(0x20):{}
\t\t.bss ALIGN(0x20):{}
\t\t.sdata ALIGN(0x20):{}
\t\t.sbss ALIGN(0x20):{}
\t\t.sdata2 ALIGN(0x20):{}
\t\t.sbss2 ALIGN(0x4):{}
\t} > text
\tspaced   =   ( 1+2 )*3 ;
}
FORCEACTIVE{unused b}
"""

LISTS = """MEMORY { text : origin = 0x80003100 }
SECTIONS
{
""" + GROUP + """}
FORCEACTIVE
{
    unused,
    b
}
FORCEFILES
{
    b.o
}
EXCLUDEFILES
{
    stub.o
}
"""

SHORTEN = """MEMORY { text : origin = 0x80003100 }
SECTIONS
{
""" + GROUP + """}
SHORTEN_NAMES_FOR_TOR_101
"""

ASSIGNMENTS_FIRST = """MEMORY { text : origin = 0x80003100 }
SECTIONS
{
    first = 0x1234;
    second = first * 2;
""" + GROUP + """    third = second + _f_text;
}
"""

ERRORS = {
    "error-keyword": "MEMORY { text : origin = 0x80003100 }\nSECTIONS {\n" + GROUP + "}\nNOTAKEYWORD { x }\n",
    "error-brace": "MEMORY { text : origin = 0x80003100 }\nSECTIONS {\n" + GROUP,
    "error-comment": "MEMORY { text : origin = 0x80003100 }\n/* never closed\nSECTIONS {\n" + GROUP + "}\n",
    "error-number": "MEMORY { text : origin = 0x8000310g }\nSECTIONS {\n" + GROUP + "}\n",
    "error-symbol": "MEMORY { text : origin = 0x80003100 }\nSECTIONS {\n" + GROUP + "    x = no_such_symbol + 1;\n}\n",
    "error-memory": "MEMORY { text : origin = 0x80003100\n text : origin = 0x80400000 }\nSECTIONS {\n" + GROUP + "}\n",
    "error-region": "MEMORY { text : origin = 0x80003100 }\nSECTIONS {\n" + GROUP.replace("> text", "> nowhere") + "}\n",
    "error-operator": "MEMORY { text : origin = 0x80003100 }\nSECTIONS {\n" + GROUP + "    x = 1 + * 2;\n}\n",
    "error-paren": "MEMORY { text : origin = 0x80003100 }\nSECTIONS {\n" + GROUP + "    x = (1 + 2;\n}\n",
    "error-compact": "MEMORY{text:origin=0x80003100}\nSECTIONS {\n" + GROUP + "}\n",
    "error-align": "MEMORY { text : origin = 0x80003100 }\nSECTIONS {\n"
                   + GROUP.replace(".text ALIGN(0x4):{}", ".text ALIGN(0x4):{ *(.text) . = ALIGN(0x40); }") + "}\n",
    "error-includedwarf": "MEMORY { text : origin = 0x80003100 }\nSECTIONS {\n" + GROUP + "}\nINCLUDEDWARF { a.o }\n",
    "error-section-kind":"MEMORY { text : origin = 0x80003100 }\nSECTIONS {\n"
                          + GROUP.replace(".bss ALIGN", ".bss (NOTAKIND) ALIGN") + "}\n",
}

# (the linker-defined symbols, which the map lists: one the command file assigns twice; predefined ones it assigns,
# one of them twice; section symbols it assigns before the linker makes them, _f_text, _f_data_rom and _e_bss; an
# output section whose name has two dots, its symbols' names made with underscores; a ROM image, whose _rom
# symbols are the ROM addresses)
ASSIGNMENTS = "    _stack_end = _f_sbss2 + SIZEOF(.sbss2);"
LINKSYM = {
    "linksym-twice": DOLPHIN.replace(ASSIGNMENTS, ASSIGNMENTS + "\n    twice = 0x10;\n    twice = 0x20;"),
    "linksym-predefined": DOLPHIN.replace(ASSIGNMENTS, ASSIGNMENTS + "\n    _SDA_BASE_ = _f_sdata + 0x7ff0;\n"
                                          "    _heap_addr = 0x80300000;\n    _heap_end = 0x80400000;\n"
                                          "    _SDA_BASE_ = 0x80020000;"),
    "linksym-section-assigned": DOLPHIN.replace(ASSIGNMENTS, "    _f_text = 0x80004000;\n    _f_data_rom = 0x10;\n"
                                                "    _e_bss = _f_text + 4;\n" + ASSIGNMENTS),
    "linksym-dotted": DOLPHIN.replace("        .stack ALIGN(0x100):{}",
                                      "        .data.extra.more ALIGN(0x4):{}\n        .stack ALIGN(0x100):{}"),
}

LINKSYM_OPTIONS = {"linksym-rom": ["-romaddr", "0x80400000", "-rambuffer", "0x80500000"]}
LINKSYM.update({name: DOLPHIN for name in LINKSYM_OPTIONS})

SCENARIOS = {
    # (the checks after the layout: a section bound over another, the stack and the heap ending before they start,
    # and a stack over the code)
    "lcf-overlap": DOLPHIN.replace(".data ALIGN(0x20):{}", ".data BIND(0x80003100) ALIGN(0x20):{}"),
    "lcf-stack-heap-reversed": DOLPHIN.replace("_stack_addr = (_stack_end + 0x16004 + 0x7) & ~0x7;",
                                               "_stack_addr = _stack_end - 0x100;\n"
                                               "    _heap_addr = 0x81000000;\n    _heap_end = 0x80f00000;"),
    "lcf-stack-over-code": DOLPHIN.replace("_stack_end = _f_sbss2 + SIZEOF(.sbss2);", "_stack_end = _f_text;"),
    "lcf-dolphin": DOLPHIN,
    "lcf-operators": OPERATORS,
    "lcf-contents": CONTENTS,
    "lcf-memory": MEMORY,
    "lcf-comments": COMMENTS,
    "lcf-lists": LISTS,
    "lcf-shorten": SHORTEN,
    "lcf-assignments-first": ASSIGNMENTS_FIRST,
    **ERRORS,
    **LINKSYM,
    # (other ends of line, written as they are: the command file's lexer ends a line and a // comment at a lone LF or
    # CR; the driver's text loader, which turns lone LFs into CRs, is not on its way)
    "lcf-eol-unix": COMMENTS.encode(),
    "lcf-eol-mac": COMMENTS.replace("\n", "\r").encode(),
    "error-keyword-eol-unix": ERRORS["error-keyword"].encode(),
    "error-keyword-eol-mac": ERRORS["error-keyword"].replace("\n", "\r").encode(),
}

# (the S-record output: the default, the record lengths at the ends of their range and outside it, each end of line, a
# file name, and code at other addresses, whose bytes are in the checksums; the linker writes only S0, S3 and S7
# records, so the other types SRecord_Start knows are not reached)
LOW = DOLPHIN.replace("origin = 0x80003100", "origin = 0x00003100")
MIDDLE = DOLPHIN.replace("origin = 0x80003100", "origin = 0x00103100")
SREC = {
    "srec-default": (DOLPHIN, ["-srec"]),
    "srec-named": (DOLPHIN, ["-srec", "{out}/named.s"]),
    "srec-length-8": (DOLPHIN, ["-sreclength", "8"]),
    "srec-length-9": (DOLPHIN, ["-sreclength", "9"]),
    "srec-length-255": (DOLPHIN, ["-sreclength", "255"]),
    "srec-length-7": (DOLPHIN, ["-sreclength", "7"]),
    "srec-length-256": (DOLPHIN, ["-sreclength", "256"]),
    "srec-eol-mac": (DOLPHIN, ["-sreceol", "mac"]),
    "srec-eol-dos": (DOLPHIN, ["-sreceol", "dos"]),
    "srec-eol-unix": (DOLPHIN, ["-sreceol", "unix"]),
    "srec-eol-bad": (DOLPHIN, ["-sreceol", "amiga"]),
    "srec-low": (LOW, ["-srec", "-sreclength", "40"]),
    "srec-middle": (MIDDLE, ["-srec", "-sreceol", "unix"]),
    # (2.7: the size of its write buffers; 2.6 has no -linkmode)
    "linkmode-lessram": (DOLPHIN, ["-linkmode", "lessram", "-srec"]),
    "linkmode-moreram": (DOLPHIN, ["-linkmode", "moreram", "-srec"]),
}
SCENARIOS.update({name: lcf for name, (lcf, _) in SREC.items()})

# (debug information: DWARF 1 and its line tables, kept or dropped, whose byte order the linker converts)
DEBUG = {
    "debug-g": ["-g"],
    "debug-sym-on": ["-sym", "on"],
    "debug-dropped": [],
}
SCENARIOS.update({name: DOLPHIN for name in DEBUG})

# (inputs named by wildcards, which the driver expands (Generic.c's OS_MatchPath): the program's objects renamed, then
# the patterns; a pattern of 64 characters, more than the 1.x drivers' 63 (its whole path stays under Windows' 260
# characters while OUT's is under 190 or so)
LONG_NAME = "a" + "x" * 60
WILDCARD = {
    "wildcard-star": ({}, ["*.o"]),
    "wildcard-question": ({}, ["?.o", "stub.o"]),
    "wildcard-long": ({"a.o": LONG_NAME + "1.o", "b.o": LONG_NAME + "2.o"}, [LONG_NAME + "*.o", "stub.o"]),
    "wildcard-none": ({}, ["no*.o"]),
}
SCENARIOS.update({name: DOLPHIN for name in WILDCARD})


# (-library: archives of objects with global, weak and no global symbols, names of 15, 16 and more characters (the
# long names member), objects of odd sizes (the padding), C++ (weak symbols); each archive is linked into a program
# too, by each linker from the original's archive, which reads its members' names)
LIBRARIES = {
    "library-basic": {"short.c": "int g = 1; int f(int x) { return x + g; }\n",
                      "other.c": "int h(int x) { return x * 2; } int table[3] = {1, 2, 3};\n"},
    "library-long-names": {"a_very_long_object_file_name.c": "int lf(int x) { return x + 7; }\n",
                           "fifteen_chars.c": "int f15(void) { return 15; }\n",
                           "sixteen_chars_.c": "int f16(void) { return 16; }\n",
                           "another_long_object_name.c": "int lg = 4;\n",
                           "s.c": "int sf(void) { return 1; }\n"},
    "library-no-globals": {"static_only.c": "static int s(int x) { return x; } static int t = 3;\n",
                           "short.c": "int g = 1; int f(int x) { return x + g; }\n"},
    "library-odd": {"odd1.c": "char c = 1;\n", "odd2.c": "const char s[] = \"abc\"; char d = 2;\n",
                    "odd3.c": "short sh = 3; int f(void) { return sh; }\n"},
    "library-weak": {"weak.cpp": "inline int w(int x) { return x * 3 + 1; } extern \"C\" int use(int x) { return w(x); }\n"
                                 "struct A { virtual int v() { return 1; } }; extern \"C\" int mk(void) { A x; return x.v(); }\n",
                     "short.c": "int g = 1; int f(int x) { return x + g; }\n"},
}
# (the program linked against each archive: it calls what the archive defines)
LIBRARY_PROGRAMS = {
    "library-basic": "extern int f(int); extern int h(int); void _start(void) { f(h(1)); }\n",
    "library-long-names": "extern int lf(int); extern int f15(void); extern int f16(void); extern int lg;\n"
                          "extern int sf(void); void _start(void) { lf(f15() + f16() + lg + sf()); }\n",
    "library-no-globals": "extern int f(int); void _start(void) { f(1); }\n",
    "library-odd": "extern char c; extern char d; extern int f(void); void _start(void) { f(); c = d; }\n",
    "library-weak": "extern int use(int); extern int f(int); void _start(void) { use(f(1)); }\n",
}


def undated(raw):
    """An archive with its members' dates blanked (2.7 writes the time of the link)."""
    raw, pos = bytearray(raw), 8
    while raw[:8] == b"!<arch>\n" and pos + 60 <= len(raw):
        size = int(raw[pos + 48:pos + 58].strip() or b"0")
        raw[pos + 16:pos + 28] = b" " * 12
        pos += 60 + size + (size & 1)
    return bytes(raw)


def library_scenario(name, linker_dir, rebuilt, out_root, runtime):
    out = out_root / name
    out.mkdir(parents=True, exist_ok=True)
    objects = []
    for file, text in {**LIBRARIES[name], "main.c": LIBRARY_PROGRAMS[name], "stub.c": lo.STUB}.items():
        (out / file).write_text(text)
        obj = out / (file.rsplit(".", 1)[0] + ".o")
        flags = ["-Cpp_exceptions", "off"] if file.endswith(".cpp") else []
        code, log = lo.run(linker_dir / "mwcceppc.exe", "-c", "-proc", "gekko", *flags, out / file, "-o", obj)
        if code:
            return [f"compile of {file} failed:\n{log}"]
        objects.append(obj)
    members, program = objects[:-2], objects[-2:]
    (out / "ldscript.lcf").write_text(DOLPHIN)
    problems, results = [], {}
    for who, linker in (("oracle", linker_dir / "mwldeppc.exe"), ("mine", rebuilt)):
        code, log = lo.run(linker, "-library", "-o", out / f"{who}.a", *members)
        results[who] = (code, messages(log, linker).replace(f"{who}.a", "OUT.a"))
    if results["oracle"] != results["mine"]:
        problems.append(f"the archives' links differ: {results['oracle']} against {results['mine']}")
    elif undated((out / "oracle.a").read_bytes()) != undated((out / "mine.a").read_bytes()):
        problems.append("the archives differ")
    # (each linker links the program against the original's archive)
    results = {}
    inputs = [*program, out / "oracle.a", runtime / "global_destructor_chain.o", runtime / "__init_cpp_exceptions.o"]
    for who, linker in (("oracle", linker_dir / "mwldeppc.exe"), ("mine", rebuilt)):
        code, log = lo.run(linker, "-nodefaults", "-fp", "hardware", "-lcf", out / "ldscript.lcf", "-m", "_start",
                           "-map", out / f"{who}.map", "-o", out / f"{who}.elf", *inputs)
        results[who] = (code, messages(log, linker).replace(f"{who}.elf", "OUT.elf").replace(f"{who}.map", "OUT.map"))
    if results["oracle"] != results["mine"]:
        problems.append(f"the programs' links differ: {results['oracle']} against {results['mine']}")
    elif results["oracle"][0] == 0:
        problems += lo.compare(out / "oracle.elf", out / "mine.elf", out / "oracle.map", out / "mine.map")
    else:
        problems.append(f"the original fails to link the program:\n{results['oracle'][1]}")
    return problems


# (the library search: library-basic's program linked against its archive found by -l in the -L paths, by the access
# paths of the environment's MWLibraries, or named by MWLibraryFiles; the archive is in OUT/a as libbasic.a, in OUT/b
# as libbasic.lib and as plain.a, and in OUT/c as libbasic.a again but with f returning x - g, so that the order of
# the paths shows. Each entry: the options, and the environment's variables, with {out} for OUT)
LIBRARY_SEARCH = {
    "library-search-a": (["-L{out}/a", "-lbasic"], {}),
    "library-search-lib": (["-L{out}/b", "-lbasic"], {}),
    "library-search-name": (["-L{out}/b", "-lplain.a"], {}),
    "library-search-missing": (["-L{out}/a", "-lnosuch"], {}),
    "library-search-long-name": (["-L{out}/a", "-l" + "x" * 250], {}),
    "library-search-path-list": (["-L{out}/nosuch;{out}/a", "-lbasic"], {}),
    "library-search-env": (["-lbasic"], {"MWLibraries": "{out}/nosuch;{out}/a"}),
    "library-search-env-first": (["-lbasic"], {"MWEABIPPCLibraries": "{out}/c", "MWLibraries": "{out}/a"}),
    "library-search-order": (["-L{out}/a", "-lbasic"], {"MWLibraries": "{out}/c"}),
    "library-search-order-env-first": (["-L{out}/c", "-lbasic"], {"MWLibraries": "{out}/a"}),
    "library-files-env": ([], {"MWLibraries": "{out}/a", "MWLibraryFiles": "libbasic.a"}),
    "library-files-env-list": (["-L{out}/b"], {"MWLibraryFiles": "nosuch.a;libbasic.lib:plain.a"}),
    "library-files-env-colon": (["-L{out}/b"], {"MWLibraryFiles": "libbasic.lib:plain.a"}),
    "library-files-env-dir": (["-L{out}/a"], {"MWLibraryFiles": "{out}/b;libbasic.a"}),
}
OTHER_BASIC = {"short.c": "int g = 1; int f(int x) { return x - g; }\n",
               "other.c": "int h(int x) { return x * 2; } int table[3] = {1, 2, 3};\n"}


def library_search_scenario(name, linker_dir, rebuilt, out_root, runtime):
    import os
    out = out_root / name
    out.mkdir(parents=True, exist_ok=True)
    for folder in "abc":
        (out / folder).mkdir(exist_ok=True)

    def compile_all(sources, where):
        objects = []
        for file, text in sources.items():
            (where / file).write_text(text)
            obj = where / (file.rsplit(".", 1)[0] + ".o")
            code, log = lo.run(linker_dir / "mwcceppc.exe", "-c", "-proc", "gekko", where / file, "-o", obj)
            if code:
                raise RuntimeError(f"compile of {file} failed:\n{log}")
            objects.append(obj)
        return objects

    try:
        members = compile_all(LIBRARIES["library-basic"], out / "a")
        others = compile_all(OTHER_BASIC, out / "c")
        program = compile_all({"main.c": LIBRARY_PROGRAMS["library-basic"], "stub.c": lo.STUB}, out)
    except RuntimeError as error:
        return [str(error)]
    for archive_path, objects in ((out / "a" / "libbasic.a", members), (out / "c" / "libbasic.a", others)):
        code, log = lo.run(linker_dir / "mwldeppc.exe", "-library", "-o", archive_path, *objects)
        if code:
            return [f"the archive {archive_path.name} failed:\n{log}"]
    for copy in ("libbasic.lib", "plain.a"):
        shutil.copy(out / "a" / "libbasic.a", out / "b" / copy)
    (out / "ldscript.lcf").write_text(DOLPHIN)
    options, variables = LIBRARY_SEARCH[name]
    fill = lambda text: text.replace("{out}", str(out))
    saved = {key: os.environ.pop(key, None) for key in
             ("MWEABIPPCLibraries", "MWLibraries", "MWEABIPPCLibraryFiles", "MWLibraryFiles")}
    results = {}
    try:
        os.environ.update({key: fill(value) for key, value in variables.items()})
        for who, linker in (("oracle", linker_dir / "mwldeppc.exe"), ("mine", rebuilt)):
            # (-nodefaults would leave the environment's paths and files out)
            code, log = lo.run(linker, *([] if variables else ["-nodefaults"]), "-fp", "hardware", "-lcf",
                               out / "ldscript.lcf", "-m", "_start", "-map", out / f"{who}.map", "-o", out / f"{who}.elf",
                               *program,
                               runtime / "global_destructor_chain.o", runtime / "__init_cpp_exceptions.o",
                               *map(fill, options))
            results[who] = (code, messages(log, linker).replace(f"{who}.elf", "OUT.elf").replace(f"{who}.map",
                                                                                               "OUT.map"))
    finally:
        for key in variables:
            os.environ.pop(key, None)
        os.environ.update({key: value for key, value in saved.items() if value is not None})
    (out / "messages.txt").write_text(f"exit {results['oracle'][0]}\n{results['oracle'][1]}\n")
    if results["oracle"] != results["mine"]:
        return [f"the links differ: {results['oracle']} against {results['mine']}"]
    if results["oracle"][0] == 0:
        return lo.compare(out / "oracle.elf", out / "mine.elf", out / "oracle.map", out / "mine.map")
    return []


# (-dis: the disassembler's dumps of objects compiled with -g, whose DWARF has every kind of entry, attribute, type
# modifier, array subscript, location expression and constant; also of a linked program, and with -relocate)
DUMP_SOURCES = {
    "program.c": PROGRAM["a.c"] + PROGRAM["b.c"],
    "types.c": "typedef struct S { int a; char b; short c; struct S *next; } S;\n"
               "enum E { RED, GREEN = 5, BLUE };\n"
               "union U { int i; float f; double d; };\n"
               "S gs; enum E ge = GREEN; union U gu;\n"
               "const volatile int cv = 3; int *const cp = 0; const char *strings[4];\n"
               "int matrix[3][4]; char name[] = \"name\"; float vec[2] = {1.5f, 2.5f};\n"
               "long long ll = 5; unsigned long long ull; signed char sc; unsigned short us; double dd = 2.0;\n"
               "int (*fp)(int, char); S *ps; S **pps; struct S arr[2];\n"
               "int f(int x, char y) { int local = x; register int r = y; static int st; st += local;\n"
               "    { int inner = r * 2; local += inner; } return local + st; }\n"
               "static int helper(S *s) { return s ? s->a : 0; }\n"
               "int g(void) { return helper(&gs) + f(1, 2); }\n"
               "void _start(void) { g(); }\n",
    "spr.c": "asm void sprs(void) {\n nofralloc\n mfspr r3, 1008\n mfspr r4, 920\n mtspr 912, r5\n mfspr r6, 22\n"
             " mfspr r7, 26\n mfspr r8, 287\n mfspr r9, 1017\n mfspr r10, 953\n mfspr r11, 1\n mtspr 8, r12\n"
             " mfspr r3, 9\n mfspr r4, 0\n mfspr r5, 4\n mfspr r6, 1019\n mfspr r7, 528\n mfspr r8, 1023\n blr\n}\n",
    "dcr.c": "asm void dcrs(void) {\n nofralloc\n mfdcr r3, 0x40\n mtdcr 0x42, r4\n mfdcr r5, 0x80\n"
             " mfdcr r6, 0xa0\n mfdcr r7, 0x1\n blr\n}\n",
    "classes.cpp": "class Base { public: virtual int v() { return 1; } int x; Base() : x(2) {} };\n"
                   "class Derived : public Base { public: int v() { return 3; } char y; };\n"
                   "struct Plain { int a; int &ref; Plain(int &r) : ref(r), a(0) {} };\n"
                   "namespace N { int n = 4; int nf(int a) { return a + n; } }\n"
                   "template <class T> T twice(T t) { return t + t; }\n"
                   "extern \"C\" int cpp_entry(void) { Derived d; int z = 1; Plain p(z);\n"
                   "    return d.v() + N::nf(z) + twice(2) + (int)twice(1.5) + p.a; }\n",
    # (compiled with C++ exceptions: its functions have exception tables, extab and extabindex)
    "throws.cpp": "struct Guard { int *p; Guard(int *q) : p(q) {} ~Guard() { *p = 0; } };\n"
                  "int may(int x) { if (x) throw x; return 1; }\n"
                  "int caught(int x) { int v = 1; Guard g(&v); try { return may(x); }\n"
                  "    catch (int e) { return e; } catch (...) { return -1; } }\n"
                  "int guards(int n) { Guard a(&n); Guard b(&n); Guard c[2] = {Guard(&n), Guard(&n)};\n"
                  "    return may(n) + caught(n); }\n",
    # (a function too big for the short .mwcats record, 36000 bytes: its record is the long one)
    "big.c": "int big(int x) {\n" + "".join(f"    x = x * {i} + (x >> 3);\n" for i in range(1, 3001)) +
             "    return x; }\nint small(int x) { return big(x) + 1; }\n",
}
DUMPS = {
    "dump-debug": (["-show", "only,debug"], ["types.o"]),
    "dump-debug-cpp": (["-show", "only,debug"], ["classes.o"]),
    "dump-debug-relocate": (["-show", "only,debug", "-relocate"], ["types.o", "classes.o"]),
    "dump-all": (["-show", "all"], ["types.o"]),
    "dump-linked-debug": (["-show", "only,debug"], ["linked.elf"]),
    "dump-code": (["-show", "only,code"], ["types.o", "classes.o"]),
    "dump-code-extended": (["-show", "only,code,extended"], ["types.o", "classes.o"]),
    "dump-code-nobinary": (["-show", "only,code,nobinary"], ["types.o"]),
    "dump-code-detail": (["-show", "only,code,detail"], ["types.o"]),
    "dump-code-noextended": (["-fmt", "nox", "-show", "only,code"], ["types.o"]),
    "dump-code-linked": (["-show", "only,code,extended"], ["linked.elf"]),
    "dump-spr-gekko": (["-proc", "gekko", "-show", "only,code,extended"], ["spr.o"]),
    "dump-spr-603e": (["-proc", "603e", "-show", "only,code,extended"], ["spr.o"]),
    "dump-spr-860": (["-proc", "860", "-show", "only,code,extended"], ["spr.o"]),
    "dump-spr-generic": (["-proc", "generic", "-show", "only,code,extended"], ["spr.o"]),
    "dump-spr-7400": (["-proc", "7400", "-show", "only,code,extended"], ["spr.o"]),
    "dump-spr-e500": (["-proc", "e500", "-show", "only,code,extended"], ["spr.o"]),
    "dump-dcr-403": (["-proc", "403", "-show", "only,code,extended"], ["dcr.o"]),
    "dump-dcr-401": (["-proc", "401", "-show", "only,code,extended"], ["dcr.o"]),
    # (PrepDumpELF.c: an archive's members, with long names; an empty and a text member; the dump written to a file
    # with -o; files DumpELF.c stops at: of the other byte order, for another machine, of another ELF version, not ELF)
    "dump-archive": (["-show", "only,headers"], ["lib.a"]),
    "dump-archive-symbols": (["-show", "only,headers,symtab"], ["lib.a"]),
    "dump-archive-odd": (["-show", "only,headers"], ["odd.a"]),
    "dump-to-file": (["-show", "only,headers", "-o", "{out}"], ["types.o"]),
    "dump-archive-to-file": (["-o", "{out}"], ["lib.a"]),
    "dump-little-endian": ([], ["little.o"]),
    "dump-other-machine": ([], ["machine.o"]),
    "dump-other-version": ([], ["version.o"]),
    "dump-not-elf": ([], ["text.o"]),
    "dump-two-files": (["-show", "only,headers"], ["types.o", "lib.a"]),
    # (DumpELF.c: the default dump; data in hex; the string and symbol tables; exception tables; everything, with what
    # no other part dumps in hex; a linked file's headers, its program headers among them; the long record of a big
    # function; a ROM image, whose .PPC.EMB.seginfo has the ROM copy table; an object whose .comment and .mwcats.text
    # are renamed: a section no other part dumps, left for the end in hex, and a .debug* section other than .debug;
    # one whose .comment is named .dynamic)
    "dump-default": ([], ["types.o", "classes.o", "throws.o"]),
    "dump-data": (["-show", "only,data"], ["types.o", "throws.o", "linked.elf"]),
    "dump-tables": (["-show", "only,tables"], ["types.o", "classes.o", "linked.elf"]),
    "dump-exceptions": (["-show", "only,data,exceptions"], ["throws.o"]),
    "dump-xtables": (["-show", "only,data,xtables"], ["throws.o"]),
    "dump-detail": (["-show", "all,detail"], ["types.o", "throws.o", "linked.elf"]),
    "dump-headers-linked": (["-show", "only,headers"], ["linked.elf"]),
    "dump-big": (["-show", "only,code,nobinary"], ["big.o"]),
    "dump-rom": (["-show", "all,detail"], ["rom.elf"]),
    "dump-rom-default": ([], ["rom.elf"]),
    "dump-renamed": (["-show", "all"], ["renamed.o"]),
    "dump-renamed-relocate": (["-show", "all", "-relocate"], ["renamed.o"]),
    "dump-renamed-headers": (["-show", "only,headers"], ["renamed.o"]),
    "dump-dynamic": (["-show", "all"], ["dynamic.o"]),
}
# (the processor a source is compiled for, when not the Gekko)
DUMP_PROCESSORS = {"dcr.c": "403"}


def archive(members):
    """A Unix archive of [(name, bytes)], with a long names member for the names of more than 15 characters."""
    long_names = b"".join(n.encode() + b"/\n" for n, _ in members if len(n) > 15)
    data = b"!<arch>\n"
    entries = ([("//", long_names)] if long_names else []) + members
    for name, contents in entries:
        if name == "//" or len(name) <= 15:
            field = name if name == "//" else name + "/"
        else:
            field = f"/{long_names.index(name.encode() + b'/')}"
        data += f"{field:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(contents):<10}`\n".encode() + contents
        if len(contents) & 1:
            data += b"\n"
    return data


def make_dump_inputs(linker_dir, out, inputs):
    """Makes the dump inputs that are not compiled: archives and changed objects."""
    types = (out / "types.o").read_bytes()
    if "lib.a" in inputs:
        (out / "a_rather_long_object_name.o").write_bytes((out / "classes.o").read_bytes())
        code, log = lo.run(linker_dir / "mwldeppc.exe", "-library", "-o", out / "lib.a", out / "types.o",
                           out / "a_rather_long_object_name.o")
        if code:
            return [f"the original fails to make the archive:\n{log}"]
    if "odd.a" in inputs:
        (out / "odd.a").write_bytes(archive([("types.o", types), ("empty.o", b""), ("notes.txt", b"not an object\n"),
                                             ("another_long_member_name.o", types)]))
    changes = {"little.o": (5, b"\x01"), "machine.o": (0x12, b"\x00\x03"), "version.o": (0x14, b"\x00\x00\x00\x02")}
    for file, (at, value) in changes.items():
        if file in inputs:
            (out / file).write_bytes(types[:at] + value + types[at + len(value):])
    if "text.o" in inputs:
        (out / "text.o").write_text("this is not an object file\n")
    if "renamed.o" in inputs:
        (out / "renamed.o").write_bytes(types.replace(b".comment\0", b".c0mment\0")
                                        .replace(b".mwcats.text\0", b".debug_mwcat\0"))
    if "dynamic.o" in inputs:
        (out / "dynamic.o").write_bytes(types.replace(b".comment\0", b".dynamic\0"))
    return []


def dump_scenario(name, linker_dir, rebuilt, out_root, runtime):
    out = out_root / name
    out.mkdir(parents=True, exist_ok=True)
    for file, text in {**DUMP_SOURCES, "stub.c": lo.STUB}.items():
        (out / file).write_text(text)
        flags = ["-Cpp_exceptions", "on" if file == "throws.cpp" else "off"] if file.endswith(".cpp") else []
        code, log = lo.run(linker_dir / "mwcceppc.exe", "-c", "-g", "-proc", DUMP_PROCESSORS.get(file, "gekko"),
                           *flags, out / file,
                           "-o", out / (file.rsplit(".", 1)[0] + ".o"))
        if code:
            return [f"compile of {file} failed:\n{log}"]
    options, inputs = DUMPS[name]
    made = make_dump_inputs(linker_dir, out, inputs)
    if made:
        return made
    for linked, rom in (("linked.elf", []), ("rom.elf", ["-romaddr", "0x80400000", "-rambuffer", "0x80500000"])):
        if linked not in inputs:
            continue
        (out / "ldscript.lcf").write_text(DOLPHIN)
        code, log = lo.run(linker_dir / "mwldeppc.exe", "-nodefaults", "-fp", "hardware", "-g", *rom, "-lcf",
                           out / "ldscript.lcf", "-m", "_start", "-o", out / linked, out / "program.o",
                           out / "stub.o", runtime / "global_destructor_chain.o", runtime / "__init_cpp_exceptions.o")
        if code:
            return [f"the original fails to link the program:\n{log}"]
    results, files = {}, {}
    for who, linker in (("oracle", linker_dir / "mwldeppc.exe"), ("mine", rebuilt)):
        written = out / f"{who}-dump.txt"
        written.unlink(missing_ok=True)
        code, log = lo.run(linker, "-dis", *[o.format(out=written) for o in options], *[out / i for i in inputs])
        results[who] = (code, messages(log, linker).replace(str(written), "OUT"))
        (out / f"{who}.txt").write_text(log)
        files[who] = written.read_bytes() if written.exists() else None
    problems = []
    if files["oracle"] != files["mine"]:
        problems.append(f"the dump files differ ({out / 'oracle-dump.txt'} and {out / 'mine-dump.txt'})")
    if "-o" in options and files["oracle"] is None:
        problems.append("the original wrote no dump file")
    if results["oracle"][0] != results["mine"][0]:
        problems.append(f"exit status {results['oracle'][0]} against {results['mine'][0]}")
    if results["oracle"][1] != results["mine"][1]:
        problems.append(f"the dumps differ ({out / 'oracle.txt'} and {out / 'mine.txt'})")
    return problems


# (the disassembler's sweeps: objects whose code is instruction words made to cover the decoding (every primary opcode,
# every extended opcode of 19, 31, 59 and 63 and the others' forms, the conditional branches' BO and BI, every special,
# time base and device control register, the traps' TO, rA 0 and rS equal to rB, a fixed batch of random words) and the
# rotates' whole SH, MB and ME space (the extended mnemonics), dumped with -dis for one processor of each of the
# disassembler's processor masks, with and without extended mnemonics, and a little-endian object (-little))
SWEEP_PROCESSORS = ["401", "403", "505", "601", "602", "603e", "604", "750", "801", "823", "850", "7400", "7450",
                    "8240", "8260", "e500", "gekko", "generic"]


def sweep_words(kind):
    """The words of the sweep object KIND ("base" or "rotate"), the same every run."""
    import random
    rnd = random.Random(26)
    words = []

    def r(bits):
        return rnd.getrandbits(bits)
    if kind == "rotate":
        for primary in (20, 21):
            for sh in range(32):
                for mb in range(32):
                    for me in range(32):
                        words.append(primary << 26 | r(10) << 16 | sh << 11 | mb << 6 | me << 1 | r(1))
        for mb in range(32):
            for me in range(32):
                words.append(23 << 26 | r(15) << 11 | mb << 6 | me << 1 | r(1))
        return words
    for primary in range(64):
        words += [primary << 26 | r(26) for _ in range(32)]
    for primary in (19, 31, 59, 63):
        for xo in range(1024):
            for rc in (0, 1):
                words.append(primary << 26 | r(15) << 11 | xo << 1 | rc)
            if primary == 31:
                rs = r(5)
                words.append(31 << 26 | rs << 21 | 0 << 16 | rs << 11 | xo << 1)
                words.append(31 << 26 | rs << 21 | r(5) << 16 | rs << 11 | xo << 1 | 1)
    for low in range(2048):
        words.append(4 << 26 | r(15) << 11 | low)
    for primary, bits in ((30, 5), (58, 2), (62, 2)):
        for low in range(1 << bits):
            words += [primary << 26 | r(26 - bits) << bits | low for _ in range(8)]
    for bo in range(32):
        for bi in range(32):
            for aa_lk in range(4):
                words.append(16 << 26 | bo << 21 | bi << 16 | r(14) << 2 | aa_lk)
            for xo in (16, 528):
                for lk in (0, 1):
                    words.append(19 << 26 | bo << 21 | bi << 16 | r(5) << 11 | xo << 1 | lk)
    for number in range(1024):
        field = (number & 31) << 5 | number >> 5
        for xo in (339, 467, 371, 323, 451):
            words.append(31 << 26 | r(5) << 21 | field << 11 | xo << 1)
    for to in range(32):
        for _ in range(4):
            words.append(31 << 26 | to << 21 | r(10) << 11 | 4 << 1)
            words.append(3 << 26 | to << 21 | r(21))
    for primary in (14, 15, 24, 25, 26, 27, 28, 29, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54):
        words += [primary << 26 | r(5) << 21 | 0 << 16 | r(16) for _ in range(8)]
    words += [0x60000000, 0x7c0802a6, 0x7c0803a6, 0x4e800020, 0x4e800021, 0x4e800420, 0x00000000, 0xffffffff]
    words += [r(32) for _ in range(8192)]
    return words


SWEEPS = {f"sweep-{proc}{suffix}": ("base", ["-proc", proc, "-show", "only,code" + suffix.replace("-", ",")])
          for proc in SWEEP_PROCESSORS for suffix in ("", "-extended")}
SWEEPS.update({
    "sweep-rotate": ("rotate", ["-proc", "gekko", "-show", "only,code"]),
    "sweep-rotate-extended": ("rotate", ["-proc", "gekko", "-show", "only,code,extended"]),
    "sweep-little": ("little", ["-little", "-proc", "gekko", "-show", "only,code"]),
    "sweep-little-extended": ("little", ["-little", "-proc", "gekko", "-show", "only,code,extended"]),
})


# The driver's command line alone (no inputs): -help and its keywords (Help.c's columns), -version, bad options.
DRIVER = {
    "driver-help": ["-help"],
    "driver-help-usage": ["-help", "usage"],
    "driver-help-all": ["-help", "all"],
    "driver-help-all-spaces": ["-help", "all,spaces"],
    "driver-help-obsolete": ["-help", "obsolete"],
    "driver-help-ignored": ["-help", "ignored"],
    "driver-help-deprecated": ["-help", "deprecated"],
    "driver-help-meaningless": ["-help", "meaningless"],
    "driver-help-compatible": ["-help", "compatible"],
    "driver-help-nonormal": ["-help", "nonormal,obsolete,ignored"],
    "driver-help-option": ["-help", "opt=map"],
    "driver-help-option-short": ["-help", "option=g"],
    "driver-help-option-unknown": ["-help", "opt=nosuchoption"],
    "driver-help-option-long": ["-help", "opt=" + "x" * 70],
    "driver-help-search": ["-help", "search=section"],
    "driver-help-search-none": ["-help", "search=zzzz"],
    "driver-help-group": ["-help", "group=Linker"],
    "driver-help-group-empty": ["-help", "group="],
    "driver-help-bogus": ["-help", "bogus"],
    "driver-version": ["-version"],
    "driver-unknown-option": ["-nosuchoption"],
    "driver-missing-argument": ["-o"],
    "driver-no-inputs": [],
    "driver-missing-file": ["nosuchfile.o"],
    "driver-missing-library": ["-lnosuch"],
    "driver-missing-response-file": ["@nosuchfile.txt"],
    # (-w: the linker's own warnings, TargetWarningHelpers-ppc-ld.c's)
    "driver-warnings-display": ["-w", "display"],
    "driver-warnings-off": ["-w", "off,display"],
    "driver-warnings-off-on": ["-w", "off", "-w", "on,display"],
    "driver-warnings-error": ["-w", "error,nocmdline,display"],
    "driver-warnings-bad": ["-w", "bogus"],
    # (an empty first entry in an option's list: Option.c's parse, the match flags of no option yet)
    "driver-list-empty-first": ["-w", ",display"],
    "driver-help-empty-first": ["-help", ",usage"],
    "driver-show-empty-first": ["-show", ",only"],
    # (2.x's messages in gcc's style (a short one: gcc's lines start with the linker's path, whose length the
    # wrapping counts, and the two linkers' paths differ), and -plugindebug's list of the plugins and their versions)
    "driver-msgstyle-gcc": ["-msgstyle", "gcc", "-nosuchoption"],
    "driver-plugindebug": ["-plugindebug", "-version"],
}


def driver_scenario(name, linker_dir, rebuilt, out_root, runtime):
    """The messages and exit status of the linker run with DRIVER[NAME]'s options."""
    out = out_root / name
    out.mkdir(parents=True, exist_ok=True)
    results = {}
    for who, linker in (("oracle", linker_dir / "mwldeppc.exe"), ("mine", rebuilt)):
        code, log = lo.run(linker, *DRIVER[name])
        log = messages(log, linker)
        (out / f"{who}.txt").write_text(f"exit {code}\n{log}\n")
        results[who] = (code, log)
    if results["oracle"] != results["mine"]:
        return [f"the outputs differ ({out / 'oracle.txt'} and {out / 'mine.txt'})"]
    return []


def sweep_object(linker_dir, out, kind):
    """OUT/KIND.o: an object of asm functions of 4096 words each, compiled with placeholders and patched with the words
    (the little-endian object is the base's words, compiled with -little)."""
    import struct
    words = sweep_words("base" if kind == "little" else kind)
    chunk = 4096
    source = "".join(f"asm void sweep{k}(void) {{\n nofralloc\n" + " opword 0x60000000\n" * chunk + "}\n"
                     for k in range((len(words) + chunk - 1) // chunk))
    (out / f"{kind}.c").write_text(source)
    code, log = lo.run(linker_dir / "mwcceppc.exe", "-c", "-proc", "gekko", *(["-little"] if kind == "little" else []),
                       out / f"{kind}.c", "-o", out / f"{kind}.o")
    if code:
        return [f"compile of {kind}.c failed:\n{log}"]
    data = bytearray((out / f"{kind}.o").read_bytes())
    order = "<" if data[5] == 1 else ">"
    shoff = struct.unpack_from(order + "I", data, 0x20)[0]
    count, names = struct.unpack_from(order + "HH", data, 0x30)
    headers = [struct.unpack_from(order + "10I", data, shoff + 40 * i) for i in range(count)]
    for header in headers:
        at = headers[names][4] + header[0]
        if data[at:data.index(b"\0", at)] == b".text":
            for i in range(min(len(words), header[5] // 4)):
                struct.pack_into(order + "I", data, header[4] + 4 * i, words[i])
    (out / f"{kind}.o").write_bytes(bytes(data))
    return []


def sweep_scenario(name, linker_dir, rebuilt, out_root, runtime):
    out = out_root / name
    out.mkdir(parents=True, exist_ok=True)
    kind, options = SWEEPS[name]
    made = sweep_object(linker_dir, out, kind)
    if made:
        return made
    results = {}
    for who, linker in (("oracle", linker_dir / "mwldeppc.exe"), ("mine", rebuilt)):
        code, log = lo.run(linker, "-dis", *options, out / f"{kind}.o")
        log = messages(log, linker)   # (a processor the linker does not know: its usage error, with its path)
        (out / f"{who}.txt").write_text(log)
        # (a conditional branch whose BO ignores the condition prints an address as its BI, the original's own: a
        # buffer's, which each executable has elsewhere; no operand is a number that large)
        log = re.sub(r"(?<![\w$])(\d{7})(?!\w)",
                     lambda m: "(an address)" if 0x400000 <= int(m.group(1)) < 0x500000 else m.group(1), log)
        results[who] = (code, log)
    if results["oracle"] != results["mine"]:
        return [f"the dumps differ ({out / 'oracle.txt'} and {out / 'mine.txt'})"]
    return []


def messages(log, linker):
    """A link's messages, without the linker's own path."""
    return re.sub(r"### .*?mwldeppc\.exe ", "### mwldeppc.exe ", log.replace(str(linker), "mwldeppc.exe"))


def lcf_scenario(name, linker_dir, rebuilt, out_root, runtime):
    out = out_root / name
    out.mkdir(parents=True, exist_ok=True)
    sources = {**PROGRAM, "stub.c": lo.STUB}
    objects = []
    for file, text in sources.items():
        (out / file).write_text(text)
        obj = out / (file.rsplit(".", 1)[0] + ".o")
        flags = ["-g"] if name in DEBUG else []
        code, log = lo.run(linker_dir / "mwcceppc.exe", "-c", "-proc", "gekko", *flags, out / file, "-o", obj)
        if code:
            return [f"compile of {file} failed:\n{log}"]
        objects.append(obj)
    if isinstance(SCENARIOS[name], bytes):
        (out / "ldscript.lcf").write_bytes(SCENARIOS[name])
    else:
        (out / "ldscript.lcf").write_text(SCENARIOS[name])
    if name in WILDCARD:
        renames, patterns = WILDCARD[name]
        for old, new in renames.items():
            (out / new).unlink(missing_ok=True)
            (out / old).rename(out / new)
        objects = [out / pattern for pattern in patterns]
    inputs = [*objects, runtime / "global_destructor_chain.o", runtime / "__init_cpp_exceptions.o"]
    options = SREC[name][1] if name in SREC else DEBUG.get(name, LINKSYM_OPTIONS.get(name, []))
    results, srecords = {}, {}
    for who, linker in (("oracle", linker_dir / "mwldeppc.exe"), ("mine", rebuilt)):
        # (each linker's S-record file, wherever the options put it: the files of the run before are moved aside)
        for old in out.glob("*.mot"):
            old.unlink()
        (out / "named.s").unlink(missing_ok=True)
        code, log = lo.run(linker, "-nodefaults", "-fp", "hardware", "-lcf", out / "ldscript.lcf", "-m", "_start",
                           "-map", out / f"{who}.map", *[o.format(out=out) for o in options],
                           "-o", out / f"{who}.elf", *inputs)
        results[who] = (code, messages(log, linker).replace(f"{who}.", "OUT."))
        made = sorted([*out.glob("*.mot"), *out.glob("named.s")])
        srecords[who] = [(p.name.replace(who, "OUT"), p.read_bytes()) for p in made]
        for p in made:
            p.rename(out / f"{who}-{p.name}.srec")
    problems = []
    if results["oracle"][0] != results["mine"][0]:
        problems.append(f"exit status {results['oracle'][0]} against {results['mine'][0]}")
    if results["oracle"][1] != results["mine"][1]:
        problems.append(f"the messages differ:\n--- original\n{results['oracle'][1]}\n--- rebuilt\n{results['mine'][1]}")
    if results["oracle"][0] == 0 and results["mine"][0] == 0:
        problems += lo.compare(out / "oracle.elf", out / "mine.elf", out / "oracle.map", out / "mine.map")
    if srecords["oracle"] != srecords["mine"]:
        problems.append("the S-record files differ: "
                        + ", ".join(f"{who} {[(n, len(d)) for n, d in files]}" for who, files in srecords.items()))
    if name in SREC and results["oracle"][0] == 0 and not srecords["oracle"]:
        problems.append("the original made no S-record file")
    return problems


# (links without a command file: the addresses and sizes the plugin's glue copies from the linker's panel, each alone
# and together (the stack address rounded up to 8), a ROM image, the unused symbols in the map, and the map and the
# S-record file named after the output)
ADDRESSES = {
    "addr-default": [],
    "addr-code": ["-codeaddr", "0x80003100"],
    "addr-data": ["-codeaddr", "0x80003100", "-dataaddr", "0x80100000"],
    "addr-sdata": ["-sdataaddr", "0x80200000"],
    "addr-sdata2": ["-sdata2addr", "0x80300000"],
    "addr-all": ["-codeaddr", "0x80003100", "-dataaddr", "0x80100000", "-sdataaddr", "0x80200000",
                 "-sdata2addr", "0x80300000"],
    "addr-stack-heap": ["-stackaddr", "0x81000000", "-heapaddr", "0x80800000"],
    "addr-stack-rounded": ["-stackaddr", "0x80f00003"],
    "addr-heap-rounded": ["-heapaddr", "0x80700005"],
    "addr-sizes": ["-stacksize", "32", "-heapsize", "2048"],
    "addr-rom": ["-codeaddr", "0x80003100", "-romaddr", "0x80400000", "-rambuffer", "0x80500000"],
    "addr-mapunused": ["-mapunused"],
    "addr-map-default": ["-map"],
    "addr-srec-default": ["-srec"],
}


def address_scenario(name, linker_dir, rebuilt, out_root, runtime):
    out = out_root / name
    out.mkdir(parents=True, exist_ok=True)
    objects = []
    for file, text in {**PROGRAM, "stub.c": lo.STUB}.items():
        (out / file).write_text(text)
        obj = out / (file.rsplit(".", 1)[0] + ".o")
        code, log = lo.run(linker_dir / "mwcceppc.exe", "-c", "-proc", "gekko", out / file, "-o", obj)
        if code:
            return [f"compile of {file} failed:\n{log}"]
        objects.append(obj)
    inputs = [*objects, runtime / "global_destructor_chain.o", runtime / "__init_cpp_exceptions.o"]
    options = ADDRESSES[name]
    results, side = {}, {}
    for who, linker in (("oracle", linker_dir / "mwldeppc.exe"), ("mine", rebuilt)):
        for old in [*out.glob("*.MAP"), *out.glob("*.mot")]:
            old.unlink()
        # (an explicit map named apart from the .MAP the linker names after the output: names are case-blind here)
        map_options = [] if "-map" in options else ["-map", out / f"{who}-link.txt"]
        code, log = lo.run(linker, "-nodefaults", "-fp", "hardware", "-m", "_start", *map_options, *options,
                           "-o", out / f"{who}.elf", *inputs)
        results[who] = (code, messages(log, linker).replace(f"{who}.", "OUT."))
        made = sorted([*out.glob("*.MAP"), *out.glob("*.mot")])
        side[who] = [(p.name.replace(who, "OUT"), p.read_bytes()) for p in made]
        for p in made:
            p.rename(out / f"{who}-{p.name}.side")
    problems = []
    if results["oracle"][0] != results["mine"][0]:
        problems.append(f"exit status {results['oracle'][0]} against {results['mine'][0]}")
    if results["oracle"][1] != results["mine"][1]:
        problems.append(f"the messages differ:\n--- original\n{results['oracle'][1]}\n--- rebuilt\n{results['mine'][1]}")
    if results["oracle"][0] == 0 and results["mine"][0] == 0:
        if "-map" in options:
            problems += lo.compare(out / "oracle.elf", out / "mine.elf", out / "oracle.elf", out / "mine.elf")
        else:
            problems += lo.compare(out / "oracle.elf", out / "mine.elf", out / "oracle-link.txt", out / "mine-link.txt")
    if side["oracle"] != side["mine"]:
        problems.append("the map or S-record files differ: "
                        + ", ".join(f"{who} {[(n, len(d)) for n, d in files]}" for who, files in side.items()))
    if ("-map" in options or "-srec" in options) and results["oracle"][0] == 0 and not side["oracle"]:
        problems.append("the original made no map or S-record file")
    return problems


# (debug information of dead-stripped code, which the linker removes from .debug and .line: dead functions before,
# between and after kept ones, a file of dead code only, static functions and data, C++ classes and inline functions,
# optimized code, and a partial link (-r), which keeps it all; compiled with -g, linked with the options given)
STRIPPED = {
    "strip-functions": ({"a.c": "int g = 5;\nint dead1(int x) { return x * 3; }\nint f(int x) { return x + g; }\n"
                                "int dead2(int x) { int i, s = 0; for (i = 0; i < x; i++) s += i; return s; }\n"
                                "int f2(int x) { return f(x) * 2; }\nint dead3(void) { return 7; }\n"
                                "void _start(void) { f2(1); }\n"}, [], ["-g"]),
    "strip-files": ({"a.c": "extern int fb(int);\nint fa(int x) { return fb(x) + 1; }\nvoid _start(void) { fa(1); }\n",
                     "b.c": "int bdata = 3;\nint fb(int x) { return x + bdata; }\nint bdead(int x) { return x - 1; }\n",
                     "c.c": "struct P { int x, y; };\nstruct P cp;\nint cdead(struct P *p) { return p->x + p->y; }\n"
                            "int cdead2(int x) { return x * x; }\n"}, [], ["-g"]),
    "strip-statics": ({"a.c": "static int counter;\nstatic int bump(int x) { counter += x; return counter; }\n"
                              "static int unused_static(int x) { return x << 2; }\n"
                              "int f(int x) { static int calls; calls++; return bump(x) + calls; }\n"
                              "int dead(int x) { static int inside = 4; return inside + unused_static(x); }\n"
                              "void _start(void) { f(1); }\n"}, [], ["-g"]),
    "strip-cpp": ({"a.cpp": "struct Shape { int w, h; Shape(int a, int b) : w(a), h(b) {} int area() const { return w * h; }\n"
                            "  int perimeter() const { return 2 * (w + h); } };\n"
                            "inline int twice(int x) { return x * 2; }\nint used(int x) { Shape s(x, 3); return s.area(); }\n"
                            "int unused(int x) { Shape s(x, x); return s.perimeter() + twice(x); }\n"
                            'extern "C" void _start(void) { used(2); }\n'}, ["-inline", "off"], ["-g"]),
    "strip-optimized": ({"a.c": "int tab[8];\nint dead(int x) { return tab[x & 7] * 9; }\n"
                                "int sum(int n) { int i, s = 0; for (i = 0; i < n; i++) s += tab[i & 7]; return s; }\n"
                                "int dead2(int x) { return sum(x) + x; }\nvoid _start(void) { sum(4); }\n"},
                        ["-O4,p"], ["-g"]),
    "strip-no-g": ({"a.c": "int dead(int x) { return x * 3; }\nint f(int x) { return x + 1; }\n"
                           "void _start(void) { f(1); }\n",
                    "b.c": "int bdead(int x) { return x - 1; }\n"}, [], []),
    "strip-partial": ({"a.c": "int dead(int x) { return x * 3; }\nint f(int x) { return x + 1; }\n",
                       "b.c": "int bdead(int x) { return x - 1; }\nint fb(int x) { return f(x) + 2; }\n"},
                      [], ["-r", "-g"]),
    "strip-weak": ({"a.cpp": "inline int w(int x) { return x * 3 + 1; }\nint dead(int x) { return w(x) - 2; }\n"
                             "int fa(int x) { return w(x) + 5; }\nextern int fb(int);\n"
                             'extern "C" void _start(void) { fa(1); fb(2); }\n',
                    "b.cpp": "inline int w(int x) { return x * 3 + 1; }\nint bdead(int x) { return x - 1; }\n"
                             "int fb(int x) { return w(x) * 2; }\ninline int v(int x) { return x + 9; }\n"
                             "int bdead2(int x) { return v(x); }\n"}, ["-inline", "off"], ["-g"]),
    "strip-prelinked": ({"a.c": "int adead(int x) { return x * 7; }\nint adead2(int x) { return adead(x) + 1; }\n",
                         "b.c": "int bdead(int x) { return x - 1; }\nint fb(int x) { return x + 2; }\n"
                                "int bdead2(int x) { return x << 3; }\n",
                         "c.c": "int cdata = 4;\nint fc(int x) { return x * cdata; }\nint cdead(int x) { return -x; }\n",
                         "e.c": "int edata = 6;\nint fe(int x) { return x + edata; }\nint fe2(int x) { return fe(x) * 3; }\n",
                         "d.c": "extern int fb(int); extern int fc(int); extern int fe2(int);\n"
                                "void _start(void) { fb(1); fc(2); fe2(3); }\n"},
                        [], ["-g"]),
}
STRIPPED["strip-overwrite"] = STRIPPED["strip-functions"]
# (the scenarios whose ELF file and map are there before the link, longer than the linker's)
OVERWRITTEN = {"strip-overwrite"}
# (the sources linked with -r into one object before the link: a file of dead code, two with some, one all kept)
PRELINKED = {"strip-prelinked": ["a.c", "b.c", "e.c", "c.c"], "strip30-prelinked": ["a.c", "b.c", "e.c", "c.c"]}
# (the 3.0 compilers give each .debug entry a symbol, ".dwarf.<tag>.<name>", and each function's lines one,
# ".line.<name>": the linker then removes the dropped code's entries and lines piece by piece, and the compile units and
# line tables left empty; the same programs, compiled by 3.0a5.2)
STRIPPED_COMPILER = "3.0a5.2"
STRIPPED.update({name.replace("strip-", "strip30-"): value for name, value in STRIPPED.items()})


def stripped_scenario(name, linker_dir, rebuilt, out_root, runtime):
    sources, flags, options = STRIPPED[name]
    out = out_root / name
    out.mkdir(parents=True, exist_ok=True)
    partial = "-r" in options
    sources = sources if partial else {**sources, "stub.c": lo.STUB}
    objects = []
    for file, text in sources.items():
        (out / file).write_text(text)
        obj = out / (file.rsplit(".", 1)[0] + ".o")
        compiler = linker_dir.parent / STRIPPED_COMPILER if name.startswith("strip30-") else linker_dir
        code, log = lo.run(compiler / "mwcceppc.exe", "-c", "-g", "-proc", "gekko", *flags, out / file, "-o", obj)
        if code:
            return [f"compile of {file} failed:\n{log}"]
        objects.append(obj)
    if name in PRELINKED:
        # (an object of several compile units: some of the objects linked with -r first, by the original)
        members = [out / (file.rsplit(".", 1)[0] + ".o") for file in PRELINKED[name]]
        code, log = lo.run(linker_dir / "mwldeppc.exe", "-nodefaults", "-fp", "hardware", "-r", "-g",
                           "-o", out / "prelinked.o", *members)
        if code:
            return [f"the partial link failed:\n{log}"]
        objects = [out / "prelinked.o", *[o for o in objects if o not in members]]
    if partial:
        common = ["-nodefaults", "-fp", "hardware", *options]
    else:
        objects += [runtime / "global_destructor_chain.o", runtime / "__init_cpp_exceptions.o"]
        common = ["-nostdlib", "-m", "_start", *options]
    results = {}
    for who, linker in (("oracle", linker_dir / "mwldeppc.exe"), ("mine", rebuilt)):
        if name in OVERWRITTEN:
            # (the outputs are there already, and longer: the linker makes them empty first)
            for old in (out / f"{who}.elf", out / f"{who}.map"):
                old.write_bytes(b"old output " * 20000)
        code, log = lo.run(linker, *common, "-map", out / f"{who}.map", "-o", out / f"{who}.elf", *objects)
        results[who] = (code, messages(log, linker).replace(f"{who}.", "OUT."))
    problems = []
    if results["oracle"] != results["mine"]:
        problems.append(f"the links differ: {results['oracle']} against {results['mine']}")
    if results["oracle"][0] == 0 and results["mine"][0] == 0:
        problems += lo.compare(out / "oracle.elf", out / "mine.elf", out / "oracle.map", out / "mine.map")
    return problems


# (the loading of the objects and what the command file says of them: a function two objects define, common symbols
# (merged, and against a definition), an object that defines a linker-defined symbol, a missing entry point, FORCEFILES
# keeping an object's dead code, the command file's files no object is, a member pattern for a file that is not an
# archive, EXCLUDEFILES and INCLUDEDWARF of files that are not there, a linked program given to EXCLUDEFILES (its
# symbols another object has weak are dropped), C++ constructors and destructors, and code that refers to a
# linker-defined symbol whose value names a function; each is (sources, compiler flags, command file, link options),
# and a "pre.c" source is linked first into pre.elf, which the link gets too)
LINK_MAIN = "int g = 1;\nint f(int x) { return x + g; }\nvoid _start(void) { f(1); }\n"
# (the Dolphin command file without its FORCEACTIVE: with fewer sections than it has, the 2.6 linker crashes on
# some programs)
LINK_LCF = DOLPHIN[:DOLPHIN.index("FORCEACTIVE")].rstrip() + "\n"
LINKS = {
    "link-duplicate": ({"a.c": "int dup(int x) { return x + 1; }\nvoid _start(void) { dup(1); }\n",
                        "b.c": "int dup(int x) { return x - 1; }\nint bonly(int x) { return dup(x); }\n"},
                       [], LINK_LCF + "FORCEACTIVE { bonly }\n", []),
    "link-common": ({"a.c": "int c1; double c2; char c3; int c4[4];\n"
                            "void _start(void) { c1 = 1; c2 = 2.0; c3 = 3; c4[1] = 4; }\n",
                     "b.c": "int c1; int c4[8]; char c5;\nint fb(void) { return c1 + c4[7] + c5; }\n",
                     "c.c": "char c3 = 9;\nint fc(void) { return c3; }\n"},
                    ["-common", "on"], LINK_LCF + "FORCEACTIVE { fb fc }\n", []),
    "link-common-larger": ({"a.c": "int big[2] = {1};\nvoid _start(void) { big[0] = 1; }\n",
                            "b.c": "int big[8];\nint fb(void) { return big[7]; }\n"},
                           ["-common", "on"], LINK_LCF + "FORCEACTIVE { fb }\n", []),
    "link-predefined": ({"a.c": "int _stack_addr = 4;\nint _SDA_BASE_(void) { return 1; }\n"
                                "void _start(void) { _stack_addr = _SDA_BASE_(); }\n"},
                        [], LINK_LCF, []),
    "link-no-entry": ({"a.c": LINK_MAIN}, [], LINK_LCF, ["-m", "no_such_entry"]),
    "link-forcefiles": ({"a.c": "int g = 3;\nint dead(int x) { return x * g; }\nstatic int sdead(int x) { return x - 1; }\n"
                                "int dead2(int x) { return sdead(x); }\nvoid _start(void) { }\n"
                                "char c1 = 1; double d1 = 2.0; short s1 = 3; char c2 = 4; long long l1 = 5;\n"
                                "char ctab[3] = {1, 2, 3}; double dtab[2] = {1.0, 2.0};\n",
                         "b.c": "int bdead(int x) { return x + 2; }\n"},
                        [], LINK_LCF + "FORCEFILES { a.o }\n", []),
    "link-missing-files": ({"a.c": LINK_MAIN}, [],
                           LINK_LCF.replace(".text ALIGN(0x4):{}", ".text ALIGN(0x4):{ a.o (.text) gone.o (.text) }")
                           + "FORCEFILES { nothere.o lib.a(member.o) }\n", []),
    "link-forcefiles-member":({"a.c": LINK_MAIN}, [], LINK_LCF + "FORCEFILES { a.o(x.o) }\n", []),
    "link-exclude-missing": ({"a.c": LINK_MAIN}, [], LINK_LCF + "EXCLUDEFILES { nothere.o }\n", []),
    "link-includedwarf-missing": ({"a.c": LINK_MAIN}, ["-g"], LINK_LCF + "INCLUDEDWARF { nothere.o }\n",
                                  ["-g"]),
    "link-excluded": ({"pre.cpp": "int pdata = 3;\ninline int w(int x) { return x * 3 + pdata; }\n"
                                  "int pw(int x) { return w(x); }\n"
                                  'extern "C" void _start(void) { pw(1); }\n',
                       "a.cpp": "inline int w(int x) { return x * 3 + 1; }\nint fa(int x) { return w(x) + 2; }\n"
                                'extern "C" void _start(void) { fa(1); }\n'},
                      ["-inline", "off", "-Cpp_exceptions", "off"], LINK_LCF + "EXCLUDEFILES { pre.elf }\n", ["-r1"]),
    "link-ctors": ({"a.cpp": "struct A { int x; A(); ~A(); };\nA::A() { x = 1; }\nA::~A() { x = 0; }\nA ga;\n"
                             "static A sa;\nint dead(void) { static A la; return la.x; }\n"
                             'extern "C" void _start(void) { ga.x++; }\n',
                    "b.cpp": "struct B { int y; B() : y(2) {} };\nB gb;\n"},
                   ["-Cpp_exceptions", "off"], LINK_LCF, []),
    "link-linksym-ref": ({"a.c": "int unused(int x) { return x * 5; }\nextern char alias[];\n"
                                 "char *p(void) { return alias; }\nvoid _start(void) { p(); }\n"},
                         [], LINK_LCF[:-2] + "    alias = unused + 4;\n}\n", []),
    # (the predefined linker-defined symbols, used: absolute values, or the tables' sections)
    "link-predefined-ref": ({"a.c": "extern char _stack_addr[], _stack_end[], _heap_addr[], _heap_end[], _nbfunctions[];\n"
                                    "extern char _SDA_BASE_[], _SDA2_BASE_[], _rom_copy_info[], _bss_init_info[];\n"
                                    "char *t[9];\nvoid _start(void) { t[0] = _stack_addr; t[1] = _stack_end; "
                                    "t[2] = _heap_addr; t[3] = _heap_end; t[4] = _nbfunctions; t[5] = _SDA_BASE_; "
                                    "t[6] = _SDA2_BASE_; t[7] = _rom_copy_info; t[8] = _bss_init_info; }\n"},
                            [], LINK_LCF, []),
    # (INCLUDEDWARF of a linked program that is there (it takes only those): its debugging sections are taken
    # from it)
    "link-includedwarf": ({"pre.c": "int pdata = 2;\nint pf(int x) { return x + pdata; }\nvoid _start(void) { pf(1); }\n",
                           "a.c": "int fa(int x) { return x * 2; }\nvoid _start(void) { fa(1); }\n"},
                          ["-g"], LINK_LCF + "INCLUDEDWARF { pre.elf }\n", ["-g"]),
    # (small data beyond the 64K that the small data base reaches: an error; the compiler's -sdata is at most
    # 32767, above which it puts nothing in small data)
    "link-sdata-far": ({"a.c": "int far1[8000] = {1}; int far3[8000] = {3}; int far2[8000];\nint near1 = 2;\n"
                               "void _start(void) { far1[1] = far2[1] + far3[1] + near1; }\n"},
                       ["-sdata", "32767"], LINK_LCF, []),
    # (.sbss placed before .sdata, which the small data base is measured from: an error)
    "link-sbss-first": ({"a.c": "int near1 = 2; int near2;\nvoid _start(void) { near2 = near1; }\n"}, [],
                        LINK_LCF.replace("        .sdata ALIGN(0x20):{}\n        .sbss ALIGN(0x20):{}\n",
                                         "        .sbss ALIGN(0x20):{}\n        .sdata ALIGN(0x20):{}\n"), []),
}


def into(output, items):
    """LINK_LCF with ITEMS as the contents of its output section OUTPUT."""
    return re.sub(r"(        " + re.escape(output) + r" ALIGN\(0x[0-9a-f]+\)):\{\}", r"\1:{ " + items + " }", LINK_LCF)


# (the relocations of asm code: ADDR16_HI, ADDR16_LO, ADDR16_HA, ADDR16, REL14 and ADDR24 (ba, bla); linked low, where
# they all reach, and at 0x80003100, where ADDR16 and ADDR24 are out of range)
RELOCS = ("int target2[4] = {1, 2, 3, 4};\nvoid far_fn(void) { }\n"
          "asm void relocs(void) {\n nofralloc\n lis r3, target2@h\n addi r3, r3, target2@l\n lis r3, target2@ha\n"
          " lwz r3, target2(r0)\n bc 12, 0, far_fn\n ba far_fn\n bla far_fn\n blr\n}\n"
          "void _start(void) { relocs(); }\n")
KINDS = "int z[10] = {1}; int zb[10]; const int zc[4] = {1, 2, 3, 4};\nvoid _start(void) { z[1] = zb[1] + zc[1]; }\n"
USER_DATA = ('#pragma section RW ".mydata" ".mybss"\n__declspec(section ".mydata") int zu[8] = {1};\n'
             "void _start(void) { zu[1] = 2; }\n")
USER_CODE = ('#pragma section code_type ".mytext"\n__declspec(section ".mytext") int fu(int x) { return x; }\n'
             "void _start(void) { fu(1); }\n")
LINKS.update({
    "link-relocs": ({"a.c": RELOCS}, [], LINK_LCF.replace("origin = 0x80003100", "origin = 0x00003100"), []),
    "link-relocs-range": ({"a.c": RELOCS}, [], LINK_LCF, []),
    # (a small data reference to data that is not small: an error)
    "link-sda-violation": ({"a.c": "extern int big;\nvoid _start(void) { big = 1; }\n", "b.c": "int big[100] = {1};\n"},
                           [], LINK_LCF + "FORCEACTIVE { big }\n", []),
    # (a section bound below its memory area's origin, and beyond its length)
    "link-bind-below": ({"a.c": KINDS}, [], LINK_LCF.replace(".data ALIGN(0x20)", ".data BIND(0x80000000) ALIGN(0x20)"),
                        []),
    "link-bind-beyond": ({"a.c": KINDS}, [], LINK_LCF.replace("origin = 0x80003100", "origin = 0x80003100, length = 0x1000")
                         .replace(".data ALIGN(0x20)", ".data BIND(0x80100000) ALIGN(0x20)"), []),
    # (objects of different EABI compliance (the pragmas that break it): warnings, the first file the least
    # compliant, then a compliant one)
    "link-compliance": ({"a.c": "#pragma incompatible_return_small_structs on\n" + KINDS,
                         "b.c": "#pragma incompatible_sfpe_double_params on\nint fb(int x) { return x; }\n",
                         "c.c": "int fc(int x) { return x; }\n"}, [], LINK_LCF + "FORCEACTIVE { fb fc }\n", []),
    "link-compliance-later": ({"a.c": KINDS,
                               "b.c": "#pragma incompatible_sfpe_double_params on\nint fb(int x) { return x; }\n",
                               "c.c": "#pragma incompatible_return_small_structs on\nint fc(int x) { return x; }\n"},
                              [], LINK_LCF + "FORCEACTIVE { fb fc }\n", []),
    # (the command file's contents: a member of a file that is no archive, sections of other kinds mixed (BSS with
    # others, small data with others, code in small BSS), sections that can't be named, and kinds that can be mixed)
    "link-member-not-archive": ({"a.c": KINDS}, [], into(".text", "a.o(x.o) (.text)"), []),
    "link-bss-in-text": ({"a.c": KINDS}, [], into(".text", "*(.text) *(.bss)"), []),
    "link-bss-in-data": ({"a.c": KINDS}, [], into(".data", "*(.data) *(.bss)"), []),
    "link-data-in-sdata": ({"a.c": KINDS}, [], into(".sdata", "*(.data)"), []),
    "link-bss-in-sbss": ({"a.c": KINDS}, [], into(".sbss", "*(.bss)"), []),
    "link-text-in-sbss": ({"a.c": KINDS}, [], into(".sbss", "*(.text)"), []),
    "link-sdata-in-data": ({"a.c": KINDS}, [], into(".data", "*(.data) *(.sdata)"), []),
    "link-ctors-in-data": ({"a.c": KINDS}, [], into(".data", "*(.data) *(.ctors)"), []),
    "link-mixed-kinds": ({"a.c": KINDS}, [], into(".data", "*(.data) *(.text) *(.rodata)")
                         .replace(".rodata ALIGN(0x20):{}", ".rodata ALIGN(0x20):{ *(.rodata) *(.init) }")
                         .replace(".bss ALIGN(0x20):{}", ".bss ALIGN(0x20):{ *(.bss) *(.data) }"), []),
    "link-file-items": ({"a.c": KINDS}, [], into(".text", "a.o (.data) stub.o (.text)"), []),
    # (output sections missing: .text and .bss are made, a small data section is an error)
    "link-no-text-output": ({"a.c": KINDS}, [], LINK_LCF.replace("        .text ALIGN(0x4):{}\n", ""), []),
    "link-no-bss-output": ({"a.c": KINDS}, [], LINK_LCF.replace("        .bss ALIGN(0x20):{}\n", ""), []),
    "link-no-sdata-output": ({"a.c": KINDS + "int zs = 3;\n"}, [], LINK_LCF.replace("        .sdata ALIGN(0x20):{}\n", ""),
                             []),
    # (sections of the program's own: code and data not in the command file, an output section named for them, one
    # of another type, an .abs. section at its own address)
    "link-user-code": ({"a.c": USER_CODE}, [], LINK_LCF, []),
    "link-user-code-named": ({"a.c": USER_CODE}, [],
                             LINK_LCF.replace("        .ctors ALIGN", "        .mytext ALIGN(0x4):{}\n        .ctors ALIGN"), []),
    "link-user-data": ({"a.c": USER_DATA}, [], LINK_LCF, []),
    "link-user-data-text": ({"a.c": USER_DATA}, ["-sdata", "0"],
                            LINK_LCF.replace("        .ctors ALIGN", "        .mydata (TEXT) ALIGN(0x4):{}\n        .ctors ALIGN"),
                            []),
    "link-user-data-bss": ({"a.c": USER_DATA}, ["-sdata", "0"],
                           LINK_LCF.replace("        .ctors ALIGN", "        .mydata (BSS) ALIGN(0x4):{}\n        .ctors ALIGN"),
                           []),
    "link-user-data-in-sdata": ({"a.c": USER_DATA}, [], into(".sdata", "*(.sdata) *(.mydata)"), []),
    "link-user-data-in-sbss": ({"a.c": USER_DATA}, [], into(".sbss", "*(.sbss) *(.mydata)"), []),
    # (__start, the entry the linker looks for first, in a code section of its own: the linker's data goes in its
    # output section)
    "link-start-symbol": ({"a.c": "void _start(void) { }\n",
                           "b.c": '#pragma section code_type ".mytext"\n__declspec(section ".mytext") void __start(void) { }\n'
                                  "int zz[4] = {1};\n"}, [],
                          LINK_LCF.replace("        .ctors ALIGN", "        .mytext ALIGN(0x4):{}\n        .ctors ALIGN")
                          + "FORCEACTIVE { __start }\n", []),
    # (the messages' limits: more than 100 errors (undefined symbols, symbols defined twice, small data references
    # to data that is not small: the buffered first lines) end with "too many link errors"; more than 2000 warnings
    # (code sections the command file does not name) are cut; and a symbol the command file uses that is not there)
    "link-undefined-many": ({"a.c": "".join(f"extern int u{i}(void);\n" for i in range(105))
                                    + "void _start(void) {" + "".join(f" u{i}();" for i in range(105)) + " }\n"},
                            [], LINK_LCF, []),
    "link-duplicate-many": ({"a.c": "".join(f"int d{i}(void) {{ return {i}; }}\n" for i in range(105))
                                    + "void _start(void) { }\n",
                             "b.c": "".join(f"int d{i}(void) {{ return {i} + 1; }}\n" for i in range(105))
                                    + "int bonly(void) { return d0(); }\n"},
                            [], LINK_LCF + "FORCEACTIVE { bonly }\n", []),
    "link-sda-many": ({"a.c": "".join(f"extern int big{i};\n" for i in range(105))
                              + "void _start(void) {" + "".join(f" big{i} = 1;" for i in range(105)) + " }\n",
                       "b.c": "".join(f"int big{i}[100] = {{1}};\n" for i in range(105))}, [], LINK_LCF, []),
    "link-warnings-many": ({"a.c": "".join(f'#pragma section code_type ".u{i}"\n'
                                           f'__declspec(section ".u{i}") int fu{i}(int x) {{ return x + {i}; }}\n'
                                           for i in range(2005))
                                   + "void _start(void) {" + "".join(f" fu{i}(1);" for i in range(2005)) + " }\n"},
                           [], LINK_LCF, []),
    "link-undefined-lcf": ({"a.c": "void _start(void) { }\n"}, [], LINK_LCF[:-2] + "    x = nowhere + 1;\n}\n", []),
    "link-abs-section": ({"a.c": '#pragma section RW ".abs.80600000"\n'
                                 '__declspec(section ".abs.80600000") int za[2] = {1};\nvoid _start(void) { za[1] = 2; }\n'},
                         ["-sdata", "0"], LINK_LCF, []),
})
# (the partial links that use the command file: -r1 (its constructor tables), -r2 (unresolved symbols are errors),
# -strip_partial (dead stripping), the last with FORCEFILES, EXCLUDEFILES of an object (an error: only a linked
# program can be) and INCLUDEDWARF)
PARTIAL_SOURCES = {"a.c": LINK_MAIN + "int adead(int x) { return x * 7; }\nextern int fb(int);\nint fa(int x) { return fb(x); }\n",
                   "b.c": "int bdata = 2;\nint fb(int x) { return x + bdata; }\nint bdead(int x) { return x - 1; }\n"}
LINKS.update({
    "link-r1": (PARTIAL_SOURCES, [], LINK_LCF, ["-r1"]),
    "link-r2": (PARTIAL_SOURCES, [], LINK_LCF, ["-r2"]),
    "link-r2-unresolved": ({"a.c": "extern int nowhere(int);\n" + LINK_MAIN + "int fa(int x) { return nowhere(x); }\n"},
                           [], LINK_LCF, ["-r2"]),
    "link-strip-partial": (PARTIAL_SOURCES, [], LINK_LCF, ["-r1", "-strip_partial"]),
    "link-strip-partial-forced": (PARTIAL_SOURCES, [], LINK_LCF + "FORCEFILES { b.o }\n", ["-r1", "-strip_partial"]),
    "link-partial-exclude-object": (PARTIAL_SOURCES, [], LINK_LCF + "EXCLUDEFILES { b.o }\n", ["-r1"]),
    "link-partial-includedwarf": (PARTIAL_SOURCES, ["-g"], LINK_LCF + "INCLUDEDWARF { b.o }\n",
                                  ["-r1", "-strip_partial", "-g"]),
    "link-partial-exclude-missing": (PARTIAL_SOURCES, [], LINK_LCF + "EXCLUDEFILES { nothere.o }\n", ["-r1"]),
    "link-ctors-r1": (LINKS["link-ctors"][0], ["-Cpp_exceptions", "off"], LINK_LCF, ["-r1"]),
    "link-ctors-strip-partial": (LINKS["link-ctors"][0], ["-Cpp_exceptions", "off"], LINK_LCF, ["-r1", "-strip_partial"]),
})
# (partial links like a game's modules: commons (2.7 gives them .bss even with -r), the destructor chain without the
# C++ runtime ("{noruntime}": 2.7 then adds its own __destroy_global_chain_reference to .dtors$10), and a weak
# function the compiler makes force active (2.7's .comment clears its weak flags, not its force active one))
CHAIN_SOURCE = ("typedef struct DestructorChain { struct DestructorChain *next; void *destructor; void *object; } DestructorChain;\n"
                "DestructorChain *__global_destructor_chain;\n"
                "void *__register_global_object(void *object, void *destructor, void *regmem) {\n"
                "    ((DestructorChain *)regmem)->next = __global_destructor_chain;\n"
                "    ((DestructorChain *)regmem)->destructor = destructor;\n"
                "    ((DestructorChain *)regmem)->object = object;\n"
                "    __global_destructor_chain = (DestructorChain *)regmem;\n"
                "    return object;\n}\n"
                "void __destroy_global_chain(void) {\n"
                "    DestructorChain *iter;\n"
                "    while ((iter = __global_destructor_chain) != 0) {\n"
                "        __global_destructor_chain = iter->next;\n"
                "        ((void (*)(void *, short))iter->destructor)(iter->object, -1);\n    }\n}\n"
                "#pragma section \".dtors$10\"\n"
                "__declspec(section \".dtors$10\") __declspec(weak) extern void *const __destroy_global_chain_reference = __destroy_global_chain;\n")
MODULE_SOURCES = {"a.c": LINK_MAIN + "int ca; char cb; double cc[3];\nint fa(int x) { cc[x] = 1.0; return ca + cb; }\n",
                  "chain.c": CHAIN_SOURCE}
LINKS.update({
    "link-common-kept": ({"a.c": "int ca; char cb; double cc[3]; short cd; int ce[5];\n"
                                 "void _start(void) { cb = 1; ce[1] = 2; ca = 3; cd = 4; }\n"
                                 "int fa(int x) { cc[x] = 1.0; return 0; }\n"},
                         ["-sdata", "0", "-sdata2", "0", "-common", "on"], LINK_LCF, ["-sdata", "0", "-sdata2", "0"]),
    "link-r-common": (MODULE_SOURCES, ["-sdata", "0", "-sdata2", "0", "-Cpp_exceptions", "off", "-common", "on"], LINK_LCF, ["-sdata", "0", "-sdata2", "0", "-r", "{noruntime}"]),
    "link-r1-dtors": (MODULE_SOURCES, ["-sdata", "0", "-sdata2", "0", "-Cpp_exceptions", "off", "-common", "on"], LINK_LCF + "FORCEACTIVE { fa __destroy_global_chain }\n",
                      ["-sdata", "0", "-sdata2", "0", "-r1", "{noruntime}"]),
    "link-r1-weak": ({"a.c": LINK_MAIN + "#pragma force_active on\n__declspec(weak) int wa(int x) { return x * 3; }\n"
                                         "#pragma force_active reset\nint wb(int x) { return x - 3; }\n"},
                     [], LINK_LCF + "FORCEACTIVE { wa wb }\n", ["-r1"]),
})
# (an older runtime, its references in .ctors and .dtors (its __init_cpp_exceptions' to __destroy_global_chain too):
# 2.7 warns and adds its own to .ctors$10, .dtors$10 and .dtors$15, those of the exceptions' functions kept with the
# exception tables, __destroy_global_chain's with __register_global_object when there is one, else with .dtors'
# entries (a runtime without .comment keeps its .dtors whole); the older ones not roots, not even force active (a
# split game's); without __init_cpp_exceptions the generated references are undefined, a reference missing is an
# error)
OLD_CHAIN = CHAIN_SOURCE[:CHAIN_SOURCE.index("#pragma section")]
OLD_REFERENCE = '__declspec(section ".dtors") static void *const __destroy_global_chain_reference = __destroy_global_chain;\n'
OLD_INIT = ("void __destroy_global_chain(void);\nint ie;\nvoid __init_cpp_exceptions(void) { ie = 1; }\n"
            "void __fini_cpp_exceptions(void) { ie = 0; }\n"
            '__declspec(section ".ctors") static void *const __init_cpp_exceptions_reference = __init_cpp_exceptions;\n'
            + OLD_REFERENCE +
            '__declspec(section ".dtors") static void *const __fini_cpp_exceptions_reference = __fini_cpp_exceptions;\n')
CHAIN_MAIN = "void __destroy_global_chain(void);\nint g = 1;\nvoid _start(void) { __destroy_global_chain(); }\n"
CHAIN_REGISTER = ("void __destroy_global_chain(void);\nvoid *__register_global_object(void *, void *, void *);\n"
                  "int g = 1;\nvoid _start(void) { __destroy_global_chain(); __register_global_object(0, 0, 0); }\n")
OLD_RUNTIME = {"global_destructor_chain.c": OLD_CHAIN + OLD_REFERENCE, "__init_cpp_exceptions.c": OLD_INIT}
LINKS.update({
    "link-runtime-old": ({"a.c": CHAIN_MAIN, **OLD_RUNTIME}, [], LINK_LCF, ["{noruntime}"]),
    "link-runtime-old-register": ({"a.c": CHAIN_REGISTER, **OLD_RUNTIME}, ["-Cpp_exceptions", "off"], LINK_LCF,
                                  ["{noruntime}"]),
    "link-runtime-old-nocomment": ({"a.c": CHAIN_MAIN, **OLD_RUNTIME}, ["-Cpp_exceptions", "off"], LINK_LCF,
                                   ["{noruntime}"]),
    "link-runtime-old-global": ({"a.c": CHAIN_MAIN, **OLD_RUNTIME,
                                 "global_destructor_chain.c": OLD_CHAIN + "#pragma force_active on\n"
                                 + OLD_REFERENCE.replace("static ", "") + "#pragma force_active reset\n"},
                                ["-Cpp_exceptions", "off"], LINK_LCF, ["{noruntime}"]),
    "link-runtime-old-alone": ({"a.c": CHAIN_MAIN, "global_destructor_chain.c": OLD_CHAIN + OLD_REFERENCE}, [],
                               LINK_LCF, ["{noruntime}"]),
    "link-runtime-missing": ({"a.c": CHAIN_MAIN, "global_destructor_chain.c": OLD_CHAIN}, [], LINK_LCF, ["{noruntime}"]),
    # (a partial link of objects compiled with -g, without it (2.7 leaves their DWARF out), with an empty object
    # (its file symbol), an empty .text and a .rodata whose only symbol is a losing weak duplicate (their section
    # symbols at their offsets))
    "link-r-debug": ({"a.c": LINK_MAIN + "__declspec(weak) const double wk[4] = {1.5, 2.5};\n"
                             "double fa(int x) { return wk[x]; }\n",
                      "b.c": "int bd[4] = {1};\n", "c.c": "",
                      "d.c": "__declspec(weak) const double wk[4] = {1.5, 2.5};\nint fd(int x) { return x + 1; }\n"},
                     ["-g"], LINK_LCF, ["-r"]),
})
# (objects like a split game's (dtk's): a label at the end of an assembly function, the start of the next (2.7 gives
# it to the next; the compiler's .mwcats records go in the program's .comment), a data file an older compiler
# compiled with -g, linked without (an empty .text kept at no address, whose section symbol 2.7 leaves out), an object whose .symtab says it has no locals (sh_info 0: 2.7
# skips the file symbol), relocations not in offset order (2.7 walks each function's in order: a partial link's
# undefined symbols come in that order), FORCEACTIVE names nothing defines (reported first; -listclosure, with the
# Linker Generated Symbol File's entries), and C++ with exceptions and the tables in .init (the tables' section
# symbol before the generated file's locals, the generated symbols beside _eti_init_info))
def patch_section(obj, name, change):
    """Rewrites section NAME's header of the big-endian object OBJ: CHANGE(fields, data) gives new (fields, data)."""
    raw = bytearray(obj.read_bytes())
    shoff, = struct.unpack_from(">I", raw, 0x20)
    count, names = struct.unpack_from(">HH", raw, 0x30)
    headers = [list(struct.unpack_from(">10I", raw, shoff + 40 * i)) for i in range(count)]
    table = headers[names]
    for i, fields in enumerate(headers):
        start = table[4] + fields[0]
        if raw[start:raw.index(0, start)].decode() == name:
            data = bytes(raw[fields[4]:fields[4] + fields[5]])
            fields, data = change(fields, data)
            raw[fields[4]:fields[4] + len(data)] = data
            struct.pack_into(">10I", raw, shoff + 40 * i, *fields)
    obj.write_bytes(bytes(raw))


def no_locals(obj):
    patch_section(obj, ".symtab", lambda fields, data: (fields[:7] + [0] + fields[8:], data))


def relocations_reversed(obj):
    patch_section(obj, ".rela.text",
                  lambda fields, data: (fields, b"".join(data[i:i + 12] for i in range(len(data) - 12, -1, -12))))


def patch_symbol(obj, name, size):
    """Gives symbol NAME of the big-endian object OBJ SIZE, and no type (like a split game's placeholder)."""
    raw = bytearray(obj.read_bytes())
    shoff, = struct.unpack_from(">I", raw, 0x20)
    count, = struct.unpack_from(">H", raw, 0x30)
    headers = [struct.unpack_from(">10I", raw, shoff + 40 * i) for i in range(count)]
    symtab = next(fields for fields in headers if fields[1] == 2)
    strings = headers[symtab[6]][4]
    for at in range(symtab[4], symtab[4] + symtab[5], 16):
        start = strings + struct.unpack_from(">I", raw, at)[0]
        if raw[start:raw.index(0, start)].decode() == name:
            struct.pack_into(">I", raw, at + 8, size)
            raw[at + 12] &= 0xf0
    obj.write_bytes(bytes(raw))


def common_empty(obj):
    patch_symbol(obj, "ku", 0)


def no_comment(obj):
    """Renames OBJ's .comment (the linker then reads it as an object without one, like a split game's)."""
    raw = obj.read_bytes()
    obj.write_bytes(raw.replace(b"\0.comment\0", b"\0.cOmment\0"))


# (a scenario's objects changed after they are compiled: {scenario: {object: change}})
PATCHES = {"link-no-locals": {"b.o": no_locals}, "link-relocations-unsorted": {"a.o": relocations_reversed},
           "link-common-empty": {"b.o": common_empty},
           "link-runtime-old-nocomment": {"global_destructor_chain.o": no_comment}}
# (a scenario's sources compiled by another kit's compiler: {scenario: {source: kit}}; 2.6's, like a game's
# older libraries, relocates a data file's .debug against its empty .text, which keeps it)
OLD_COMPILER = {"link-empty-text": {"b.c": "2.6"}}
LINKS.update({
    "link-label-at-end": ({"a.c": "void fjmid(void);\nvoid fjend(void);\n"
                                  "asm void fj(void) {\n nofralloc\n li r3, 1\n entry fjmid\n li r4, 2\n blr\n entry fjend\n}\n"
                                  "int fk(int x) { return x + 1; }\nvoid _start(void) { fj(); fjmid(); fjend(); fk(2); }\n"},
                          [], LINK_LCF, []),
    "link-empty-text": ({"a.c": LINK_MAIN, "b.c": "int bd[4] = {1};\nint *bp = bd;\n"}, ["-g"],
                        LINK_LCF + "FORCEACTIVE { bp }\n", ["-mapunused"]),
    "link-no-locals": ({"a.c": LINK_MAIN, "b.c": "int bd = 4;\nint be[2] = {1, 2};\n"}, ["-sdata", "0"],
                       LINK_LCF + "FORCEACTIVE { bd be }\n", []),
    "link-relocations-unsorted": ({"a.c": "extern int ub(int);\nextern int uc(int);\nint fb(int x) { return x + 1; }\n"
                                          "int fa(int x) { return ub(x) + fb(x) + uc(x); }\n" + LINK_MAIN},
                                  ["-inline", "off"], LINK_LCF + "FORCEACTIVE { fa }\n", ["-r1"]),
    # (a common of no size first, like a split game's __unknown_common_bss_symbol: 2.7 puts it after the one at its
    # address)
    "link-common-empty": ({"a.c": LINK_MAIN, "b.c": "int ku;\nint kv[4];\nint kw;\nint fz(void) { return ku; }\n"
                                                    "int fb(void) { return kv[1] + kw; }\n"},
                          ["-common", "on", "-sdata", "0"], LINK_LCF + "FORCEACTIVE { fb }\n", ["-mapunused"]),
    "link-forceactive-missing": ({"a.c": LINK_MAIN + "int fa(int x) { return x; }\n"}, [],
                                 LINK_LCF + "FORCEACTIVE { nowhere fa elsewhere }\n", ["-listclosure"]),
    "link-ctors-exceptions": ({**LINKS["link-ctors"][0],
                               "init.c": '#pragma section code_type ".init"\n'
                                         'extern char _rom_copy_info[], _bss_init_info[];\nchar *volatile ip;\n'
                                         '__declspec(section ".init") void __init_start(void) { ip = _rom_copy_info; '
                                         'ip = _bss_init_info; }\n'},
                              ["-Cpp_exceptions", "on"], LINK_LCF + "FORCEACTIVE { __init_start }\n", []),
})
# (the driver's handling of its inputs, 2.x's: an object given twice (ignored, said at -v -v), a file no plugin maps
# (passed to the linker), the plugins listed by -plugindebug; a C++ name the messages unmangle;
# "{dir}" in an option is the scenario's folder, and a source that is not C or C++ is only written)
LINKS.update({
    "link-object-twice": ({"a.c": LINK_MAIN}, [], LINK_LCF, ["{dir}/a.o"]),
    "link-object-twice-verbose": ({"a.c": LINK_MAIN}, [], LINK_LCF, ["-v", "-v", "{dir}/a.o"]),
    "link-unknown-file": ({"a.c": LINK_MAIN, "notes.xyz": "not an object\n"}, [], LINK_LCF, ["{dir}/notes.xyz"]),
    "link-plugindebug": ({"a.c": LINK_MAIN}, [], LINK_LCF, ["-plugindebug"]),
    # (an output that cannot be written, a read-only file ("{readonly}"): the messages name the output file)
    "link-output-unwritable": ({"a.c": LINK_MAIN}, [], LINK_LCF, ["-o", "{readonly}"]),
    "link-unresolved-cpp": ({"a.cpp": "int nowhere(int, char *);\nint fa(int x) { return nowhere(x, 0); }\n"
                                     'extern "C" void _start(void) { fa(1); }\n'},
                            ["-Cpp_exceptions", "off"], LINK_LCF, []),
})
# (commons whose alignments leave gaps between them)
LINKS["link-common"][0]["d.c"] = "char k1; double k2; char k3; int k4; short k5;\nint fd(void) { return k1 + k3 + k4 + k5; }\n"
LINKS["link-common"] = (LINKS["link-common"][0], LINKS["link-common"][1],
                        LINKS["link-common"][2].replace("{ fb fc }", "{ fb fc fd }"), LINKS["link-common"][3])


def link_scenario(name, linker_dir, rebuilt, out_root, runtime):
    sources, flags, lcf, options = LINKS[name]
    out = out_root / name
    out.mkdir(parents=True, exist_ok=True)
    if any("{readonly}" in option for option in options):
        readonly = out / "readonly.elf"
        if readonly.exists():
            readonly.chmod(0o666)
        readonly.write_bytes(b"")
        readonly.chmod(0o444)
    # ("{noruntime}": the link has no runtime objects)
    noruntime = "{noruntime}" in options
    options = [option.replace("{dir}", str(out)).replace("{readonly}", str(out / "readonly.elf")) for option in options
               if option != "{noruntime}"]
    # (the runtime's stubs: C's, and C++'s for C++ programs)
    stubs = {"stub.c": lo.STUB, **({"stub2.cpp": lo.STUB_CPP} if any(f.endswith(".cpp") for f in sources) else {})}
    objects = []
    for file, text in {**sources, **stubs}.items():
        (out / file).write_text(text)
        if not file.endswith((".c", ".cpp")):
            continue
        obj = out / (file.rsplit(".", 1)[0] + ".o")
        code, log = lo.run(linker_dir.parent / OLD_COMPILER.get(name, {}).get(file, linker_dir.name) / "mwcceppc.exe", "-c", "-proc", "gekko", *flags, out / file, "-o", obj)
        if code:
            return [f"compile of {file} failed:\n{log}"]
        objects.append(obj)
    for obj, change in PATCHES.get(name, {}).items():
        change(out / obj)
    (out / "ldscript.lcf").write_text(lcf)
    runtime_objects = [] if noruntime else [runtime / "global_destructor_chain.o", runtime / "__init_cpp_exceptions.o"]
    pre = [o for o in objects if o.stem == "pre"]
    if pre:
        # (a program linked first, by the original, from pre.* and the stubs)
        objects.remove(pre[0])
        code, log = lo.run(linker_dir / "mwldeppc.exe", "-nodefaults", "-fp", "hardware", "-lcf", out / "ldscript.lcf",
                           "-m", "_start", "-o", out / "pre.elf", pre[0], *objects[-len(stubs):], *runtime_objects)
        if code:
            return [f"the link of pre.elf failed:\n{log}"]
        objects.append(out / "pre.elf")
    results = {}
    for who, linker in (("oracle", linker_dir / "mwldeppc.exe"), ("mine", rebuilt)):
        code, log = lo.run(linker, "-nodefaults", "-fp", "hardware", "-lcf", out / "ldscript.lcf", "-m", "_start",
                           "-map", out / f"{who}.map", *options,
                           *([] if "-o" in options else ["-o", out / f"{who}.elf"]), *objects, *runtime_objects)
        # (a crash's address is each executable's own: a link both crash in compares its messages; with fewer
        # sections than LINK_LCF's, the 2.6 linker crashes in ELF_gen_SetLinkSymbols)
        log = re.sub(r"At address: +[0-9a-f]+", "At address: (the crash)", messages(log, linker))
        results[who] = (code, log.replace(f"{who}.", "OUT."))
    problems = []
    if results["oracle"] != results["mine"]:
        problems.append(f"the links differ: {results['oracle']} against {results['mine']}")
    if results["oracle"][0] == 0 and results["mine"][0] == 0:
        problems += lo.compare(out / "oracle.elf", out / "mine.elf", out / "oracle.map", out / "mine.map")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("linker_dir", type=Path)
    parser.add_argument("rebuilt", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--runtime", type=Path, required=True,
                        help="the MSL runtime's global_destructor_chain.o and __init_cpp_exceptions.o")
    parser.add_argument("names", nargs="*")
    args = parser.parse_args()
    # (the rebuilt linker needs the license library beside it, as the original has)
    license_dll = args.linker_dir / "lmgr326b.dll"
    if license_dll.exists() and not (args.rebuilt.parent / license_dll.name).exists():
        shutil.copy(license_dll, args.rebuilt.parent / license_dll.name)
    names = args.names or [*lo.SCENARIOS, *SCENARIOS, *LIBRARIES, *LIBRARY_SEARCH, *DUMPS, *STRIPPED, *LINKS, *SWEEPS, *DRIVER, *ADDRESSES]
    differing = 0
    for name in names:
        try:
            problems = run_scenario(name, args)
        except Exception as error:
            # (an output the readers cannot parse, such as a broken string table, is a difference too)
            problems = [f"the comparison failed: {type(error).__name__}: {error}"]
        if problems == "not applicable":
            print(f"{name}: not applicable (the original linker fails it)")
            continue
        print(f"{name}: {'DIFFERENT' if problems else 'identical'}")
        for problem in problems:
            print("  " + problem.replace("\n", "\n  "))
        differing += bool(problems)
    sys.exit(1 if differing else 0)


def run_scenario(name, args):
    """One scenario's problems (a list, empty when identical), or "not applicable"."""
    if name in ADDRESSES:
        problems = address_scenario(name, args.linker_dir, args.rebuilt, args.out_dir, args.runtime)
    elif name in LINKS:
        problems = link_scenario(name, args.linker_dir, args.rebuilt, args.out_dir, args.runtime)
    elif name in STRIPPED:
        problems = stripped_scenario(name, args.linker_dir, args.rebuilt, args.out_dir, args.runtime)
    elif name in DRIVER:
        problems = driver_scenario(name, args.linker_dir, args.rebuilt, args.out_dir, args.runtime)
    elif name in SWEEPS:
        problems = sweep_scenario(name, args.linker_dir, args.rebuilt, args.out_dir, args.runtime)
    elif name in DUMPS:
        problems = dump_scenario(name, args.linker_dir, args.rebuilt, args.out_dir, args.runtime)
    elif name in LIBRARY_SEARCH:
        problems = library_search_scenario(name, args.linker_dir, args.rebuilt, args.out_dir, args.runtime)
    elif name in LIBRARIES:
        problems = library_scenario(name, args.linker_dir, args.rebuilt, args.out_dir, args.runtime)
    elif name in SCENARIOS:
        problems = lcf_scenario(name, args.linker_dir, args.rebuilt, args.out_dir, args.runtime)
    else:
        problems = lo.scenario(name, args.linker_dir, args.out_dir, args.runtime, args.rebuilt)
        if problems and problems[0].startswith("the real linker failed"):
            return "not applicable"
    return problems


if __name__ == "__main__":
    main()
