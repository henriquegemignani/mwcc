# mwldeppc.exe (GC 2.7 toolset) survey

First pass at reverse engineering the linker, before any code is written. Nothing here is decompiled yet; it comes
from the PE headers, the string tables, and running the real linker.

## The binary

| | |
| --- | --- |
| file | `build/compilers/GC/2.7/mwldeppc.exe` (748032 bytes), PE32 x86, ImageBase `0x400000`, entry `0x1000` |
| banner | `Metrowerks Linker for Embedded PowerPC`, **Version 3.0.4**, runtime built Aug 13 2004 10:40:59 |
| sections | `.text` 0x4a000 (532925 bytes), `.exc`, `.rdata`, `.data`, `.rsrc`, `.CRT`, `.idata`, `.bss` (146769), `.reloc` |
| imports | KERNEL32 (65), ADVAPI32 (registry), USER32, VERSION, `LMGR326B.dll` (3 ordinals: 189, 190, 191, the license manager) |
| runtime | the MW Win32 C runtime and MSL (`MsDos.c`, `Files.c`, MSL `printf`/`time`, `std::exception`), so the linker is itself CodeWarrior-built C++ |

The 2.7 toolset's other binaries sit beside it: `mwcceppc.exe`, `mwasmeppc.exe`, `lmgr326b.dll`.

## Structure, from the source file names in the strings

The executable is the CodeWarrior command-line driver ("CmdLine") with the linker plugin compiled in. The plugin
callbacks are the same `UCB*` / `CWDROPIN` interface the IDE uses (`CLDropinCallbacks_V10.cpp`).

| layer | files |
| --- | --- |
| driver and options | `Arguments.c`, `Option.c`, `Parameter.c`, `Targets.c`, `CLIO.c` (message styles), `CLToolExec.c`, `CLProj.c`, `CLFiles.c`, `CLFileOps.c`, `CLAccessPaths.c`, `CLSegs.c`, `CLOverlays.c`, `CLDependencies.c`, `CLBrowser.c`, `CLLicenses.c`, `CLPlugins.c`, `CLPluginRequests.cpp`, `CLWriteObjectFile.c`, `CLCompilerLinkerDropin_V10.cpp`, `CLDropinCallbacks_V10.cpp` |
| host OS | `MsDos.c`, `Files.c`, `MacSpecs.c`, `MacFileTypes.c`, `Resources.c` (Mac resource-fork emulation for the `STR#` strings), `StringUtils.c` |
| linker proper | `LinkerFacePPC_EABI.c` (plugin entry, pref panels), `ELF_linker.c` (symbol resolution, dead-stripping, map file), `ELF_gen.c` (layout and ELF writing), `ELF_PPC_EABI.c` (EABI sections, SDA, linker-generated symbols), `ELF_Endian.c`, `LinkerCmdFile.c` (LCF parser), `LinkSym.c`, `LK_symbol.c` |
| debug info | `DWARF_line.c`, `EPPC_DWARF2link.c`, `EPPC_DWARF2util.c` (merging `.debug_*` from the inputs) |
| disassembler | `DumpELF.c`, `DumpELFCodePPC.c`, `DumpDWARF.c`, `PrepDumpELF.c` (`-dis`) |
| runtime hooks | `__init_cpp_exceptions.cpp` (the linker embeds knowledge of the MSL objects it needs) |

The compiler repo's `src/backend/BE_elf.c`, `ELF_Endian.c` and `DWARF.c` write the same ELF/DWARF 1 structures, and are the
reference for reading object files. `ELF_Endian.c` exists under the same name in both programs.

## Command line

The full `-help` output is in [mwldeppc-help.txt](mwldeppc-help.txt). Option groups:

* **General** (shared driver): `-help`, `-version`, `-timing`, `-progress`, `-v`, `-search`, `-lines`, `-wraplines`,
  `-maxerrors`, `-maxwarnings`, `-msgstyle {mpw,std,gcc,IDE,parseable}`, `-[no]stderr`, `-nostdlib`/`-defaults`, `-l`/`-L`/`-lr`,
  `-dis`, `-nofail`, `-o`, `@response` files.
* **Linker**: `-m|-main`, `-nomain|-noentry`, `-map [file]`, `-mapunused`, `-listclosure`, `-listdwarf`, `-[no]srec`
  (`-sreceol`, `-sreclength`, `-sortsrec`), `-lessram|-moreram`, `-linkmode`, `-lcf <file>`, `-codeaddr`, `-dataaddr`,
  `-sdataaddr`, `-sdata2addr`, `-stackaddr`, `-heapaddr`, `-romaddr`, `-rambuffer`, `-application`, `-library`,
  `-partial|-r`, `-opt_partial|-r1`, `-resolved_partial|-r2`, `-strip_partial`, `-sym`/`-g` (DWARF 1 or 2), `-fp`, `-proc`,
  `-sdata`, `-sdata2`, `-heapsize`, `-stacksize`, `-model`, `-abi`, `-tune_relocations`, `-[no]char`.
* **Environment**: `MWLibraries`, `MWLibraryFiles`, `MWEABIPPCLibraries`, `MWEABIPPCLibraryFiles`, `MWLinkOptions`,
  `MWLinkEABIPPCOptions`, `LM_LICENSE_FILE`, `TMPDIR`, `COMSPEC`, `MW_CYGDRIVE_PREFIX`, `MW_CYGWIN_ROOT`.
* Default entry symbol `__start`, default output `a.out`, default map `<outfile>.MAP`.

## Linker command file (LCF)

Keywords found in `LinkerCmdFile.c`'s tables: `MEMORY { name : origin = , length = }`, `SECTIONS { ... }`, `FORCEACTIVE`,
`FORCEFILES`, `EXCLUDEFILES`, `INCLUDEDWARF`, `ENTRY`, `SHORTEN_NAMES_FOR_TOR_101`; section attributes `ZTEXT ZCODE MIXED
CONST`, `INTERNAL_LOAD`, `EXCLUDE_FILE`, `SHORT`, `PROVIDE`, `CONSTRUCTORS`, `GROUP`, `ALIGN`, `ROMADDR`, `SIZEOF`,
`SIZEOF_HEADERS`; ELF-quirk switches `CONFIG_SYS_V_ABI`, `CONFIG_SUSE_LINUX`, `CONFIG_YELLOW_DOG_LINUX`,
`CATS_BSS_MOD`, `CATS_HEADER_MOD`, `DWARF_DIAGNOSTICS`, `DATA_TYPE_CONVERTS`, `DYNAMIC_LINKER`, `EXTERNAL_SYMBOL`,
`INTERNAL_SYMBOL`, `COMMON_ORDER`, `DYNSYM_ORDER`. Memory-map output names `addr_mode` `external|internal`.

## Linker-generated symbols and sections

From `ELF_PPC_EABI.c` and `LinkSym.c`: `_SDA_BASE_`, `_SDA2_BASE_`, `_ABS_SDA_BASE_`, `_ABS_SDA2_BASE_`,
`_stack_addr`, `_stack_end`, `_heap_addr`, `_heap_end`, `_nbfunctions`, `_f_mwerks_fixup`/`_e_mwerks_fixup`,
`_rom_copy_info`, `_bss_init_info`, `_eti_init_info` (exception table index), the `_pic_*` variants, `_ctors`,
`_dtors`, `_DYNAMIC`, `_GLOBAL_OFFSET_TABLE_`, `.startof.<sec>`, `.phdr_N`, `.sec_N`. The C++ runtime glue:
the linker requires `__init_cpp_exceptions`, `__fini_cpp_exceptions` (and the references to them),
`__destroy_global_chain`, `__register_global_object`, and complains "runtime sources `global_destructor_chain.c` and
`__init_cpp_exceptions.cpp` both need to be updated to latest version" when they are missing or old.
Section names in the order the string table lists them (a hint at the ELF writer's order, not verified against output): `.compress.init .init .compress.text .text .compress.fini .fini .rodata .ctors
.dtors .data .sdata2 .sbss2 .PPC.EMB.sdata0 .PPC.EMB.sbss0 .sbss .sdata`, then DWARF, `.symtab`, `.strtab`, `.shstrtab`.
Dead-stripping (`-opt_partial`, `-strip_partial`, `FORCEACTIVE`) and the `>>> EXCLUDED / UNREFERENCED DUPLICATE` map lines
are in `ELF_linker.c`.

## Map file format

Observed with a small program: [example-a.map](example-a.map). It starts `Link map of <entry>`, then one block per
output section (`<name> section layout`, columns `Starting address / Size / Virtual address / File offset`, then one row
per symbol with an alignment column and the owning object), then `Memory map:`, `Linker generated symbols:` and, with
`-mapunused`, `UNUSED` rows. The format strings are at file offsets 0x95a1c to 0x95b98 and 0x990e4 to 0x99190.

## The oracle and the replica

The real linker runs on this machine, so it is the test oracle. `mwld/` is a Rust crate (`cargo build --release`) that replicates a link, with or without a linker
command file (`src/link.rs` loads and strips, `layout.rs` places, `writer.rs` writes the ELF, `map.rs` the map), and `tools/linker_oracle.py LINKER_DIR OUT --runtime DIR [--mwld EXE]` links eleven small programs with both and
compares the ELF files (`tools/elfdiff.py`, an independent Python reader) and the link maps. All eleven are byte-identical, both ELF and map: dead
code, two units, `-sdata 0` and `-sdata 64` data, per-symbol alignment, floats and switch tables, pointer data, C++
with exceptions and RTTI, an archive made by the real linker's `-library`, an object compiled with `-pragma "cats off"`,
and an object from the 1.3.2 compiler (`.comment` version 10). Every program is compiled by a Metrowerks compiler
and linked with the same two MSL runtime objects (Echoes') as `__init_cpp_exceptions` and `global_destructor_chain`. 

What the real linker does, as found by those links:

* **Dead stripping is by symbol.** An input section is cut into one atom per sized symbol; atoms nothing refers to are
  dropped and the rest are packed, each at its own alignment. That alignment is in the object's `.comment` section
  (a 44-byte header, then 8 bytes per symbol: alignment, two flag bytes, padding), not in the ELF. A section with a
  symbol whose second flag byte is `0x10`, or with a symbol named `...data.0` (the compiler's mark of a section start),
  is kept whole. `.ctors` and `.dtors` atoms
  of an object with anything else live are roots (an object nothing needs is dropped whole, `.ctors$10` hooks
  included), as are a symbol's own atom when the compiler flagged it `#pragma force_active` (second `.comment` flag
  byte `0x08`), the entry and the runtime's `__init_cpp_exceptions_reference` and `__fini_cpp_exceptions_reference`
  (not `__destroy_global_chain_reference`: a link with only `global_destructor_chain.o` drops it); a weak
  definition another object overrides loses its atom. An `extabindex` entry lives when the function it describes does
  and keeps its `extab`.
* **Layout.** `.text` starts at 0x10000; the output sections go in the order `.compress.init .init .compress.text
  .text .compress.fini .fini .rodata .ctors .dtors extab extabindex .BINARY .data .got .sdata .sbss .sdata2 .sbss2
  .PPC.EMB.sdata0 .PPC.EMB.sbss0 .bss`, each at its alignment (the largest of its inputs' `sh_addralign`, and its size
  is rounded up to 4), an empty one at the running address. An input section starts at its own `sh_addralign` (the map
  shows a `*fill*` row). The file offsets are the running position; a `PROGBITS` section after a `NOBITS` one does not
  keep the address-to-offset difference.
* **Linker-made pieces.** `.ctors$00` (`_ctors`) and `.ctors$99` (`_ctors$99`, 4 zero bytes), likewise `.dtors`, exist
  only when the section has live input other than the runtime's `$10` and `$15` hooks, or when an exception table is
  live (`extabindex` kept; with none the sections are just the hooks). The suffixed input sections go between them in
  name order, an unsuffixed `.ctors` after the suffixed. A live `extabindex` ends with 32 bytes, `_eti_init_info`; with
  no exception table live but code that refers to `_eti_init_info` (the runtime's `__init_cpp_exceptions`) there is an
  empty `extabindex` section and `_eti_init_info` has size 0 and value 0. A live `extab` needs
  `__init_cpp_exceptions` (the real linker fails without it). `.mwcats.text` exists only when a kept object has one.
  The 32 bytes of `_eti_init_info` are: the table's start and end, the first function's address and the covered code's length,
  then 16 zero bytes. A global without a size (the `_savegpr_N` entry points inside `__save_gpr`) is kept in the symbol
  table and the map only if code refers to it or it is the entry. `_SDA_BASE_` and `_SDA2_BASE_` are the start of `.sdata` and `.sdata2` plus 0x8000;
  `_stack_addr` is 0x3dfff0 and the heap is below the stack, both fixed; `_nbfunctions` counts the kept functions.
* **The ELF.** One `PT_LOAD` per non-empty section, `e_flags` 0x80000000, entry at the symbol. The symbol table is, for
  each object that has a kept section: its `FILE` symbol, the section symbols of what was kept (the `extabindex` one
  has value 0), the kept locals; then the four section symbols of the linker's own pieces, all the globals in object
  order, and `_ctors`, `_ctors$99`, `_dtors`, `_dtors$99`, `_eti_init_info`. `st_other` is cleared. The relocations of
  the objects that have a `.mwcats.text` or a `.note.split` (a section the dtk splitter writes) are kept, sorted by
  address, with the address and symbol index of the output (`.rela.text`, `.relaextabindex`, `.rela.data`...);
  `.mwcats.text` itself is rebuilt for the kept functions. The rule is the section: an object compiled with `-pragma
  "cats off"` (as Echoes' runtime is) has neither and none of its relocations are kept, though the compiler and linker are the same.
  Sections: the loadable ones, `.rela*`, `.mwcats.text`, `.symtab`, `.shstrtab`, `.strtab` in the file in the order
  `.shstrtab`, `.strtab`, `.symtab`, relocations, `.mwcats.text`, with the section header table at the next multiple
  of 16.
* **The map.** The format of `mwld/src/map.rs`; the quirks are that a section's size is the input
  section's size before stripping, that a `*fill*` row shows the address after the fill, that the first `extabindex`
  listing is empty and the second has only symbol rows with the file offset of the end of the section, and that the
  `_f_X_rom` address is aligned for the input sections there were even if all were stripped.

Real objects. `tools/linker_oracle.py` only builds small programs; the Echoes objects (1062 of them, the MSL, math and
engine code the game was split into) were also linked: from a random function, the objects its undefined symbols need
(the two runtime objects and a stub for `__register_fragment` and `__unregister_fragment` added, `-nostdlib`), by both
linkers. Of 360 random links that the real linker accepts, all are identical, ELF and map (the earlier 16 differences
were three rules found since: an `R_PPC_EMB_SDA21` relocation may point 2 bytes into its instruction; active data
with sized symbols is dropped like any other, while a section with no sized symbol, or a `.ctors`/`.dtors` hook, is kept
whole; and the map's file offset of a symbol without size inside an atom is the atom's end, as the real linker prints
it). Entry names
longer than 63 characters are an error in the real linker. The generating code is in the linker: `FUN_00436b90` in the Ghidra program `mwld-gc-2-7` (the
PPC EABI symbol and hook generator; the strings `_ctors`, `_dtors`, `_eti_init_info` and the three `*_reference` hooks
are used only there). It decides which of the linker's own `.ctors$10`, `.dtors$10` and `.dtors$15` hook pieces to
add when the runtime's functions are not defined by an object; the replica does not port it and so does not make
those pieces (a link with a constructor but no `__init_cpp_exceptions.o` is not reproduced).

What it does not know (the replica stops, or is untested): `-opt_partial` and the other partial
links, `-sym` and DWARF merging, `-romaddr`, overlays, `-listclosure`, `-g` and `-mapunused` (accepted and ignored, so the map has no UNUSED rows), multiply-defined and other error
messages (it prints only the first undefined symbol), and a library search (`-l`, `MWLibraries`). Objects with no
`.comment` section, such as `mwasmeppc.exe`'s, are refused: one linked differently (the real linker kept less of the
runtime, and ordered the symbols by another rule) and its alignments and flags are unknown. The tests use the 2.7
linker, the 2.7 and 1.3.2 compilers, and the Echoes runtime objects, so that is the scope of "byte-identical".

## Linker command files and the whole game

`-lcf FILE` (`mwld/src/lcf.rs`, `layout.rs`) supports `MEMORY { name : origin = N, length = N }`, one `GROUP` of
output sections with empty bodies (`.text ALIGN(0x20):{}`), symbol assignments after it (`+ - * & | ~ << >>`,
`SIZEOF(.section)`, other symbols), and `FORCEACTIVE { names }` (the names contain `<>,`, so the block is cut out
before tokenizing). `-fp`, `-nodefaults`, `-sdata`, `-sdata2`, `-g`, `-mapunused` and `@rspfile` are accepted.
`tools/lcf_oracle.py` runs one link with both linkers and compares. Metroid Prime 2's whole DOL (970 objects,
`-fp hardware -nodefaults -lcf build/G2ME01/ldscript.lcf`, 6.6 MB) is byte-identical, ELF and map; the replica takes 0.4 s.
(The repository's own `main.elf` is from older objects and differs, so the real linker has to be run again.) What it needed:

* **Layout.** The output sections are in the order of the command file, starting at the `origin`; each starts at
  max(its `ALIGN`, its inputs' alignment); an empty one does not advance the address. `_f_X_rom` is
  align(`_f_X`, max(widest input alignment, the file's `ALIGN`)). With a command file the symbol list (map, symbol
  table) follows only the file's sections; assigned symbols that are new come first in "Linker generated symbols", and
  those the linker has (`_stack_addr`, `_stack_end`) take the new value in place. An empty `.bss` and `.stack` are
  left out of the memory map; an empty `.bss` (and `.stack`) has a `_rom` symbol, a non-empty `.bss` does not.
* **Common symbols.** Each object's commons make a `.bss` piece of their own, owned by the object, placed after
  every object's ordinary `.bss` in object order; their offsets follow the symbol order, each at its alignment (the
  symbol's value), with no padding. The piece's section symbol comes after the object's locals, and an object that is
  only commons has no `FILE` symbol.
* **`_rom_copy_info` and `_bss_init_info`** are generated at the end of `.init` ("Linker Generated Symbol File") when
  code refers to them: 12-byte entries (ROM address, address, size) for each section that has contents (`.init` too),
  then 12 zero bytes; 8-byte entries (address, size) for each non-empty bss section, then 8 zero bytes. That piece
  has a section symbol before `.ctors$00`'s.
* **`ABS` symbols.** Undefined symbols the linker defines (`_SDA_BASE_`, `_stack_addr`, those the file assigns) are
  global `NOTYPE`/`SHN_ABS` symbols after the object globals, in the order of the "Linker generated symbols" list,
  plus the symbols an emitted assignment uses (`_db_stack_addr` for `__ArenaLo`), before `_rom_copy_info`.
* **Weak duplicates.** A definition another object overrides is dropped even when it is flagged force-active (the
  duplicate inline functions of a catch-all object stay out of the output and out of the map's symbol rows, though
  the piece's size in the map still counts them).
* **Names.** A symbol may be defined local in an object and listed there as undefined global; the reference binds to the
  local. An unsized symbol inside an atom that has a sized symbol gets the atom's end as its file offset, and its
  row goes after the sized symbol's, even when it is at the atom's start.

## Partial links and the REL modules

The game's REL modules are linked twice (`build.ninja`): `.preplf` is `-sdata 0 -sdata2 0 -r` on the module's objects, and
`.plf` is `-sdata 0 -sdata2 0 -r1 -lcf <module>/ldscript.lcf -m _prolog -strip_partial` on the objects plus
`REL_Setup.o` (and usually `global_destructor_chain.o`). Both need the objects in the order of `build.ninja`.
`tools/lcf_oracle.py --cwd <echoes> ...` runs them. Of the 86 modules, all 86 `.preplf` and 69 `.plf` links are
byte-identical in ELF and map; 14 more have an identical ELF and differ only in the map's `SYMBOL NOT FOUND` order, and
DarkSamus and ScriptGui differ in the ELF (open).

* **`-r` / `-r1`** make an ET_REL file: addresses are 0, every relocation is kept (symbol indices remapped), a
  rebuilt `.comment` is written, and nothing is stripped. In plain `-r`, global sized data nothing references is
  dropped. `-strip_partial` applies the normal reachability strip (roots: the entry and `FORCEACTIVE`, locals too) with
  undefined-symbol errors turned off.
* **LCF section bodies.** `.data : { *(.data) *(extabindex) *(extab) }` merges those input sections into the output
  section. A command file without `MEMORY` means origin 0. Sections the file does not place are dropped with their atoms.
* **Generated markers.** When live code refers to `_ctors` or `_dtors`, `.ctors$00/$99` and `.dtors$00/$99` pieces are
  generated (a `.dtors$10` piece, `__destroy_global_chain_reference`, gets a relocation to `__destroy_global_chain`).
  They have section symbols after the locals and global symbols at the end of the symtab; `.comment` header byte 15 is 3
  and their entries have alignment 4.
* **Symbol table.** An undefined symbol is listed where the first object using it is.
* **`>>> SYMBOL NOT FOUND` order (map header).** A depth-first walk of the live code: roots are the entry then the
  `FORCEACTIVE` names in order; forced names no object defines come first; leftover live atoms follow in reverse index
  order. The last rule is not exact (ChozoGhost and 13 others differ); the walk's order for those leftovers is unknown.
* The map omits "Linker generated symbols" in a partial link.

## Next

1. The residuals above: the leftover-phase `SYMBOL NOT FOUND` order, and the DarkSamus/ScriptGui ELF differences.
2. `-opt_partial`.
3. Port the hook generator.
4. Decide between a matching decompilation (this repo's style, with `src/linker/`) and keeping the replica; the
   string table gives the file names and function boundaries for the former.
