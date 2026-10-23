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

The real linker runs on this machine, so it is the test oracle. `tools/mwld.py` is a replica of a link with no linker
command file, and `tools/linker_oracle.py LINKER_DIR OUT --runtime DIR` links nine small programs with both and
compares the ELF files (`tools/elfdiff.py`) and the link maps. All nine are byte-identical, both ELF and map: dead
code, two units, `-sdata 0` and `-sdata 64` data, per-symbol alignment, floats and switch tables, pointer data, C++
with exceptions and RTTI, and an archive made by the real linker's `-library`. `tools/elf.py` reads the objects.

What the real linker does, as found by those links:

* **Dead stripping is by symbol.** An input section is cut into one atom per sized symbol; atoms nothing refers to are
  dropped and the rest are packed, each at its own alignment. That alignment is in the object's `.comment` section
  (a 44-byte header, then 8 bytes per symbol: alignment, two flag bytes, padding), not in the ELF. A section with a
  symbol whose second flag byte is `0x10` (the compiler's `...data.0`) is kept whole. `.ctors` and `.dtors` atoms
  are roots, as are the entry and the runtime's `__init_cpp_exceptions_reference` and its two siblings; a weak
  definition another object overrides loses its atom. An `extabindex` entry lives when the function it describes does
  and keeps its `extab`.
* **Layout.** `.text` starts at 0x10000; the output sections go in the order `.compress.init .init .compress.text
  .text .compress.fini .fini .rodata .ctors .dtors extab extabindex .BINARY .data .got .sdata .sbss .sdata2 .sbss2
  .PPC.EMB.sdata0 .PPC.EMB.sbss0 .bss`, each at its alignment (the largest of its inputs' `sh_addralign`, and its size
  is rounded up to 4), an empty one at the running address. An input section starts at its own `sh_addralign` (the map
  shows a `*fill*` row). The file offsets are the running position; a `PROGBITS` section after a `NOBITS` one does not
  keep the address-to-offset difference.
* **Linker-made pieces.** `.ctors$00` (`_ctors`) and `.ctors$99` (`_ctors$99`, 4 zero bytes), likewise `.dtors`; the
  suffixed input sections between them in name order, an unsuffixed `.ctors` after the suffixed. `extabindex` ends with
  32 bytes, `_eti_init_info`: the table's start and end, the first function's address and the covered code's length,
  then 16 zero bytes. `_SDA_BASE_` and `_SDA2_BASE_` are the start of `.sdata` and `.sdata2` plus 0x8000;
  `_stack_addr` is 0x3dfff0 and the heap is below the stack, both fixed; `_nbfunctions` counts the kept functions.
* **The ELF.** One `PT_LOAD` per non-empty section, `e_flags` 0x80000000, entry at the symbol. The symbol table is, for
  each object that has a kept section: its `FILE` symbol, the section symbols of what was kept (the `extabindex` one
  has value 0), the kept locals; then the four section symbols of the linker's own pieces, all the globals in object
  order, and `_ctors`, `_ctors$99`, `_dtors`, `_dtors$99`, `_eti_init_info`. `st_other` is cleared. The relocations of
  the objects that have a `.mwcats.text` are kept, sorted by address, with the address and symbol index of the output
  (`.rela.text`, `.relaextabindex`, `.rela.data`...); `.mwcats.text` itself is rebuilt for the kept functions.
  Sections: the loadable ones, `.rela*`, `.mwcats.text`, `.symtab`, `.shstrtab`, `.strtab` in the file in the order
  `.shstrtab`, `.strtab`, `.symtab`, relocations, `.mwcats.text`, with the section header table at the next multiple
  of 16.
* **The map.** The format of `tools/mwld.py`'s `write_map`; the quirks are that a section's size is the input
  section's size before stripping, that a `*fill*` row shows the address after the fill, that the first `extabindex`
  listing is empty and the second has only symbol rows with the file offset of the end of the section, and that the
  `_f_X_rom` address is aligned for the input sections there were even if all were stripped.

What it does not know (the replica stops, or is untested): a linker command file, `-opt_partial` and the other partial
links, `-sym` and DWARF merging, `-romaddr`, overlays, `-mapunused`/`-listclosure`, multiply-defined and other error
messages (it prints only the first undefined symbol), a library search (`-l`, `MWLibraries`), objects whose `.comment`
version is not 0x0b (1.3.2's objects link differently: the `.ctors` go to `.rodata` with a warning, and the retained
relocations differ), and which objects have their relocations kept (the rule above fits every test; the real one may
be the compiler version). The one linker in the tests is the project's 2.7 one.

## Next

1. Run it on a project: the split objects of an actual game, checked against the real link.
2. The linker command file, which every project uses, and `-opt_partial`.
3. Decide between a matching decompilation (this repo's style, with `src/linker/`) and keeping the replica; the
   string table gives the file names and function boundaries for the former.
