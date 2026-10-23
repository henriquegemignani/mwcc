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

## The oracle

The real linker runs on this machine, so it can be the test oracle: `python tools/linker_oracle.py
build/compilers/GC/2.7 OUT --runtime <dir with the MSL runtime .o files>` builds two tiny objects with 2.7's
`mwcceppc.exe`, links them with the runtime objects, and keeps `a.elf` and `a.map` (the first link, with the default
layout, puts `.text` at `0x10000`, file offset `0x120`; the output ELF was 2496 bytes).

Findings from it:

* With no LCF, `__init_cpp_exceptions` and `__fini_cpp_exceptions` must resolve (through the MSL runtime objects, which in
  turn need `__register_fragment` and `__unregister_fragment`), even for a program that uses neither.
* Objects without the compiler's floating-point comment data draw "Floating point settings of project file ... does not
  match project settings" warnings; the linker reads the `.comment` section of each object.

## Plan

1. Read and diff (not yet written): a reader for the linker's input (ELF32 BE relocatable objects, `.a` archives with
   the `!<arch>` format, `.comment` records) and an ELF diff tool that explains where two outputs differ.
2. Replicate the no-LCF default layout, symbol resolution, relocations (`R_PPC_*`, `R_PPC_EMB_SDA21`, `R_PPC_ADDR16_*`)
   and the map file, checked byte for byte against the oracle on the tiny programs, then on the project's split objects
   (the units in `build/GC_2_7/obj`).
3. LCF parsing, `FORCEACTIVE` dead-stripping, `.ctors`/`.dtors`, exception tables (`extab`/`extabindex`), DWARF merging.
4. Decide, with the findings above, between a matching decompilation (in this repo's style, with `src/linker/`) and a
   behavioral rewrite; the string table gives the file names and function boundaries for the former.
