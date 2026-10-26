#!/usr/bin/env python3
"""python configure.py [--version VERSION]: write build.ninja (and objdiff.json) for VERSION.

A version with config/VERSION/splits.txt builds as decomp-toolkit projects do: the original is split into one object per
unit (tools/split.py), and the executable is linked from the compiled objects of the units whose source is Matching and
the split objects of the others, then checked against the original's SHA-1 (tools/link.py). objdiff compares each unit's
compiled object with its split one. Any other version compares each compiled function with the original's
(tools/compare.py)."""
import argparse
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "tools"))
from split import read_splits

# (in release order: the index is VERSION in include/version.h)
VERSIONS = ["GC_1_0", "GC_1_1", "GC_1_1p1", "GC_1_2_5", "GC_1_2_5n", "GC_1_3", "GC_1_3_2", "GC_2_7"]
# (the linkers, mwldeppc.exe: each is the driver and C library of a compiler version, config.json "compiler_version",
# with the linker plugin in place of the compiler's)
LINKERS = ["LD_1_0", "LD_1_3_2", "LD_2_6", "LD_2_7"]
# (the version the build is configured for unless one is named)
PRIMARY = "GC_1_2_5"
# (units the runtime library ships as objects)
LIBRARY_OBJECTS = {"cexc.obj": "lib/runtime/cexc.obj", "ccinit.obj": "lib/runtime/ccinit.obj"}

# (the compilers are Windows executables: wibo runs them elsewhere, and cmd.exe runs ninja's commands here: ninja
# does not use it by itself)
WINDOWS = sys.platform == "win32"
TOOL_DEP = "" if WINDOWS else "$wibo "
ENVIRONMENT = "cmd /c set MWCIncludes=include/libc&& " if WINDOWS else "MWCIncludes=include/libc "
# (the Pro 5 tools check a FlexLM license: tools/lmgr_stub stands in for the library, beside each of them)
STUB = " build/compilers/{}/lmgr326b.dll" if WINDOWS else ""
STUB_INPUT = " | tools/lmgr_stub/lmgr326b.dll" if WINDOWS else ""
# (LLVM's resource compiler and clang's assembler, for the resources and the objects a configuration has as source,
# config.json "resources" and "assembly")
LLVM_RC = shutil.which("llvm-rc") or ("C:/Program Files/LLVM/bin/llvm-rc.exe" if WINDOWS else "llvm-rc")
CLANG = shutil.which("clang") or ("C:/Program Files/LLVM/bin/clang.exe" if WINDOWS else "clang")
quote = lambda path: chr(34) + path + chr(34) if WINDOWS else shlex.quote(path)


def quote(argument):
    return subprocess.list2cmdline([argument]) if WINDOWS else shlex.quote(argument)


def join(arguments):
    return " ".join(map(quote, arguments))


def pro4_arguments(args):
    """Pro 4's driver takes Microsoft-style options."""
    result, rest = [], iter(args)
    for arg in rest:
        if arg == "-o":
            result.append("/Fo" + next(rest))
        elif arg.startswith("-"):
            result.append("/" + arg[1:])
        else:
            result.append(arg)
    return result


def matching(config, sources, source):
    """Whether SOURCE is Matching in a version: a version can list its Matching sources itself (its config's
    "matching"), else config/sources.json's status decides."""
    if "matching" in config:
        return source in config["matching"]
    return sources[source].get("status", "Matching") == "Matching"


def objdiff(version, config, sources, units):
    """objdiff's project: each unit's split object, the compiled one when it has a source."""
    entries = []
    for unit in units:
        library = unit.startswith(("src/msl/", "src/runtime/")) or unit in LIBRARY_OBJECTS
        entry = dict(name=unit.removeprefix("src/").rsplit(".", 1)[0] if unit.startswith("src/") else unit,
                     target_path=f"build/{version}/obj/{unit}.obj",
                     metadata=dict(complete=unit in LIBRARY_OBJECTS, progress_categories=["runtime" if library else "compiler"]))
        if unit in sources:
            entry["base_path"] = f"build/{version}/compiled/{unit}.obj"
            entry["metadata"].update(complete=matching(config, sources, unit), source_path=unit)
        elif unit in LIBRARY_OBJECTS:
            entry["base_path"] = LIBRARY_OBJECTS[unit]
        else:
            # (the build stamp, the linker's COMMON block, the import library's thunks: no source)
            entry["metadata"]["auto_generated"] = True
        entries.append(entry)
    Path("objdiff.json").write_text(json.dumps({
        "$schema": "https://raw.githubusercontent.com/encounter/objdiff/main/config.schema.json",
        "min_version": "3.8.0",
        "custom_make": "ninja",
        "build_target": False,
        "build_base": True,
        "watch_patterns": ["src/**/*.c", "src/**/*.cpp", "include/**/*.h", "config/**/*.json", "config/**/*.txt"],
        "units": entries,
        "progress_categories": [{"id": "compiler", "name": "Compiler"}, {"id": "runtime", "name": "MSL and runtime"}],
    }, indent=2) + "\n")


def source_only(version, config, sources, splits):
    """The build of a linker from source alone: its units are another linker's (config.json "units_from"), compiled,
    the ones with no C source assembled (config.json "assembly": {unit: source}) and the ones that are the import
    library's stubs left out; its imports are assembled too (config.json "imports": sources), and its resources
    compiled (config.json "resources")."""
    assembly = config.get("assembly", {})
    imports = config.get("imports", [])
    compiled = lambda source: f"build/{version}/compiled/{Path(source).with_suffix('.obj').as_posix()}"
    inputs = [f"build/{version}/compiled/resources.res"] if config.get("resources") else []
    replace = config.get("replace", {})
    for unit, _ in read_splits(splits)[1]:
        unit = replace.get(unit, unit)
        if unit in assembly:
            inputs.append(compiled(assembly[unit]))
        elif unit in sources:
            inputs.append(f"build/{version}/compiled/{unit}.obj")
    inputs += [compiled(source) for source in imports]
    output = config.get("output", "mwldeppc.exe")
    out = [
        "rule assemble",
        f"  command = {quote(CLANG)} --target=i386-pc-windows-msvc -c $in -o $out",
        "  description = AS $out",
        *(f"build {compiled(source)}: assemble {source}" for source in [*assembly.values(), *imports]),
        "rule link_equivalent",
        "  command = $python tools/link.py --equivalent $version $out $in",
        "  description = LINK $out",
        f"build build/{version}/equivalent/{output}: link_equivalent {' '.join(inputs)} | "
        f"{TOOL_DEP}build/compilers/pro53/mwld.exe tools/link.py || lib/ok",
        f"build equivalent: phony build/{version}/equivalent/{output}",
        "build build/compilers/pro53/mwld.exe: download",
        "  tool = mwld",
    ]
    if config.get("resources"):
        out += [
            "rule rc",
            f"  command = {quote(LLVM_RC)} -C 1252 -no-preprocess -fo $out $in",
            "  description = RC $out",
            f"build build/{version}/compiled/resources.res: rc {config['resources']}",
        ]
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", choices=VERSIONS + LINKERS, default=PRIMARY)
    parser.add_argument("--mode", choices=["link", "compare", "source"],
                        help="relink the executable from its split units, or compare each compiled function with the "
                        "original's (the default: config/<version>/config.json \"mode\", else link when there are splits)")
    parser.add_argument("--split-only", action="store_true",
                        help="link every unit from its split object, none from its compiled source (the check that "
                        "the split relinks the original)")
    arguments = parser.parse_args()
    version = arguments.version
    config = json.loads(Path(f"config/{version}/config.json").read_text())
    # (a linker builds its shared sources as its compiler version does: that version's compilers, flags and symbol
    # settings, unless the linker's config gives its own)
    release = config.get("compiler_version", version)
    if release != version:
        base = json.loads(Path(f"config/{release}/config.json").read_text())
        config = {**{k: base[k] for k in ("compilers", "flags", "compiler_overrides", "sym_on", "sym_off") if k in base},
                  **config}
    output = config.get("output", "mwcceppc.exe")
    sources = json.loads(Path("config/sources.json").read_text())
    # (a linker built from source alone, config.json "units_from": another linker's units, compiled for this one, with
    # no split of its own and no exact build; its executable is checked by its behaviour, tools/linker_equivalence.py)
    units_from = config.get("units_from")
    splits = Path(f"config/{units_from or version}/splits.txt")
    if release != version:
        # (only the sources that are units of the linker)
        units_here = {unit for unit, _ in read_splits(splits)[1]}
        # (a unit built from another source in this linker, config.json "replace": {unit: source})
        units_here |= set(config.get("replace", {}).values())
        units_here -= set(config.get("replace", {}))
        sources = {name: settings for name, settings in sources.items() if name in units_here}
    else:
        # (the linker's own files are no compiler's)
        sources = {name: settings for name, settings in sources.items() if not name.startswith("src/linker/")}
    mode = "source" if units_from else arguments.mode or config.get("mode") or ("link" if splits.exists() else "compare")
    linking = mode == "link"
    equivalent = []
    if linking and not splits.exists():
        parser.error(f"{splits} does not exist: --mode link needs the version's split")
    python = quote(sys.executable)
    out = [
        "# Generated by configure.py",
        f"python = {python}",
        "wibo = " + ("" if WINDOWS else "build/tools/wibo"),
        "",
        "pool downloads",
        "  depth = 1",
        "rule download",
        "  command = $python tools/download_tool.py $tool $out",
        "  description = DOWNLOAD $out",
        "  pool = downloads",
        "rule mwcc",
        # (-MD writes <stem>.dep to the working directory)
        "  command = " + ENVIRONMENT + "$wibo $compiler_command $cflags -MD $in -o $out"
        " && $python tools/transform_dep.py $stem.dep $out",
        "  description = MWCC $in",
        "  depfile = $out.d",
        "  deps = gcc",
        "rule mwcc_pro4",
        "  command = " + ENVIRONMENT + "$wibo $compiler_command $cflags",
        "  description = MWCC $in",
        "rule configure",
        f"  command = $python configure.py --version {version} --mode {mode}" + (" --split-only" if arguments.split_only else ""),
        "  generator = 1",
        "",
        f"version = {version}",
        "build build/tools/objdiff-cli: download",
        "  tool = objdiff-cli",
        *([] if WINDOWS else ["build build/tools/wibo: download", "  tool = wibo"]),
        "build build/compilers/ok "
        + " ".join(json.loads(Path(f"config/{v}/config.json").read_text())["original"] for v in VERSIONS + LINKERS)
        + ": download",
        "  tool = compilers",
    ]
    # (the libraries' objects the link takes as they ship come with them)
    out += [f"build lib/ok {' '.join(LIBRARY_OBJECTS.values())} lib/win32sdk/KERNEL32.LIB: download", "  tool = lib"]
    # (a version built with other compilers or options maps the sources' to its own: config/<version>/config.json
    # "compilers", and "flags", option by option; a source named in "compiler_overrides" is built with that compiler)
    overrides = config.get("compiler_overrides", {})
    host = lambda settings, source=None: (overrides.get(source)
                                          or config.get("compilers", {}).get(settings["compiler"], settings["compiler"]))
    flag = lambda option: config.get("flags", {}).get(option, option)
    for compiler in sorted({host(s, n) for n, s in sources.items()}):
        stub = WINDOWS and compiler != "pro4"
        out += [f"build build/compilers/{compiler}/mwcc.exe{STUB.format(compiler) if stub else ''}: download"
                + (STUB_INPUT if stub else ""), f"  tool = {compiler}"]
    objects = []
    for source, settings in sources.items():
        obj = f"build/{version}/compiled/{source}.obj"
        compiler = f"build/compilers/{host(settings, source)}/mwcc.exe"
        flags = list(map(flag, settings["flags"]))
        # (a version built with symbols on or off where config/sources.json says otherwise lists the source in "sym_on"
        # or "sym_off")
        for listed, value in (("sym_on", "on"), ("sym_off", "off")):
            if source in config.get(listed, []) and "-sym" in flags:
                flags[flags.index("-sym") + 1] = value
        # (-DLINKER=NN for the linker of GC N.N, so that the sources can tell the linkers apart)
        args = ["-c", *flags, f"-DVERSION={VERSIONS.index(release)}",
                *([f"-DLINKER={version[3]}{version[5]}"] if release != version else []),
                *(f"-I{d}" for d in settings.get("include_dirs", [])), "-Iinclude", "-i-",
                *(f"-I{d}" for d in settings.get("system_include_dirs", [])), "-Iinclude/libc"]
        if host(settings, source) == "pro4":
            out += [f"build {obj}: mwcc_pro4 {source} | {TOOL_DEP}{compiler} || lib/ok",
                    f"  cflags = {join(pro4_arguments([*args, source, '-o', obj]))}"]
        else:
            out += [f"build {obj}: mwcc {source} | {TOOL_DEP}{compiler} || lib/ok", f"  cflags = {join(args)}",
                    f"  stem = {Path(source).stem}"]
        out.append(f"  compiler_command = {compiler.replace('/', chr(92)) if WINDOWS else compiler}")
        objects.append(obj)
    if units_from:
        out += source_only(version, config, sources, splits)
    elif linking:
        units = [unit for unit, _ in read_splits(splits)[1]]
        split_objects = [f"build/{version}/obj/{unit}.obj" for unit in units]
        # (the executable's resources are a .res file of their own, after the sections object that orders the image)
        has_resources = ".rsrc" in read_splits(splits)[0]
        extra = [f"build/{version}/obj/resources.res"] if has_resources else []
        inputs = [f"build/{version}/obj/sections.obj", *extra]
        for unit in units:
            if unit in LIBRARY_OBJECTS:
                inputs.append(LIBRARY_OBJECTS[unit])
            elif unit in sources and matching(config, sources, unit) and not arguments.split_only:
                inputs.append(f"build/{version}/compiled/{unit}.obj")
            else:
                inputs.append(f"build/{version}/obj/{unit}.obj")
        # (the libraries the executable imports from: the SDK's, or generated from the definition files
        # config.json "imports" lists, which also fix the hints of imports by name)
        imports = [f"build/{Path(library).stem}.lib" if library.endswith(".def") else library
                   for library in config.get("imports", ["lib/win32sdk/KERNEL32.LIB"])]
        inputs += imports + ["build/lmgr326b.lib"]
        # (the units listed as "equivalent" do what the original's do without being its bytes: linked from source with
        # the Matching ones, they give a second executable, which tools/linker_equivalence.py checks by its behaviour)
        equivalent = [unit for unit in config.get("equivalent", []) if unit in sources]
        # (an "equivalent" unit with no source, an import's stubs, is left out: the linker makes the stubs from the
        # import libraries, as it does the KERNEL32 ones)
        dropped = [f"build/{version}/obj/{unit}.obj" for unit in config.get("equivalent", []) if unit not in sources]
        equivalent_inputs = [f"build/{version}/compiled/{path[len(f'build/{version}/obj/'):]}"
                             if path.startswith(f"build/{version}/obj/") and path[len(f"build/{version}/obj/"):-4]
                             in equivalent else path for path in inputs if path not in dropped]
        # (resources written as source: compiled for the equivalent executable in place of the original's)
        resource_source = config.get("resources")
        if resource_source:
            equivalent_inputs = [f"build/{version}/compiled/resources.res" if path.endswith("/resources.res") else path
                                 for path in equivalent_inputs]
        # (objects written as assembly, config.json "assembly": {link input: source}, such as the COMMON block
        # (tools/common_source.py writes it) and the runtime library's table bounds, in place of the split's or the
        # library's; and without the object that orders the sections as the original's, "order_sections": false, the
        # equivalent link is all source)
        assembled = {path: f"build/{version}/compiled/{Path(source).with_suffix('.obj')}"
                     for path, source in config.get("assembly", {}).items()}
        equivalent_inputs = [assembled.get(path, path) for path in equivalent_inputs]
        if config.get("order_sections") is False:
            equivalent_inputs = [path for path in equivalent_inputs if path != f"build/{version}/obj/sections.obj"]
        out += [
            "rule split",
            "  command = $python tools/split.py $version",
            "  description = SPLIT $version",
            "rule implib",
            "  command = $python tools/implib.py $in $out",
            "  description = IMPLIB $out",
            "rule link",
            "  command = $python tools/link.py $version $out $in",
            "  description = LINK $out",
            "rule report",
            "  command = build/tools/objdiff-cli report generate -o $out",
            "  description = REPORT $version",
            # (the Pro 5.3 compiler's download puts the license stub beside it)
            "build build/compilers/pro53/mwld.exe: download",
            "  tool = mwld",
            f"build build/{version}/obj/ok build/{version}/obj/sections.obj {' '.join(extra + split_objects)}: split | "
            f"{config['original']} config/{version}/config.json config/{version}/symbols.txt {splits} "
            "tools/split.py tools/pe.py",
            "build build/lmgr326b.lib: implib config/lmgr326b.def | tools/implib.py",
            *(f"build build/{Path(library).stem}.lib: implib {library} | tools/implib.py"
              for library in config.get("imports", []) if library.endswith(".def")),
            f"build build/{version}/{output} | build/{version}/ok: link {' '.join(inputs)} | "
            f"{TOOL_DEP}build/compilers/pro53/mwld.exe tools/link.py || lib/ok",
            f"build build/{version}/report.json: report | build/{version}/ok build/tools/objdiff-cli "
            f"{' '.join(objects)}",
        ]
        if equivalent and resource_source:
            out += [
                "rule rc",
                f"  command = {quote(LLVM_RC)} -C 1252 "
                "-no-preprocess -fo $out $in",
                "  description = RC $out",
                f"build build/{version}/compiled/resources.res: rc {resource_source}",
            ]
        if equivalent and assembled:
            out += [
                "rule assemble",
                f"  command = {quote(CLANG)} --target=i386-pc-windows-msvc -c $in -o $out",
                "  description = AS $out",
                *(f"build {assembled[path]}: assemble {source}" for path, source in config["assembly"].items()),
            ]
        if equivalent:
            out += [
                "rule link_equivalent",
                "  command = $python tools/link.py --equivalent $version $out $in",
                "  description = LINK $out",
                f"build build/{version}/equivalent/{output}: link_equivalent {' '.join(equivalent_inputs)} | "
                f"{TOOL_DEP}build/compilers/pro53/mwld.exe tools/link.py || lib/ok",
                f"build equivalent: phony build/{version}/equivalent/{output}",
            ]
        objdiff(version, config, sources, units)
    else:
        configs = (f"config/{version}/config.json config/{version}/functions.json config/{version}/bindings.json "
                   "config/sources.json")
        out += [
            "rule extract",
            "  command = $python tools/compare.py extract $version",
            "  description = EXTRACT $version",
            "rule compare",
            "  command = $python tools/compare.py compare $version",
            "  description = COMPARE $version",
            "rule report",
            "  command = $python tools/compare.py report $version",
            "  description = REPORT $version",
            f"build build/{version}/target/ok: extract | {config['original']} {configs} tools/compare.py tools/pe.py",
            f"build build/{version}/ok objdiff.json: compare | build/{version}/target/ok {' '.join(objects)}",
            f"build build/{version}/report.json: report | build/{version}/ok build/tools/objdiff-cli",
        ]
    out += [
        f"build all_source: phony {' '.join(objects)}",
        f"build progress: phony build/{version}/report.json",
        f"build build.ninja: configure | configure.py config/sources.json config/{version}/config.json"
        + (f" {splits}" if linking else ""),
        f"default build/{version}/ok all_source" + (" equivalent" if linking and equivalent else "")
        if not units_from else "default equivalent",
        "",
    ]
    Path("build.ninja").write_text("\n".join(out))


if __name__ == "__main__":
    main()
