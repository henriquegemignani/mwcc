//! mwld [-nostdlib] -m ENTRY [-map FILE] -o OUTPUT INPUT...: a replica of the GC 2.7 linker (mwldeppc.exe, Metrowerks
//! Linker 3.0.4), with or without a linker command file (`-lcf`). What it knows was found by linking programs with the
//! real linker (docs/linker/README.md); it stops with an error on what it does not know: overlays,
//! `-sym`, DWARF merging. `-Ldir` and `-lname` search for libraries. `-g` is accepted and ignored; `-mapunused` adds the
//! UNUSED rows to the map (without it the map has none). `-r`, `-r1`, `-strip_partial`, `-fp` and `-sdata` as the real
//! linker has them.
//!
//! * An input section is cut into atoms, one per sized symbol (the symbol's alignment is in the object's `.comment`); a
//!   section with a symbol the compiler marked active (`...data.0`) is one atom.
//! * Atoms nothing refers to are dropped. The roots are the entry point, the atoms of symbols marked `force_active`
//!   and the C++ runtime's init and fini `*_reference` symbols; constructors, destructors and hook sections stay
//!   only in objects that are otherwise live.
//! * The output sections go from 0x10000 in the default order (or where the command file says), relocations are
//!   applied, and the ELF and the link map are written.
mod elf;
mod layout;
mod lcf;
mod link;
mod map;
mod writer;

fn read_text(path: &str) -> elf::R<String> {
    Ok(elf::latin1(&std::fs::read(path).map_err(|e| format!("{path}: {e}"))?))
}

fn run(args: &[String]) -> elf::R<()> {
    let (mut entry, mut map_file, mut output, mut inputs) = ("__start".to_string(), None, "a.out".to_string(), vec![]);
    let mut map_unused = false;
    let mut lcf: Option<String> = None;
    let mut partial = false;
    // `-Ldir` and `-lname`: the library is looked for only in the `-L` directories (not the current one), as
    // `libname.dylib`, `libname.a` or `name`; it stands where the `-l` was among the inputs
    let (mut dirs, mut libs): (Vec<String>, Vec<(usize, String)>) = (vec![], vec![]);
    let mut generate = false;
    let mut strip_partial = false;
    let mut fp = 1u8;
    let mut args: Vec<String> = args.to_vec();
    let mut expanded: Vec<String> = vec![];
    // `@file` holds more arguments, one per line (or space separated)
    while let Some(at) = args.iter().position(|a| a.starts_with('@')) {
        let path = args[at][1..].to_string();
        if expanded.len() >= 64 {
            return Err(format!("{path}: too many response files"));
        }
        expanded.push(path.clone());
        let text = read_text(&path)?;
        args.splice(at..=at, text.split_whitespace().map(String::from));
    }
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut value = || -> elf::R<String> {
            i += 1;
            args.get(i).cloned().ok_or(format!("{a}: missing value"))
        };
        match a {
            "-m" | "-main" => entry = value()?,
            "-map" => map_file = Some(value()?),
            "-o" => output = value()?,
            "-lcf" => lcf = Some(value()?),
            "-r" => partial = true,
            "-r1" | "-opt_partial" => {
                partial = true;
                generate = true;
            }
            "-strip_partial" => strip_partial = true,
            "-fp" => {
                fp = match value()?.as_str() {
                    "hardware" | "hard" => 2,
                    "none" | "off" => 0,
                    "soft" | "software" => 1,
                    // (a partial link records these in `.comment`: `fmadd` as hardware, `efpu` and `spfp` as 3)
                    "fmadd" => 2,
                    "efpu" | "spfp" => 3,
                    other => return Err(format!("Unknown option '{other}'; expected one of 'none|off, soft[ware], hard[ware], efpu|spfp, or fmadd'")),
                }
            }
            "-sdata" | "-sdata2" => {
                value()?;
            }
            "-nostdlib" | "-nodefaults" | "-g" => {}
            "-mapunused" => map_unused = true,
            _ if a.starts_with("-L") && a.len() > 2 => dirs.push(a[2..].to_string()),
            "-L" => return Err("Argument(s) expected
while parsing option '-L'".into()),
            "-listclosure" | "-listdwarf" => return Err(format!("unsupported option '{a}'")),
            _ if a.starts_with("-l") && a.len() > 2 => {
                libs.push((inputs.len(), a[2..].to_string()));
            }
            _ if a.starts_with('-') => return Err(format!("unsupported option '{a}'")),
            _ => inputs.push(a.to_string()),
        }
        i += 1;
    }
    for (n, (at, name)) in libs.iter().enumerate() {
        let found = dirs.iter().find_map(|d| {
            [format!("lib{name}.dylib"), format!("lib{name}.a"), name.clone()]
                .iter().map(|f| std::path::Path::new(d).join(f)).find(|p| p.is_file())
        });
        let path = found.ok_or(format!("No library file found matching 'lib{name}{{.dylib|.a}}' or '{name}'"))?;
        inputs.insert(at + n, path.to_string_lossy().into_owned());
    }
    if strip_partial && !generate {
        return Err("-strip_partial only has an effect with -r1 here".into());
    }
    // (a plain `-r` link ignores the command file)
    let mut plan = match lcf.filter(|_| !partial || generate) {
        Some(path) => layout::Plan::from_lcf(lcf::parse(&read_text(&path)?)?)?,
        None => layout::Plan::default_plan(),
    };
    plan.partial = partial;
    plan.strip_partial = strip_partial;
    plan.generate = generate;
    plan.fp = fp;
    let mut linked = link::Link::new(&entry, &inputs, &plan)?;
    let lay = layout::Layout::new(&mut linked, &plan)?;
    let image = writer::build(&linked, &lay)?;
    std::fs::write(&output, image).map_err(|e| format!("{output}: {e}"))?;
    if let Some(path) = map_file {
        std::fs::write(&path, elf::to_latin1(&map::write_map(&linked, &lay, map_unused))).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(message) = run(&args) {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
