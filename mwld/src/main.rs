//! mwld [-nostdlib] -m ENTRY [-map FILE] -o OUTPUT INPUT...: a replica of the GC 2.7 linker (mwldeppc.exe, Metrowerks
//! Linker 3.0.4), with or without a linker command file (`-lcf`). What it knows was found by linking programs with the
//! real linker (docs/linker/README.md); it stops with an error on what it does not know: overlays,
//! `-sym`, DWARF merging. `-g` is accepted and ignored; `-mapunused` adds the UNUSED rows to the map (the
//! map then has no UNUSED rows).
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
    let mut generate = false;
    let mut strip_partial = false;
    let mut args: Vec<String> = args.to_vec();
    let mut expanded: Vec<String> = vec![];
    // `@file` holds more arguments, one per line (or space separated)
    while let Some(at) = args.iter().position(|a| a.starts_with('@')) {
        let path = args[at][1..].to_string();
        if expanded.len() >= 64 {
            return Err(format!("{path}: response files nest too deeply"));
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
            "-r1" => {
                partial = true;
                generate = true;
            }
            "-strip_partial" => strip_partial = true,
            "-fp" | "-sdata" | "-sdata2" => {
                value()?;
            }
            "-nostdlib" | "-nodefaults" | "-g" => {}
            "-mapunused" => map_unused = true,
            _ if a.starts_with('-') => return Err(format!("unsupported option '{a}'")),
            _ => inputs.push(a.to_string()),
        }
        i += 1;
    }
    if strip_partial && !generate {
        return Err("-strip_partial only has an effect with -r1 here".into());
    }
    // (a plain `-r` link ignores the command file)
    let plan = match lcf.filter(|_| !partial || generate) {
        Some(path) => layout::Plan::from_lcf(lcf::parse(&read_text(&path)?)?)?,
        None => layout::Plan::default_plan(),
    };
    let mut plan = plan;
    plan.partial = partial;
    plan.strip_partial = strip_partial;
    plan.generate = generate;
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
