//! Loading objects and archives, cutting sections into atoms, resolving symbols and dead stripping.
use crate::elf::{self, *};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

pub const BASE: u32 = 0x10000;
pub const ORDER: [&str; 22] = [
    ".compress.init", ".init", ".compress.text", ".text", ".compress.fini", ".fini", ".rodata", ".ctors", ".dtors",
    "extab", "extabindex", ".BINARY", ".data", ".got", ".sdata", ".sbss", ".sdata2", ".sbss2", ".PPC.EMB.sdata0",
    ".PPC.EMB.sbss0", ".bss", ".stack"];
const NOBITS: [&str; 4] = [".sbss", ".sbss2", ".PPC.EMB.sbss0", ".bss"];
const ACTIVE: u8 = 0x10;
const FORCE_ACTIVE: u8 = 0x08;     // `#pragma force_active`: the symbol's own atom is kept
/// Symbols that pull in the archive member defining them (the runtime's hooks).
const ARCHIVE_PULLS: [&str; 3] =
    ["__init_cpp_exceptions_reference", "__fini_cpp_exceptions_reference", "__destroy_global_chain_reference"];
/// The hooks that are roots of dead stripping (`__destroy_global_chain_reference` is not: nothing keeps it live).
const STRIP_ROOTS: [&str; 2] = [ARCHIVE_PULLS[0], ARCHIVE_PULLS[1]];
const LINKER_SYMBOLS: [&str; 17] = [
    "_SDA_BASE_", "_SDA2_BASE_", "_ABS_SDA_BASE_", "_ABS_SDA2_BASE_", "_stack_addr", "_stack_end", "_heap_addr",
    "_heap_end", "_nbfunctions", "SIZEOF_HEADERS", "_eti_init_info", "_ctors", "_ctors$99", "_dtors", "_dtors$99",
    "_rom_copy_info", "_bss_init_info"];

fn sized(s: &Symbol) -> bool {
    (s.typ == STT_OBJECT || s.typ == STT_FUNC) && s.size > 0
}

pub fn align(value: u32, to: u32) -> u32 {
    if to > 1 { value.wrapping_add(to - 1) & !(to - 1) } else { value }
}

pub fn is_nobits(name: &str) -> bool {
    NOBITS.contains(&name)
}

/// The output section an input section goes to (`.ctors$10` is part of `.ctors`).
pub fn output_name(name: &str) -> Option<&'static str> {
    for prefix in [".ctors", ".dtors"] {
        if name == prefix || name.starts_with(&format!("{prefix}$")) {
            return ORDER.iter().find(|&&o| o == prefix).copied();
        }
    }
    ORDER.iter().find(|&&o| o == name).copied()
}

pub struct Atom {
    pub obj: usize,
    pub sec: usize,
    pub start: u32,
    pub size: u32,
    pub align: u32,
    pub symbols: Vec<usize>,
    pub whole_section: bool,
    pub root: bool,
    pub live: bool,
    pub out_offset: u32,
    pub addr: u32,
}

impl Atom {
    pub fn contains(&self, offset: u32) -> bool {
        (self.start <= offset && offset < self.start + self.size) || (self.size == 0 && offset == self.start)
    }

    pub fn where_(&self, offset: u32) -> u32 {
        self.addr.wrapping_add(offset).wrapping_sub(self.start)
    }
}

pub struct Obj {
    pub name: String,
    pub elf: ElfFile,
    pub aligns: Vec<u32>,
    pub cmt: Vec<[u8; 8]>,                       // each symbol's 8 bytes of the `.comment` section
    pub archive: String,
    pub atoms: BTreeMap<usize, Vec<usize>>,      // section index -> atoms
    pub locals: HashMap<String, usize>,          // the local symbols the object defines, by name
    pub lost: HashSet<usize>,                    // weak definitions another object overrides
    pub relocs: HashMap<usize, Vec<Rela>>,       // section index -> the relocations that apply to it
}

impl Obj {
    /// How the map names the object: the member of an archive as 'archive member', else the file.
    pub fn label(&self) -> String {
        if self.archive.is_empty() { format!("{} ", self.name) } else { format!("{} {}", self.archive, self.name) }
    }

    /// Objects with a `.note.split` (dtk-generated) or a `.mwcats.text` keep their relocations in the output.
    pub fn keeps_relocs(&self) -> bool {
        self.has_cats() || self.elf.section(".note.split").is_some()
    }

    pub fn has_cats(&self) -> bool {
        self.elf.section(".mwcats.text").is_some()
    }

    pub fn sym(&self, i: usize) -> &Symbol {
        &self.elf.symbols[i]
    }
}

pub struct Link {
    pub entry: String,
    pub objs: Vec<Obj>,
    pub atoms: Vec<Atom>,
    pub defs: HashMap<String, (usize, usize)>,
    pub eh: bool,           // some exception table (extabindex) is live
    pub eti_ref: bool,      // some live code refers to `_eti_init_info`
    pub rom_ref: bool,      // some live code refers to `_rom_copy_info` or `_bss_init_info`
    pub partial: bool,                  // `-r`: relocatable output, nothing is stripped
    pub linker_refs: HashSet<String>,   // the symbols live code takes from the linker
    pub force_active: Vec<String>,  // symbols a linker command file keeps (FORCEACTIVE)
    pub assigned: HashSet<String>,  // symbols a linker command file defines
    pub referenced: HashSet<(usize, usize)>,    // the (object, symbol) pairs live code refers to
}

pub fn defined(s: &Symbol) -> bool {
    s.bind >= STB_GLOBAL && 0 < s.shndx && s.shndx < SHN_LORESERVE
}

fn linker_error(lines: &[String]) -> String {
    let mut all = vec!["### mwldeppc.exe Linker Error:".to_string()];
    all.extend_from_slice(lines);
    all.join("\n")
}

type Member = (String, String, Vec<u8>, ElfFile);

fn mark(atoms: &mut [Atom], work: &mut Vec<usize>, a: usize) {
    if !atoms[a].live {
        atoms[a].live = true;
        work.push(a);
    }
}

impl Link {
    pub fn new(entry: &str, inputs: &[String], plan: &crate::layout::Plan) -> R<Link> {
        let mut link = Link { entry: entry.into(), objs: vec![], atoms: vec![], defs: HashMap::new(), eh: false, eti_ref: false, rom_ref: false, partial: plan.partial, linker_refs: HashSet::new(),
                                referenced: HashSet::new(),
                                force_active: plan.force_active.clone(),
                                assigned: plan.assigns.iter().map(|a| a.0.clone()).collect() };
        let mut archives: Vec<Vec<Member>> = vec![];
        for path in inputs {
            let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            let name = Path::new(path).file_name().unwrap().to_string_lossy().to_string();
            if data.starts_with(b"!<arch>\n") {
                let mut members = vec![];
                for (member, bytes) in elf::archive_members(&data)? {
                    let parsed = elf::parse(&bytes, &member)?;
                    members.push((name.clone(), member, bytes, parsed));
                }
                archives.push(members);
            } else {
                link.load_object(&name, &data, "")?;
            }
        }
        loop {
            link.resolve();
            let mut wanted: HashSet<String> = link.objs.iter().flat_map(|o| o.elf.symbols.iter())
                .filter(|s| s.shndx == 0 && s.bind >= STB_GLOBAL && !s.name.is_empty()).map(|s| s.name.clone()).collect();
            wanted.insert(link.entry.clone());
            wanted.extend(ARCHIVE_PULLS.iter().map(|s| s.to_string()));
            wanted.extend(link.force_active.iter().cloned());
            wanted.retain(|n| !link.defs.contains_key(n));
            let found = archives.iter().enumerate().find_map(|(a, members)| {
                members.iter().position(|m| m.3.symbols.iter().any(|s| defined(s) && wanted.contains(&s.name)))
                    .map(|m| (a, m))
            });
            let Some((a, m)) = found else { break };
            let (archive, name, bytes, _) = archives[a].remove(m);
            link.load_object(&name, &bytes, &archive)?;
        }
        link.strip()?;
        Ok(link)
    }

    fn load_object(&mut self, name: &str, data: &[u8], archive: &str) -> R<()> {
        let mut e = elf::parse(data, name)?;
        // common symbols go to a `.bss` of their own for the object, laid out after every other `.bss`
        let commons: Vec<usize> = e.symbols.iter().filter(|s| s.shndx == SHN_COMMON).map(|s| s.index).collect();
        if !commons.is_empty() {
            let (index, mut size, mut widest) = (e.sections.len(), 0, 1);
            for i in commons {
                let s = &mut e.symbols[i];
                let alignment = s.value.max(1);
                size = align(size, alignment);
                widest = widest.max(alignment);
                (s.value, s.shndx) = (size, index as u16);
                size += s.size;
            }
            e.sections.push(Section { index, name: ".bss".into(), typ: SHT_NOBITS, flags: SHF_ALLOC | 1, size, info: 0,
                                      align: widest, data: vec![], synthetic: true });
        }
        let comment = e.section(".comment").ok_or(format!(
            "{name}: no .comment section (assembler output?); the symbols' alignments and flags are not known"))?;
        let (mut aligns, mut flags) = (vec![0u32; e.symbols.len()], vec![0u8; e.symbols.len()]);
        for i in 0..e.symbols.len() {
            if 52 + 8 * i <= comment.data.len() {
                aligns[i] = be32(&comment.data, 44 + 8 * i);
                flags[i] = comment.data[44 + 8 * i + 5];
            }
        }
        let cmt = (0..e.symbols.len())
            .map(|i| comment.data.get(44 + 8 * i..52 + 8 * i).map_or([0; 8], |b| b.try_into().unwrap())).collect();
        let obj_index = self.objs.len();
        let mut atoms: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for section in &e.sections {
            if section.flags & SHF_ALLOC == 0 || (section.typ != SHT_PROGBITS && section.typ != SHT_NOBITS) {
                continue;
            }
            if output_name(&section.name).is_none() {
                return Err(format!("unsupported input section '{}' in {name}", section.name));
            }
            let here: Vec<&Symbol> =
                e.symbols.iter().filter(|s| s.shndx as usize == section.index && s.typ != STT_SECTION).collect();
            let mut sized: Vec<&Symbol> =
                here.iter().copied().filter(|s| (s.typ == STT_OBJECT || s.typ == STT_FUNC) && s.size > 0).collect();
            let new = |start, size, align, symbols, whole_section| Atom {
                obj: obj_index, sec: section.index, start, size, align, symbols, whole_section, root: false, live: false, out_offset: 0,
                addr: 0 };
            let mut list: Vec<Atom> = vec![];
            // (a compiler mark such as `...data.0`, any symbol named `...`, makes the section one atom that lives or dies together)
            if sized.is_empty() || here.iter().any(|s| flags[s.index] & ACTIVE != 0 || s.name.starts_with("...")) {
                list.push(new(0, section.size, section.align, here.iter().map(|s| s.index).collect(), true));
            } else {
                sized.sort_by_key(|s| (s.value, s.index));
                for s in sized {
                    match list.last_mut() {
                        Some(last) if (last.start, last.size) == (s.value, s.size) => last.symbols.push(s.index),
                        _ => list.push(new(s.value, s.size, aligns[s.index].max(1), vec![s.index], false)),
                    }
                }
                for s in here.iter().filter(|s| s.size == 0) {
                    if let Some(owner) = list.iter_mut().find(|a| a.contains(s.value)) {
                        owner.symbols.push(s.index);
                    }
                }
            }
            for atom in list.iter_mut() {
                atom.root = atom.symbols.iter().any(|&s| flags[s] & FORCE_ACTIVE != 0);
            }
            let ids = list.into_iter().map(|a| { self.atoms.push(a); self.atoms.len() - 1 }).collect();
            atoms.insert(section.index, ids);
        }
        let locals = e.symbols.iter().filter(|s| s.bind == STB_LOCAL && s.shndx != 0 && s.shndx < SHN_LORESERVE
                                                   && s.typ != STT_SECTION && s.typ != STT_FILE)
            .map(|s| (s.name.clone(), s.index)).collect();
        let relocs = e.sections.iter().filter(|s| s.flags & SHF_ALLOC != 0).map(|s| (s.index, e.relocs(s.index))).collect();
        self.objs.push(Obj { name: name.into(), elf: e, aligns, cmt, archive: archive.into(), atoms, lost: HashSet::new(), relocs, locals });
        Ok(())
    }

    fn resolve(&mut self) {
        self.defs.clear();
        for (o, obj) in self.objs.iter().enumerate() {
            for s in obj.elf.symbols.iter().filter(|s| defined(s) && !s.name.is_empty()) {
                let replace = match self.defs.get(&s.name) {
                    None => true,
                    Some(&(po, ps)) => self.objs[po].elf.symbols[ps].bind == STB_WEAK && s.bind == STB_GLOBAL,
                };
                if replace {
                    self.defs.insert(s.name.clone(), (o, s.index));
                }
            }
        }
        for o in 0..self.objs.len() {
            let lost = self.objs[o].elf.symbols.iter()
                .filter(|s| defined(s) && self.defs.get(&s.name) != Some(&(o, s.index))).map(|s| s.index).collect();
            self.objs[o].lost = lost;
        }
    }

    /// The (object, symbol) a symbol of `obj` stands for, or None for a linker symbol.
    pub fn lookup(&self, obj: usize, sym: usize) -> Option<(usize, usize)> {
        let s = self.objs[obj].sym(sym);
        if s.shndx == 0 || (s.bind >= STB_GLOBAL && self.objs[obj].lost.contains(&sym)) {
            // (a reference the object itself defines as a local, which assembler output can have, binds to that)
            self.defs.get(&s.name).copied().or_else(|| self.objs[obj].locals.get(&s.name).map(|&l| (obj, l)))
        } else {
            Some((obj, sym))
        }
    }

    /// The atom a defined symbol of object `o` lies in.
    pub fn atom_of(&self, o: usize, s: &Symbol) -> Option<&Atom> {
        self.objs[o].atoms.get(&(s.shndx as usize))?.iter().map(|&a| &self.atoms[a]).find(|a| a.contains(s.value))
    }

    /// Whether a defined symbol of object `o` goes to the output symbol table: it is not overridden, and a global without
    /// a size (such as the `_savefpr_N` entry points inside `__save_fpr`) stays only if code refers to it.
    pub fn emits_symbol(&self, o: usize, s: &Symbol) -> bool {
        defined(s) && !self.objs[o].lost.contains(&s.index) && (s.size > 0 || self.referenced.contains(&(o, s.index)))
    }

    /// The (atom, offset in its section) a relocation against symbol + addend reaches.
    pub fn target(&self, obj: usize, sym: usize, addend: i32) -> Option<(usize, u32)> {
        let (o, si) = self.lookup(obj, sym)?;
        let s = self.objs[o].sym(si);
        if s.shndx >= SHN_LORESERVE {
            return None;
        }
        let offset = if s.typ == STT_SECTION { s.value.wrapping_add(addend as u32) } else { s.value };
        self.objs[o].atoms.get(&(s.shndx as usize))?.iter()
            .find(|&&a| self.atoms[a].contains(offset)).map(|&a| (a, offset))
    }

    pub fn relocs(&self, atom: usize) -> Vec<Rela> {
        let a = &self.atoms[atom];
        self.objs[a.obj].relocs.get(&a.sec).into_iter().flatten().filter(|r| a.contains(r.offset)).cloned().collect()
    }

    pub fn section_name(&self, atom: usize) -> &str {
        let a = &self.atoms[atom];
        &self.objs[a.obj].elf.sections[a.sec].name
    }

    /// Notes the symbols the live code refers to.
    fn record_references(&mut self) {
        for a in (0..self.atoms.len()).filter(|&a| self.atoms[a].live) {
            for r in self.relocs(a) {
                let found = self.lookup(self.atoms[a].obj, r.sym);
                self.referenced.extend(found);
            }
        }
    }

    fn strip(&mut self) -> R<()> {
        if self.partial {
            self.atoms.iter_mut().for_each(|a| a.live = true);
            // (unreferenced global data with sized symbols is dropped even here)
            let mut used = vec![false; self.atoms.len()];
            for a in 0..self.atoms.len() {
                for r in self.relocs(a) {
                    if let Some((t, _)) = self.target(self.atoms[a].obj, r.sym, r.addend) {
                        used[t] = true;
                    }
                }
            }
            for a in 0..self.atoms.len() {
                let atom = &self.atoms[a];
                let o = atom.obj;
                let name = &self.objs[o].elf.sections[atom.sec].name;
                let data = output_name(name).map_or(false, |n| !matches!(n, ".text" | ".init" | ".ctors" | ".dtors"));
                if data && !used[a] && !atom.whole_section && atom.symbols.iter().any(|&s| sized(self.objs[o].sym(s))) {
                    self.atoms[a].live = false;
                }
            }
            self.record_references();
            return Ok(());
        }
        if !self.defs.contains_key(&self.entry) {
            return Err(linker_error(&[format!("#   undefined: '{}'", self.entry),
                                      "#   Referenced from <entry point>".into()]));
        }
        let mut work: Vec<usize> = vec![];
        for a in 0..self.atoms.len() {
            // (a root that another object's definition overrides is dropped)
            let overridden = self.atoms[a].symbols.iter().any(|s| self.objs[self.atoms[a].obj].lost.contains(s));
            if self.atoms[a].root && !overridden {
                mark(&mut self.atoms, &mut work, a);
            }
        }
        let roots: Vec<String> = std::iter::once(self.entry.clone()).chain(STRIP_ROOTS.map(String::from))
            .chain(self.force_active.iter().cloned()).collect();
        for name in &roots {
            if let Some(&(o, s)) = self.defs.get(name) {
                let (a, _) = self.target(o, s, 0).ok_or(format!("no code for '{name}'"))?;
                mark(&mut self.atoms, &mut work, a);
            }
        }
        loop {
            while let Some(a) = work.pop() {
                let obj = self.atoms[a].obj;
                for r in self.relocs(a) {
                    if let Some((t, _)) = self.target(obj, r.sym, r.addend) {
                                        mark(&mut self.atoms, &mut work, t);
                        continue;
                    }
                    let s = self.objs[obj].sym(r.sym);
                    if s.shndx == 0 && !self.defs.contains_key(&s.name) && s.bind != STB_WEAK
                        && !LINKER_SYMBOLS.contains(&s.name.as_str()) && !self.assigned.contains(&s.name) && !crate::layout::is_section_symbol(&s.name) {
                        let from = self.atoms[a].symbols.first().map_or(self.section_name(a), |&s| &self.objs[obj].sym(s).name);
                        return Err(linker_error(&[format!("#   undefined: '{}'", s.name),
                            format!("#   Referenced from '{}' in {}", from, self.objs[obj].name)]));
                    }
                }
            }
            // constructors, destructors and active data of a live object stay (an object nothing needs is dropped whole)
            for o in 0..self.objs.len() {
                let ids: Vec<usize> = self.objs[o].atoms.values().flatten().copied().collect();
                if !ids.iter().any(|&a| self.atoms[a].live) {
                    continue;
                }
                for a in ids {
                    let atom = &self.atoms[a];
                    let section = &self.objs[o].elf.sections[atom.sec].name;
                    // (a whole-section atom with no sized symbol stays, e.g. a hook section; active data that has sized
                    // symbols is dropped like any other; so are the constructors and destructors of a dead object)
                    let bare = atom.whole_section && atom.size > 0
                        && !atom.symbols.iter().any(|&s| sized(self.objs[o].sym(s)));
                    if (bare || matches!(output_name(section), Some(".ctors") | Some(".dtors")))
                        && !atom.symbols.iter().any(|s| self.objs[o].lost.contains(s)) {
                        mark(&mut self.atoms, &mut work, a);
                    }
                }
            }
            // an extabindex entry lives when the function it describes does
            for o in 0..self.objs.len() {
                let Some(index) = self.objs[o].elf.sections.iter().position(|s| s.name == "extabindex") else { continue };
                for a in self.objs[o].atoms.get(&index).cloned().unwrap_or_default() {
                    let first = self.relocs(a).into_iter().next();
                    let found = first.and_then(|r| self.target(o, r.sym, r.addend));
                    if found.map_or(false, |(t, _)| self.atoms[t].live) {
                        mark(&mut self.atoms, &mut work, a);
                    }
                }
            }
            if work.is_empty() {
                break;
            }
        }
        let live = |a: &&Atom| a.live;
        self.eh = self.atoms.iter().filter(live).any(|a| self.objs[a.obj].elf.sections[a.sec].name == "extabindex");
        for a in (0..self.atoms.len()).filter(|&a| self.atoms[a].live) {
            for r in self.relocs(a) {
                let obj = self.atoms[a].obj;
                let s = self.objs[obj].sym(r.sym);
                if s.shndx != 0 || self.defs.contains_key(&s.name) || self.objs[obj].locals.contains_key(&s.name) {
                    continue;
                }
                match s.name.as_str() {
                    "_eti_init_info" => self.eti_ref = true,
                    "_rom_copy_info" | "_bss_init_info" => self.rom_ref = true,
                    "_ctors" | "_ctors$99" | "_dtors" | "_dtors$99" => {}
                    _ if s.bind != STB_WEAK => {
                        self.linker_refs.insert(s.name.clone());
                    }
                    _ => {}
                }
            }
        }
        self.record_references();
        self.referenced.extend(self.defs.get(&self.entry).copied());
        if self.eh && !self.defs.contains_key("__init_cpp_exceptions") {
            return Err(linker_error(&["#   undefined: '__init_cpp_exceptions'".into(),
                "#   Referenced from '__init_cpp_exceptions_reference' in Linker Generated".into(),
                "#   Symbol File".into()]));
        }
        Ok(())
    }
}
