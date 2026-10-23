//! Loading objects and archives, cutting sections into atoms, resolving symbols and dead stripping.
use crate::elf::{self, be32, ElfFile, Symbol, R};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

pub const BASE: u32 = 0x10000;
pub const ORDER: [&str; 21] = [
    ".compress.init", ".init", ".compress.text", ".text", ".compress.fini", ".fini", ".rodata", ".ctors", ".dtors",
    "extab", "extabindex", ".BINARY", ".data", ".got", ".sdata", ".sbss", ".sdata2", ".sbss2", ".PPC.EMB.sdata0",
    ".PPC.EMB.sbss0", ".bss"];
const NOBITS: [&str; 4] = [".sbss", ".sbss2", ".PPC.EMB.sbss0", ".bss"];
const ACTIVE: u8 = 0x10;
const FORCE_ACTIVE: u8 = 0x08;     // `#pragma force_active`: the symbol's own atom is kept
const RUNTIME_ROOTS: [&str; 3] =
    ["__init_cpp_exceptions_reference", "__fini_cpp_exceptions_reference", "__destroy_global_chain_reference"];
const LINKER_SYMBOLS: [&str; 15] = [
    "_SDA_BASE_", "_SDA2_BASE_", "_ABS_SDA_BASE_", "_ABS_SDA2_BASE_", "_stack_addr", "_stack_end", "_heap_addr",
    "_heap_end", "_nbfunctions", "SIZEOF_HEADERS", "_eti_init_info", "_ctors", "_ctors$99", "_dtors", "_dtors$99"];

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
    pub forced: bool,
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
    pub archive: String,
    pub atoms: BTreeMap<usize, Vec<usize>>,      // section index -> atoms
    pub lost: HashSet<usize>,                    // weak definitions another object overrides
}

impl Obj {
    /// How the map names the object: the member of an archive as 'archive member', else the file.
    pub fn label(&self) -> String {
        if self.archive.is_empty() { format!("{} ", self.name) } else { format!("{} {}", self.archive, self.name) }
    }

    pub fn has_cats(&self) -> bool {
        self.elf.section(".mwcats.text").is_some()
    }

    pub fn sym(&self, i: usize) -> &Symbol {
        &self.elf.symbols[i]
    }
}

pub struct Rel {
    pub offset: u32,
    pub sym: usize,
    pub kind: u8,
    pub addend: i32,
}

pub struct Link {
    pub entry: String,
    pub objs: Vec<Obj>,
    pub atoms: Vec<Atom>,
    pub defs: HashMap<String, (usize, usize)>,
    pub eh: bool,           // some exception table (extabindex) is live
    pub eti_ref: bool,      // some live code refers to `_eti_init_info`
}

fn defined(s: &Symbol) -> bool {
    s.bind >= 1 && 0 < s.shndx && s.shndx < 0xFF00
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
    pub fn new(entry: &str, inputs: &[String]) -> R<Link> {
        let mut link = Link { entry: entry.into(), objs: vec![], atoms: vec![], defs: HashMap::new(), eh: false, eti_ref: false };
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
                .filter(|s| s.shndx == 0 && s.bind >= 1 && !s.name.is_empty()).map(|s| s.name.clone()).collect();
            wanted.insert(link.entry.clone());
            wanted.extend(RUNTIME_ROOTS.iter().map(|s| s.to_string()));
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
        let e = elf::parse(data, name)?;
        let comment = e.section(".comment").ok_or(format!(
            "{name}: no .comment section (assembler output?); the symbols' alignments and flags are not known"))?;
        let (mut aligns, mut flags) = (vec![0u32; e.symbols.len()], vec![0u8; e.symbols.len()]);
        for i in 0..e.symbols.len() {
            if 52 + 8 * i <= comment.data.len() {
                aligns[i] = be32(&comment.data, 44 + 8 * i);
                flags[i] = comment.data[44 + 8 * i + 5];
            }
        }
        let obj_index = self.objs.len();
        let mut atoms: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for section in &e.sections {
            if section.flags & 2 == 0 || (section.typ != 1 && section.typ != 8) {
                continue;
            }
            if output_name(&section.name).is_none() {
                return Err(format!("unsupported input section '{}' in {name}", section.name));
            }
            let here: Vec<&Symbol> =
                e.symbols.iter().filter(|s| s.shndx as usize == section.index && s.typ != 3).collect();
            let mut sized: Vec<&Symbol> =
                here.iter().copied().filter(|s| (s.typ == 1 || s.typ == 2) && s.size > 0).collect();
            let new = |start, size, align, symbols, forced| Atom {
                obj: obj_index, sec: section.index, start, size, align, symbols, forced, root: false, live: false, out_offset: 0,
                addr: 0 };
            let mut list: Vec<Atom> = vec![];
            if sized.is_empty() || here.iter().any(|s| flags[s.index] & ACTIVE != 0) {
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
        self.objs.push(Obj { name: name.into(), elf: e, aligns, archive: archive.into(), atoms, lost: HashSet::new() });
        Ok(())
    }

    fn resolve(&mut self) {
        self.defs.clear();
        for (o, obj) in self.objs.iter().enumerate() {
            for s in obj.elf.symbols.iter().filter(|s| defined(s) && !s.name.is_empty()) {
                let replace = match self.defs.get(&s.name) {
                    None => true,
                    Some(&(po, ps)) => self.objs[po].elf.symbols[ps].bind == 2 && s.bind == 1,
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
        if s.shndx == 0 || (s.bind >= 1 && self.objs[obj].lost.contains(&sym)) {
            self.defs.get(&s.name).copied()
        } else {
            Some((obj, sym))
        }
    }

    /// The (atom, offset in its section) a relocation against symbol + addend reaches.
    pub fn target(&self, obj: usize, sym: usize, addend: i32) -> Option<(usize, u32)> {
        let (o, si) = self.lookup(obj, sym)?;
        let s = self.objs[o].sym(si);
        if s.shndx >= 0xFF00 {
            return None;
        }
        let offset = if s.typ == 3 { s.value.wrapping_add(addend as u32) } else { s.value };
        self.objs[o].atoms.get(&(s.shndx as usize))?.iter()
            .find(|&&a| self.atoms[a].contains(offset)).map(|&a| (a, offset))
    }

    pub fn relocs(&self, atom: usize) -> Vec<Rel> {
        let a = &self.atoms[atom];
        self.objs[a.obj].elf.relocs(a.sec).into_iter().filter(|r| a.contains(r.offset))
            .map(|r| Rel { offset: r.offset, sym: r.sym, kind: r.kind, addend: r.addend }).collect()
    }

    pub fn section_name(&self, atom: usize) -> &str {
        let a = &self.atoms[atom];
        &self.objs[a.obj].elf.sections[a.sec].name
    }

    fn strip(&mut self) -> R<()> {
        if !self.defs.contains_key(&self.entry) {
            return Err(linker_error(&[format!("#   undefined: '{}'", self.entry),
                                      "#   Referenced from <entry point>".into()]));
        }
        let mut work: Vec<usize> = vec![];
        for obj in &self.objs {
            for ids in obj.atoms.values() {
                for &a in ids {
                    let atom = &self.atoms[a];
                    if atom.forced || atom.root {
                        mark(&mut self.atoms, &mut work, a);
                    }
                }
            }
        }
        for name in std::iter::once(self.entry.as_str()).chain(RUNTIME_ROOTS.into_iter().filter(|n| *n != RUNTIME_ROOTS[2])) {
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
                    if s.shndx == 0 && !self.defs.contains_key(&s.name) && s.bind != 2
                        && !LINKER_SYMBOLS.contains(&s.name.as_str()) && !s.name.starts_with("_f_")
                        && !s.name.starts_with("_e_") {
                        let from = &self.objs[obj].sym(self.atoms[a].symbols[0]).name;
                        return Err(linker_error(&[format!("#   undefined: '{}'", s.name),
                            format!("#   Referenced from '{}' in {}", from, self.objs[obj].name)]));
                    }
                }
            }
            // constructors and destructors a live object registers run (an object nothing needs is dropped whole)
            for o in 0..self.objs.len() {
                let ids: Vec<usize> = self.objs[o].atoms.values().flatten().copied().collect();
                if !ids.iter().any(|&a| self.atoms[a].live) {
                    continue;
                }
                for a in ids {
                    let atom = &self.atoms[a];
                    let section = &self.objs[o].elf.sections[atom.sec].name;
                    if matches!(output_name(section), Some(".ctors") | Some(".dtors"))
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
        self.eti_ref = (0..self.atoms.len()).filter(|&a| self.atoms[a].live).any(|a| {
            self.relocs(a).iter().any(|r| {
                let s = self.objs[self.atoms[a].obj].sym(r.sym);
                s.shndx == 0 && s.name == "_eti_init_info"
            })
        });
        if self.eh && !self.defs.contains_key("__init_cpp_exceptions") {
            return Err(linker_error(&["#   undefined: '__init_cpp_exceptions'".into(),
                "#   Referenced from '__init_cpp_exceptions_reference' in Linker Generated".into(),
                "#   Symbol File".into()]));
        }
        Ok(())
    }
}
