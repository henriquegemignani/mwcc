//! Section contents, relocations, the symbol table and the output ELF file.
use crate::elf::*;
use crate::layout::{init_info_sections, oi, section_symbol_names, Layout, Piece};
use crate::link::{align, is_nobits, output_name, Link, ORDER};
use std::collections::{HashMap, HashSet};

struct Ent {
    name: String,
    value: u32,
    size: u32,
    info: u8,
    shndx: u16,
}

type Retained = (usize, u32, usize, u8, i32);      // (atom, offset, symbol, type, addend)

fn put32(buf: &mut [u8], pos: usize, v: u32) {
    buf[pos..pos + 4].copy_from_slice(&v.to_be_bytes());
}

fn put16(buf: &mut [u8], pos: usize, v: u32) {
    buf[pos..pos + 2].copy_from_slice(&(v as u16).to_be_bytes());
}

fn push32(out: &mut Vec<u8>, values: &[u32]) {
    for v in values {
        out.extend_from_slice(&v.to_be_bytes());
    }
}

const EHDR_SIZE: u32 = 52;
const PHDR_SIZE: u32 = 32;
const SHDR_SIZE: u32 = 40;

/// A section header; fields not named stay 0.
#[derive(Default)]
struct SecHeader {
    name: u32,
    kind: u32,
    flags: u32,
    addr: u32,
    off: u32,
    size: u32,
    link: u32,
    info: u32,
    align: u32,
    entsize: u32,
}

impl SecHeader {
    fn bytes(&self) -> Vec<u8> {
        let mut out = vec![];
        push32(&mut out, &[self.name, self.kind, self.flags, self.addr, self.off, self.size, self.link, self.info,
                           self.align, self.entsize]);
        out
    }
}

/// The live (size word, atom, offset) entries of an object's .mwcats.text.
fn cats_entries(link: &Link, o: usize) -> Vec<([u8; 4], usize, u32)> {
    let obj = &link.objs[o];
    let section = obj.elf.section(".mwcats.text").unwrap();
    let relas = obj.elf.relocs(section.index);
    let mut out = vec![];
    for i in 0..section.data.len() / 8 {
        let target = relas.iter().filter(|r| r.offset as usize == 8 * i + 4)
            .last().and_then(|r| link.target(o, r.sym, r.addend));
        if let Some((atom, offset)) = target {
            if link.atoms[atom].live {
                out.push((section.data[8 * i..8 * i + 4].try_into().unwrap(), atom, offset));
            }
        }
    }
    out
}

/// The relocations kept in the output, by output section: those of the objects with a `.mwcats.text` or `.note.split`.
fn retained_relocs(link: &Link, lay: &Layout) -> Vec<Vec<Retained>> {
    let mut out: Vec<Vec<Retained>> = vec![vec![]; ORDER.len()];
    for &i in &lay.nonempty {
        for piece in &lay.pieces[i] {
            if piece.obj.map_or(false, |o| link.partial || link.objs[o].keeps_relocs()) {
                for &a in &piece.atoms {
                    for r in link.relocs(a) {
                        out[i].push((a, r.offset, r.sym, r.kind, r.addend));
                    }
                }
            }
        }
        // (the compiler may write them in any order; the linker's are by address)
        out[i].sort_by_key(|r| link.atoms[r.0].where_(r.1));
    }
    out
}

fn symbol_addr(link: &Link, lay: &Layout, obj: usize, sym: usize, addend: i32) -> R<(u32, Option<&'static str>)> {
    if let Some((atom, offset)) = link.target(obj, sym, addend) {
        return Ok((link.atoms[atom].where_(offset), output_name(link.section_name(atom))));
    }
    let s = link.objs[obj].sym(sym);
    if let Some(&v) = lay.sym_map.get(&s.name) {
        return Ok((v, None));
    }
    if let Some(v) = lay.gen_addr(&s.name) {
        return Ok((v, None));
    }
    if s.bind == STB_WEAK {
        return Ok((0, None));
    }
    Err(format!("undefined: '{}'", s.name))
}

fn apply_relocs(link: &Link, lay: &Layout, data: &mut [Vec<u8>]) -> R<()> {
    for &i in &lay.nonempty {
        for piece in &lay.pieces[i] {
            for &a in &piece.atoms {
                let atom = &link.atoms[a];
                for r in link.relocs(a) {
                    let (s, tsec) = symbol_addr(link, lay, atom.obj, r.sym, r.addend)?;
                    let section_symbol = link.objs[atom.obj].sym(r.sym).typ == STT_SECTION;
                    let value = if section_symbol { s } else { s.wrapping_add(r.addend as u32) };
                    let pos = (atom.out_offset + r.offset - atom.start) as usize;
                    let p = atom.addr + r.offset - atom.start;
                    let buf = &mut data[i];
                    match r.kind {
                        R_PPC_ADDR32 => put32(buf, pos, value),
                        R_PPC_ADDR16 | R_PPC_ADDR16_LO => put16(buf, pos, value),
                        R_PPC_ADDR16_HI => put16(buf, pos, value >> 16),
                        R_PPC_ADDR16_HA => put16(buf, pos, value.wrapping_add(0x8000) >> 16),
                        R_PPC_REL24 => { let w = be32(buf, pos); put32(buf, pos, (w & 0xFC000003) | (value.wrapping_sub(p) & 0x03FFFFFC)) }
                        R_PPC_REL14 => { let w = be32(buf, pos); put32(buf, pos, (w & 0xFFFF0003) | (value.wrapping_sub(p) & 0xFFFC)) }
                        R_PPC_EMB_SDA21 => {
                            let (reg, base) = match tsec {
                                Some(".sdata") | Some(".sbss") => (13, lay.sda),
                                Some(".sdata2") | Some(".sbss2") => (2, lay.sda2),
                                Some(".PPC.EMB.sdata0") | Some(".PPC.EMB.sbss0") => (0, 0),
                                _ => return Err(format!("R_PPC_EMB_SDA21 to '{}' outside the small data sections",
                                                        link.objs[atom.obj].sym(r.sym).name)),
                            };
                            // (the compiler may point the relocation at the displacement, 2 bytes into the instruction)
                            let pos = pos - (r.offset & 3) as usize;
                            let w = be32(buf, pos);
                            put32(buf, pos, (w & 0xFFE00000) | (reg << 16) | (value.wrapping_sub(base) & 0xFFFF));
                        }
                        k => return Err(format!("unsupported relocation type {k}")),
                    }
                }
            }
        }
    }
    Ok(())
}

/// The output symbol table: every entry, where each object's symbols went, and the index of the first global.
struct SymbolTable {
    entries: Vec<Ent>,
    comment: Vec<[u8; 8]>,                      // the `.comment` entry of each symbol, for a partial link
    undefined: HashMap<String, usize>,          // the index of each undefined symbol, for a partial link
    new_index: Vec<HashMap<usize, usize>>,
    first_global: usize,
}

/// The output section index (counting the null section as 0) of the output section `i` of ORDER.
fn shndx_of(lay: &Layout, i: usize) -> u16 {
    lay.nonempty.iter().position(|&x| x == i).unwrap() as u16 + 1
}

/// The output symbol standing for the section symbol of an object's input section.
fn section_symbol(lay: &Layout, o: usize, section: &Section) -> Ent {
    let out = output_name(&section.name).unwrap();
    let piece = lay.pieces[oi(out)].iter()
        .find(|p| p.obj == Some(o) && p.sec.as_ref().map(|s| s.index) == Some(section.index)).unwrap();
    let value = if out == "extabindex" { 0 } else { piece.addr };
    Ent { name: String::new(), value, size: 0, info: STT_SECTION, shndx: shndx_of(lay, oi(out)) }
}

fn symbol_table(link: &Link, lay: &Layout, cats: &[usize], cats_shndx: u16) -> SymbolTable {
    let sec_of = |i: usize| shndx_of(lay, i);
    let mut entries = vec![Ent { name: String::new(), value: 0, size: 0, info: 0, shndx: 0 }];
    let mut new_index: Vec<HashMap<usize, usize>> = vec![HashMap::new(); link.objs.len()];
    for (o, obj) in link.objs.iter().enumerate() {
        let e = &obj.elf;
        let live_secs: Vec<usize> =
            obj.atoms.iter().filter(|(_, ids)| ids.iter().any(|&a| link.atoms[a].live)).map(|(&i, _)| i).collect();
        if live_secs.is_empty() && !cats.contains(&o) {
            continue;
        }
        // (an object that is only common symbols has no file symbol)
        let real_sections = e.sections.iter().any(|s| !s.synthetic && live_secs.contains(&s.index));
        if let Some(file) = e.symbols.iter().find(|s| s.typ == STT_FILE).filter(|_| real_sections || cats.contains(&o)) {
            new_index[o].insert(file.index, entries.len());
            entries.push(Ent { name: file.name.clone(), value: 0, size: 0, info: STT_FILE, shndx: SHN_ABS });
        }
        for section in &e.sections {
            let sym = e.symbols.iter().find(|s| s.typ == STT_SECTION && s.shndx as usize == section.index);
            if live_secs.contains(&section.index) {
                if !section.synthetic {
                    if let Some(sym) = sym {
                        new_index[o].insert(sym.index, entries.len());
                    }
                    entries.push(section_symbol(lay, o, section));
                }
            } else if section.name == ".mwcats.text" && cats.contains(&o) {
                if let Some(sym) = sym {
                    new_index[o].insert(sym.index, entries.len());
                }
                entries.push(Ent { name: String::new(), value: 0, size: 0, info: STT_SECTION, shndx: cats_shndx });
            }
        }
        for s in &e.symbols {
            if s.bind == STB_LOCAL && s.typ != STT_SECTION && s.typ != STT_FILE && live_secs.contains(&(s.shndx as usize)) {
                if let Some(atom) = link.atom_of(o, s).filter(|a| a.live) {
                    new_index[o].insert(s.index, entries.len());
                    let out = output_name(&e.sections[s.shndx as usize].name).unwrap();
                    entries.push(Ent { name: s.name.clone(), value: atom.where_(s.value), size: s.size, info: s.typ,
                                       shndx: sec_of(oi(out)) });
                }
            }
        }
        // (the section of an object's common symbols gets its symbol after the object's locals)
        for section in e.sections.iter().filter(|s| s.synthetic && live_secs.contains(&s.index)) {
            entries.push(section_symbol(lay, o, section));
        }
    }
    // section symbols of the linker's own pieces
    for piece in lay.pieces[oi(".init")].iter().filter(|p| p.obj.is_none() && !p.gen.is_empty()) {
        entries.push(Ent { name: String::new(), value: piece.addr, size: 0, info: STT_SECTION, shndx: sec_of(oi(".init")) });
    }
    for name in [".ctors", ".dtors"] {
        for tag in ["$00", "$99"] {
            if let Some(piece) = lay.pieces[oi(name)].iter().find(|p| p.name == format!("{name}{tag}")) {
                entries.push(Ent { name: String::new(), value: piece.addr, size: 0, info: STT_SECTION, shndx: sec_of(oi(name)) });
            }
        }
    }
    let first_global = entries.len();
    for (o, obj) in link.objs.iter().enumerate() {
        for s in &obj.elf.symbols {
            if link.emits_symbol(o, s) {
                if let Some(atom) = link.atom_of(o, s).filter(|a| a.live) {
                    new_index[o].insert(s.index, entries.len());
                    let out = output_name(&obj.elf.sections[s.shndx as usize].name).unwrap();
                    entries.push(Ent { name: s.name.clone(), value: atom.where_(s.value), size: s.size,
                                       info: (s.bind << 4) | s.typ, shndx: sec_of(oi(out)) });
                }
            }
        }
    }
    // the symbols code takes from the linker (`_SDA_BASE_`, those a linker command file defines), and the ones those
    // definitions use, in the order of the linker's symbol list
    let mut needed: HashSet<&String> = link.linker_refs.iter().collect();
    let mut work: Vec<&String> = needed.iter().copied().collect();
    while let Some(name) = work.pop() {
        for dep in lay.assign_deps.get(name).into_iter().flatten() {
            if needed.insert(dep) {
                work.push(dep);
            }
        }
    }
    for (name, value) in lay.symbols.iter().filter(|(name, _)| needed.contains(name)) {
        entries.push(Ent { name: name.clone(), value: *value, size: 0, info: STB_GLOBAL << 4, shndx: SHN_ABS });
    }
    for name in [".init", ".ctors", ".dtors"] {
        for g in lay.pieces[oi(name)].iter().flat_map(|p| p.gen.iter()) {
            entries.push(Ent { name: g.name.clone(), value: lay.gen_addr(&g.name).unwrap(), size: g.size,
                               info: (STB_GLOBAL << 4) | g.typ, shndx: sec_of(oi(name)) });
        }
    }
    if let Some(value) = lay.gen_addr("_eti_init_info") {
        let size = if link.eh { 32 } else { 0 };
        entries.push(Ent { name: "_eti_init_info".into(), value, size, info: (STB_GLOBAL << 4) | STT_OBJECT,
                           shndx: sec_of(oi("extabindex")) });
    }
    SymbolTable { entries, comment: vec![], undefined: HashMap::new(), new_index, first_global }
}

/// The symbol table of a partial link: each object's file symbol, section symbols and locals, then the globals of every
/// object in order, undefined ones where they are first named, each with its `.comment` entry.
fn partial_symbol_table(link: &Link, lay: &Layout) -> SymbolTable {
    let mut entries = vec![Ent { name: String::new(), value: 0, size: 0, info: 0, shndx: 0 }];
    let mut comment = vec![[0u8; 8]];
    let mut new_index: Vec<HashMap<usize, usize>> = vec![HashMap::new(); link.objs.len()];
    let entry = |align: u32| {
        let mut c = [0u8; 8];
        c[..4].copy_from_slice(&align.to_be_bytes());
        c
    };
    // (the weak marker in the entry's first flag byte is not kept)
    let kept = |mut c: [u8; 8]| {
        c[4] = 0;
        c
    };
    for (o, obj) in link.objs.iter().enumerate() {
        let e = &obj.elf;
        let live_secs: Vec<usize> =
            obj.atoms.iter().filter(|(_, ids)| ids.iter().any(|&a| link.atoms[a].live)).map(|(&i, _)| i).collect();
        let real_sections = e.sections.iter().any(|s| !s.synthetic && live_secs.contains(&s.index));
        if let Some(file) = e.symbols.iter().find(|s| s.typ == STT_FILE).filter(|_| real_sections) {
            new_index[o].insert(file.index, entries.len());
            entries.push(Ent { name: file.name.clone(), value: 0, size: 0, info: STT_FILE, shndx: SHN_ABS });
            comment.push(entry(1));
        }
        for section in e.sections.iter().filter(|s| !s.synthetic && live_secs.contains(&s.index)) {
            if let Some(sym) = e.symbols.iter().find(|s| s.typ == STT_SECTION && s.shndx as usize == section.index) {
                new_index[o].insert(sym.index, entries.len());
            }
            entries.push(section_symbol(lay, o, section));
            comment.push(entry(section.align));
        }
        for s in &e.symbols {
            if s.bind == STB_LOCAL && s.typ != STT_SECTION && s.typ != STT_FILE && live_secs.contains(&(s.shndx as usize)) {
                if let Some(atom) = link.atom_of(o, s).filter(|a| a.live) {
                    new_index[o].insert(s.index, entries.len());
                    let out = output_name(&e.sections[s.shndx as usize].name).unwrap();
                    entries.push(Ent { name: s.name.clone(), value: atom.where_(s.value), size: s.size, info: s.typ,
                                       shndx: shndx_of(lay, oi(out)) });
                    comment.push(kept(obj.cmt[s.index]));
                }
            }
        }
        for section in e.sections.iter().filter(|s| s.synthetic && live_secs.contains(&s.index)) {
            entries.push(section_symbol(lay, o, section));
            comment.push(entry(section.align));
        }
    }
    // the linker's own pieces (the markers of the constructors and destructors) have section symbols too, and symbols
    // that follow all the others
    let generated: Vec<(usize, &Piece)> =
        lay.seq.iter().flat_map(|&i| lay.pieces[i].iter().filter(|p| !p.gen.is_empty()).map(move |p| (i, p))).collect();
    for &(i, piece) in &generated {
        entries.push(Ent { name: String::new(), value: piece.start, size: 0, info: STT_SECTION, shndx: shndx_of(lay, i) });
        comment.push(entry(4));
    }
    let first_global = entries.len();
    let mut undefined = HashMap::new();
    for (o, obj) in link.objs.iter().enumerate() {
        for s in obj.elf.symbols.iter().filter(|s| s.bind >= STB_GLOBAL && !s.name.is_empty() && s.typ != STT_FILE) {
            if s.shndx == 0 {
                if !link.defs.contains_key(&s.name) && !undefined.contains_key(&s.name)
                    && !generated.iter().any(|(_, p)| p.gen.iter().any(|g| g.name == s.name)) {
                    undefined.insert(s.name.clone(), entries.len());
                    entries.push(Ent { name: s.name.clone(), value: 0, size: 0, info: (s.bind << 4) | s.typ, shndx: 0 });
                    comment.push(entry(1));
                }
            } else if let Some(atom) = link.atom_of(o, s).filter(|_| !obj.lost.contains(&s.index)) {
                new_index[o].insert(s.index, entries.len());
                let out = output_name(&obj.elf.sections[s.shndx as usize].name).unwrap();
                entries.push(Ent { name: s.name.clone(), value: atom.where_(s.value), size: s.size,
                                   info: (s.bind << 4) | s.typ, shndx: shndx_of(lay, oi(out)) });
                comment.push(kept(obj.cmt[s.index]));
            }
        }
    }
    for &(i, piece) in &generated {
        for g in &piece.gen {
            undefined.entry(g.name.clone()).or_insert(entries.len());    // (code that refers to a generated symbol)
            entries.push(Ent { name: g.name.clone(), value: piece.start + g.offset, size: g.size,
                               info: (STB_GLOBAL << 4) | g.typ, shndx: shndx_of(lay, i) });
            comment.push(entry(4));
        }
    }
    SymbolTable { entries, comment, undefined, new_index, first_global }
}

fn entry_address(link: &Link) -> R<u32> {
    if link.partial {
        return Ok(0);
    }
    let (eo, es) = link.defs[&link.entry];
    let sym = link.objs[eo].sym(es);
    let atom = link.atom_of(eo, sym).ok_or("the entry point has no code")?;
    Ok(atom.where_(sym.value))
}

/// The contents of each output section, relocated, with the exception table index's info block filled in.
fn section_contents(link: &Link, lay: &Layout) -> R<Vec<Vec<u8>>> {
    let mut data: Vec<Vec<u8>> = vec![vec![]; ORDER.len()];
    for &i in &lay.nonempty {
        let mut buf = vec![0u8; lay.size[i] as usize];
        for piece in &lay.pieces[i] {
            for &a in &piece.atoms {
                let atom = &link.atoms[a];
                let section = &link.objs[atom.obj].elf.sections[atom.sec];
                if section.typ == SHT_PROGBITS {
                    let (from, to) = (atom.start as usize, atom.out_offset as usize);
                    let bytes = section.data.get(from..from + atom.size as usize).ok_or("a symbol lies outside its section")?;
                    buf[to..to + atom.size as usize].copy_from_slice(bytes);
                }
            }
        }
        data[i] = buf;
    }
    if !link.partial {
        apply_relocs(link, lay, &mut data)?;
    }
    if link.rom_ref {
        write_init_info(lay, &mut data);
    }
    if link.eh {
        write_eti_info(lay, &mut data);
    }
    Ok(data)
}

/// `_rom_copy_info` and `_bss_init_info`: where each section with contents is copied from, and which sections to clear.
fn write_init_info(lay: &Layout, data: &mut [Vec<u8>]) {
    let init = oi(".init");
    let at = (lay.gen_addr("_rom_copy_info").unwrap() - lay.addr[init]) as usize;
    let (copied, cleared) = init_info_sections(&lay.seq, |i| lay.nonempty.contains(&i));
    let (mut copy, mut clear) = (vec![], vec![]);
    for i in copied {
        push32(&mut copy, &[lay.sym_map[&section_symbol_names(ORDER[i]).1], lay.addr[i], lay.size[i]]);
    }
    for i in cleared {
        push32(&mut clear, &[lay.addr[i], lay.size[i]]);
    }
    copy.extend_from_slice(&[0; 12]);
    clear.extend_from_slice(&[0; 8]);
    data[init][at..at + copy.len()].copy_from_slice(&copy);
    data[init][at + copy.len()..at + copy.len() + clear.len()].copy_from_slice(&clear);
}

/// `_eti_init_info`: the extabindex start and end, then the code range its entries cover.
fn write_eti_info(lay: &Layout, data: &mut [Vec<u8>]) {
    let ex = oi("extabindex");
    let at = (lay.gen_addr("_eti_init_info").unwrap() - lay.addr[ex]) as usize;      // (the entries come first)
    let start = lay.addr[ex];
    let (mut lo, mut hi) = (None::<u32>, 0u32);
    for i in 0..at / 12 {
        let (func, size) = (be32(&data[ex], 12 * i), be32(&data[ex], 12 * i + 4));
        lo = Some(lo.map_or(func, |l| l.min(func)));
        hi = hi.max(func.wrapping_add(size));
    }
    let mut info = vec![];
    push32(&mut info, &[start, start + at as u32, lo.unwrap_or(0), lo.map_or(0, |l| hi.wrapping_sub(l))]);
    info.extend_from_slice(&[0; 16]);
    data[ex][at..at + 32].copy_from_slice(&info);
}

/// The `.mwcats.text` contents: (size word, address of the code) for the live entries of the given objects.
fn cats_section(link: &Link, cats: &[usize]) -> Vec<u8> {
    let mut out = vec![];
    for &o in cats {
        for (word, atom, offset) in cats_entries(link, o) {
            out.extend_from_slice(&word);
            out.extend_from_slice(&link.atoms[atom].where_(offset).to_be_bytes());
        }
    }
    out
}

/// The `.comment` section of a partial link: the linker's header, then an entry for each symbol.
fn comment_bytes(entries: &[[u8; 8]], generated: bool) -> Vec<u8> {
    let mut out = b"CodeWarrior".to_vec();
    // (the fifth byte reads 3 instead of 2 when the linker has symbols of its own in the output)
    out.extend_from_slice(&[0x0d, 0x03, 0x00, 0x00, if generated { 3 } else { 2 }, 0x00, 0x02, 0x00, 0x14, 0x2c]);
    out.resize(44, 0);
    entries.iter().for_each(|e| out.extend_from_slice(e));
    out
}

/// The `.symtab` and `.strtab` contents.
fn symtab_bytes(entries: &[Ent]) -> (Vec<u8>, Vec<u8>) {
    let (mut strtab, mut symtab) = (vec![0u8], vec![]);
    for ent in entries {
        let mut offset = 0;
        if !ent.name.is_empty() {
            offset = strtab.len() as u32;
            strtab.extend(to_latin1(&ent.name));
            strtab.push(0);
        }
        push32(&mut symtab, &[offset, ent.value, ent.size]);
        symtab.extend_from_slice(&[ent.info, 0]);
        symtab.extend_from_slice(&ent.shndx.to_be_bytes());
    }
    (symtab, strtab)
}

pub fn build(link: &Link, lay: &Layout) -> R<Vec<u8>> {
    let total = lay.nonempty.len();
    let cats: Vec<usize> =
        (0..link.objs.len()).filter(|&o| !link.partial && link.objs[o].has_cats() && !cats_entries(link, o).is_empty()).collect();
    let retained = retained_relocs(link, lay);
    let rela_sections: Vec<usize> = lay.nonempty.iter().copied().filter(|&i| !retained[i].is_empty()).collect();
    let has_cats = !cats.is_empty();
    // after the output sections come the relocations, `.mwcats.text`, then `.symtab`, `.shstrtab` and `.strtab`
    let cats_shndx = (total + rela_sections.len() + 1) as u16;
    let symtab_shndx = cats_shndx + u16::from(has_cats);
    let (shstrtab_shndx, strtab_shndx) = (symtab_shndx + 1, symtab_shndx + 2);

    let SymbolTable { entries, comment, undefined, new_index, first_global } =
        if link.partial { partial_symbol_table(link, lay) } else { symbol_table(link, lay, &cats, cats_shndx) };
    let entry_addr = entry_address(link)?;
    let data = section_contents(link, lay)?;
    let cats_data = cats_section(link, &cats);
    let (symtab, strtab) = symtab_bytes(&entries);
    let comment_data = if link.partial { comment_bytes(&comment, lay.pieces.iter().flatten().any(|p| !p.gen.is_empty())) } else { vec![] };

    let mut out_secs = vec![];       // (order index, type, flags, entsize)
    let mut pos = lay.hdr;
    for &i in &lay.nonempty {
        pos = lay.file_off[i] + if is_nobits(ORDER[i]) { 0 } else { lay.size[i] };
        let flags = lay.pieces[i].iter().filter_map(|p| p.sec.as_ref()).fold(0, |f, s| f | s.flags);
        let kind = if is_nobits(ORDER[i]) { SHT_NOBITS } else { SHT_PROGBITS };
        out_secs.push((i, kind, if flags == 0 { SHF_ALLOC } else { flags }, u32::from(matches!(ORDER[i], ".ctors" | ".dtors"))));
    }
    let rela_names: Vec<String> = rela_sections.iter().map(|&i| format!(".rela{}", ORDER[i])).collect();
    let mut all_names: Vec<String> = out_secs.iter().map(|s| ORDER[s.0].to_string()).collect();
    all_names.extend(rela_names.iter().cloned());
    if has_cats {
        all_names.push(".mwcats.text".into());
    }
    all_names.extend([".symtab", ".shstrtab", ".strtab"].map(String::from));
    if link.partial {
        all_names.push(".comment".into());
    }
    let mut shstr = vec![0u8];
    let mut shoffs: HashMap<String, u32> = HashMap::new();
    for n in &all_names {
        shoffs.insert(n.clone(), shstr.len() as u32);
        shstr.extend(n.bytes());
        shstr.push(0);
    }
    let shstr_pos = pos;
    let strtab_pos = shstr_pos + shstr.len() as u32;
    let symtab_pos = align(strtab_pos + strtab.len() as u32, 4);
    pos = symtab_pos + symtab.len() as u32;
    let (mut rela_data, mut rela_pos) = (vec![], vec![]);
    for &i in &rela_sections {
        pos = align(pos, 4);
        let mut bytes = vec![];
        for &(a, r_offset, sym, kind, addend) in &retained[i] {
            let atom = &link.atoms[a];
            let name = &link.objs[atom.obj].sym(sym).name;
            let idx = match link.lookup(atom.obj, sym) {
                Some((fo, fs)) => new_index[fo].get(&fs),
                None => undefined.get(name),
            };
            let idx = *idx.ok_or(format!("no output symbol for '{name}'"))?;
            push32(&mut bytes, &[atom.where_(r_offset), ((idx as u32) << 8) | kind as u32, addend as u32]);
        }
        // (the destructor chain's reference the linker repeats refers to the chain)
        for piece in lay.pieces[i].iter().filter(|p| link.partial && p.obj.is_none() && p.name == ".dtors$10") {
            let (fo, fs) = link.defs["__destroy_global_chain"];
            push32(&mut bytes, &[piece.start, ((new_index[fo][&fs] as u32) << 8) | R_PPC_ADDR32 as u32, 0]);
        }
        rela_pos.push(pos);
        pos += bytes.len() as u32;
        rela_data.push(bytes);
    }
    pos = align(pos, 4);
    let cats_pos = pos;
    pos += cats_data.len() as u32;
    let comment_pos = pos;
    pos += comment_data.len() as u32;
    let shoff = align(pos, 16);
    let n_sections = out_secs.len() + rela_names.len() + 3 + usize::from(has_cats) + usize::from(link.partial);
    let mut image = vec![0u8; shoff as usize + SHDR_SIZE as usize * (n_sections + 1)];
    let mut place = |at: u32, bytes: &[u8]| image[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
    for &(i, kind, ..) in &out_secs {
        if kind == SHT_PROGBITS {
            place(lay.file_off[i], &data[i]);
        }
    }
    place(shstr_pos, &shstr);
    place(strtab_pos, &strtab);
    place(symtab_pos, &symtab);
    for (p, bytes) in rela_pos.iter().zip(&rela_data) {
        place(*p, bytes);
    }
    place(cats_pos, &cats_data);
    place(comment_pos, &comment_data);
    let mut sh = vec![SecHeader::default()];
    for &(i, kind, flags, entsize) in &out_secs {
        sh.push(SecHeader { name: shoffs[ORDER[i]], kind, flags, addr: lay.addr[i], off: lay.file_off[i], size: lay.size[i],
                            align: lay.align[i], entsize, ..Default::default() });
    }
    for (k, &i) in rela_sections.iter().enumerate() {
        sh.push(SecHeader { name: shoffs[&rela_names[k]], kind: SHT_RELA, off: rela_pos[k], size: rela_data[k].len() as u32,
                            link: symtab_shndx as u32, info: shndx_of(lay, i) as u32, align: 4, entsize: 12,
                            ..Default::default() });
    }
    if has_cats {
        let cats_type = link.objs[cats[0]].elf.section(".mwcats.text").unwrap().typ;
        sh.push(SecHeader { name: shoffs[".mwcats.text"], kind: cats_type, off: cats_pos, size: cats_data.len() as u32,
                            link: shndx_of(lay, oi(".text")) as u32, align: 4, entsize: 1, ..Default::default() });
    }
    sh.push(SecHeader { name: shoffs[".symtab"], kind: SHT_SYMTAB, off: symtab_pos, size: symtab.len() as u32,
                        link: strtab_shndx as u32, info: first_global as u32, align: 4, entsize: 16, ..Default::default() });
    sh.push(SecHeader { name: shoffs[".shstrtab"], kind: SHT_STRTAB, off: shstr_pos, size: shstr.len() as u32, align: 1,
                        entsize: 1, ..Default::default() });
    sh.push(SecHeader { name: shoffs[".strtab"], kind: SHT_STRTAB, off: strtab_pos, size: strtab.len() as u32, align: 1,
                        entsize: 1, ..Default::default() });
    if link.partial {
        sh.push(SecHeader { name: shoffs[".comment"], kind: SHT_PROGBITS, off: comment_pos, size: comment_data.len() as u32,
                            align: 4, entsize: 1, ..Default::default() });
    }
    for (k, h) in sh.iter().enumerate() {
        place(shoff + SHDR_SIZE * k as u32, &h.bytes());
    }
    let mut phdrs = vec![];
    for &(i, kind, flags, _) in out_secs.iter().filter(|_| !link.partial) {
        let perm = 4 | if flags & 1 != 0 { 2 } else { 0 } | u32::from(flags & 4 != 0);
        push32(&mut phdrs, &[PT_LOAD, lay.file_off[i], lay.addr[i], 0, if kind == SHT_NOBITS { 0 } else { lay.size[i] },
                             lay.size[i], perm, lay.align[i]]);
    }
    let mut head = b"\x7fELF\x01\x02\x01".to_vec();
    head.extend_from_slice(&[0; 9]);
    head.extend_from_slice(&(if link.partial { ET_REL } else { ET_EXEC }).to_be_bytes());
    head.extend_from_slice(&EM_PPC.to_be_bytes());
    push32(&mut head, &[1, entry_addr, if link.partial { 0 } else { EHDR_SIZE }, shoff, EF_PPC_EMB]);
    let phnum = if link.partial { 0 } else { out_secs.len() as u16 };
    for v in [EHDR_SIZE as u16, if link.partial { 0 } else { PHDR_SIZE as u16 }, phnum, SHDR_SIZE as u16, sh.len() as u16, shstrtab_shndx] {
        head.extend_from_slice(&v.to_be_bytes());
    }
    place(0, &head);
    place(EHDR_SIZE, &phdrs);
    Ok(image)
}
