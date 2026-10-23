//! Section contents, relocations, the symbol table and the output ELF file.
use crate::elf::{be32, to_latin1, R};
use crate::layout::{oi, Layout};
use crate::link::{align, is_nobits, output_name, Link, ORDER};
use std::collections::HashMap;

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

fn header(name: u32, kind: u32, flags: u32, addr: u32, off: u32, size: u32, link: u32, info: u32, al: u32, ent: u32) -> Vec<u8> {
    let mut out = vec![];
    push32(&mut out, &[name, kind, flags, addr, off, size, link, info, al, ent]);
    out
}

/// The live (size word, atom, offset) entries of an object's .mwcats.text.
fn cats_entries(link: &Link, o: usize) -> Vec<([u8; 4], usize, u32)> {
    let obj = &link.objs[o];
    let section = obj.elf.section(".mwcats.text").unwrap();
    let relas = obj.elf.relocs(section.index);
    let mut out = vec![];
    for i in 0..section.data.len() / 8 {
        let target = relas.iter().filter(|r| r.offset as usize == 8 * i + 4)
            .fold(None, |_, r| link.target(o, r.sym, r.addend));
        if let Some((atom, offset)) = target {
            if link.atoms[atom].live {
                out.push((section.data[8 * i..8 * i + 4].try_into().unwrap(), atom, offset));
            }
        }
    }
    out
}

/// The relocations kept in the output, by output section: those of the objects with a `.mwcats.text`.
fn retained_relocs(link: &Link, lay: &Layout) -> Vec<Vec<Retained>> {
    let mut out: Vec<Vec<Retained>> = vec![vec![]; ORDER.len()];
    for &i in &lay.nonempty {
        for piece in &lay.pieces[i] {
            if piece.obj.map_or(false, |o| link.objs[o].has_cats()) {
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
    if s.bind == 2 {
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
                    let section_symbol = link.objs[atom.obj].sym(r.sym).typ == 3;
                    let value = if section_symbol { s } else { s.wrapping_add(r.addend as u32) };
                    let pos = (atom.out_offset + r.offset - atom.start) as usize;
                    let p = atom.addr + r.offset - atom.start;
                    let buf = &mut data[i];
                    let word = if pos + 4 <= buf.len() { be32(buf, pos) } else { 0 };
                    match r.kind {
                        1 => put32(buf, pos, value),
                        3 | 4 => put16(buf, pos, value),
                        5 => put16(buf, pos, value >> 16),
                        6 => put16(buf, pos, value.wrapping_add(0x8000) >> 16),
                        10 => put32(buf, pos, (word & 0xFC000003) | (value.wrapping_sub(p) & 0x03FFFFFC)),
                        11 => put32(buf, pos, (word & 0xFFFF0003) | (value.wrapping_sub(p) & 0xFFFC)),
                        109 => {
                            let (reg, base) = match tsec {
                                Some(".sdata") | Some(".sbss") => (13, lay.sda),
                                Some(".sdata2") | Some(".sbss2") => (2, lay.sda2),
                                Some(".PPC.EMB.sdata0") | Some(".PPC.EMB.sbss0") => (0, 0),
                                _ => return Err(format!("R_PPC_EMB_SDA21 to '{}' outside the small data sections",
                                                        link.objs[atom.obj].sym(r.sym).name)),
                            };
                            put32(buf, pos, (word & 0xFFE00000) | (reg << 16) | (value.wrapping_sub(base) & 0xFFFF));
                        }
                        k => return Err(format!("unsupported relocation type {k}")),
                    }
                }
            }
        }
    }
    Ok(())
}

pub struct Output {
    pub image: Vec<u8>,
}

pub fn build(link: &Link, lay: &Layout) -> R<Output> {
    let sec_index = |name: &str| lay.nonempty.iter().position(|&x| x == oi(name)).map(|p| p as u16 + 1);
    let sec_of = |i: usize| lay.nonempty.iter().position(|&x| x == i).unwrap() as u16 + 1;
    let total = lay.nonempty.len();
    let cats: Vec<usize> =
        (0..link.objs.len()).filter(|&o| link.objs[o].has_cats() && !cats_entries(link, o).is_empty()).collect();
    let retained = retained_relocs(link, lay);
    let rela_sections: Vec<usize> = lay.nonempty.iter().copied().filter(|&i| !retained[i].is_empty()).collect();
    let has_cats = !cats.is_empty();
    let cats_shndx = (total + rela_sections.len() + 1) as u16;
    let symtab_shndx = cats_shndx + u16::from(has_cats);

    // -- symbols
    let mut entries = vec![Ent { name: String::new(), value: 0, size: 0, info: 0, shndx: 0 }];
    let mut new_index: Vec<HashMap<usize, usize>> = vec![HashMap::new(); link.objs.len()];
    for (o, obj) in link.objs.iter().enumerate() {
        let e = &obj.elf;
        let live_secs: Vec<usize> =
            obj.atoms.iter().filter(|(_, ids)| ids.iter().any(|&a| link.atoms[a].live)).map(|(&i, _)| i).collect();
        if live_secs.is_empty() && !cats.contains(&o) {
            continue;
        }
        if let Some(file) = e.symbols.iter().find(|s| s.typ == 4) {
            new_index[o].insert(file.index, entries.len());
            entries.push(Ent { name: file.name.clone(), value: 0, size: 0, info: 4, shndx: 0xFFF1 });
        }
        for section in &e.sections {
            let sym = e.symbols.iter().find(|s| s.typ == 3 && s.shndx as usize == section.index);
            if live_secs.contains(&section.index) {
                let out = output_name(&section.name).unwrap();
                let piece = lay.pieces[oi(out)].iter()
                    .find(|p| p.obj == Some(o) && p.sec.as_ref().map(|s| s.index) == Some(section.index)).unwrap();
                let value = if out == "extabindex" { 0 } else { piece.addr };
                if let Some(sym) = sym {
                    new_index[o].insert(sym.index, entries.len());
                }
                entries.push(Ent { name: String::new(), value, size: 0, info: 3, shndx: sec_of(oi(out)) });
            } else if section.name == ".mwcats.text" && cats.contains(&o) {
                if let Some(sym) = sym {
                    new_index[o].insert(sym.index, entries.len());
                }
                entries.push(Ent { name: String::new(), value: 0, size: 0, info: 3, shndx: cats_shndx });
            }
        }
        for s in &e.symbols {
            if s.bind == 0 && s.typ != 3 && s.typ != 4 && live_secs.contains(&(s.shndx as usize)) {
                let atom = obj.atoms[&(s.shndx as usize)].iter().map(|&a| &link.atoms[a]).find(|a| a.contains(s.value));
                if let Some(atom) = atom.filter(|a| a.live) {
                    new_index[o].insert(s.index, entries.len());
                    let out = output_name(&e.sections[s.shndx as usize].name).unwrap();
                    entries.push(Ent { name: s.name.clone(), value: atom.where_(s.value), size: s.size, info: s.typ,
                                       shndx: sec_of(oi(out)) });
                }
            }
        }
    }
    // section symbols of the linker's own pieces
    for name in [".ctors", ".dtors"] {
        for tag in ["$00", "$99"] {
            if let Some(piece) = lay.pieces[oi(name)].iter().find(|p| p.name == format!("{name}{tag}")) {
                entries.push(Ent { name: String::new(), value: piece.addr, size: 0, info: 3, shndx: sec_of(oi(name)) });
            }
        }
    }
    let first_global = entries.len();
    for (o, obj) in link.objs.iter().enumerate() {
        for s in &obj.elf.symbols {
            if s.bind >= 1 && 0 < s.shndx && s.shndx < 0xFF00 && !obj.lost.contains(&s.index) {
                let atom = obj.atoms.get(&(s.shndx as usize)).and_then(|ids| {
                    ids.iter().map(|&a| &link.atoms[a]).find(|a| a.contains(s.value))
                });
                if let Some(atom) = atom.filter(|a| a.live) {
                    new_index[o].insert(s.index, entries.len());
                    let out = output_name(&obj.elf.sections[s.shndx as usize].name).unwrap();
                    entries.push(Ent { name: s.name.clone(), value: atom.where_(s.value), size: s.size,
                                       info: (s.bind << 4) | s.typ, shndx: sec_of(oi(out)) });
                }
            }
        }
    }
    for name in [".ctors", ".dtors"] {
        for (sym, _, size, kind) in lay.pieces[oi(name)].iter().flat_map(|p| p.gen.iter()) {
            entries.push(Ent { name: sym.clone(), value: lay.gen_addr(sym).unwrap(), size: *size,
                               info: 0x10 | kind, shndx: sec_of(oi(name)) });
        }
    }
    if let Some(value) = lay.gen_addr("_eti_init_info") {
        let size = if link.eh { 32 } else { 0 };
        entries.push(Ent { name: "_eti_init_info".into(), value, size, info: 0x11, shndx: sec_of(oi("extabindex")) });
    }
    let (eo, es) = link.defs[&link.entry];
    let entry_atom = link.objs[eo].atoms[&(link.objs[eo].sym(es).shndx as usize)].iter().map(|&a| &link.atoms[a])
        .find(|a| a.contains(link.objs[eo].sym(es).value)).ok_or("the entry point has no code")?;
    let entry_addr = entry_atom.where_(link.objs[eo].sym(es).value);

    // -- section contents
    let mut data: Vec<Vec<u8>> = vec![vec![]; ORDER.len()];
    for &i in &lay.nonempty {
        let mut buf = vec![0u8; lay.size[i] as usize];
        for piece in &lay.pieces[i] {
            for &a in &piece.atoms {
                let atom = &link.atoms[a];
                let section = &link.objs[atom.obj].elf.sections[atom.sec];
                if section.typ == 1 {
                    let (from, to) = (atom.start as usize, atom.out_offset as usize);
                    buf[to..to + atom.size as usize].copy_from_slice(&section.data[from..from + atom.size as usize]);
                }
            }
        }
        data[i] = buf;
    }
    apply_relocs(link, lay, &mut data)?;

    // -- the exception table index info: extabindex start/end, the code range it covers
    let ex = oi("extabindex");
    if link.eh {
        let n_entries = lay.pieces[ex].iter().flat_map(|p| p.atoms.iter()).map(|&a| link.atoms[a].size).sum::<u32>() / 12;
        let start = lay.addr[ex];
        let (mut lo, mut hi) = (None::<u32>, 0u32);
        for i in 0..n_entries as usize {
            let (func, size) = (be32(&data[ex], 12 * i), be32(&data[ex], 12 * i + 4));
            lo = Some(lo.map_or(func, |l| l.min(func)));
            hi = hi.max(func.wrapping_add(size));
        }
        let mut info = vec![];
        push32(&mut info, &[start, start + n_entries * 12, lo.unwrap_or(0), lo.map_or(0, |l| hi.wrapping_sub(l))]);
        info.extend_from_slice(&[0; 16]);
        let at = n_entries as usize * 12;
        data[ex][at..at + 32].copy_from_slice(&info);
    }
    let mut cats_data = vec![];
    for &o in &cats {
        for (word, atom, offset) in cats_entries(link, o) {
            cats_data.extend_from_slice(&word);
            cats_data.extend_from_slice(&link.atoms[atom].where_(offset).to_be_bytes());
        }
    }

    // -- the file
    let (mut strtab, mut symtab) = (vec![0u8], vec![]);
    for ent in &entries {
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
    let mut out_secs = vec![];       // (order index, type, flags, entsize)
    let mut pos = lay.hdr;
    for &i in &lay.nonempty {
        pos = lay.map_off[i] + if is_nobits(ORDER[i]) { 0 } else { lay.size[i] };
        let flags = lay.pieces[i].iter().filter_map(|p| p.sec.as_ref()).fold(0, |f, s| f | s.flags);
        let kind = if is_nobits(ORDER[i]) { 8 } else { 1 };
        out_secs.push((i, kind, if flags == 0 { 2 } else { flags }, u32::from(matches!(ORDER[i], ".ctors" | ".dtors"))));
    }
    let rela_names: Vec<String> = rela_sections.iter().map(|&i| format!(".rela{}", ORDER[i])).collect();
    let mut all_names: Vec<String> = out_secs.iter().map(|s| ORDER[s.0].to_string()).collect();
    all_names.extend(rela_names.iter().cloned());
    if has_cats {
        all_names.push(".mwcats.text".into());
    }
    all_names.extend([".symtab", ".shstrtab", ".strtab"].map(String::from));
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
            let (fo, fs) = link.lookup(atom.obj, sym).ok_or(format!("no output symbol for '{}'", link.objs[atom.obj].sym(sym).name))?;
            let idx = *new_index[fo].get(&fs).ok_or(format!("no output symbol for '{}'", link.objs[fo].sym(fs).name))?;
            push32(&mut bytes, &[atom.addr + r_offset - atom.start, ((idx as u32) << 8) | kind as u32, addend as u32]);
        }
        rela_pos.push(pos);
        pos += bytes.len() as u32;
        rela_data.push(bytes);
    }
    pos = align(pos, 4);
    let cats_pos = pos;
    pos += cats_data.len() as u32;
    let shoff = align(pos, 16);
    let n_sections = out_secs.len() + rela_names.len() + 3 + usize::from(has_cats);
    let mut image = vec![0u8; shoff as usize + 40 * (n_sections + 1)];
    let mut place = |at: u32, bytes: &[u8]| image[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
    for &(i, kind, ..) in &out_secs {
        if kind == 1 {
            place(lay.map_off[i], &data[i]);
        }
    }
    place(shstr_pos, &shstr);
    place(strtab_pos, &strtab);
    place(symtab_pos, &symtab);
    for (p, bytes) in rela_pos.iter().zip(&rela_data) {
        place(*p, bytes);
    }
    place(cats_pos, &cats_data);
    let mut sh = vec![vec![0u8; 40]];
    for &(i, kind, flags, ent) in &out_secs {
        sh.push(header(shoffs[ORDER[i]], kind, flags, lay.addr[i], lay.map_off[i], lay.size[i], 0, 0, lay.align[i], ent));
    }
    for (k, &i) in rela_sections.iter().enumerate() {
        sh.push(header(shoffs[&rela_names[k]], 4, 0, 0, rela_pos[k], rela_data[k].len() as u32, symtab_shndx as u32,
                       sec_of(i) as u32, 4, 12));
    }
    if has_cats {
        let cats_type = link.objs[cats[0]].elf.section(".mwcats.text").unwrap().typ;
        sh.push(header(shoffs[".mwcats.text"], cats_type, 0, 0, cats_pos, cats_data.len() as u32,
                       sec_index(".text").unwrap_or(0) as u32, 0, 4, 1));
    }
    sh.push(header(shoffs[".symtab"], 2, 0, 0, symtab_pos, symtab.len() as u32, symtab_shndx as u32 + 2,
                   first_global as u32, 4, 16));
    sh.push(header(shoffs[".shstrtab"], 3, 0, 0, shstr_pos, shstr.len() as u32, 0, 0, 1, 1));
    sh.push(header(shoffs[".strtab"], 3, 0, 0, strtab_pos, strtab.len() as u32, 0, 0, 1, 1));
    for (k, h) in sh.iter().enumerate() {
        place(shoff + 40 * k as u32, h);
    }
    let mut phdrs = vec![];
    for &(i, kind, flags, _) in &out_secs {
        let perm = 4 | if flags & 1 != 0 { 2 } else { 0 } | u32::from(flags & 4 != 0);
        push32(&mut phdrs, &[1, lay.map_off[i], lay.addr[i], 0, if kind == 8 { 0 } else { lay.size[i] }, lay.size[i], perm,
                             lay.align[i]]);
    }
    let mut head = b"\x7fELF\x01\x02\x01".to_vec();
    head.extend_from_slice(&[0; 9]);
    head.extend_from_slice(&2u16.to_be_bytes());
    head.extend_from_slice(&20u16.to_be_bytes());
    push32(&mut head, &[1, entry_addr, 52, shoff, 0x80000000]);
    for v in [52u16, 32, out_secs.len() as u16, 40, sh.len() as u16, (n_sections - 1) as u16] {
        head.extend_from_slice(&v.to_be_bytes());
    }
    place(0, &head);
    place(52, &phdrs);
    Ok(Output { image })
}
