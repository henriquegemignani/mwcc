//! The default (no linker command file) layout: output sections from the base address in a fixed order.
use crate::link::{align, is_nobits, output_name, Link, BASE, ORDER};
use std::collections::HashMap;

const SDA0: u32 = 0xFFFF8000;

pub struct SecInfo {
    pub index: usize,
    pub align: u32,
    pub size: u32,
    pub flags: u32,
}

/// What an output section holds from one input section (or the linker's own).
pub struct Piece {
    pub name: String,
    pub obj: Option<usize>,
    pub sec: Option<SecInfo>,
    pub atoms: Vec<usize>,
    pub start: u32,
    pub size: u32,                              // as the map shows it
    pub addr: u32,
    pub gen: Vec<(String, u32, u32, u8)>,       // (symbol name, offset, size, type) of a linker-generated piece
}

pub struct Layout {
    pub pieces: Vec<Vec<Piece>>,                // by index into ORDER
    pub addr: Vec<u32>,
    pub size: Vec<u32>,
    pub align: Vec<u32>,
    pub fills: Vec<Vec<(u32, u32, u32)>>,       // (offset, size, alignment) of the padding before a piece
    pub nonempty: Vec<usize>,
    pub hdr: u32,
    pub map_off: Vec<u32>,
    pub sda: u32,
    pub sda2: u32,
    pub symbols: Vec<(String, u32)>,
    pub sym_map: HashMap<String, u32>,
}

pub fn oi(name: &str) -> usize {
    ORDER.iter().position(|&n| n == name).unwrap()
}

fn gen_piece(name: &str, gen: Vec<(String, u32, u32, u8)>) -> Piece {
    Piece { name: name.into(), obj: None, sec: None, atoms: vec![], start: 0, size: 0, addr: 0, gen }
}

impl Layout {
    pub fn new(link: &mut Link) -> Layout {
        let mut pieces: Vec<Vec<Piece>> = vec![];
        for name in ORDER {
            let mut found = vec![];
            for (o, obj) in link.objs.iter().enumerate() {
                for (&i, ids) in &obj.atoms {
                    let live: Vec<usize> = ids.iter().copied().filter(|&a| link.atoms[a].live).collect();
                    let section = &obj.elf.sections[i];
                    if !live.is_empty() && output_name(&section.name) == Some(name) {
                        found.push(Piece {
                            name: section.name.clone(), obj: Some(o),
                            sec: Some(SecInfo { index: i, align: section.align, size: section.size, flags: section.flags }),
                            atoms: live, start: 0, size: 0, addr: 0, gen: vec![] });
                    }
                }
            }
            if name == ".ctors" || name == ".dtors" {
                found.sort_by_key(|p| (p.name == name, p.name.clone()));    // (an unsuffixed one follows the suffixed)
                let sym = format!("_{}", &name[1..]);
                found.insert(0, gen_piece(&format!("{name}$00"), vec![(sym.clone(), 0, 0, 0)]));
                found.push(gen_piece(&format!("{name}$99"), vec![(format!("{sym}$99"), 0, 4, 1)]));
            }
            if name == "extabindex" {
                found.push(gen_piece("extabindex", vec![("_eti_init_info".into(), 0, 32, 1)]));
            }
            pieces.push(found);
        }
        let n = ORDER.len();
        let nonempty: Vec<usize> =
            (0..n).filter(|&i| pieces[i].iter().any(|p| !p.atoms.is_empty() || !p.gen.is_empty())).collect();
        let hdr = align(52 + 32 * nonempty.len() as u32, 16);
        let mut lay = Layout { pieces, addr: vec![0; n], size: vec![0; n], align: vec![1; n], fills: vec![vec![]; n],
                               nonempty, hdr, map_off: vec![0; n], sda: 0, sda2: 0, symbols: vec![],
                               sym_map: HashMap::new() };
        let mut cur = BASE;
        for i in 0..n {
            let name = ORDER[i];
            if !lay.nonempty.contains(&i) {
                lay.addr[i] = if name.starts_with(".PPC.EMB") { SDA0 } else { cur };
                continue;
            }
            let extra = if matches!(name, ".ctors" | ".dtors" | "extabindex") { 4 } else { 1 };
            lay.align[i] = lay.pieces[i].iter().filter_map(|p| p.sec.as_ref().map(|s| s.align)).max().unwrap_or(0).max(extra);
            cur = align(cur, lay.align[i]);
            lay.addr[i] = cur;
            let mut offset = 0;
            for piece in lay.pieces[i].iter_mut() {
                if let Some(sec) = &piece.sec {
                    let start = align(offset, sec.align);
                    if start > offset {
                        lay.fills[i].push((offset, start - offset, sec.align));
                    }
                    offset = start;
                }
                piece.start = offset;
                piece.addr = cur + offset;
                for &a in &piece.atoms {
                    let atom = &mut link.atoms[a];
                    offset = align(offset, atom.align);
                    atom.out_offset = offset;
                    atom.addr = cur + offset;
                    offset += atom.size;
                }
                offset += piece.gen.iter().map(|g| g.2).sum::<u32>();
                piece.size = piece.sec.as_ref().map_or_else(|| piece.gen.iter().map(|g| g.2).sum(), |s| s.size);
            }
            offset = align(offset, 4);
            lay.size[i] = offset;
            cur += offset;
        }
        // file offsets as the map shows them: a section without contents (or in the bss) starts where the last ended
        let mut pos = hdr;
        for i in 0..n {
            if !lay.nonempty.contains(&i) {
                lay.map_off[i] = pos;
            } else {
                pos = align(pos, lay.align[i]);
                lay.map_off[i] = pos;
                if !is_nobits(ORDER[i]) {
                    pos += lay.size[i];
                }
            }
        }
        lay.sda = lay.addr[oi(".sdata")] + 0x8000;
        lay.sda2 = lay.addr[oi(".sdata2")] + 0x8000;
        lay.generated_symbols(link);
        lay
    }

    pub fn gen_addr(&self, symbol: &str) -> Option<u32> {
        self.pieces.iter().flatten().find_map(|p| p.gen.iter().find(|g| g.0 == symbol).map(|g| p.addr + g.1))
    }

    fn generated_symbols(&mut self, link: &Link) {
        let mut syms: Vec<(String, u32)> = vec![];
        for (i, name) in ORDER.iter().enumerate() {
            let dotted = name.starts_with('.');
            let tag = if dotted { name.trim_matches('.').replace('.', "_") } else { name.to_string() };
            let sep = if dotted { "_" } else { "" };
            let (f, e) = (self.addr[i], self.addr[i] + self.size[i]);
            syms.push((format!("_f{sep}{tag}"), f));
            if !is_nobits(name) {
                // (a ROM address is aligned for the input sections there were, even when all of them were stripped)
                let widest = link.objs.iter().flat_map(|o| o.elf.sections.iter())
                    .filter(|s| s.flags & 2 != 0 && output_name(&s.name) == Some(name)).map(|s| s.align).max().unwrap_or(1);
                syms.push((format!("_f{sep}{tag}_rom"), align(f, widest)));
            }
            syms.push((format!("_e{sep}{tag}"), e));
        }
        let functions = link.objs.iter().flat_map(|o| o.atoms.values().flatten())
            .filter(|&&a| link.atoms[a].live && link.atoms[a].symbols.iter().any(|&s| link.objs[link.atoms[a].obj].sym(s).typ == 2))
            .count() as u32;
        syms.extend([("_stack_addr", 0x3DFFF0), ("_stack_end", 0x3CFFF0), ("_heap_addr", 0x2CFFF0), ("_heap_end", 0x3CFFF0),
                     ("_nbfunctions", functions), ("SIZEOF_HEADERS", self.hdr), ("_SDA_BASE_", self.sda),
                     ("_SDA2_BASE_", self.sda2), ("_ABS_SDA_BASE_", self.sda), ("_ABS_SDA2_BASE_", self.sda2)]
            .map(|(n, v)| (n.to_string(), v)));
        self.sym_map = syms.iter().cloned().collect();
        self.symbols = syms;
    }
}
