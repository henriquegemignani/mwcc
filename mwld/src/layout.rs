//! The layout: output sections placed in the plan's order (the default fixed order from the base address, or a linker
//! command file's).
use crate::elf::{R, SHF_ALLOC, STT_FUNC};
use crate::lcf::{Expr, Lcf};
use crate::link::{align, is_nobits, output_name, Link, BASE, ORDER};
use std::collections::HashMap;

const SDA0: u32 = 0xFFFF8000;

pub struct SecInfo {
    pub index: usize,
    pub align: u32,
    pub size: u32,
    pub flags: u32,
}

/// A symbol the linker defines inside one of its own pieces.
pub struct GenSymbol {
    pub name: String,
    pub offset: u32,
    pub size: u32,
    pub typ: u8,
}

fn gen_symbol(name: impl Into<String>, offset: u32, size: u32, typ: u8) -> GenSymbol {
    GenSymbol { name: name.into(), offset, size, typ }
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
    pub gen: Vec<GenSymbol>,                    // the symbols of a linker-generated piece
}

/// Where the output sections go: the address of the first, and the sections in order with the alignments a linker
/// command file gives them. Without a file, the default order from `BASE`.
pub struct Plan {
    pub origin: u32,
    pub seq: Vec<(usize, Option<u32>)>,
    pub assigns: Vec<(String, Expr)>,
    pub lcf: bool,
    pub partial: bool,
    pub force_active: Vec<String>,
}

impl Plan {
    pub fn default_plan() -> Plan {
        Plan { origin: BASE, seq: (0..ORDER.len()).filter(|&i| ORDER[i] != ".stack").map(|i| (i, None)).collect(),
               assigns: vec![], lcf: false, partial: false, force_active: vec![] }
    }

    pub fn from_lcf(lcf: Lcf) -> R<Plan> {
        let mut seq = vec![];
        for (name, align) in &lcf.sections {
            let i = ORDER.iter().position(|o| o == name).ok_or(format!("linker command file: unknown section '{name}'"))?;
            if seq.iter().any(|&(j, _)| j == i) {
                return Err(format!("linker command file: section '{name}' is placed twice"));
            }
            if align.map_or(false, |a| !a.is_power_of_two()) {
                return Err(format!("linker command file: ALIGN of '{name}' is not a power of two"));
            }
            seq.push((i, *align));
        }
        let origin = lcf.origin.ok_or("linker command file: the first MEMORY region has no origin")?;
        Ok(Plan { origin, seq, assigns: lcf.assigns, lcf: true, partial: false, force_active: lcf.force_active })
    }
}

pub struct Layout {
    pub lcf: bool,                              // a linker command file placed the sections
    pub forced_align: Vec<u32>,                 // the alignment the file gives each output section
    pub seq: Vec<usize>,                        // the output sections in order, as indices into ORDER
    pub pieces: Vec<Vec<Piece>>,                // by index into ORDER
    pub addr: Vec<u32>,
    pub size: Vec<u32>,
    pub align: Vec<u32>,
    pub fills: Vec<Vec<(u32, u32, u32)>>,       // (offset, size, alignment) of the padding before a piece
    pub nonempty: Vec<usize>,
    pub hdr: u32,
    pub file_off: Vec<u32>,
    pub sda: u32,
    pub sda2: u32,
    pub symbols: Vec<(String, u32)>,
    pub sym_map: HashMap<String, u32>,
    /// The symbols each assignment of the linker command file uses.
    pub assign_deps: HashMap<String, Vec<String>>,
}

fn has_contents(pieces: &[Vec<Piece>], i: usize) -> bool {
    pieces[i].iter().any(|p| !p.atoms.is_empty() || !p.gen.is_empty())
}

/// The output sections `_rom_copy_info` has an entry for (those with contents, and `.init`), and those `_bss_init_info`
/// clears (the bss ones with contents), in order.
pub fn init_info_sections(seq: &[usize], has_contents: impl Fn(usize) -> bool) -> (Vec<usize>, Vec<usize>) {
    let copied = seq.iter().copied().filter(|&i| !is_nobits(ORDER[i]) && (has_contents(i) || ORDER[i] == ".init")).collect();
    let cleared = seq.iter().copied().filter(|&i| is_nobits(ORDER[i]) && has_contents(i)).collect();
    (copied, cleared)
}

/// The names of the linker's symbols for an output section: its start, the ROM address of its start, its end.
pub fn section_symbol_names(name: &str) -> (String, String, String) {
    let dotted = name.starts_with('.');
    let tag = if dotted { name.trim_matches('.').replace('.', "_") } else { name.to_string() };
    let sep = if dotted { "_" } else { "" };
    (format!("_f{sep}{tag}"), format!("_f{sep}{tag}_rom"), format!("_e{sep}{tag}"))
}

/// Whether `name` is one of the `_f_X`, `_f_X_rom` and `_e_X` symbols the linker defines for an output section.
pub fn is_section_symbol(name: &str) -> bool {
    ORDER.iter().any(|o| { let (f, r, e) = section_symbol_names(o); name == f || name == r || name == e })
}

/// The widest alignment among the input sections that go to an output section, even those stripped.
fn widest_input_align(link: &Link, output: &str) -> u32 {
    link.objs.iter().flat_map(|o| o.elf.sections.iter())
        .filter(|s| s.flags & SHF_ALLOC != 0 && output_name(&s.name) == Some(output)).map(|s| s.align).max().unwrap_or(1)
}

pub fn oi(name: &str) -> usize {
    ORDER.iter().position(|&n| n == name).unwrap()
}

fn gen_piece(name: &str, gen: Vec<GenSymbol>) -> Piece {
    Piece { name: name.into(), obj: None, sec: None, atoms: vec![], start: 0, size: 0, addr: 0, gen }
}

impl Layout {
    pub fn new(link: &mut Link, plan: &Plan) -> R<Layout> {
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
            // The linker's own pieces: the `$00`/`$99` markers exist around constructors and destructors a program has
            // (the runtime's own `$10` and `$15` hooks do not count), or whenever an exception table is live; the
            // exception table index has its 32-byte info when one is live, and an empty `_eti_init_info` when only
            // code refers to it.
            let hooks = |p: &Piece| p.name.ends_with("$10") || p.name.ends_with("$15");
            if name == ".bss" {
                found.sort_by_key(|p| p.obj.zip(p.sec.as_ref()).map_or(false, |(o, s)| link.objs[o].elf.sections[s.index].synthetic));
            }
            if plan.partial {
                pieces.push(found);
                continue;
            }
            if name == ".ctors" || name == ".dtors" {
                found.sort_by_key(|p| (p.name == name, p.name.clone()));    // (an unsuffixed one follows the suffixed)
            }
            if (name == ".ctors" || name == ".dtors") && (link.eh || found.iter().any(|p| !hooks(p))) {
                let sym = format!("_{}", &name[1..]);
                found.insert(0, gen_piece(&format!("{name}$00"), vec![gen_symbol(sym.clone(), 0, 0, 0)]));
                found.push(gen_piece(&format!("{name}$99"), vec![gen_symbol(format!("{sym}$99"), 0, 4, 1)]));
            }
            if name == "extabindex" && link.eh {
                found.push(gen_piece("extabindex", vec![gen_symbol("_eti_init_info", 0, 32, 1)]));
            } else if name == "extabindex" && link.eti_ref {
                found.push(gen_piece("extabindex", vec![gen_symbol("_eti_init_info", 0, 0, 1)]));
            }
            pieces.push(found);
        }
        // `_rom_copy_info` and `_bss_init_info`, at the end of `.init` when code refers to them: a (ROM address, address, size)
        // entry for each section with contents, then a (address, size) entry for each bss section, each list ended by zeros
        if link.rom_ref {
            let seq: Vec<usize> = plan.seq.iter().map(|s| s.0).collect();
            let (copied, cleared) = init_info_sections(&seq, |i| has_contents(&pieces, i));
            let (copy_size, bss_size) = (12 * (copied.len() as u32 + 1), 8 * (cleared.len() as u32 + 1));
            pieces[oi(".init")].push(gen_piece(".init", vec![gen_symbol("_rom_copy_info", 0, copy_size, 1),
                                                             gen_symbol("_bss_init_info", copy_size, bss_size, 1)]));
        }
        let n = ORDER.len();
        let seq: Vec<usize> = plan.seq.iter().map(|s| s.0).collect();
        let has_contents = |i: usize| has_contents(&pieces, i);
        if let Some(i) = (0..n).find(|&i| has_contents(i) && !seq.contains(&i)) {
            return Err(format!("the linker command file does not place the section '{}'", ORDER[i]));
        }
        let nonempty: Vec<usize> = seq.iter().copied().filter(|&i| has_contents(i)).collect();
        let hdr = align(52 + if plan.partial { 0 } else { 32 * nonempty.len() as u32 }, 16);
        let mut forced_align = vec![1; n];
        for &(i, a) in &plan.seq {
            forced_align[i] = a.unwrap_or(1);
        }
        let mut lay = Layout { lcf: plan.lcf, forced_align, seq, pieces, addr: vec![0; n], size: vec![0; n], align: vec![1; n], fills: vec![vec![]; n],
                               nonempty, hdr, file_off: vec![0; n], sda: 0, sda2: 0, symbols: vec![],
                               sym_map: HashMap::new(), assign_deps: HashMap::new() };
        let mut cur = plan.origin;
        for &(i, forced_align) in &plan.seq {
            let name = ORDER[i];
            if !lay.nonempty.contains(&i) {
                lay.addr[i] = if plan.partial { 0 } else if name.starts_with(".PPC.EMB") { SDA0 } else { cur };
                continue;
            }
            let extra = if matches!(name, ".ctors" | ".dtors" | "extabindex") { 4 } else { 1 };
            lay.align[i] = lay.pieces[i].iter().filter_map(|p| p.sec.as_ref().map(|s| s.align)).max().unwrap_or(0)
                .max(extra).max(forced_align.unwrap_or(1));
            if plan.partial {
                cur = 0;
            }
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
                let gen_size: u32 = piece.gen.iter().map(|g| g.size).sum();
                offset += gen_size;
                // (in a partial link a section whose trailing atoms were dropped ends where the last live one does)
                piece.size = piece.sec.as_ref().map_or(gen_size, |s| if plan.partial { s.size.min(offset - piece.start) } else { s.size });
            }
            offset = align(offset, 4);
            lay.size[i] = offset;
            cur += offset;
        }
        // file offsets as the map shows them: a section without contents (or in the bss) starts where the last ended
        let mut pos = hdr;
        for &i in &lay.seq.clone() {
            if !lay.nonempty.contains(&i) {
                // (an empty section is aligned for the input sections there were, even when all of them were stripped)
                lay.file_off[i] = align(pos, widest_input_align(link, ORDER[i]));
            } else {
                pos = align(pos, lay.align[i]);
                lay.file_off[i] = pos;
                if !is_nobits(ORDER[i]) {
                    pos += lay.size[i];
                }
            }
        }
        lay.sda = lay.addr[oi(".sdata")] + 0x8000;
        lay.sda2 = lay.addr[oi(".sdata2")] + 0x8000;
        lay.generated_symbols(link);
        lay.assign(plan)?;
        Ok(lay)
    }

    /// The symbol assignments of a linker command file: a new symbol is listed before the linker's own, one the linker
    /// defines (`_stack_addr`) takes the new value in its place.
    fn assign(&mut self, plan: &Plan) -> R<()> {
        let sizes: HashMap<String, u32> = self.seq.iter().map(|&i| (ORDER[i].to_string(), self.size[i])).collect();
        let mut added = vec![];
        for (name, expr) in &plan.assigns {
            let value = expr.eval(&self.sym_map, &sizes)?;
            let deps = self.assign_deps.entry(name.clone()).or_default();
            deps.clear();
            expr.names(deps);
            self.sym_map.insert(name.clone(), value);
            match self.symbols.iter_mut().chain(added.iter_mut()).find(|s| s.0 == *name) {
                Some(slot) => slot.1 = value,
                None => added.push((name.clone(), value)),
            }
        }
        added.append(&mut self.symbols);
        self.symbols = added;
        Ok(())
    }

    pub fn gen_addr(&self, symbol: &str) -> Option<u32> {
        // (an empty `_eti_init_info`, there only because code refers to it, is at address 0)
        self.pieces.iter().flatten().find_map(|p| p.gen.iter().find(|g| g.name == symbol)
            .map(|g| if g.size == 0 && symbol == "_eti_init_info" { 0 } else { p.addr + g.offset }))
    }

    fn generated_symbols(&mut self, link: &Link) {
        let mut syms: Vec<(String, u32)> = vec![];
        for &i in &self.seq {
            let name = ORDER[i];
            let (first, rom, end) = section_symbol_names(name);
            let (f, e) = (self.addr[i], self.addr[i] + self.size[i]);
            syms.push((first, f));
            // (with a linker command file, an empty `.bss` has a ROM address too)
            if !is_nobits(name) || (self.lcf && name == ".bss" && self.size[i] == 0) {
                // (a ROM address is aligned for the input sections there were, even when all of them were stripped)
                syms.push((rom, align(f, widest_input_align(link, name).max(self.forced_align[i]))));
            }
            syms.push((end, e));
        }
        let functions = link.objs.iter().flat_map(|o| o.atoms.values().flatten())
            .filter(|&&a| link.atoms[a].live && link.atoms[a].symbols.iter().any(|&s| link.objs[link.atoms[a].obj].sym(s).typ == STT_FUNC))
            .count() as u32;
        syms.extend([("_stack_addr", 0x3DFFF0), ("_stack_end", 0x3CFFF0), ("_heap_addr", 0x2CFFF0), ("_heap_end", 0x3CFFF0),
                     ("_nbfunctions", functions), ("SIZEOF_HEADERS", self.hdr), ("_SDA_BASE_", self.sda),
                     ("_SDA2_BASE_", self.sda2), ("_ABS_SDA_BASE_", self.sda), ("_ABS_SDA2_BASE_", self.sda2)]
            .map(|(n, v)| (n.to_string(), v)));
        self.sym_map = syms.iter().cloned().collect();
        self.symbols = syms;
    }
}
