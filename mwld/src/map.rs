//! The link map file.
use crate::elf::STB_LOCAL;
use crate::layout::{oi, Layout, Piece};
use crate::link::{Link, ORDER};

const GENERATED: &str = "Linker Generated Symbol File ";

fn row(off: u32, size: u32, addr: u32, file: u32, align: u32, name: &str, owner: &str) -> String {
    format!("  {off:08x} {size:06x} {addr:08x} {file:08x} {align:2} {name} \t{owner}\n")
}

fn section_head(out: &mut String, name: &str) {
    out.push('\n');
    out.push_str(&format!("\n{name} section layout\n  Starting        Virtual  File\n  address  Size   address  offset\n  ---------------------------------\n"));
}

fn owner(link: &Link, piece: &Piece) -> String {
    piece.obj.map_or_else(|| GENERATED.to_string(), |o| link.objs[o].label())
}

fn symbol_rows(link: &Link, lay: &Layout, i: usize, piece: &Piece, file_off: Option<u32>, unused: bool) -> Vec<String> {
    let Some(o) = piece.obj else { return vec![] };
    let obj = &link.objs[o];
    // (position among the object's atoms, sort key, text); the rows of dead atoms are the ones `-mapunused` adds
    let mut items: Vec<(u32, (u32, u8, usize), String)> = vec![];
    let mut live = vec![];
    for &a in &piece.atoms {
        let atom = &link.atoms[a];
        if unused {
            // (a global without size inside live code that nothing refers to, such as `_savefpr_14`)
            for &s in atom.symbols.iter().filter(|&&s| {
                let sym = obj.sym(s);
                !obj.lost.contains(&s) && !(sym.size > 0 || sym.bind == STB_LOCAL || link.referenced.contains(&(o, s)))
            }) {
                let sym = obj.sym(s);
                items.push((atom.start, (atom.out_offset + sym.value - atom.start, 2, s),
                            format!("  UNUSED   {:06x} ........ ........    {} {}
", 0, sym.name, obj.label())));
            }
        }
        for &s in atom.symbols.iter().filter(|&&s| {
            let sym = obj.sym(s);
            !obj.lost.contains(&s) && (sym.size > 0 || sym.bind == STB_LOCAL || link.referenced.contains(&(o, s)))
        }) {
            let sym = obj.sym(s);
            let owner = if atom.whole_section { piece.name.clone() } else { obj.sym(atom.symbols[0]).name.clone() };
            // (the file offset of a symbol without size inside an atom is where the atom ends, and the row follows the
            // sized symbol at the same address; a `...` mark at the start of a whole section is the exception)
            let inside = sym.size == 0 && (sym.value > atom.start || !atom.whole_section);
            let class = if sym.size > 0 { 1 } else if inside { 2 } else { 0 };
            live.push((atom.start, atom.out_offset + sym.value - atom.start, class, s, owner,
                       inside.then_some(atom.out_offset + atom.size)));
        }
    }
    for (start, off, class, s, owner, end) in live {
        let sym = obj.sym(s);
        let fo = file_off.unwrap_or(lay.file_off[i] + end.unwrap_or(off));
        let text = if sym.size == 0 {
            format!("  {off:08x} {:06x} {:08x} {fo:08x}    {} (entry of {}) 	{}
", 0, lay.addr[i] + off, sym.name,
                    owner, obj.label())
        } else {
            row(off, sym.size, lay.addr[i] + off, fo, obj.aligns[s].max(1), &sym.name, &obj.label())
        };
        items.push((start, (off, class, s), text));
    }
    if unused {
        if let Some(sec) = &piece.sec {
            for &a in obj.atoms.get(&sec.index).into_iter().flatten().filter(|&&a| !link.atoms[a].live) {
                let atom = &link.atoms[a];
                for &s in &atom.symbols {
                    let sym = obj.sym(s);
                    if sym.size > 0 && !obj.lost.contains(&s) {
                        items.push((atom.start, (sym.value, 0, s),
                                    format!("  UNUSED   {:06x} ........ ........    {} {}
", sym.size, sym.name, obj.label())));
                    }
                }
            }
        }
    }
    items.sort_by_key(|i| (i.0, i.1));
    items.into_iter().map(|i| i.2).collect()
}

pub fn write_map(link: &Link, lay: &Layout, unused: bool) -> String {
    let mut out = format!("Link map of {}\n", link.entry);
    if link.partial {
        // the names nothing defines, in the order the linker came across them
        let generated = |name: &str| lay.pieces.iter().flatten().any(|p| p.gen.iter().any(|g| g.name == name));
        for (name, _) in link.not_found.iter().filter(|(name, _)| !generated(name)) {
            out.push_str(&format!(">>> SYMBOL NOT FOUND: {name}
"));
        }
    }
    for &i in &lay.seq {
        let name = ORDER[i];
        if name == ".got" {
            continue;
        }
        section_head(&mut out, name);
        if name == "extabindex" {
            continue;
        }
        for piece in &lay.pieces[i] {
            if piece.atoms.is_empty() && piece.gen.is_empty() {
                continue;
            }
            let fill = lay.fills[i].iter().find(|f| f.0 + f.1 == piece.start && piece.sec.is_some());
            if let Some(f) = fill {
                out.push_str(&format!("  {:08x} {:06x} {:08x} {:08x} {:2} *fill*\n", f.0, f.1, lay.addr[i] + piece.start,
                                      lay.file_off[i] + piece.start, f.2));
            }
            let who = owner(link, piece);
            out.push_str(&row(piece.start, piece.size, piece.addr, lay.file_off[i] + piece.start, 1, &piece.name, &who));
            for g in &piece.gen {
                out.push_str(&row(piece.start + g.offset, g.size, piece.addr + g.offset,
                                  lay.file_off[i] + piece.start + g.offset, 4, &g.name, &who));
            }
            out.extend(symbol_rows(link, lay, i, piece, None, unused));
        }
    }
    // the exception table index, listed again after the others, when there is one
    if link.eh {
        section_head(&mut out, "extabindex");
        let ex = oi("extabindex");
        let end_off = lay.file_off[ex] + lay.size[ex];
        for piece in &lay.pieces[ex] {
            out.extend(symbol_rows(link, lay, ex, piece, Some(end_off), unused));
            let who = owner(link, piece);
            for g in &piece.gen {
                out.push_str(&row(piece.start + g.offset, g.size, piece.addr + g.offset, end_off, 4, &g.name, &who));
            }
        }
    }
    out.push_str("\n\nMemory map:\n                   Starting Size     File\n                   address           Offset\n");
    for &i in &lay.seq {
        let name = ORDER[i];
        // (with a linker command file, an empty `.bss` and `.stack` are not listed)
        if lay.lcf && lay.size[i] == 0 && matches!(name, ".bss" | ".stack") {
            continue;
        }
        out.push_str(&format!("  {:>15}  {:08x} {:08x} {:08x}\n", name, lay.addr[i], lay.size[i], lay.file_off[i]));
    }
    if !link.partial {
        out.push_str("\n\nLinker generated symbols:\n");
        for (sym, value) in &lay.symbols {
            out.push_str(&format!("{sym:>25} {value:08x}\n"));
        }
    }
    out
}
