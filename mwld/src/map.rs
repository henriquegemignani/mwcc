//! The link map file.
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

fn symbol_rows(link: &Link, lay: &Layout, i: usize, piece: &Piece, file_off: Option<u32>) -> Vec<String> {
    let Some(o) = piece.obj else { return vec![] };
    let obj = &link.objs[o];
    let mut items = vec![];
    for &a in &piece.atoms {
        let atom = &link.atoms[a];
        for &s in &atom.symbols {
            items.push((atom.out_offset + obj.sym(s).value - atom.start, s));
        }
    }
    items.sort();
    items.iter().map(|&(off, s)| {
        let sym = obj.sym(s);
        let fo = file_off.unwrap_or(lay.map_off[i] + off);
        if sym.size == 0 {
            format!("  {off:08x} {:06x} {:08x} {fo:08x}    {} (entry of {}) \t{}\n", 0, lay.addr[i] + off, sym.name,
                    piece.name, obj.label())
        } else {
            row(off, sym.size, lay.addr[i] + off, fo, obj.aligns[s].max(1), &sym.name, &obj.label())
        }
    }).collect()
}

pub fn write_map(link: &Link, lay: &Layout) -> String {
    let mut out = format!("Link map of {}\n", link.entry);
    for (i, &name) in ORDER.iter().enumerate() {
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
                                      lay.map_off[i] + piece.start, f.2));
            }
            let who = owner(link, piece);
            out.push_str(&row(piece.start, piece.size, piece.addr, lay.map_off[i] + piece.start, 1, &piece.name, &who));
            for (sym, off, size, _) in &piece.gen {
                out.push_str(&row(piece.start + off, *size, piece.addr + off, lay.map_off[i] + piece.start + off, 4, sym,
                                  &who));
            }
            out.extend(symbol_rows(link, lay, i, piece, None));
        }
    }
    // the exception table index, after the others
    section_head(&mut out, "extabindex");
    let ex = oi("extabindex");
    let end_off = lay.map_off[ex] + lay.size[ex];
    for piece in &lay.pieces[ex] {
        out.extend(symbol_rows(link, lay, ex, piece, Some(end_off)));
        let who = owner(link, piece);
        for (sym, off, size, _) in &piece.gen {
            out.push_str(&row(piece.start + off, *size, piece.addr + off, end_off, 4, sym, &who));
        }
    }
    out.push_str("\n\nMemory map:\n                   Starting Size     File\n                   address           Offset\n");
    for (i, name) in ORDER.iter().enumerate() {
        out.push_str(&format!("  {:>15}  {:08x} {:08x} {:08x}\n", name, lay.addr[i], lay.size[i], lay.map_off[i]));
    }
    out.push_str("\n\nLinker generated symbols:\n");
    for (sym, value) in &lay.symbols {
        out.push_str(&format!("{sym:>25} {value:08x}\n"));
    }
    out
}
