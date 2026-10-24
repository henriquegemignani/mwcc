//! Big-endian ELF32 relocatable files and `!<arch>` archives, read into plain structures.
pub type R<T> = Result<T, String>;

// ELF section types and flags, symbol bindings, types and special indices, and the PowerPC relocation types used.
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_RELA: u32 = 4;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_STRTAB: u32 = 3;
pub const SHF_WRITE: u32 = 1;
pub const SHF_ALLOC: u32 = 2;
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const SHN_ABS: u16 = 0xFFF1;
pub const SHN_LORESERVE: u16 = 0xFF00;
pub const SHN_COMMON: u16 = 0xFFF2;
pub const PT_LOAD: u32 = 1;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const EM_PPC: u16 = 20;
pub const EF_PPC_EMB: u32 = 0x80000000;
pub const R_PPC_ADDR32: u8 = 1;
pub const R_PPC_ADDR16: u8 = 3;
pub const R_PPC_ADDR16_LO: u8 = 4;
pub const R_PPC_ADDR16_HI: u8 = 5;
pub const R_PPC_ADDR16_HA: u8 = 6;
pub const R_PPC_REL24: u8 = 10;
pub const R_PPC_REL14: u8 = 11;
pub const R_PPC_EMB_SDA21: u8 = 109;

pub struct Section {
    pub index: usize,
    pub name: String,
    pub typ: u32,
    pub flags: u32,
    pub size: u32,
    pub info: u32,
    pub align: u32,
    pub data: Vec<u8>,
    pub synthetic: bool,        // made by the linker, not in the file (the home of common symbols)
}

pub struct Symbol {
    pub index: usize,
    pub name: String,
    pub value: u32,
    pub size: u32,
    pub bind: u8,
    pub typ: u8,
    pub shndx: u16,
}

#[derive(Clone)]
pub struct Rela {
    pub offset: u32,
    pub sym: usize,
    pub kind: u8,
    pub addend: i32,
}

pub struct ElfFile {
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
}

pub fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}

pub fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(b[off..off + 2].try_into().unwrap())
}

pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

pub fn to_latin1(text: &str) -> Vec<u8> {
    text.chars().map(|c| c as u32 as u8).collect()
}

fn cstr(table: &[u8], offset: usize) -> R<String> {
    let rest = table.get(offset..).ok_or("string offset out of range")?;
    let end = rest.iter().position(|&b| b == 0).ok_or("unterminated string")?;
    Ok(latin1(&rest[..end]))
}

impl ElfFile {
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// The relocations (SHT_RELA) that apply to the section `index`, in file order.
    pub fn relocs(&self, index: usize) -> Vec<Rela> {
        let mut out = vec![];
        for rela in self.sections.iter().filter(|s| s.typ == SHT_RELA && s.info as usize == index) {
            for off in (0..rela.data.len() / 12 * 12).step_by(12) {
                let info = be32(&rela.data, off + 4);
                out.push(Rela { offset: be32(&rela.data, off), sym: (info >> 8) as usize, kind: info as u8,
                                addend: be32(&rela.data, off + 8) as i32 });
            }
        }
        out
    }
}

pub fn parse(raw: &[u8], path: &str) -> R<ElfFile> {
    if raw.len() < 52 || &raw[..4] != b"\x7fELF" || raw[4] != 1 || raw[5] != 2 {
        return Err(format!("{path}: not a big-endian ELF32 file"));
    }
    let (shoff, shentsize, shnum, shstrndx) =
        (be32(raw, 32) as usize, be16(raw, 46) as usize, be16(raw, 48) as usize, be16(raw, 50) as usize);
    let mut names = vec![];
    let mut sections = vec![];
    for i in 0..shnum {
        let at = shoff + i * shentsize;
        if at + 40 > raw.len() {
            return Err(format!("{path}: section header table out of range"));
        }
        let (name, typ, flags, offset, size) =
            (be32(raw, at), be32(raw, at + 4), be32(raw, at + 8), be32(raw, at + 16) as usize, be32(raw, at + 20));
        let data = if typ == SHT_NOBITS { vec![] } else {
            raw.get(offset..offset + size as usize).ok_or(format!("{path}: section data out of range"))?.to_vec()
        };
        names.push(name);
        sections.push(Section { index: i, name: String::new(), typ, flags, size, info: be32(raw, at + 28),
                                align: be32(raw, at + 32), data, synthetic: false });
    }
    if shnum > 0 {
        let table = sections.get(shstrndx).ok_or(format!("{path}: bad section name table index"))?.data.clone();
        for (s, n) in sections.iter_mut().zip(names) {
            s.name = cstr(&table, n as usize)?;
        }
    }
    let mut symbols = vec![];
    for s in sections.iter().filter(|s| s.typ == SHT_SYMTAB) {
        let link = be32(raw, shoff + s.index * shentsize + 24) as usize;
        let strings = &sections.get(link).ok_or(format!("{path}: bad string table index"))?.data;
        symbols.clear();
        for i in 0..s.data.len() / 16 {
            let d = &s.data[i * 16..];
            symbols.push(Symbol { index: i, name: cstr(strings, be32(d, 0) as usize)?, value: be32(d, 4),
                                  size: be32(d, 8), bind: d[12] >> 4, typ: d[12] & 15, shndx: be16(d, 14) });
        }
    }
    for rela in sections.iter().filter(|s| s.typ == SHT_RELA) {
        if (0..rela.data.len() / 12).any(|k| (be32(&rela.data, k * 12 + 4) >> 8) as usize >= symbols.len()) {
            return Err(format!("{path}: relocation symbol index out of range"));
        }
    }
    Ok(ElfFile { sections, symbols })
}

/// The members of a `!<arch>` archive: (name, contents).
pub fn archive_members(raw: &[u8]) -> R<Vec<(String, Vec<u8>)>> {
    if !raw.starts_with(b"!<arch>\n") {
        return Err("not an archive".into());
    }
    let (mut members, mut pos, mut longnames) = (vec![], 8, vec![]);
    while pos + 60 <= raw.len() {
        let size: usize = latin1(&raw[pos + 48..pos + 58]).trim().parse().map_err(|_| "bad archive member size")?;
        let data = raw.get(pos + 60..pos + 60 + size).ok_or("archive member out of range")?.to_vec();
        let name = latin1(&raw[pos..pos + 16]).trim_end().to_string();
        if name == "//" {
            longnames = data;
        } else if name.starts_with('/') && name[1..].chars().all(|c| c.is_ascii_digit()) && name.len() > 1 {
            let at: usize = name[1..].parse().map_err(|_| "bad archive long name offset")?;
            // (the table ends a name with NUL, or with `/` and a newline as GNU `ar` writes it)
            let rest = longnames.get(at..).ok_or("string offset out of range")?;
            let end = rest.iter().position(|&b| b == 0 || b == b'\n').ok_or("unterminated string")?;
            members.push((latin1(&rest[..end]).trim_end_matches('/').to_string(), data));
        } else if name != "/" && name != "/SYM64/" {
            members.push((name.trim_end_matches('/').to_string(), data));
        }
        pos += 60 + size + (size & 1);
    }
    Ok(members)
}
