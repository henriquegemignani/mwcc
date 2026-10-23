//! The linker command file: `MEMORY`, `SECTIONS` (one `GROUP` of output sections, then symbol assignments) and
//! `FORCEACTIVE`. A section body lists input sections by name (`*(.data) *(extab)`); nothing else is supported in one.
use crate::elf::R;
use std::collections::HashMap;

pub enum Expr {
    Num(u32),
    Sym(String),
    SizeOf(String),
    Not(Box<Expr>),
    Bin(char, Box<Expr>, Box<Expr>),
}

pub struct Lcf {
    pub origin: Option<u32>,
    pub memory: bool,
    /// The output sections in order, each with the alignment the file gives it.
    pub sections: Vec<(String, Option<u32>)>,
    /// The input sections each output section names (`*(.data) *(extab)`), by output section.
    pub bodies: Vec<(String, Vec<String>)>,
    /// The symbol assignments, in order.
    pub assigns: Vec<(String, Expr)>,
    pub force_active: Vec<String>,
}

fn tokens(text: &str) -> R<Vec<String>> {
    let chars: Vec<char> = text.chars().collect();
    let (mut out, mut i) = (vec![], 0);
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            let end = (i + 2..chars.len().saturating_sub(1)).find(|&k| chars[k] == '*' && chars[k + 1] == '/')
                .ok_or("linker command file: unterminated comment")?;
            i = end + 2;
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c.is_alphanumeric() || "_.$?@".contains(c) {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || "_.$?@".contains(chars[i])) {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
        } else if "{}():=;>+-*&|~,<".contains(c) {
            if (c == '<' || c == '>') && chars.get(i + 1) == Some(&c) {
                out.push(format!("{c}{c}"));
                i += 2;
            } else {
                out.push(c.to_string());
                i += 1;
            }
        } else {
            return Err(format!("linker command file: unexpected '{c}'"));
        }
    }
    Ok(out)
}

fn number(token: &str) -> Option<u32> {
    match token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => token.parse().ok(),
    }
}

struct Parser {
    toks: Vec<String>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.at).map(String::as_str)
    }

    fn next(&mut self) -> R<String> {
        let t = self.toks.get(self.at).cloned().ok_or("linker command file: unexpected end")?;
        self.at += 1;
        Ok(t)
    }

    fn expect(&mut self, want: &str) -> R<()> {
        let got = self.next()?;
        if got == want { Ok(()) } else { Err(format!("linker command file: expected '{want}', found '{got}'")) }
    }

    fn eat(&mut self, want: &str) -> bool {
        let hit = self.peek() == Some(want);
        if hit {
            self.at += 1;
        }
        hit
    }

    // expression: | lowest, then &, then << >>, then + -, then * , then unary ~ and primaries
    fn expr(&mut self) -> R<Expr> {
        self.binary(0)
    }

    fn binary(&mut self, level: usize) -> R<Expr> {
        const LEVELS: [&[&str]; 4] = [&["|"], &["&"], &["<<", ">>", "+", "-"], &["*"]];
        if level == LEVELS.len() {
            return self.unary();
        }
        let mut left = self.binary(level + 1)?;
        while let Some(op) = self.peek().filter(|t| LEVELS[level].contains(t)).map(String::from) {
            self.at += 1;
            let right = self.binary(level + 1)?;
            let c = match op.as_str() { "<<" => 'l', ">>" => 'r', o => o.chars().next().unwrap() };
            left = Expr::Bin(c, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> R<Expr> {
        let t = self.next()?;
        if t == "~" {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        if t == "(" {
            let e = self.expr()?;
            self.expect(")")?;
            return Ok(e);
        }
        if let Some(n) = number(&t) {
            return Ok(Expr::Num(n));
        }
        if t == "SIZEOF" {
            self.expect("(")?;
            let name = self.next()?;
            self.expect(")")?;
            return Ok(Expr::SizeOf(name));
        }
        if t.chars().next().map_or(false, |c| c.is_alphabetic() || "_.$".contains(c)) {
            return Ok(Expr::Sym(t));
        }
        Err(format!("linker command file: unexpected '{t}' in an expression"))
    }
}

/// Cuts the `FORCEACTIVE { ... }` block out of the text: its entries are mangled names, words of any characters.
fn split_force_active(text: &str) -> R<(String, Vec<String>)> {
    let Some(at) = text.find("FORCEACTIVE") else { return Ok((text.to_string(), vec![])) };
    let open = text[at..].find('{').ok_or("linker command file: FORCEACTIVE without a block")? + at;
    let close = text[open..].find('}').ok_or("linker command file: unterminated FORCEACTIVE")? + open;
    let names = text[open + 1..close].split_whitespace().map(String::from).collect();
    Ok((format!("{}{}", &text[..at], &text[close + 1..]), names))
}

pub fn parse(text: &str) -> R<Lcf> {
    let (text, force_active) = split_force_active(text)?;
    let mut p = Parser { toks: tokens(&text)?, at: 0 };
    let mut lcf = Lcf { origin: None, memory: false, sections: vec![], assigns: vec![], bodies: vec![], force_active };
    while let Some(head) = p.peek().map(String::from) {
        p.at += 1;
        match head.as_str() {
            "MEMORY" => {
                lcf.memory = true;
                p.expect("{")?;
                let mut first = true;
                while !p.eat("}") {
                    let _name = p.next()?;
                    p.expect(":")?;
                    while !p.eat(";") && p.peek() != Some("}") {
                        let key = p.next()?;
                        if key == "origin" || key == "length" {
                            p.expect("=")?;
                            let value = number(&p.next()?).ok_or("linker command file: bad number")?;
                            if key == "origin" && first {
                                lcf.origin = Some(value);
                            }
                        } else if key != "," {
                            return Err(format!("linker command file: unexpected '{key}' in MEMORY"));
                        }
                    }
                    first = false;
                }
            }
            "SECTIONS" => {
                p.expect("{")?;
                while !p.eat("}") {
                    if p.eat("GROUP") || p.peek() == Some("{") {
                        p.eat(":");
                        p.expect("{")?;
                        while !p.eat("}") {
                            let name = p.next()?;
                            let mut align = None;
                            if p.eat("ALIGN") {
                                p.expect("(")?;
                                align = Some(number(&p.next()?).ok_or("linker command file: bad ALIGN")?);
                                p.expect(")")?;
                            }
                            p.expect(":")?;
                            p.expect("{")?;
                            let mut body = vec![];
                            while !p.eat("}") {
                                p.expect("*")?;
                                p.expect("(")?;
                                body.push(p.next()?);
                                p.expect(")")?;
                            }
                            if !body.is_empty() {
                                lcf.bodies.push((name.clone(), body));
                            }
                            lcf.sections.push((name, align));
                        }
                        if p.eat(">") {
                            p.next()?;
                        }
                    } else {
                        let name = p.next()?;
                        p.expect("=")?;
                        let value = p.expr()?;
                        p.eat(";");
                        lcf.assigns.push((name, value));
                    }
                }
            }
            other => return Err(format!("linker command file: unsupported statement '{other}'")),
        }
    }
    Ok(lcf)
}

impl Expr {
    /// The names of the symbols the expression uses.
    pub fn names(&self, out: &mut Vec<String>) {
        match self {
            Expr::Sym(s) => out.push(s.clone()),
            Expr::Not(e) => e.names(out),
            Expr::Bin(_, a, b) => {
                a.names(out);
                b.names(out);
            }
            Expr::Num(_) | Expr::SizeOf(_) => {}
        }
    }

    /// The value, given the symbols defined so far and the sizes of output sections.
    pub fn eval(&self, symbols: &HashMap<String, u32>, sizes: &HashMap<String, u32>) -> R<u32> {
        Ok(match self {
            Expr::Num(n) => *n,
            Expr::Sym(s) => *symbols.get(s).ok_or(format!("linker command file: undefined symbol '{s}'"))?,
            Expr::SizeOf(s) => *sizes.get(s).ok_or(format!("linker command file: no section '{s}'"))?,
            Expr::Not(e) => !e.eval(symbols, sizes)?,
            Expr::Bin(op, a, b) => {
                let (a, b) = (a.eval(symbols, sizes)?, b.eval(symbols, sizes)?);
                match op {
                    '+' => a.wrapping_add(b),
                    '-' => a.wrapping_sub(b),
                    '*' => a.wrapping_mul(b),
                    '&' => a & b,
                    '|' => a | b,
                    'l' => a.wrapping_shl(b),
                    _ => a.wrapping_shr(b),
                }
            }
        })
    }
}
