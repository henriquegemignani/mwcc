//! The linker command file: `MEMORY`, `SECTIONS` (one `GROUP` of output sections, then symbol assignments) and
//! `FORCEACTIVE`. A section body lists input sections by name (`*(.data) *(extab)`); nothing else is supported in one.
use crate::elf::R;
use std::collections::HashMap;

#[derive(Clone, Copy)]
pub enum Op {
    Or,
    And,
    Shl,
    Shr,
    Add,
    Sub,
    Mul,
}

pub enum Expr {
    Num(u32),
    Sym(String),
    SizeOf(String),
    Not(Box<Expr>),
    Bin(Op, Box<Expr>, Box<Expr>),
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
        const LEVELS: [&[(&str, Op)]; 4] = [
            &[("|", Op::Or)],
            &[("&", Op::And)],
            &[("<<", Op::Shl), (">>", Op::Shr), ("+", Op::Add), ("-", Op::Sub)],
            &[("*", Op::Mul)],
        ];
        if level == LEVELS.len() {
            return self.unary();
        }
        let mut left = self.binary(level + 1)?;
        while let Some(op) = self.peek().and_then(|t| LEVELS[level].iter().find(|l| l.0 == t)).map(|l| l.1) {
            self.at += 1;
            let right = self.binary(level + 1)?;
            left = Expr::Bin(op, Box::new(left), Box::new(right));
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
        if t.chars().next().is_some_and(|c| c.is_alphabetic() || "_.$".contains(c)) {
            return Ok(Expr::Sym(t));
        }
        Err(format!("linker command file: unexpected '{t}' in an expression"))
    }
}

/// The text with its comments replaced by spaces.
fn strip_comments(text: &str) -> R<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('/') {
        let (kept, tail) = rest.split_at(at);
        out.push_str(kept);
        if let Some(body) = tail.strip_prefix("/*") {
            let end = body.find("*/").ok_or("linker command file: unterminated comment")?;
            out.push(' ');
            rest = &body[end + 2..];
        } else if tail.starts_with("//") {
            out.push(' ');
            rest = tail.find('\n').map_or("", |n| &tail[n..]);
        } else {
            out.push('/');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    Ok(out)
}

/// Cuts the `FORCEACTIVE { ... }` blocks out of the text (already without comments): their entries are mangled names,
/// words of any characters.
fn split_force_active(text: &str) -> R<(String, Vec<String>)> {
    const WORD: &str = "FORCEACTIVE";
    let is_word = |c: char| c.is_alphanumeric() || "_.$?@".contains(c);
    let (mut rest, mut kept, mut names) = (text, String::new(), vec![]);
    while let Some(at) = rest.find(WORD) {
        let (before, after) = (&rest[..at], &rest[at + WORD.len()..]);
        if before.chars().next_back().is_some_and(is_word) || after.chars().next().is_some_and(is_word) {
            kept.push_str(&rest[..at + WORD.len()]);
            rest = after;
            continue;
        }
        kept.push_str(before);
        let open = after.find('{').ok_or("linker command file: FORCEACTIVE without a block")?;
        let close = after[open..].find('}').ok_or("linker command file: unterminated FORCEACTIVE")? + open;
        names.extend(after[open + 1..close].split_whitespace().map(String::from));
        rest = &after[close + 1..];
    }
    kept.push_str(rest);
    Ok((kept, names))
}

pub fn parse(text: &str) -> R<Lcf> {
    let (text, force_active) = split_force_active(&strip_comments(text)?)?;
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
                    Op::Add => a.wrapping_add(b),
                    Op::Sub => a.wrapping_sub(b),
                    Op::Mul => a.wrapping_mul(b),
                    Op::And => a & b,
                    Op::Or => a | b,
                    Op::Shl => a.wrapping_shl(b),
                    Op::Shr => a.wrapping_shr(b),
                }
            }
        })
    }
}
