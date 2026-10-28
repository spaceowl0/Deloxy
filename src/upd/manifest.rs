//! Strict manifest parser. Only ever run on bytes whose signature has already been verified, but still
//! treats them as hostile: bounded sizes/depth, checked arithmetic, no unknown keys, no duplicates.

use alloc::string::String;
use alloc::vec::Vec;

pub const MAX_MANIFEST: usize = 64 * 1024;
pub const MAX_ARTIFACTS: usize = 16;
pub const MAX_ARTIFACT_SIZE: u64 = 8 * 1024 * 1024;
pub const MAX_TOTAL_SIZE: u64 = 16 * 1024 * 1024;

pub type Version = [u16; 3];

#[derive(Debug, Clone)]
pub struct Artifact {
    pub name: String,
    pub size: u64,
    pub sha256: [u8; 32],
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub version: Version,
    pub min_version: Version,
    pub created: u64,
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug)]
enum J {
    Num(u64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

type R<T> = Result<T, &'static str>;

impl<'a> P<'a> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.i += 1;
        }
    }
    fn eat(&mut self, c: u8) -> R<()> {
        if self.b.get(self.i) == Some(&c) {
            self.i += 1;
            Ok(())
        } else {
            Err("unexpected character")
        }
    }
    fn string(&mut self) -> R<String> {
        self.eat(b'"')?;
        let mut s = String::new();
        loop {
            let c = *self.b.get(self.i).ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or("unterminated escape")?;
                    self.i += 1;
                    match e {
                        b'"' | b'\\' | b'/' => s.push(e as char),
                        _ => return Err("unsupported escape"),
                    }
                }
                0x20..=0x7E => s.push(c as char),
                _ => return Err("non-ascii or control character in string"),
            }
            if s.len() > 256 {
                return Err("string too long");
            }
        }
    }
    fn number(&mut self) -> R<u64> {
        let start = self.i;
        let mut v: u64 = 0;
        while let Some(c @ b'0'..=b'9') = self.b.get(self.i) {
            v = v.checked_mul(10).and_then(|v| v.checked_add((c - b'0') as u64)).ok_or("number overflow")?;
            self.i += 1;
        }
        let n = self.i - start;
        if n == 0 || (n > 1 && self.b[start] == b'0') {
            return Err("bad number");
        }
        Ok(v)
    }
    fn value(&mut self, depth: u32) -> R<J> {
        if depth > 4 {
            return Err("nesting too deep");
        }
        self.ws();
        match self.b.get(self.i).ok_or("unexpected end")? {
            b'"' => Ok(J::Str(self.string()?)),
            b'0'..=b'9' => Ok(J::Num(self.number()?)),
            b'[' => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(J::Arr(v));
                }
                loop {
                    if v.len() >= 64 {
                        return Err("array too long");
                    }
                    v.push(self.value(depth + 1)?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(J::Arr(v));
                        }
                        _ => return Err("bad array"),
                    }
                }
            }
            b'{' => {
                self.i += 1;
                let mut v: Vec<(String, J)> = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(J::Obj(v));
                }
                loop {
                    if v.len() >= 16 {
                        return Err("object too large");
                    }
                    self.ws();
                    let k = self.string()?;
                    if v.iter().any(|(x, _)| *x == k) {
                        return Err("duplicate key");
                    }
                    self.ws();
                    self.eat(b':')?;
                    v.push((k, self.value(depth + 1)?));
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(J::Obj(v));
                        }
                        _ => return Err("bad object"),
                    }
                }
            }
            _ => Err("unsupported value"),
        }
    }
}

pub fn parse_version(s: &str) -> R<Version> {
    let mut out = [0u16; 3];
    let mut n = 0;
    for part in s.split('.') {
        if n >= 3 || part.is_empty() || part.len() > 5 || (part.len() > 1 && part.starts_with('0')) || !part.bytes().all(|c| c.is_ascii_digit()) {
            return Err("bad version");
        }
        out[n] = part.parse::<u16>().map_err(|_| "version component out of range")?;
        n += 1;
    }
    if n != 3 {
        return Err("bad version");
    }
    Ok(out)
}

pub fn hex32(s: &str) -> R<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err("bad sha256 length");
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Ok(out)
}

pub fn nib(c: u8) -> R<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err("bad hex digit"),
    }
}

fn safe_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s != "." && s != ".." && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// A request path that can be embedded in an HTTP request line without any injection risk.
pub fn safe_path(s: &str) -> bool {
    s.starts_with('/') && s.len() <= 128 && !s.contains("..") && !s.contains("//") && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'.' | b'_' | b'-'))
}

pub fn parse(data: &[u8]) -> R<Manifest> {
    if data.len() > MAX_MANIFEST {
        return Err("manifest too large");
    }
    let mut p = P { b: data, i: 0 };
    let root = p.value(0)?;
    p.ws();
    if p.i != data.len() {
        return Err("trailing data after manifest");
    }
    let J::Obj(fields) = root else { return Err("manifest is not an object") };
    let get = |k: &str| fields.iter().find(|(n, _)| n == k).map(|(_, v)| v);
    if fields.len() != 5 {
        return Err("unexpected or missing manifest fields");
    }
    match get("format") {
        Some(J::Num(1)) => {}
        _ => return Err("unsupported manifest format"),
    }
    let Some(J::Str(v)) = get("version") else { return Err("missing version") };
    let Some(J::Str(mv)) = get("min_version") else { return Err("missing min_version") };
    let Some(J::Num(created)) = get("created") else { return Err("missing created") };
    let Some(J::Arr(arts)) = get("artifacts") else { return Err("missing artifacts") };
    if arts.len() > MAX_ARTIFACTS {
        return Err("too many artifacts");
    }
    let mut out = Vec::new();
    let mut total: u64 = 0;
    for a in arts {
        let J::Obj(f) = a else { return Err("artifact is not an object") };
        if f.len() != 4 {
            return Err("unexpected or missing artifact fields");
        }
        let g = |k: &str| f.iter().find(|(n, _)| n == k).map(|(_, v)| v);
        let (Some(J::Str(name)), Some(J::Num(size)), Some(J::Str(sha)), Some(J::Str(path))) = (g("name"), g("size"), g("sha256"), g("path")) else {
            return Err("bad artifact fields");
        };
        if !safe_name(name) || !safe_path(path) || *size > MAX_ARTIFACT_SIZE {
            return Err("unsafe artifact name/path or size");
        }
        total = total.checked_add(*size).ok_or("total size overflow")?;
        if total > MAX_TOTAL_SIZE {
            return Err("artifacts too large in total");
        }
        if out.iter().any(|x: &Artifact| x.name == *name) {
            return Err("duplicate artifact name");
        }
        out.push(Artifact { name: name.clone(), size: *size, sha256: hex32(sha)?, path: path.clone() });
    }
    Ok(Manifest { version: parse_version(v)?, min_version: parse_version(mv)?, created: *created, artifacts: out })
}
