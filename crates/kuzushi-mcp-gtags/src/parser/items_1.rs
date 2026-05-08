use super::prelude::*;
use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtagsRecord {
    pub symbol: String,
    pub line: u32,
    pub file: PathBuf,
    pub snippet: String,
}

impl GtagsRecord {
    pub fn into_symbol(self) -> Symbol {
        let location = Range::single_line(self.file.clone(), self.line);
        Symbol {
            name: self.symbol,
            kind: SymbolKind::Unknown,
            location,
            qualifier: None,
            language: None,
        }
    }
}

pub fn parse_global_x_line(line: &str) -> Option<GtagsRecord> {
    let mut fields = line.split_whitespace();
    let symbol = fields.next()?;
    let line_str = fields.next()?;
    let file_str = fields.next()?;

    let line_num: u32 = line_str.parse().ok()?;

    // Find the byte offset in `line` where the file path ends so the
    // snippet captures everything after, with embedded whitespace intact.
    let file_byte_end = byte_position_of_field_end(line, &[symbol, line_str, file_str])?;
    let snippet = line[file_byte_end..].trim_start().trim_end().to_string();

    Some(GtagsRecord {
        symbol: symbol.to_string(),
        line: line_num,
        file: PathBuf::from(file_str),
        snippet,
    })
}

pub(crate) fn byte_position_of_field_end(line: &str, fields: &[&str]) -> Option<usize> {
    let mut cursor = 0;
    for field in fields {
        let rest = &line[cursor..];
        let pos = rest.find(field)?;
        cursor += pos + field.len();
    }
    Some(cursor)
}

pub fn parse_global_x(output: &str) -> Vec<GtagsRecord> {
    output
        .lines()
        .filter_map(|line| parse_global_x_line(line.trim_end()))
        .collect()
}

pub fn records_to_symbols(records: Vec<GtagsRecord>, repo_root: &std::path::Path) -> Vec<Symbol> {
    records
        .into_iter()
        .map(|mut rec| {
            if rec.file.is_relative() {
                rec.file = repo_root.join(&rec.file);
            }
            let mut sym = rec.into_symbol();
            sym.location.start = Position {
                file: sym.location.start.file.clone(),
                line: sym.location.start.line,
                column: None,
            };
            sym.location.end = sym.location.start.clone();
            sym
        })
        .collect()
}
