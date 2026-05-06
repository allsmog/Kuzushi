//! Parser for `global -x` output.
//!
//! `global -x <symbol>` formats each match as a fixed-column line:
//! ```text
//! <symbol>             <line>  <file>                          <snippet>
//! ```
//! Columns are space-separated with the symbol left-justified in a 16-char
//! field, the line number right-justified in a 4-char field, and the file
//! path in a 16-char field. Past those fixed widths the snippet is the
//! literal source line. We don't rely on the exact widths — we tolerate any
//! amount of whitespace.

use std::path::PathBuf;

use kuzushi_mcp_common::schema::{Position, Range, Symbol, SymbolKind};

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

/// Parse a single line of `global -x` output. Returns `None` for empty or
/// malformed lines (gtags occasionally emits warnings on stdout that we
/// must skip).
///
/// Layout: `symbol  line  file  snippet` separated by runs of whitespace.
/// The snippet may contain embedded whitespace (and tabs), so we identify
/// the first three fields with `split_whitespace` and slice the original
/// line for the rest.
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

/// Walk `line` matching each `field` in order, returning the byte offset
/// just past the last match. `None` if any field can't be located in
/// sequence — that means `line` doesn't actually contain those tokens
/// where they were expected.
fn byte_position_of_field_end(line: &str, fields: &[&str]) -> Option<usize> {
    let mut cursor = 0;
    for field in fields {
        let rest = &line[cursor..];
        let pos = rest.find(field)?;
        cursor += pos + field.len();
    }
    Some(cursor)
}

/// Parse the entirety of a `global -x` document.
pub fn parse_global_x(output: &str) -> Vec<GtagsRecord> {
    output
        .lines()
        .filter_map(|line| parse_global_x_line(line.trim_end()))
        .collect()
}

/// Convert a parsed record list to fully-resolved [`Symbol`]s, prefixing
/// each file path with `repo_root` when the path is relative (gtags
/// emits relative paths by default).
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured `global -x` output for a hypothetical lookup of
    /// `recv_msg`. Three records, the third with a snippet containing
    /// embedded whitespace and tabs.
    const FIXTURE: &str = "\
recv_msg            42 src/net.c                int recv_msg(int fd, struct msg *m) {
recv_msg           107 src/proto.c              extern int recv_msg(int, struct msg *);
__recv_msg_hook      3 vendor/inst.h            #define __recv_msg_hook(...) /* ... */\t/* annotated */
";

    #[test]
    fn parses_three_records_from_fixture() {
        let records = parse_global_x(FIXTURE);
        assert_eq!(records.len(), 3);

        assert_eq!(records[0].symbol, "recv_msg");
        assert_eq!(records[0].line, 42);
        assert_eq!(records[0].file, PathBuf::from("src/net.c"));
        assert!(records[0].snippet.starts_with("int recv_msg"));

        assert_eq!(records[2].symbol, "__recv_msg_hook");
        assert_eq!(records[2].line, 3);
        assert!(records[2].snippet.contains("#define __recv_msg_hook"));
        assert!(records[2].snippet.contains("/* annotated */"));
    }

    #[test]
    fn ignores_blank_and_garbled_lines() {
        let records = parse_global_x("\n\n\nfoo\n");
        assert!(
            records.is_empty(),
            "lines without line+file fields are skipped"
        );
    }

    #[test]
    fn line_with_no_snippet_still_parses() {
        let line = "main 1 src/main.c";
        let r = parse_global_x_line(line).unwrap();
        assert_eq!(r.symbol, "main");
        assert_eq!(r.line, 1);
        assert_eq!(r.file, PathBuf::from("src/main.c"));
        assert_eq!(r.snippet, "");
    }

    #[test]
    fn records_to_symbols_resolves_relative_paths() {
        let records = parse_global_x(FIXTURE);
        let syms = records_to_symbols(records, std::path::Path::new("/repo"));
        assert_eq!(
            syms[0].location.start.file,
            PathBuf::from("/repo/src/net.c")
        );
        assert_eq!(syms[0].location.start.line, 42);
    }
}
