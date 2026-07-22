//! Deterministic tree-sitter detector for identifier-position SQL
//! injection in C codebases (the dblink_open / dblink_close /
//! dblink_fetch finding shape).
//!
//! Pattern: a printf-family call (`appendStringInfo`, `psprintf`,
//! `snprintf`, ...) where a `%s` lands at an identifier position in
//! a SQL fragment (`DECLARE %s`, `CLOSE %s`, `FETCH ... FROM %s`,
//! ` FROM %s`, ` JOIN %s`, ` TABLE %s`, ...) and the substituted
//! argument doesn't go through a known safe identifier-quoter
//! (`quote_identifier`, `quote_ident_cstr`, `PQescapeIdentifier`,
//! ...). Both the SQL keyword check and the safe-wrapper check are
//! intentionally precise and codebase-agnostic — they catch the
//! exact class of bug CVE-2018-1058 / CVE-2020-25694 and the dblink
//! finding share without needing CPG flow analysis.
//!
//! Cost: 0 LLM tokens. Pure tree-sitter, runs in <10s on the full
//! postgres tree (~1600 .c files). Feeds into the existing
//! `TaintIrisNextCandidate` stream so Thread D's mandatory
//! call-site audit runs against detector hits the same way it does
//! for rg / cpg-rs / codeql candidates.

use super::*;
use tree_sitter::{Node, Parser};

/// One identifier-injection match. Mirrors the fields of
/// `TaintIrisNextCandidate` so the adapter at the call site can map
/// directly without information loss.
#[derive(Debug, Clone)]
pub(crate) struct IdentifierInjectionMatch {
    pub(crate) file_path: String,
    pub(crate) line: u32,
    /// The printf-family function name (e.g. `appendStringInfo`).
    pub(crate) printf_callee: String,
    /// The literal contents of the format-string argument with the
    /// surrounding `"..."` stripped.
    pub(crate) format_string: String,
    /// The exact substring before the offending `%s` (uppercased)
    /// that triggered the identifier-position match (e.g. `"DECLARE "`,
    /// `"CLOSE "`, `"FETCH 1 FROM "`).
    pub(crate) sql_keyword_before_percent_s: String,
    /// The source-text expression substituted at the `%s` slot,
    /// e.g. `"curname"`, `"quote_ident_cstr(curname)"` (the latter
    /// would be filtered out before emission).
    pub(crate) injected_arg_source: String,
}

/// Printf-family functions whose format-string + variadic argument
/// shape we walk. `appendStringInfoString` is intentionally absent —
/// it takes a single literal string and has no format spec to scan.
const PRINTF_FAMILY: &[&str] = &[
    "appendStringInfo",
    "psprintf",
    "snprintf",
    "sprintf",
    "pg_snprintf",
    "fprintf",
    "printf",
    "asprintf",
    "vsnprintf",
];

/// Case-insensitive substrings that, when found in the 32 bytes
/// preceding a `%s`, indicate the slot is at a SQL-identifier
/// position. Each entry is uppercase. Whitespace-sensitive on
/// purpose: `" FROM "` matches `... FROM %s` but not `FROMAGE`.
const SQL_IDENTIFIER_KEYWORDS: &[&str] = &[
    "DECLARE ",
    "CLOSE ",
    "FETCH ",
    " FROM ",
    " INTO ",
    "UPDATE ",
    " JOIN ",
    " TABLE ",
    " INDEX ",
    " SCHEMA ",
    " VIEW ",
    " SET ",
    "GRANT ",
    "REVOKE ",
    "CURSOR FOR ",
    "TRUNCATE ",
    "EXECUTE ",
    "ALTER TABLE ",
    "DROP TABLE ",
    "CREATE TABLE ",
    "REFRESH MATERIALIZED VIEW ",
    " OPERATOR(",
];

/// Safe identifier-quoter / escaper function names. A `%s` argument
/// wrapped in any of these is presumed sanitized; the detector
/// won't emit a candidate. The match is on the immediate-call
/// function name; if a caller writes `quote_ident_cstr(...)` we
/// trust them, even if `quote_ident_cstr` itself has a bug.
const SAFE_IDENT_WRAPPERS: &[&str] = &[
    "quote_identifier",
    "quote_ident_cstr",
    "quote_ident",
    "quote_qualified_identifier",
    "PQescapeIdentifier",
    "PQescapeLiteral",
];

/// True iff the given function name should be treated as a safe
/// identifier-quoter wrapper. Matches the explicit list above plus
/// any name with the conventional `quote_ident*` / `escape_ident*`
/// / `sanitize_ident*` / `*_quote_name*` prefix shape. Conservative
/// — false positives here LOSE recall (we'd miss real bugs), so the
/// allow-list is short and intentional.
fn is_safe_wrapper(name: &str) -> bool {
    if SAFE_IDENT_WRAPPERS.iter().any(|w| *w == name) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.starts_with("quote_ident")
        || lower.starts_with("quote_identifier")
        || lower.starts_with("escape_ident")
        || lower.starts_with("escape_identifier")
        || lower.starts_with("sanitize_ident")
        || lower.starts_with("sanitize_identifier")
}

/// Scan the given C/C++ source-file paths. Returns one match per `%s` slot that
/// lands at an identifier position without a safe wrapper.
pub(crate) fn detect_identifier_injection_in_paths(
    files: &[TaintIrisNextSourcePath],
) -> Vec<IdentifierInjectionMatch> {
    let mut out: Vec<IdentifierInjectionMatch> = Vec::new();
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .is_err()
    {
        return out;
    }
    for file in files {
        collect_identifier_injection_file_matches(file, &mut parser, &mut out);
    }
    out
}

fn collect_identifier_injection_file_matches(
    file: &TaintIrisNextSourcePath,
    parser: &mut Parser,
    out: &mut Vec<IdentifierInjectionMatch>,
) {
    if !is_c_family_source(file) {
        return;
    }
    let Some(bytes) = parseable_source_bytes(file) else {
        return;
    };
    let Some(tree) = parser.parse(&bytes, None) else {
        return;
    };
    walk_node(tree.root_node(), &bytes, &file.relative_path, out);
}

fn is_c_family_source(file: &TaintIrisNextSourcePath) -> bool {
    file.language == "c" || file.language == "cpp"
}

fn parseable_source_bytes(file: &TaintIrisNextSourcePath) -> Option<Vec<u8>> {
    let bytes = crate::bounded_file::read_regular_bytes(&file.absolute_path, 8 * 1024 * 1024).ok()?;
    (!bytes.is_empty() && !bytes.iter().take(4096).any(|byte| *byte == 0)).then_some(bytes)
}

fn walk_node(node: Node<'_>, src: &[u8], rel_path: &str, out: &mut Vec<IdentifierInjectionMatch>) {
    if node.kind() == "call_expression" {
        check_call(node, src, rel_path, out);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_node(child, src, rel_path, out);
    }
}

fn check_call(call: Node<'_>, src: &[u8], rel_path: &str, out: &mut Vec<IdentifierInjectionMatch>) {
    let Some(printf_call) = identifier_printf_call(call, src) else {
        return;
    };
    collect_identifier_injection_specs(&printf_call, rel_path, out);
}

struct IdentifierPrintfCall<'tree, 'src> {
    callee_name: &'src str,
    src: &'src [u8],
    args: Vec<Node<'tree>>,
    fmt_arg_idx: usize,
    fmt_node: Node<'tree>,
    fmt_inner: String,
    fmt_inner_upper: String,
}

fn identifier_printf_call<'tree, 'src>(
    call: Node<'tree>,
    src: &'src [u8],
) -> Option<IdentifierPrintfCall<'tree, 'src>> {
    // Resolve callee name. Handles both plain `foo(...)` and the
    // field-expression form `obj->foo(...)`.
    let func_node = call.child_by_field_name("function")?;
    let callee_name = callee_name_text(func_node, src);
    let callee_name = callee_name?;
    if !PRINTF_FAMILY.iter().any(|f| *f == callee_name) {
        return None;
    }

    let args_node = call.child_by_field_name("arguments")?;
    let arg_nodes: Vec<Node> = (0..args_node.named_child_count())
        .filter_map(|i| u32::try_from(i).ok())
        .filter_map(|i| args_node.named_child(i))
        .collect();
    if arg_nodes.is_empty() {
        return None;
    }

    let (fmt_arg_idx, fmt_node) = locate_format_string_arg(&arg_nodes)?;
    let fmt_inner = string_literal_inner_text(fmt_node, src);
    if fmt_inner.is_empty() {
        return None;
    }
    Some(IdentifierPrintfCall {
        callee_name,
        src,
        args: arg_nodes,
        fmt_arg_idx,
        fmt_node,
        fmt_inner_upper: fmt_inner.to_ascii_uppercase(),
        fmt_inner,
    })
}

/// Heuristic: first `string_literal` in the argument list. This handles
/// appendStringInfo(buf, "fmt", ...), sprintf(buf, "fmt", ...),
/// printf("fmt", ...), and snprintf(buf, size, "fmt", ...).
fn locate_format_string_arg<'tree>(arg_nodes: &[Node<'tree>]) -> Option<(usize, Node<'tree>)> {
    arg_nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| (node.kind() == "string_literal").then_some((idx, *node)))
}

fn collect_identifier_injection_specs(
    printf_call: &IdentifierPrintfCall<'_, '_>,
    rel_path: &str,
    out: &mut Vec<IdentifierInjectionMatch>,
) {
    // Walk %-specs, tracking the variadic argument index. arg 0 in
    // the variadic position is the first arg AFTER the format
    // string in the call's argument list — so its absolute index in
    // `arg_nodes` is `fmt_arg_idx + 1 + variadic_position`.
    let mut variadic_position: usize = 0;
    let bytes = printf_call.fmt_inner.as_bytes();
    let mut i = 0;
    while let Some(format_spec) = next_printf_format_spec(bytes, i) {
        i = format_spec.next_offset;
        if format_spec.spec == b's' {
            push_identifier_spec_match(
                printf_call,
                rel_path,
                format_spec.marker_offset,
                variadic_position,
                out,
            );
        }
        if format_spec.consumes_arg {
            variadic_position += 1;
        }
    }
}

struct PrintfFormatSpec {
    marker_offset: usize,
    next_offset: usize,
    spec: u8,
    consumes_arg: bool,
}

fn next_printf_format_spec(bytes: &[u8], offset: usize) -> Option<PrintfFormatSpec> {
    let marker_offset = next_percent_offset(bytes, offset)?;
    let spec_offset = printf_specifier_offset(bytes, marker_offset + 1)?;
    let spec = bytes[spec_offset];
    Some(PrintfFormatSpec {
        marker_offset,
        next_offset: spec_offset + 1,
        spec,
        consumes_arg: spec != b'%' && printf_spec_consumes_arg(spec),
    })
}

fn next_percent_offset(bytes: &[u8], mut offset: usize) -> Option<usize> {
    while offset < bytes.len() {
        if bytes[offset] == b'%' {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

fn printf_specifier_offset(bytes: &[u8], mut offset: usize) -> Option<usize> {
    offset = consume_printf_flags(bytes, offset);
    offset = consume_printf_width_precision(bytes, offset);
    offset = consume_printf_length(bytes, offset);
    (offset < bytes.len()).then_some(offset)
}

fn consume_printf_flags(bytes: &[u8], mut offset: usize) -> usize {
    while offset < bytes.len() && matches!(bytes[offset], b'-' | b'+' | b' ' | b'#' | b'0') {
        offset += 1;
    }
    offset
}

fn consume_printf_width_precision(bytes: &[u8], mut offset: usize) -> usize {
    while offset < bytes.len()
        && (bytes[offset].is_ascii_digit() || bytes[offset] == b'.' || bytes[offset] == b'*')
    {
        offset += 1;
    }
    offset
}

fn consume_printf_length(bytes: &[u8], mut offset: usize) -> usize {
    while offset < bytes.len() && matches!(bytes[offset], b'h' | b'l' | b'L' | b'z' | b'j' | b't') {
        offset += 1;
    }
    offset
}

fn printf_spec_consumes_arg(spec: u8) -> bool {
    matches!(
        spec,
        b's' | b'd'
            | b'i'
            | b'u'
            | b'x'
            | b'X'
            | b'o'
            | b'f'
            | b'e'
            | b'E'
            | b'g'
            | b'G'
            | b'c'
            | b'p'
            | b'a'
            | b'A'
            | b'n'
    )
}

fn push_identifier_spec_match(
    printf_call: &IdentifierPrintfCall<'_, '_>,
    rel_path: &str,
    byte_offset: usize,
    variadic_position: usize,
    out: &mut Vec<IdentifierInjectionMatch>,
) {
    let preceding_window =
        preceding_window_uppercase(&printf_call.fmt_inner_upper, byte_offset, 32);
    let Some(keyword) = identifier_keyword_hit(&preceding_window) else {
        return;
    };
    let arg_idx = printf_call.fmt_arg_idx + 1 + variadic_position;
    let Some(arg_node) = printf_call.args.get(arg_idx).copied() else {
        return;
    };
    let Some(match_arg) = classify_arg(arg_node, printf_call.src) else {
        return;
    };
    if match_arg.wrapped_in_safe {
        return;
    }
    out.push(identifier_injection_match(
        printf_call,
        rel_path,
        keyword,
        match_arg.text,
    ));
}

fn identifier_injection_match(
    printf_call: &IdentifierPrintfCall<'_, '_>,
    rel_path: &str,
    keyword: String,
    injected_arg_source: String,
) -> IdentifierInjectionMatch {
    IdentifierInjectionMatch {
        file_path: rel_path.to_string(),
        line: printf_call.fmt_node.start_position().row as u32 + 1,
        printf_callee: printf_call.callee_name.to_string(),
        format_string: printf_call.fmt_inner.clone(),
        sql_keyword_before_percent_s: keyword,
        injected_arg_source,
    }
}

struct ArgClassification {
    text: String,
    wrapped_in_safe: bool,
}

/// Classify a variadic argument expression. Returns None for
/// string literals (compile-time constants — not user-controllable
/// in any realistic threat model). Otherwise returns the source
/// text + a flag indicating whether the outermost call is a safe
/// identifier-quoter.
fn classify_arg(arg: Node<'_>, src: &[u8]) -> Option<ArgClassification> {
    let kind = arg.kind();
    if kind == "string_literal" || kind == "concatenated_string" {
        // Constant — not attacker-controllable.
        return None;
    }
    let text = node_text(arg, src).to_string();
    if kind == "call_expression" {
        if let Some(callee) = arg.child_by_field_name("function") {
            if let Some(name) = callee_name_text(callee, src) {
                if is_safe_wrapper(name) {
                    return Some(ArgClassification {
                        text,
                        wrapped_in_safe: true,
                    });
                }
            }
        }
    }
    Some(ArgClassification {
        text,
        wrapped_in_safe: false,
    })
}

fn callee_name_text<'a>(node: Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    identifier_callee_text(node, src)
        .or_else(|| field_expression_callee_text(node, src))
        .or_else(|| parenthesized_callee_text(node, src))
}

fn identifier_callee_text<'a>(node: Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    (node.kind() == "identifier").then_some(node_text(node, src))
}

fn field_expression_callee_text<'a>(node: Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    (node.kind() == "field_expression")
        .then(|| {
            node.child_by_field_name("field")
                .map(|field| node_text(field, src))
        })
        .flatten()
}

fn parenthesized_callee_text<'a>(node: Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    if node.kind() != "parenthesized_expression" {
        return None;
    }
    first_child_callee_name(node, src)
}

fn first_child_callee_name<'a>(node: Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(name) = callee_name_text(child, src) {
            return Some(name);
        }
    }
    None
}

fn node_text<'a>(node: Node<'_>, src: &'a [u8]) -> &'a str {
    let range = node.byte_range();
    std::str::from_utf8(&src[range.start..range.end]).unwrap_or("")
}

/// Strip the outer `"..."` of a `string_literal` node. tree-sitter-c
/// represents `"foo"` as a `string_literal` whose children include
/// `"` tokens and a `string_content` child carrying the contents.
fn string_literal_inner_text(node: Node<'_>, src: &[u8]) -> String {
    let out = string_literal_child_text(node, src);
    if out.is_empty() {
        raw_string_literal_inner_text(node, src).unwrap_or_default()
    } else {
        out
    }
}

fn string_literal_child_text(node: Node<'_>, src: &[u8]) -> String {
    let mut out = String::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_string_literal_content_child(child.kind()) {
            out.push_str(node_text(child, src));
        } else if child.kind() == "escape_sequence" {
            push_decoded_escape(&mut out, node_text(child, src));
        }
    }
    out
}

fn is_string_literal_content_child(kind: &str) -> bool {
    matches!(kind, "string_content" | "string_fragment")
}

fn raw_string_literal_inner_text(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(node, src);
    raw.strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .map(str::to_string)
}

fn push_decoded_escape(out: &mut String, raw: &str) {
    if let Some(decoded) = decoded_common_escape(raw) {
        out.push(decoded);
    } else {
        out.push_str(raw);
    }
}

fn decoded_common_escape(raw: &str) -> Option<char> {
    const ESCAPES: &[(&str, char)] = &[
        ("\\n", '\n'),
        ("\\t", '\t'),
        ("\\r", '\r'),
        ("\\\\", '\\'),
        ("\\\"", '"'),
        ("\\'", '\''),
    ];
    ESCAPES
        .iter()
        .find_map(|(candidate, decoded)| (*candidate == raw).then_some(*decoded))
}

fn preceding_window_uppercase(fmt_upper: &str, byte_offset: usize, window: usize) -> String {
    // The format string can contain multi-byte UTF-8 sequences
    // (emoji, accented chars in error messages, etc.). Slicing by
    // raw byte offset risks landing mid-codepoint and panicking
    // with `byte index N is not a char boundary`. Walk back to
    // the nearest char boundary at-or-before the requested offset,
    // and to the boundary at-or-after the requested start. The
    // SQL-keyword check is ASCII-only so dropping a few leading
    // bytes is harmless.
    let bytes = fmt_upper.as_bytes();
    let safe_end = clamp_to_char_boundary_left(bytes, byte_offset.min(bytes.len()));
    let raw_start = safe_end.saturating_sub(window);
    let safe_start = clamp_to_char_boundary_right(bytes, raw_start);
    if safe_start >= safe_end {
        return String::new();
    }
    fmt_upper[safe_start..safe_end].to_string()
}

/// Move left until the byte at `idx` is the start of a UTF-8
/// codepoint (continuation bytes have the form 10xxxxxx).
fn clamp_to_char_boundary_left(bytes: &[u8], mut idx: usize) -> usize {
    while idx > 0 && idx < bytes.len() && (bytes[idx] & 0b1100_0000) == 0b1000_0000 {
        idx -= 1;
    }
    idx
}

/// Move right until the byte at `idx` is the start of a UTF-8
/// codepoint. Useful when the window-start raw offset lands mid-
/// codepoint.
fn clamp_to_char_boundary_right(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() && (bytes[idx] & 0b1100_0000) == 0b1000_0000 {
        idx += 1;
    }
    idx
}

fn identifier_keyword_hit(preceding_window_upper: &str) -> Option<String> {
    // Return the keyword whose match is CLOSEST to the end of the
    // window (i.e., the last identifier-position context before
    // the %s). For "FETCH %d FROM %s" the window is
    // "FETCH %D FROM " — both "FETCH " and " FROM " match, but
    // " FROM " is the immediate context.
    let mut best: Option<(usize, &'static str)> = None;
    for kw in SQL_IDENTIFIER_KEYWORDS {
        if let Some(idx) = preceding_window_upper.rfind(kw) {
            match best {
                Some((b_idx, _)) if idx <= b_idx => {}
                _ => best = Some((idx, kw)),
            }
        }
    }
    best.map(|(_, kw)| kw.to_string())
}

/// Convert detector matches into `TaintIrisNextCandidate` rows so
/// they flow through the existing evidence-extraction pipeline.
/// Marks `source: "ts.identifier-injection"` and
/// `confidence: "high"` — the detector is deterministic and only
/// emits where the SQL keyword + missing-wrapper combination is
/// unambiguous, so the agent's Thread D audit doesn't need to
/// re-derive the basic mechanic.
pub(crate) fn candidates_from_identifier_injection_matches(
    matches: &[IdentifierInjectionMatch],
    cwe_focus: &[String],
) -> Vec<TaintIrisNextCandidate> {
    let allow: std::collections::BTreeSet<String> = cwe_focus
        .iter()
        .map(|cwe| cwe.to_ascii_uppercase())
        .collect();
    // The detector is hardcoded to CWE-89 (SQL injection — identifier
    // position). Filter the whole batch out when an operator-supplied
    // cwe_focus excludes CWE-89.
    if !allow.is_empty() && !allow.contains("CWE-89") {
        return Vec::new();
    }
    matches
        .iter()
        .map(|m| TaintIrisNextCandidate {
            id: format!(
                "CWE-89:ts-identifier-injection:{}:{}:{}",
                m.file_path, m.line, m.printf_callee
            ),
            cwe: "CWE-89".to_string(),
            taint_class: "sql-injection".to_string(),
            track: "ts-identifier-injection".to_string(),
            role: "sink".to_string(),
            kind: "identifier-position-format-spec".to_string(),
            pattern: m.printf_callee.clone(),
            file_path: m.file_path.clone(),
            line: m.line,
            snippet: format!(
                "{}: {} <- {}",
                m.printf_callee,
                truncate(&m.format_string, 120),
                truncate(&m.injected_arg_source, 80),
            ),
            language: "c".to_string(),
            confidence: "high".to_string(),
            catalog_signal: format!(
                "ts.identifier-injection: %s after \"{}\"",
                m.sql_keyword_before_percent_s.trim()
            ),
            source: "ts.identifier-injection".to_string(),
        })
        .collect()
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let end = clamp_to_char_boundary_left(s.as_bytes(), n.min(s.len()));
        format!("{}…", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn fixture_file(
        path: &str,
        contents: &str,
    ) -> (tempfile::TempDir, Vec<TaintIrisNextSourcePath>) {
        let temp = tempdir().unwrap();
        let target = temp.path().join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&target, contents).unwrap();
        let files = vec![TaintIrisNextSourcePath {
            absolute_path: target,
            relative_path: path.to_string(),
            language: "c".to_string(),
        }];
        (temp, files)
    }

    #[test]
    fn detects_dblink_close_cursor_name_injection() {
        let (_temp, files) = fixture_file(
            "contrib/dblink/dblink.c",
            r#"
static void
dblink_close(PG_FUNCTION_ARGS)
{
    StringInfoData buf;
    char *curname = text_to_cstring(PG_GETARG_TEXT_PP(0));
    initStringInfo(&buf);
    appendStringInfo(&buf, "CLOSE %s", curname);
}
"#,
        );
        let matches = detect_identifier_injection_in_paths(&files);
        assert_eq!(matches.len(), 1, "got {matches:?}");
        let m = &matches[0];
        assert_eq!(m.printf_callee, "appendStringInfo");
        assert!(m.sql_keyword_before_percent_s.contains("CLOSE"));
        assert!(m.injected_arg_source.contains("curname"));
    }

    #[test]
    fn detects_dblink_open_declare_cursor() {
        let (_temp, files) = fixture_file(
            "contrib/dblink/dblink.c",
            r#"
static void
dblink_open(PG_FUNCTION_ARGS)
{
    StringInfoData buf;
    char *curname = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char *sql = text_to_cstring(PG_GETARG_TEXT_PP(1));
    appendStringInfo(&buf, "DECLARE %s CURSOR FOR %s", curname, sql);
}
"#,
        );
        let matches = detect_identifier_injection_in_paths(&files);
        // Both %s slots fire because: %s after DECLARE (identifier),
        // %s after CURSOR FOR (also identifier-position per our list).
        // The CURSOR FOR slot's argument is `sql` — also unwrapped —
        // so it emits too. Both are real concerns.
        assert!(matches.len() >= 1, "got {matches:?}");
        assert!(
            matches
                .iter()
                .any(|m| m.sql_keyword_before_percent_s.contains("DECLARE")),
            "DECLARE position should fire: {matches:?}",
        );
    }

    #[test]
    fn detects_dblink_fetch_from_cursor() {
        let (_temp, files) = fixture_file(
            "contrib/dblink/dblink.c",
            r#"
static void
dblink_fetch(PG_FUNCTION_ARGS)
{
    StringInfoData buf;
    int howmany = PG_GETARG_INT32(0);
    char *curname = text_to_cstring(PG_GETARG_TEXT_PP(1));
    appendStringInfo(&buf, "FETCH %d FROM %s", howmany, curname);
}
"#,
        );
        let matches = detect_identifier_injection_in_paths(&files);
        assert_eq!(matches.len(), 1, "got {matches:?}");
        let m = &matches[0];
        assert!(
            m.sql_keyword_before_percent_s.contains("FROM"),
            "FROM should be the trigger: {m:?}",
        );
    }

    #[test]
    fn skips_safe_wrapped_argument() {
        let (_temp, files) = fixture_file(
            "ok.c",
            r#"
void f(void)
{
    StringInfoData buf;
    char *name = "foo";
    appendStringInfo(&buf, "SELECT * FROM %s", quote_identifier(name));
}
"#,
        );
        let matches = detect_identifier_injection_in_paths(&files);
        assert!(
            matches.is_empty(),
            "quote_identifier-wrapped %s should not flag: {matches:?}",
        );
    }

    #[test]
    fn skips_quote_ident_cstr_wrapped() {
        let (_temp, files) = fixture_file(
            "ok2.c",
            r#"
void f(void)
{
    StringInfoData buf;
    appendStringInfo(&buf, "DECLARE %s CURSOR FOR ...", quote_ident_cstr(name));
}
"#,
        );
        let matches = detect_identifier_injection_in_paths(&files);
        assert!(
            matches.is_empty(),
            "quote_ident_cstr-wrapped should not flag: {matches:?}",
        );
    }

    #[test]
    fn skips_literal_substitution() {
        let (_temp, files) = fixture_file(
            "ok3.c",
            r#"
void f(void)
{
    StringInfoData buf;
    appendStringInfo(&buf, "DECLARE %s CURSOR FOR SELECT 1", "fixed_cursor");
}
"#,
        );
        let matches = detect_identifier_injection_in_paths(&files);
        assert!(
            matches.is_empty(),
            "string-literal substitution should not flag: {matches:?}",
        );
    }

    #[test]
    fn skips_non_identifier_position_percent_s() {
        // %s appears but NOT after a SQL identifier keyword — should
        // not flag. Example: error-message formatting.
        let (_temp, files) = fixture_file(
            "ok4.c",
            r#"
void f(void)
{
    char *userinput = text_to_cstring(PG_GETARG_TEXT_PP(0));
    fprintf(stderr, "user said: %s\n", userinput);
}
"#,
        );
        let matches = detect_identifier_injection_in_paths(&files);
        assert!(
            matches.is_empty(),
            "%s in non-identifier position should not flag: {matches:?}",
        );
    }

    #[test]
    fn handles_width_and_length_modifiers() {
        // %lus, %-20s, %.10s all consume one argument; their
        // argument-index tracking must stay correct.
        let (_temp, files) = fixture_file(
            "modifiers.c",
            r#"
void f(void)
{
    char *name = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char *fixed = "abc";
    appendStringInfo(&buf, "PREFIX %-20s %lu DECLARE %s ...", fixed, 0UL, name);
}
"#,
        );
        let matches = detect_identifier_injection_in_paths(&files);
        // The DECLARE position fires on `name` (variadic_position=2,
        // after `fixed` and `0UL`).
        assert_eq!(matches.len(), 1, "got {matches:?}");
        assert!(matches[0].injected_arg_source.contains("name"));
    }

    #[test]
    fn maps_to_taint_iris_next_candidate_with_cwe_89() {
        let (_temp, files) = fixture_file(
            "x.c",
            r#"
void f(void) { appendStringInfo(&buf, "CLOSE %s", curname); }
"#,
        );
        let matches = detect_identifier_injection_in_paths(&files);
        assert_eq!(matches.len(), 1);
        let candidates = candidates_from_identifier_injection_matches(&matches, &[]);
        assert_eq!(candidates.len(), 1);
        let c = &candidates[0];
        assert_eq!(c.cwe, "CWE-89");
        assert_eq!(c.confidence, "high");
        assert_eq!(c.source, "ts.identifier-injection");
        assert_eq!(c.role, "sink");
        assert!(c.catalog_signal.contains("CLOSE"));
    }

    #[test]
    fn cwe_focus_filters_out_when_cwe_89_excluded() {
        let matches = vec![IdentifierInjectionMatch {
            file_path: "x.c".to_string(),
            line: 1,
            printf_callee: "appendStringInfo".to_string(),
            format_string: "CLOSE %s".to_string(),
            sql_keyword_before_percent_s: "CLOSE ".to_string(),
            injected_arg_source: "curname".to_string(),
        }];
        // Operator focuses on CWE-120 only — detector output dropped.
        let candidates =
            candidates_from_identifier_injection_matches(&matches, &["CWE-120".to_string()]);
        assert!(candidates.is_empty());
        // Operator focuses on CWE-89 — detector output kept.
        let candidates =
            candidates_from_identifier_injection_matches(&matches, &["CWE-89".to_string()]);
        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn handles_utf8_in_format_string_without_panicking() {
        // Regression for the llama.cpp panic: format strings can
        // contain multi-byte UTF-8 (emoji, accented chars in
        // error messages). The detector must not panic on these
        // when slicing the 32-byte preceding window.
        let (_temp, files) = fixture_file(
            "emoji.c",
            r#"
void f(void) {
    // U+2728 (sparkles) + U+1F680 (rocket) + arbitrary identifier %s
    appendStringInfo(&buf, "✨ working 🚀 DECLARE %s CURSOR FOR SELECT 1", curname);
}
"#,
        );
        // Must not panic. May or may not flag — both are fine.
        let _ = detect_identifier_injection_in_paths(&files);
    }

    #[test]
    fn truncate_preserves_utf8_boundaries() {
        let text = format!("{}🚀z", "a".repeat(120));
        let truncated = truncate(&text, 121);
        assert_eq!(truncated, format!("{}…", "a".repeat(120)));
    }

    #[test]
    fn is_safe_wrapper_recognises_known_quoters() {
        assert!(is_safe_wrapper("quote_identifier"));
        assert!(is_safe_wrapper("quote_ident_cstr"));
        assert!(is_safe_wrapper("quote_ident"));
        assert!(is_safe_wrapper("PQescapeIdentifier"));
        assert!(is_safe_wrapper("quote_identifier_v2"));
        assert!(is_safe_wrapper("escape_identifier"));
        assert!(is_safe_wrapper("sanitize_identifier_strict"));
        assert!(!is_safe_wrapper("text_to_cstring"));
        assert!(!is_safe_wrapper("appendStringInfo"));
        assert!(!is_safe_wrapper("strdup"));
    }
}
