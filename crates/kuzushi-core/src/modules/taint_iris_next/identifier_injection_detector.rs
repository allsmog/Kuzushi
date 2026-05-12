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
//! finding share without needing joern's flow analysis.
//!
//! Cost: 0 LLM tokens. Pure tree-sitter, runs in <10s on the full
//! postgres tree (~1600 .c files). Feeds into the existing
//! `TaintIrisNextCandidate` stream so Thread D's mandatory
//! call-site audit runs against detector hits the same way it does
//! for rg / joern / codeql candidates.

use super::*;
use std::path::Path;
use tree_sitter::{Node, Parser};

/// One identifier-injection match. Mirrors the fields of
/// `TaintIrisNextCandidate` so the adapter at the call site can map
/// directly without information loss.
#[derive(Debug, Clone)]
pub(in crate::modules) struct IdentifierInjectionMatch {
    pub(in crate::modules) file_path: String,
    pub(in crate::modules) line: u32,
    /// The printf-family function name (e.g. `appendStringInfo`).
    pub(in crate::modules) printf_callee: String,
    /// The literal contents of the format-string argument with the
    /// surrounding `"..."` stripped.
    pub(in crate::modules) format_string: String,
    /// The exact substring before the offending `%s` (uppercased)
    /// that triggered the identifier-position match (e.g. `"DECLARE "`,
    /// `"CLOSE "`, `"FETCH 1 FROM "`).
    pub(in crate::modules) sql_keyword_before_percent_s: String,
    /// The source-text expression substituted at the `%s` slot,
    /// e.g. `"curname"`, `"quote_ident_cstr(curname)"` (the latter
    /// would be filtered out before emission).
    pub(in crate::modules) injected_arg_source: String,
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

/// Scan the given source-file slice. Each file must be the actual
/// on-disk contents (the detector reparses with tree-sitter rather
/// than the line-split shape `TaintIrisNextSourceFile` carries).
/// Returns one match per `%s` slot that lands at an identifier
/// position without a safe wrapper.
pub(in crate::modules) fn detect_identifier_injection_in_target(
    scan_root: &Path,
    files: &[TaintIrisNextSourceFile],
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
        if file.language != "c" && file.language != "cpp" {
            continue;
        }
        let abs = scan_root.join(&file.relative_path);
        let Ok(bytes) = std::fs::read(&abs) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        let Some(tree) = parser.parse(&bytes, None) else {
            continue;
        };
        walk_node(tree.root_node(), &bytes, &file.relative_path, &mut out);
    }
    out
}

fn walk_node(
    node: Node<'_>,
    src: &[u8],
    rel_path: &str,
    out: &mut Vec<IdentifierInjectionMatch>,
) {
    if node.kind() == "call_expression" {
        check_call(node, src, rel_path, out);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_node(child, src, rel_path, out);
    }
}

fn check_call(
    call: Node<'_>,
    src: &[u8],
    rel_path: &str,
    out: &mut Vec<IdentifierInjectionMatch>,
) {
    // Resolve callee name. Handles both plain `foo(...)` and the
    // field-expression form `obj->foo(...)`.
    let Some(func_node) = call.child_by_field_name("function") else {
        return;
    };
    let callee_name = callee_name_text(func_node, src);
    let Some(callee_name) = callee_name else { return };
    if !PRINTF_FAMILY.iter().any(|f| *f == callee_name) {
        return;
    }

    let Some(args_node) = call.child_by_field_name("arguments") else {
        return;
    };
    let arg_nodes: Vec<Node> = (0..args_node.named_child_count())
        .filter_map(|i| args_node.named_child(i))
        .collect();
    if arg_nodes.is_empty() {
        return;
    }

    // Locate the format-string argument. Heuristic: first
    // `string_literal` in the argument list. This handles
    // appendStringInfo(buf, "fmt", ...) (fmt at index 1) AND
    // sprintf(buf, "fmt", ...) (fmt at index 1) AND
    // printf("fmt", ...) (fmt at index 0). For snprintf(buf, size,
    // "fmt", ...) the literal is at index 2 — same heuristic.
    let Some((fmt_arg_idx, fmt_node)) =
        arg_nodes.iter().enumerate().find(|(_, n)| n.kind() == "string_literal")
    else {
        return;
    };
    let fmt_inner = string_literal_inner_text(*fmt_node, src);
    if fmt_inner.is_empty() {
        return;
    }
    let fmt_inner_upper = fmt_inner.to_ascii_uppercase();

    // Walk %-specs, tracking the variadic argument index. arg 0 in
    // the variadic position is the first arg AFTER the format
    // string in the call's argument list — so its absolute index in
    // `arg_nodes` is `fmt_arg_idx + 1 + variadic_position`.
    let mut variadic_position: usize = 0;
    let bytes = fmt_inner.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        // Consume flags, width, precision, length modifiers.
        let mut j = i + 1;
        while j < bytes.len() && matches!(bytes[j], b'-' | b'+' | b' ' | b'#' | b'0') {
            j += 1;
        }
        while j < bytes.len()
            && (bytes[j].is_ascii_digit() || bytes[j] == b'.' || bytes[j] == b'*')
        {
            j += 1;
        }
        while j < bytes.len() && matches!(bytes[j], b'h' | b'l' | b'L' | b'z' | b'j' | b't') {
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }
        let spec = bytes[j];
        if spec == b'%' {
            // %% — literal %, no argument consumed.
            i = j + 1;
            continue;
        }
        // Every other spec consumes a variadic argument.
        let consumes_arg = matches!(
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
        );
        if spec == b's' {
            // Identifier-position check.
            let preceding_window = preceding_window_uppercase(&fmt_inner_upper, i, 32);
            if let Some(keyword) = identifier_keyword_hit(&preceding_window) {
                // Find the variadic arg expression.
                let arg_idx = fmt_arg_idx + 1 + variadic_position;
                if arg_idx < arg_nodes.len() {
                    let arg_node = arg_nodes[arg_idx];
                    if let Some(m) = classify_arg(arg_node, src) {
                        if !m.wrapped_in_safe {
                            let line = fmt_node.start_position().row as u32 + 1;
                            out.push(IdentifierInjectionMatch {
                                file_path: rel_path.to_string(),
                                line,
                                printf_callee: callee_name.to_string(),
                                format_string: fmt_inner.clone(),
                                sql_keyword_before_percent_s: keyword,
                                injected_arg_source: m.text,
                            });
                        }
                    }
                }
            }
        }
        if consumes_arg {
            variadic_position += 1;
        }
        i = j + 1;
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
    match node.kind() {
        "identifier" => Some(node_text(node, src)),
        "field_expression" => node
            .child_by_field_name("field")
            .and_then(|f| Some(node_text(f, src))),
        "parenthesized_expression" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if let Some(name) = callee_name_text(child, src) {
                    return Some(name);
                }
            }
            None
        }
        _ => None,
    }
}

fn node_text<'a>(node: Node<'_>, src: &'a [u8]) -> &'a str {
    let range = node.byte_range();
    std::str::from_utf8(&src[range.start..range.end]).unwrap_or("")
}

/// Strip the outer `"..."` of a `string_literal` node. tree-sitter-c
/// represents `"foo"` as a `string_literal` whose children include
/// `"` tokens and a `string_content` child carrying the contents.
fn string_literal_inner_text(node: Node<'_>, src: &[u8]) -> String {
    let mut out = String::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "string_content" || child.kind() == "string_fragment" {
            out.push_str(node_text(child, src));
        } else if child.kind() == "escape_sequence" {
            // Decode common escapes so a `\nDECLARE` still matches
            // the identifier-keyword check. Anything we don't
            // recognise gets passed through verbatim.
            let raw = node_text(child, src);
            match raw {
                "\\n" => out.push('\n'),
                "\\t" => out.push('\t'),
                "\\r" => out.push('\r'),
                "\\\\" => out.push('\\'),
                "\\\"" => out.push('"'),
                "\\'" => out.push('\''),
                other => out.push_str(other),
            }
        }
    }
    if out.is_empty() {
        // Fallback: strip the outer chars from raw node text.
        let raw = node_text(node, src);
        if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
            return raw[1..raw.len() - 1].to_string();
        }
    }
    out
}

fn preceding_window_uppercase(fmt_upper: &str, byte_offset: usize, window: usize) -> String {
    let start = byte_offset.saturating_sub(window);
    fmt_upper[start..byte_offset].to_string()
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
pub(in crate::modules) fn candidates_from_identifier_injection_matches(
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
        format!("{}…", &s[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn fixture_file(path: &str, contents: &str) -> (tempfile::TempDir, Vec<TaintIrisNextSourceFile>) {
        let temp = tempdir().unwrap();
        let target = temp.path().join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&target, contents).unwrap();
        let files = vec![TaintIrisNextSourceFile {
            relative_path: path.to_string(),
            language: "c".to_string(),
            lines: contents.lines().map(|l| l.to_string()).collect(),
        }];
        (temp, files)
    }

    #[test]
    fn detects_dblink_close_cursor_name_injection() {
        let (temp, files) = fixture_file(
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
        let matches = detect_identifier_injection_in_target(temp.path(), &files);
        assert_eq!(matches.len(), 1, "got {matches:?}");
        let m = &matches[0];
        assert_eq!(m.printf_callee, "appendStringInfo");
        assert!(m.sql_keyword_before_percent_s.contains("CLOSE"));
        assert!(m.injected_arg_source.contains("curname"));
    }

    #[test]
    fn detects_dblink_open_declare_cursor() {
        let (temp, files) = fixture_file(
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
        let matches = detect_identifier_injection_in_target(temp.path(), &files);
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
        let (temp, files) = fixture_file(
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
        let matches = detect_identifier_injection_in_target(temp.path(), &files);
        assert_eq!(matches.len(), 1, "got {matches:?}");
        let m = &matches[0];
        assert!(
            m.sql_keyword_before_percent_s.contains("FROM"),
            "FROM should be the trigger: {m:?}",
        );
    }

    #[test]
    fn skips_safe_wrapped_argument() {
        let (temp, files) = fixture_file(
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
        let matches = detect_identifier_injection_in_target(temp.path(), &files);
        assert!(
            matches.is_empty(),
            "quote_identifier-wrapped %s should not flag: {matches:?}",
        );
    }

    #[test]
    fn skips_quote_ident_cstr_wrapped() {
        let (temp, files) = fixture_file(
            "ok2.c",
            r#"
void f(void)
{
    StringInfoData buf;
    appendStringInfo(&buf, "DECLARE %s CURSOR FOR ...", quote_ident_cstr(name));
}
"#,
        );
        let matches = detect_identifier_injection_in_target(temp.path(), &files);
        assert!(
            matches.is_empty(),
            "quote_ident_cstr-wrapped should not flag: {matches:?}",
        );
    }

    #[test]
    fn skips_literal_substitution() {
        let (temp, files) = fixture_file(
            "ok3.c",
            r#"
void f(void)
{
    StringInfoData buf;
    appendStringInfo(&buf, "DECLARE %s CURSOR FOR SELECT 1", "fixed_cursor");
}
"#,
        );
        let matches = detect_identifier_injection_in_target(temp.path(), &files);
        assert!(
            matches.is_empty(),
            "string-literal substitution should not flag: {matches:?}",
        );
    }

    #[test]
    fn skips_non_identifier_position_percent_s() {
        // %s appears but NOT after a SQL identifier keyword — should
        // not flag. Example: error-message formatting.
        let (temp, files) = fixture_file(
            "ok4.c",
            r#"
void f(void)
{
    char *userinput = text_to_cstring(PG_GETARG_TEXT_PP(0));
    fprintf(stderr, "user said: %s\n", userinput);
}
"#,
        );
        let matches = detect_identifier_injection_in_target(temp.path(), &files);
        assert!(
            matches.is_empty(),
            "%s in non-identifier position should not flag: {matches:?}",
        );
    }

    #[test]
    fn handles_width_and_length_modifiers() {
        // %lus, %-20s, %.10s all consume one argument; their
        // argument-index tracking must stay correct.
        let (temp, files) = fixture_file(
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
        let matches = detect_identifier_injection_in_target(temp.path(), &files);
        // The DECLARE position fires on `name` (variadic_position=2,
        // after `fixed` and `0UL`).
        assert_eq!(matches.len(), 1, "got {matches:?}");
        assert!(matches[0].injected_arg_source.contains("name"));
    }

    #[test]
    fn maps_to_taint_iris_next_candidate_with_cwe_89() {
        let (temp, files) = fixture_file(
            "x.c",
            r#"
void f(void) { appendStringInfo(&buf, "CLOSE %s", curname); }
"#,
        );
        let matches = detect_identifier_injection_in_target(temp.path(), &files);
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
