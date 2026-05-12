use super::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Language, Node, Parser, Tree};

/// Drop candidates whose byte range falls inside a comment, string literal,
/// or template-string fragment. The rg/inproc matchers are pure substring
/// search and happily match catalog patterns inside `// req.query` comments
/// or `console.log("req.query")` log strings — those aren't real sources.
///
/// Strategy: parse each unique file once (reusing the parsed tree across
/// every candidate from that file), descend to the smallest node spanning
/// the candidate's match byte range, walk the parent chain checking node
/// kinds. If any ancestor is a comment/string/template node, drop the
/// candidate.
///
/// Behavior on languages without a grammar (C, C++, Rust, C#, …): pass
/// candidates through unchanged. Narrowing is a precision improver, not a
/// correctness gate, so absence of a grammar should never lose true
/// positives.
pub(crate) fn narrow_taint_iris_next_candidates_syntactically(
    scan_root: &Path,
    candidates: Vec<TaintIrisNextCandidate>,
) -> Vec<TaintIrisNextCandidate> {
    if candidates.is_empty() {
        return candidates;
    }
    let mut narrower = SyntacticNarrower::new();
    candidates
        .into_iter()
        .filter(|candidate| narrower.keeps(scan_root, candidate))
        .collect()
}

struct SyntacticNarrower {
    parsers: RefCell<HashMap<&'static str, Parser>>,
    parsed: HashMap<String, Option<ParsedFile>>,
}

struct ParsedFile {
    source_bytes: Vec<u8>,
    tree: Tree,
}

impl SyntacticNarrower {
    fn new() -> Self {
        Self {
            parsers: RefCell::new(HashMap::new()),
            parsed: HashMap::new(),
        }
    }

    fn keeps(&mut self, scan_root: &Path, candidate: &TaintIrisNextCandidate) -> bool {
        let Some(language_id) = grammar_id_for(&candidate.language) else {
            // No grammar registered for this language — pass through. The
            // pre-existing rg + language-scope gate is the only filter that
            // applies. Don't drop true positives just because we lack a
            // parser.
            return true;
        };
        let parsed = match self.parse_for(scan_root, &candidate.file_path, language_id) {
            Some(parsed) => parsed,
            None => return true, // I/O failure or parse error — fail open.
        };
        let Some(byte_range) = locate_candidate_bytes(parsed, candidate) else {
            // Couldn't find the catalog pattern on the recorded line. Could
            // mean the line was matched via the alias table (e.g. "query
            // parameter" -> "req.query"), in which case substring matching
            // already accepted a derivative. Keep the candidate rather than
            // silently dropping it; the model still gets the same evidence.
            return true;
        };
        let Some(node) = smallest_node_spanning(parsed.tree.root_node(), byte_range) else {
            return true;
        };
        !is_within_noise_node(node)
    }

    fn parse_for(
        &mut self,
        scan_root: &Path,
        relative_path: &str,
        language_id: &'static str,
    ) -> Option<&ParsedFile> {
        if !self.parsed.contains_key(relative_path) {
            let absolute = scan_root.join(relative_path);
            let parsed = parse_file(&absolute, language_id, &mut self.parsers.borrow_mut());
            self.parsed.insert(relative_path.to_string(), parsed);
        }
        self.parsed.get(relative_path).and_then(Option::as_ref)
    }
}

fn parse_file(
    absolute: &Path,
    language_id: &'static str,
    parsers: &mut HashMap<&'static str, Parser>,
) -> Option<ParsedFile> {
    let source_bytes = std::fs::read(absolute).ok()?;
    if source_bytes.is_empty() {
        return None;
    }
    let parser = parsers.entry(language_id).or_insert_with(|| {
        let mut parser = Parser::new();
        // unwrap is fine — language() built-ins on the grammar crates
        // are infallible and the LanguageFn -> Language conversion only
        // fails on ABI mismatch which would be a build-time bug.
        let _ = parser.set_language(&language_for(language_id));
        parser
    });
    let tree = parser.parse(&source_bytes, None)?;
    Some(ParsedFile { source_bytes, tree })
}

/// Map our internal language tag (from `language_for_path`) to the grammar
/// id we register parsers under. Returning `None` means "no parser; skip
/// narrowing for this candidate".
fn grammar_id_for(language: &str) -> Option<&'static str> {
    match language {
        "javascript" => Some("javascript"),
        "typescript" => Some("typescript"),
        "python" => Some("python"),
        "java" => Some("java"),
        "ruby" => Some("ruby"),
        "php" => Some("php"),
        "go" => Some("go"),
        // tree-sitter-c parses both C (.c/.h) and is a reasonable fallback
        // for C++ here — we don't pull tree-sitter-cpp because the C
        // grammar already covers comments and string literals correctly,
        // which is all the narrowing pass uses to filter noise.
        "c" | "cpp" => Some("c"),
        _ => None,
    }
}

fn language_for(grammar_id: &'static str) -> Language {
    match grammar_id {
        "javascript" => tree_sitter_javascript::LANGUAGE.into(),
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        "ruby" => tree_sitter_ruby::LANGUAGE.into(),
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "c" => tree_sitter_c::LANGUAGE.into(),
        other => panic!("grammar_id_for/language_for drift: unsupported grammar {other:?}"),
    }
}

fn locate_candidate_bytes(
    parsed: &ParsedFile,
    candidate: &TaintIrisNextCandidate,
) -> Option<(usize, usize)> {
    let line_index = candidate.line.checked_sub(1)? as usize;
    let line_start = nth_line_start(&parsed.source_bytes, line_index)?;
    let line_end = line_end_byte(&parsed.source_bytes, line_start);
    let line_bytes = &parsed.source_bytes[line_start..line_end];
    let line_text = std::str::from_utf8(line_bytes).ok()?;
    let pattern_lower = candidate.pattern.to_ascii_lowercase();
    let line_lower = line_text.to_ascii_lowercase();
    let offset_in_line = line_lower.find(&pattern_lower)?;
    let start = line_start + offset_in_line;
    let end = start + pattern_lower.len();
    Some((start, end))
}

fn nth_line_start(bytes: &[u8], line_index: usize) -> Option<usize> {
    if line_index == 0 {
        return Some(0);
    }
    let mut newlines_seen = 0usize;
    for (offset, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            newlines_seen += 1;
            if newlines_seen == line_index {
                return Some(offset + 1);
            }
        }
    }
    None
}

fn line_end_byte(bytes: &[u8], line_start: usize) -> usize {
    bytes[line_start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|relative| line_start + relative)
        .unwrap_or(bytes.len())
}

fn smallest_node_spanning(root: Node<'_>, range: (usize, usize)) -> Option<Node<'_>> {
    let (start, end) = range;
    let mut best = root.descendant_for_byte_range(start, end)?;
    // descendant_for_byte_range returns the smallest node fully containing
    // the range; that's exactly what we want, but bubble up if it equals
    // the root (no real descendant) — that's a sign the byte range fell
    // outside the parsed content and the parent-chain check would be
    // useless.
    if best == root && root.kind() != "ERROR" {
        // Empty file or comment-only file: no useful narrowing to do.
        return None;
    }
    while best.kind() == "ERROR" {
        best = best.parent()?;
    }
    Some(best)
}

fn is_within_noise_node(mut node: Node<'_>) -> bool {
    loop {
        if NOISE_NODE_KINDS.contains(&node.kind()) {
            return true;
        }
        match node.parent() {
            Some(parent) => node = parent,
            None => return false,
        }
    }
}

/// Tree-sitter node kinds whose contents are not executable code.
///
/// Includes the union across the seven supported grammars so we can use a
/// single flat lookup. False positives here would *keep* candidates that
/// should be dropped (precision miss), so the list is conservative —
/// it only contains kinds whose contents are documented as non-code by
/// the respective grammar:
///   - Comments: `comment` (most), `line_comment`, `block_comment` (Java/Go)
///   - Strings: `string`, `string_literal`, `string_fragment` (TS/JS),
///     `string_content` (TS/JS), `template_string` (TS/JS),
///     `interpreted_string_literal`/`raw_string_literal` (Go),
///     `heredoc_body` (Ruby/PHP), `string_array` / `symbol_array` (Ruby)
///   - Doc comments: `doc_comment` (where present)
///   - Decorator-like raw text: none — decorators DO contain expressions
///     that should be analyzed
const NOISE_NODE_KINDS: &[&str] = &[
    "comment",
    "line_comment",
    "block_comment",
    "doc_comment",
    "shebang",
    "string",
    "string_literal",
    "string_fragment",
    "string_content",
    "raw_string_literal",
    "interpreted_string_literal",
    "template_string",
    "template_chars",
    "heredoc_body",
    "heredoc_content",
    "string_array",
    "symbol_array",
    "regex",
    "regex_pattern",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn candidate_at(
        file: &str,
        line: u32,
        language: &str,
        pattern: &str,
    ) -> TaintIrisNextCandidate {
        TaintIrisNextCandidate {
            id: format!("test:{file}:{line}:{pattern}"),
            cwe: "CWE-89".to_string(),
            taint_class: "injection".to_string(),
            track: "taint".to_string(),
            role: "sink".to_string(),
            kind: "external-arg-sink".to_string(),
            pattern: pattern.to_string(),
            file_path: file.to_string(),
            line,
            snippet: String::new(),
            language: language.to_string(),
            confidence: "medium".to_string(),
            catalog_signal: format!("sink: {pattern}"),
            source: "structural".to_string(),
        }
    }

    #[test]
    fn drops_candidate_inside_javascript_line_comment() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("noise.js"),
            "// db.query in a comment is not a sink\nconsole.log('hi');\n",
        )
        .unwrap();
        let candidates = vec![candidate_at("noise.js", 1, "javascript", "db.query")];
        let kept = narrow_taint_iris_next_candidates_syntactically(temp.path(), candidates);
        assert!(
            kept.is_empty(),
            "candidate inside a // comment should be dropped"
        );
    }

    #[test]
    fn drops_candidate_inside_typescript_string_literal() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("logging.ts"),
            "const message = \"db.query template\";\n",
        )
        .unwrap();
        let candidates = vec![candidate_at("logging.ts", 1, "typescript", "db.query")];
        let kept = narrow_taint_iris_next_candidates_syntactically(temp.path(), candidates);
        assert!(
            kept.is_empty(),
            "candidate inside \"...\" should be dropped"
        );
    }

    #[test]
    fn drops_candidate_inside_python_docstring() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("doc.py"),
            "def f():\n    \"\"\"docs mention req.query but it's just text.\"\"\"\n    return 1\n",
        )
        .unwrap();
        let candidates = vec![candidate_at("doc.py", 2, "python", "req.query")];
        let kept = narrow_taint_iris_next_candidates_syntactically(temp.path(), candidates);
        assert!(
            kept.is_empty(),
            "candidate inside a docstring should be dropped"
        );
    }

    #[test]
    fn keeps_candidate_in_real_call_expression() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("real.js"),
            "const id = req.query.id;\nconst rows = db.query(`select * from t where id = ${id}`);\n",
        )
        .unwrap();
        let candidates = vec![
            candidate_at("real.js", 2, "javascript", "db.query"),
            candidate_at("real.js", 1, "javascript", "req.query"),
        ];
        let kept = narrow_taint_iris_next_candidates_syntactically(temp.path(), candidates);
        assert_eq!(kept.len(), 2, "real call/member expressions should be kept");
    }

    #[test]
    fn drops_candidate_inside_c_block_comment_and_string_literal() {
        let temp = tempdir().unwrap();
        std::fs::write(
            temp.path().join("tidscan.c"),
            "/* numAllocTids = list_length() in this palloc-related comment */\n\
const char *banner = \"palloc test message\";\n\
int main(void) { palloc(8); return 0; }\n",
        )
        .unwrap();
        let candidates = vec![
            // line 1: pattern lives inside a /* ... */ block comment — drop
            candidate_at("tidscan.c", 1, "c", "palloc"),
            // line 2: pattern lives inside a "..." string literal — drop
            candidate_at("tidscan.c", 2, "c", "palloc"),
            // line 3: real call expression — keep
            candidate_at("tidscan.c", 3, "c", "palloc"),
        ];
        let kept = narrow_taint_iris_next_candidates_syntactically(temp.path(), candidates);
        assert_eq!(
            kept.len(),
            1,
            "only the real palloc() call should survive, got {kept:?}"
        );
        assert_eq!(kept[0].line, 3);
    }

    #[test]
    fn passes_through_languages_without_a_grammar() {
        // Rust isn't in our grammar map; narrowing should not touch its
        // candidates. We give a candidate pointing at a comment line —
        // narrowing would normally drop it, but with no grammar we keep
        // it (precision miss is preferable to a recall miss).
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("file.rs"),
            "// req.query in a comment\nfn main() {}\n",
        )
        .unwrap();
        let candidates = vec![candidate_at("file.rs", 1, "rust", "req.query")];
        let kept = narrow_taint_iris_next_candidates_syntactically(temp.path(), candidates);
        assert_eq!(kept.len(), 1, "Rust has no grammar yet; keep candidate");
    }

    #[test]
    fn passes_through_when_file_is_unreadable() {
        let temp = tempdir().unwrap();
        // No file written.
        let candidates = vec![candidate_at("missing.ts", 1, "typescript", "db.query")];
        let kept = narrow_taint_iris_next_candidates_syntactically(temp.path(), candidates);
        assert_eq!(kept.len(), 1, "missing file => fail open");
    }

    #[test]
    fn keeps_candidate_when_pattern_is_not_on_recorded_line() {
        // Candidate carries a catalog pattern that only matched via the
        // alias table (e.g. "query parameter" matched because the line
        // contained "req.query"). Narrowing can't locate the catalog
        // pattern itself on the line, so it should keep the candidate
        // rather than guess wrong about its byte range.
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("aliased.ts"), "const id = req.query.id;\n").unwrap();
        let candidates = vec![candidate_at(
            "aliased.ts",
            1,
            "typescript",
            "query parameter",
        )];
        let kept = narrow_taint_iris_next_candidates_syntactically(temp.path(), candidates);
        assert_eq!(
            kept.len(),
            1,
            "alias-derived candidates pass through narrowing"
        );
    }
}
