//! Panic-surface ratchet for the hostile-input parsing closure.
//!
//! Importers (HAR/Burp/recon), scanner-output parsers, and report
//! summarizers consume bytes an attacker can shape: capture files,
//! scanned repositories, and tool output. A reachable `unwrap`/`expect`/
//! `panic!` there turns malformed input into an operator-facing crash
//! instead of an explicit error. Audited 2026-07-21 (wave-3 P2): the
//! production regions of these modules contain only the allowlisted
//! invariants below, none of which depend on external input. This
//! ratchet keeps it that way: a new panic site in these modules is a
//! deliberate, reviewed decision — return an explicit error, or add the
//! site here with a justification.

use std::path::{Path, PathBuf};

/// Directories whose production code parses externally shaped bytes.
const HOSTILE_INPUT_DIRS: &[&str] = &[
    "findings/import",
    "capabilities/recon/application",
    "report/artifact_summary",
    "scan/engines",
];

/// Audited panic sites: (path relative to `src/`, unique line substring).
/// Every entry must justify why the panic cannot fire on external input.
const AUDITED_PANIC_SITES: &[(&str, &str)] = &[
    // Lookups into the compile-time canonical artifact spec table; the
    // keys are static literals, so a miss is a build defect, not input.
    (
        "report/artifact_summary/jsonl.rs",
        "run events artifact must be in shared canonical spec",
    ),
    // Internal routing invariant: core manifests are dispatched to the
    // extended analyzer before this match arm can be reached.
    (
        "scan/engines/dep_hygiene/textual_cvss_severity.rs",
        "core manifest routed to extended analyzer",
    ),
];

// Split so this file's own strings never match the detection patterns.
fn panic_patterns() -> [String; 4] {
    [
        format!(".{}()", "unwrap"),
        format!(".{}(", "expect"),
        format!("{}!(", "panic"),
        format!("{}!(", "unreachable"),
    ]
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The file's production region: everything outside its top-level
/// `#[cfg(test)]` items. The attribute guards one item, not the rest of the
/// file, so a module that declares a test submodule beside its other `mod`
/// lines (including the `#[path = "..."]` form), or that keeps a one-line
/// declaration or column-0-closed braced `#[cfg(test)]` helper above its
/// production body, still has that body scanned. A guarded item whose end
/// cannot be confirmed ends the region at its attribute, as the scan always
/// did. Files whose region above the first guarded item contains `#[test]`
/// are dedicated test files pulled in via a `#[cfg(test)] mod` in their parent
/// and are skipped entirely.
fn production_region(body: &str) -> Option<String> {
    let region = scanned_region(body);
    (!region.contains("#[test]")).then_some(region)
}

/// A column-0 `#[cfg(test)]` — the only form that guards a whole top-level
/// item. The item may share its line or follow on a later one.
const TEST_ATTRIBUTE: &str = "#[cfg(test)]";
const TEST_ATTRIBUTE_AFTER_NEWLINE: &str = "\n#[cfg(test)]";

/// Everything the old rule scanned — the text above the first guarded
/// attribute below the top line — plus the text after each guarded item whose
/// end is certain. An uncertain skip ends the region at its attribute, or at
/// that old boundary when the file opens with the item, so coverage never
/// drops below the old rule and test code is never resumed as production.
fn scanned_region(body: &str) -> String {
    let mut region = String::with_capacity(body.len());
    let mut cursor = 0;
    while let Some(attribute) = next_test_attribute(body, cursor) {
        region.push_str(&body[cursor..attribute]);
        let Some(end) = end_of_test_item(body, attribute + TEST_ATTRIBUTE.len()) else {
            let floor = end_of_old_region(body).max(attribute);
            region.push_str(&body[attribute..floor]);
            return region;
        };
        cursor = end;
    }
    region.push_str(&body[cursor..]);
    region
}

/// Where the old rule ended the region: the first guarded attribute below the
/// top line. Only an item at the very top of the file can sit above it.
fn end_of_old_region(body: &str) -> usize {
    body.find(TEST_ATTRIBUTE_AFTER_NEWLINE)
        .map_or(0, |newline| newline + 1)
}

/// The next guarded attribute at or after `cursor`, which always sits at the
/// start of a line. Checking `cursor` itself catches an attribute directly
/// after a skipped item or at the top of the file, where no newline precedes
/// it inside the searched slice.
fn next_test_attribute(body: &str, cursor: usize) -> Option<usize> {
    let rest = &body[cursor..];
    if rest.starts_with(TEST_ATTRIBUTE) {
        return Some(cursor);
    }
    let newline = rest.find(TEST_ATTRIBUTE_AFTER_NEWLINE)?;
    Some(cursor + newline + 1)
}

/// Where one guarded top-level item ends: a declaration at the end of its own
/// line, a braced item after the column-0 `}` or `};` line that closes it.
/// Deliberately not brace counting, because a `{` inside a string, a char
/// literal or a comment would unbalance the count and swallow the production
/// body below the item. Any other shape — a multi-line signature, a one-line
/// braced item, a multi-line attribute, a block comment — returns `None`, as
/// does an end the text after it does not confirm.
fn end_of_test_item(body: &str, from: usize) -> Option<usize> {
    let item = start_of_item(body, from)?;
    let line = body[item..].lines().next()?.trim_end();
    // `"{"`, not `'{'`: the repo's CRAP gate counts a brace char literal.
    if line.ends_with(';') && !line.contains("{") {
        let end = end_of_line(body, item);
        return (resumption(body, end) == Resumption::Production).then_some(end);
    }
    if !line.ends_with("{") {
        return None;
    }
    end_of_braced_item(body, item)
}

/// The item's first line, past the rest of the attribute's own line and any
/// further one-line attributes, comments, doc comments or blank lines.
fn start_of_item(body: &str, from: usize) -> Option<usize> {
    let mut start = from;
    while body[start..].lines().next().is_some_and(is_item_preamble) {
        start = end_of_line(body, start);
    }
    (start < body.len()).then_some(start)
}

fn is_item_preamble(line: &str) -> bool {
    let line = line.trim();
    let attribute = line.starts_with("#[") && line.ends_with(']');
    line.is_empty() || line.starts_with("//") || attribute
}

/// A column-0 `}` inside a multi-line string can pass for the item's close,
/// so each candidate close is confirmed by the text after it: one that
/// resumes inside the item moves on to the next candidate, and one that
/// cannot be told apart from production gives up.
fn end_of_braced_item(body: &str, item: usize) -> Option<usize> {
    let mut search = item;
    while let Some(close) = next_closing_line(body, search) {
        let end = end_of_line(body, close);
        match resumption(body, end) {
            Resumption::Production => return Some(end),
            Resumption::InsideItem => search = end,
            Resumption::Ambiguous => return None,
        }
    }
    None
}

/// The next column-0 line that closes a braced item, skipping column-0 text
/// such as `});` that only a string literal can hold.
fn next_closing_line(body: &str, from: usize) -> Option<usize> {
    let mut search = from;
    loop {
        let close = search + body[search..].find("\n}")? + 1;
        if matches!(body[close..].lines().next(), Some("}" | "};")) {
            return Some(close);
        }
        search = close;
    }
}

#[derive(Debug, PartialEq)]
enum Resumption {
    Production,
    InsideItem,
    Ambiguous,
}

/// What the text from `end` to the next guarded attribute reads as. A test
/// attribute, or a first line indented like an item body, means the scan
/// resumed inside a test item. A column-0 line no rustfmt-formatted top level
/// begins with, such as the rest of a string literal, is ambiguous: a
/// production string can hold one too.
fn resumption(body: &str, end: usize) -> Resumption {
    let next = next_test_attribute(body, end).unwrap_or(body.len());
    let text = &body[end..next];
    if text.lines().any(is_test_attribute_line) || starts_indented(text) {
        return Resumption::InsideItem;
    }
    if text.lines().any(is_foreign_top_level) {
        return Resumption::Ambiguous;
    }
    Resumption::Production
}

fn is_test_attribute_line(line: &str) -> bool {
    line.contains("#[test]") || line.contains("::test]")
}

fn starts_indented(text: &str) -> bool {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .is_some_and(|line| line.starts_with(char::is_whitespace))
}

fn is_foreign_top_level(line: &str) -> bool {
    let Some(first) = line.chars().next() else {
        return false;
    };
    let opens = first.is_whitespace() || first.is_alphanumeric();
    let delimiter = matches!(line.trim_end(), "{" | "}" | "};" | "];");
    !(opens || delimiter || matches!(first, '_' | '#' | '/' | ')'))
}

fn end_of_line(body: &str, from: usize) -> usize {
    body[from..]
        .find('\n')
        .map_or(body.len(), |newline| from + newline + 1)
}

fn panic_lines_in_region(region: &str) -> Vec<String> {
    let patterns = panic_patterns();
    region
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && patterns.iter().any(|pattern| line.contains(pattern))
        })
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_input_parsers_stay_free_of_unaudited_panic_sites() {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut violations = Vec::new();
        let mut matched = vec![false; AUDITED_PANIC_SITES.len()];
        for dir in HOSTILE_INPUT_DIRS {
            let mut sources = Vec::new();
            rust_sources(&src.join(dir), &mut sources);
            for path in sources {
                let relative = path
                    .strip_prefix(&src)
                    .expect("source under src/")
                    .to_string_lossy()
                    .replace('\\', "/");
                if relative.ends_with("tests.rs") || relative.contains("/tests/") {
                    continue;
                }
                let Ok(body) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let Some(region) = production_region(&body) else {
                    continue;
                };
                for line in panic_lines_in_region(&region) {
                    let audited = AUDITED_PANIC_SITES
                        .iter()
                        .position(|(file, needle)| *file == relative && line.contains(needle));
                    match audited {
                        Some(index) => matched[index] = true,
                        None => violations.push(format!("{relative}: {}", line.trim())),
                    }
                }
            }
        }
        assert!(
            violations.is_empty(),
            "new panic site in a hostile-input parsing module — return an \
             explicit error instead, or audit it into AUDITED_PANIC_SITES \
             with a justification:\n{}",
            violations.join("\n")
        );
        let stale: Vec<&(&str, &str)> = AUDITED_PANIC_SITES
            .iter()
            .zip(&matched)
            .filter(|(_, matched)| !**matched)
            .map(|(entry, _)| entry)
            .collect();
        assert!(
            stale.is_empty(),
            "AUDITED_PANIC_SITES has stale entries (site removed or moved): \
             {stale:?}. Remove them so the ratchet stays honest."
        );
    }

    #[test]
    fn production_region_skips_cfg_test_items_and_dedicated_test_files() {
        assert_eq!(
            production_region("fn a() {}\n#[cfg(test)]\nmod tests {}").as_deref(),
            Some("fn a() {}\n")
        );
        assert_eq!(
            production_region("#[cfg(test)]\nmod t {}").as_deref(),
            Some("")
        );
        assert_eq!(production_region("#[test]\nfn t() {}"), None);
        assert_eq!(production_region("fn a() {}").as_deref(), Some("fn a() {}"));
    }

    /// The bug this rule replaces: a guarded declaration or helper above the
    /// production body hid everything below it from the ratchet.
    #[test]
    fn a_guarded_item_above_the_body_no_longer_hides_the_rest_of_the_file() {
        assert_eq!(
            production_region("use x;\n#[cfg(test)]\nmod unit_tests;\nfn a() {}").as_deref(),
            Some("use x;\nfn a() {}")
        );
        assert_eq!(
            production_region("use x;\n#[cfg(test)]\nfn helper() -> u8 {\n    1\n}\nfn a() {}")
                .as_deref(),
            Some("use x;\nfn a() {}")
        );
    }

    /// Counting braces here let a `{` inside a string end the scan early and
    /// hide every production line below the guarded helper.
    #[test]
    fn a_brace_inside_a_literal_cannot_swallow_the_production_body() {
        let body = concat!(
            "use x;\n",
            "#[cfg(test)]\n",
            "fn helper() {\n",
            "    let _ = \"{\";\n",
            "}\n",
            "fn a() {\n",
            "    Path::new(\"x\").to_str().unwrap();\n",
            "}"
        );
        let region = production_region(body).expect("production region");
        assert_eq!(panic_lines_in_region(&region).len(), 1, "{region}");
    }

    /// A shape this cannot delimit ends the region, which is exactly where the
    /// scan stopped before it could skip a guarded item at all.
    #[test]
    fn an_undelimited_guarded_item_ends_the_region() {
        assert_eq!(
            production_region("use x;\n#[cfg(test)]\nuse a::{b};\nfn a() {}").as_deref(),
            Some("use x;\n")
        );
    }

    /// A column-0 `}` inside a test fixture string once passed for the close
    /// of `mod tests`: the scan resumed mid-module, met its `#[test]`, and
    /// dropped the whole file from the ratchet.
    #[test]
    fn a_column_0_brace_inside_a_test_string_cannot_resume_the_scan() {
        let body = concat!(
            "use x;\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    const FIXTURE: &str = r#\"resource {\n",
            "}\n",
            "\"#;\n",
            "    #[test]\n",
            "    fn t() {}\n",
            "}\n",
            "fn a() {}\n"
        );
        assert_eq!(
            production_region(body).as_deref(),
            Some("use x;\nfn a() {}\n")
        );
    }

    /// When the text after a candidate close could be either a string's tail
    /// or production code, the region ends at the attribute, as it always did.
    #[test]
    fn an_unconfirmed_close_ends_the_region_at_its_attribute() {
        let body = concat!(
            "use x;\n",
            "#[cfg(test)]\n",
            "fn fixture() -> &'static str {\n",
            "    r#\"\n",
            "}\n",
            "\"#\n",
            "}\n",
            "fn a() {}\n"
        );
        assert_eq!(production_region(body).as_deref(), Some("use x;\n"));
    }

    /// After a skip the scan sits at the start of a line, where the next
    /// attribute has no newline before it inside the searched text.
    #[test]
    fn back_to_back_guarded_declarations_are_all_skipped() {
        let body = concat!(
            "use x;\n",
            "#[cfg(test)]\n",
            "mod a;\n",
            "#[cfg(test)]\n",
            "mod b;\n",
            "#[cfg(test)] mod c;\n",
            "fn a() {}\n"
        );
        assert_eq!(
            production_region(body).as_deref(),
            Some("use x;\nfn a() {}\n")
        );
    }

    #[test]
    fn a_guarded_item_at_the_top_of_the_file_hides_only_itself() {
        assert_eq!(
            production_region("#[cfg(test)]\nuse super::helper;\nfn a() {}").as_deref(),
            Some("fn a() {}")
        );
    }

    #[test]
    fn attributes_and_doc_comments_between_the_guard_and_its_item_are_skipped() {
        let body = concat!(
            "use x;\n",
            "#[cfg(test)]\n",
            "#[path = \"x_tests.rs\"]\n",
            "/// Unit tests.\n",
            "mod tests;\n",
            "fn a() {}\n"
        );
        assert_eq!(
            production_region(body).as_deref(),
            Some("use x;\nfn a() {}\n")
        );
    }
}
