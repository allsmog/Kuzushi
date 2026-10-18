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
/// lines, or that keeps a `#[cfg(test)]` helper above its production body,
/// still has that body scanned. Files whose production region itself contains
/// `#[test]` are dedicated test files pulled in via a `#[cfg(test)] mod`
/// in their parent and are skipped entirely.
fn production_region(body: &str) -> Option<String> {
    if body.starts_with("#[cfg(test)]") {
        return Some(String::new());
    }
    let region = scanned_region(body);
    (!region.contains("#[test]")).then_some(region)
}

/// A column-0 `#[cfg(test)]` on its own line — the only form that guards a
/// whole top-level item.
const TEST_ATTRIBUTE_LINE: &str = "\n#[cfg(test)]\n";

fn scanned_region(body: &str) -> String {
    let mut region = String::with_capacity(body.len());
    let mut cursor = 0;
    while let Some(offset) = body[cursor..].find(TEST_ATTRIBUTE_LINE) {
        // Keep the newline the needle anchored on: dropping it would join the
        // line above the attribute to the line below the item, and a comment
        // line joined to a code line hides that code from the line scan.
        let attribute = cursor + offset;
        region.push_str(&body[cursor..=attribute]);
        let Some(end) = end_of_test_item(body, attribute + TEST_ATTRIBUTE_LINE.len()) else {
            return region;
        };
        cursor = end;
    }
    region.push_str(&body[cursor..]);
    region
}

/// Where one guarded top-level item ends: a declaration at the end of its own
/// line, a braced item after the column-0 `}` that closes it. Deliberately not
/// brace counting, because a `{` inside a string, a char literal or a comment
/// would unbalance the count and swallow the production body below the item.
/// Any other shape returns `None`, and the region ends there as it did before
/// this rule could skip an item at all.
fn end_of_test_item(body: &str, item: usize) -> Option<usize> {
    let line = body[item..].lines().next()?.trim_end();
    if line.ends_with(';') && !line.contains('{') {
        return Some(end_of_line(body, item));
    }
    if !line.ends_with('{') {
        return None;
    }
    let closing_brace = item + body[item..].find("\n}")? + 1;
    Some(end_of_line(body, closing_brace))
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
}
