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

const TEST_ATTRIBUTE: &str = "#[cfg(test)]";

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

/// The file's production region: everything outside its `#[cfg(test)]`
/// items. The attribute guards one item, not the rest of the file, so a
/// module that declares a test submodule beside its other `mod` lines, or
/// that keeps a `#[cfg(test)]` helper above its production body, still has
/// that body scanned. Files whose production region itself contains
/// `#[test]` are dedicated test files pulled in via a `#[cfg(test)] mod`
/// in their parent and are skipped entirely.
fn production_region(body: &str) -> Option<String> {
    let mut region = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(position) = rest.find(TEST_ATTRIBUTE) {
        region.push_str(&rest[..position]);
        rest = after_test_item(&rest[position + TEST_ATTRIBUTE.len()..]);
    }
    region.push_str(rest);
    (!region.contains("#[test]")).then_some(region)
}

/// What follows the item one `#[cfg(test)]` guards: a declaration ends at
/// its `;`, a braced item at its matching close brace. An item whose braces
/// never balance consumes the remainder, which keeps the scan conservative.
fn after_test_item(guarded: &str) -> &str {
    match (guarded.find(';'), guarded.find('{')) {
        (Some(semicolon), brace) if brace.is_none_or(|brace| semicolon < brace) => {
            &guarded[semicolon + 1..]
        }
        (_, Some(brace)) => after_braced_item(&guarded[brace..]),
        (_, None) => "",
    }
}

fn after_braced_item(from_open_brace: &str) -> &str {
    let mut depth = 0_usize;
    for (index, character) in from_open_brace.char_indices() {
        depth = match character {
            '{' => depth + 1,
            '}' => depth.saturating_sub(1),
            _ => depth,
        };
        if depth == 0 {
            return &from_open_brace[index + character.len_utf8()..];
        }
    }
    ""
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
            production_region("#[cfg(test)]\nmod unit_tests;\nfn a() {}").as_deref(),
            Some("\nfn a() {}")
        );
        assert_eq!(
            production_region("#[cfg(test)]\nfn helper() -> u8 { 1 }\nfn a() {}").as_deref(),
            Some("\nfn a() {}")
        );
        assert_eq!(
            production_region("#[cfg(test)]\nmod tests { fn unbalanced() {} ").as_deref(),
            Some("")
        );
    }
}
