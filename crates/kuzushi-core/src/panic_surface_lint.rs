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
    (
        "report/artifact_summary/jsonl.rs",
        "runtime trace artifact must be in shared canonical spec",
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

/// The file's production region: everything before the first top-level
/// `#[cfg(test)]`. Files whose production region itself contains
/// `#[test]` are dedicated test files pulled in via a `#[cfg(test)] mod`
/// in their parent and are skipped entirely.
fn production_region(body: &str) -> Option<&str> {
    let region = match body.find("\n#[cfg(test)]") {
        Some(position) => &body[..position],
        None if body.starts_with("#[cfg(test)]") => "",
        None => body,
    };
    if region.contains("#[test]") {
        return None;
    }
    Some(region)
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
                for line in panic_lines_in_region(region) {
                    let audited = AUDITED_PANIC_SITES.iter().position(|(file, needle)| {
                        *file == relative && line.contains(needle)
                    });
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
    fn production_region_cuts_at_cfg_test_and_skips_dedicated_test_files() {
        assert_eq!(
            production_region("fn a() {}\n#[cfg(test)]\nmod tests {}"),
            Some("fn a() {}")
        );
        assert_eq!(production_region("#[cfg(test)]\nmod t {}"), Some(""));
        assert_eq!(production_region("#[test]\nfn t() {}"), None);
        assert_eq!(production_region("fn a() {}"), Some("fn a() {}"));
    }
}
