//! Env-read and panic-surface ratchets for the CLI, mirroring
//! kuzushi-core's `env_boundary_lint` / `panic_surface_lint`.
//!
//! CLI env reads are legitimate only for credentials/OAuth, `PATH`/`HOME`
//! integration, doctor diagnostics (whose job is probing the operator
//! environment), and terminal/accessibility modes. The application and
//! presentation layers parse run artifacts and tool JSON, so they must
//! stay free of reachable panic sites.

use std::path::{Path, PathBuf};

/// Audited 2026-07-21 (wave-4 X1). Relative to `src/`.
const AUDITED_ENV_READ_FILES: &[&str] = &[
    // Credential / OAuth boundaries.
    "adapters/auth_bridge.rs", // configured api-key env for the bridge
    "adapters/auth_oauth.rs",  // OPENAI_BASE_URL, CODEX_CI, key presence
    // Doctor diagnostics probe the operator environment by design.
    "doctor/bridge.rs", // PATH
    "doctor/checks.rs", // PATH, HOME, REVNG_IMAGE locators
    // Terminal / accessibility mode.
    "presentation/terminal.rs", // KUZUSHI_PLAIN/SCREEN_READER/LOW_BANDWIDTH
];

/// Application + presentation parse run artifacts and tool output.
const PANIC_SCAN_DIRS: &[&str] = &["application", "presentation", "doctor"];

/// Audited panic sites: (path relative to `src/`, unique line substring).
/// Compile-time canonical artifact spec lookups; a miss is a build defect.
const AUDITED_PANIC_SITES: &[(&str, &str)] = &[
    (
        "application/pr_comment.rs",
        "tool result artifact must be in shared spec",
    ),
    (
        "application/runs.rs",
        "trace artifact must be in shared canonical spec",
    ),
    (
        "application/runs_diff.rs",
        "tool result artifact must be in shared spec",
    ),
];

// Split so this file never matches its own detection patterns.
fn env_read_pattern() -> String {
    format!("env::{}", "var")
}

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

fn is_dedicated_test_file(relative: &str) -> bool {
    relative.ends_with("tests.rs") || relative.contains("/tests/")
}

/// Everything before the first top-level `#[cfg(test)]`; `None` for files
/// whose production region contains `#[test]` (dedicated test modules).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn src_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    fn relative_sources(root: &Path) -> Vec<(String, String)> {
        let mut sources = Vec::new();
        rust_sources(root, &mut sources);
        sources
            .into_iter()
            .filter_map(|path| {
                let relative = path
                    .strip_prefix(src_root())
                    .expect("source under src/")
                    .to_string_lossy()
                    .replace('\\', "/");
                let body = std::fs::read_to_string(&path).ok()?;
                Some((relative, body))
            })
            .collect()
    }

    #[test]
    fn env_reads_stay_within_the_audited_boundary_files() {
        let pattern = env_read_pattern();
        let mut found = Vec::new();
        for (relative, body) in relative_sources(&src_root()) {
            if is_dedicated_test_file(&relative) || relative == "boundary_lints.rs" {
                continue;
            }
            let Some(region) = production_region(&body) else {
                continue;
            };
            if region.contains(&pattern) {
                found.push(relative);
            }
        }
        found.sort();

        let audited: std::collections::BTreeSet<&str> =
            AUDITED_ENV_READ_FILES.iter().copied().collect();
        let unaudited: Vec<&String> = found
            .iter()
            .filter(|file| !audited.contains(file.as_str()))
            .collect();
        assert!(
            unaudited.is_empty(),
            "new std::env read outside the audited boundary files: {unaudited:?}. \
             Route the value through config/options, or audit the read here \
             with a category comment."
        );

        let found: std::collections::BTreeSet<&str> =
            found.iter().map(String::as_str).collect();
        let stale: Vec<&&str> = AUDITED_ENV_READ_FILES
            .iter()
            .filter(|file| !found.contains(**file))
            .collect();
        assert!(stale.is_empty(), "stale AUDITED_ENV_READ_FILES: {stale:?}");
    }

    #[test]
    fn artifact_parsing_code_stays_free_of_unaudited_panic_sites() {
        let patterns = panic_patterns();
        let mut violations = Vec::new();
        let mut matched = vec![false; AUDITED_PANIC_SITES.len()];
        for dir in PANIC_SCAN_DIRS {
            for (relative, body) in relative_sources(&src_root().join(dir)) {
                if is_dedicated_test_file(&relative) {
                    continue;
                }
                let Some(region) = production_region(&body) else {
                    continue;
                };
                for line in region.lines() {
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("//")
                        || !patterns.iter().any(|pattern| line.contains(pattern))
                    {
                        continue;
                    }
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
            "new panic site in artifact-parsing CLI code — return an explicit \
             error instead, or audit it into AUDITED_PANIC_SITES:\n{}",
            violations.join("\n")
        );
        let stale: Vec<&(&str, &str)> = AUDITED_PANIC_SITES
            .iter()
            .zip(&matched)
            .filter(|(_, matched)| !**matched)
            .map(|(entry, _)| entry)
            .collect();
        assert!(stale.is_empty(), "stale AUDITED_PANIC_SITES: {stale:?}");
    }
}
