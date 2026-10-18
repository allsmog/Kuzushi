//! Env-read and panic-surface ratchets for the interactive shell,
//! mirroring kuzushi-core's `env_boundary_lint` / `panic_surface_lint`.
//!
//! Env reads in the TUI are legitimate only at presentation/adapter
//! boundaries: terminal & accessibility modes, credential PRESENCE
//! probes (never values into view models), `PATH`/`HOME`, and documented
//! test/devex hooks. A panic in a render or view-model path corrupts the
//! operator's terminal, so the pane-facing dirs must stay free of
//! reachable panic sites.

use std::path::{Path, PathBuf};

/// Audited 2026-08-21, plus `theme/config.rs` on 2026-10-18 — the first
/// run after the region rule below stopped hiding it. Relative to `src/`.
const AUDITED_ENV_READ_FILES: &[&str] = &[
    // Terminal / accessibility / presentation mode.
    "app/runtime/run_shell.rs", // KUZUSHI_PLAIN/SCREEN_READER/LOW_BANDWIDTH
    "app/runtime/render_plain_scripted_session.rs", // KUZUSHI_MOUSE_CAPTURE
    "theme/config.rs",          // KUZUSHI_THEME/REDUCED_MOTION, NO_COLOR, COLORTERM, TERM
    "ui_view_models/prompt.rs", // KUZUSHI_CLI_NAME branding compat
    "app/onboarding/initial_view.rs", // KUZUSHI_SKIP_ONBOARDING presentation toggle
    // Credential presence and canonical OAuth-path adapter; values never surface.
    "app/settings/normalize_thinking_level/oauth_status.rs",
    // PATH / HOME process integration.
    "app/tool_runner/run_tool/background/preflight.rs", // PATH
    "app/onboarding/task_row.rs", // PATH + KUZUSHI_CODEQL_BIN CLI presence probe
    "ui_view_models/home_cockpit.rs", // HOME for ~ display
    // Compatibility adapter reads (documented in AGENTS.md).
    "app/shell_lifecycle/construction.rs", // ui.auto_open_viz compat value
    // Test / devex hooks.
    "app/devex_phase_fixture/mod.rs",      // DEVEX_PHASE_FIXTURE_ENV
    "app/onboarding/target_candidates.rs", // cfg!(test)-gated history hook
    "app/view_hydration/reader.rs",        // KUZUSHI_* hydration test hooks
    "renderer/phase_composition_contract/snapshots.rs", // KUZUSHI_PHASE_SNAPSHOT_OUT regen
];

/// Directories whose production code paints panes or folds artifacts
/// into view models; a panic here tears down the raw-mode terminal.
const PANIC_SCAN_DIRS: &[&str] = &["renderer", "ui_view_models", "commands"];

/// The snapshot-contract harness lives outside `#[cfg(test)]` so the
/// regen path works, but it is only invoked from its own tests.
const PANIC_SCAN_EXCLUDED_DIRS: &[&str] = &["renderer/phase_composition_contract"];

/// Audited panic sites: (path relative to `src/`, unique line substring).
const AUDITED_PANIC_SITES: &[(&str, &str)] = &[
    // Local match-arm invariant: the Reuse/Blocked arms return earlier in
    // the same function; no input reaches this arm.
    (
        "renderer/views/onboarding/planning_picker.rs",
        "handled above",
    ),
    // Lookups into the compile-time canonical artifact spec table; the
    // keys are static literals, so a miss is a build defect, not input.
    (
        "ui_view_models/failure_handoff.rs",
        "failures artifact must be in shared canonical spec",
    ),
    (
        "ui_view_models/home_cockpit.rs",
        "run metadata artifact must be in shared canonical spec",
    ),
    (
        "ui_view_models/run_timeline.rs",
        "run metadata artifact must be in shared canonical spec",
    ),
];

const TEST_ATTRIBUTE: &str = "#[cfg(test)]";

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

/// The file's production region: everything outside its `#[cfg(test)]`
/// items. The attribute guards one item, not the rest of the file, so a
/// module that declares a test submodule beside its other `mod` lines, or
/// that keeps a `#[cfg(test)]` helper above its production body, still has
/// that body scanned. `None` for files whose production region contains
/// `#[test]` (dedicated test modules).
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
    fn production_region_keeps_the_body_below_a_guarded_item() {
        assert_eq!(
            production_region("#[cfg(test)]\nmod unit_tests;\nfn a() {}").as_deref(),
            Some("\nfn a() {}")
        );
        assert_eq!(
            production_region("#[cfg(test)]\nfn helper() -> u8 { 1 }\nfn a() {}").as_deref(),
            Some("\nfn a() {}")
        );
        assert_eq!(
            production_region("fn a() {}\n#[cfg(test)]\nmod tests { fn b() {} }").as_deref(),
            Some("fn a() {}\n")
        );
        assert_eq!(production_region("#[test]\nfn t() {}"), None);
    }

    /// An item the scanner cannot delimit must swallow the remainder rather
    /// than hand test code to the ratchet as production source.
    #[test]
    fn an_undelimited_guarded_item_consumes_the_remainder() {
        assert_eq!(
            production_region("fn a() {}\n#[cfg(test)]\nmod tests { fn b() {} ").as_deref(),
            Some("fn a() {}\n")
        );
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

        let found: std::collections::BTreeSet<&str> = found.iter().map(String::as_str).collect();
        let stale: Vec<&&str> = AUDITED_ENV_READ_FILES
            .iter()
            .filter(|file| !found.contains(**file))
            .collect();
        assert!(stale.is_empty(), "stale AUDITED_ENV_READ_FILES: {stale:?}");
    }

    #[test]
    fn pane_facing_code_stays_free_of_unaudited_panic_sites() {
        let patterns = panic_patterns();
        let mut violations = Vec::new();
        let mut matched = vec![false; AUDITED_PANIC_SITES.len()];
        for dir in PANIC_SCAN_DIRS {
            for (relative, body) in relative_sources(&src_root().join(dir)) {
                if is_dedicated_test_file(&relative)
                    || PANIC_SCAN_EXCLUDED_DIRS
                        .iter()
                        .any(|excluded| relative.starts_with(excluded))
                {
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
            "new panic site in pane-facing code — a panic there corrupts the \
             raw-mode terminal; return a degraded view instead, or audit it \
             into AUDITED_PANIC_SITES:\n{}",
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
