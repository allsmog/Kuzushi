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

/// Directories whose production code paints panes, folds artifacts into view
/// models, or reduces an operator action into shell state; a panic here tears
/// down the raw-mode terminal. `app` is scanned whole: every subtree under it
/// either carries an operator action, a background event or a tool result into
/// shell state, or folds an on-disk `.kuzushi` artifact into a view model, and
/// a panic in any of them reaches the operator exactly as a panic in the
/// renderer does. Scanning the tree rather than named subtrees also covers a
/// new subtree the day it is added, instead of the day someone remembers it.
const PANIC_SCAN_DIRS: &[&str] = &["renderer", "ui_view_models", "commands", "app"];

/// Paths the panic scan does not reach yet, each for one of two reasons.
///
/// The first two are test-only code that cannot live under `#[cfg(test)]`: the
/// snapshot-contract harness needs its regen path, and the owned-dispatcher
/// fixtures are built by tests in several modules.
///
/// The rest is the remaining audit backlog — subtrees and files whose panic
/// sites predate this scan and have not been read yet. Each entry is a debt,
/// not a dispensation: the panic sites inside it reach the operator exactly as
/// the scanned ones do. Removing an entry is how that subtree gets audited, and
/// `every_excluded_panic_scan_path_exists` keeps the list from rotting into a
/// blanket exemption for paths that no longer exist.
///
/// Every directory entry ends in `/`. The match is a path prefix, so a bare
/// `app/campaign` would also exempt the sibling file `app/campaign.rs` — a
/// module that is scanned, and whose name several of these subtrees share.
const PANIC_SCAN_EXCLUDED_DIRS: &[&str] = &[
    // Test-only code outside `#[cfg(test)]`.
    "renderer/phase_composition_contract/",
    "app/owned_dispatcher_test_support.rs",
    // Audit backlog. `app/effect_runtime.rs` is the largest single item: its
    // twelve `unreachable!` arms fire when the category router and one of its
    // sub-matches drift, and routing a stray effect to an honest notice
    // instead is its own change. `app/session_state.rs` holds `#[cfg(test)]`
    // helpers inside an `impl` block, which the column-0 region rule, which
    // only strips a whole top-level item, does not reach.
    "app/effect_runtime.rs",
    "app/session_state.rs",
    "app/agent_session/",
    "app/batch_scan/",
    "app/campaign/",
    "app/devex_phase_fixture/",
    "app/file_picker/",
    "app/goal_review/",
    "app/guided_scan/",
    "app/lessons/",
    "app/line_editor/",
    "app/onboarding/",
    "app/operator_questions/",
    "app/options/",
    "app/relationships/",
    "app/runtime_keymap/",
    "app/scan/",
    "app/scope_review/",
    "app/source_review/",
    "app/strategy/",
    "app/threats/",
];

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
    // Serializing a `&str` emits a JSON string. The writer reports an error
    // only for a non-string map key, a non-finite float, or a `Serialize`
    // that fails, and a path supplies none of them.
    (
        "ui_view_models/scope_review/paths.rs",
        "a path string is serializable",
    ),
    // The same writer over a `serde_json::Value`, which can hold neither a
    // non-finite number nor a non-string map key, so neither error the
    // writer reports is reachable from one.
    (
        "ui_view_models/study_context/comparison/content.rs",
        "JSON values serialize",
    ),
    // Split-match classification invariant: the completion, transient and run
    // keys are mapped by `hydration_group` before it delegates, so only a
    // `ViewHydrationKey` variant added without a cache group reaches this arm.
    // A group decides eviction, so there is no honest default to fall back to.
    (
        "app/view_state/workbench_cache/hydration_state.rs",
        "completion, transient and run keys are classified first",
    ),
    // The same shape on the reader side, and contained twice over: the arm is
    // reachable only from a `ViewHydrationKey` variant that no reader boundary
    // claims, and every call runs inside `caught_read`, which since #356
    // discloses the recovered panic on the surface whose data went missing.
    (
        "app/view_hydration/reader.rs",
        "view hydration key was not assigned to a reader boundary",
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

/// The file's production region: everything outside its top-level
/// `#[cfg(test)]` items. The attribute guards one item, not the rest of the
/// file, so a module that declares a test submodule beside its other `mod`
/// lines (including the `#[path = "..."]` form), or that keeps a one-line
/// declaration or column-0-closed braced `#[cfg(test)]` helper above its
/// production body, still has that body scanned. A guarded item whose end
/// cannot be confirmed ends the region at its attribute, as the scan always
/// did. `None` for files whose region above the first guarded item contains
/// `#[test]` (dedicated test modules).
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
            production_region("use x;\n#[cfg(test)]\nmod unit_tests;\nfn a() {}").as_deref(),
            Some("use x;\nfn a() {}")
        );
        assert_eq!(
            production_region("use x;\n#[cfg(test)]\nfn helper() -> u8 {\n    1\n}\nfn a() {}")
                .as_deref(),
            Some("use x;\nfn a() {}")
        );
        assert_eq!(production_region("#[test]\nfn t() {}"), None);
    }

    /// A brace inside a string, a char literal or a comment must not be read
    /// as the item's own: counting braces here let a guarded helper swallow
    /// every production line below it.
    #[test]
    fn a_brace_inside_a_literal_cannot_swallow_the_production_body() {
        let body = concat!(
            "use x;\n",
            "#[cfg(test)]\n",
            "fn helper() {\n",
            "    let _ = \"{\";\n",
            "}\n",
            "fn a() {\n",
            "    std::env::var(\"X\");\n",
            "}"
        );
        let region = production_region(body).expect("production region");
        assert!(region.contains(&env_read_pattern()), "{region}");
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

    /// An exclusion that no longer names a real path is a blanket exemption
    /// nobody can see: it never fails, so the backlog it records stops
    /// shrinking and a renamed subtree silently leaves the scan.
    #[test]
    fn every_excluded_panic_scan_path_exists() {
        let missing: Vec<&&str> = PANIC_SCAN_EXCLUDED_DIRS
            .iter()
            .filter(|excluded| !src_root().join(excluded).exists())
            .collect();
        assert!(
            missing.is_empty(),
            "stale PANIC_SCAN_EXCLUDED_DIRS — the path is gone, so drop the \
             entry rather than leave an exemption that cannot fail: {missing:?}"
        );
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
