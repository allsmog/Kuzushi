#![cfg(test)]

//! Rendered-surface lints: deterministic checks over the operator-facing
//! text corpus — every phase-cockpit snapshot fixture body plus the plain
//! projection of every `ShellView`.
//!
//! These catch the copy bugs a human only notices under stress: internal
//! jargon leaking onto operator surfaces, duplicated segments
//! ("missing · missing"), separator collisions, truncation artifacts, and
//! unbounded decision cards. Zero tmux, zero model calls — they run with
//! the ordinary test suite.

use super::render_plain_app;
use crate::app::{ShellApp, ShellView};
use kuzushi_core::{Finding, Severity, V2Config};
use std::fmt;
use std::fs;
use std::path::Path;
use strum::IntoEnumIterator;

const PLAIN_LINT_WIDTH: usize = 120;

pub(crate) struct SurfaceLine {
    pub(crate) source: String,
    pub(crate) number: usize,
    pub(crate) text: String,
}

pub(crate) struct Violation {
    rule: &'static str,
    source: String,
    number: usize,
    detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} [{}] {}",
            self.source, self.number, self.rule, self.detail
        )
    }
}

// ── corpus ──────────────────────────────────────────────────────────────────

pub(crate) fn rendered_surface_corpus() -> Vec<SurfaceLine> {
    let mut corpus = snapshot_fixture_lines();
    corpus.extend(plain_view_lines());
    assert!(
        corpus.len() > 200,
        "lint corpus suspiciously small ({} lines) — fixture path or view iteration broke",
        corpus.len()
    );
    corpus
}

/// Bodies of every checked-in phase-cockpit snapshot, with the YAML
/// frontmatter (source/contract/phase/size metadata) stripped — only the
/// rendered screen is an operator surface.
pub(crate) fn snapshot_fixture_lines() -> Vec<SurfaceLine> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/renderer/snapshots/phase_cockpit");
    let mut lines = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("snapshot dir {}: {error}", dir.display()))
        .map(|entry| entry.expect("snapshot dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "snap"))
        .collect();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("snapshot")
            .to_string();
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        for (number, text) in snapshot_body(&content) {
            lines.push(SurfaceLine {
                source: name.clone(),
                number,
                text,
            });
        }
    }
    lines
}

fn snapshot_body(content: &str) -> Vec<(usize, String)> {
    let mut fence_count = 0usize;
    let mut body = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if fence_count < 2 {
            if line.trim() == "---" {
                fence_count += 1;
            }
            continue;
        }
        body.push((index + 1, line.to_string()));
    }
    body
}

/// Plain projection of every `ShellView` over one seeded app. Empty-state
/// hints are operator copy too, so views without seeded artifacts still
/// contribute their guidance lines.
fn plain_view_lines() -> Vec<SurfaceLine> {
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![Finding::new_semgrep(
        "demo.sqli",
        "apps/api/orders.rs",
        12,
        Some(14),
        Severity::High,
        "sql injection via order_id",
    )];
    app.set_error_notice("tool", "semgrep:scan failed — scanner exited 2");
    let mut lines = Vec::new();
    for view in ShellView::iter() {
        app.set_shell_view(view);
        let rendered = render_plain_app(&app, PLAIN_LINT_WIDTH);
        for (index, text) in rendered.lines().enumerate() {
            lines.push(SurfaceLine {
                source: format!("plain:{view:?}"),
                number: index + 1,
                text: text.to_string(),
            });
        }
    }
    lines
}

// ── L1: jargon deny-list ────────────────────────────────────────────────────

/// Internal vocabulary that must never reach an operator surface. Matched
/// on word boundaries, case-insensitively.
const JARGON_WORDS: [&str; 4] = ["projection", "hydration", "hydrate", "watermark"];

pub(crate) fn lint_jargon(corpus: &[SurfaceLine]) -> Vec<Violation> {
    let mut violations = Vec::new();
    for line in corpus {
        let mut flag = |detail: String| {
            violations.push(Violation {
                rule: "jargon",
                source: line.source.clone(),
                number: line.number,
                detail,
            });
        };
        if let Some(uuid) = first_uuid_token(&line.text) {
            flag(format!("raw UUID `{uuid}` — use the operator alias"));
        }
        if line.text.contains("sha256:") {
            flag(format!("raw digest on screen: {}", line.text.trim()));
        }
        if let Some(counter) = seq_counter(&line.text) {
            flag(format!("internal sequence counter `{counter}`"));
        }
        for word in JARGON_WORDS {
            if contains_word_case_insensitive(&line.text, word) {
                flag(format!("deny-listed word `{word}`: {}", line.text.trim()));
            }
        }
        if contains_word_case_insensitive(&line.text, "typed")
            && !line.text.to_ascii_lowercase().contains("typed command")
        {
            flag(format!("deny-listed word `typed`: {}", line.text.trim()));
        }
        if let Some(token) = schema_version_token(&line.text) {
            flag(format!("schema-version suffix `{token}` on screen"));
        }
    }
    violations
}

fn first_uuid_token(text: &str) -> Option<String> {
    text.split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .find(|token| is_uuid(token))
        .map(str::to_string)
}

fn is_uuid(token: &str) -> bool {
    if token.len() != 36 {
        return false;
    }
    token.char_indices().all(|(index, c)| match index {
        8 | 13 | 18 | 23 => c == '-',
        _ => c.is_ascii_hexdigit(),
    })
}

fn seq_counter(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(offset) = lower[search_from..].find("seq ") {
        let start = search_from + offset;
        let boundary_ok = start == 0
            || !lower[..start]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric);
        let after = &lower[start + 4..];
        if boundary_ok && after.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
            return Some(format!("seq {digits}"));
        }
        search_from = start + 4;
    }
    None
}

fn contains_word_case_insensitive(text: &str, word: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(offset) = lower[search_from..].find(word) {
        let start = search_from + offset;
        let end = start + word.len();
        let left_ok = start == 0
            || !lower[..start]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric);
        let right_ok = !lower[end..]
            .chars()
            .next()
            .is_some_and(char::is_alphanumeric);
        if left_ok && right_ok {
            return true;
        }
        search_from = end;
    }
    false
}

/// Tokens shaped like `cockpit-spine-v1` — a schema/contract version tag —
/// have no business on an operator surface.
fn schema_version_token(text: &str) -> Option<String> {
    text.split_whitespace()
        .map(|token| token.trim_matches(|c: char| !c.is_ascii_alphanumeric()))
        .find(|token| is_schema_version_token(token))
        .map(str::to_string)
}

fn is_schema_version_token(token: &str) -> bool {
    let Some((prefix, version)) = token.rsplit_once("-v") else {
        return false;
    };
    !prefix.is_empty()
        && !version.is_empty()
        && version.chars().all(|c| c.is_ascii_digit())
        && prefix.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

// ── L2: duplication ─────────────────────────────────────────────────────────

/// Adjacent identical content lines and a segment repeated within one line
/// ("missing · missing") both read as rendering bugs to an operator.
pub(crate) fn lint_duplication(corpus: &[SurfaceLine]) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut previous: Option<(&str, String)> = None;
    for line in corpus {
        let trimmed = line.text.trim().to_string();
        if is_content_bearing(&trimmed) {
            if let Some((source, text)) = &previous {
                if *source == line.source && *text == trimmed {
                    violations.push(Violation {
                        rule: "duplicate-line",
                        source: line.source.clone(),
                        number: line.number,
                        detail: format!("adjacent identical lines: {trimmed}"),
                    });
                }
            }
            previous = Some((&line.source, trimmed.clone()));
        } else {
            previous = None;
        }
        if let Some(segment) = repeated_adjacent_segment(&line.text) {
            violations.push(Violation {
                rule: "duplicate-segment",
                source: line.source.clone(),
                number: line.number,
                detail: format!("segment repeats within the line: `{segment} · {segment}`"),
            });
        }
    }
    violations
}

/// Decorative rows (borders, rules, whitespace) legitimately repeat; only
/// lines with real words participate in the adjacent-duplicate check.
fn is_content_bearing(trimmed: &str) -> bool {
    trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .count()
        >= 8
}

fn repeated_adjacent_segment(text: &str) -> Option<String> {
    for cell in text.split('│') {
        let segments: Vec<&str> = cell.split('·').map(str::trim).collect();
        for pair in segments.windows(2) {
            if pair[0].is_empty() || pair[1].is_empty() {
                continue;
            }
            if pair[0] == pair[1] && pair[0].len() >= 4 {
                return Some(pair[0].to_string());
            }
            // "context:missing · missing. Next: …" — the word astride the
            // separator repeats even though the full segments differ.
            let left = trailing_word(pair[0]);
            if left.len() >= 4 && left == leading_word(pair[1]) {
                return Some(left);
            }
        }
    }
    None
}

/// Only sentence punctuation may sit between the word and the separator;
/// symbol suffixes like the `+↑` in `Ctrl+↑ · Ctrl+↓` make the words
/// distinct copy, not a repeat.
const EDGE_PUNCTUATION: &[char] = &['.', ',', ':', ';', '!', '?', '…', ')'];

fn leading_word(segment: &str) -> String {
    let stripped = segment.trim_start_matches(|c: char| EDGE_PUNCTUATION.contains(&c) || c == '(');
    if !stripped
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return String::new();
    }
    stripped
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect()
}

fn trailing_word(segment: &str) -> String {
    let stripped = segment.trim_end_matches(|c: char| EDGE_PUNCTUATION.contains(&c));
    if !stripped
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return String::new();
    }
    let reversed: String = stripped
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    reversed.chars().rev().collect()
}

// ── L3: separator collisions and truncation artifacts ──────────────────────

pub(crate) fn lint_separators_and_truncation(corpus: &[SurfaceLine]) -> Vec<Violation> {
    let mut violations = Vec::new();
    for line in corpus {
        let mut flag = |rule: &'static str, detail: String| {
            violations.push(Violation {
                rule,
                source: line.source.clone(),
                number: line.number,
                detail,
            });
        };
        if line.text.contains("· ·") || line.text.contains("··") {
            flag(
                "separator-collision",
                format!("`· ·`: {}", line.text.trim()),
            );
        }
        for cell in line.text.split('│') {
            let cell = cell.trim_end();
            if cell.trim().len() < 2 {
                continue;
            }
            // `—` is the UI-wide absent-value placeholder, so only a
            // dangling `·` counts as a clipped separator.
            if cell.ends_with(" ·") {
                flag(
                    "trailing-separator",
                    format!("cell ends on a separator: `{}`", cell.trim()),
                );
            }
            if let Some(token) = trailing_hex_token(cell) {
                flag(
                    "hex-tail",
                    format!("cell ends mid-hex-token `{token}`: {}", cell.trim()),
                );
            }
        }
        if let Some(token) = unbroken_long_token(&line.text) {
            flag(
                "unwrappable-token",
                format!("unbroken {}-char token `{token}`", token.chars().count()),
            );
        }
    }
    violations
}

/// A cell whose last token is a bare hex run reads as a clipped hash — the
/// operator can neither compare nor act on it.
fn trailing_hex_token(cell: &str) -> Option<String> {
    let token = cell.trim().rsplit(|c: char| c.is_whitespace()).next()?;
    let token = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    let is_hex_run = token.len() >= 8
        && token.chars().all(|c| c.is_ascii_hexdigit())
        && token.chars().any(|c| c.is_ascii_digit())
        && token.chars().any(|c| c.is_ascii_alphabetic());
    is_hex_run.then(|| token.to_string())
}

/// Whitespace-delimited tokens 40+ columns wide with no break opportunity
/// wrap ugly on a 68-column terminal. Decorative art (no alphanumerics),
/// slash-broken paths, and `|`-broken usage syntax are excluded.
fn unbroken_long_token(text: &str) -> Option<String> {
    text.split('│')
        .flat_map(str::split_whitespace)
        .filter(|token| token.chars().count() >= 40)
        .find(|token| {
            let has_words = token.chars().any(|c| c.is_ascii_alphanumeric());
            has_words && !token.contains('/') && !token.contains('|')
        })
        .map(str::to_string)
}

// ── L4: decision-card row budget ────────────────────────────────────────────

/// Attention cards the broker can put in front of an operator. A card that
/// dumps more than `CARD_ROW_BUDGET` rows without a disclosure line is a
/// receipt wall, not a decision surface.
const CARD_TITLES: [&str; 5] = [
    "RESULT READY",
    "APPROVAL REQUIRED",
    "WAITING INPUT",
    "PARTIAL RESULT",
    "CREDENTIALS REQUIRED",
];
const CARD_ROW_BUDGET: usize = 10;

pub(crate) fn lint_decision_card_budgets(corpus: &[SurfaceLine]) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut card: Option<(usize, &SurfaceLine, usize, bool)> = None; // (rows, title line, number, disclosed)
    for line in corpus {
        let starts_card = CARD_TITLES.iter().any(|title| line.text.contains(title));
        let blank = line.text.trim().is_empty();
        if let Some((rows, title_line, number, disclosed)) = card.take() {
            let same_source = title_line.source == line.source;
            if same_source && !blank && !starts_card {
                let discloses = disclosed || discloses_more(&line.text);
                card = Some((rows + 1, title_line, number, discloses));
                continue;
            }
            if rows > CARD_ROW_BUDGET && !disclosed {
                violations.push(Violation {
                    rule: "card-row-budget",
                    source: title_line.source.clone(),
                    number,
                    detail: format!(
                        "decision card runs {rows} rows with no disclosure line: {}",
                        title_line.text.trim()
                    ),
                });
            }
        }
        if starts_card {
            card = Some((0, line, line.number, false));
        }
    }
    if let Some((rows, title_line, number, false)) = card {
        if rows > CARD_ROW_BUDGET {
            violations.push(Violation {
                rule: "card-row-budget",
                source: title_line.source.clone(),
                number,
                detail: format!(
                    "decision card runs {rows} rows with no disclosure line: {}",
                    title_line.text.trim()
                ),
            });
        }
    }
    violations
}

fn discloses_more(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains(" more")
        || lower.contains('…')
        || lower.contains("see ")
        || carries_position_counter(text)
}

/// A windowed-list position counter ("1/6 · ↑/↓ move …") discloses the
/// full extent of a list whose renderer windows it under height pressure —
/// the guided-question card's footer is the canonical case.
fn carries_position_counter(text: &str) -> bool {
    let trimmed = text.trim_start_matches(['│', '┃', '|', ' ']);
    let Some((counter, _)) = trimmed.split_once(" · ") else {
        return false;
    };
    let Some((position, total)) = counter.split_once('/') else {
        return false;
    };
    match (position.parse::<usize>(), total.parse::<usize>()) {
        (Ok(position), Ok(total)) => position >= 1 && position <= total && total >= 2,
        _ => false,
    }
}

// ── assertions ──────────────────────────────────────────────────────────────

fn assert_no_violations(violations: Vec<Violation>) {
    if violations.is_empty() {
        return;
    }
    let listing: Vec<String> = violations.iter().map(Violation::to_string).collect();
    panic!(
        "{} rendered-surface lint violation(s):\n  {}",
        listing.len(),
        listing.join("\n  ")
    );
}

#[test]
fn rendered_surfaces_carry_no_internal_jargon() {
    assert_no_violations(lint_jargon(&rendered_surface_corpus()));
}

#[test]
fn decision_cards_stay_within_their_row_budget() {
    assert_no_violations(lint_decision_card_budgets(&rendered_surface_corpus()));
}

#[test]
fn card_budget_matcher_hits_its_shape() {
    let mut corpus: Vec<SurfaceLine> = Vec::new();
    corpus.push(SurfaceLine {
        source: "synthetic".into(),
        number: 1,
        text: "▸ RESULT READY · map failed".into(),
    });
    for number in 2..=13 {
        corpus.push(SurfaceLine {
            source: "synthetic".into(),
            number,
            text: format!("receipt row {number}"),
        });
    }
    assert_eq!(
        lint_decision_card_budgets(&corpus).len(),
        1,
        "12 rows, no disclosure"
    );

    corpus[12].text = "… 9 more rows · logs to inspect".into();
    assert!(
        lint_decision_card_budgets(&corpus).is_empty(),
        "a disclosure line absolves the budget"
    );

    corpus[12].text = "│1/6 · ↑/↓ move · Enter choose · Esc dismiss".into();
    assert!(
        lint_decision_card_budgets(&corpus).is_empty(),
        "a windowed-list position counter is a disclosure"
    );

    assert!(!carries_position_counter("│6 · Discard"));
    assert!(!carries_position_counter("1/1 · only item"));
    assert!(!carries_position_counter("apps/api · route table"));
}

#[test]
fn rendered_surfaces_carry_no_duplicated_copy() {
    assert_no_violations(lint_duplication(&rendered_surface_corpus()));
}

#[test]
fn rendered_surfaces_carry_no_separator_or_truncation_artifacts() {
    assert_no_violations(lint_separators_and_truncation(&rendered_surface_corpus()));
}

#[test]
fn duplication_and_truncation_matchers_hit_their_shapes() {
    assert_eq!(
        repeated_adjacent_segment("context:missing · missing. Next: build"),
        Some("missing".to_string()),
        "the word astride the separator repeats"
    );
    assert_eq!(
        repeated_adjacent_segment("state missing · missing"),
        Some("missing".to_string())
    );
    assert_eq!(
        repeated_adjacent_segment("z chain / DFD · report open Report"),
        None,
        "case-differing edge words are distinct copy"
    );
    assert_eq!(
        repeated_adjacent_segment("raise Ctrl+↑ · Ctrl+↓ lower"),
        None,
        "chord modifiers make the words distinct"
    );
    assert!(trailing_hex_token("finding 4f9a2c81b0").is_some());
    assert!(trailing_hex_token("finding F-0001").is_none());
    assert_eq!(
        unbroken_long_token("run ────────────────────────────────────────────── done"),
        None,
        "repeated-char rules are decorative"
    );
    assert!(unbroken_long_token(
        "id kzfinding4f9a2c81b0e77d3aa91c4f2b8d6e5a0c1b2d3e4f5a6b7c8d9e0f1a2b"
    )
    .is_some());
}

#[test]
fn jargon_matchers_hit_their_shapes() {
    assert!(is_uuid("0198c6a2-1f2b-4c3d-8e9f-a0b1c2d3e4f5"));
    assert!(!is_uuid("not-a-uuid"));
    assert_eq!(seq_counter("watcher seq 423 ready"), Some("seq 423".into()));
    assert_eq!(seq_counter("sequence of steps"), None);
    assert!(contains_word_case_insensitive(
        "state Projection ready",
        "projection"
    ));
    assert!(!contains_word_case_insensitive("projections", "projection"));
    assert!(is_schema_version_token("cockpit-spine-v1"));
    assert!(!is_schema_version_token("TLSv1"));
}
