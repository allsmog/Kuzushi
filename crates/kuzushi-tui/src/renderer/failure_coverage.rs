#![cfg(test)]

//! Failure-state coverage matrix: every operator-facing failure/attention
//! state the shell can project must appear in at least one machine-checked
//! fixture — a journey `expect:`/`wait-for:` line or a phase-cockpit
//! snapshot body. Error states are exactly where operators are most
//! stressed and where raw internals leak, so the states with zero fixture
//! coverage are the ones today's bugs hide in.
//!
//! The matrix is honest about gaps: `KNOWN_GAPS` names every state that is
//! currently uncovered, and the test fails in both directions — a state
//! that loses coverage must be re-covered, and a state that gains coverage
//! must be struck from the gap list so it can never silently regress.

use super::surface_lints::snapshot_fixture_lines;
use std::fs;
use std::path::Path;

/// One operator-facing failure/attention state and the literal rendered
/// strings that prove it appeared on screen. Any one signature counts.
struct FailureState {
    name: &'static str,
    signatures: &'static [&'static str],
}

/// Sources: attention-card titles in `app/attention.rs`, RESULT READY
/// prompts in `app/guided_scan/presentation_copy.rs::phase_result_prompt`,
/// ledger-degradation copy in `app/shellapp.rs` / `app/phase_results.rs`,
/// blocked-selection copy in `runtime_event_drains.rs`, and the
/// partial-acknowledgement copy in `ui_view_models/journey.rs` /
/// `phase_cockpit/scan.rs`.
const FAILURE_STATES: &[FailureState] = &[
    FailureState {
        name: "approval-gate-card",
        signatures: &["APPROVAL REQUIRED"],
    },
    FailureState {
        name: "operator-question-card",
        signatures: &["WAITING INPUT"],
    },
    FailureState {
        name: "credential-gate-card",
        signatures: &["CREDENTIALS REQUIRED"],
    },
    FailureState {
        name: "partial-result-attention",
        signatures: &["PARTIAL RESULT", "1 PARTIAL"],
    },
    FailureState {
        name: "result-ready-card",
        signatures: &["RESULT READY"],
    },
    FailureState {
        name: "result-failed-prompt",
        signatures: &["failed. Open the run or try again"],
    },
    FailureState {
        name: "result-canceled-prompt",
        signatures: &["was canceled. Open the run or try again"],
    },
    FailureState {
        name: "result-partial-prompt",
        signatures: &["returned partial evidence"],
    },
    FailureState {
        name: "partial-acknowledgement",
        signatures: &["acknowledge the partial", "partial acknowledged"],
    },
    FailureState {
        name: "degraded-ledger",
        signatures: &["ledger is degraded", "ledger is unreadable"],
    },
    FailureState {
        name: "blocked-selection",
        signatures: &[
            "selection blocked",
            "live run settlement is not healthy",
            "advancement is blocked",
        ],
    },
];

/// States with no machine-checked fixture yet. Growing this list is a
/// regression. The three remaining entries share one obstacle: their
/// uppercase card titles live only in the terminal *window title*
/// (`terminal_title.rs`) — the in-frame approval surface says "CONFIRM /
/// allow once", the credential editor has its own Setup copy, and the
/// operator-question card needs a live agent interaction to render.
/// Covering them means either fixturing those surfaces directly or
/// extending the signature lists to their real in-frame copy.
const KNOWN_GAPS: &[&str] = &[
    "approval-gate-card",
    "operator-question-card",
    "credential-gate-card",
];

/// A line of fixture text plus how it should be matched. Journey checks
/// run case-insensitively (mirroring the harness `d_expect`); snapshot
/// bodies are literal rendered screens and match case-sensitively, so
/// incidental lowercase copy (e.g. a "human approval required" guardrail
/// note) cannot stand in for the uppercase APPROVAL card.
struct FixtureLine {
    source: String,
    text: String,
    case_insensitive: bool,
}

impl FixtureLine {
    fn contains(&self, signature: &str) -> bool {
        if self.case_insensitive {
            self.text
                .to_ascii_lowercase()
                .contains(&signature.to_ascii_lowercase())
        } else {
            self.text.contains(signature)
        }
    }
}

fn machine_checked_fixture_lines() -> Vec<FixtureLine> {
    let mut lines = journey_check_lines();
    lines.extend(
        snapshot_fixture_lines()
            .into_iter()
            .map(|line| FixtureLine {
                source: format!("{}:{}", line.source, line.number),
                text: line.text,
                case_insensitive: false,
            }),
    );
    lines
}

/// The machine-enforced payloads of every journey: `expect:` substrings
/// and `wait-for:` needles (after the leading timeout). `ask:` lines are
/// human review, `expect-not:` asserts absence — neither demonstrates that
/// a state rendered, so both are excluded.
fn journey_check_lines() -> Vec<FixtureLine> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/devex/journeys");
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("journeys dir {}: {error}", dir.display()))
        .map(|entry| entry.expect("journey dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "journey"))
        .collect();
    entries.sort();
    let mut lines = Vec::new();
    for path in entries {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("journey")
            .to_string();
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        for (index, line) in content.lines().enumerate() {
            let Some(payload) = journey_check_payload(line) else {
                continue;
            };
            lines.push(FixtureLine {
                source: format!("{name}:{}", index + 1),
                text: payload,
                case_insensitive: true,
            });
        }
    }
    lines
}

fn journey_check_payload(line: &str) -> Option<String> {
    if let Some(needle) = line.strip_prefix("expect:") {
        return Some(needle.trim().to_string());
    }
    let waited = line.strip_prefix("wait-for:")?.trim();
    // `wait-for: <timeout-seconds> <needle>` — the needle is what must
    // actually appear on screen.
    let needle = match waited.split_once(char::is_whitespace) {
        Some((timeout, rest)) if timeout.parse::<u64>().is_ok() => rest.trim(),
        _ => waited,
    };
    Some(needle.to_string())
}

fn uncovered_states(fixtures: &[FixtureLine]) -> Vec<&'static str> {
    FAILURE_STATES
        .iter()
        .filter(|state| covering_fixture(state, fixtures).is_none())
        .map(|state| state.name)
        .collect()
}

fn covering_fixture<'a>(state: &FailureState, fixtures: &'a [FixtureLine]) -> Option<&'a str> {
    fixtures
        .iter()
        .find(|line| {
            state
                .signatures
                .iter()
                .any(|signature| line.contains(signature))
        })
        .map(|line| line.source.as_str())
}

#[test]
fn every_failure_state_is_covered_or_a_tracked_gap() {
    let fixtures = machine_checked_fixture_lines();
    let gaps = uncovered_states(&fixtures);

    let regressions: Vec<_> = gaps
        .iter()
        .filter(|name| !KNOWN_GAPS.contains(name))
        .collect();
    assert!(
        regressions.is_empty(),
        "failure states LOST machine-checked coverage: {regressions:?} — \
         restore the journey expect/wait-for line or snapshot fixture that \
         demonstrated them"
    );

    let newly_covered: Vec<String> = KNOWN_GAPS
        .iter()
        .filter(|name| !gaps.contains(name))
        .map(|name| {
            let state = FAILURE_STATES
                .iter()
                .find(|state| state.name == *name)
                .expect("gap list names validated against FAILURE_STATES");
            let source = covering_fixture(state, &fixtures).unwrap_or("unknown");
            format!("{name} (covered by {source})")
        })
        .collect();
    assert!(
        newly_covered.is_empty(),
        "failure states gained coverage: {newly_covered:?} — remove them \
         from KNOWN_GAPS so the coverage can never silently regress"
    );
}

#[test]
fn matrix_matcher_recognizes_every_signature() {
    let synthetic: Vec<FixtureLine> = FAILURE_STATES
        .iter()
        .map(|state| FixtureLine {
            source: format!("synthetic:{}", state.name),
            text: format!("… {} …", state.signatures[0]),
            case_insensitive: false,
        })
        .collect();
    assert_eq!(
        uncovered_states(&synthetic),
        Vec::<&str>::new(),
        "a state's own first signature failed to satisfy it"
    );
}

#[test]
fn failure_state_names_are_unique_and_gap_list_names_real_states() {
    let mut names: Vec<_> = FAILURE_STATES.iter().map(|state| state.name).collect();
    names.sort_unstable();
    let mut deduped = names.clone();
    deduped.dedup();
    assert_eq!(names, deduped, "duplicate failure-state name");
    for gap in KNOWN_GAPS {
        assert!(
            FAILURE_STATES.iter().any(|state| state.name == *gap),
            "KNOWN_GAPS names an unknown state: {gap}"
        );
    }
}

#[test]
fn journey_corpus_parses_machine_checked_payloads() {
    let lines = journey_check_lines();
    assert!(
        lines.len() > 40,
        "journey check corpus suspiciously small ({} lines) — path or \
         parsing broke",
        lines.len()
    );
    assert!(
        lines
            .iter()
            .any(|line| line.text.contains("CHOOSE A TARGET")),
        "wait-for payloads must survive timeout stripping"
    );
    assert!(
        lines.iter().any(|line| line.text == "canceled"),
        "expect payloads must be captured verbatim"
    );
}
