//! Plain-renderer parity sweep: the non-TTY projection of every
//! `ShellView` must hold the same promises the guardrails make for
//! scripted output — it speaks (real content or an explicit sentinel,
//! never silence), it stays inside the requested width, and it depends on
//! neither ANSI control sequences nor box-drawing glyph support.
//!
//! The surface lints (`surface_lints.rs`) judge the *copy* on these
//! surfaces; this module judges the *contract* of the plain channel
//! itself, across every view and at the widths scripted operators
//! actually run (a 40-column CI log is as real as a 120-column pipe).

use super::render_plain_app;
use crate::app::{ShellApp, ShellView};
use kuzushi_core::workflow_attempts::{
    append_phase_attempt_completed, PhaseAttemptCompleted, PhaseAttemptOutcome, PhaseTargetSnapshot,
};
use kuzushi_core::{Finding, Severity, V2Config, WorkflowPhase, WorkspaceTarget};
use strum::IntoEnumIterator;

/// Narrowest supported plain width, a typical CI log, and the lint width
/// the copy corpus uses.
const SWEEP_WIDTHS: [usize; 3] = [40, 68, 120];

/// Views whose plain projection is currently silent (no content-bearing
/// line) for the named app state. Growing this list is a parity
/// regression; a view that starts speaking must be struck so it can never
/// go silent again.
const KNOWN_SILENT: &[(&str, &str)] = &[];

/// Keeps the target-backed state's tempdir alive for the app's lifetime.
struct SweepState {
    name: &'static str,
    app: ShellApp,
    _target: Option<tempfile::TempDir>,
}

fn sweep_apps() -> Vec<SweepState> {
    let bare = ShellApp::new(V2Config::default(), None);
    let mut seeded = ShellApp::new(V2Config::default(), None);
    *seeded.findings_mut() = vec![Finding::new_semgrep(
        "demo.sqli",
        "apps/api/orders.rs",
        12,
        Some(14),
        Severity::High,
        "sql injection via order_id",
    )];
    seeded.set_error_notice("tool", "semgrep:scan failed — scanner exited 2");
    let (engaged, target) = engaged_failed_map_app();
    vec![
        SweepState {
            name: "bare",
            app: bare,
            _target: None,
        },
        SweepState {
            name: "seeded",
            app: seeded,
            _target: None,
        },
        SweepState {
            name: "engaged-failed-map",
            app: engaged,
            _target: Some(target),
        },
    ]
}

/// A target-backed engagement with an unresolved FAILED Map attempt — the
/// RESULT strip, journey chrome, and phase pages all project through plain
/// output here, which is where parity actually gets stressed.
fn engaged_failed_map_app() -> (ShellApp, tempfile::TempDir) {
    let target = tempfile::tempdir().expect("plain parity target");
    let completed = PhaseAttemptCompleted::new(
        WorkflowPhase::Map,
        vec!["run-plain-parity".to_string()],
        PhaseTargetSnapshot::capture(target.path()),
        PhaseAttemptOutcome::Failed,
    );
    append_phase_attempt_completed(target.path(), completed).expect("persist failed attempt");
    let workspace = WorkspaceTarget::new(target.path()).expect("plain parity workspace");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.refresh_phase_attempt_projection();
    (app, target)
}

fn is_content_bearing(line: &str) -> bool {
    line.chars().filter(|c| c.is_ascii_alphanumeric()).count() >= 3
}

#[test]
fn every_shell_view_speaks_in_plain_output() {
    let mut silent = Vec::new();
    for mut state in sweep_apps() {
        for view in ShellView::iter() {
            state.app.set_shell_view(view);
            let rendered = render_plain_app(&state.app, 120);
            if !rendered.lines().any(is_content_bearing) {
                silent.push((state.name, format!("{view:?}")));
            }
        }
    }
    let regressions: Vec<_> = silent
        .iter()
        .filter(|(state, view)| {
            !KNOWN_SILENT
                .iter()
                .any(|(known_state, known_view)| known_state == state && known_view == view)
        })
        .collect();
    assert!(
        regressions.is_empty(),
        "views went SILENT in plain output (scripted operators get nothing): \
         {regressions:?} — plain must project content or an explicit sentinel"
    );
    let newly_speaking: Vec<_> = KNOWN_SILENT
        .iter()
        .filter(|(known_state, known_view)| {
            !silent
                .iter()
                .any(|(state, view)| state == known_state && view == known_view)
        })
        .collect();
    assert!(
        newly_speaking.is_empty(),
        "views gained plain output: {newly_speaking:?} — remove them from \
         KNOWN_SILENT so the coverage can never silently regress"
    );
}

/// The mode-parity guardrail: no hidden interaction-only state. An
/// unresolved failed attempt is a pending operator decision; a scripted
/// shell reading plain Workbench output must see it, not discover it later
/// in the interactive TUI.
#[test]
fn plain_workbench_discloses_the_unresolved_failed_attempt() {
    let (mut app, _target) = engaged_failed_map_app();
    app.set_shell_view(ShellView::Workbench);
    let rendered = render_plain_app(&app, 120);
    let lower = rendered.to_ascii_lowercase();
    assert!(
        lower.contains("result") && lower.contains("failed"),
        "plain Workbench hides the unresolved FAILED attempt — scripted \
         operators cannot see the pending decision:\n{rendered}"
    );
}

#[test]
fn plain_output_respects_the_requested_width_on_every_view() {
    for mut state in sweep_apps() {
        let name = state.name;
        for view in ShellView::iter() {
            state.app.set_shell_view(view);
            for width in SWEEP_WIDTHS {
                let rendered = render_plain_app(&state.app, width);
                for (number, line) in rendered.lines().enumerate() {
                    let columns = line.chars().count();
                    assert!(
                        columns <= width,
                        "{name}/{view:?} width {width}: line {} runs {columns} \
                         columns: {line:?}",
                        number + 1
                    );
                }
            }
        }
    }
}

#[test]
fn plain_output_carries_no_control_sequences_or_box_drawing() {
    for mut state in sweep_apps() {
        let name = state.name;
        for view in ShellView::iter() {
            state.app.set_shell_view(view);
            let rendered = render_plain_app(&state.app, 120);
            for (number, line) in rendered.lines().enumerate() {
                assert!(
                    !line.chars().any(char::is_control),
                    "{name}/{view:?}: control character on line {}: {line:?}",
                    number + 1
                );
                let box_drawing: Vec<char> = line
                    .chars()
                    .filter(|c| ('\u{2500}'..='\u{257f}').contains(c))
                    .collect();
                assert!(
                    box_drawing.is_empty(),
                    "{name}/{view:?}: plain output depends on box-drawing \
                     glyphs {box_drawing:?} on line {}: {line:?}",
                    number + 1
                );
            }
        }
    }
}
