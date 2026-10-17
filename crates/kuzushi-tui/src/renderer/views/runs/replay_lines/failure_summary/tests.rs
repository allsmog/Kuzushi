use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::run_lifecycle::*;

const RUN: &str = "owned-failure-summary";
const ISSUE: &str = "Remove the unused setting. No model request started.";

fn fixture() -> (tempfile::TempDir, ShellApp) {
    fixture_with_data(serde_json::json!({}))
}

fn fixture_with_data(data: serde_json::Value) -> (tempfile::TempDir, ShellApp) {
    let target = tempfile::tempdir().unwrap();
    let summary = kuzushi_core::RunSummary::running(RUN, "agentic-sast:scan", None, "owned")
        .failed(ISSUE)
        .with_artifact(kuzushi_core::run_artifacts::RunArtifact {
            label: "tool result".into(),
            path: "result.json".into(),
            kind: "json".into(),
        });
    kuzushi_core::write_run_summary(target.path(), &summary).unwrap();
    let output = serde_json::json!({"tool":"agentic-sast:scan","status":"failed","summary":"agentic-sast:scan failed","output":ISSUE,"errors":[ISSUE],"data":data});
    std::fs::write(
        kuzushi_core::run_dir(target.path(), RUN).join("result.json"),
        serde_json::to_vec(&output).unwrap(),
    )
    .unwrap();
    let observation = RunObservationHandle::jsonl(target.path(), RUN).unwrap();
    let call = kuzushi_core::modules::ApplicationToolCall::start(
        observation.clone(),
        "agentic-sast:scan",
        &serde_json::json!({}),
        None,
        None,
    )
    .unwrap();
    let pending = call.completion_from_result(&Ok(output.clone()));
    let identity = pending.identity().unwrap();
    let reference =
        verified_result_artifact_reference(target.path(), RUN, identity.item_id).unwrap();
    pending.finish(Some(reference)).unwrap();
    emit_persisted_terminal_outcome_for_call(
        &observation,
        target.path(),
        RUN,
        &output,
        Some(identity),
    )
    .unwrap();
    observation.flush().unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(target.path().to_owned()));
    app.open_replay_for_test(RUN);
    for _ in 0..3 {
        app.hydrate_active_view_blocking();
    }
    assert!(crate::ui_view_models::replay_has_summary(&app));
    (target, app)
}

fn press(app: &mut ShellApp, key: KeyCode, modifiers: KeyModifiers) {
    assert!(app.reduce_key(KeyEvent::new(key, modifiers)).handled);
}

fn document(app: &ShellApp, width: u16) -> String {
    replay_lines(app, Rect::new(0, 0, width, 36), RUN)
        .iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn failure_opens_on_saved_result_and_the_complete_receipt_is_explicitly_reachable() {
    let (_target, mut app) = fixture();
    let model = replay_model(&app, RUN);
    let summary = document(&app, 120);
    assert!(summary.contains("REPLAY · Result") && summary.contains(ISSUE));
    assert!(summary.contains("SAVED OUTPUT"));
    assert_eq!(summary.matches(ISSUE).count(), 1);
    assert!(!summary.contains("sha256:") && !summary.contains("TIMELINE"));
    assert!(crate::ui_view_models::footer_keybindings(&app)
        .iter()
        .any(|b| b.key == "Tab" && b.label == "full receipt"));
    press(&mut app, KeyCode::Tab, KeyModifiers::NONE);
    let full = document(&app, 120);
    assert!(full.contains("REPLAY · Full receipt") && full.contains("sha256:"));
    assert!(full.contains("RUN DETAILS") && full.contains("TIMELINE"));
    assert_eq!(replay_model(&app, RUN), model);
}

#[test]
fn retained_failure_inputs_have_consistent_visible_controls_at_every_size() {
    let (_root, mut app) = fixture_with_data(serde_json::json!({"inputDocument":{
        "schemaVersion":1,"text":"Owned prepared source; provider delivery unknown."}}));
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let text = document(&app, width);
        assert!(text.contains("REPLAY · Result · Tab inputs"), "{text}");
        press(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        let input = document(&app, width)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            input.contains("REPLAY · Inputs") && input.contains("provider delivery unknown"),
            "{input}"
        );
        press(&mut app, KeyCode::BackTab, KeyModifiers::SHIFT);
        assert!(!app.has_running_work());
    }
}

#[test]
fn tab_and_backtab_restore_each_readers_scroll_and_keep_the_navigation_origin() {
    let (_target, mut app) = fixture();
    let origin = app.router.overlay_origin();
    app.router.default_scroll_mut().set(3);
    press(&mut app, KeyCode::Tab, KeyModifiers::NONE);
    assert_eq!(app.router.default_scroll().offset(), 0);
    app.router.default_scroll_mut().set(11);
    press(&mut app, KeyCode::BackTab, KeyModifiers::SHIFT);
    assert!(!app.router.replay().full_receipt());
    assert_eq!(app.router.default_scroll().offset(), 3);
    press(&mut app, KeyCode::Tab, KeyModifiers::NONE);
    assert_eq!(app.router.default_scroll().offset(), 11);
    assert_eq!(app.router.overlay_origin(), origin);
}

#[test]
fn prompt_drafts_keep_tab_while_navigation_can_switch_without_editing_them() {
    let (_target, mut app) = fixture();
    app.set_input_mode(crate::InputMode::Prompt);
    app.set_input("preserved\n無関係 draft");
    let cursor = app.cursor();
    press(&mut app, KeyCode::Tab, KeyModifiers::NONE);
    assert!(!app.router.replay().full_receipt());
    assert_eq!(app.input(), "preserved\n無関係 draft");
    assert!(!crate::ui_view_models::footer_keybindings(&app)
        .iter()
        .any(|b| b.label == "full receipt"));
    app.set_input_mode(crate::InputMode::Navigate);
    press(&mut app, KeyCode::Tab, KeyModifiers::NONE);
    assert!(app.router.replay().full_receipt());
    assert_eq!(app.input(), "preserved\n無関係 draft");
    assert_eq!(app.cursor(), cursor);
}

#[test]
fn plain_replay_remains_exhaustive_independent_of_the_interactive_page_or_scroll() {
    let (_target, mut app) = fixture();
    let before = crate::renderer::render_plain_app(&app, 120);
    assert!(before.contains("sha256:") && before.contains("TIMELINE"));
    press(&mut app, KeyCode::Tab, KeyModifiers::NONE);
    app.router.default_scroll_mut().set(12);
    assert_eq!(crate::renderer::render_plain_app(&app, 120), before);
}

#[test]
fn both_reading_pages_fit_all_supported_widths_and_keep_the_complete_recovery() {
    let (_target, mut app) = fixture();
    for full in [false, true] {
        if full {
            press(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        }
        for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
            app.set_viewport(crate::app::TerminalViewport::new(width, height));
            let rows = replay_lines(&app, Rect::new(0, 0, width, height), RUN);
            assert!(rows.iter().all(|row| row.width() <= width as usize));
            let heading_index = rows
                .iter()
                .position(|row| row.to_string().contains("REPLAY"))
                .unwrap();
            assert!(
                rows[heading_index + 1].to_string().contains("Outcome ·"),
                "Heading wrapped at {width}"
            );
            let heading = rows
                .iter()
                .find(|row| row.to_string().contains("REPLAY"))
                .unwrap()
                .to_string();
            assert!(
                heading.contains(if full { "Tab result" } else { "Tab receipt" }),
                "{width}: {heading}"
            );
            let text = rows.iter().map(|row| row.to_string()).collect::<String>();
            let compact = text.split_whitespace().collect::<String>();
            assert!(compact.contains(&ISSUE.split_whitespace().collect::<String>()));
        }
    }
}
