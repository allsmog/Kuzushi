use super::*;
use crate::{InputMode, ShellView};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::run_artifacts::{
    record_tool_run_started, try_record_tool_run_complete_settled, ToolRunRecord, TraceHandle,
};
use kuzushi_core::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use ratatui::{backend::TestBackend, Terminal};
use serde_json::{json, Value};

const RUN: &str = "owned-catalog-reader";
const LAST: &str = "OwnedMarker19";
mod first_value;
mod input_tests;
mod request_context;

fn dispatch(workspace: &WorkspaceTarget, run: &str, tool: &str, input: Value) -> Value {
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let trace = TraceHandle::jsonl(workspace.root(), run);
    let record = ToolRunRecord::new(workspace.root(), run, "tool", tool);
    record_tool_run_started(record, &input);
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: None,
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(tool, input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let observation = ctx.run_observation().unwrap();
    let dispatched = registry
        .dispatch_prepared_input_observed_with_runtime(prepared, &ctx, None)
        .unwrap();
    let result = dispatched.execution.unwrap();
    try_record_tool_run_complete_settled(record, &result, &observation, dispatched.completion)
        .unwrap();
    result
}

fn owned_reader() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let path = root.path().join("owned-sinks.jsonl");
    let rows = (0..20)
        .map(|index| {
            json!({"callee":format!("OwnedMarker{index:02}"),"cwe":format!("CWE-{}",100+index)})
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, rows).unwrap();
    dispatch(
        &workspace,
        "owned-import",
        "taint-iris-next:import-sinks",
        json!({"sinksPath":path}),
    );
    let result = dispatch(&workspace, RUN, "taint-iris-next:catalog-read", json!({}));
    assert!(result["output"].as_str().unwrap().contains(LAST));
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.set_shell_view(ShellView::Report);
    app.open_replay_for_test(RUN);
    for _ in 0..3 {
        app.hydrate_active_view_blocking();
    }
    let model = crate::ui_view_models::replay_model(&app, RUN);
    assert!(crate::ui_view_models::replay_document_available(&model));
    assert!(
        model
            .document
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .output
            .len()
            > 12
    );
    (root, app)
}

fn press(app: &mut ShellApp, code: KeyCode) {
    assert!(
        app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
            .handled,
        "unhandled reader key: {code:?}"
    );
}

fn frame_text(app: &ShellApp, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn real_prepared_catalog_output_beyond_twelve_lines_is_keyboard_readable_at_every_size() {
    let (_root, mut app) = owned_reader();
    app.set_input_mode(InputMode::Navigate);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        press(&mut app, KeyCode::Home);
        let first = frame_text(&app, width, height);
        assert!(
            first.contains("Outcome · completed"),
            "{width}x{height}: {first}"
        );
        press(&mut app, KeyCode::End);
        let mut found = frame_text(&app, width, height).contains(LAST);
        for _ in 0..3 {
            press(&mut app, KeyCode::PageUp);
            found |= frame_text(&app, width, height).contains(LAST);
        }
        assert!(
            found,
            "{width}x{height}: last saved entry must be reachable"
        );
    }
}

#[test]
fn receipt_switch_preserves_both_scrolls_and_held_input_and_back_restores_origin() {
    let (_root, mut app) = owned_reader();
    app.set_input_mode(InputMode::Navigate);
    app.set_input("held\noperator café");
    let cursor = app.cursor();
    app.router.default_scroll_mut().set(9);
    press(&mut app, KeyCode::Tab);
    assert!(app.router.replay().full_receipt());
    assert_eq!(app.router.default_scroll().offset(), 0);
    app.router.default_scroll_mut().set(3);
    press(&mut app, KeyCode::BackTab);
    assert!(!app.router.replay().full_receipt());
    assert_eq!(app.router.default_scroll().offset(), 9);
    assert_eq!(app.input(), "held\noperator café");
    assert_eq!(app.cursor(), cursor);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.input(), "held\noperator café");
}

#[test]
fn prompt_mode_tab_cannot_switch_the_receipt_or_start_work() {
    let (_root, mut app) = owned_reader();
    app.set_input_mode(InputMode::Prompt);
    app.set_input("owned retained draft");
    let input = app.input().to_string();
    app.reduce_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert!(!app.router.replay().full_receipt());
    assert_eq!(app.input(), input);
    app.router.default_scroll_mut().set(4);
    press(&mut app, KeyCode::Home);
    assert_eq!(app.cursor(), 0);
    assert_eq!(app.router.default_scroll().offset(), 4);
    press(&mut app, KeyCode::End);
    assert_eq!(app.cursor(), input.len());
    assert_eq!(app.router.default_scroll().offset(), 4);
    assert!(!app.has_running_work());
}

#[test]
fn saved_output_keeps_blank_lines_and_text_equal_to_the_summary() {
    use kuzushi_core::run_lifecycle::{RunItemStatus, SafeText};
    let document = RunResultDocument {
        status: RunItemStatus::Completed,
        summary: SafeText::document_lines("Owned title"),
        output: SafeText::document_lines("Owned title\n\n  owned source"),
        warnings: Vec::new(),
        errors: Vec::new(),
        supplied_input: None,
    };
    let mut output = Vec::new();
    append_output(&mut output, &document, 120);
    let text = output
        .iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(text.matches("Owned title").count(), 2);
    assert!(text.contains("Owned title\n\n  owned source"));
}

#[test]
fn repeated_render_models_share_one_authenticated_document() {
    let (_root, app) = owned_reader();
    let first = crate::ui_view_models::replay_model(&app, RUN)
        .document
        .unwrap()
        .unwrap();
    let second = crate::ui_view_models::replay_model(&app, RUN)
        .document
        .unwrap()
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(&first, &second));
}

#[test]
fn replay_heading_and_position_survive_tail_reading_resize_and_receipt_switch() {
    let (_root, mut app) = owned_reader();
    app.set_input_mode(InputMode::Navigate);
    app.set_input("held café\ndraft");
    let cursor = app.cursor();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        for full in [false, true] {
            press(&mut app, KeyCode::End);
            let text = frame_text(&app, width, height);
            let heading = &text[..text
                .char_indices()
                .nth(width as usize)
                .map_or(text.len(), |(i, _)| i)];
            assert!(heading.contains("REPLAY"), "{width}x{height}: {text}");
            assert!(
                heading
                    .to_lowercase()
                    .contains(if full { "receipt" } else { "result" }),
                "{heading}"
            );
            if app.router.default_scroll().offset() > 0 {
                assert!(text.contains("rows "), "{width}x{height}: {text}");
            }
            if width <= 60 {
                assert!(text.contains("PgUp/Dn read"), "{text}");
            }
            assert_eq!(app.input(), "held café\ndraft");
            assert_eq!(app.cursor(), cursor);
            assert!(!app.has_running_work());
            press(&mut app, KeyCode::Tab);
        }
    }
}

#[test]
fn exact_saved_warning_is_displayed_once_and_distinct_recorded_issue_is_retained() {
    use kuzushi_core::run_lifecycle::{RunItemStatus, SafeText};
    let (_root, app) = owned_reader();
    let document = RunResultDocument {
        status: RunItemStatus::Partial,
        summary: SafeText::document_lines("Owned partial draft"),
        output: SafeText::document_lines("Owned source prefix"),
        warnings: SafeText::document_lines("Owned partial input requires acknowledgement"),
        errors: Vec::new(),
        supplied_input: None,
    };
    let original = document.clone();
    for message in [
        "Owned partial input requires acknowledgement",
        "Owned source revision changed",
    ] {
        let mut model = crate::ui_view_models::replay_model(&app, RUN);
        model.issue = Some(crate::ui_view_models::ReplayIssueModel {
            source_key: None,
            label: "Recorded warning",
            message: message.into(),
            tool: None,
        });
        let text = lines(&app, Rect::new(0, 0, 120, 36), &model, &document)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            text.matches("Owned partial input requires acknowledgement")
                .count(),
            1
        );
        assert!(text.contains(message), "{text}");
        assert_eq!(model.issue.as_ref().unwrap().message, message);
        assert_eq!(document, original);
    }
}

#[test]
fn plain_replay_retains_context_first_complete_receipt_independent_of_reader_position() {
    let (_root, mut app) = owned_reader();
    app.set_input_mode(InputMode::Navigate);
    for width in [40, 60, 80, 96, 120, 160] {
        let before = crate::renderer::render_plain_app(&app, width);
        assert!(before.find("KUZUSHI").unwrap() < before.find("REPLAY").unwrap());
        assert!(before.contains("RUN DETAILS") && before.contains("TIMELINE"));
        assert!(!before.contains("rows "));
        app.router.default_scroll_mut().tail();
        press(&mut app, KeyCode::Tab);
        assert_eq!(crate::renderer::render_plain_app(&app, width), before);
        press(&mut app, KeyCode::Tab);
    }
}

#[test]
fn selected_result_read_failure_is_explicit_and_recovered_by_rereading_without_work() {
    let (root, mut app) = owned_reader();
    let projection = kuzushi_core::run_lifecycle::load_run_projection(root.path(), RUN)
        .unwrap()
        .projection;
    let (producer, _, reference) =
        kuzushi_core::run_artifacts::single_result_artifact(&projection).unwrap();
    let path = kuzushi_core::run_dir(root.path(), RUN).join(reference.path.as_str());
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        kuzushi_core::run_artifacts::load_correlated_result_document(
            root.path(),
            RUN,
            producer,
            "owned-wrong-digest"
        )
        .is_err()
    );
    std::fs::remove_file(&path).unwrap();
    app.workbench_cache()
        .borrow_mut()
        .invalidate_one_run_cache(root.path(), RUN);
    for _ in 0..3 {
        app.hydrate_active_view_blocking();
    }
    let failed = crate::ui_view_models::replay_model(&app, RUN);
    assert!(failed.document.as_ref().unwrap().is_err());
    assert!(!crate::ui_view_models::replay_document_available(&failed));
    std::fs::write(&path, bytes).unwrap();
    app.workbench_cache()
        .borrow_mut()
        .invalidate_one_run_cache(root.path(), RUN);
    for _ in 0..3 {
        app.hydrate_active_view_blocking();
    }
    let recovered = crate::ui_view_models::replay_model(&app, RUN);
    assert!(recovered.document.as_ref().unwrap().is_ok());
    assert!(crate::ui_view_models::replay_document_available(&recovered));
    assert!(!app.has_running_work());
}

#[test]
fn an_unreported_second_tool_call_keeps_the_full_receipt_but_internal_models_do_not() {
    let (root, _app) = owned_reader();
    let mut projection = kuzushi_core::run_lifecycle::load_run_projection(root.path(), RUN)
        .unwrap()
        .projection;
    let mut extra = projection.calls.values().next().unwrap().clone();
    extra.item_id = kuzushi_core::run_lifecycle::RunItemId::new();
    extra.result_artifact = None;
    let id = kuzushi_core::run_lifecycle::RunCallId::new();
    projection.calls.insert(id, extra);
    assert!(kuzushi_core::run_artifacts::single_result_artifact(&projection).is_none());
    projection.calls.get_mut(&id).unwrap().kind = kuzushi_core::run_lifecycle::CallKind::Model;
    assert!(kuzushi_core::run_artifacts::single_result_artifact(&projection).is_some());
}
