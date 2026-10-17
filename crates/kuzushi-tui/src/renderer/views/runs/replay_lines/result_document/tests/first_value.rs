use super::*;

fn partial_reader() -> (tempfile::TempDir, ShellApp) {
    partial_result_reader(
        json!({"ok":true,"status":"partial","summary":"Owned context drafts: 1; partial source context",
        "output":"Owned context drafts: 1; partial source context\nUnverified safety assumptions. Review before accepting context.\nowned-assumption: inspect this candidate\n  Source: owned.c:1\n  Evidence: owned_input\nComplete repository coverage is not established.",
        "costUsd":null,"observedCostUsd":0.0,"costUsdExact":false,"providerSpendUnresolved":true,
        "warnings":["Owned source inspection is partial"],"data":{}}),
    )
}

fn partial_result_reader(result: Value) -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let record = ToolRunRecord::new(root.path(), RUN, "tool", "fixture:reader");
    record_tool_run_started(record, &json!({"fixture":"owned partial reader metadata"}));
    let observation =
        kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(root.path(), RUN).unwrap();
    let call = kuzushi_core::modules::ApplicationToolCall::start(
        observation.clone(),
        "fixture:reader",
        &json!({}),
        None,
        None,
    )
    .unwrap();
    let completion = call.completion_from_result(&Ok(result.clone()));
    try_record_tool_run_complete_settled(record, &result, &observation, completion).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Report);
    app.open_replay_for_test(RUN);
    for _ in 0..3 {
        app.hydrate_active_view_blocking();
    }
    app.set_input_mode(InputMode::Navigate);
    (root, app)
}

#[test]
fn compact_result_exposes_selected_count_and_uncertainty_in_the_first_frame() {
    let (_root, mut app) = partial_reader();
    app.set_input("held café\ndraft");
    let cursor = app.cursor();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        press(&mut app, KeyCode::Home);
        let text = frame_text(&app, width, height);
        assert!(
            text.contains("Owned context drafts: 1"),
            "{width}x{height}: {text}"
        );
        assert!(
            text.contains("owned-assumption"),
            "{width}x{height}: {text}"
        );
        assert!(text.contains("Outcome · partial"), "{text}");
        assert!(text.contains("cost unavailable"), "{text}");
        assert!(!text.contains("$0"));
        assert!(text.contains("Scope "), "{text}");
        let mut candidate_reached = text.contains("owned-assumption");
        for _ in 0..12 {
            press(&mut app, KeyCode::PageDown);
            candidate_reached |= frame_text(&app, width, height).contains("owned-assumption");
        }
        assert!(
            candidate_reached,
            "{width}x{height}: candidate must remain readable"
        );
    }
    assert_eq!(app.input(), "held café\ndraft");
    assert_eq!(app.cursor(), cursor);
    assert!(!app.has_running_work());
}

#[test]
fn zero_candidates_are_visible_with_a_different_workspace_count() {
    let result = json!({"ok":true,"status":"partial","summary":"UAF source analysis: 0 candidates; partial local analysis",
        "output":"UAF source analysis: 0 candidates; partial local analysis\nUnverified source-analysis candidates. Review evidence before deciding.\nNavigation calls: 1. Repository tool calls: 0.",
        "costUsd":null,"observedCostUsd":0.0,"costUsdExact":false,
        "providerSpendUnresolved":true,"warnings":["Navigation timed out"],"data":{}});
    let (_root, mut app) = partial_result_reader(result);
    *app.findings_mut() = vec![kuzushi_core::Finding::new_tool(
        "owned-fixture",
        "unrelated-history",
        "owned.c",
        1,
        None,
        kuzushi_core::Severity::Low,
        "Owned historical observation",
    )];
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        press(&mut app, KeyCode::Home);
        let text = frame_text(&app, width, height);
        assert!(text.contains("0 candidates"), "{width}x{height}: {text}");
        assert!(text.contains("Outcome · partial"), "{text}");
        assert!(text.contains("cost unavailable"), "{text}");
        assert!(
            text.contains("Workspace 1 finding"),
            "{width}x{height}: {text}"
        );
        assert!(!app.has_running_work());
    }
}

#[test]
fn compact_projection_preserves_original_text_summary_warnings_and_blank_lines() {
    use kuzushi_core::run_lifecycle::{RunItemStatus, SafeText};
    let document = RunResultDocument {
        status: RunItemStatus::Partial,
        summary: SafeText::document_lines("Owned title"),
        output: SafeText::document_lines("Owned title\n\n  owned source\n  owned last row"),
        warnings: SafeText::document_lines("Owned partial source"),
        errors: Vec::new(),
        supplied_input: None,
    };
    let original = document.clone();
    let mut rows = Vec::new();
    compact::append_output(&mut rows, &document);
    let text = rows
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("\n  owned source\n  owned last row"));
    assert!(text.contains("Warning: Owned partial source"));
    assert!(text.find("Owned title").unwrap() < text.find("owned source").unwrap());
    assert_eq!(text.matches("Owned title").count(), 1);
    assert_eq!(document, original);
}

#[test]
fn summary_only_results_and_distinct_output_remain_complete_without_repeated_titles() {
    use kuzushi_core::run_lifecycle::{RunItemStatus, SafeText};
    for (summary, output, expected) in [
        ("Owned result", "Owned result", "Owned result"),
        ("Owned result", "", "Owned result\n"),
        ("", "  Owned result\n\n", "\n  Owned result\n\n"),
        (
            "Owned result",
            "Different source\n  Evidence",
            "Owned result\nDifferent source\n  Evidence",
        ),
    ] {
        let document = RunResultDocument {
            status: RunItemStatus::Completed,
            summary: SafeText::document_lines(summary),
            output: SafeText::document_lines(output),
            warnings: Vec::new(),
            errors: Vec::new(),
            supplied_input: None,
        };
        let mut rows = Vec::new();
        compact::append_output(&mut rows, &document);
        let text = rows
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(text, expected);
    }
}
