use super::*;
use crate::app::ShellView;

fn reference(id: char) -> ThreatModelRef {
    serde_json::from_value(serde_json::json!({"modelId":format!("tm_{}", id.to_string().repeat(32)),"revisionId":format!("tmr_{}", id.to_string().repeat(32)),"sha256":format!("sha256:{}",id.to_string().repeat(64))})).unwrap()
}

#[test]
fn missing_selected_revision_does_not_fall_back_to_active_context() {
    let mut state = ContextHistoryState::new("/owned".into(), ShellView::Home);
    state.selected = Some(reference('1'));
    let catalog = ContextHistoryCatalog {
        rows: vec![ContextHistoryRow {
            reference: reference('2'),
            label: "Active".into(),
            details: vec![],
            active: true,
        }],
        status: "ready".into(),
    };
    assert_eq!(catalog.selected_index(Some(&state)), None);
    assert!(history_detail_lines(&state, &catalog, 40)
        .join(" ")
        .contains("without substitution"));
}

#[test]
fn layouts_keep_reader_text_and_all_controls_in_the_viewport() {
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let area = Rect::new(0, 0, width, height);
        for reader in [false, true] {
            let layout = history_layout(area, reader);
            assert!(layout.detail.height >= if reader { 6 } else { 3 });
            assert_eq!(layout.controls.height, 3);
            assert!(layout.controls.bottom() < area.bottom());
            assert!(layout.detail.right() < area.right());
            assert_eq!(layout.list.is_none(), reader);
        }
    }
}

#[test]
fn comparison_preserves_complete_multiline_text_and_coverage_disclosure() {
    let mut state = ContextHistoryState::new("/owned".into(), ShellView::Home);
    state.begin(ContextHistoryRequest::Compare {
        baseline: reference('1'),
        candidate: reference('2'),
    });
    state.data = Some(std::sync::Arc::new(
        serde_json::json!({"contextText":[{"label":"Overview","before":"Earlier overview","after":"Edited first line α\nLast complete line"}],"documentChanged":true,"changedDocumentSections":["dfd"],"comparisonCoverage":{"structural":"Selected fields only"}}),
    ));
    let lines = history_detail_lines(&state, &empty_catalog("ready".into()), 40).join("\n");
    assert!(lines.contains("Earlier overview"));
    assert!(lines.contains("Edited first line α"));
    assert!(lines.contains("Last complete line"));
    assert!(lines.contains("Selected fields only"));
}

#[test]
fn malformed_comparison_is_disclosed_without_claiming_unchanged_text() {
    for data in [
        Value::Null,
        serde_json::json!([]),
        serde_json::json!("invalid"),
        serde_json::json!(7),
    ] {
        let mut state = ContextHistoryState::new("/owned".into(), ShellView::Home);
        state.begin(ContextHistoryRequest::Compare {
            baseline: reference('1'),
            candidate: reference('2'),
        });
        state.data = Some(std::sync::Arc::new(data));
        let lines = history_detail_lines(&state, &empty_catalog("ready".into()), 40).join(" ");
        assert!(lines.contains("Comparison result is invalid"), "{lines}");
        assert!(!lines.contains("No editable text differs"), "{lines}");
    }
}

#[test]
fn inspection_keeps_the_captured_label_while_manifest_refresh_is_pending() {
    let mut state = ContextHistoryState::new("/owned".into(), ShellView::Home);
    state.selected = Some(reference('1'));
    state.selected_label = Some("Reviewed context · revision 2".into());
    state.begin(ContextHistoryRequest::Read(reference('1')));
    let lines =
        history_detail_lines(&state, &empty_catalog("Loading history".into()), 80).join("\n");
    assert!(lines.contains("Inspect: Reviewed context · revision 2"));
}

#[test]
fn historical_goal_is_readable_before_document_in_both_views_without_rewriting_it() {
    let document = serde_json::json!({"title":"Exact historical document","systemContext":"Last source detail"});
    let mut state = ContextHistoryState::new("/owned".into(), ShellView::Home);
    state.begin(ContextHistoryRequest::Read(reference('1')));
    state.data = Some(std::sync::Arc::new(serde_json::json!({"document":document,
        "goalState":{"status":"recorded","reference":{"briefId":"repository","revision":1},
            "textBytes":22,"text":"Historical priorities"}})));
    for raw in [false, true] {
        state.document_raw = raw;
        let lines = history_detail_lines(&state, &empty_catalog("ready".into()), 120).join("\n");
        assert!(lines.contains("Historical priorities"));
        assert!(lines.contains("Model use is not independently verified"));
        assert!(
            lines.find("RECORDED GOAL GUIDANCE").unwrap()
                < lines.find("Exact historical document").unwrap()
        );
        assert_eq!(state.data.as_ref().unwrap()["document"], document);
    }
}
