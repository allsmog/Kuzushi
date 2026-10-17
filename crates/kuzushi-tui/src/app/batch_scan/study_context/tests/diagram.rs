use super::*;
use crate::ui_view_models::study_context::diagram::diagram_detail_lines;
use crossterm::event::{KeyEvent, KeyModifiers};

fn graph() -> Value {
    json!({"version":"1", "methodology":"stride", "title":"Inactive source context", "summary":{},
        "dfd":{
            "nodes":[
                {"id":"client","name":"Browser client","type":"external_entity","trustZone":"public"},
                {"id":"api","name":"Request handler","type":"process","trustZone":"application", "description":"Reads the request and records the selected item.", "purpose":"Serves the source fixture."},
                {"id":"store","name":"Record store","type":"data_store","trustZone":"application"}
            ],
            "flows":[
                {"id":"request","description":"Request input","sourceId":"client","targetId":"api","trustBoundaryIds":["edge"]},
                {"id":"record","description":"Stored record","sourceId":"api","targetId":"store","trustBoundaryIds":[]}
            ],
            "trustBoundaries":[{"id":"edge","name":"Request boundary","innerZone":"application","outerZone":"public","crossingFlowIds":["request"]}]
        },
        "attackSurface":{"entryPoints":[{"id":"AS-input","targetElementIds":["api","request"],"name":"Recorded request input","description":"A labeled source-only fixture observation.","evidence":"main.rs:1","path":"main.rs","line":1}],"roleGates":[],"externalSinks":[],"trustedCallers":[]},
        "assets":[],"threats":[]
    })
}

fn graph_fixture() -> (tempfile::TempDir, ShellApp, ThreatModelRef, ThreatModelRef) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let selected = commit_document(root.path(), "Selected graph", &graph());
    let active = commit(root.path(), "Different active Map");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.hydrate_all_view_data_for_test();
    app.open_study_context_picker();
    app.handle_study_context_key(KeyCode::Up);
    let result = inspect(&app, root.path(), &selected);
    app.cache_tool_snapshot("threat-model:read", &result);
    (root, app, selected, active)
}

fn key(app: &mut ShellApp, code: KeyCode) {
    let update = app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE));
    assert!(
        update.effects.is_empty(),
        "diagram keys may not dispatch work: {} effects",
        update.effects.len()
    );
}

fn screen(app: &mut ShellApp, width: u16, height: u16) -> String {
    app.reduce_resize(width, height);
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn diagram_uses_inspected_revision_and_returns_to_the_exact_context_draft() {
    let (root, mut app, selected, active) = graph_fixture();
    app.set_input("unsent\noperator draft");
    app.set_cursor(4);
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .context_picker
        .as_mut()
        .unwrap()
        .detail_scroll = 3;
    let previous = app.study_context_picker().unwrap().clone();
    key(&mut app, KeyCode::Char('v'));
    let preview = app
        .study_context_picker()
        .unwrap()
        .preview
        .as_ref()
        .unwrap();
    assert_eq!(preview.dfd.nodes.len(), 3);
    assert_eq!(preview.dfd.flows.len(), 2);
    assert_eq!(preview.dfd.boundaries.len(), 1);
    assert_eq!(
        preview.dfd.link_state,
        crate::ui_view_models::DfdLinkState::Complete
    );
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Enter);
    let details = diagram_detail_lines(&app, 120).join("\n");
    assert!(
        details.contains("Recorded request input") && details.contains("main.rs:1"),
        "{details}"
    );
    for code in [KeyCode::Char('g'), KeyCode::Char('a'), KeyCode::Char('L')] {
        key(&mut app, code);
    }
    key(&mut app, KeyCode::Esc);
    let picker = app.study_context_picker().unwrap();
    assert!(!picker.diagram_visible);
    assert_eq!(picker.selected, previous.selected);
    assert_eq!(picker.detail_scroll, previous.detail_scroll);
    assert_eq!(picker.scan_input, previous.scan_input);
    assert_eq!(picker.text_view, previous.text_view);
    key(&mut app, KeyCode::Char('v'));
    assert_eq!(
        app.study_context_picker()
            .unwrap()
            .diagram
            .as_ref()
            .unwrap()
            .selection,
        1
    );
    assert!(
        app.study_context_picker()
            .unwrap()
            .diagram
            .as_ref()
            .unwrap()
            .details
    );
    key(&mut app, KeyCode::Esc);
    assert_eq!((app.input(), app.cursor()), ("unsent\noperator draft", 4));
    app.handle_study_context_key(KeyCode::Char('a'));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .scan_input
            .as_ref()
            .unwrap()["threatModelRef"],
        json!(selected)
    );
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
}

#[test]
fn diagram_and_full_details_are_reachable_at_every_viewport_and_in_plain_output() {
    let (_root, mut app, _, _) = graph_fixture();
    key(&mut app, KeyCode::Char('v'));
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        for selected in 0..6 {
            let rendered = screen(&mut app, width, height);
            assert!(
                rendered.contains("CONTEXT DATA FLOW")
                    && rendered.contains("Esc context")
                    && rendered.contains("Enter details"),
                "{width}x{height}: {rendered}"
            );
            key(&mut app, KeyCode::Enter);
            let mut read = screen(&mut app, width, height);
            for _ in 0..20 {
                key(&mut app, KeyCode::PageDown);
                read.push_str(&screen(&mut app, width, height));
            }
            let expected = ["client", "api", "store", "request", "record", "edge"][selected];
            assert!(
                read.contains(&format!("Element: {expected}")),
                "{width}x{height}: {read}"
            );
            key(&mut app, KeyCode::Home);
            key(&mut app, KeyCode::Enter);
            key(&mut app, KeyCode::Down);
        }
        for _ in 0..6 {
            key(&mut app, KeyCode::Up);
        }
    }
    let plain = crate::renderer::render_plain_app(&app, 80);
    for expected in [
        "Browser client",
        "Request handler",
        "Record store",
        "Request boundary",
        "main.rs:1",
    ] {
        assert!(plain.contains(expected), "{plain}");
    }
}

#[test]
fn missing_or_unlinked_diagrams_never_offer_implicit_generation() {
    let (root, mut app, first, _) = fixture();
    key(&mut app, KeyCode::Char('v'));
    assert!(app.study_context_picker().unwrap().diagram.is_none());
    let mut result = inspect(&app, root.path(), &first);
    app.handle_study_context_key(KeyCode::Up);
    result["data"]["document"]["threats"] = json!([{"id":"legacy","title":"Unlinked claim"}]);
    app.cache_tool_snapshot("threat-model:read", &result);
    key(&mut app, KeyCode::Char('v'));
    key(&mut app, KeyCode::Enter);
    let details = diagram_detail_lines(&app, 80).join("\n");
    assert!(
        details.contains("Context links are unverified"),
        "{details}"
    );
    key(&mut app, KeyCode::Esc);
    let mut result = inspect(&app, root.path(), &first);
    result["data"]["document"]["dfd"] = json!({"nodes":[],"flows":[],"trustBoundaries":[]});
    app.cache_tool_snapshot("threat-model:read", &result);
    key(&mut app, KeyCode::Char('v'));
    key(&mut app, KeyCode::Enter);
    assert!(diagram_detail_lines(&app, 80)
        .join("\n")
        .contains("No diagram elements"));
    result["data"]["document"] = Value::Null;
    app.cache_tool_snapshot("threat-model:read", &result);
    assert!(!app.study_context_picker().unwrap().diagram_visible);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("Context preview unavailable"));
}

#[test]
fn finding_link_uses_the_inactive_revision_and_back_restores_its_entire_draft() {
    let (root, mut app, selected, active) = graph_fixture();
    app.set_input("unsent\ncontext draft");
    app.set_cursor(4);
    app.set_active_findings_filter(Some("severity:high".into()));
    key(&mut app, KeyCode::Char('v'));
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::PageDown);
    let previous = app.router.campaign().batch_scan_config.clone().unwrap();
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE));
    let [ShellEffect::RefreshFindings(request)] = update.effects.as_slice() else {
        panic!("Finding links must only request a ledger read");
    };
    let filter =
        kuzushi_core::FindingListFilter::from_filter_expression(request.filter.as_deref().unwrap())
            .unwrap();
    assert_eq!(filter.file_paths, ["main.rs"]);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(app.router.campaign().batch_scan_config.is_none());
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
    app.go_back();
    assert_eq!(
        app.router.campaign().batch_scan_config.as_ref(),
        Some(&previous)
    );
    assert_eq!(
        app.study_context_picker().unwrap().selected.as_ref(),
        Some(&selected)
    );
    assert_eq!(
        app.active_findings_filter().as_deref(),
        Some("severity:high")
    );
    assert_eq!((app.input(), app.cursor()), ("unsent\ncontext draft", 4));
    assert!(screen(&mut app, 40, 12).contains("f findings"));
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
}

#[test]
fn finding_link_without_paths_keeps_the_preview_and_shows_its_reason() {
    let (root, mut app, selected, active) = graph_fixture();
    key(&mut app, KeyCode::Char('v'));
    key(&mut app, KeyCode::Char('f'));
    let rendered = screen(&mut app, 40, 12);
    assert!(
        rendered.contains("Select a component") && rendered.contains("Esc context"),
        "{rendered}"
    );
    key(&mut app, KeyCode::Enter);
    assert!(diagram_detail_lines(&app, 80)
        .join("\n")
        .contains("repository file evidence"));
    assert_eq!(
        app.study_context_picker().unwrap().selected.as_ref(),
        Some(&selected)
    );
    key(&mut app, KeyCode::Down);
    assert!(app
        .study_context_picker()
        .unwrap()
        .diagram
        .as_ref()
        .unwrap()
        .notice
        .is_none());
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        active
    );
}

#[test]
fn unlinked_preview_finding_query_never_reads_the_active_context_instead() {
    let (root, mut app, first, _) = graph_fixture();
    let mut result = inspect(&app, root.path(), &first);
    result["data"]["document"] = graph();
    result["data"]["document"]["attackSurface"]["entryPoints"][0]
        .as_object_mut()
        .unwrap()
        .remove("targetElementIds");
    app.cache_tool_snapshot("threat-model:read", &result);
    key(&mut app, KeyCode::Char('v'));
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('f'));
    assert!(diagram_detail_lines(&app, 100)
        .join("\n")
        .contains("Inspect or rebuild linked context"));
    assert!(app.study_context_picker().unwrap().diagram_visible);
}

#[test]
fn diagram_evidence_wrapping_keeps_literal_filename_whitespace() {
    let (root, mut app, selected, _) = graph_fixture();
    let mut result = inspect(&app, root.path(), &selected);
    result["data"]["document"]["attackSurface"]["entryPoints"][0]["path"] = json!("app/a  b.rs#L7");
    app.cache_tool_snapshot("threat-model:read", &result);
    key(&mut app, KeyCode::Char('v'));
    key(&mut app, KeyCode::Down);
    let lines = diagram_detail_lines(&app, 120).join("\n");
    assert!(lines.contains("Source: app/a  b.rs#L7"), "{lines}");
}
