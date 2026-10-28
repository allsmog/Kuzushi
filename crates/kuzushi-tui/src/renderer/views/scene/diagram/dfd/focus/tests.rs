use super::*;
use crate::ui_view_models::{DfdKind, DfdLinkState, DfdNodeModel};

fn model(path: &str) -> DfdModel {
    DfdModel {
        nodes: vec![DfdNodeModel {
            key: "app".into(),
            name: "Owned component".into(),
            description: None,
            purpose: None,
            zone: "local".into(),
            kind: DfdKind::Process,
        }],
        security_context: vec![DfdSecurityItem {
            key: "entry".into(),
            kind: DfdSecurityKind::EntryPoint,
            label: "Owned source".into(),
            detail: "Recorded source path".into(),
            evidence: path.into(),
            evidence_paths: vec![path.into()],
            file_paths: vec![path.into()],
            target_element_ids: vec!["app".into()],
        }],
        link_state: DfdLinkState::Complete,
        ..Default::default()
    }
}

#[test]
fn focused_source_paths_stay_literal_in_six_layouts_without_changing_action_membership() {
    let path = " a\nb ";
    let model = model(path);
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let area = Rect::new(0, 0, width, height);
        let mut buffer = Buffer::empty(area);
        render(&mut buffer, area, &model, 0, 0);
        let text = crate::renderer::tests::rendered_buffer_rows(&buffer).join("\n");
        assert!(text.contains("\" a\\nb \""), "{width}x{height}: {text}");
        assert!(!text.contains("\" a\nb \""), "{width}x{height}: {text}");
    }
    assert_eq!(model.file_paths_for_selection(0, Some(0)), [path]);
    assert_eq!(model.security_context[0].evidence, path);
}

#[test]
fn evidence_labels_escape_path_delimiters_and_preserve_prose() {
    for path in [" a ", "a\tb", "a\\b", "a\"b", "a:7"] {
        let item = model(path).security_context.remove(0);
        let label = item.evidence_label();
        assert_eq!(serde_json::from_str::<String>(&label).unwrap(), path);
    }
    let mut item = model("a.rs").security_context.remove(0);
    item.evidence = "An operator-recorded source boundary".into();
    assert_eq!(item.evidence_label(), item.evidence);
}

#[test]
fn short_shell_bodies_prioritize_selected_annotation_and_escaped_evidence() {
    let model = model(" a\nb ");
    for height in 4..9 {
        let area = Rect::new(0, 0, 38, height);
        let mut buffer = Buffer::empty(area);
        render(&mut buffer, area, &model, 0, 0);
        let text = crate::renderer::tests::rendered_buffer_rows(&buffer).join("\n");
        assert!(
            text.contains("ENTRY · 1/1 · Owned source"),
            "{height}: {text}"
        );
        assert!(text.contains("Evidence: \" a\\nb \""), "{height}: {text}");
    }
}

#[test]
fn short_shell_bodies_disclose_missing_annotations() {
    let mut model = model("a.rs");
    model.security_context.clear();
    let area = Rect::new(0, 0, 38, 5);
    let mut buffer = Buffer::empty(area);
    render(&mut buffer, area, &model, 0, 0);
    let text = crate::renderer::tests::rendered_buffer_rows(&buffer).join("\n");
    assert!(text.contains("No linked annotations"), "{text}");
    assert!(!text.contains("1/0"), "{text}");
}
