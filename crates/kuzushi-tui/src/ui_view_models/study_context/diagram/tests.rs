use super::*;
use crate::ui_view_models::{DfdKind, DfdNodeModel, DfdSecurityItem, DfdSecurityKind};

#[test]
fn literal_evidence_paths_are_quoted_while_prose_stays_readable() {
    let mut model = DfdModel {
        link_state: DfdLinkState::Complete,
        nodes: vec![DfdNodeModel {
            key: "owned".into(),
            name: "Owned component".into(),
            description: None,
            purpose: None,
            zone: "local".into(),
            kind: DfdKind::Process,
        }],
        security_context: vec![DfdSecurityItem {
            key: "owned-context".into(),
            kind: DfdSecurityKind::Asset,
            label: "Owned evidence".into(),
            detail: "Source-only architecture evidence".into(),
            evidence: " app /lib.py".into(),
            evidence_paths: vec![" app /lib.py".into(), "app/lib.py".into()],
            file_paths: vec![" app /lib.py".into(), "app/lib.py".into()],
            target_element_ids: vec!["owned".into()],
        }],
        ..Default::default()
    };
    let text = linked_evidence_lines(&model, 0).join("\n");
    assert!(text.contains("Evidence: \" app /lib.py\""));
    assert!(text.contains("Source: \"app/lib.py\""));
    model.security_context[0].evidence = "A recorded source boundary".into();
    let text = linked_evidence_lines(&model, 0).join("\n");
    assert!(text.contains("Evidence: A recorded source boundary"));
    assert!(text.contains("Source: \" app /lib.py\""));
}
