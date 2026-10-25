use super::*;
use crate::ui_view_models::{DfdKind, DfdNodeModel};

fn model_with_direct_file(path: &str) -> DfdModel {
    DfdModel {
        nodes: vec![DfdNodeModel {
            key: "app".into(),
            name: "Owned source".into(),
            description: None,
            purpose: None,
            zone: "local".into(),
            kind: DfdKind::Process,
        }],
        element_file_paths: [("app".into(), vec![path.into()])].into_iter().collect(),
        link_state: DfdLinkState::Complete,
        ..Default::default()
    }
}

#[test]
fn direct_node_files_support_scoped_actions_without_security_annotations() {
    let target = tempfile::tempdir().unwrap();
    let model = model_with_direct_file(" app /source.rs:7");
    assert!(model.security_context.is_empty());
    let selection = DfdScanSelection::from_model(target.path(), &model, 0, None).unwrap();
    assert_eq!(selection.paths, [" app /source.rs:7"]);
}

#[test]
fn direct_files_cannot_create_traversal_or_root_scopes() {
    for path in ["../outside.rs", ".", "https://example.test/file.rs"] {
        let model = model_with_direct_file(path);
        assert!(DfdScanSelection::from_model(Path::new("/owned"), &model, 0, None).is_err());
    }
}
