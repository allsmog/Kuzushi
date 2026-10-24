use super::*;
use crate::ui_view_models::{DfdKind, DfdNodeModel};

#[test]
fn literal_members_preserve_spaces_punctuation_and_platform_separators() {
    let target = tempfile::tempdir().unwrap();
    for path in [
        " app / source.rs ",
        "src/a,b.rs",
        "src/`code`.rs",
        "src/a.rs:7",
        "src/a#L9.rs",
    ] {
        assert_eq!(literal_path(target.path(), path).unwrap(), path);
    }
    #[cfg(unix)]
    assert_eq!(
        literal_path(target.path(), "src/a\\b.rs").unwrap(),
        "src/a\\b.rs"
    );
    #[cfg(windows)]
    assert_eq!(
        literal_path(target.path(), "src\\a.rs").unwrap(),
        "src/a.rs"
    );
    assert_eq!(
        literal_path(
            target.path(),
            target.path().join(" app /a.rs").to_str().unwrap()
        )
        .unwrap(),
        " app /a.rs"
    );
    assert_eq!(
        literal_path(target.path(), "./src/a.rs").unwrap(),
        "src/a.rs"
    );
}

#[test]
fn invalid_or_root_evidence_never_expands_into_repository_work() {
    for path in [
        "",
        ".",
        "./",
        "/owned",
        "../outside.rs",
        "src/../file.rs",
        "/other/a.rs",
        "https://example.test/a.rs",
    ] {
        assert!(literal_path(Path::new("/owned"), path).is_err(), "{path:?}");
    }
}

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
