use super::*;
use kuzushi_core::V2Config;
use std::path::PathBuf;

#[test]
fn knowledge_base_model_projects_default_store_and_supported_modules() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = knowledge_base_model(&app);

    assert_eq!(model.module_id_label, "context");
    assert_eq!(model.store_label, ".kuzushi/v2/attachments.json");
    assert!(model.supported_label.contains("threat-model"));
    assert!(model.artifact_rows.is_empty());
    assert!(model.attachment_rows.is_empty());
}

#[test]
fn knowledge_base_model_filters_attachments_to_active_module() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.kb_view.module_id = "x-ray".to_string();
    app.kb_view.store_path = Some(PathBuf::from("/tmp/demo/.kuzushi/v2/attachments.json"));
    app.kb_view.artifacts = vec![KnownArtifact {
        module_id: "x-ray".to_string(),
        path: "crates/demo/src/lib.rs".to_string(),
        description: "Rust entrypoint".to_string(),
        exists: true,
    }];
    app.kb_view.attachments = vec![
        attachment("x-ray", "a-1", AttachmentKind::Url),
        attachment("context", "a-2", AttachmentKind::Path),
    ];

    let model = knowledge_base_model(&app);

    assert_eq!(model.store_label, "./attachments.json");
    assert_eq!(model.artifact_rows[0].state, "present");
    assert_eq!(model.artifact_rows[0].path, "crates/demo/src/lib.rs");
    assert_eq!(model.attachment_rows.len(), 1);
    assert_eq!(model.attachment_rows[0].id, "a-1");
    assert_eq!(model.attachment_rows[0].kind, "url");
}

fn attachment(module_id: &str, id: &str, kind: AttachmentKind) -> AttachmentRecord {
    AttachmentRecord {
        id: id.to_string(),
        module_id: module_id.to_string(),
        kind,
        source: "https://example.test/ref".to_string(),
        title: "reference".to_string(),
        metadata_only: true,
        content_hash: None,
        byte_count: None,
        status: "indexed".to_string(),
        updated_at_unix: 1,
    }
}
