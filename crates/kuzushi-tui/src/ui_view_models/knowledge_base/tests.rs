use super::*;
use kuzushi_core::V2Config;
use std::path::PathBuf;

#[test]
fn knowledge_base_model_projects_default_store_and_supported_modules() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = knowledge_base_model(&app);

    assert_eq!(model.title, "KB ATTACHMENTS");
    assert_eq!(
        model.summary_rows[0],
        KnowledgeBaseSummaryRow {
            label: "module",
            value: "context".to_string(),
        }
    );
    assert!(model.summary_rows.contains(&KnowledgeBaseSummaryRow {
        label: "store",
        value: ".kuzushi/v2/attachments.json".to_string(),
    }));
    assert!(model
        .summary_rows
        .iter()
        .any(|row| row.label == "supported" && row.value.contains("threat-model")));
    assert_eq!(
        model.commands,
        [
            "kb [module]",
            "attach <path-or-url>",
            "detach <id>",
            "reparse <id>",
        ]
    );
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

    assert!(model.summary_rows.contains(&KnowledgeBaseSummaryRow {
        label: "store",
        value: "./attachments.json".to_string(),
    }));
    assert_eq!(model.artifact_rows[0].state, "present");
    assert_eq!(model.artifact_rows[0].path, "crates/demo/src/lib.rs");
    assert_eq!(model.attachment_rows.len(), 1);
    assert_eq!(model.attachment_rows[0].id, "a-1");
    assert_eq!(model.attachment_rows[0].kind, "url");
}

#[test]
fn plain_knowledge_base_model_projects_empty_sections() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = plain_knowledge_base_model(&app);

    assert_eq!(model.title, "KB ATTACHMENTS");
    assert!(model.summary_rows.contains(&"module: context".to_string()));
    assert_eq!(model.artifact_section.title, "KNOWN ARTIFACTS");
    assert_eq!(
        model.artifact_section.headers,
        ["state", "path", "description"]
    );
    assert_eq!(
        model.artifact_section.empty_message,
        Some("No known Rust artifacts for this module.")
    );
    assert_eq!(model.attachment_section.title, "ATTACHED");
    assert_eq!(
        model.attachment_section.headers,
        ["id", "kind", "source", "status"]
    );
    assert_eq!(
        model.attachment_section.empty_message,
        Some("No attachments yet. Next: attach <repo-relative-path> or attach <url>")
    );
    assert_eq!(
        model.next_hint,
        "Next: kb [module], attach <path-or-url>, detach <id>, reparse <id>"
    );
}

#[test]
fn plain_knowledge_base_model_projects_artifact_and_attachment_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.kb_view.module_id = "x-ray".to_string();
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

    let model = plain_knowledge_base_model(&app);

    assert!(model.artifact_section.empty_message.is_none());
    assert_eq!(model.artifact_section.rows[0].state, "present");
    assert_eq!(
        model.artifact_section.rows[0].path,
        "crates/demo/src/lib.rs"
    );
    assert!(model.attachment_section.empty_message.is_none());
    assert_eq!(model.attachment_section.rows.len(), 1);
    assert_eq!(model.attachment_section.rows[0].id, "a-1");
    assert_eq!(model.attachment_section.rows[0].kind, "url");
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
