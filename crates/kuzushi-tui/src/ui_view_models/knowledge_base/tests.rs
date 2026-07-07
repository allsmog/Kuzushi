use super::*;
use kuzushi_core::V2Config;
use std::path::PathBuf;

#[test]
fn attachments_store_relative_path_uses_core_workspace_path() {
    assert_eq!(
        attachments_store_relative_path(),
        kuzushi_core::workspace::workspace_attachments_path("")
            .display()
            .to_string()
    );
}

#[test]
fn knowledge_base_model_projects_default_store_and_supported_modules() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = knowledge_base_model(&app);

    assert_eq!(model.title, "KB ATTACHMENTS");
    assert_eq!(
        model.summary_rows[0],
        KnowledgeBaseSummaryRow {
            cells: ["module".to_string(), "context".to_string()],
        }
    );
    assert!(model.summary_rows.contains(&KnowledgeBaseSummaryRow {
        cells: [
            "store".to_string(),
            ".kuzushi/v3/attachments.json".to_string(),
        ],
    }));
    assert!(model
        .summary_rows
        .iter()
        .any(|row| row.cells[0] == "supported" && row.cells[1].contains("threat-model")));
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
    app.domain_mut().kb_view_mut().module_id = "x-ray".to_string();
    app.domain_mut().kb_view_mut().store_path =
        Some(PathBuf::from("/tmp/demo/.kuzushi/v3/attachments.json"));
    app.domain_mut().kb_view_mut().artifacts = vec![KnownArtifact {
        module_id: "x-ray".to_string(),
        path: "crates/demo/src/lib.rs".to_string(),
        description: "Rust entrypoint".to_string(),
        exists: true,
    }];
    app.domain_mut().kb_view_mut().attachments = vec![
        attachment("x-ray", "a-1", AttachmentKind::Url),
        attachment("context", "a-2", AttachmentKind::Path),
    ];

    let model = knowledge_base_model(&app);

    assert!(model.summary_rows.contains(&KnowledgeBaseSummaryRow {
        cells: ["store".to_string(), "./attachments.json".to_string()],
    }));
    assert_eq!(model.artifact_rows[0].cells[0], "present");
    assert_eq!(model.artifact_rows[0].cells[1], "crates/demo/src/lib.rs");
    assert_eq!(model.attachment_rows.len(), 1);
    assert_eq!(model.attachment_rows[0].cells[0], "a-1");
    assert_eq!(model.attachment_rows[0].cells[1], "url");
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
        Some("No artifacts indexed for this module yet.")
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
    app.domain_mut().kb_view_mut().module_id = "x-ray".to_string();
    app.domain_mut().kb_view_mut().artifacts = vec![KnownArtifact {
        module_id: "x-ray".to_string(),
        path: "crates/demo/src/lib.rs".to_string(),
        description: "Rust entrypoint".to_string(),
        exists: true,
    }];
    app.domain_mut().kb_view_mut().attachments = vec![
        attachment("x-ray", "a-1", AttachmentKind::Url),
        attachment("context", "a-2", AttachmentKind::Path),
    ];

    let model = plain_knowledge_base_model(&app);

    assert!(model.artifact_section.empty_message.is_none());
    assert_eq!(model.artifact_section.rows[0].cells[0], "present");
    assert_eq!(
        model.artifact_section.rows[0].cells[1],
        "crates/demo/src/lib.rs"
    );
    assert!(model.attachment_section.empty_message.is_none());
    assert_eq!(model.attachment_section.rows.len(), 1);
    assert_eq!(model.attachment_section.rows[0].cells[0], "a-1");
    assert_eq!(model.attachment_section.rows[0].cells[1], "url");
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
