#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn attaches_repo_file_under_v2_state() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("notes.md"), "operator note\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let record = attach_source(&workspace, "context", "notes.md").unwrap();

        assert_eq!(record.module_id, "context");
        assert_eq!(record.kind, AttachmentKind::Path);
        assert_eq!(record.source, "notes.md");
        assert_eq!(record.byte_count, Some("operator note\n".len() as u64));
        assert!(record.content_hash.is_some());
        assert_eq!(
            attachment_store_path(&workspace),
            crate::workspace::workspace_attachments_path(workspace.root())
        );
        assert!(attachment_store_path(&workspace).exists());
    }

    #[test]
    fn rejects_paths_outside_workspace_root() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let error = attach_source(&workspace, "context", outside.path().to_str().unwrap())
            .unwrap_err()
            .to_string();

        assert!(error.contains("escapes workspace root"));
    }

    #[test]
    fn url_attachments_are_metadata_only() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let record =
            attach_source(&workspace, "threat-model", "https://example.test/design").unwrap();

        assert_eq!(record.kind, AttachmentKind::Url);
        assert!(record.metadata_only);
        assert_eq!(record.content_hash, None);
        assert!(record.status.contains("not fetched"));
    }

    #[test]
    fn reparse_updates_file_hash_and_detach_removes_record() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("x-ray.md"), "first\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let first = attach_source(&workspace, "x-ray", "x-ray.md").unwrap();
        fs::write(tmp.path().join("x-ray.md"), "second\n").unwrap();

        let second = reparse_source(&workspace, &first.id).unwrap();

        assert_eq!(first.id, second.id);
        assert_ne!(first.content_hash, second.content_hash);
        let removed = detach_source(&workspace, &first.id).unwrap();
        assert_eq!(removed.id, first.id);
        assert!(list_attachments(&workspace).unwrap().is_empty());
    }

    #[test]
    fn known_artifacts_cover_supported_bridge_modules() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("x-ray")).unwrap();
        fs::write(tmp.path().join("x-ray/x-ray.md"), "# X-Ray\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        for module_id in SUPPORTED_ATTACHMENT_MODULES {
            let artifacts = known_artifacts(&workspace, module_id).unwrap();
            assert!(!artifacts.is_empty(), "missing artifacts for {module_id}");
        }
        assert!(SUPPORTED_ATTACHMENT_MODULES.contains(&"offense-review"));
        assert!(!SUPPORTED_ATTACHMENT_MODULES.contains(&"carlini-threat-hunt"));
        assert!(is_supported_attachment_module("carlini-threat-hunt"));
        assert!(!known_artifacts(&workspace, "carlini-threat-hunt")
            .unwrap()
            .is_empty());
        let context = known_artifacts(&workspace, "context").unwrap();
        assert!(context.iter().any(|artifact| {
            artifact.path
                == crate::workspace::artifact_kb::relative_workspace_path(
                    workspace.root(),
                    &crate::context::context_snapshot_path(workspace.root()),
                )
                && artifact.description == "context snapshot"
        }));
        let threat_model = known_artifacts(&workspace, "threat-model").unwrap();
        assert!(threat_model.iter().any(|artifact| {
            artifact.path
                == crate::workspace::artifact_kb::relative_workspace_path(
                    workspace.root(),
                    &crate::capabilities::persistent_threat_model_path(workspace.root()),
                )
                && artifact.description == "persisted threat model"
        }));
        let offense_review = known_artifacts(&workspace, "offense-review").unwrap();
        assert!(offense_review.iter().any(|artifact| {
            artifact.path
                == crate::workspace::artifact_kb::relative_workspace_path(
                    workspace.root(),
                    &crate::workspace::workspace_findings_db_path(workspace.root()),
                )
                && artifact.description == "hunt findings database"
        }));
        let x_ray = known_artifacts(&workspace, "x-ray").unwrap();
        assert!(x_ray.iter().any(|artifact| {
            artifact.path == "x-ray/x-ray.md" && artifact.description == "x-ray report"
        }));
    }
}
