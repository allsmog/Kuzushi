//! Executors for `threat-model:verify` and `threat-model:import`.
//!
//! Verify grounds the live persisted document against the target and stamps
//! the verdict back (no versions-ledger row — a timestamp-only change would
//! defeat the ledger's sha dedupe). Import is the explicit front door for
//! externally-authored documents: normalize → provenance(`import`) → verify
//! → stamp → save (refusing to clobber a user-edited live doc without
//! `force`) → ledger row `source='import'`.

use super::*;

const IMPORT_MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn verify_threat_model_adapter(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "threat-model:verify",
        ))?;
    let root = workspace.root();
    let mut document = try_load_persistent_threat_model(root)?.context(
        "threat-model:verify requires a persisted threat model \
         (.kuzushi/threat-model.json); run threat-model:build or \
         threat-model:import first",
    )?;
    let verification = verify_threat_model_document(&document, root)?;
    stamp_verification(&mut document, &verification);
    let write = input.get("write").and_then(Value::as_bool).unwrap_or(true);
    if write {
        // force: the only change is the verification block; user edits in
        // the document body are carried through untouched.
        save_persistent_threat_model(root, &document, true)?;
    }
    let output = format!(
        "threat-model:verify — {} ({} cited paths, {} missing; coverage {}/{})",
        verification.verdict,
        verification.checked_paths,
        verification.missing_count,
        verification.coverage_considered - verification.coverage_gaps,
        verification.coverage_considered,
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "verification": verification,
            "written": write,
        }),
    ))
}

pub(crate) fn import_threat_model_adapter(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "threat-model:import",
        ))?;
    let root = workspace.root();
    let raw = import_document_value(&input)?;
    let methodology = import_methodology(&input, &raw);
    let mut document = normalize_document(raw, &methodology)?;
    stamp_provenance(&mut document, root, "import");
    let verification = verify_threat_model_document(&document, root)?;
    stamp_verification(&mut document, &verification);
    persist_imported_document(root, &document, &input)?;
    let output = format!(
        "threat-model:import saved ({}; {} threats, verification {})",
        methodology,
        document
            .get("threats")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        verification.verdict,
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "methodology": methodology,
            "verification": verification,
        }),
    ))
}

fn persist_imported_document(root: &Path, document: &Value, input: &Value) -> Result<()> {
    let force = input.get("force").and_then(Value::as_bool).unwrap_or(false);
    if !save_persistent_threat_model(root, document, force)? {
        anyhow::bail!(
            "threat-model:import refused to overwrite the user-edited live \
             threat model; pass force=true to replace it"
        );
    }
    record_threat_model_version(root, document, "import", None)?;
    Ok(())
}

fn import_document_value(input: &Value) -> Result<Value> {
    if let Some(document) = input.get("document") {
        if !document.is_null() {
            return Ok(document.clone());
        }
    }
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .context("threat-model:import requires `path` or an inline `document`")?;
    let body = crate::bounded_file::read_utf8_text(Path::new(path), IMPORT_MAX_DOCUMENT_BYTES)
        .with_context(|| format!("Could not read threat-model document {path}"))?;
    serde_json::from_str(&body).with_context(|| format!("{path} is not valid JSON"))
}

/// Explicit option wins; else the document's own methodology; else stride.
fn import_methodology(input: &Value, raw: &Value) -> String {
    input
        .get("methodology")
        .and_then(Value::as_str)
        .or_else(|| raw.get("methodology").and_then(Value::as_str))
        .or_else(|| raw.pointer("/document/methodology").and_then(Value::as_str))
        .unwrap_or("stride")
        .trim()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod verify_import_tests {
    use super::*;
    use crate::modules::ExecutionAuthorization;
    use crate::{V2Config, WorkspaceTarget};

    fn fixture() -> (tempfile::TempDir, WorkspaceTarget) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/app.py"), "a\nb\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        (temp, workspace)
    }

    fn ctx<'a>(config: &'a V2Config, workspace: &'a WorkspaceTarget) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: ExecutionAuthorization::default(),
        }
    }

    fn hand_written_document() -> Value {
        json!({
            "methodology": "stride",
            "dfd": {"nodes": [], "flows": []},
            "threats": [{
                "id": "T-001",
                "title": "download traversal",
                "affectedFiles": ["src/app.py"],
            }],
        })
    }

    #[test]
    fn import_saves_verifies_and_ledgers_the_document() {
        let (_temp, workspace) = fixture();
        let config = V2Config::default();
        let ctx = ctx(&config, &workspace);

        let result = import_threat_model_adapter(
            json!({"document": hand_written_document()}),
            &ctx,
        )
        .unwrap();
        assert_eq!(result["data"]["verification"]["verdict"], json!("verified"));

        let live = load_persistent_threat_model(workspace.root()).unwrap();
        assert_eq!(live.pointer("/verification/verdict"), Some(&json!("verified")));
        assert_eq!(live.pointer("/provenance/pipeline"), Some(&json!("import")));
        let versions =
            list_threat_model_versions(workspace.root(), 10).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].source, "import");
    }

    #[test]
    fn import_refuses_user_edited_live_doc_without_force() {
        let (_temp, workspace) = fixture();
        let config = V2Config::default();
        let ctx = ctx(&config, &workspace);
        let mut edited = hand_written_document();
        edited["userEdited"] = json!(true);
        save_persistent_threat_model(workspace.root(), &edited, true).unwrap();

        let refused = import_threat_model_adapter(
            json!({"document": hand_written_document()}),
            &ctx,
        )
        .unwrap_err();
        assert!(refused.to_string().contains("force=true"), "{refused:#}");

        import_threat_model_adapter(
            json!({"document": hand_written_document(), "force": true}),
            &ctx,
        )
        .unwrap();
    }

    #[test]
    fn verify_write_preserves_user_edits_and_stamps_the_verdict() {
        let (_temp, workspace) = fixture();
        let config = V2Config::default();
        let ctx = ctx(&config, &workspace);
        let mut edited = hand_written_document();
        edited["userEdited"] = json!(true);
        save_persistent_threat_model(workspace.root(), &edited, true).unwrap();

        verify_threat_model_adapter(json!({}), &ctx).unwrap();

        let live = load_persistent_threat_model(workspace.root()).unwrap();
        assert_eq!(live.get("userEdited"), Some(&json!(true)));
        assert!(live.get("verification").is_some());
        assert!(
            list_threat_model_versions(workspace.root(), 10)
                .unwrap()
                .is_empty(),
            "verify never writes a versions-ledger row"
        );
    }
}
