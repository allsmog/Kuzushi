use super::*;
mod goal_state;
mod scanner_preview;
mod source_state;
pub(crate) use goal_state::inspect as inspect_goal_guidance;
pub(crate) use scanner_preview::build as build_scanner_preview;

/// Explicit context reads authenticate the same object that scanners consume.
pub(super) fn read_exact_context(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<Value>> {
    let selection = ThreatModelSelection::from_input(input)?;
    if !selection.is_bound() {
        anyhow::ensure!(
            input.get("threatModelDigestRef").is_none(),
            "Frozen scanner context requires an exact threatModelRef"
        );
        return Ok(None);
    }
    refuse_read_overrides(input)?;
    let target = resolve_target(input, ctx)?;
    let document = match &selection {
        ThreatModelSelection::Revision(reference) => {
            Some(load_exact_threat_model(&target, reference)?)
        }
        _ => None,
    };
    let reference = match selection {
        ThreatModelSelection::Revision(reference) => Some(reference),
        _ => None,
    };
    let preview = selected_preview(input, &target, reference.as_ref(), document.as_ref())?;
    Ok(Some(exact_context_result(
        ctx, target, document, reference, preview,
    )?))
}

fn exact_context_result(
    ctx: &ToolExecutionContext<'_>,
    target: PathBuf,
    document: Option<Value>,
    reference: Option<ThreatModelRef>,
    preview: Option<Value>,
) -> Result<Value> {
    let lesson_state = document
        .as_ref()
        .map(|document| inspect_lesson_state(&target, document));
    let summary = if reference.is_some() {
        "Loaded exact scanner context without changing the active threat model."
    } else {
        "Threat-model context explicitly omitted."
    };
    let source_state = reference
        .as_ref()
        .zip(document.as_ref())
        .map(|(reference, document)| {
            source_state::inspect_source_state(&target, reference, document, ctx)
        });
    anyhow::ensure!(
        !ctx.is_cancelled(),
        "Context read was canceled during source inspection"
    );
    Ok(crate::module_result::completed_output_result(
        summary.to_string(),
        summary.to_string(),
        json!({
            "target": target, "modelRef": reference, "document": document,
            "resolvedFrom": "exact-context",
            "sourceState": source_state,
            "lessonState":lesson_state,
            "goalState":document.as_ref().map(|document| goal_state::inspect(&target, document)),
            "scannerContextPreview":preview,
        }),
    ))
}

fn selected_preview(
    input: &Value,
    target: &Path,
    reference: Option<&ThreatModelRef>,
    document: Option<&Value>,
) -> Result<Option<Value>> {
    let Some(value) = input.get("threatModelDigestRef") else {
        return Ok(document.map(scanner_preview::build));
    };
    let reference = reference.context("Frozen scanner context cannot accompany omitted context")?;
    let frozen = crate::scan::inspect_threat_model_digest(target, value, reference)?;
    let matches = crate::incremental_index::current_workspace_resume_identity(target)
        .ok()
        .map(|current| current == frozen.source_identity);
    let mut preview = frozen.preview;
    preview["frozenReference"] = value.clone();
    preview["sourceMatchesAtInspection"] = json!(matches);
    Ok(Some(preview))
}

fn inspect_lesson_state(target: &Path, document: &Value) -> Value {
    match persistence::lesson_selection::validate_reviewed_lessons(target, document) {
        Ok(()) => json!({"usable":true}),
        Err(error) => json!({"usable":false,"reason":error.to_string()}),
    }
}

fn refuse_read_overrides(input: &Value) -> Result<()> {
    let conflicts = ["outputDir", "output_dir", "scope", "methodology", "type"];
    anyhow::ensure!(
        !conflicts.iter().any(|key| input.get(key).is_some()),
        "threatModelRef reads exact scanner context and cannot combine with scope, outputDir or methodology overlays"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::ModuleRegistry;

    #[test]
    fn prepared_exact_context_read_preserves_the_scanner_document_and_active_model() {
        let root = tempfile::tempdir().unwrap();
        let first = commit_test_model(root.path(), "reviewed context");
        let active = commit_test_model(root.path(), "other context");
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        let config = crate::V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let prepared = registry
            .prepare_dispatch_input(
                "threat-model:read",
                json!({"threatModelRef": first}),
                &ctx,
                None,
            )
            .unwrap();
        let result = registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
        assert_eq!(
            result["data"]["document"],
            load_exact_threat_model(root.path(), &first).unwrap()
        );
        assert_eq!(result["data"]["modelRef"], json!(first));
        assert_eq!(
            result["data"]["scannerContextPreview"],
            scanner_preview::build(&result["data"]["document"])
        );
        assert_eq!(
            load_active_threat_model(root.path())
                .unwrap()
                .unwrap()
                .model_ref,
            active
        );
        for input in [
            json!({"threatModelRef": null}),
            json!({"threat_model_ref": null}),
        ] {
            let result = read_exact_context(&input, &ctx).unwrap().unwrap();
            assert!(result["data"]["document"].is_null());
        }
    }

    #[test]
    fn exact_context_read_refuses_overlays_and_bad_references() {
        let config = crate::V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        for key in ["outputDir", "scope", "methodology"] {
            assert!(
                read_exact_context(&json!({"threatModelRef": null, key: "value"}), &ctx).is_err()
            );
        }
        assert!(read_exact_context(&json!({"threatModelRef": "active"}), &ctx).is_err());
    }
}
