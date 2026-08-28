use super::*;
use anyhow::Context;

impl ShellApp {
    pub(crate) fn expand_map_build_steps(
        &mut self,
        workspace: &kuzushi_core::WorkspaceTarget,
    ) -> Result<Vec<super::super::runner::PlanningRunStep>> {
        let task = PlanningTaskId::BuildThreatModel;
        let build_set_id = kuzushi_core::new_run_id("map-build-set");
        let input =
            super::super::planning_task_explicit_input(task, self.engagement.option_overrides());
        if input.get("scope").and_then(Value::as_str) != Some(ALL_LEAF_SCOPES) {
            return Ok(vec![self.step_with_extra_input(
                task,
                json!({"mapBuildSetId": build_set_id}),
            )?]);
        }
        self.expand_all_map_scopes(workspace, task, &build_set_id)
    }

    fn expand_all_map_scopes(
        &mut self,
        workspace: &kuzushi_core::WorkspaceTarget,
        task: PlanningTaskId,
        build_set_id: &str,
    ) -> Result<Vec<super::super::runner::PlanningRunStep>> {
        let tree = kuzushi_core::load_nested_project_scopes(workspace.root())?
            .context("all scopes needs a persisted project decomposition")?;
        let leaves = eligible_leaf_scopes(&tree);
        validate_all_scope_count(leaves.len())?;
        let review_key = self.all_scope_review_key(&tree)?;
        anyhow::ensure!(
            leaves.len() <= ALL_SCOPES_REVIEW_THRESHOLD
                || self
                    .router
                    .setup()
                    .map_run_config()
                    .all_scopes_reviewed(&review_key),
            "{} eligible scopes require explicit review above the {}-scope threshold",
            leaves.len(),
            ALL_SCOPES_REVIEW_THRESHOLD
        );
        let methodology = self.configured_map_methodology();
        leaves
            .into_iter()
            .map(|scope| self.all_scope_step(workspace, task, build_set_id, &methodology, scope))
            .collect()
    }

    fn all_scope_step(
        &self,
        workspace: &kuzushi_core::WorkspaceTarget,
        task: PlanningTaskId,
        build_set_id: &str,
        methodology: &str,
        scope: &kuzushi_core::NestedProjectScope,
    ) -> Result<super::super::runner::PlanningRunStep> {
        let extra = all_scope_lineage_input(workspace.root(), scope, methodology, build_set_id)?;
        let mut input =
            super::super::planning_task_explicit_input(task, self.engagement.option_overrides());
        replace_lineage_controls(&mut input, extra);
        let input = self.registry().prepare_tool_input(
            task.tool_name(),
            input,
            Some(self.option_store()),
        )?;
        Ok(super::super::runner::PlanningRunStep {
            task,
            tool_name: task.tool_name().to_string(),
            input,
        })
    }
}

fn all_scope_lineage_input(
    root: &std::path::Path,
    scope: &kuzushi_core::NestedProjectScope,
    methodology: &str,
    build_set_id: &str,
) -> Result<Value> {
    let current = kuzushi_core::capabilities::current_scope_ref_for_path(root, &scope.rel_path)?
        .with_context(|| {
            format!(
                "all-scopes run cannot bind current scope {} ({})",
                scope.id, scope.rel_path
            )
        })?;
    let lineage =
        kuzushi_core::capabilities::resolve_unique_build_lineage(root, &current, methodology)
            .with_context(|| format!("all-scopes rerun refused for scope {}", scope.rel_path))?;
    Ok(lineage_input(scope, methodology, build_set_id, lineage))
}

fn lineage_input(
    scope: &kuzushi_core::NestedProjectScope,
    methodology: &str,
    build_set_id: &str,
    lineage: Option<kuzushi_core::ThreatModelId>,
) -> Value {
    match lineage {
        Some(model_id) => json!({
            "scope": format!("id:{}", scope.id),
            "methodology": methodology,
            "mode": "refine",
            "seedMode": "seeded",
            "modelId": model_id.as_str(),
            "newModel": false,
            "mapBuildSetId": build_set_id,
        }),
        None => json!({
            "scope": format!("id:{}", scope.id),
            "methodology": methodology,
            "mode": "build",
            "seedMode": "fresh",
            "newModel": false,
            "mapBuildSetId": build_set_id,
        }),
    }
}

fn replace_lineage_controls(input: &mut Value, replacement: Value) {
    let Some(input) = input.as_object_mut() else {
        return;
    };
    for key in [
        "mode",
        "seedMode",
        "seed_mode",
        "modelId",
        "model_id",
        "newModel",
        "new_model",
    ] {
        input.remove(key);
    }
    if let Some(replacement) = replacement.as_object() {
        input.extend(replacement.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{
        NestedProjectKind, NestedProjectScope, NestedProjectScopeTree, ThreatModelCommit,
        ThreatModelId, ThreatModelRevisionSource, V2Config,
    };

    #[test]
    fn all_scope_expansion_binds_one_durable_build_set() {
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join("api")).unwrap();
        std::fs::create_dir_all(target.path().join("web")).unwrap();
        kuzushi_core::save_nested_project_scopes(target.path(), &scope_tree()).unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.set_map_option("scope", json!(ALL_LEAF_SCOPES)).unwrap();

        let steps = app.expand_map_build_steps(&workspace).unwrap();

        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps[0].input["mapBuildSetId"],
            steps[1].input["mapBuildSetId"]
        );
        assert_ne!(steps[0].input["scope"], steps[1].input["scope"]);

        let next = app.expand_map_build_steps(&workspace).unwrap();
        assert_ne!(
            steps[0].input["mapBuildSetId"],
            next[0].input["mapBuildSetId"]
        );
    }

    #[test]
    fn setup_summary_flat_options_prepared_input_and_run_receipt_agree() {
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join("docs")).unwrap();
        std::fs::write(target.path().join("docs/design.md"), "# Tenant boundary\n").unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.set_map_option("methodology", json!("pasta")).unwrap();
        app.set_map_option("designDocs", json!(["docs/design.md"]))
            .unwrap();
        app.set_map_option("seed", json!(["tenant isolation is required"]))
            .unwrap();

        let summary = app.map_run_config_summary();
        let flat = super::super::super::planning_task_explicit_input(
            PlanningTaskId::BuildThreatModel,
            app.engagement.option_overrides(),
        );
        let step = app.expand_map_build_steps(&workspace).unwrap().remove(0);
        let (run_id, dispatch_input) = app
            .persist_background_tool_preparation_for_test(
                &step.tool_name,
                step.input.clone(),
                &workspace,
            )
            .unwrap();
        let (_, receipt_body) = kuzushi_core::run_artifacts::read_run_artifact_text(
            workspace.root(),
            &run_id,
            "input.json",
        )
        .require("prepared Map input receipt")
        .unwrap();
        let receipt: Value = serde_json::from_str(&receipt_body).unwrap();

        assert_eq!(summary.methodology, "pasta");
        assert_eq!(summary.scope, "whole repository");
        assert_eq!(summary.design_docs, 1);
        assert_eq!(summary.context_rows, 1);
        assert_eq!(flat["methodology"], step.input["methodology"]);
        assert_eq!(flat["designDocs"], step.input["designDocs"]);
        assert_eq!(flat["seed"], step.input["seed"]);
        assert_eq!(receipt, dispatch_input);
        assert_eq!(receipt["methodology"], step.input["methodology"]);
        assert_eq!(receipt["designDocs"], step.input["designDocs"]);
        assert_eq!(receipt["seed"], step.input["seed"]);
        assert_eq!(
            receipt["target"],
            json!(workspace.root().display().to_string())
        );
    }

    #[test]
    fn equal_scope_counts_do_not_reuse_review_for_a_changed_decomposition() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.set_map_option("scope", json!(ALL_LEAF_SCOPES)).unwrap();
        let first = scope_tree();
        let first_key = app.all_scope_review_key(&first).unwrap();
        app.router
            .setup_mut()
            .map_run_config_mut()
            .set_all_scopes_reviewed(Some(first_key.clone()));
        let mut changed = scope_tree();
        changed.scopes[1].id = "worker".to_string();
        changed.scopes[1].rel_path = "worker".into();
        let changed_key = app.all_scope_review_key(&changed).unwrap();

        assert_ne!(first_key, changed_key);
        assert!(app
            .router
            .setup()
            .map_run_config()
            .all_scopes_reviewed(&first_key));
        assert!(!app
            .router
            .setup()
            .map_run_config()
            .all_scopes_reviewed(&changed_key));
    }

    #[test]
    fn repeated_all_scope_run_refines_exact_lineages_and_rebuilds_stale_ones() {
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join("api")).unwrap();
        std::fs::create_dir_all(target.path().join("web")).unwrap();
        kuzushi_core::save_nested_project_scopes(target.path(), &scope_tree()).unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.set_map_option("scope", json!(ALL_LEAF_SCOPES)).unwrap();
        app.set_map_option("methodology", json!("stride")).unwrap();

        let initial = app.expand_map_build_steps(&workspace).unwrap();
        assert!(initial.iter().all(is_fresh_build));

        let api = commit_scope_model(target.path(), "api", false, true);
        let web = commit_scope_model(target.path(), "web", false, false);
        app.set_map_option("mode", json!("build")).unwrap();
        app.set_map_option("seedMode", json!("fresh")).unwrap();
        app.set_map_option("newModel", json!(true)).unwrap();
        app.set_map_option("modelId", json!(api.as_str())).unwrap();
        let repeated = app.expand_map_build_steps(&workspace).unwrap();
        assert_refine_step(&repeated, "api", &api);
        assert_refine_step(&repeated, "web", &web);

        let mut changed = scope_tree();
        changed.scopes[1]
            .inherited_sections
            .push("changed-decomposition".to_string());
        kuzushi_core::save_nested_project_scopes(target.path(), &changed).unwrap();
        let stale = app.expand_map_build_steps(&workspace).unwrap();
        assert!(stale.iter().all(is_fresh_build));
    }

    #[test]
    fn all_scope_rerun_refuses_ambiguous_variants_even_when_one_is_active() {
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join("api")).unwrap();
        std::fs::create_dir_all(target.path().join("web")).unwrap();
        kuzushi_core::save_nested_project_scopes(target.path(), &scope_tree()).unwrap();
        commit_scope_model(target.path(), "api", false, true);
        commit_scope_model(target.path(), "api", true, false);
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.set_map_option("scope", json!(ALL_LEAF_SCOPES)).unwrap();
        app.set_map_option("methodology", json!("stride")).unwrap();

        let error = app.expand_map_build_steps(&workspace).unwrap_err();
        let message = format!("{error:#}");

        assert!(
            message.contains("all-scopes rerun refused for scope api"),
            "{message}"
        );
        assert!(
            message.contains("multiple threat-model variants"),
            "{message}"
        );
        assert!(message.contains("select modelId explicitly"), "{message}");
    }

    fn is_fresh_build(step: &super::super::super::runner::PlanningRunStep) -> bool {
        step.input["mode"] == "build"
            && step.input["seedMode"] == "fresh"
            && step.input["newModel"] == false
            && step.input.get("modelId").is_none()
    }

    fn assert_refine_step(
        steps: &[super::super::super::runner::PlanningRunStep],
        scope_id: &str,
        model_id: &ThreatModelId,
    ) {
        let scope = format!("id:{scope_id}");
        let step = steps
            .iter()
            .find(|step| step.input["scope"] == scope)
            .unwrap();
        assert_eq!(step.input["mode"], "refine");
        assert_eq!(step.input["seedMode"], "seeded");
        assert_eq!(step.input["modelId"], model_id.as_str());
        assert_eq!(step.input["newModel"], false);
    }

    fn commit_scope_model(
        root: &std::path::Path,
        rel_path: &str,
        new_model: bool,
        activate: bool,
    ) -> ThreatModelId {
        let scope = kuzushi_core::capabilities::current_scope_ref_for_path(root, rel_path)
            .unwrap()
            .unwrap();
        kuzushi_core::capabilities::commit_threat_model_revision(
            root,
            &model_document(rel_path),
            ThreatModelCommit {
                model_id: None,
                new_model,
                label: rel_path.to_string(),
                scope,
                methodology: "stride".to_string(),
                source: ThreatModelRevisionSource::Build,
                source_revision_id: None,
                run_id: None,
                activate: Some(activate),
                actor: "test".to_string(),
            },
        )
        .unwrap()
        .model_ref
        .model_id
    }

    fn model_document(node: &str) -> Value {
        json!({
            "version": "2.0",
            "methodology": "stride",
            "dfd": {"nodes": [{"id": node}], "flows": [], "trustBoundaries": []},
            "threats": [],
            "summary": {}
        })
    }

    fn scope_tree() -> NestedProjectScopeTree {
        NestedProjectScopeTree {
            schema_version: 2,
            root: "root".to_string(),
            scopes: vec![
                scope("root", None, ".", NestedProjectKind::Root),
                scope("api", Some("root"), "api", NestedProjectKind::PackageRoot),
                scope("web", Some("root"), "web", NestedProjectKind::PackageRoot),
            ],
        }
    }

    fn scope(
        id: &str,
        parent: Option<&str>,
        path: &str,
        kind: NestedProjectKind,
    ) -> NestedProjectScope {
        NestedProjectScope {
            id: id.into(),
            parent: parent.map(str::to_string),
            kind,
            rel_path: path.into(),
            inherited_sections: Vec::new(),
        }
    }
}
