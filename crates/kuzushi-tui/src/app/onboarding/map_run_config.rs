use super::PlanningTaskId;
use crate::app::view_hydration::ViewDataState;
use crate::app::{MapRunConfigRowId, ProjectScopeTreeState};
use crate::ShellApp;
use anyhow::{Context, Result};
use kuzushi_core::NestedProjectScope;
use serde_json::{json, Value};
use std::path::Path;

mod expansion;
#[cfg(test)]
mod regeneration;
mod scope_policy;
mod scope_selection;

pub(crate) use scope_policy::eligible_leaf_scopes;
use scope_policy::{
    scope_label, scope_selection_error, selected_scope_count, validate_all_scope_count,
};

pub(crate) const ALL_LEAF_SCOPES: &str = "all:leaf";
pub(crate) const ALL_SCOPES_REVIEW_THRESHOLD: usize = 16;
pub(crate) const ALL_SCOPES_HARD_CAP: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MapRunConfigSummary {
    pub(crate) methodology: String,
    pub(crate) scope: String,
    pub(crate) selected_scopes: usize,
    pub(crate) design_docs: usize,
    pub(crate) context_rows: usize,
    pub(crate) cost: String,
    pub(crate) review_required: bool,
    pub(crate) scope_error: Option<String>,
}

impl ShellApp {
    pub(crate) fn open_map_run_config(&mut self) -> Result<()> {
        self.router.setup_mut().map_run_config_mut().open();
        self.router
            .setup_mut()
            .begin_editor(crate::app::SetupEditor::ThreatModel);
        Ok(())
    }

    pub(crate) fn map_run_config_summary(&self) -> MapRunConfigSummary {
        let tree = self.cached_map_scope_tree();
        let leaves: Vec<NestedProjectScope> = tree
            .as_ref()
            .map(|tree| eligible_leaf_scopes(tree).into_iter().cloned().collect())
            .unwrap_or_default();
        let scope_value = self.map_option_string("scope");
        let selected_scopes = selected_scope_count(scope_value.as_deref(), leaves.len());
        let review_key = tree
            .as_ref()
            .and_then(|tree| self.all_scope_review_key(tree).ok());
        let review_required = scope_value.as_deref() == Some(ALL_LEAF_SCOPES)
            && leaves.len() > ALL_SCOPES_REVIEW_THRESHOLD
            && !review_key.as_deref().is_some_and(|key| {
                self.router
                    .setup()
                    .map_run_config()
                    .all_scopes_reviewed(key)
            });
        MapRunConfigSummary {
            methodology: self
                .map_option_string("methodology")
                .unwrap_or_else(|| "stride".into()),
            scope: scope_label(scope_value.as_deref(), &leaves),
            selected_scopes,
            design_docs: self.map_string_list("designDocs").len(),
            context_rows: self.map_string_list("seed").len(),
            cost: self.map_cost_upper_bound(selected_scopes),
            review_required,
            scope_error: scope_selection_error(scope_value.as_deref(), leaves.len()),
        }
    }

    pub(crate) fn cycle_map_methodology(&mut self) -> Result<()> {
        let current = self.map_option_string("methodology");
        let next = next_map_methodology(current.as_deref());
        self.set_map_option("methodology", json!(next))
    }

    pub(crate) fn configured_map_methodology(&self) -> String {
        self.map_option_string("methodology")
            .unwrap_or_else(|| "stride".to_string())
    }

    pub(crate) fn begin_map_text_edit(&mut self, row: MapRunConfigRowId) {
        let option = map_text_option(row).unwrap_or_default();
        let values = self.map_string_list(option);
        self.router
            .setup_mut()
            .map_run_config_mut()
            .begin_edit(row, values);
    }

    pub(crate) fn commit_map_text_edit(&mut self) -> Result<()> {
        let list = self
            .router
            .setup()
            .map_run_config()
            .text()
            .context("Map text editor is not open")?;
        let field = list.field.as_ref().context("select an entry to edit")?;
        anyhow::ensure!(
            !field.text().trim().is_empty(),
            "enter a value, or Esc to cancel"
        );
        if list.row == MapRunConfigRowId::DesignDocs {
            validate_map_document(self.target(), field.text())?;
        }
        let row = list.row;
        let values = list.candidate_values(field.text().to_string());
        self.save_map_text_values(row, values)
    }

    pub(crate) fn remove_map_text_entry(&mut self) -> Result<()> {
        let list = self
            .router
            .setup()
            .map_run_config()
            .text()
            .context("Map text editor is not open")?;
        self.save_map_text_values(list.row, list.without_selected())
    }

    fn save_map_text_values(&mut self, row: MapRunConfigRowId, values: Vec<String>) -> Result<()> {
        let option = map_text_option(row).context("selected Map row is not text")?;
        self.set_map_option(option, json!(&values))?;
        if let Some(list) = self.router.setup_mut().map_run_config_mut().text_mut() {
            list.saved(values);
        }
        Ok(())
    }

    fn map_option_string(&self, name: &str) -> Option<String> {
        self.engagement
            .option_override_value(PlanningTaskId::BuildThreatModel, name)
            .and_then(|value| value.as_str().map(str::to_string))
            .or_else(|| {
                self.resolved_input_for_planning_task(PlanningTaskId::BuildThreatModel)
                    .ok()?
                    .get(name)?
                    .as_str()
                    .map(str::to_string)
            })
    }

    fn map_string_list(&self, name: &str) -> Vec<String> {
        self.resolved_input_for_planning_task(PlanningTaskId::BuildThreatModel)
            .ok()
            .and_then(|input| input.get(name).and_then(Value::as_array).cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect()
    }

    fn set_map_option(&mut self, name: &str, value: Value) -> Result<()> {
        let task = PlanningTaskId::BuildThreatModel;
        let spec = self
            .planning_option_spec(task, name)
            .with_context(|| format!("threat-model:build option {name:?} is unavailable"))?;
        self.set_planning_option_override(task, &spec, value)
    }

    fn cached_map_scope_tree(&self) -> Option<kuzushi_core::NestedProjectScopeTree> {
        let state = self
            .workbench_cache()
            .borrow()
            .cached_project_scope_tree(self.target());
        let ViewDataState::Ready(ProjectScopeTreeState::Persisted(tree)) = state else {
            return None;
        };
        Some(tree)
    }

    fn map_cost_upper_bound(&self, count: usize) -> String {
        let per_build = self
            .resolved_input_for_planning_task(PlanningTaskId::BuildThreatModel)
            .ok()
            .and_then(|input| input.get("budgetUsd").and_then(Value::as_f64));
        match (per_build, self.session().session_budget_usd()) {
            (Some(cap), _) => format!("upper bound ${:.2}", cap * count as f64),
            (None, Some(cap)) => format!("session upper bound ${cap:.2}"),
            (None, None) => "upper bound not capped".to_string(),
        }
    }

    fn apply_map_scope_choice(
        &mut self,
        next: Option<String>,
        tree: Option<&kuzushi_core::NestedProjectScopeTree>,
        count: usize,
    ) -> Result<()> {
        if next.as_deref() == Some(ALL_LEAF_SCOPES) {
            validate_all_scope_count(count)?;
            self.set_map_option("scope", json!(ALL_LEAF_SCOPES))?;
        } else if let Some(scope) = next {
            self.set_map_option("scope", json!(scope))?;
        } else {
            self.engagement
                .remove_option_override(PlanningTaskId::BuildThreatModel, "scope");
        }
        let reviewed_key = (count <= ALL_SCOPES_REVIEW_THRESHOLD)
            .then(|| tree.and_then(|tree| self.all_scope_review_key(tree).ok()))
            .flatten();
        self.router
            .setup_mut()
            .map_run_config_mut()
            .set_all_scopes_reviewed(reviewed_key);
        Ok(())
    }

    pub(super) fn all_scope_review_key(
        &self,
        tree: &kuzushi_core::NestedProjectScopeTree,
    ) -> Result<String> {
        let eligible = eligible_leaf_scopes(tree)
            .into_iter()
            .map(|scope| json!({"id": scope.id, "path": scope.rel_path}))
            .collect::<Vec<_>>();
        let mut input = self.resolved_input_for_planning_task(PlanningTaskId::BuildThreatModel)?;
        if let Some(fields) = input.as_object_mut() {
            fields.remove("mapBuildSetId");
        }
        let material = json!({
            "scopeTree": tree,
            "eligibleScopes": eligible,
            "preparedOptions": input,
            "sessionBudgetUsd": self.session().session_budget_usd(),
        });
        let bytes = serde_json::to_vec(&material)?;
        Ok(kuzushi_core::run_lifecycle::sha256_content_digest(&bytes))
    }
}

fn map_text_option(row: MapRunConfigRowId) -> Option<&'static str> {
    match row {
        MapRunConfigRowId::DesignDocs => Some("designDocs"),
        MapRunConfigRowId::Context => Some("seed"),
        MapRunConfigRowId::Methodology | MapRunConfigRowId::Scope => None,
    }
}

fn validate_map_document(target: Option<&Path>, value: &str) -> Result<()> {
    let target = target.context("choose a target before adding a document")?;
    let path = target.join(value);
    let metadata = path
        .metadata()
        .with_context(|| format!("cannot read document {value:?}"))?;
    anyhow::ensure!(metadata.is_file(), "document {value:?} must be a file");
    Ok(())
}

fn next_map_methodology(current: Option<&str>) -> &'static str {
    if current == Some("stride") {
        "pasta"
    } else {
        "stride"
    }
}

#[cfg(test)]
mod tests {
    use super::{next_map_methodology, validate_map_document};

    #[test]
    fn first_class_methodology_toggles_stride_and_pasta_only() {
        assert_eq!(next_map_methodology(Some("stride")), "pasta");
        assert_eq!(next_map_methodology(Some("pasta")), "stride");
        assert_eq!(next_map_methodology(Some("dread")), "stride");
    }

    #[test]
    fn document_validation_preserves_commas_and_spaces_and_names_invalid_files() {
        let target = tempfile::tempdir().unwrap();
        let name = "Architecture, v2.md";
        std::fs::write(target.path().join(name), "context").unwrap();
        validate_map_document(Some(target.path()), name).unwrap();
        let error = validate_map_document(Some(target.path()), "missing.md").unwrap_err();
        assert!(error.to_string().contains("missing.md"));
        assert!(validate_map_document(Some(target.path()), ".").is_err());
    }
}
