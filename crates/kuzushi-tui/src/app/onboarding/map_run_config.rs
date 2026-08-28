use super::PlanningTaskId;
use crate::app::view_hydration::ViewDataState;
use crate::app::{MapRunConfigRowId, ProjectScopeTreeState};
use crate::ShellApp;
use anyhow::{Context, Result};
use kuzushi_core::NestedProjectScope;
use serde_json::{json, Value};

mod expansion;
mod regeneration;
mod scope_policy;

pub(crate) use regeneration::scoped_regeneration_input;
pub(crate) use scope_policy::{eligible_leaf_scopes, owning_leaf_scope};
use scope_policy::{
    next_scope_value, scope_label, scope_selection_error, selected_scope_count,
    validate_all_scope_count,
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

    pub(crate) fn cycle_map_scope(&mut self) -> Result<()> {
        let tree = self.cached_map_scope_tree();
        let leaves: Vec<NestedProjectScope> = tree
            .as_ref()
            .map(|tree| eligible_leaf_scopes(tree).into_iter().cloned().collect())
            .unwrap_or_default();
        let current = self.map_option_string("scope");
        if self.confirm_pending_all_scope_review(current.as_deref(), tree.as_ref()) {
            return Ok(());
        }
        let next = next_scope_value(current.as_deref(), &leaves);
        self.apply_map_scope_choice(next, tree.as_ref(), leaves.len())
    }

    pub(crate) fn begin_map_text_edit(&mut self, row: MapRunConfigRowId) {
        let option = map_text_option(row).unwrap_or_default();
        let draft = self.map_string_list(option).join(", ");
        self.router
            .setup_mut()
            .map_run_config_mut()
            .begin_edit(row, draft);
    }

    pub(crate) fn commit_map_text_edit(&mut self) -> Result<()> {
        let state = self.router.setup().map_run_config();
        let row = state.edit().context("Map text editor is not open")?;
        let values = parse_string_list(state.draft());
        let option = map_text_option(row).context("selected Map row is not text")?;
        self.set_map_option(option, json!(values))?;
        self.router.setup_mut().map_run_config_mut().finish_edit();
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

    fn confirm_pending_all_scope_review(
        &mut self,
        current: Option<&str>,
        tree: Option<&kuzushi_core::NestedProjectScopeTree>,
    ) -> bool {
        let count = tree.map_or(0, |tree| eligible_leaf_scopes(tree).len());
        let review_key = tree.and_then(|tree| self.all_scope_review_key(tree).ok());
        let pending = current == Some(ALL_LEAF_SCOPES)
            && count > ALL_SCOPES_REVIEW_THRESHOLD
            && !review_key.as_deref().is_some_and(|key| {
                self.router
                    .setup()
                    .map_run_config()
                    .all_scopes_reviewed(key)
            });
        if pending {
            self.router
                .setup_mut()
                .map_run_config_mut()
                .set_all_scopes_reviewed(review_key);
            self.router.setup_mut().map_run_config_mut().clear_error();
        }
        pending
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

fn parse_string_list(draft: &str) -> Vec<String> {
    draft
        .split([',', '\n'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
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
    use super::{next_map_methodology, parse_string_list};

    #[test]
    fn first_class_methodology_toggles_stride_and_pasta_only() {
        assert_eq!(next_map_methodology(Some("stride")), "pasta");
        assert_eq!(next_map_methodology(Some("pasta")), "stride");
        assert_eq!(next_map_methodology(Some("dread")), "stride");
    }

    #[test]
    fn string_lists_accept_comma_and_line_delimiters() {
        assert_eq!(
            parse_string_list("docs/a.md, docs/b.md\nnotes/c.md"),
            vec!["docs/a.md", "docs/b.md", "notes/c.md"]
        );
    }
}
