use super::dependencies::{direct_dependents, topological_order, transitive_dependencies};
use super::task_id::PlanningTaskId;
use super::task_row::PlanningTaskRow;
use std::collections::BTreeSet;

/// Outcome of toggling a row in the planning picker. Reported back to
/// the caller (the key handler) so it can emit log lines without
/// having to know the dependency logic itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToggleOutcome {
    /// Row toggled on. `auto_added` lists transitively-included
    /// dependencies that were auto-checked at the same time.
    On {
        task: PlanningTaskId,
        auto_added: Vec<PlanningTaskId>,
    },
    /// Row toggled off cleanly (no dependents were still selected).
    Off { task: PlanningTaskId },
    /// Refused to toggle off because dependents are still selected.
    Blocked {
        task: PlanningTaskId,
        dependents: Vec<PlanningTaskId>,
    },
    /// Tried to toggle a row whose CLI requirement isn't met
    /// (joern-parse / codeql not on PATH).
    MissingCli {
        task: PlanningTaskId,
        cli: &'static str,
    },
}

pub fn toggle_planning_row(
    task: PlanningTaskId,
    rows: &[PlanningTaskRow],
    selected: &mut BTreeSet<PlanningTaskId>,
) -> ToggleOutcome {
    let row = match rows.iter().find(|row| row.id == task) {
        Some(row) => row,
        None => return ToggleOutcome::Off { task },
    };
    if !row.cli_available {
        return ToggleOutcome::MissingCli {
            task,
            cli: row.required_cli.unwrap_or("required binary"),
        };
    }
    if selected.contains(&task) {
        toggle_off(task, selected)
    } else {
        toggle_on(task, selected)
    }
}

fn toggle_on(task: PlanningTaskId, selected: &mut BTreeSet<PlanningTaskId>) -> ToggleOutcome {
    let mut auto_added = Vec::new();
    for dep in transitive_dependencies(task) {
        if selected.insert(dep) {
            auto_added.push(dep);
        }
    }
    selected.insert(task);
    ToggleOutcome::On { task, auto_added }
}

fn toggle_off(task: PlanningTaskId, selected: &mut BTreeSet<PlanningTaskId>) -> ToggleOutcome {
    let still_needed: Vec<PlanningTaskId> = direct_dependents(task)
        .into_iter()
        .filter(|dep| selected.contains(dep))
        .collect();
    if !still_needed.is_empty() {
        return ToggleOutcome::Blocked {
            task,
            dependents: still_needed,
        };
    }
    selected.remove(&task);
    ToggleOutcome::Off { task }
}

/// Build the ordered execution plan from the currently-selected rows.
/// Cached rows are filtered out (they don't need to be re-run).
pub fn build_execution_plan(
    rows: &[PlanningTaskRow],
    selected: &BTreeSet<PlanningTaskId>,
) -> Vec<PlanningTaskId> {
    let runnable: BTreeSet<PlanningTaskId> = selected
        .iter()
        .copied()
        .filter(|task| {
            rows.iter()
                .find(|row| row.id == *task)
                .map(|row| {
                    row.cli_available
                        && !matches!(row.artifact_state, super::task_row::ArtifactState::Cached)
                })
                .unwrap_or(false)
        })
        .collect();
    topological_order(&runnable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::onboarding::task_row::ArtifactState;
    use std::path::PathBuf;
    use PlanningTaskId::*;

    fn row(id: PlanningTaskId, state: ArtifactState) -> PlanningTaskRow {
        PlanningTaskRow {
            id,
            label: id.label(),
            tool_name: id.tool_name(),
            artifact_path: PathBuf::from("/dev/null"),
            artifact_state: state,
            model_backed: id.is_model_backed(),
            required_cli: id.required_cli(),
            cli_available: id.required_cli().is_none(),
        }
    }

    #[test]
    fn toggle_on_auto_adds_context() {
        let rows = vec![
            row(GatherRepoContext, ArtifactState::Missing),
            row(BuildXRay, ArtifactState::Missing),
        ];
        let mut selected = BTreeSet::new();
        let outcome = toggle_planning_row(BuildXRay, &rows, &mut selected);
        match outcome {
            ToggleOutcome::On { task, auto_added } => {
                assert_eq!(task, BuildXRay);
                assert_eq!(auto_added, vec![GatherRepoContext]);
            }
            other => panic!("expected On, got {other:?}"),
        }
        assert!(selected.contains(&GatherRepoContext));
        assert!(selected.contains(&BuildXRay));
    }

    #[test]
    fn toggle_off_blocked_when_dependents_present() {
        let rows = vec![
            row(GatherRepoContext, ArtifactState::Missing),
            row(BuildXRay, ArtifactState::Missing),
        ];
        let mut selected = BTreeSet::new();
        selected.insert(GatherRepoContext);
        selected.insert(BuildXRay);
        let outcome = toggle_planning_row(GatherRepoContext, &rows, &mut selected);
        match outcome {
            ToggleOutcome::Blocked { task, dependents } => {
                assert_eq!(task, GatherRepoContext);
                assert_eq!(dependents, vec![BuildXRay]);
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
        assert!(selected.contains(&GatherRepoContext));
    }

    #[test]
    fn toggle_off_succeeds_after_dependents_removed() {
        let rows = vec![
            row(GatherRepoContext, ArtifactState::Missing),
            row(BuildXRay, ArtifactState::Missing),
        ];
        let mut selected = BTreeSet::new();
        selected.insert(GatherRepoContext);
        let outcome = toggle_planning_row(GatherRepoContext, &rows, &mut selected);
        assert_eq!(
            outcome,
            ToggleOutcome::Off {
                task: GatherRepoContext
            }
        );
        assert!(selected.is_empty());
    }

    #[test]
    fn execution_plan_skips_cached_rows() {
        let rows = vec![
            row(GatherRepoContext, ArtifactState::Cached),
            row(BuildXRay, ArtifactState::Missing),
        ];
        let mut selected = BTreeSet::new();
        selected.insert(GatherRepoContext);
        selected.insert(BuildXRay);
        let plan = build_execution_plan(&rows, &selected);
        assert_eq!(plan, vec![BuildXRay]);
    }

    #[test]
    fn cpg_with_missing_cli_is_blocked() {
        // CPG row without joern-parse on PATH cannot be toggled on.
        let rows = vec![PlanningTaskRow {
            id: BuildCodePropertyGraph,
            label: BuildCodePropertyGraph.label(),
            tool_name: BuildCodePropertyGraph.tool_name(),
            artifact_path: PathBuf::from("/dev/null"),
            artifact_state: ArtifactState::Missing,
            model_backed: false,
            required_cli: Some("joern-parse"),
            cli_available: false,
        }];
        let mut selected = BTreeSet::new();
        let outcome = toggle_planning_row(BuildCodePropertyGraph, &rows, &mut selected);
        assert_eq!(
            outcome,
            ToggleOutcome::MissingCli {
                task: BuildCodePropertyGraph,
                cli: "joern-parse"
            }
        );
        assert!(selected.is_empty());
    }
}
