use super::{
    context_snapshot_model, dfd_model, findings_model, scoped_target_path_label,
    threat_summary_review,
};
use crate::app::ProjectScopeTreeState;
use crate::{ShellApp, ViewDataState};

mod context_columns;
mod document_rows;
pub(crate) use context_columns::{
    project_context_columns, ProjectContextCell, ProjectContextRow, ProjectContextTable,
    CONTEXT_COLUMN_RULE,
};
use document_rows::project_model_document_rows;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectModel {
    pub(crate) scope_label: String,
    pub(crate) revision_label: String,
    pub(crate) rows: Vec<ProjectModelRow>,
    pub(crate) next_hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectModelRow {
    pub(crate) section: &'static str,
    pub(crate) origin: ProjectModelOrigin,
    pub(crate) state: &'static str,
    pub(crate) summary: String,
    pub(crate) action: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectModelOrigin {
    Local,
    #[allow(dead_code)]
    Inherited,
    Missing,
    Stale,
}

impl ProjectModelOrigin {
    pub(crate) fn glyph(self) -> &'static str {
        match self {
            Self::Local => "◆",
            Self::Inherited => "⤓",
            Self::Missing => "○",
            Self::Stale => "⚠",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Inherited => "inherited",
            Self::Missing => "missing",
            Self::Stale => "stale",
        }
    }
}

pub(crate) fn project_model(app: &ShellApp) -> ProjectModel {
    let mut rows = vec![scope_tree_row(app)];
    if let Some(document_rows) = project_model_document_rows(app) {
        rows.extend(document_rows);
    } else {
        let context = context_snapshot_model(app);
        let threat = threat_summary_review(app);
        let dfd = dfd_model(app);
        rows.extend([
            context_feed_row(&context),
            inventory_row(&context),
            threat_model_row(&threat),
            dfd_row(&dfd),
        ]);
    }
    let findings = findings_model(app);
    rows.push(review_surface_row(&findings));
    ProjectModel {
        scope_label: project_scope_label(app),
        revision_label: project_revision_label(app),
        rows,
        next_hint: "Next: context build, threats summary, scan, project model",
    }
}

fn project_scope_label(app: &ShellApp) -> String {
    app.target()
        .map(|_| scoped_target_path_label(app))
        .unwrap_or_else(|| "no target selected".to_string())
}

pub(crate) fn project_revision_label(app: &ShellApp) -> String {
    if app.target().is_none() {
        return "rev:unknown".to_string();
    }
    match app
        .workbench_cache()
        .borrow()
        .cached_git_metadata(app.target())
    {
        ViewDataState::Ready(Some(git)) => {
            let sha = git.sha.chars().take(7).collect::<String>();
            format!("rev:{}{}", sha, if git.dirty { "*" } else { "" })
        }
        // "unknown" is a terminal claim; while the probe is merely in
        // flight the honest state is "checking".
        ViewDataState::NotRequested | ViewDataState::Loading => "rev:checking…".to_string(),
        ViewDataState::Ready(None) => "rev:unknown".to_string(),
    }
}

fn scope_tree_row(app: &ShellApp) -> ProjectModelRow {
    if app.target().is_none() {
        return ProjectModelRow {
            section: "scope tree",
            origin: ProjectModelOrigin::Missing,
            state: "missing",
            summary: "select a target to discover nested project scopes".to_string(),
            action: "target <path>",
        };
    };
    match app
        .workbench_cache()
        .borrow()
        .cached_project_scope_tree(app.target())
    {
        ViewDataState::Ready(ProjectScopeTreeState::Persisted(tree)) => {
            scope_tree_project_row(&tree, ProjectModelOrigin::Local, "present")
        }
        ViewDataState::Ready(ProjectScopeTreeState::RootOnly) => root_only_scope_tree_row(),
        ViewDataState::Ready(ProjectScopeTreeState::Unreadable(error)) => ProjectModelRow {
            section: "scope tree",
            origin: ProjectModelOrigin::Stale,
            state: "unreadable",
            summary: format!("scope tree could not be read: {error}"),
            action: "target <path>",
        },
        ViewDataState::NotRequested | ViewDataState::Loading => root_only_scope_tree_row(),
    }
}

fn root_only_scope_tree_row() -> ProjectModelRow {
    ProjectModelRow {
        section: "scope tree",
        origin: ProjectModelOrigin::Missing,
        state: "root only",
        summary: "no persisted nested scopes yet; run `next` to map project boundaries".to_string(),
        action: "next",
    }
}

fn scope_tree_project_row(
    tree: &kuzushi_core::NestedProjectScopeTree,
    origin: ProjectModelOrigin,
    state: &'static str,
) -> ProjectModelRow {
    let nested = tree.non_root_scopes().collect::<Vec<_>>();
    let summary = if nested.is_empty() {
        "root scope only".to_string()
    } else {
        format!(
            "{} nested scope(s): {}",
            nested.len(),
            nested_scope_summary(&nested)
        )
    };
    ProjectModelRow {
        section: "scope tree",
        origin,
        state,
        summary,
        action: "project model",
    }
}

fn nested_scope_summary(scopes: &[&kuzushi_core::NestedProjectScope]) -> String {
    let mut parts = scopes
        .iter()
        .take(4)
        .map(|scope| format!("{} {}", scope.kind.label(), scope.rel_path))
        .collect::<Vec<_>>();
    if scopes.len() > parts.len() {
        parts.push(format!("+{} more", scopes.len() - parts.len()));
    }
    parts.join(", ")
}

fn context_feed_row(context: &super::ContextSnapshotModel) -> ProjectModelRow {
    ProjectModelRow {
        section: "context feed",
        origin: origin_for_context_state(context.state),
        state: context.state,
        summary: format!("{} · {}", context.snapshot, context.status),
        action: if context.snapshot_present {
            "context status"
        } else {
            "context build"
        },
    }
}

fn inventory_row(context: &super::ContextSnapshotModel) -> ProjectModelRow {
    let summary = context
        .details
        .as_ref()
        .map(|details| {
            format!(
                "{} files · languages {} · frameworks {}",
                details.files, details.languages, details.frameworks
            )
        })
        .unwrap_or_else(|| "inventory is unavailable until context exists".to_string());
    ProjectModelRow {
        section: "inventory",
        origin: origin_for_context_state(context.state),
        state: context.state,
        summary,
        action: "context build",
    }
}

fn threat_model_row(threat: &super::ThreatSummaryReview) -> ProjectModelRow {
    let present = threat.status == "current persisted model";
    ProjectModelRow {
        section: "threat model",
        origin: if present {
            ProjectModelOrigin::Local
        } else {
            ProjectModelOrigin::Missing
        },
        state: if present { "present" } else { "missing" },
        summary: format!(
            "{} · threats {} · assumptions {}",
            threat.summary,
            threat.threats,
            assumption_count_label(threat, present)
        ),
        action: "threats summary",
    }
}

/// Without a persisted model the review's assumption list carries guidance
/// copy, not measured assumptions, so the row reports an em-dash instead.
fn assumption_count_label(threat: &super::ThreatSummaryReview, present: bool) -> String {
    if present {
        threat.assumptions.len().to_string()
    } else {
        "—".to_string()
    }
}

fn dfd_row(dfd: &super::DfdModel) -> ProjectModelRow {
    ProjectModelRow {
        section: "data flow",
        origin: if dfd.empty_hint.is_none() {
            ProjectModelOrigin::Local
        } else {
            ProjectModelOrigin::Missing
        },
        state: if dfd.empty_hint.is_none() {
            "present"
        } else {
            "missing"
        },
        summary: dfd.empty_hint.clone().unwrap_or_else(|| {
            format!(
                "{} nodes · {} flows · zones {}",
                dfd.nodes.len(),
                dfd.flows.len(),
                dfd.zones.join(", ")
            )
        }),
        action: "workbench",
    }
}

fn review_surface_row(findings: &super::FindingsModel) -> ProjectModelRow {
    ProjectModelRow {
        section: "review surface",
        origin: if findings.total == 0 {
            ProjectModelOrigin::Missing
        } else {
            ProjectModelOrigin::Local
        },
        state: if findings.total == 0 {
            "missing"
        } else {
            "present"
        },
        summary: format!(
            "{} items · {} triaged · {} pending",
            findings.total, findings.triaged, findings.pending
        ),
        action: "findings",
    }
}

fn origin_for_context_state(state: &str) -> ProjectModelOrigin {
    match state {
        "current" => ProjectModelOrigin::Local,
        "stale" | "unverifiable" | "malformed" => ProjectModelOrigin::Stale,
        _ => ProjectModelOrigin::Missing,
    }
}

#[cfg(test)]
mod tests;
