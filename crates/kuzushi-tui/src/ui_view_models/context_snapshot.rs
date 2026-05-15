use super::compact_target_path;
use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextSnapshotModel {
    pub(crate) snapshot: String,
    pub(crate) state: &'static str,
    pub(crate) status: String,
    pub(crate) running: Option<ContextSnapshotRunning>,
    pub(crate) details: Option<ContextSnapshotDetails>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextSnapshotRunning {
    pub(crate) tool: String,
    pub(crate) glyph: &'static str,
    pub(crate) message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextSnapshotDetails {
    pub(crate) target: String,
    pub(crate) discovery: String,
    pub(crate) files: String,
    pub(crate) languages: String,
    pub(crate) frameworks: String,
    pub(crate) generated: String,
    pub(crate) stale: String,
}

pub(crate) fn context_snapshot_model(app: &ShellApp) -> ContextSnapshotModel {
    let view = &app.context_view;
    let running = context_running(app);
    ContextSnapshotModel {
        snapshot: view
            .snapshot_path
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/context-snapshot.json".to_string()),
        state: if view.exists { "present" } else { "missing" },
        status: context_status(app, running.as_ref()),
        running,
        details: view.exists.then(|| ContextSnapshotDetails::from_app(app)),
    }
}

fn context_running(app: &ShellApp) -> Option<ContextSnapshotRunning> {
    app.running_tool_name()
        .filter(|tool| matches!(*tool, "context:build" | "context-lite:index"))
        .map(|tool| ContextSnapshotRunning {
            tool: tool.to_string(),
            glyph: "⏵",
            message: "building snapshot; this view updates when the worker finishes",
        })
}

fn context_status(app: &ShellApp, running: Option<&ContextSnapshotRunning>) -> String {
    running
        .map(|running| {
            format!(
                "{} {} indexing repository context",
                app.spinner_glyph(),
                running.tool
            )
        })
        .unwrap_or_else(|| app.context_view.status.clone())
}

impl ContextSnapshotDetails {
    fn from_app(app: &ShellApp) -> Self {
        let view = &app.context_view;
        Self {
            target: view.target.clone().unwrap_or_else(|| "unknown".to_string()),
            discovery: view
                .discovery
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            files: files_label(view.files_indexed, view.total_files),
            languages: join_or_dash(&view.languages),
            frameworks: join_or_dash(&view.frameworks),
            generated: join_or_dash(&view.generated_slices),
            stale: join_or_dash(&view.stale_slices),
        }
    }
}

fn files_label(indexed: Option<u64>, total: Option<u64>) -> String {
    format!(
        "indexed={} total={}",
        optional_count(indexed),
        optional_count(total)
    )
}

fn optional_count(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".to_string())
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests;
