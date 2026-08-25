use super::workspace_artifact_path_label;
use crate::ShellApp;
use std::sync::OnceLock;

static CONTEXT_SNAPSHOT_RELATIVE_PATH: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextSnapshotModel {
    pub(crate) snapshot: String,
    pub(crate) snapshot_present: bool,
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
    pub(crate) enrichment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainContextModel {
    pub(crate) title: &'static str,
    pub(crate) summary_rows: Vec<String>,
    pub(crate) body_rows: Vec<String>,
    pub(crate) next_hint: &'static str,
}

pub(crate) fn context_snapshot_model(app: &ShellApp) -> ContextSnapshotModel {
    let view = app.domain().context_view();
    let running = context_running(app);
    let snapshot_present = view.exists;
    let state = context_snapshot_state(app);
    ContextSnapshotModel {
        snapshot: view
            .snapshot_path
            .as_ref()
            .map(|path| workspace_artifact_path_label(app, path))
            .unwrap_or_else(|| context_snapshot_relative_path().to_string()),
        snapshot_present,
        state,
        status: context_status(app, running.as_ref()),
        running,
        details: snapshot_present.then(|| ContextSnapshotDetails::from_app(app)),
    }
}

pub(crate) fn plain_context_model(app: &ShellApp) -> PlainContextModel {
    PlainContextModel::from_context_snapshot_model(context_snapshot_model(app))
}

impl PlainContextModel {
    fn from_context_snapshot_model(model: ContextSnapshotModel) -> Self {
        PlainContextModel {
            title: "CONTEXT",
            summary_rows: vec![
                format!("snapshot: {}", model.snapshot),
                format!("state: {}", model.state),
                format!("status: {}", model.status),
            ],
            body_rows: plain_context_body_rows(model.state, &model.status, model.details),
            next_hint: "Next: context build, context status, context regen repo",
        }
    }
}

fn plain_context_body_rows(
    state: &'static str,
    status: &str,
    details: Option<ContextSnapshotDetails>,
) -> Vec<String> {
    match (state, details) {
        ("malformed", _) => malformed_context_rows(status),
        (_, Some(details)) => plain_context_detail_rows(details),
        (_, None) => missing_context_rows(),
    }
}

fn missing_context_rows() -> Vec<String> {
    vec![
        String::new(),
        format!(
            "No context snapshot exists yet. Next: context build writes {}.",
            context_snapshot_relative_path()
        ),
    ]
}

fn malformed_context_rows(status: &str) -> Vec<String> {
    if status.contains("(not a file)") {
        return vec![
            String::new(),
            format!(
                "Context snapshot path is not a file. Next: context build rewrites {}.",
                context_snapshot_relative_path()
            ),
        ];
    }

    vec![
        String::new(),
        format!(
            "Context snapshot is malformed JSON. Next: context build rewrites {}.",
            context_snapshot_relative_path()
        ),
    ]
}

pub(crate) fn context_snapshot_relative_path() -> &'static str {
    CONTEXT_SNAPSHOT_RELATIVE_PATH
        .get_or_init(|| {
            kuzushi_core::context_snapshot_path("")
                .display()
                .to_string()
        })
        .as_str()
}

fn plain_context_detail_rows(details: ContextSnapshotDetails) -> Vec<String> {
    vec![
        format!("target: {}", details.target),
        format!("discovery: {}", details.discovery),
        format!("files: {}", details.files),
        format!("languages: {}", details.languages),
        format!("frameworks: {}", details.frameworks),
        format!("generated: {}", details.generated),
        format!("stale: {}", details.stale),
        format!("enrichment: {}", details.enrichment),
    ]
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
        .unwrap_or_else(|| app.domain().context_view().status.clone())
}

pub(crate) fn context_snapshot_state(app: &ShellApp) -> &'static str {
    let view = app.domain().context_view();
    if let Some(freshness) = view.freshness.as_ref() {
        return match freshness {
            kuzushi_core::context::ContextSnapshotFreshness::Current => "current",
            kuzushi_core::context::ContextSnapshotFreshness::Stale(_) => "stale",
            kuzushi_core::context::ContextSnapshotFreshness::Unverifiable(_) => "unverifiable",
        };
    }
    if view.status.starts_with("malformed context snapshot") {
        "malformed"
    } else {
        "missing"
    }
}

impl ContextSnapshotDetails {
    fn from_app(app: &ShellApp) -> Self {
        let view = app.domain().context_view();
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
            enrichment: enrichment_label(view.enrichment_claims, view.enrichment_model.as_deref()),
        }
    }
}

fn enrichment_label(claims: usize, model: Option<&str>) -> String {
    if claims == 0 {
        return "not run".to_string();
    }
    match model {
        Some(model) => format!("{claims} source-cited claim(s) · {model}"),
        None => format!("{claims} source-cited claim(s) · model unrecorded"),
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
