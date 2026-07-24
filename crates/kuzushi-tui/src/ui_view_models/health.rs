use super::{
    configured_model_credential_readiness, context_snapshot_state, cost_model, format_session_cost,
    CredentialReadiness,
};
use crate::{
    app::PathState, HealthFooter, HealthSnapshot, HealthStatus, ShellApp, ViewDataState,
    ViewHealthChecks,
};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HealthTone {
    Pass,
    Warn,
    Fail,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HealthRow {
    pub(crate) tone: HealthTone,
    pub(crate) status: &'static str,
    pub(crate) check: &'static str,
    pub(crate) detail: String,
    pub(crate) next: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HealthModel {
    pub(crate) summary: String,
    pub(crate) rows: Vec<HealthRow>,
    pub(crate) commands: [&'static str; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HealthDisplayModel {
    pub(crate) status: HealthStatus,
    pub(crate) body_rows: Vec<String>,
    pub(crate) summary: String,
    pub(crate) footer: HealthFooter,
}

pub(crate) fn health_model(app: &ShellApp) -> HealthModel {
    let checks = cached_health_checks(app);
    let rows = vec![
        model_runtime_row(app),
        credential_row(app, checks.as_ref()),
        scanner_row("semgrep", checks.as_ref().map(|value| &value.semgrep_error)),
        scanner_row("codeql", checks.as_ref().map(|value| &value.codeql_error)),
        codeql_db_row(app),
        cpg_engine_row(),
        cpg_graph_row(app),
    ];
    HealthModel {
        summary: health_summary(&rows),
        rows,
        commands: ["doctor", "auth", "model <n>", "tools semgrep"],
    }
}

pub(crate) fn health_display_model(app: &ShellApp) -> HealthDisplayModel {
    app.health_snapshot()
        .cloned()
        .map(HealthDisplayModel::from)
        .unwrap_or_else(|| default_health_display_model(app))
}

impl From<HealthSnapshot> for HealthDisplayModel {
    fn from(snapshot: HealthSnapshot) -> Self {
        let summary = snapshot.footer.stage.clone();
        Self {
            status: snapshot.status,
            body_rows: snapshot.body_rows,
            summary,
            footer: snapshot.footer,
        }
    }
}

fn default_health_display_model(app: &ShellApp) -> HealthDisplayModel {
    let model = health_model(app);
    HealthDisplayModel {
        status: default_status(app),
        body_rows: default_body_rows(&model),
        summary: model.summary.clone(),
        footer: default_footer(app, &model),
    }
}

fn default_status(app: &ShellApp) -> HealthStatus {
    HealthStatus {
        target: app
            .target()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string()),
        ctx: health_context_label(context_snapshot_state(app)).to_string(),
        model: app
            .config()
            .model
            .clone()
            .unwrap_or_else(|| "unconfigured".to_string()),
        module: "doctor".to_string(),
        cost: default_cost(app),
    }
}

fn health_context_label(state: &str) -> &'static str {
    match state {
        "present" => "✓ built",
        "malformed" => "! malformed",
        _ => "not built",
    }
}

fn default_cost(app: &ShellApp) -> String {
    cost_model(app)
        .budget_status
        .map(|status| status.cells[1].clone())
        .unwrap_or_else(|| format_session_cost(0.0))
}

fn default_body_rows(model: &HealthModel) -> Vec<String> {
    let mut rows = vec![
        " --:--:--  ●  doctor".to_string(),
        String::new(),
        " -- CURRENT PREFLIGHT".to_string(),
    ];
    rows.extend(model.rows.iter().map(default_check_row));
    rows
}

fn default_check_row(row: &HealthRow) -> String {
    let next = optional_next_hint(row);
    format!(
        "  {}  {:<30} {}{}",
        health_symbol(row.tone),
        row.check,
        row.detail,
        next
    )
}

fn optional_next_hint(row: &HealthRow) -> String {
    if row.next.is_empty() {
        String::new()
    } else {
        format!("  ·  {}", row.next)
    }
}

fn health_symbol(tone: HealthTone) -> &'static str {
    match tone {
        HealthTone::Pass => "✓",
        HealthTone::Warn => "!",
        HealthTone::Fail => "✗",
        HealthTone::Pending => "…",
    }
}

fn default_footer(app: &ShellApp, model: &HealthModel) -> HealthFooter {
    HealthFooter {
        stage: model.summary.clone(),
        findings: app.findings_total_count(),
        keybinds: vec![
            ("/auth".to_string(), "login".to_string()),
            ("/model".to_string(), "select".to_string()),
            ("j/k".to_string(), "row".to_string()),
        ],
        prompt_module: Some("doctor".to_string()),
    }
}

fn model_runtime_row(app: &ShellApp) -> HealthRow {
    let Some(model) = app.config().model.as_deref() else {
        return health_row(
            HealthTone::Warn,
            "model/runtime",
            "no model selected",
            "run `model <n>` before LLM-backed tools",
        );
    };
    match kuzushi_core::runtime::bridge_api_key_env_for_model(
        model,
        &app.config().runtime.api_key_env,
    ) {
        Ok(api_key_env) => health_row(
            HealthTone::Pass,
            "model/runtime",
            format!("{model} uses {api_key_env}"),
            "run tools normally",
        ),
        Err(error) => health_row(
            HealthTone::Fail,
            "model/runtime",
            error.to_string(),
            "config",
        ),
    }
}

fn credential_row(app: &ShellApp, checks: Option<&ViewHealthChecks>) -> HealthRow {
    let api_key_env = effective_credential_env(app);
    if let Some(row) = configured_credential_row(app, api_key_env) {
        return row;
    }
    let Some(checks) = checks else {
        return loading_health_row("credentials");
    };
    if checks.credential_set {
        return health_row(
            HealthTone::Pass,
            "credentials",
            format!("{api_key_env}=set; value hidden"),
            "run tools normally",
        );
    }
    health_row(
        HealthTone::Fail,
        "credentials",
        format!("{api_key_env}=missing"),
        "export the key or run `auth`",
    )
}

fn configured_credential_row(app: &ShellApp, api_key_env: &str) -> Option<HealthRow> {
    let detail = match configured_model_credential_readiness(app) {
        CredentialReadiness::Session => "session credential accepted; value hidden".to_string(),
        CredentialReadiness::StoredOAuth => "stored OAuth ready; value hidden".to_string(),
        CredentialReadiness::ApiKey => format!("{api_key_env}=set; value hidden"),
        CredentialReadiness::NotRequired => {
            return Some(health_row(
                HealthTone::Warn,
                "credentials",
                "no model selected",
                "deterministic tools can still run",
            ));
        }
        CredentialReadiness::Missing => return None,
    };
    Some(health_row(
        HealthTone::Pass,
        "credentials",
        detail,
        "run tools normally",
    ))
}

fn effective_credential_env(app: &ShellApp) -> &str {
    let Some(model) = app.config().model.as_deref() else {
        return app.config().runtime.api_key_env.as_str();
    };
    match kuzushi_core::runtime::bridge_api_key_env_for_model(
        model,
        &app.config().runtime.api_key_env,
    ) {
        Ok(env) if env == "ANTHROPIC_API_KEY" => "ANTHROPIC_API_KEY",
        Ok(env) if env == "OPENAI_API_KEY" => "OPENAI_API_KEY",
        _ => app.config().runtime.api_key_env.as_str(),
    }
}

fn scanner_row(check: &'static str, error: Option<&Option<String>>) -> HealthRow {
    match error {
        Some(None) => health_row(HealthTone::Pass, check, "scanner binary found", "run scan"),
        Some(Some(error)) => health_row(HealthTone::Fail, check, error, "tools missing"),
        None => loading_health_row(check),
    }
}

fn codeql_db_row(app: &ShellApp) -> HealthRow {
    let Some(target) = app.target() else {
        return health_row(
            HealthTone::Warn,
            "codeql db",
            "no target selected",
            "target <path>",
        );
    };
    let path = existing_codeql_db(app, target);
    match path {
        Some(path) => health_row(
            HealthTone::Pass,
            "codeql db",
            path.display(),
            "backend=codeql",
        ),
        None => health_row(
            HealthTone::Warn,
            "codeql db",
            format!("no DB under {}", target.display()),
            "run taint-iris-next:codeql-db or codeql database create",
        ),
    }
}

fn cpg_engine_row() -> HealthRow {
    health_row(
        HealthTone::Pass,
        "cpg",
        format!(
            "cpg-rs engine compiled in (graph shape v{})",
            kuzushi_core::CPG_GRAPH_SHAPE_VERSION
        ),
        "backend=cpg-rs",
    )
}

fn cpg_graph_row(app: &ShellApp) -> HealthRow {
    let Some(target) = app.target() else {
        return health_row(
            HealthTone::Warn,
            "cpg graphs",
            "no target selected",
            "target <path>",
        );
    };
    let dir = kuzushi_core::cpg_artifact_dir(target);
    if matches!(cached_path_state(app, &dir), PathState::Directory) {
        return health_row(
            HealthTone::Pass,
            "cpg graphs",
            dir.display(),
            "backend=cpg-rs",
        );
    }
    health_row(
        HealthTone::Pass,
        "cpg graphs",
        "none prebuilt; graphs build implicitly on first hunt",
        "run cpg:build to prebuild",
    )
}

fn existing_codeql_db(app: &ShellApp, target: &Path) -> Option<PathBuf> {
    [
        kuzushi_core::workspace_codeql_db_path(target),
        kuzushi_core::legacy_workspace_codeql_db_path(target),
        kuzushi_core::legacy_codeql_db_path(target),
    ]
    .into_iter()
    .find(|path| matches!(cached_path_state(app, path), PathState::Directory))
}

fn cached_health_checks(app: &ShellApp) -> Option<ViewHealthChecks> {
    let credential_env = effective_credential_env(app);
    match app
        .workbench_cache()
        .borrow()
        .cached_health_checks(app.target(), credential_env)
    {
        ViewDataState::Ready(checks) => Some(checks),
        ViewDataState::NotRequested | ViewDataState::Loading => None,
    }
}

fn cached_path_state(app: &ShellApp, path: &Path) -> PathState {
    let Some(target) = app.target() else {
        return PathState::Missing;
    };
    match app
        .workbench_cache()
        .borrow()
        .cached_path_state(target, path)
    {
        ViewDataState::Ready(state) => state,
        ViewDataState::NotRequested | ViewDataState::Loading => PathState::Missing,
    }
}

fn loading_health_row(check: &'static str) -> HealthRow {
    health_row(
        HealthTone::Pending,
        check,
        "check loading",
        "wait for health refresh",
    )
}

fn health_summary(rows: &[HealthRow]) -> String {
    if rows.iter().any(|row| row.tone == HealthTone::Pending) {
        return "health checks loading".to_string();
    }
    let fail = rows
        .iter()
        .filter(|row| row.tone == HealthTone::Fail)
        .count();
    let warn = rows
        .iter()
        .filter(|row| row.tone == HealthTone::Warn)
        .count();
    if fail == 0 && warn == 0 {
        return "health ok".to_string();
    }
    format!("health: {fail} failing, {warn} warning")
}

fn health_row(
    tone: HealthTone,
    check: &'static str,
    detail: impl ToString,
    next: impl ToString,
) -> HealthRow {
    HealthRow {
        tone,
        status: health_status(tone),
        check,
        detail: detail.to_string(),
        next: next.to_string(),
    }
}

fn health_status(tone: HealthTone) -> &'static str {
    match tone {
        HealthTone::Pass => "pass",
        HealthTone::Warn => "warn",
        HealthTone::Fail => "fail",
        HealthTone::Pending => "loading",
    }
}

#[cfg(test)]
mod tests;
