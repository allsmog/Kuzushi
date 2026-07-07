use super::{cost_model, format_session_cost};
use crate::{HealthFooter, HealthSnapshot, HealthStatus, ShellApp};
use kuzushi_core::{executable_on_path, CodeqlScanner, ScanEngine, SemgrepScanner};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HealthTone {
    Pass,
    Warn,
    Fail,
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
    pub(crate) footer: HealthFooter,
}

pub(crate) fn health_model(app: &ShellApp) -> HealthModel {
    let rows = vec![
        model_runtime_row(app),
        credential_row(app),
        scanner_row("semgrep", SemgrepScanner::default().preflight()),
        scanner_row("codeql", CodeqlScanner::default().preflight()),
        codeql_db_row(app),
        joern_cli_row(),
        joern_cpg_row(app),
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
        Self {
            status: snapshot.status,
            body_rows: snapshot.body_rows,
            footer: snapshot.footer,
        }
    }
}

fn default_health_display_model(app: &ShellApp) -> HealthDisplayModel {
    let model = health_model(app);
    HealthDisplayModel {
        status: default_status(app),
        body_rows: default_body_rows(&model),
        footer: default_footer(app, &model),
    }
}

fn default_status(app: &ShellApp) -> HealthStatus {
    HealthStatus {
        target: app
            .target()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string()),
        ctx: "live".to_string(),
        model: app
            .config()
            .model
            .clone()
            .unwrap_or_else(|| "unconfigured".to_string()),
        module: "doctor".to_string(),
        cost: default_cost(app),
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
    rows.push(String::new());
    rows.push(" -- SUMMARY".to_string());
    rows.push(format!("   {}", model.summary));
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

fn credential_row(app: &ShellApp) -> HealthRow {
    let api_key_env = effective_credential_env(app);
    if env_is_set(api_key_env) {
        return health_row(
            HealthTone::Pass,
            "credential env",
            format!("{api_key_env}=set; value hidden"),
            "run tools normally",
        );
    }
    health_row(
        HealthTone::Fail,
        "credential env",
        format!("{api_key_env}=missing"),
        "export the key or run `auth`",
    )
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

fn scanner_row(check: &'static str, result: anyhow::Result<()>) -> HealthRow {
    match result {
        Ok(()) => health_row(HealthTone::Pass, check, "scanner binary found", "run scan"),
        Err(error) => health_row(HealthTone::Fail, check, error.to_string(), "tools missing"),
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
    let path = existing_codeql_db(target);
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

fn joern_cli_row() -> HealthRow {
    if let Some(path) = joern_launcher_path() {
        return health_row(HealthTone::Pass, "joern", path.display(), "backend=joern");
    }
    health_row(
        HealthTone::Fail,
        "joern",
        "joern launcher not found",
        "install Joern or set KUZUSHI_JOERN_BIN",
    )
}

fn joern_cpg_row(app: &ShellApp) -> HealthRow {
    let Some(path) = joern_cpg_path(app) else {
        return health_row(
            HealthTone::Warn,
            "joern cpg",
            "no target selected",
            "target <path>",
        );
    };
    if path.exists() {
        return health_row(
            HealthTone::Pass,
            "joern cpg",
            path.display(),
            "backend=joern",
        );
    }
    health_row(
        HealthTone::Warn,
        "joern cpg",
        format!("missing {}", path.display()),
        "run cpg:build or joern-parse",
    )
}

fn existing_codeql_db(target: &Path) -> Option<PathBuf> {
    [
        kuzushi_core::workspace_codeql_db_path(target),
        kuzushi_core::legacy_codeql_db_path(target),
    ]
    .into_iter()
    .find(|path| path.is_dir())
}

fn joern_launcher_path() -> Option<PathBuf> {
    configured_binary("KUZUSHI_JOERN_BIN")
        .or_else(|| executable_on_path("joern"))
        .or_else(|| {
            first_existing(&[
                "/opt/joern/joern-cli/joern",
                "/usr/local/bin/joern",
                "/usr/bin/joern",
            ])
        })
}

fn joern_cpg_path(app: &ShellApp) -> Option<PathBuf> {
    configured_path("KUZUSHI_JOERN_CPG").or_else(|| {
        app.target()
            .map(|target| target.join(".kuzushi").join("cpg.bin"))
    })
}

fn configured_binary(name: &str) -> Option<PathBuf> {
    let path = configured_path(name)?;
    path.is_file().then_some(path)
}

fn configured_path(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os(name)?);
    (!path.as_os_str().is_empty()).then_some(path)
}

fn first_existing(paths: &[&str]) -> Option<PathBuf> {
    paths.iter().map(PathBuf::from).find(|path| path.is_file())
}

fn env_is_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

fn health_summary(rows: &[HealthRow]) -> String {
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
    }
}
