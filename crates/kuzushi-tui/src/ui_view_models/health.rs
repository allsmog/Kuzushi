use crate::ShellApp;
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

fn model_runtime_row(app: &ShellApp) -> HealthRow {
    let Some(model) = app.config.model.as_deref() else {
        return health_row(
            HealthTone::Warn,
            "model/runtime",
            "no model selected",
            "run `model <n>` before LLM-backed tools",
        );
    };
    match kuzushi_core::runtime::validate_model_api_key_env(model, &app.config.runtime.api_key_env)
    {
        Ok(()) => health_row(
            HealthTone::Pass,
            "model/runtime",
            format!("{model} matches {}", app.config.runtime.api_key_env),
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
    let api_key_env = app.config.runtime.api_key_env.as_str();
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

fn scanner_row(check: &'static str, result: anyhow::Result<()>) -> HealthRow {
    match result {
        Ok(()) => health_row(HealthTone::Pass, check, "scanner binary found", "run scan"),
        Err(error) => health_row(HealthTone::Fail, check, error.to_string(), "tools missing"),
    }
}

fn codeql_db_row(app: &ShellApp) -> HealthRow {
    let Some(target) = app.target.as_deref() else {
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
        app.target
            .as_ref()
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
