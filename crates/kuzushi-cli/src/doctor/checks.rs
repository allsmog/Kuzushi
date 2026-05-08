use super::bridge::{current_dir_for_doctor, resolve_executable};
use super::DoctorCheck;
use kuzushi_core::{FindingStore, WorkspaceTarget};
use std::env;
use std::fs;
use std::path::Path;

pub(crate) fn check_findings_db(workspace: &WorkspaceTarget) -> DoctorCheck {
    let db_path = workspace.findings_db_path();
    let existed = db_path.exists();
    let check_path = if existed {
        db_path.clone()
    } else {
        workspace.state_dir().join(format!(
            ".doctor-findings-check-{}.sqlite3",
            std::process::id()
        ))
    };

    let check = match FindingStore::open(&check_path) {
        Ok(_) if existed => DoctorCheck::ok(
            "findings-db",
            format!("{} opened successfully", db_path.display()),
        ),
        Ok(_) => DoctorCheck::ok(
            "findings-db",
            format!(
                "{} is creatable; next `kuzushi scan <repo>` will initialize it",
                db_path.display()
            ),
        ),
        Err(error) => DoctorCheck::fail(
            "findings-db",
            format!("{} could not be opened: {error}", db_path.display()),
            "Fix .kuzushi/v2 permissions or move the workspace to a writable path.",
        ),
    };
    if !existed {
        remove_sqlite_file_set(&check_path);
    }
    check
}

pub(crate) fn remove_sqlite_file_set(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
    let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
}

pub(crate) fn check_scanner_binary(binary: &'static str) -> DoctorCheck {
    match resolve_executable(
        binary,
        env::var_os("PATH").as_deref(),
        &current_dir_for_doctor(),
    ) {
        Some(path) => DoctorCheck::ok(binary, format!("found {}", path.display())),
        None => {
            let next = match binary {
                "semgrep" => "Install Semgrep (`pipx install semgrep` or `brew install semgrep`) or pass a scanner binary in tool input.",
                "codeql" => "Install the CodeQL CLI or pass {\"binary\":\"/path/to/codeql\"} to codeql:scan.",
                _ => "Install the missing scanner binary or configure the tool input with an explicit path.",
            };
            DoctorCheck::warn(binary, format!("{binary} was not found on PATH"), next)
        }
    }
}

pub(crate) fn check_model_config(config: &kuzushi_core::V2Config) -> DoctorCheck {
    match config
        .model
        .as_deref()
        .map(str::trim)
        .filter(|model| !model.is_empty())
    {
        None => DoctorCheck::warn(
            "model",
            "no explicit model configured; static scanners still work",
            "Set `KUZUSHI_MODEL=provider:model` or add `model = \"provider:model\"` before using agentic tools.",
        ),
        Some(model) => match model.split_once(':') {
            Some((provider, name)) if !provider.trim().is_empty() && !name.trim().is_empty() => {
                DoctorCheck::ok(
                    "model",
                    format!(
                        "explicit model configured for provider {}",
                        provider.trim()
                    ),
                )
            }
            _ => DoctorCheck::fail(
                "model",
                format!("model must use non-empty provider:model syntax, got {model:?}"),
                "Set `KUZUSHI_MODEL=provider:model` or fix config.toml.",
            ),
        },
    }
}

pub(crate) fn check_auth_env(config: &kuzushi_core::V2Config) -> DoctorCheck {
    let name = config.runtime.api_key_env.trim();
    if name.is_empty() {
        return DoctorCheck::fail(
            "auth-env",
            "runtime.api_key_env is empty",
            "Set runtime.api_key_env to the name of an environment variable, not a secret value.",
        );
    }

    if env::var_os(name).is_some() {
        DoctorCheck::ok("auth-env", format!("{name} is set; value is hidden"))
    } else {
        DoctorCheck::warn(
            "auth-env",
            format!("{name} is not set"),
            format!("Export {name}=<token> before running model-backed tools."),
        )
    }
}
