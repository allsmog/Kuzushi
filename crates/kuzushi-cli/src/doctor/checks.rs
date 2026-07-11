use super::bridge::{current_dir_for_doctor, resolve_executable};
use super::DoctorCheck;
use kuzushi_core::{CargoAuditScanner, FindingStore, WorkspaceTarget};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

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
            "Fix .kuzushi/v3 permissions or move the workspace to a writable path.",
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
                "semgrep" => "Semgrep is optional for automatic scans: they skip it visibly and continue with built-in scanners. Install Semgrep (`pipx install semgrep` or `brew install semgrep`) before requesting `--tasks semgrep`.",
                "codeql" => "Install the CodeQL CLI or pass {\"binary\":\"/path/to/codeql\"} to codeql:scan.",
                // M2 §2.2 recon-intake adapters consume the output of these
                // bounty tools but do not invoke them — doctor reports
                // their absence as a warning so operators know the tool
                // is missing if they intended to use it.
                "amass" => "Install OWASP Amass (`brew install amass` or `go install github.com/owasp-amass/amass/v4/...`) to feed recon:import.",
                "httpx" => "Install ProjectDiscovery httpx (`go install github.com/projectdiscovery/httpx/cmd/httpx@latest`) to feed recon:import.",
                "nuclei" => "Install ProjectDiscovery nuclei (`go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`) to feed recon:import.",
                "nmap" => "Install nmap (`brew install nmap` or your OS package manager) before using recon:nmap.",
                _ => "Install the missing scanner binary or configure the tool input with an explicit path.",
            };
            DoctorCheck::warn(binary, format!("{binary} was not found on PATH"), next)
        }
    }
}

pub(crate) fn check_joern_binary() -> DoctorCheck {
    if let Some(check) = check_joern_env_override() {
        return check;
    }

    let path = env::var_os("PATH");
    let cwd = current_dir_for_doctor();
    if let Some(found) = resolve_executable("joern", path.as_deref(), &cwd) {
        return DoctorCheck::ok("joern", format!("found joern at {}", found.display()));
    }
    if let Some(found) = resolve_executable("joern-parse", path.as_deref(), &cwd) {
        return DoctorCheck::ok("joern", format!("found joern-parse at {}", found.display()));
    }

    DoctorCheck::warn(
        "joern",
        "joern and joern-parse were not found on PATH",
        "Install Joern from https://docs.joern.io/installation or set KUZUSHI_JOERN_BIN=<path-to-joern> before using Joern-backed analysis.",
    )
}

fn check_joern_env_override() -> Option<DoctorCheck> {
    let path = env::var_os("KUZUSHI_JOERN_BIN").map(PathBuf::from)?;
    if path.is_file() {
        return Some(DoctorCheck::ok(
            "joern",
            format!("KUZUSHI_JOERN_BIN points to {}", path.display()),
        ));
    }
    Some(DoctorCheck::warn(
        "joern",
        format!(
            "KUZUSHI_JOERN_BIN points to missing file {}",
            path.display()
        ),
        "Fix KUZUSHI_JOERN_BIN or install joern/joern-parse on PATH.",
    ))
}

pub(crate) fn deterministic_capability_checks() -> Vec<DoctorCheck> {
    vec![
        built_in_capability_check("secret-scan", "built-in secret scanner is available"),
        built_in_capability_check("dep-hygiene", "built-in manifest analyzer is available"),
        built_in_capability_check("iac-scan", "built-in IaC scanner is available"),
        built_in_capability_check("license-scan", "built-in license-risk scanner is available"),
        cargo_audit_capability_check(),
    ]
}

fn built_in_capability_check(name: &'static str, detail: &'static str) -> DoctorCheck {
    DoctorCheck::ok(name, detail)
}

fn cargo_audit_capability_check() -> DoctorCheck {
    if CargoAuditScanner::binary_available() {
        return DoctorCheck::ok("cargo-audit", "`cargo audit` is available");
    }
    DoctorCheck::warn(
        "cargo-audit",
        "`cargo audit` was not found; automatic scans skip this optional task visibly, while explicit `--tasks cargo-audit` requests fail closed",
        "Install cargo-audit with `cargo install cargo-audit` before explicitly requesting cargo-audit advisory checks.",
    )
}

pub(crate) fn check_container_runtime() -> DoctorCheck {
    if let Some(path) = resolve_executable(
        "podman",
        env::var_os("PATH").as_deref(),
        &current_dir_for_doctor(),
    ) {
        return DoctorCheck::ok(
            "container-runtime",
            format!("found podman at {}", path.display()),
        );
    }
    if let Some(path) = resolve_executable(
        "docker",
        env::var_os("PATH").as_deref(),
        &current_dir_for_doctor(),
    ) {
        return DoctorCheck::ok(
            "container-runtime",
            format!("found docker at {}", path.display()),
        );
    }
    DoctorCheck::warn(
        "container-runtime",
        "neither podman nor docker was found on PATH",
        "Install Podman or Docker before using rev.ng-backed pwn reverse-engineering tools.",
    )
}

/// Whether live `offense:chain` traffic can be namespace-isolated. The
/// transport prefers bwrap, then podman; without either it falls back to the
/// unsandboxed Plain backend (fine for loopback labs, warned for other
/// targets).
pub(crate) fn check_offense_sandbox() -> DoctorCheck {
    let path = env::var_os("PATH");
    let cwd = current_dir_for_doctor();
    if let Some(found) = resolve_executable("bwrap", path.as_deref(), &cwd) {
        return DoctorCheck::ok(
            "offense-sandbox",
            format!(
                "found bwrap at {}; live offense:chain traffic is namespace-isolated",
                found.display()
            ),
        );
    }
    if let Some(found) = resolve_executable("podman", path.as_deref(), &cwd) {
        return DoctorCheck::ok(
            "offense-sandbox",
            format!(
                "found podman at {}; live offense:chain traffic is isolated",
                found.display()
            ),
        );
    }
    DoctorCheck::warn(
        "offense-sandbox",
        "no isolating sandbox backend (bwrap/podman) on PATH; live offense:chain uses the Plain backend (no host isolation) and warns for non-loopback targets",
        "Install bubblewrap (`apt-get install bubblewrap` / `brew install bubblewrap`) or Podman to isolate offensive traffic from your host.",
    )
}

pub(crate) fn check_revng_image() -> DoctorCheck {
    let runtime = resolve_executable(
        "podman",
        env::var_os("PATH").as_deref(),
        &current_dir_for_doctor(),
    )
    .map(|_| "podman")
    .or_else(|| {
        resolve_executable(
            "docker",
            env::var_os("PATH").as_deref(),
            &current_dir_for_doctor(),
        )
        .map(|_| "docker")
    });
    let Some(runtime) = runtime else {
        return DoctorCheck::warn(
            "revng-image",
            "rev.ng image was not checked because no container runtime is available",
            "Install Podman or Docker, then run `kuzushi mcp health revng`.",
        );
    };
    let image =
        env::var("KUZUSHI_REVNG_IMAGE").unwrap_or_else(|_| "revng/revng:latest".to_string());
    match std::process::Command::new(runtime)
        .args(["image", "inspect", &image])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => {
            DoctorCheck::ok("revng-image", format!("{image} is available to {runtime}"))
        }
        _ => DoctorCheck::warn(
            "revng-image",
            format!("{image} is not available locally"),
            format!("Pull it with `{runtime} pull {image}` or set KUZUSHI_REVNG_IMAGE."),
        ),
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
            "no explicit model configured; static scanners still work; no fallback model will be selected",
            "Set `KUZUSHI_MODEL=provider:model` or add `model = \"provider:model\"` before using agentic tools.",
        ),
        Some(model) => model_config_check(model, config),
    }
}

fn model_config_check(model: &str, config: &kuzushi_core::V2Config) -> DoctorCheck {
    match kuzushi_core::runtime::canonical_model_spec(model) {
        Ok(canonical) => match model_runtime_check(&canonical, config) {
            Ok(()) => DoctorCheck::ok(
                "model",
                format!(
                    "explicit model configured for provider {}",
                    model_provider(&canonical)
                ),
            ),
            Err(error) => DoctorCheck::fail(
                "model",
                error.to_string(),
                "Align runtime.api_key_env with the model provider or choose a model for the configured runtime credentials.",
            ),
        },
        Err(error) => DoctorCheck::fail(
            "model",
            error.to_string(),
            "Set `KUZUSHI_MODEL=provider:model` or fix config.toml.",
        ),
    }
}

fn model_runtime_check(model: &str, config: &kuzushi_core::V2Config) -> Result<(), anyhow::Error> {
    kuzushi_core::runtime::validate_model_api_key_env(model, &config.runtime.api_key_env)
}

fn model_provider(model: &str) -> &str {
    model
        .split_once(':')
        .map(|(provider, _)| provider)
        .unwrap_or(model)
}

pub(crate) fn check_auth_env(config: &kuzushi_core::V2Config) -> DoctorCheck {
    if let Some(provider) = configured_model_provider(config) {
        return match provider.as_str() {
            "openai" => check_provider_api_key("OPENAI_API_KEY", "model openai:*"),
            "anthropic" => check_provider_api_key("ANTHROPIC_API_KEY", "model anthropic:*"),
            "openai-codex" => check_openai_oauth_credentials(),
            _ => check_provider_api_key(
                config.runtime.api_key_env.trim(),
                &format!("model provider {provider}"),
            ),
        };
    }
    let name = config.runtime.api_key_env.trim();
    check_provider_api_key(name, "runtime.api_key_env")
}

fn configured_model_provider(config: &kuzushi_core::V2Config) -> Option<String> {
    let model = config.model.as_deref()?.trim();
    let canonical = kuzushi_core::runtime::canonical_model_spec(model).ok()?;
    Some(canonical.split_once(':')?.0.to_string())
}

fn check_provider_api_key(name: &str, context: &str) -> DoctorCheck {
    if name.is_empty() {
        return DoctorCheck::fail(
            "auth-env",
            format!("{context} needs a credential env var, but the resolved name is empty"),
            "Set a provider-matching credential env var name, not a secret value.",
        );
    }
    if env::var_os(name).is_some() {
        DoctorCheck::ok(
            "auth-env",
            format!("{name} is set; value is hidden (for {context})"),
        )
    } else {
        DoctorCheck::warn(
            "auth-env",
            format!("{name} is not set for {context}"),
            format!("Export {name}=<token> before running model-backed tools."),
        )
    }
}

fn check_openai_oauth_credentials() -> DoctorCheck {
    match openai_oauth_status() {
        OpenAiOauthStatus::Ready => DoctorCheck::ok(
            "auth-env",
            "OpenAI OAuth credentials are stored for model openai-codex:*; values hidden",
        ),
        OpenAiOauthStatus::ExpiredRefreshable => DoctorCheck::ok(
            "auth-env",
            "OpenAI OAuth access token is expired but refresh token is present; it will refresh on next call",
        ),
        OpenAiOauthStatus::Missing(path) => DoctorCheck::warn(
            "auth-env",
            format!("OpenAI OAuth credentials not found at {}", path.display()),
            "Run `kuzushi auth login openai` before using model openai-codex:*.",
        ),
        OpenAiOauthStatus::Invalid(path, reason) => DoctorCheck::fail(
            "auth-env",
            format!("OpenAI OAuth credentials at {} are invalid: {reason}", path.display()),
            "Run `kuzushi auth login openai` to replace the stored credentials.",
        ),
    }
}

enum OpenAiOauthStatus {
    Ready,
    ExpiredRefreshable,
    Missing(PathBuf),
    Invalid(PathBuf, String),
}

fn openai_oauth_status() -> OpenAiOauthStatus {
    let Some(home) = env::var_os("HOME") else {
        return OpenAiOauthStatus::Missing(PathBuf::from("~/.kuzushi/oauth-credentials.json"));
    };
    let path = kuzushi_core::config::default_oauth_credentials_path(home);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return OpenAiOauthStatus::Missing(path);
        }
        Err(error) => {
            return OpenAiOauthStatus::Invalid(
                path,
                format!("could not read credentials file: {}", error.kind()),
            );
        }
    };
    let value = match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(value) => value,
        Err(_) => {
            return OpenAiOauthStatus::Invalid(
                path,
                "credentials file is not valid JSON".to_string(),
            );
        }
    };
    let Some(entry) = value.get("openai-codex").filter(|entry| entry.is_object()) else {
        return OpenAiOauthStatus::Invalid(
            path,
            "credentials file is missing an `openai-codex` provider entry".to_string(),
        );
    };
    openai_oauth_entry_status(path, entry)
}

fn openai_oauth_entry_status(path: PathBuf, entry: &serde_json::Value) -> OpenAiOauthStatus {
    let access = entry
        .get("access")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.is_empty());
    let refresh = entry
        .get("refresh")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.is_empty());
    if !access {
        return OpenAiOauthStatus::Invalid(path, "missing `access` field".to_string());
    }
    let expires = entry
        .get("expires")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(u64::MAX);
    if expires <= current_unix_ms() {
        if refresh {
            return OpenAiOauthStatus::ExpiredRefreshable;
        }
        return OpenAiOauthStatus::Invalid(
            path,
            "access token is expired and no `refresh` token is present".to_string(),
        );
    }
    OpenAiOauthStatus::Ready
}

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
