use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

struct CodeqlDbOutputPath {
    path: PathBuf,
    explicit: bool,
}

struct CodeqlCreateOutcome {
    build_mode: String,
    fallback: bool,
    first_error: Option<String>,
}

pub(in crate::modules) fn codeql_db_module() -> BuiltinModule {
    builtin_module(
        "codeql-db",
        "CodeQL Database",
        ModuleKind::Intel,
        "Create a CodeQL database (.kuzushi/codeql-db/) for downstream taint and \
         security queries. Deterministic; wraps `codeql database create`.",
        vec![tool_with_options(
            "codeql:create-db",
            "Create a CodeQL database for the active target. Skips silently when the codeql CLI \
             is missing; otherwise writes .kuzushi/codeql-db/.",
            vec![
                target_option(),
                opt(
                    "language",
                    OptionType::String,
                    "CodeQL language pack (e.g. javascript, python, cpp, java, rust). Defaults to auto-detection.",
                ),
                opt(
                    "outputPath",
                    OptionType::Path,
                    "Destination DB directory. Defaults to <target>/.kuzushi/codeql-db.",
                )
                .advanced(),
                opt(
                    "buildMode",
                    OptionType::String,
                    "CodeQL build mode override (none, autobuild). When omitted, compiled languages try autobuild, then fall back to none where supported.",
                )
                .advanced()
                .aliases(&["build_mode"]),
            ],
        )],
        vec![dag("codeql:create-db", "codeql-db", &["context:build"])],
    )
}

pub(in crate::modules) fn run_codeql_create_db(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    let bin = match locate_codeql_bin()? {
        Some(path) => path,
        None => return Ok(skipped_response(&target)),
    };
    let language = resolve_language(input, &target);
    let output_path = resolve_db_output_path(input, &target);
    let build_modes = resolve_build_modes(input, &language)?;
    let start_label = format!(
        "codeql:create-db start · language={language} target={}",
        target.display()
    );
    emit_step(ctx, "tool", "create-db", start_label);
    let (outcome, elapsed_ms) = timed_codeql_create(
        &bin,
        &target,
        &output_path.path,
        &language,
        &build_modes,
        can_remove_non_db_path(&output_path),
    )?;
    emit_done_step(ctx, &output_path.path, elapsed_ms);
    let timestamp = now_ms()?;
    Ok(codeql_db_response(
        &target,
        &output_path.path,
        &bin,
        &language,
        &outcome,
        elapsed_ms,
        timestamp,
    ))
}

fn timed_codeql_create(
    bin: &Path,
    target: &Path,
    output_path: &Path,
    language: &str,
    build_modes: &[String],
    allow_non_db_removal: bool,
) -> Result<(CodeqlCreateOutcome, u64)> {
    let started = Instant::now();
    let outcome = invoke_codeql_create_with_fallbacks(
        bin,
        target,
        output_path,
        language,
        build_modes,
        allow_non_db_removal,
    )?;
    Ok((outcome, started.elapsed().as_millis() as u64))
}

fn emit_done_step(ctx: &ToolExecutionContext<'_>, output_path: &Path, elapsed_ms: u64) {
    let done_label = format!(
        "codeql:create-db complete · {} in {elapsed_ms} ms",
        output_path.display()
    );
    emit_step(ctx, "done", "create-db", done_label);
}

fn locate_codeql_bin() -> Result<Option<PathBuf>> {
    if let Some(value) = std::env::var_os("KUZUSHI_CODEQL_BIN") {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Ok(Some(path));
        }
        anyhow::bail!(
            "KUZUSHI_CODEQL_BIN points to a missing CodeQL binary: {}",
            path.display()
        );
    }
    Ok(which_on_path("codeql"))
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn resolve_language(input: &Value, target: &Path) -> String {
    input
        .get("language")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| autodetect_language(target))
}

fn autodetect_language(target: &Path) -> String {
    if target.join("Cargo.toml").is_file() {
        return "rust".to_string();
    }
    if target.join("package.json").is_file() || target.join("tsconfig.json").is_file() {
        return "javascript".to_string();
    }
    if target.join("pyproject.toml").is_file() || target.join("requirements.txt").is_file() {
        return "python".to_string();
    }
    if target.join("go.mod").is_file() {
        return "go".to_string();
    }
    if target.join("pom.xml").is_file() || target.join("build.gradle").is_file() {
        return "java".to_string();
    }
    "javascript".to_string()
}

fn resolve_db_output_path(input: &Value, target: &Path) -> CodeqlDbOutputPath {
    if let Some(path) = input
        .get("outputPath")
        .or_else(|| input.get("output_path"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
    {
        return CodeqlDbOutputPath {
            path,
            explicit: true,
        };
    }
    CodeqlDbOutputPath {
        path: target.join(".kuzushi/codeql-db"),
        explicit: false,
    }
}

fn resolve_build_modes(input: &Value, language: &str) -> Result<Vec<String>> {
    let explicit = input
        .get("buildMode")
        .or_else(|| input.get("build_mode"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    crate::codeql_build_mode::codeql_build_mode_plan(language, explicit)
}

fn can_remove_non_db_path(output_path: &CodeqlDbOutputPath) -> bool {
    !output_path.explicit || !output_path.path.exists()
}

fn prepare_db_directory(path: &Path, allow_non_db_removal: bool) -> Result<()> {
    if path.exists() {
        if !allow_non_db_removal && !looks_like_codeql_database(path) {
            anyhow::bail!(
                "refusing to clear explicit outputPath because it is not a CodeQL database: {}",
                path.display()
            );
        }
        fs::remove_dir_all(path)
            .with_context(|| format!("clearing existing CodeQL DB at {}", path.display()))?;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {} for CodeQL DB", parent.display()))?;
    }
    Ok(())
}

fn looks_like_codeql_database(path: &Path) -> bool {
    path.join("codeql-database.yml").is_file()
}

fn invoke_codeql_create_with_fallbacks(
    bin: &Path,
    target: &Path,
    output_path: &Path,
    language: &str,
    build_modes: &[String],
    allow_non_db_removal: bool,
) -> Result<CodeqlCreateOutcome> {
    let mut last_output: Option<std::process::Output> = None;
    let mut first_error = None;
    for (index, build_mode) in build_modes.iter().enumerate() {
        prepare_db_directory(output_path, allow_non_db_removal)?;
        let output = invoke_codeql_create(bin, target, output_path, language, build_mode)?;
        if output.status.success() {
            return Ok(CodeqlCreateOutcome {
                build_mode: build_mode.clone(),
                fallback: index > 0,
                first_error,
            });
        }
        if first_error.is_none() {
            first_error = Some(codeql_failure_summary(&output));
        }
        last_output = Some(output);
    }
    bail_on_codeql_failure(&last_output.context("no CodeQL build modes were attempted")?)
}

fn invoke_codeql_create(
    bin: &Path,
    target: &Path,
    output_path: &Path,
    language: &str,
    build_mode: &str,
) -> Result<std::process::Output> {
    // Capture stdout/stderr rather than inheriting the terminal — otherwise
    // codeql's progress output corrupts the Ratatui shell. Stderr is surfaced
    // on failure.
    let mut command = Command::new(bin);
    command
        .arg("database")
        .arg("create")
        .arg(output_path)
        .arg("--language")
        .arg(language)
        .arg("--source-root")
        .arg(target)
        .arg("--overwrite");
    if build_mode != "default" {
        command.arg(format!("--build-mode={build_mode}"));
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
        .output()
        .with_context(|| format!("spawning {}", bin.display()))
}

fn bail_on_codeql_failure(output: &std::process::Output) -> Result<CodeqlCreateOutcome> {
    if output.status.success() {
        unreachable!("successful CodeQL output should be returned before failure handling");
    }
    anyhow::bail!(
        "`codeql database create` exited with status {:?}: {}",
        output.status.code(),
        codeql_failure_summary(output)
    )
}

fn codeql_failure_summary(output: &std::process::Output) -> String {
    crate::module_result::subprocess_failure_summary(
        &output.stderr,
        "check the language flag and the source-root",
    )
}

fn skipped_response(target: &Path) -> Value {
    let output = "codeql:create-db skipped — the `codeql` CLI is not installed (KUZUSHI_CODEQL_BIN \
                  unset, not on PATH). Install CodeQL or set KUZUSHI_CODEQL_BIN to enable database creation."
        .to_string();
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "skipped": true,
            "reason": "`codeql` CLI not found",
        }),
    )
}

fn codeql_db_response(
    target: &Path,
    output_path: &Path,
    bin: &Path,
    language: &str,
    outcome: &CodeqlCreateOutcome,
    elapsed_ms: u64,
    timestamp: u64,
) -> Value {
    let output = format!(
        "codeql:create-db built a {language} database at {} in {} ms (buildMode={build_mode})",
        output_path.display(),
        elapsed_ms,
        build_mode = outcome.build_mode
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "dbPath": output_path.display().to_string(),
            "language": language,
            "buildMode": outcome.build_mode.as_str(),
            "buildModeFallback": outcome.fallback,
            "firstAttemptError": outcome.first_error.as_deref(),
            "codeqlBin": bin.display().to_string(),
            "elapsedMs": elapsed_ms,
            "timestamp": timestamp,
        }),
    )
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis() as u64)
}

fn emit_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, label: impl Into<String>) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, label.into()).emit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn build_mode_resolution_rejects_unknown_values() {
        let input = json!({"buildMode": "fast"});

        let error = resolve_build_modes(&input, "cpp").unwrap_err().to_string();

        assert!(error.contains("buildMode must be one of"));
    }

    #[test]
    fn explicit_existing_non_db_output_path_is_not_removed() {
        let temp = tempdir().unwrap();
        let output = temp.path().join("not-codeql");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("important.txt"), "keep").unwrap();

        let error = prepare_db_directory(&output, false)
            .unwrap_err()
            .to_string();

        assert!(error.contains("refusing to clear explicit outputPath"));
        assert!(output.join("important.txt").exists());
    }

    #[test]
    fn retry_may_remove_directory_created_by_this_run() {
        let temp = tempdir().unwrap();
        let output = temp.path().join("codeql-db");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("partial"), "stale").unwrap();

        prepare_db_directory(&output, true).unwrap();

        assert!(!output.exists());
        assert!(output.parent().unwrap().exists());
    }

    #[test]
    fn invalid_codeql_bin_env_is_not_silent_fallback() {
        let _guard = crate::test_env::codeql_bin_env_lock();
        let temp = tempdir().unwrap();
        let previous = std::env::var_os("KUZUSHI_CODEQL_BIN");
        std::env::set_var("KUZUSHI_CODEQL_BIN", temp.path().join("missing-codeql"));

        let error = locate_codeql_bin().unwrap_err().to_string();

        match previous {
            Some(value) => std::env::set_var("KUZUSHI_CODEQL_BIN", value),
            None => std::env::remove_var("KUZUSHI_CODEQL_BIN"),
        }
        assert!(error.contains("KUZUSHI_CODEQL_BIN points to a missing CodeQL binary"));
    }
}
