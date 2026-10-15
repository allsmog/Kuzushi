use super::*;
use std::collections::BTreeSet;
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_CODEQL_CREATE_TIMEOUT_MS: u64 =
    crate::codeql_repository_execution::DEFAULT_CODEQL_REPOSITORY_TIMEOUT_MS;
const MAX_CODEQL_CREATE_TIMEOUT_MS: u64 =
    crate::codeql_repository_execution::MAX_CODEQL_REPOSITORY_TIMEOUT_MS;

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
        "Create a CodeQL database (.kuzushi/v3/codeql-db/) for downstream taint and \
         security queries. Deterministic; wraps `codeql database create`.",
        tools_with_policy(
            repository_execute_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            ),
            vec![tool_with_options(
                "codeql:create-db",
                "Experimental source-bound database preparation with explicit repository-execution consent. Can run build logic in an isolated checkout. Missing CodeQL is skipped; a prepared database does not complete Map or establish findings.",
                codeql_create_db_options(),
            ).without_phase_result()],
        ),
        vec![dag("codeql:create-db", "codeql-db", &["context:build"])],
    )
    .labs()
}

fn codeql_create_db_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        opt(
            "importPath",
            OptionType::Path,
            "Compatibility input for a prebuilt CodeQL database. Kuzushi refuses raw imports \
             until they can be authenticated against the current source and an operator-owned \
             promotion receipt; run codeql:create-db against the target instead.",
        )
        .external_read()
        .aliases(&["import_path", "existingDb", "existing_db"]),
        opt(
            "language",
            OptionType::String,
            "CodeQL language pack (e.g. javascript, python, cpp, java, rust). Defaults to auto-detection.",
        ),
        codeql_output_path_option(),
        codeql_binary_path_option(),
        opt(
            "buildMode",
            OptionType::String,
            "CodeQL build mode override (none, autobuild). When omitted, compiled languages try autobuild, then fall back to none where supported.",
        )
        .advanced()
        .aliases(&["build_mode"]),
        opt(
            "timeoutMs",
            OptionType::Int,
            "Per-attempt CodeQL database-create deadline in milliseconds. A deadline kills and reaps the complete CodeQL process tree.",
        )
        .aliases(&["timeout_ms"])
        .default(json!(DEFAULT_CODEQL_CREATE_TIMEOUT_MS))
        .integer_range(1, MAX_CODEQL_CREATE_TIMEOUT_MS as i64)
        .advanced(),
        repository_source_commit_binding_option(),
        repository_target_scope_binding_option(),
    ]
}

fn codeql_output_path_option() -> OptionSpec {
    opt(
        "outputPath",
        OptionType::Path,
        "Destination DB directory below <target>/.kuzushi. Defaults to <target>/.kuzushi/v3/codeql-db; paths outside Kuzushi state are rejected.",
    )
    .state_write()
    .advanced()
}

fn codeql_binary_path_option() -> OptionSpec {
    opt(
        "codeqlBin",
        OptionType::Path,
        "Explicit CodeQL CLI binary path. When omitted, Kuzushi searches PATH.",
    )
    .aliases(&["codeql_bin"])
    .executable()
    .advanced()
}

pub(in crate::modules) fn run_codeql_create_db(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let target = resolve_tool_target(input, ctx)?;
    if let Some(import_path) = resolve_db_import_path(input) {
        return reject_unauthenticated_db_import(&import_path);
    }
    let launcher = crate::codeql_repository_execution::prepared_codeql_launcher(input)?;
    if matches!(
        launcher,
        crate::codeql_repository_execution::PreparedCodeqlLauncher::Unavailable
    ) {
        return Ok(skipped_response(&target));
    };
    execute_codeql_create(input, ctx, target, launcher)
}

fn resolve_db_import_path(input: &Value) -> Option<PathBuf> {
    input
        .get("importPath")
        .or_else(|| input.get("import_path"))
        .or_else(|| input.get("existingDb"))
        .or_else(|| input.get("existing_db"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}

fn reject_unauthenticated_db_import(import_path: &Path) -> Result<Value> {
    anyhow::bail!(
        "codeql:create-db refuses prebuilt database import from {} because a raw copy cannot be \
         authenticated against the current repository source or an operator promotion receipt; \
         run codeql:create-db without importPath",
        import_path.display()
    )
}

fn execute_codeql_create(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    target: PathBuf,
    launcher: crate::codeql_repository_execution::PreparedCodeqlLauncher,
) -> Result<Value> {
    let bin = launcher
        .display_path()
        .context("prepared CodeQL launcher has no executable path")?
        .to_path_buf();
    let output_path = resolve_db_output_path(input, &target);
    let binding = crate::remediation::patch::repository_source_binding(input)?;
    let timeout = codeql_create_timeout(input)?;
    let execution = crate::codeql_repository_execution::CodeqlRepositoryExecution::prepare(
        crate::codeql_repository_execution::CodeqlRepositoryRequest {
            source_root: &target,
            binding: binding.clone(),
            destination: &output_path,
            launcher,
            cancellation: ctx.cancellation,
            timeout,
        },
    )?;
    let started = Instant::now();
    let (language, outcome) = execute_bound_codeql_create(&execution, input, ctx, &target)?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    emit_done_step(ctx, &output_path, elapsed_ms);
    Ok(source_bound_db_response(
        codeql_db_response(
            &target,
            &output_path,
            &bin,
            &language,
            &outcome,
            elapsed_ms,
            now_ms()?,
        ),
        &binding,
    ))
}

fn source_bound_db_response(
    mut response: Value,
    binding: &crate::remediation::patch::RepositorySourceBinding,
) -> Value {
    let text = response["output"].as_str().unwrap_or_default();
    response["output"] = json!(format!("{text}\nSource commit: {}\nTarget scope: {:?}\nDatabase preparation does not complete Map or establish findings.",binding.commit,binding.target_scope));
    response["data"]["sourceCommit"] = json!(binding.commit);
    response["data"]["targetScope"] = json!(binding.target_scope);
    response
}

fn execute_bound_codeql_create(
    execution: &crate::codeql_repository_execution::CodeqlRepositoryExecution<'_>,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
) -> Result<(String, CodeqlCreateOutcome)> {
    execution.with_bound_target(|bound_target| {
        let language = resolve_language_with_cancel(input, bound_target, ctx.cancellation)?;
        let build_modes = resolve_build_modes(input, &language)?;
        emit_step(
            ctx,
            "tool",
            "create-db",
            format!(
                "codeql:create-db start · language={language} target={}",
                target.display()
            ),
        );
        let outcome = invoke_codeql_create_with_fallbacks(
            &execution,
            bound_target,
            &language,
            &build_modes,
            ctx.cancellation,
        )?;
        Ok((language, outcome))
    })
}

fn codeql_create_timeout(input: &Value) -> Result<Duration> {
    crate::bounded_subprocess::timeout_from_input(
        input,
        &["timeoutMs", "timeout_ms"],
        DEFAULT_CODEQL_CREATE_TIMEOUT_MS,
        MAX_CODEQL_CREATE_TIMEOUT_MS,
        "codeql:create-db timeoutMs",
    )
}

fn emit_done_step(ctx: &ToolExecutionContext<'_>, output_path: &Path, elapsed_ms: u64) {
    let done_label = format!(
        "codeql:create-db complete · {} in {elapsed_ms} ms",
        output_path.display()
    );
    emit_step(ctx, "done", "create-db", done_label);
}

#[cfg(test)]
fn resolve_language(input: &Value, target: &Path) -> Result<String> {
    resolve_language_with_cancel(input, target, None)
}

fn resolve_language_with_cancel(
    input: &Value,
    target: &Path,
    cancel: Option<&crate::scan::ScanCancellation>,
) -> Result<String> {
    let explicit = input
        .get("language")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|language| !language.is_empty());
    match explicit {
        Some(language) => Ok(language.to_lowercase()),
        None => autodetect_language_with_cancel(target, cancel),
    }
}

#[cfg(test)]
fn autodetect_language(target: &Path) -> Result<String> {
    autodetect_language_with_cancel(target, None)
}

fn autodetect_language_with_cancel(
    target: &Path,
    cancel: Option<&crate::scan::ScanCancellation>,
) -> Result<String> {
    let languages = detected_codeql_languages_with_cancel(target, cancel)?;
    match languages.len() {
        1 => languages
            .into_iter()
            .next()
            .map(str::to_string)
            .context("CodeQL language detection lost its only candidate"),
        0 => unknown_language_error(target),
        _ => ambiguous_language_error(target, &languages),
    }
}

fn detected_codeql_languages_with_cancel(
    target: &Path,
    cancel: Option<&crate::scan::ScanCancellation>,
) -> Result<BTreeSet<&'static str>> {
    let inventory =
        crate::workspace::build_repository_inventory_with_observer(target, &mut |_| {}, &|| {
            cancel.is_some_and(crate::scan::ScanCancellation::is_cancelled)
        })?;
    anyhow::ensure!(
        inventory.truncation.is_none(),
        "CodeQL language inventory is partial; inspect its limits or supply an explicit language"
    );
    let inspection = inventory
        .inspection
        .context("CodeQL language inventory has no inspection receipt")?;
    let mut languages = BTreeSet::new();
    for path in &inspection.files {
        let path = Path::new(path);
        if path
            .components()
            .any(|component| ignored_language_dir(component.as_os_str()))
        {
            continue;
        }
        languages.extend(codeql_language_for_source(path));
        languages.extend(root_manifest_language(path));
    }
    Ok(languages)
}

fn root_manifest_language(path: &Path) -> Option<&'static str> {
    [
        ("Cargo.toml", "rust"),
        ("package.json", "javascript"),
        ("tsconfig.json", "javascript"),
        ("pyproject.toml", "python"),
        ("requirements.txt", "python"),
        ("go.mod", "go"),
        ("pom.xml", "java"),
        ("build.gradle", "java"),
        ("Gemfile", "ruby"),
    ]
    .into_iter()
    .find_map(|(name, language)| (path == Path::new(name)).then_some(language))
}

fn ignored_language_dir(name: &std::ffi::OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(
            ".git"
                | ".kuzushi"
                | ".next"
                | ".venv"
                | "__pycache__"
                | "build"
                | "coverage"
                | "dist"
                | "node_modules"
                | "obj"
                | "target"
                | "vendor"
                | "venv"
        )
    )
}

fn codeql_language_for_source(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "py" | "pyi" | "pyw" => Some("python"),
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts" => Some("javascript"),
        "rs" => Some("rust"),
        "go" => Some("go"),
        "java" | "kt" | "kts" => Some("java"),
        "c" | "h" | "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => Some("cpp"),
        "cs" => Some("csharp"),
        "rb" => Some("ruby"),
        "swift" => Some("swift"),
        _ => None,
    }
}

fn unknown_language_error(target: &Path) -> Result<String> {
    anyhow::bail!(
        "codeql:create-db could not auto-detect a supported source language in {}. Pass an explicit language option, for example --option language=python",
        target.display()
    )
}

fn ambiguous_language_error(target: &Path, languages: &BTreeSet<&'static str>) -> Result<String> {
    anyhow::bail!(
        "codeql:create-db detected multiple source languages in {}: {}. Pass the language to analyze explicitly with --option language=<language>",
        target.display(),
        languages.iter().copied().collect::<Vec<_>>().join(", ")
    )
}

fn resolve_db_output_path(input: &Value, target: &Path) -> PathBuf {
    if let Some(path) = input
        .get("outputPath")
        .or_else(|| input.get("output_path"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
    {
        return path;
    }
    crate::workspace::workspace_codeql_db_path(target)
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

fn invoke_codeql_create_with_fallbacks(
    execution: &crate::codeql_repository_execution::CodeqlRepositoryExecution<'_>,
    bound_target: &Path,
    language: &str,
    build_modes: &[String],
    cancellation: Option<&crate::scan::ScanCancellation>,
) -> Result<CodeqlCreateOutcome> {
    let mut last_output: Option<std::process::Output> = None;
    let mut first_error = None;
    for (index, build_mode) in build_modes.iter().enumerate() {
        let output =
            run_codeql_create_attempt(execution, bound_target, language, build_mode, cancellation)?;
        if output.status.success() {
            return Ok(completed_codeql_create_attempt(
                build_mode,
                index,
                first_error,
            ));
        }
        if first_error.is_none() {
            first_error = Some(codeql_failure_summary(&output));
        }
        last_output = Some(output);
    }
    let output = last_output.context("no CodeQL build modes were attempted")?;
    Err(codeql_failure_error(&output))
}

fn completed_codeql_create_attempt(
    build_mode: &str,
    attempt_index: usize,
    first_error: Option<String>,
) -> CodeqlCreateOutcome {
    CodeqlCreateOutcome {
        build_mode: build_mode.to_string(),
        fallback: attempt_index > 0,
        first_error,
    }
}

fn run_codeql_create_attempt(
    execution: &crate::codeql_repository_execution::CodeqlRepositoryExecution<'_>,
    bound_target: &Path,
    language: &str,
    build_mode: &str,
    cancellation: Option<&crate::scan::ScanCancellation>,
) -> Result<std::process::Output> {
    ensure_codeql_attempt_active(cancellation)?;
    execution.build(
        bound_target,
        language,
        crate::codeql_repository_execution::CodeqlBuildStrategy::BuildMode(build_mode),
    )
}

fn ensure_codeql_attempt_active(
    cancellation: Option<&crate::scan::ScanCancellation>,
) -> Result<()> {
    anyhow::ensure!(
        !cancellation.is_some_and(crate::scan::ScanCancellation::is_cancelled),
        "codeql:create-db was cancelled before starting an attempt"
    );
    Ok(())
}

fn codeql_failure_error(output: &std::process::Output) -> anyhow::Error {
    anyhow::anyhow!(
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
    let output = "codeql:create-db skipped: the `codeql` CLI is not installed and no `codeqlBin` \
                  option was provided. Install CodeQL on PATH or pass codeqlBin to enable database creation."
        .to_string();
    crate::module_result::skipped_output_result(
        output.clone(),
        output.clone(),
        vec![json!(output)],
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
    fn db_import_path_resolves_from_any_alias_and_ignores_blank() {
        assert_eq!(
            resolve_db_import_path(&json!({"importPath": "/x/db"})),
            Some(PathBuf::from("/x/db"))
        );
        assert_eq!(
            resolve_db_import_path(&json!({"existing_db": "/y/db"})),
            Some(PathBuf::from("/y/db"))
        );
        assert_eq!(resolve_db_import_path(&json!({"importPath": " "})), None);
        assert_eq!(resolve_db_import_path(&json!({})), None);
    }

    #[test]
    fn prebuilt_database_import_fails_closed() {
        let error = reject_unauthenticated_db_import(Path::new("/shared/prebuilt-db"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("cannot be authenticated"), "{error}");
        assert!(error.contains("without importPath"), "{error}");
    }

    #[test]
    fn language_inventory_stops_on_cancellation_without_guessing_a_boundary() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("owned.py"), "# inert owned source\n").unwrap();
        let cancel = crate::scan::ScanCancellation::default();
        cancel.cancel();
        let error = detected_codeql_languages_with_cancel(root.path(), Some(&cancel)).unwrap_err();
        assert!(format!("{error:#}").contains("partial"));
    }

    #[test]
    fn deep_language_inventory_is_iterative_and_retains_loose_root_files() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("owned.py"), "# inert owned source\n").unwrap();
        let mut nested = root.path().to_path_buf();
        for _ in 0..200 {
            nested.push("d");
            fs::create_dir(&nested).unwrap();
        }
        fs::write(nested.join("owned.rs"), "// inert owned source\n").unwrap();
        let languages = detected_codeql_languages_with_cancel(root.path(), None).unwrap();
        assert_eq!(languages, BTreeSet::from(["python", "rust"]));
    }

    #[test]
    fn build_mode_resolution_rejects_unknown_values() {
        let input = json!({"buildMode": "fast"});

        let error = resolve_build_modes(&input, "cpp").unwrap_err().to_string();

        assert!(error.contains("buildMode must be one of"));
    }

    #[test]
    fn create_timeout_is_defaulted_and_bounded() {
        assert_eq!(
            codeql_create_timeout(&json!({})).unwrap(),
            Duration::from_millis(DEFAULT_CODEQL_CREATE_TIMEOUT_MS)
        );
        assert!(codeql_create_timeout(&json!({"timeoutMs": 0})).is_err());
        assert!(codeql_create_timeout(&json!({
            "timeoutMs": MAX_CODEQL_CREATE_TIMEOUT_MS + 1
        }))
        .is_err());
    }

    #[test]
    fn missing_codeql_binary_is_an_explicit_skip() {
        let response = skipped_response(Path::new("/repo"));

        assert_eq!(response["status"], "skipped");
        assert_eq!(response["data"]["skipped"], true);
    }

    #[test]
    fn auto_detection_recognizes_single_file_repositories() {
        let cases = [
            ("app.py", "python"),
            ("app.ts", "javascript"),
            ("lib.rs", "rust"),
            ("main.go", "go"),
            ("App.java", "java"),
            ("native.cpp", "cpp"),
            ("Program.cs", "csharp"),
            ("app.rb", "ruby"),
        ];
        for (file_name, language) in cases {
            let target = tempdir().unwrap();
            fs::write(target.path().join(file_name), "source").unwrap();

            assert_eq!(autodetect_language(target.path()).unwrap(), language);
        }
    }

    #[test]
    fn auto_detection_rejects_ambiguous_repository() {
        let target = tempdir().unwrap();
        fs::write(target.path().join("app.py"), "source").unwrap();
        fs::write(target.path().join("app.ts"), "source").unwrap();

        let error = autodetect_language(target.path()).unwrap_err().to_string();

        assert!(error.contains("multiple source languages"), "{error}");
        assert!(error.contains("javascript, python"), "{error}");
        assert!(error.contains("--option language="), "{error}");
    }

    #[test]
    fn auto_detection_rejects_unknown_repository() {
        let target = tempdir().unwrap();
        fs::write(target.path().join("README.md"), "docs only").unwrap();

        let error = autodetect_language(target.path()).unwrap_err().to_string();

        assert!(error.contains("could not auto-detect"), "{error}");
        assert!(error.contains("--option language=python"), "{error}");
    }

    #[test]
    fn explicit_language_resolves_ambiguous_repository() {
        let target = tempdir().unwrap();
        fs::write(target.path().join("app.py"), "source").unwrap();
        fs::write(target.path().join("app.ts"), "source").unwrap();

        let language = resolve_language(&json!({"language": " Python "}), target.path()).unwrap();

        assert_eq!(language, "python");
    }

    #[test]
    fn cancellation_before_retry_preserves_existing_output() {
        let workspace = tempdir().unwrap();
        let output = crate::workspace::workspace_codeql_db_path(workspace.path());
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("partial"), "stale").unwrap();
        let cancellation = crate::scan::ScanCancellation::default();
        cancellation.cancel();
        let error = ensure_codeql_attempt_active(Some(&cancellation))
            .unwrap_err()
            .to_string();

        assert!(error.contains("cancelled"), "{error}");
        assert!(output.join("partial").exists());
    }
}
