use super::*;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_CODEQL_CREATE_TIMEOUT_MS: u64 = 30 * 60 * 1000;
const MAX_CODEQL_CREATE_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

struct CodeqlDbOutputPath {
    path: PathBuf,
    explicit: bool,
}

struct CodeqlCreateOutcome {
    build_mode: String,
    fallback: bool,
    first_error: Option<String>,
}

#[derive(Clone, Copy)]
struct CodeqlCreateCommand<'a> {
    bin: &'a Path,
    target: &'a Path,
    output_path: &'a Path,
    language: &'a str,
    allow_non_db_removal: bool,
    cancellation: Option<&'a crate::scan::ScanCancellation>,
    timeout: Duration,
}

pub(in crate::modules) fn codeql_db_module() -> BuiltinModule {
    builtin_module(
        "codeql-db",
        "CodeQL Database",
        ModuleKind::Intel,
        "Create a CodeQL database (.kuzushi/codeql-db/) for downstream taint and \
         security queries. Deterministic; wraps `codeql database create`.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            ),
            vec![tool_with_options(
                "codeql:create-db",
                "Create a CodeQL database for the active target. Returns an explicit skipped result \
                 when the codeql CLI is missing; otherwise writes .kuzushi/codeql-db/.",
                codeql_create_db_options(),
            )],
        ),
        vec![dag("codeql:create-db", "codeql-db", &["context:build"])],
    )
}

fn codeql_create_db_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        opt(
            "importPath",
            OptionType::Path,
            "Reuse a prebuilt CodeQL database directory instead of running `codeql database \
             create`: the directory is validated (codeql-database.yml) and copied to the \
             canonical <target>/.kuzushi/codeql-db. The codeql CLI need not be installed. \
             Use for large targets where the database is built out-of-band or shared.",
        )
        .external_read()
        .aliases(&["import_path", "existingDb", "existing_db"]),
        opt(
            "language",
            OptionType::String,
            "CodeQL language pack (e.g. javascript, python, cpp, java, rust). Defaults to auto-detection.",
        ),
        opt(
            "outputPath",
            OptionType::Path,
            "Destination DB directory below <target>/.kuzushi. Defaults to <target>/.kuzushi/codeql-db; paths outside Kuzushi state are rejected.",
        )
        .state_write()
        .advanced(),
        opt(
            "codeqlBin",
            OptionType::Path,
            "Explicit CodeQL CLI binary path. When omitted, Kuzushi searches PATH.",
        )
        .aliases(&["codeql_bin"])
        .executable()
        .advanced(),
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
        .advanced(),
    ]
}

pub(in crate::modules) fn run_codeql_create_db(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let target = resolve_tool_target(input, ctx)?;
    if let Some(import_path) = resolve_db_import_path(input) {
        return run_codeql_db_import(ctx, &target, &import_path, input);
    }
    let bin = match locate_codeql_bin(input)? {
        Some(path) => path,
        None => return Ok(skipped_response(&target)),
    };
    execute_codeql_create(input, ctx, target, bin)
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

/// Import a prebuilt CodeQL database: validate the source directory, then copy
/// it to the canonical output path so downstream queries find it where they
/// already look. No `codeql database create` involvement.
fn run_codeql_db_import(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    import_path: &Path,
    input: &Value,
) -> Result<Value> {
    validate_db_import_source(import_path)?;
    let output_path = resolve_db_output_path(input, target);
    emit_step(
        ctx,
        "tool",
        "create-db",
        format!("codeql:create-db import from {}", import_path.display()),
    );
    let started = Instant::now();
    prepare_db_directory(target, &output_path.path, can_remove_non_db_path(&output_path))?;
    copy_directory_recursive(import_path, &output_path.path).with_context(|| {
        format!(
            "Could not copy prebuilt CodeQL DB {} to {}",
            import_path.display(),
            output_path.path.display()
        )
    })?;
    anyhow::ensure!(
        looks_like_codeql_database(&output_path.path),
        "imported CodeQL DB copy at {} is missing codeql-database.yml",
        output_path.path.display()
    );
    let elapsed_ms = started.elapsed().as_millis() as u64;
    emit_done_step(ctx, &output_path.path, elapsed_ms);
    Ok(codeql_db_import_response(
        target,
        &output_path.path,
        import_path,
        elapsed_ms,
        now_ms()?,
    ))
}

/// A usable import source is a directory carrying the codeql-database.yml
/// marker that `codeql database create` writes.
fn validate_db_import_source(import_path: &Path) -> Result<()> {
    anyhow::ensure!(
        import_path.is_dir(),
        "prebuilt CodeQL DB not found at {} — check importPath",
        import_path.display()
    );
    anyhow::ensure!(
        looks_like_codeql_database(import_path),
        "{} is not a CodeQL database (no codeql-database.yml)",
        import_path.display()
    );
    Ok(())
}

/// Copy a directory tree of regular files. Symlinks are skipped rather than
/// followed so a hostile prebuilt artifact cannot pull outside content into
/// Kuzushi state; CodeQL databases contain none.
fn copy_directory_recursive(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)
        .with_context(|| format!("creating {}", destination.display()))?;
    for entry in fs::read_dir(source).with_context(|| format!("reading {}", source.display()))? {
        let entry = entry.with_context(|| format!("reading entry below {}", source.display()))?;
        copy_directory_entry(&entry, destination)?;
    }
    Ok(())
}

fn copy_directory_entry(entry: &fs::DirEntry, destination: &Path) -> Result<()> {
    let file_type = entry
        .file_type()
        .with_context(|| format!("inspecting {}", entry.path().display()))?;
    let target = destination.join(entry.file_name());
    if file_type.is_dir() {
        return copy_directory_recursive(&entry.path(), &target);
    }
    if file_type.is_file() {
        fs::copy(entry.path(), &target)
            .with_context(|| format!("copying {}", entry.path().display()))?;
    }
    Ok(())
}

fn codeql_db_import_response(
    target: &Path,
    output_path: &Path,
    import_path: &Path,
    elapsed_ms: u64,
    timestamp: u64,
) -> Value {
    let output = format!(
        "codeql:create-db imported prebuilt database from {} to {} in {} ms",
        import_path.display(),
        output_path.display(),
        elapsed_ms
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "dbPath": output_path.display().to_string(),
            "importedFrom": import_path.display().to_string(),
            "elapsedMs": elapsed_ms,
            "timestamp": timestamp,
        }),
    )
}

fn execute_codeql_create(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    target: PathBuf,
    bin: PathBuf,
) -> Result<Value> {
    let language = resolve_language(input, &target)?;
    let output_path = resolve_db_output_path(input, &target);
    let build_modes = resolve_build_modes(input, &language)?;
    let timeout = codeql_create_timeout(input)?;
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
        ctx.cancellation,
        timeout,
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
    cancellation: Option<&crate::scan::ScanCancellation>,
    timeout: Duration,
) -> Result<(CodeqlCreateOutcome, u64)> {
    let started = Instant::now();
    let command = CodeqlCreateCommand {
        bin,
        target,
        output_path,
        language,
        allow_non_db_removal,
        cancellation,
        timeout,
    };
    let outcome = invoke_codeql_create_with_fallbacks(command, build_modes)?;
    Ok((outcome, started.elapsed().as_millis() as u64))
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

fn locate_codeql_bin(input: &Value) -> Result<Option<PathBuf>> {
    if let Some(value) = optional_string_input(input, &["codeqlBin", "codeql_bin"])? {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Ok(Some(path));
        }
        anyhow::bail!(
            "codeqlBin points to a missing CodeQL binary: {}",
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

fn resolve_language(input: &Value, target: &Path) -> Result<String> {
    let explicit = input
        .get("language")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|language| !language.is_empty());
    match explicit {
        Some(language) => Ok(language.to_lowercase()),
        None => autodetect_language(target),
    }
}

fn autodetect_language(target: &Path) -> Result<String> {
    let languages = detected_codeql_languages(target)?;
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

fn detected_codeql_languages(target: &Path) -> Result<BTreeSet<&'static str>> {
    anyhow::ensure!(
        target.is_dir(),
        "codeql:create-db target is not a directory: {}",
        target.display()
    );
    let mut languages = root_manifest_languages(target);
    collect_source_languages(target, &mut languages)?;
    Ok(languages)
}

fn root_manifest_languages(target: &Path) -> BTreeSet<&'static str> {
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
    .filter_map(|(name, language)| target.join(name).is_file().then_some(language))
    .collect()
}

fn collect_source_languages(dir: &Path, languages: &mut BTreeSet<&'static str>) -> Result<()> {
    let entries = fs::read_dir(dir)
        .with_context(|| format!("reading repository directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading entry below {}", dir.display()))?;
        collect_source_language_entry(&entry, languages)?;
    }
    Ok(())
}

fn collect_source_language_entry(
    entry: &fs::DirEntry,
    languages: &mut BTreeSet<&'static str>,
) -> Result<()> {
    let file_type = entry
        .file_type()
        .with_context(|| format!("inspecting {}", entry.path().display()))?;
    if file_type.is_dir() && !ignored_language_dir(&entry.file_name()) {
        return collect_source_languages(&entry.path(), languages);
    }
    if file_type.is_file() {
        languages.extend(codeql_language_for_source(&entry.path()));
    }
    Ok(())
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

fn prepare_db_directory(target: &Path, path: &Path, allow_non_db_removal: bool) -> Result<()> {
    let path = prepare_codeql_db_output_path(target, path)?;
    if path.exists() {
        if !allow_non_db_removal && !looks_like_codeql_database(&path) {
            anyhow::bail!(
                "refusing to clear explicit outputPath because it is not a CodeQL database: {}",
                path.display()
            );
        }
        fs::remove_dir_all(&path)
            .with_context(|| format!("clearing existing CodeQL DB at {}", path.display()))?;
    }
    Ok(())
}

fn prepare_codeql_db_output_path(target: &Path, path: &Path) -> Result<PathBuf> {
    let relative = path.strip_prefix(target).with_context(|| {
        format!(
            "CodeQL database output {} must stay inside target {}",
            path.display(),
            target.display()
        )
    })?;
    anyhow::ensure!(
        relative.starts_with(crate::workspace::KUZUSHI_STATE_DIR),
        "CodeQL database output {} must stay below .kuzushi",
        path.display()
    );
    crate::workspace::prepare_workspace_output_path(target, relative)
}

fn looks_like_codeql_database(path: &Path) -> bool {
    std::fs::symlink_metadata(path.join("codeql-database.yml"))
        .is_ok_and(|metadata| metadata.file_type().is_file() && !metadata.file_type().is_symlink())
}

fn invoke_codeql_create_with_fallbacks(
    command: CodeqlCreateCommand<'_>,
    build_modes: &[String],
) -> Result<CodeqlCreateOutcome> {
    let mut last_output: Option<std::process::Output> = None;
    let mut first_error = None;
    for (index, build_mode) in build_modes.iter().enumerate() {
        let output = run_codeql_create_attempt(command, build_mode)?;
        if output.status.success() {
            return completed_codeql_create_attempt(
                command.target,
                command.output_path,
                build_mode,
                index,
                first_error,
            );
        }
        if first_error.is_none() {
            first_error = Some(codeql_failure_summary(&output));
        }
        last_output = Some(output);
    }
    let output = last_output.context("no CodeQL build modes were attempted")?;
    Err(cleanup_codeql_output_after_error(
        command.target,
        command.output_path,
        codeql_failure_error(&output),
    ))
}

fn completed_codeql_create_attempt(
    target: &Path,
    output_path: &Path,
    build_mode: &str,
    attempt_index: usize,
    first_error: Option<String>,
) -> Result<CodeqlCreateOutcome> {
    validate_codeql_create_output(target, output_path)?;
    Ok(CodeqlCreateOutcome {
        build_mode: build_mode.to_string(),
        fallback: attempt_index > 0,
        first_error,
    })
}

fn run_codeql_create_attempt(
    command: CodeqlCreateCommand<'_>,
    build_mode: &str,
) -> Result<std::process::Output> {
    if command
        .cancellation
        .is_some_and(crate::scan::ScanCancellation::is_cancelled)
    {
        let error = anyhow::anyhow!("codeql:create-db was cancelled before starting an attempt");
        return Err(cleanup_codeql_output_after_error(
            command.target,
            command.output_path,
            error,
        ));
    }
    prepare_db_directory(
        command.target,
        command.output_path,
        command.allow_non_db_removal,
    )?;
    invoke_codeql_create(
        command.bin,
        command.target,
        command.output_path,
        command.language,
        build_mode,
        command.cancellation,
        command.timeout,
    )
    .map_err(|error| cleanup_codeql_output_after_error(command.target, command.output_path, error))
}

fn validate_codeql_create_output(target: &Path, output_path: &Path) -> Result<()> {
    prepare_codeql_db_output_path(target, output_path)?;
    if looks_like_codeql_database(output_path) {
        return Ok(());
    }
    let error = anyhow::anyhow!(
        "codeql reported success without a valid database at {}",
        output_path.display()
    );
    Err(cleanup_codeql_output_after_error(
        target,
        output_path,
        error,
    ))
}

fn cleanup_codeql_output_after_error(
    target: &Path,
    output_path: &Path,
    error: anyhow::Error,
) -> anyhow::Error {
    match clear_codeql_output(target, output_path) {
        Ok(()) => error,
        Err(cleanup) => cleanup.context(error),
    }
}

fn clear_codeql_output(target: &Path, output_path: &Path) -> Result<()> {
    let path = prepare_codeql_db_output_path(target, output_path)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(&path)
                .with_context(|| format!("clearing CodeQL DB at {}", path.display()))
        }
        Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(&path)
                .with_context(|| format!("clearing CodeQL output at {}", path.display()))
        }
        Ok(_) => anyhow::bail!("CodeQL output is not removable: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn invoke_codeql_create(
    bin: &Path,
    target: &Path,
    output_path: &Path,
    language: &str,
    build_mode: &str,
    cancellation: Option<&crate::scan::ScanCancellation>,
    timeout: Duration,
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
    command.stdin(Stdio::null());
    crate::bounded_subprocess::output_with_control(
        &mut command,
        "codeql database create",
        cancellation,
        timeout,
    )
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
    let output = "codeql:create-db skipped — the `codeql` CLI is not installed and no `codeqlBin` \
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
    fn db_import_source_requires_codeql_database_marker() {
        let temp = tempdir().unwrap();
        let missing = temp.path().join("absent");
        assert!(validate_db_import_source(&missing).is_err());

        let plain = temp.path().join("plain");
        fs::create_dir_all(&plain).unwrap();
        let error = validate_db_import_source(&plain).unwrap_err().to_string();
        assert!(error.contains("codeql-database.yml"), "{error}");

        fs::write(plain.join("codeql-database.yml"), "db").unwrap();
        validate_db_import_source(&plain).unwrap();
    }

    #[test]
    fn directory_copy_preserves_tree_and_skips_symlinks() {
        let source = tempdir().unwrap();
        fs::write(source.path().join("codeql-database.yml"), "db").unwrap();
        fs::create_dir_all(source.path().join("db-cpp/sub")).unwrap();
        fs::write(source.path().join("db-cpp/sub/data.bin"), "payload").unwrap();
        #[cfg(unix)]
        {
            let outside = source.path().join("codeql-database.yml");
            std::os::unix::fs::symlink(&outside, source.path().join("link.yml")).unwrap();
        }
        let destination = tempdir().unwrap();
        let copy_root = destination.path().join("copy");

        copy_directory_recursive(source.path(), &copy_root).unwrap();

        assert!(copy_root.join("codeql-database.yml").is_file());
        assert_eq!(
            fs::read_to_string(copy_root.join("db-cpp/sub/data.bin")).unwrap(),
            "payload"
        );
        #[cfg(unix)]
        assert!(!copy_root.join("link.yml").exists());
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
    fn explicit_existing_non_db_output_path_is_not_removed() {
        let temp = tempdir().unwrap();
        let output = temp.path().join(".kuzushi/not-codeql");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("important.txt"), "keep").unwrap();

        let error = prepare_db_directory(temp.path(), &output, false)
            .unwrap_err()
            .to_string();

        assert!(error.contains("refusing to clear explicit outputPath"));
        assert!(output.join("important.txt").exists());
    }

    #[test]
    fn retry_may_remove_directory_created_by_this_run() {
        let temp = tempdir().unwrap();
        let output = temp.path().join(".kuzushi/codeql-db");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("partial"), "stale").unwrap();

        prepare_db_directory(temp.path(), &output, true).unwrap();

        assert!(!output.exists());
        assert!(output.parent().unwrap().exists());
    }

    #[test]
    fn invalid_codeql_bin_option_is_not_silent_fallback() {
        let temp = tempdir().unwrap();
        let input = json!({"codeqlBin": temp.path().join("missing-codeql")});

        let error = locate_codeql_bin(&input).unwrap_err().to_string();

        assert!(error.contains("codeqlBin points to a missing CodeQL binary"));
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

    #[cfg(unix)]
    #[test]
    fn database_output_rejects_workspace_symlink() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::create_dir(workspace.path().join(".kuzushi")).unwrap();
        symlink(outside.path(), workspace.path().join(".kuzushi/codeql-db")).unwrap();
        let output = workspace.path().join(".kuzushi/codeql-db");

        assert!(prepare_db_directory(workspace.path(), &output, true).is_err());
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_failure_preserves_primary_codeql_error() {
        use std::os::unix::fs::PermissionsExt;

        let workspace = tempdir().unwrap();
        let output = workspace.path().join(".kuzushi/codeql-db");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("partial"), "stale").unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o500)).unwrap();

        let error = cleanup_codeql_output_after_error(
            workspace.path(),
            &output,
            anyhow::anyhow!("primary codeql failure"),
        );
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(error.to_string().contains("primary codeql failure"));
        let message = format!("{error:#}");

        assert!(message.contains("primary codeql failure"), "{message}");
        assert!(message.contains("clearing CodeQL DB"), "{message}");
    }

    #[test]
    fn cancellation_before_retry_cleans_partial_database() {
        let workspace = tempdir().unwrap();
        let output = workspace.path().join(".kuzushi/codeql-db");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("partial"), "stale").unwrap();
        let cancellation = crate::scan::ScanCancellation::default();
        cancellation.cancel();
        let command = CodeqlCreateCommand {
            bin: Path::new("unused-codeql"),
            target: workspace.path(),
            output_path: &output,
            language: "javascript",
            allow_non_db_removal: true,
            cancellation: Some(&cancellation),
            timeout: Duration::from_secs(1),
        };

        let error = run_codeql_create_attempt(command, "none")
            .unwrap_err()
            .to_string();

        assert!(error.contains("cancelled"), "{error}");
        assert!(!output.exists());
    }
}
