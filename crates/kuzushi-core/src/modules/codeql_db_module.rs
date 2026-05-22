use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
    let bin = match locate_codeql_bin() {
        Some(path) => path,
        None => return Ok(skipped_response(&target)),
    };
    let language = resolve_language(input, &target);
    let output_path = resolve_db_output_path(input, &target);
    prepare_db_directory(&output_path)?;
    emit_step(
        ctx,
        "tool",
        "create-db",
        format!(
            "codeql:create-db start · language={} target={}",
            language,
            target.display()
        ),
    );
    let started = Instant::now();
    let status = invoke_codeql_create(&bin, &target, &output_path, &language)?;
    if !status.success() {
        anyhow::bail!(
            "`codeql database create` exited with status {:?}; check the language flag and the source-root",
            status.code()
        );
    }
    let elapsed_ms = started.elapsed().as_millis() as u64;
    emit_step(
        ctx,
        "done",
        "create-db",
        format!(
            "codeql:create-db complete · {} in {} ms",
            output_path.display(),
            elapsed_ms
        ),
    );
    let timestamp = now_ms()?;
    Ok(codeql_db_response(
        &target,
        &output_path,
        &bin,
        &language,
        elapsed_ms,
        timestamp,
    ))
}

fn locate_codeql_bin() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("KUZUSHI_CODEQL_BIN") {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Some(path);
        }
    }
    which_on_path("codeql")
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

fn resolve_db_output_path(input: &Value, target: &Path) -> PathBuf {
    input
        .get("outputPath")
        .or_else(|| input.get("output_path"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| target.join(".kuzushi/codeql-db"))
}

fn prepare_db_directory(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)
            .with_context(|| format!("clearing existing CodeQL DB at {}", path.display()))?;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {} for CodeQL DB", parent.display()))?;
    }
    Ok(())
}

fn invoke_codeql_create(
    bin: &Path,
    target: &Path,
    output_path: &Path,
    language: &str,
) -> Result<std::process::ExitStatus> {
    Command::new(bin)
        .arg("database")
        .arg("create")
        .arg(output_path)
        .arg("--language")
        .arg(language)
        .arg("--source-root")
        .arg(target)
        .arg("--overwrite")
        .status()
        .with_context(|| format!("spawning {}", bin.display()))
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
    elapsed_ms: u64,
    timestamp: u64,
) -> Value {
    let output = format!(
        "codeql:create-db built a {language} database at {} in {} ms",
        output_path.display(),
        elapsed_ms
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "dbPath": output_path.display().to_string(),
            "language": language,
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
