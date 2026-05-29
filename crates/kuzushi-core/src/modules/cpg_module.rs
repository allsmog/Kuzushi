use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub(in crate::modules) fn cpg_module() -> BuiltinModule {
    builtin_module(
        "cpg",
        "Code Property Graph",
        ModuleKind::Intel,
        "Build a Joern Code Property Graph (.kuzushi/cpg.bin) for downstream \
         taint analyses. Deterministic; wraps `joern-parse`. Honors KUZUSHI_JOERN_BIN.",
        vec![tool_with_options(
            "cpg:build",
            "Build the Joern CPG for the active target. Skips silently when joern-parse is not \
             installed; otherwise writes .kuzushi/cpg.bin.",
            vec![
                target_option(),
                opt(
                    "outputPath",
                    OptionType::Path,
                    "Destination CPG binary. Defaults to <target>/.kuzushi/cpg.bin.",
                )
                .advanced(),
            ],
        )],
        vec![dag("cpg:build", "cpg", &["context:build"])],
    )
}

pub(in crate::modules) fn run_cpg_build(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    let bin = match locate_joern_parse_bin() {
        Some(path) => path,
        None => return Ok(skipped_response(&target, "joern-parse")),
    };
    let output_path = resolve_cpg_output_path(input, &target);
    ensure_parent(&output_path)?;
    emit_step(
        ctx,
        "tool",
        "build",
        format!("cpg:build start · joern-parse {}", target.display()),
    );
    let started = Instant::now();
    let output = invoke_joern_parse(&bin, &target, &output_path)?;
    if let Some(skip) = joern_outcome(ctx, &target, &output)? {
        return Ok(skip);
    }
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let bytes = fs::metadata(&output_path).map(|meta| meta.len()).unwrap_or(0);
    emit_step(
        ctx,
        "done",
        "build",
        format!("cpg:build complete · {} bytes in {} ms", bytes, elapsed_ms),
    );
    let timestamp = now_ms()?;
    Ok(cpg_build_response(
        &target,
        &output_path,
        &bin,
        bytes,
        elapsed_ms,
        timestamp,
    ))
}

fn locate_joern_parse_bin() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("KUZUSHI_JOERN_BIN") {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Some(path);
        }
    }
    which_on_path("joern-parse")
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

fn resolve_cpg_output_path(input: &Value, target: &Path) -> PathBuf {
    input
        .get("outputPath")
        .or_else(|| input.get("output_path"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| target.join(".kuzushi/cpg.bin"))
}

fn ensure_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent)
        .with_context(|| format!("creating {} for CPG artifact", parent.display()))
}

fn invoke_joern_parse(
    bin: &Path,
    target: &Path,
    output_path: &Path,
) -> Result<std::process::Output> {
    // Capture stdout/stderr instead of inheriting them: joern is noisy and,
    // when kuzushi runs inside the Ratatui alternate screen, inherited child
    // output corrupts the TUI. The captured stderr is surfaced on failure.
    Command::new(bin)
        .arg(target)
        .arg("--output")
        .arg(output_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("spawning {}", bin.display()))
}

/// Interpret a finished joern-parse run: `Ok(None)` on success, `Ok(Some(skip))`
/// when an incomplete-install (missing astgen) makes a graceful skip the right
/// call, or an error otherwise.
fn joern_outcome(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    output: &std::process::Output,
) -> Result<Option<Value>> {
    if output.status.success() {
        return Ok(None);
    }
    if let Some(skip) = joern_environment_skip(target, &output.stderr) {
        // Emit a terminal step so the Activity DAG row resolves (not left
        // spinning) and reads as a clean skip rather than a failure.
        emit_step(ctx, "done", "build", "cpg:build skipped — joern astgen frontend missing");
        return Ok(Some(skip));
    }
    bail_on_joern_failure(output)?;
    Ok(None)
}

fn bail_on_joern_failure(output: &std::process::Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    anyhow::bail!(
        "joern-parse exited with status {:?}: {}",
        output.status.code(),
        crate::module_result::subprocess_failure_summary(
            &output.stderr,
            "check that the target is a parseable source tree"
        )
    )
}

/// A joern install can be on PATH yet incomplete — most commonly its `astgen`
/// language-frontend helper is missing (Homebrew joern downloads it lazily and
/// the download can fail). That is a missing optional dependency, not a scan
/// failure, so skip gracefully with actionable guidance instead of erroring and
/// cancelling the planning queue.
fn joern_environment_skip(target: &Path, stderr: &[u8]) -> Option<Value> {
    let text = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    let astgen_missing = text.contains("astgen")
        && (text.contains("not found")
            || text.contains("does not exist")
            || text.contains("not executable"));
    if !astgen_missing {
        return None;
    }
    let output = "cpg:build skipped — Joern is installed but its `astgen` language frontend is \
         missing, so it cannot parse this target. Reinstall Joern (e.g. `brew reinstall joern`) \
         or set ASTGEN_BIN to a working astgen binary, then re-run cpg:build."
        .to_string();
    Some(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "skipped": true,
            "reason": "joern astgen frontend not installed",
        }),
    ))
}

fn skipped_response(target: &Path, missing_bin: &str) -> Value {
    let output = format!(
        "cpg:build skipped — `{}` is not installed (KUZUSHI_JOERN_BIN unset, not on PATH). \
         Install Joern or set KUZUSHI_JOERN_BIN to enable code-property-graph construction.",
        missing_bin
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "skipped": true,
            "reason": format!("`{missing_bin}` not found"),
        }),
    )
}

fn cpg_build_response(
    target: &Path,
    output_path: &Path,
    bin: &Path,
    bytes: u64,
    elapsed_ms: u64,
    timestamp: u64,
) -> Value {
    let output = format!(
        "cpg:build wrote {} bytes to {} in {} ms",
        bytes,
        output_path.display(),
        elapsed_ms
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "cpgPath": output_path.display().to_string(),
            "joernBin": bin.display().to_string(),
            "bytes": bytes,
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
mod joern_skip_tests {
    use super::joern_environment_skip;
    use std::path::Path;

    #[test]
    fn missing_astgen_is_a_graceful_skip() {
        let stderr = b"ERROR AstGenRunner Local astgen binary not found at '/x/astgen' or is not executable!";
        let skip = joern_environment_skip(Path::new("/tmp/t"), stderr)
            .expect("astgen-missing should map to a skip");
        assert_eq!(skip["data"]["skipped"], true);
        assert!(skip["output"].as_str().unwrap().contains("astgen"));
    }

    #[test]
    fn genuine_parse_error_is_not_skipped() {
        let stderr = b"java.lang.RuntimeException: could not parse source tree";
        assert!(joern_environment_skip(Path::new("/tmp/t"), stderr).is_none());
    }
}
