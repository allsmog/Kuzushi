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
                opt(
                    "heapMb",
                    OptionType::Int,
                    "Max JVM heap for joern-parse, in MB (passed as -J-Xmx). Defaults to ~75% of \
                     physical RAM. Raise this when large targets fail with a Java heap OOM.",
                )
                .advanced(),
            ],
        )],
        vec![dag("cpg:build", "cpg", &["context:build"])],
    )
}

fn announce_cpg_phase(ctx: &ToolExecutionContext<'_>, kind: &str, label: &str) {
    emit_step(ctx, kind, "build", label.to_string());
}

fn cpg_complete_label(bytes: u64, elapsed_ms: u64) -> String {
    format!(
        "cpg:build complete · {} in {} ms · ready for taint analysis",
        human_bytes(bytes),
        elapsed_ms
    )
}

/// Render a byte count as a compact human label (e.g. `16.3 MB`).
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
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
    let heap_mb = resolve_heap_mb(input);
    announce_cpg_phase(ctx, "tool", "cpg:build start");
    let started = Instant::now();
    // joern's parse is a multi-second black box; announce the phase so the
    // Activity output pane isn't silent while it runs.
    announce_cpg_phase(
        ctx,
        "tool-progress",
        &format!("parsing source with joern → CPG (heap {} MB)", heap_mb),
    );
    let output = invoke_joern_parse(&bin, &target, &output_path, heap_mb)?;
    if let Some(skip) = joern_outcome(ctx, &target, &output, heap_mb)? {
        return Ok(skip);
    }
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let bytes = fs::metadata(&output_path)
        .map(|meta| meta.len())
        .unwrap_or(0);
    announce_cpg_phase(ctx, "done", &cpg_complete_label(bytes, elapsed_ms));
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
    heap_mb: u64,
) -> Result<std::process::Output> {
    // Capture stdout/stderr instead of inheriting them: joern is noisy and,
    // when kuzushi runs inside the Ratatui alternate screen, inherited child
    // output corrupts the TUI. The captured stderr is surfaced on failure.
    // `-J-Xmx` is forwarded to the JVM by the joern-parse launcher; without it
    // the JVM defaults to ~25% of RAM and large targets die with a heap OOM.
    Command::new(bin)
        .arg(format!("-J-Xmx{heap_mb}m"))
        .arg(target)
        .arg("--output")
        .arg(output_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("spawning {}", bin.display()))
}

/// Resolve the JVM max-heap (MB) for joern-parse: an explicit `heapMb` option
/// (clamped to a sane band) or a RAM-derived default that beats the JVM's
/// stock ~25%-of-RAM ceiling.
fn resolve_heap_mb(input: &Value) -> u64 {
    input
        .get("heapMb")
        .or_else(|| input.get("heap_mb"))
        .and_then(Value::as_u64)
        .map(|mb| mb.clamp(MIN_HEAP_MB, MAX_HEAP_MB))
        .unwrap_or_else(default_heap_mb)
}

const MIN_HEAP_MB: u64 = 1024;
const MAX_HEAP_MB: u64 = 65536;

fn default_heap_mb() -> u64 {
    let ram_mb = physical_ram_mb().unwrap_or(8192);
    (ram_mb * 3 / 4).clamp(4096, 16384)
}

/// Physical RAM in MB via POSIX `sysconf` (portable across macOS and Linux),
/// or `None` when the query is unavailable.
#[cfg(unix)]
fn physical_ram_mb() -> Option<u64> {
    // SAFETY: sysconf only reads system constants; no memory is touched.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    (pages > 0 && page_size > 0).then(|| (pages as u64) * (page_size as u64) / (1024 * 1024))
}

#[cfg(not(unix))]
fn physical_ram_mb() -> Option<u64> {
    None
}

/// Interpret a finished joern-parse run: `Ok(None)` on success, `Ok(Some(skip))`
/// when an incomplete-install (missing astgen) makes a graceful skip the right
/// call, or an error otherwise.
fn joern_outcome(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    output: &std::process::Output,
    heap_mb: u64,
) -> Result<Option<Value>> {
    if output.status.success() {
        return Ok(None);
    }
    if let Some(skip) = joern_environment_skip(target, &output.stderr) {
        // Emit a terminal step so the Activity DAG row resolves (not left
        // spinning) and reads as a clean skip rather than a failure.
        emit_step(
            ctx,
            "done",
            "build",
            "cpg:build skipped — joern astgen frontend missing",
        );
        return Ok(Some(skip));
    }
    if let Some(message) = joern_oom_message(&output.stderr, heap_mb) {
        anyhow::bail!("{message}");
    }
    bail_on_joern_failure(output)?;
    Ok(None)
}

/// joern's javasrc2cpg frontend dies with a `java.lang.OutOfMemoryError` on
/// very large targets. That truncates uselessly through the generic failure
/// path, so detect it and return an actionable message carrying a parseable
/// `[retry:raise-heap:<mb>]` hint the retry gate can act on.
fn joern_oom_message(stderr: &[u8], heap_mb: u64) -> Option<String> {
    let text = String::from_utf8_lossy(stderr);
    if !text.contains("OutOfMemoryError") {
        return None;
    }
    let suggested = suggested_retry_heap_mb(heap_mb);
    Some(format!(
        "cpg:build ran out of Java heap — joern's frontend hit an OutOfMemoryError with a {heap_mb} MB \
         heap. Raise it (`cpg:build heapMb={suggested}`) or scope cpg:build to a subdirectory rather \
         than the whole tree. [retry:raise-heap:{suggested}]"
    ))
}

/// Next heap to try after an OOM: double the current heap, but stay within the
/// hard cap and below physical RAM so the retry doesn't thrash the host.
fn suggested_retry_heap_mb(heap_mb: u64) -> u64 {
    let ram_ceiling = physical_ram_mb()
        .map(|ram| ram * 9 / 10)
        .unwrap_or(MAX_HEAP_MB);
    (heap_mb * 2).min(MAX_HEAP_MB).min(ram_ceiling).max(heap_mb)
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
    use super::*;
    use serde_json::json;
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

    #[test]
    fn oom_stderr_maps_to_actionable_retry_hint() {
        let stderr =
            b"... java.lang.OutOfMemoryError: Java heap space\n\tat com.github.javaparser...";
        let message = joern_oom_message(stderr, 4096).expect("OOM should be classified");
        assert!(message.contains("OutOfMemoryError"));
        assert!(message.contains("heapMb="));
        // Carries a parseable hint the retry gate can act on.
        assert!(message.contains("[retry:raise-heap:"));
    }

    #[test]
    fn non_oom_stderr_has_no_oom_message() {
        let stderr = b"java.lang.RuntimeException: could not parse source tree";
        assert!(joern_oom_message(stderr, 4096).is_none());
    }

    #[test]
    fn resolve_heap_mb_honors_explicit_option_and_clamps() {
        assert_eq!(resolve_heap_mb(&json!({"heapMb": 12288})), 12288);
        // Below the floor clamps up; absurd values clamp to the cap.
        assert_eq!(resolve_heap_mb(&json!({"heapMb": 16})), MIN_HEAP_MB);
        assert_eq!(resolve_heap_mb(&json!({"heapMb": 999999})), MAX_HEAP_MB);
    }

    #[test]
    fn resolve_heap_mb_defaults_within_band_when_unset() {
        let heap = resolve_heap_mb(&json!({}));
        assert!(
            (4096..=16384).contains(&heap),
            "default heap {heap} out of band"
        );
    }

    #[test]
    fn suggested_retry_heap_grows_but_stays_bounded() {
        let next = suggested_retry_heap_mb(4096);
        assert!(next >= 4096, "retry heap must not shrink");
        assert!(next <= MAX_HEAP_MB);
    }
}
