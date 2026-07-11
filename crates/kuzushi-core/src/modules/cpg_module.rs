use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_CPG_BUILD_TIMEOUT_MS: u64 = 30 * 60 * 1000;
const MAX_CPG_BUILD_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

pub(in crate::modules) fn cpg_module() -> BuiltinModule {
    builtin_module(
        "cpg",
        "Code Property Graph",
        ModuleKind::Intel,
        "Build a Joern Code Property Graph (.kuzushi/cpg.bin) for downstream \
         taint analyses. Deterministic; wraps `joern-parse`. Honors KUZUSHI_JOERN_BIN.",
        vec![cpg_build_tool()],
        vec![dag("cpg:build", "cpg", &["context:build"])],
    )
}

fn cpg_build_tool() -> ToolDescriptor {
    tool_with_options(
        "cpg:build",
        "Build the Joern CPG for the active target. Returns an explicit skipped result when \
         joern-parse is not installed; otherwise writes .kuzushi/cpg.bin.",
        cpg_build_options(),
    )
    .with_policy(workspace_policy(
        ToolPhase::Map,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Optional,
    ))
}

fn cpg_build_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        opt(
            "outputPath",
            OptionType::Path,
            "Destination CPG binary below <target>/.kuzushi. Defaults to <target>/.kuzushi/cpg.bin; paths outside Kuzushi state are rejected.",
        )
        .state_write()
        .advanced(),
        opt(
            "heapMb",
            OptionType::Int,
            "Max JVM heap for joern-parse, in MB (passed as -J-Xmx). Defaults to ~75% of \
             physical RAM. Raise this when large targets fail with a Java heap OOM.",
        )
        .advanced(),
        opt(
            "timeoutMs",
            OptionType::Int,
            "Joern parse deadline in milliseconds. A deadline kills and reaps the complete Joern/JVM process tree.",
        )
        .aliases(&["timeout_ms"])
        .default(json!(DEFAULT_CPG_BUILD_TIMEOUT_MS))
        .advanced(),
    ]
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
    ctx.ensure_active()?;
    let target = resolve_tool_target(input, ctx)?;
    let bin = match locate_joern_parse_bin() {
        Some(path) => path,
        None => return Ok(skipped_response(&target, "joern-parse")),
    };
    let output_path = resolve_cpg_output_path(input, &target);
    let timeout = cpg_build_timeout(input)?;
    prepare_cpg_output_path(&target, &output_path)?;
    ctx.ensure_active()?;
    clear_cpg_output(&output_path)?;
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
    if let Some(skip) = run_joern_parse_checked(ctx, &bin, &target, &output_path, heap_mb, timeout)?
    {
        return Ok(skip);
    }
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let bytes = cpg_output_size_checked(&output_path)?;
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

fn run_joern_parse_checked(
    ctx: &ToolExecutionContext<'_>,
    bin: &Path,
    target: &Path,
    output_path: &Path,
    heap_mb: u64,
    timeout: Duration,
) -> Result<Option<Value>> {
    let output = invoke_joern_parse(bin, target, output_path, heap_mb, ctx.cancellation, timeout)
        .map_err(|error| cleanup_cpg_after_error(output_path, error))?;
    let outcome = joern_outcome(ctx, target, &output, heap_mb)
        .map_err(|error| cleanup_cpg_after_error(output_path, error))?;
    if outcome.is_some() {
        clear_cpg_output(output_path)?;
    }
    Ok(outcome)
}

fn cpg_build_timeout(input: &Value) -> Result<Duration> {
    crate::bounded_subprocess::timeout_from_input(
        input,
        &["timeoutMs", "timeout_ms"],
        DEFAULT_CPG_BUILD_TIMEOUT_MS,
        MAX_CPG_BUILD_TIMEOUT_MS,
        "cpg:build timeoutMs",
    )
}

fn cpg_output_size_checked(output_path: &Path) -> Result<u64> {
    cpg_output_size(output_path).map_err(|error| cleanup_cpg_after_error(output_path, error))
}

fn cleanup_cpg_after_error(output_path: &Path, error: anyhow::Error) -> anyhow::Error {
    match clear_cpg_output(output_path) {
        Ok(()) => error,
        Err(cleanup) => cleanup.context(error),
    }
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

fn prepare_cpg_output_path(target: &Path, path: &Path) -> Result<PathBuf> {
    let relative = path.strip_prefix(target).with_context(|| {
        format!(
            "CPG output {} must stay inside target {}",
            path.display(),
            target.display()
        )
    })?;
    anyhow::ensure!(
        relative.starts_with(crate::workspace::KUZUSHI_STATE_DIR),
        "CPG output {} must stay below .kuzushi",
        path.display()
    );
    crate::workspace::prepare_workspace_output_path(target, relative)
}

fn cpg_output_size(path: &Path) -> Result<u64> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "joern reported success without output at {}",
            path.display()
        )
    })?;
    anyhow::ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "joern output is not a regular file: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() > 0,
        "joern produced an empty CPG at {}",
        path.display()
    );
    Ok(metadata.len())
}

fn clear_cpg_output(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(path)
                .with_context(|| format!("Could not clear CPG output {}", path.display()))
        }
        Ok(_) => anyhow::bail!("CPG output is not a regular file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn invoke_joern_parse(
    bin: &Path,
    target: &Path,
    output_path: &Path,
    heap_mb: u64,
    cancellation: Option<&crate::scan::ScanCancellation>,
    timeout: Duration,
) -> Result<std::process::Output> {
    // Capture stdout/stderr instead of inheriting them: joern is noisy and,
    // when kuzushi runs inside the Ratatui alternate screen, inherited child
    // output corrupts the TUI. The captured stderr is surfaced on failure.
    // `-J-Xmx` is forwarded to the JVM by the joern-parse launcher; without it
    // the JVM defaults to ~25% of RAM and large targets die with a heap OOM.
    let mut command = Command::new(bin);
    command
        .arg(format!("-J-Xmx{heap_mb}m"))
        .arg(target)
        .arg("--output")
        .arg(output_path)
        .stdin(Stdio::null());
    crate::bounded_subprocess::output_with_control(
        &mut command,
        "joern-parse",
        cancellation,
        timeout,
    )
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
    Some(crate::module_result::skipped_output_result(
        output.clone(),
        output.clone(),
        vec![json!(output)],
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
    crate::module_result::skipped_output_result(
        output.clone(),
        output.clone(),
        vec![json!(output)],
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
        assert_eq!(skip["status"], "skipped");
        assert_eq!(skip["data"]["skipped"], true);
        assert!(skip["output"].as_str().unwrap().contains("astgen"));
    }

    #[cfg(unix)]
    #[test]
    fn failed_child_symlink_output_is_unlinked_without_touching_destination() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside-cpg");
        let output = temp.path().join("cpg.bin");
        std::fs::write(&outside, "outside sentinel").unwrap();
        symlink(&outside, &output).unwrap();

        clear_cpg_output(&output).unwrap();

        assert!(!output.exists());
        assert_eq!(
            std::fs::read_to_string(outside).unwrap(),
            "outside sentinel"
        );
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
    fn build_timeout_is_defaulted_and_bounded() {
        assert_eq!(
            cpg_build_timeout(&json!({})).unwrap(),
            Duration::from_millis(DEFAULT_CPG_BUILD_TIMEOUT_MS)
        );
        assert!(cpg_build_timeout(&json!({"timeoutMs": 0})).is_err());
        assert!(cpg_build_timeout(&json!({
            "timeoutMs": MAX_CPG_BUILD_TIMEOUT_MS + 1
        }))
        .is_err());
    }

    #[test]
    fn suggested_retry_heap_grows_but_stays_bounded() {
        let next = suggested_retry_heap_mb(4096);
        assert!(next >= 4096, "retry heap must not shrink");
        assert!(next <= MAX_HEAP_MB);
    }

    #[cfg(unix)]
    #[test]
    fn cpg_output_rejects_preexisting_symlink() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::create_dir(workspace.path().join(".kuzushi")).unwrap();
        symlink(outside.path(), workspace.path().join(".kuzushi/cpg.bin")).unwrap();

        assert!(prepare_cpg_output_path(
            workspace.path(),
            &workspace.path().join(".kuzushi/cpg.bin")
        )
        .is_err());
    }
}
