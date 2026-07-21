use super::*;
use crate::scan::{RegisteredChild, ScanCancellation};

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

const APK_MAGIC: [u8; 4] = [b'P', b'K', 0x03, 0x04];
const MAX_ANDROID_OUTPUT_ENTRIES: usize = 1_000_000;
const MAX_ANDROID_EXPANDED_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub(in crate::modules) const DEFAULT_ANDROID_COMMAND_TIMEOUT_MS: u64 = 10 * 60 * 1_000;
const MAX_ANDROID_COMMAND_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1_000;

pub(in crate::modules) fn prepare_apk(
    input: &Value,
    target: &Path,
    cancellation: &ScanCancellation,
) -> Result<PreparedApk> {
    let apk_path = resolve_apk_path(input)?;
    validate_apk_magic(&apk_path)?;
    let decompiler = read_decompiler_choice(input)?;
    let command_timeout = android_command_timeout(input)?;
    let tools = AndroidApkToolchain::from_tool_input(input);
    let workspace = AndroidApkWorkspace::create(target, command_timeout)?;
    let _prepare_lock = acquire_android_prepare_lock(&workspace.root)?;
    let staging_parent = android_staging_parent(&workspace.root)?;
    let staged = StagedAndroidOutput::new(&staging_parent, "android-decompiled")?;
    let staged_workspace = workspace.with_decompiled_root(staged.path().to_path_buf());
    staged_workspace.run_unzip(&apk_path, &tools, cancellation)?;
    if matches!(decompiler, Decompiler::Jadx | Decompiler::Both) {
        staged_workspace.run_jadx(&apk_path, &tools, cancellation)?;
    }
    if matches!(decompiler, Decompiler::Apktool | Decompiler::Both) {
        staged_workspace.run_apktool(&apk_path, &tools, cancellation)?;
    }
    staged.publish(&workspace.root, &workspace.decompiled_root)?;
    Ok(PreparedApk {
        apk: apk_path,
        decompiler,
        workspace,
    })
}

fn resolve_apk_path(input: &Value) -> Result<PathBuf> {
    let raw = read_apk_string(input)?;
    let expanded = expand_home(raw);
    let path = PathBuf::from(&expanded);
    if !path.is_file() {
        anyhow::bail!("android-apk:prepare: apk path {raw:?} is not a readable file");
    }
    Ok(path)
}

fn read_apk_string(input: &Value) -> Result<&str> {
    input
        .get("apk")
        .and_then(Value::as_str)
        .or_else(|| input.get("apkPath").and_then(Value::as_str))
        .or_else(|| input.get("apk_path").and_then(Value::as_str))
        .or_else(|| input.get("file").and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("android-apk:prepare requires 'apk': path to the .apk file"))
}

fn expand_home(raw: &str) -> String {
    if let Some(stripped) = raw.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped).display().to_string();
        }
    }
    raw.to_string()
}

fn validate_apk_magic(path: &Path) -> Result<()> {
    let mut head = [0u8; 4];
    let bytes_read = read_head(path, &mut head)?;
    if bytes_read < 4 || head != APK_MAGIC {
        anyhow::bail!(
            "android-apk:prepare: file {} is not a ZIP/APK archive (bad magic)",
            path.display()
        );
    }
    Ok(())
}

fn android_command_timeout(input: &Value) -> Result<Duration> {
    let Some(value) = input.get("timeoutMs").or_else(|| input.get("timeout_ms")) else {
        return Ok(Duration::from_millis(DEFAULT_ANDROID_COMMAND_TIMEOUT_MS));
    };
    let millis = value
        .as_u64()
        .context("android-apk timeoutMs must be a positive integer")?;
    anyhow::ensure!(millis > 0, "android-apk timeoutMs must be at least 1");
    anyhow::ensure!(
        millis <= MAX_ANDROID_COMMAND_TIMEOUT_MS,
        "android-apk timeoutMs may not exceed {MAX_ANDROID_COMMAND_TIMEOUT_MS}"
    );
    Ok(Duration::from_millis(millis))
}

fn read_head(path: &Path, head: &mut [u8]) -> Result<usize> {
    use std::io::Read;
    let mut file = fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("could not open {}: {error}", path.display()))?;
    let mut total = 0usize;
    while total < head.len() {
        match file.read(&mut head[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(error) => anyhow::bail!("read error on {}: {error}", path.display()),
        }
    }
    Ok(total)
}

fn read_decompiler_choice(input: &Value) -> Result<Decompiler> {
    let raw = input
        .get("decompiler")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("both");
    match raw {
        "jadx" => Ok(Decompiler::Jadx),
        "apktool" => Ok(Decompiler::Apktool),
        "both" => Ok(Decompiler::Both),
        other => anyhow::bail!(
            "android-apk:prepare: unknown decompiler {other:?} (expected jadx, apktool, or both)"
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::modules) enum Decompiler {
    Jadx,
    Apktool,
    Both,
}

impl Decompiler {
    fn as_str(self) -> &'static str {
        match self {
            Self::Jadx => "jadx",
            Self::Apktool => "apktool",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct AndroidApkWorkspace {
    root: PathBuf,
    decompiled_root: PathBuf,
    raw_dir: PathBuf,
    jadx_dir: PathBuf,
    apktool_dir: PathBuf,
    command_timeout: Duration,
}

impl AndroidApkWorkspace {
    fn create(workspace_root: &Path, command_timeout: Duration) -> Result<Self> {
        let root = fs::canonicalize(workspace_root)
            .with_context(|| format!("could not resolve workspace {}", workspace_root.display()))?;
        let decompiled_root =
            crate::workspace::prepare_workspace_output_path(&root, "android-decompiled")?;
        Ok(Self::at_decompiled_root(
            root,
            decompiled_root,
            command_timeout,
        ))
    }

    fn with_decompiled_root(&self, decompiled_root: PathBuf) -> Self {
        Self::at_decompiled_root(self.root.clone(), decompiled_root, self.command_timeout)
    }

    fn at_decompiled_root(
        root: PathBuf,
        decompiled_root: PathBuf,
        command_timeout: Duration,
    ) -> Self {
        let raw_dir = decompiled_root.join("raw");
        let jadx_dir = decompiled_root.join("jadx");
        let apktool_dir = decompiled_root.join("apktool");
        Self {
            root,
            decompiled_root,
            raw_dir,
            jadx_dir,
            apktool_dir,
            command_timeout,
        }
    }

    fn run_unzip(
        &self,
        apk: &Path,
        tools: &AndroidApkToolchain,
        cancellation: &ScanCancellation,
    ) -> Result<()> {
        preflight_apk_archive(apk, tools, cancellation, self.command_timeout)?;
        create_staged_android_directory(&self.raw_dir)?;
        let mut command = Command::new(&tools.unzip);
        command
            .arg("-q")
            .arg("-o")
            .arg(apk)
            .arg("-d")
            .arg(&self.raw_dir);
        let output = run_apk_command(
            command,
            "unzip",
            &tools.unzip,
            cancellation,
            Some(&self.decompiled_root),
            self.command_timeout,
        )?;
        if !output.status.success() {
            anyhow::bail!(
                "unzip exited with status {} when extracting {}: {}",
                output.status,
                apk.display(),
                crate::module_result::subprocess_failure_summary(
                    &output.stderr,
                    "unzip did not provide error details",
                )
            );
        }
        validate_workspace_dir(&self.root, &self.raw_dir)
    }

    fn run_jadx(
        &self,
        apk: &Path,
        tools: &AndroidApkToolchain,
        cancellation: &ScanCancellation,
    ) -> Result<()> {
        create_staged_android_directory(&self.jadx_dir)?;
        let mut command = Command::new(&tools.jadx);
        command
            .arg("--no-res")
            .arg("--show-bad-code")
            .arg("-d")
            .arg(&self.jadx_dir)
            .arg(apk);
        let output = run_apk_command(
            command,
            "jadx",
            &tools.jadx,
            cancellation,
            Some(&self.decompiled_root),
            self.command_timeout,
        )?;
        if !output.status.success() {
            anyhow::bail!(
                "jadx exited with status {} when decompiling {}: {}",
                output.status,
                apk.display(),
                crate::module_result::subprocess_failure_summary(
                    &output.stderr,
                    "jadx did not provide error details",
                )
            );
        }
        validate_workspace_dir(&self.root, &self.jadx_dir)
    }

    fn run_apktool(
        &self,
        apk: &Path,
        tools: &AndroidApkToolchain,
        cancellation: &ScanCancellation,
    ) -> Result<()> {
        create_staged_android_directory(&self.apktool_dir)?;
        let mut command = Command::new(&tools.apktool);
        command
            .arg("d")
            .arg("-f")
            .arg("-o")
            .arg(&self.apktool_dir)
            .arg(apk);
        let output = run_apk_command(
            command,
            "apktool",
            &tools.apktool,
            cancellation,
            Some(&self.decompiled_root),
            self.command_timeout,
        )?;
        if !output.status.success() {
            anyhow::bail!(
                "apktool exited with status {} when decoding {}: {}",
                output.status,
                apk.display(),
                crate::module_result::subprocess_failure_summary(
                    &output.stderr,
                    "apktool did not provide error details",
                )
            );
        }
        validate_workspace_dir(&self.root, &self.apktool_dir)
    }
}

fn create_staged_android_directory(path: &Path) -> Result<()> {
    fs::create_dir(path)
        .with_context(|| format!("could not create staged Android output {}", path.display()))
}

fn acquire_android_prepare_lock(
    workspace_root: &Path,
) -> Result<crate::file_lock::ExclusiveFileLock> {
    let state_dir = android_state_dir(workspace_root)?;
    crate::file_lock::ExclusiveFileLock::acquire(&state_dir.join(".android-prepare.lock"))
}

fn android_state_dir(workspace_root: &Path) -> Result<PathBuf> {
    crate::workspace::ensure_workspace_output_dir(
        workspace_root,
        Path::new(crate::workspace::KUZUSHI_STATE_DIR)
            .join(crate::workspace::WORKSPACE_STATE_VERSION_DIR),
    )
}

fn android_staging_parent(workspace_root: &Path) -> Result<PathBuf> {
    crate::workspace::ensure_workspace_output_dir(
        workspace_root,
        Path::new(crate::workspace::KUZUSHI_STATE_DIR)
            .join(crate::workspace::WORKSPACE_STATE_VERSION_DIR)
            .join("android-staging"),
    )
}

struct StagedAndroidOutput {
    directory: tempfile::TempDir,
}

impl StagedAndroidOutput {
    fn new(parent: &Path, label: &str) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix(&format!(".{label}-staged-"))
            .tempdir_in(parent)
            .with_context(|| format!("could not stage android-apk {label} output"))?;
        Ok(Self { directory })
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn publish(self, workspace_root: &Path, destination: &Path) -> Result<()> {
        validate_extracted_tree(self.path())?;
        publish_staged_directory(workspace_root, self.path(), destination)?;
        validate_workspace_dir(workspace_root, destination)
    }
}

fn preflight_apk_archive(
    apk: &Path,
    tools: &AndroidApkToolchain,
    cancellation: &ScanCancellation,
    timeout: Duration,
) -> Result<()> {
    let mut command = Command::new(&tools.unzip);
    command.arg("-l").arg(apk);
    let output = run_apk_command(
        command,
        "unzip-list",
        &tools.unzip,
        cancellation,
        None,
        timeout,
    )?;
    anyhow::ensure!(
        output.status.success(),
        "unzip could not inspect {}: {}",
        apk.display(),
        crate::module_result::subprocess_failure_summary(
            &output.stderr,
            "unzip did not provide listing error details",
        )
    );
    validate_unzip_listing(&output.stdout)
}

fn validate_unzip_listing(listing: &[u8]) -> Result<()> {
    let listing = std::str::from_utf8(listing).context("unzip listing was not UTF-8")?;
    let mut entries = 0usize;
    let mut expanded_bytes = 0u64;
    let mut in_entries = false;
    for line in listing.lines() {
        let entry = classify_unzip_listing_line(line, &mut in_entries)?;
        if entry.end {
            break;
        }
        let Some(length) = entry.size else {
            continue;
        };
        entries = entries.saturating_add(1);
        expanded_bytes = expanded_bytes
            .checked_add(length)
            .context("android-apk expanded size overflowed")?;
        enforce_android_output_quota(entries, expanded_bytes)?;
    }
    anyhow::ensure!(
        in_entries && entries > 0,
        "unzip returned no archive entries"
    );
    Ok(())
}

struct UnzipListingLine {
    size: Option<u64>,
    end: bool,
}

fn classify_unzip_listing_line(line: &str, in_entries: &mut bool) -> Result<UnzipListingLine> {
    let trimmed = line.trim();
    if trimmed.starts_with("--------") {
        let end = *in_entries;
        *in_entries = true;
        return Ok(UnzipListingLine { size: None, end });
    }
    if !*in_entries {
        return Ok(UnzipListingLine {
            size: None,
            end: false,
        });
    }
    let size = trimmed
        .split_whitespace()
        .next()
        .context("unzip listing contained an entry without a size")?
        .parse::<u64>()
        .context("unzip listing contained an invalid entry size")?;
    Ok(UnzipListingLine {
        size: Some(size),
        end: false,
    })
}

fn enforce_android_output_quota(entries: usize, bytes: u64) -> Result<()> {
    anyhow::ensure!(
        entries <= MAX_ANDROID_OUTPUT_ENTRIES,
        "android-apk output exceeds {MAX_ANDROID_OUTPUT_ENTRIES} entries"
    );
    anyhow::ensure!(
        bytes <= MAX_ANDROID_EXPANDED_BYTES,
        "android-apk output exceeds the {MAX_ANDROID_EXPANDED_BYTES}-byte expanded-size limit"
    );
    Ok(())
}

fn run_apk_command(
    command: Command,
    tool_name: &str,
    configured_path: &str,
    cancellation: &ScanCancellation,
    monitored_output: Option<&Path>,
    timeout: Duration,
) -> Result<Output> {
    let (child, readers) = spawn_apk_command(command, tool_name, configured_path, cancellation)?;
    let status = wait_for_apk_command(&child, cancellation, tool_name, monitored_output, timeout);
    let stdout = join_apk_output_reader(readers.stdout, tool_name)?;
    let stderr = join_apk_output_reader(readers.stderr, tool_name)?;
    Ok(Output {
        status: status?,
        stdout,
        stderr,
    })
}

struct ApkOutputReaders {
    stdout: std::thread::JoinHandle<Result<Vec<u8>>>,
    stderr: std::thread::JoinHandle<Result<Vec<u8>>>,
}

fn spawn_apk_command(
    mut command: Command,
    tool_name: &str,
    configured_path: &str,
    cancellation: &ScanCancellation,
) -> Result<(RegisteredChild, ApkOutputReaders)> {
    let process_group = crate::scan::configure_scanner_process_group(&mut command)?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| missing_tool_error(tool_name, configured_path, error))?;
    let stdout = child
        .stdout
        .take()
        .context("android-apk could not capture subprocess stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("android-apk could not capture subprocess stderr")?;
    let stdout = std::thread::spawn(move || {
        crate::bounded_subprocess::drain_bounded(
            stdout,
            crate::bounded_subprocess::DEFAULT_STDOUT_LIMIT,
            "android-apk stdout",
        )
    });
    let stderr = std::thread::spawn(move || {
        crate::bounded_subprocess::drain_bounded(
            stderr,
            crate::bounded_subprocess::DEFAULT_STDERR_LIMIT,
            "android-apk stderr",
        )
    });
    let child = cancellation.register_prepared_child(child, process_group)?;
    Ok((child, ApkOutputReaders { stdout, stderr }))
}

fn wait_for_apk_command(
    child: &RegisteredChild,
    cancellation: &ScanCancellation,
    tool_name: &str,
    monitored_output: Option<&Path>,
    timeout: Duration,
) -> Result<ExitStatus> {
    let mut limits = ApkRuntimeLimits {
        deadline: Instant::now() + timeout,
        next_quota_check: Instant::now(),
        monitored_output,
    };
    loop {
        enforce_apk_runtime_limits(child, cancellation, tool_name, &mut limits)?;
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => {
                child.kill_and_wait().with_context(|| {
                    format!("android-apk:{tool_name} could not clean up after a wait failure")
                })?;
                return Err(error);
            }
        }
    }
}

struct ApkRuntimeLimits<'a> {
    deadline: Instant,
    next_quota_check: Instant,
    monitored_output: Option<&'a Path>,
}

fn enforce_apk_runtime_limits(
    child: &RegisteredChild,
    cancellation: &ScanCancellation,
    tool_name: &str,
    limits: &mut ApkRuntimeLimits<'_>,
) -> Result<()> {
    if cancellation.is_cancelled() {
        child.kill_and_wait()?;
        anyhow::bail!("android-apk:{tool_name} cancelled and was killed")
    }
    if Instant::now() >= limits.deadline {
        child.kill_and_wait()?;
        anyhow::bail!("android-apk:{tool_name} exceeded its subprocess deadline")
    }
    if Instant::now() < limits.next_quota_check {
        return Ok(());
    }
    limits.next_quota_check = Instant::now() + Duration::from_millis(250);
    enforce_live_android_output_quota(limits.monitored_output).map_err(|error| {
        let _ = child.kill_and_wait();
        error.context(format!("android-apk:{tool_name} output quota exceeded"))
    })
}

fn enforce_live_android_output_quota(output: Option<&Path>) -> Result<()> {
    let Some(output) = output else {
        return Ok(());
    };
    let (entries, bytes) = measure_android_output(output)?;
    enforce_android_output_quota(entries, bytes)
}

fn measure_android_output(root: &Path) -> Result<(usize, u64)> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0usize;
    let mut bytes = 0u64;
    while let Some(directory) = pending.pop() {
        for entry in read_extracted_directory(&directory)? {
            let entry = inspect_extracted_entry(entry, &directory)?;
            entries = entries.saturating_add(1);
            bytes = bytes
                .checked_add(validate_extracted_entry(&entry, &mut pending)?)
                .context("android-apk live output size overflowed")?;
            enforce_android_output_quota(entries, bytes)?;
        }
    }
    Ok((entries, bytes))
}

fn join_apk_output_reader(
    reader: std::thread::JoinHandle<Result<Vec<u8>>>,
    tool_name: &str,
) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("android-apk:{tool_name} output reader panicked"))?
}

fn publish_staged_directory(
    workspace_root: &Path,
    staged: &Path,
    destination: &Path,
) -> Result<()> {
    let relative = workspace_relative_path(workspace_root, destination)?;
    let destination = crate::workspace::prepare_workspace_output_path(workspace_root, relative)?;
    let backup = android_staging_parent(workspace_root)?.join(format!(
        "android-decompiled-backup-{}",
        uuid::Uuid::new_v4()
    ));
    let had_previous = move_previous_android_output(&destination, &backup)?;
    if let Err(error) = fs::rename(staged, &destination) {
        let primary = anyhow::Error::from(error).context(format!(
            "could not publish android-apk output to {}",
            destination.display()
        ));
        return match restore_previous_android_output(&destination, &backup, had_previous) {
            Ok(()) => Err(primary),
            Err(restore) => Err(restore.context(primary)),
        };
    }
    if had_previous {
        if let Err(error) = fs::remove_dir_all(&backup) {
            crate::runtime_diagnostics::record_runtime_diagnostic(
                "android-apk",
                format!(
                    "Android output committed, but old backup {} could not be removed: {error}",
                    backup.display()
                ),
            );
        }
    }
    Ok(())
}

fn move_previous_android_output(destination: &Path, backup: &Path) -> Result<bool> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            fs::rename(destination, backup).with_context(|| {
                format!(
                    "could not stage previous Android output {}",
                    destination.display()
                )
            })?;
            Ok(true)
        }
        Ok(_) => anyhow::bail!(
            "android-apk output is not a real directory: {}",
            destination.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn restore_previous_android_output(
    destination: &Path,
    backup: &Path,
    had_previous: bool,
) -> Result<()> {
    if !had_previous {
        return Ok(());
    }
    fs::rename(backup, destination).with_context(|| {
        format!(
            "could not restore previous Android output {} after publish failure",
            destination.display()
        )
    })
}

fn validate_workspace_dir(workspace_root: &Path, path: &Path) -> Result<()> {
    let relative = workspace_relative_path(workspace_root, path)?;
    let safe_output = crate::workspace::ensure_workspace_output_dir(workspace_root, relative)?;
    anyhow::ensure!(
        safe_output == path,
        "android-apk output moved outside the workspace: {}",
        path.display()
    );
    validate_extracted_tree(&safe_output)
}

fn validate_extracted_tree(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries_seen = 0usize;
    let mut bytes_seen = 0u64;
    while let Some(directory) = pending.pop() {
        for entry in read_extracted_directory(&directory)? {
            let entry = inspect_extracted_entry(entry, &directory)?;
            entries_seen = entries_seen.saturating_add(1);
            bytes_seen = bytes_seen
                .checked_add(validate_extracted_entry(&entry, &mut pending)?)
                .context("android-apk extracted size overflowed")?;
            enforce_android_output_quota(entries_seen, bytes_seen)?;
        }
    }
    Ok(())
}

fn read_extracted_directory(directory: &Path) -> Result<fs::ReadDir> {
    fs::read_dir(directory).with_context(|| {
        format!(
            "could not inspect extracted directory {}",
            directory.display()
        )
    })
}

fn inspect_extracted_entry(
    entry: std::io::Result<fs::DirEntry>,
    directory: &Path,
) -> Result<fs::DirEntry> {
    entry.with_context(|| {
        format!(
            "could not inspect extracted entry under {}",
            directory.display()
        )
    })
}

fn validate_extracted_entry(entry: &fs::DirEntry, pending: &mut Vec<PathBuf>) -> Result<u64> {
    let path = entry.path();
    let file_type = entry
        .file_type()
        .with_context(|| format!("could not inspect extracted path {}", path.display()))?;
    anyhow::ensure!(
        !file_type.is_symlink(),
        "android-apk extracted output contains a symlink: {}",
        path.display()
    );
    if file_type.is_dir() {
        pending.push(path);
        return Ok(0);
    }
    anyhow::ensure!(
        file_type.is_file(),
        "android-apk extracted output contains a special file: {}",
        path.display()
    );
    fs::symlink_metadata(&path)
        .with_context(|| format!("could not measure extracted path {}", path.display()))
        .map(|metadata| metadata.len())
}

fn workspace_relative_path<'a>(workspace_root: &Path, path: &'a Path) -> Result<&'a Path> {
    path.strip_prefix(workspace_root).with_context(|| {
        format!(
            "android-apk output {} is outside workspace {}",
            path.display(),
            workspace_root.display()
        )
    })
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct PreparedApk {
    apk: PathBuf,
    decompiler: Decompiler,
    workspace: AndroidApkWorkspace,
}

impl PreparedApk {
    pub(in crate::modules) fn to_tool_json(&self) -> Value {
        let jadx_present = matches!(self.decompiler, Decompiler::Jadx | Decompiler::Both);
        let apktool_present = matches!(self.decompiler, Decompiler::Apktool | Decompiler::Both);
        let summary = format!(
            "android-apk: prepared {} into {}",
            self.apk.display(),
            self.workspace.decompiled_root.display()
        );
        json!({
            "ok": true,
            "summary": summary,
            "output": summary,
            "data": {
                "apk": self.apk.display().to_string(),
                "decompiler": self.decompiler.as_str(),
                "workspaceRoot": self.workspace.root.display().to_string(),
                "decompiledRoot": self.workspace.decompiled_root.display().to_string(),
                "rawDir": self.workspace.raw_dir.display().to_string(),
                "jadxDir": jadx_present.then(|| self.workspace.jadx_dir.display().to_string()),
                "apktoolDir": apktool_present.then(|| self.workspace.apktool_dir.display().to_string()),
                "nextSteps": [
                    format!("kuzushi scan {}", self.workspace.decompiled_root.display()),
                    "kuzushi findings --severity high,critical",
                ],
            },
            "warnings": [],
            "errors": [],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_zip_fixture(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(&APK_MAGIC).unwrap();
        file.write_all(&[0u8; 26]).unwrap();
        path
    }

    fn write_non_zip(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(b"not a zip").unwrap();
        path
    }

    #[test]
    fn validate_magic_accepts_zip_header() {
        let dir = tempdir().unwrap();
        let path = write_zip_fixture(dir.path(), "good.apk");
        validate_apk_magic(&path).expect("zip magic accepted");
    }

    #[test]
    fn validate_magic_rejects_non_zip() {
        let dir = tempdir().unwrap();
        let path = write_non_zip(dir.path(), "bad.apk");
        let error = validate_apk_magic(&path).expect_err("non-zip rejected");
        assert!(error.to_string().contains("not a ZIP/APK archive"));
    }

    #[test]
    fn resolve_apk_path_errors_when_missing() {
        let error = resolve_apk_path(&json!({})).expect_err("missing apk rejected");
        assert!(error.to_string().contains("requires 'apk'"));
    }

    #[test]
    fn resolve_apk_path_errors_on_directory() {
        let dir = tempdir().unwrap();
        let input = json!({"apk": dir.path().display().to_string()});
        let error = resolve_apk_path(&input).expect_err("directory rejected");
        assert!(error.to_string().contains("not a readable file"));
    }

    #[test]
    fn resolve_apk_path_accepts_alias_keys() {
        let dir = tempdir().unwrap();
        let path = write_zip_fixture(dir.path(), "alias.apk");
        let input = json!({"apkPath": path.display().to_string()});
        let resolved = resolve_apk_path(&input).expect("alias resolved");
        assert_eq!(resolved, path);
    }

    #[test]
    fn read_decompiler_choice_defaults_to_both() {
        assert_eq!(
            read_decompiler_choice(&json!({})).unwrap(),
            Decompiler::Both
        );
    }

    #[test]
    fn read_decompiler_choice_rejects_unknown() {
        let error =
            read_decompiler_choice(&json!({"decompiler": "ghidra"})).expect_err("unknown rejected");
        assert!(error.to_string().contains("unknown decompiler"));
    }

    #[test]
    fn android_command_timeout_rejects_zero_and_excessive_values() {
        assert!(android_command_timeout(&json!({"timeoutMs": 0})).is_err());
        assert!(android_command_timeout(&json!({
            "timeoutMs": MAX_ANDROID_COMMAND_TIMEOUT_MS + 1
        }))
        .is_err());
    }

    #[test]
    fn android_subprocess_deadline_kills_hung_child() {
        let mut command = Command::new("node");
        command.args(["-e", "setTimeout(() => {}, 60_000)"]);

        let error = run_apk_command(
            command,
            "deadline-fixture",
            "node",
            &ScanCancellation::default(),
            None,
            Duration::from_millis(10),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("subprocess deadline"), "{error}");
    }

    #[test]
    fn workspace_create_reserves_decompiled_root_without_mutating_target() {
        let dir = tempdir().unwrap();
        let workspace = AndroidApkWorkspace::create(
            dir.path(),
            Duration::from_millis(DEFAULT_ANDROID_COMMAND_TIMEOUT_MS),
        )
        .expect("workspace created");
        assert!(!workspace.decompiled_root.exists());
        assert_eq!(
            workspace.decompiled_root,
            fs::canonicalize(dir.path())
                .unwrap()
                .join("android-decompiled")
        );
    }

    #[cfg(unix)]
    #[test]
    fn workspace_create_rejects_symlinked_decompiled_root() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().unwrap();
        let outside = tempdir().unwrap();
        symlink(outside.path(), workspace.path().join("android-decompiled")).unwrap();

        assert!(AndroidApkWorkspace::create(
            workspace.path(),
            Duration::from_millis(DEFAULT_ANDROID_COMMAND_TIMEOUT_MS),
        )
        .is_err());
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn extracted_tree_rejects_symlink_entries() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().unwrap();
        let output = workspace.path().join("android-decompiled/raw");
        fs::create_dir_all(&output).unwrap();
        symlink("/etc/passwd", output.join("payload-link")).unwrap();

        let error = validate_extracted_tree(&output).unwrap_err().to_string();

        assert!(error.contains("contains a symlink"));
    }

    #[test]
    fn unzip_listing_rejects_archive_bomb_size_before_extraction() {
        let listing = format!(
            "Archive: fixture.apk\n  Length Date Time Name\n--------- ---------- ----- ----\n{} 2026-01-01 00:00 huge.bin\n---------\n",
            MAX_ANDROID_EXPANDED_BYTES + 1
        );

        let error = validate_unzip_listing(listing.as_bytes())
            .unwrap_err()
            .to_string();

        assert!(error.contains("expanded-size limit"), "{error}");
    }

    #[test]
    fn android_output_quota_rejects_excessive_entry_count() {
        let error = enforce_android_output_quota(MAX_ANDROID_OUTPUT_ENTRIES + 1, 0)
            .unwrap_err()
            .to_string();
        assert!(error.contains("exceeds") && error.contains("entries"));
    }

    #[test]
    fn live_output_measurement_rejects_oversized_sparse_file() {
        let output = tempdir().unwrap();
        fs::File::create(output.path().join("inflated.bin"))
            .unwrap()
            .set_len(MAX_ANDROID_EXPANDED_BYTES + 1)
            .unwrap();

        let error = measure_android_output(output.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("expanded-size limit"), "{error}");
    }

    #[test]
    fn live_output_measurement_is_cumulative_across_generation_stages() {
        let output = tempdir().unwrap();
        for stage in ["raw", "jadx"] {
            let stage_dir = output.path().join(stage);
            fs::create_dir(&stage_dir).unwrap();
            fs::File::create(stage_dir.join("expanded.bin"))
                .unwrap()
                .set_len(MAX_ANDROID_EXPANDED_BYTES / 2 + 1)
                .unwrap();
        }

        let error = measure_android_output(output.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("expanded-size limit"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn rejected_staged_output_preserves_previous_published_directory() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let workspace = AndroidApkWorkspace::create(
            root.path(),
            Duration::from_millis(DEFAULT_ANDROID_COMMAND_TIMEOUT_MS),
        )
        .unwrap();
        fs::create_dir_all(&workspace.raw_dir).unwrap();
        fs::write(workspace.raw_dir.join("old.txt"), "old").unwrap();
        let staged = StagedAndroidOutput::new(&workspace.root, "android-decompiled").unwrap();
        symlink("/etc/passwd", staged.path().join("payload-link")).unwrap();

        assert!(staged
            .publish(&workspace.root, &workspace.decompiled_root)
            .is_err());
        assert_eq!(
            fs::read_to_string(workspace.raw_dir.join("old.txt")).unwrap(),
            "old"
        );
    }

    #[test]
    fn whole_generation_publish_removes_stale_unselected_outputs() {
        let root = tempdir().unwrap();
        let workspace = AndroidApkWorkspace::create(
            root.path(),
            Duration::from_millis(DEFAULT_ANDROID_COMMAND_TIMEOUT_MS),
        )
        .unwrap();
        fs::create_dir_all(&workspace.apktool_dir).unwrap();
        fs::write(workspace.apktool_dir.join("stale.txt"), "old").unwrap();
        let staged = StagedAndroidOutput::new(&workspace.root, "android-decompiled").unwrap();
        fs::create_dir(staged.path().join("raw")).unwrap();
        fs::write(staged.path().join("raw/new.txt"), "new").unwrap();

        staged
            .publish(&workspace.root, &workspace.decompiled_root)
            .unwrap();

        assert_eq!(
            fs::read_to_string(workspace.raw_dir.join("new.txt")).unwrap(),
            "new"
        );
        assert!(!workspace.apktool_dir.exists());
    }
}
