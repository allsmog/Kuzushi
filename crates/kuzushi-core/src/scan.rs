use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::dep_hygiene::DepHygieneScanner;
use crate::findings::{Finding, FindingStore, Severity};
use crate::iac_scan::IacScanScanner;
use crate::secret_scan::SecretScanScanner;
use crate::workspace::WorkspaceTarget;

pub trait ScanEngine: Send + Sync {
    fn id(&self) -> &'static str;
    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>>;
}

#[derive(Debug, Clone)]
pub struct ScanCancellation {
    cancelled: Arc<AtomicBool>,
    next_child_id: Arc<AtomicU64>,
    children: Arc<Mutex<HashMap<u64, ManagedChild>>>,
}

impl Default for ScanCancellation {
    fn default() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            next_child_id: Arc::new(AtomicU64::new(1)),
            children: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ScanCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Ok(mut children) = self.children.lock() {
            for child in children.values_mut() {
                kill_managed_child(child);
            }
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn register_child(
        &self,
        child: Child,
        process_group_id: Option<u32>,
    ) -> Result<RegisteredChild> {
        let id = self.next_child_id.fetch_add(1, Ordering::SeqCst);
        let mut children = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("scan cancellation registry was poisoned"))?;
        children.insert(
            id,
            ManagedChild {
                child,
                process_group_id,
            },
        );
        Ok(RegisteredChild {
            id,
            children: Arc::clone(&self.children),
        })
    }
}

#[derive(Debug)]
struct RegisteredChild {
    id: u64,
    children: Arc<Mutex<HashMap<u64, ManagedChild>>>,
}

impl RegisteredChild {
    fn try_wait(&self) -> Result<Option<ExitStatus>> {
        let mut children = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("scan cancellation registry was poisoned"))?;
        let Some(managed) = children.get_mut(&self.id) else {
            return Ok(None);
        };
        let status = managed.child.try_wait()?;
        if status.is_some() {
            children.remove(&self.id);
        }
        Ok(status)
    }

    fn kill_and_wait(&self) -> Result<()> {
        let mut children = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("scan cancellation registry was poisoned"))?;
        if let Some(mut child) = children.remove(&self.id) {
            kill_managed_child(&mut child);
            let _ = child.child.wait();
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ManagedChild {
    child: Child,
    process_group_id: Option<u32>,
}

fn kill_managed_child(child: &mut ManagedChild) {
    #[cfg(unix)]
    {
        if let Some(process_group_id) = child.process_group_id {
            unsafe {
                libc::killpg(process_group_id as libc::pid_t, libc::SIGKILL);
            }
            return;
        }
    }

    let _ = child.child.kill();
}

fn child_process_group_id(child: &Child) -> Option<u32> {
    #[cfg(unix)]
    {
        Some(child.id())
    }

    #[cfg(not(unix))]
    {
        let _ = child;
        None
    }
}

#[derive(Debug, Clone)]
pub struct SemgrepScanner {
    pub binary: String,
    pub config: Vec<String>,
}

impl Default for SemgrepScanner {
    fn default() -> Self {
        Self {
            binary: "semgrep".to_string(),
            config: vec!["auto".to_string()],
        }
    }
}

impl SemgrepScanner {
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut scanner = Self::default();
        if let Some(binary) = input
            .get("binary")
            .or_else(|| input.get("scannerBin"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            scanner.binary = binary.to_string();
        }

        if let Some(config) = parse_semgrep_config_input(input)? {
            scanner.config = config;
        }

        Ok(scanner)
    }

    pub fn scan(&self, target: &Path) -> Result<Vec<Finding>> {
        self.scan_with_cancel(target, &ScanCancellation::default())
    }

    pub fn scan_with_cancel(
        &self,
        target: &Path,
        cancel: &ScanCancellation,
    ) -> Result<Vec<Finding>> {
        let output = self.run_semgrep_process(target, cancel)?;
        let stdout = String::from_utf8(output.stdout).context("semgrep emitted non-UTF8 JSON")?;
        normalize_semgrep_json(&stdout)
    }

    fn run_semgrep_process(
        &self,
        target: &Path,
        cancel: &ScanCancellation,
    ) -> Result<ProcessOutput> {
        if cancel.is_cancelled() {
            anyhow::bail!("semgrep scan cancelled");
        }

        let mut command = Command::new(&self.binary);
        command.arg("--json");
        for config in &self.config {
            command.arg("--config").arg(config);
        }
        command
            .arg(target)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(unix)]
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = command.spawn().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "semgrep: could not find scanner binary {:?}. Install Semgrep (for example `pipx install semgrep` or `brew install semgrep`) or pass {{\"binary\":\"/path/to/semgrep\"}}.",
                    self.binary
                )
            } else {
                anyhow::anyhow!("semgrep: could not start scanner {:?}: {error}", self.binary)
            }
        })?;
        let process_group_id = child_process_group_id(&child);

        let stdout = child
            .stdout
            .take()
            .context("Could not capture semgrep stdout")?;
        let stderr = child
            .stderr
            .take()
            .context("Could not capture semgrep stderr")?;
        let stdout_reader = thread::spawn(move || read_pipe(stdout));
        let stderr_reader = thread::spawn(move || read_pipe(stderr));

        let child = cancel.register_child(child, process_group_id)?;

        let status = loop {
            if cancel.is_cancelled() {
                child.kill_and_wait()?;
                break None;
            }

            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            thread::sleep(Duration::from_millis(75));
        };

        let stdout = stdout_reader
            .join()
            .map_err(|_| anyhow::anyhow!("semgrep stdout reader panicked"))??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow::anyhow!("semgrep stderr reader panicked"))??;

        let Some(status) = status else {
            anyhow::bail!("semgrep scan cancelled");
        };

        if !status.success() && stdout.is_empty() {
            anyhow::bail!(
                "semgrep failed with status {}: {}",
                status,
                String::from_utf8_lossy(&stderr)
            );
        }

        Ok(ProcessOutput { stdout })
    }
}

#[derive(Debug, Clone)]
pub struct CodeqlScanner {
    pub binary: Option<String>,
    pub db_path: Option<String>,
    pub language: Option<String>,
    pub suite: Option<String>,
    pub threads: Option<u32>,
    pub ram: Option<u32>,
    pub multi_language: bool,
}

impl Default for CodeqlScanner {
    fn default() -> Self {
        Self {
            binary: None,
            db_path: None,
            language: None,
            suite: None,
            threads: None,
            ram: None,
            multi_language: false,
        }
    }
}

impl CodeqlScanner {
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut scanner = Self::default();
        scanner.binary = optional_string_any(
            input,
            &["binary", "codeqlBinary", "codeqlBin", "scannerBin"],
        );
        scanner.db_path = optional_string_any(input, &["dbPath", "database", "databasePath"]);
        scanner.language = optional_string_any(input, &["language"])
            .and_then(|language| normalize_codeql_language(&language));
        scanner.suite = optional_string_any(input, &["suite"]);
        scanner.threads = positive_u32(input, "threads")?;
        scanner.ram = positive_u32(input, "ram")?;
        scanner.multi_language = input
            .get("multiLanguage")
            .or_else(|| input.get("multi_language"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(scanner)
    }

    pub fn scan(&self, target: &Path) -> Result<Vec<Finding>> {
        self.scan_with_cancel(target, &ScanCancellation::default())
    }

    pub fn scan_with_cancel(
        &self,
        target: &Path,
        cancel: &ScanCancellation,
    ) -> Result<Vec<Finding>> {
        if cancel.is_cancelled() {
            anyhow::bail!("codeql scan cancelled");
        }
        if !target.is_dir() {
            anyhow::bail!("codeql: target is not a directory: {}", target.display());
        }

        let binary = resolve_codeql_binary(self.binary.as_deref())?;
        let repo_name = target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("repo")
            .to_string();

        if self.multi_language && self.language.is_none() {
            let languages = detect_all_codeql_languages(target, &binary, cancel)?;
            let mut findings = Vec::new();
            let mut errors = Vec::new();
            for language in languages {
                let mut scanner = self.clone();
                scanner.language = Some(language.clone());
                scanner.multi_language = false;
                match scanner.scan_single_language(target, &binary, &repo_name, cancel) {
                    Ok(mut language_findings) => findings.append(&mut language_findings),
                    Err(error) if cancel.is_cancelled() => return Err(error),
                    Err(error) => errors.push(format!("{language}: {error}")),
                }
            }

            if findings.is_empty() && !errors.is_empty() {
                anyhow::bail!(
                    "codeql: all language analyses failed: {}",
                    errors.join("; ")
                );
            }
            return Ok(findings);
        }

        self.scan_single_language(target, &binary, &repo_name, cancel)
    }

    fn scan_single_language(
        &self,
        target: &Path,
        binary: &str,
        repo_name: &str,
        cancel: &ScanCancellation,
    ) -> Result<Vec<Finding>> {
        let database = self.ensure_database(target, binary, cancel)?;
        let suite = resolve_codeql_suite(self.suite.as_deref(), &database.language)?;
        let sarif = self.run_codeql_analysis(binary, &database.db_path, &suite, cancel)?;
        normalize_codeql_sarif(&sarif, repo_name)
    }

    fn ensure_database(
        &self,
        target: &Path,
        binary: &str,
        cancel: &ScanCancellation,
    ) -> Result<CodeqlDatabase> {
        if let Some(configured_db_path) = &self.db_path {
            let db_path = resolve_repo_path(target, configured_db_path);
            if !is_codeql_database_dir(&db_path) {
                anyhow::bail!(
                    "Configured CodeQL database path is not valid: {}",
                    db_path.display()
                );
            }

            let language = self
                .language
                .clone()
                .or_else(|| {
                    detect_language_from_database(binary, &db_path, cancel)
                        .ok()
                        .flatten()
                })
                .or_else(|| detect_codeql_language_from_heuristics(target))
                .unwrap_or_else(|| "javascript".to_string());

            return Ok(CodeqlDatabase { db_path, language });
        }

        let language = match self.language.clone() {
            Some(language) => language,
            None => detect_codeql_language(target, binary, cancel)?,
        };
        let db_path = target.join(".kuzushi").join("codeql-db");
        if is_codeql_database_dir(&db_path) {
            return Ok(CodeqlDatabase { db_path, language });
        }

        if db_path.exists() {
            if db_path.is_dir() {
                fs::remove_dir_all(&db_path).with_context(|| {
                    format!("codeql: could not remove stale {}", db_path.display())
                })?;
            } else {
                fs::remove_file(&db_path).with_context(|| {
                    format!("codeql: could not remove stale {}", db_path.display())
                })?;
            }
        }
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("codeql: could not create {}", parent.display()))?;
        }

        let mut create_args = vec![
            "database".to_string(),
            "create".to_string(),
            db_path.display().to_string(),
            format!("--language={language}"),
            "--overwrite".to_string(),
            format!("--source-root={}", target.display()),
        ];

        if is_compiled_codeql_language(&language) {
            let mut autobuild_args = create_args.clone();
            autobuild_args.push("--build-mode=autobuild".to_string());
            match self.run_codeql_command(binary, &autobuild_args, Some(target), cancel) {
                Ok(_) => {}
                Err(error) if cancel.is_cancelled() => return Err(error),
                Err(_) => {
                    self.run_codeql_command(binary, &create_args, Some(target), cancel)?;
                }
            }
        } else {
            self.run_codeql_command(binary, &create_args, Some(target), cancel)?;
        }

        create_args.clear();
        Ok(CodeqlDatabase { db_path, language })
    }

    fn run_codeql_analysis(
        &self,
        binary: &str,
        db_path: &Path,
        suite: &str,
        cancel: &ScanCancellation,
    ) -> Result<String> {
        let tmp_dir = env::temp_dir().join(format!("kuzushi-codeql-{}", Uuid::new_v4()));
        fs::create_dir_all(&tmp_dir)
            .with_context(|| format!("codeql: could not create {}", tmp_dir.display()))?;
        let output_path = tmp_dir.join("results.sarif");

        let result = (|| {
            let mut args = vec![
                "database".to_string(),
                "analyze".to_string(),
                db_path.display().to_string(),
                suite.to_string(),
                "--format=sarif-latest".to_string(),
                format!("--output={}", output_path.display()),
            ];
            if let Some(threads) = self.threads {
                args.push(format!("--threads={threads}"));
            }
            if let Some(ram) = self.ram {
                args.push(format!("--ram={ram}"));
            }

            self.run_codeql_command(binary, &args, None, cancel)?;
            fs::read_to_string(&output_path).with_context(|| {
                format!(
                    "codeql: could not read SARIF output {}",
                    output_path.display()
                )
            })
        })();

        let _ = fs::remove_dir_all(&tmp_dir);
        result
    }

    fn run_codeql_command(
        &self,
        binary: &str,
        args: &[String],
        cwd: Option<&Path>,
        cancel: &ScanCancellation,
    ) -> Result<ProcessOutput> {
        if cancel.is_cancelled() {
            anyhow::bail!("codeql scan cancelled");
        }

        let mut command = Command::new(binary);
        command.args(args);
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());

        #[cfg(unix)]
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = command.spawn().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "codeql: could not find CodeQL CLI {:?}. Install it with `gh extension install github/gh-codeql && gh codeql install-stub`, download it from https://github.com/github/codeql-cli-binaries/releases, or pass {{\"binary\":\"/path/to/codeql\"}}.",
                    binary
                )
            } else {
                anyhow::anyhow!(
                    "codeql: could not start {:?} {}: {error}",
                    binary,
                    shell_join(args)
                )
            }
        })?;
        let process_group_id = child_process_group_id(&child);

        let stdout = child
            .stdout
            .take()
            .context("Could not capture codeql stdout")?;
        let stderr = child
            .stderr
            .take()
            .context("Could not capture codeql stderr")?;
        let stdout_reader = thread::spawn(move || read_pipe(stdout));
        let stderr_reader = thread::spawn(move || read_pipe(stderr));

        let child = cancel.register_child(child, process_group_id)?;

        let status = loop {
            if cancel.is_cancelled() {
                child.kill_and_wait()?;
                break None;
            }

            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            thread::sleep(Duration::from_millis(75));
        };

        let stdout = stdout_reader
            .join()
            .map_err(|_| anyhow::anyhow!("codeql stdout reader panicked"))??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow::anyhow!("codeql stderr reader panicked"))??;

        let Some(status) = status else {
            anyhow::bail!("codeql scan cancelled");
        };

        if !status.success() {
            let details =
                String::from_utf8_lossy(if stderr.is_empty() { &stdout } else { &stderr });
            anyhow::bail!(
                "CodeQL command failed with status {}: {} {}\n{}",
                status,
                binary,
                shell_join(args),
                details.trim()
            );
        }

        Ok(ProcessOutput { stdout })
    }
}

impl ScanEngine for CodeqlScanner {
    fn id(&self) -> &'static str {
        "codeql"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        self.scan_with_cancel(target, cancellation)
    }
}

#[derive(Debug, Clone)]
struct CodeqlDatabase {
    db_path: PathBuf,
    language: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepScanReport {
    pub target: String,
    pub count: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<SemgrepPersistedRun>,
}

impl SemgrepScanReport {
    pub fn new(
        target: impl Into<String>,
        findings: Vec<Finding>,
        persisted: Option<SemgrepPersistedRun>,
    ) -> Self {
        Self {
            target: target.into(),
            count: findings.len(),
            findings,
            persisted,
        }
    }

    pub fn output(&self) -> String {
        let mut lines = vec![format!(
            "semgrep: {} finding{} under {}",
            self.count,
            if self.count == 1 { "" } else { "s" },
            self.target
        )];

        if let Some(persisted) = &self.persisted {
            lines.push(format!(
                "  Persisted run: {} ({})",
                persisted.run_id, persisted.findings_db
            ));
        }

        if !self.findings.is_empty() {
            lines.push(String::new());
            lines.push("Top findings:".to_string());
            for finding in self.findings.iter().take(10) {
                lines.push(format!(
                    "  - {} - {} - {}:{}",
                    finding.severity.as_str(),
                    finding.rule_id,
                    finding.file_path,
                    finding.start_line
                ));
            }
            if self.findings.len() > 10 {
                lines.push(format!("  ... and {} more", self.findings.len() - 10));
            }
        }

        lines.join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepPersistedRun {
    pub run_id: String,
    pub findings_db: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CodeqlScanReport {
    pub target: String,
    pub count: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<CodeqlPersistedRun>,
}

impl CodeqlScanReport {
    pub fn new(
        target: impl Into<String>,
        findings: Vec<Finding>,
        persisted: Option<CodeqlPersistedRun>,
    ) -> Self {
        Self {
            target: target.into(),
            count: findings.len(),
            findings,
            persisted,
        }
    }

    pub fn output(&self) -> String {
        let mut lines = vec![format!(
            "codeql: {} finding{} under {}",
            self.count,
            if self.count == 1 { "" } else { "s" },
            self.target
        )];

        if let Some(persisted) = &self.persisted {
            lines.push(format!(
                "  Persisted run: {} ({})",
                persisted.run_id, persisted.findings_db
            ));
        }

        if !self.findings.is_empty() {
            lines.push(String::new());
            lines.push("Top findings:".to_string());
            for finding in self.findings.iter().take(10) {
                lines.push(format!(
                    "  - {} - {} - {}:{}",
                    finding.severity.as_str(),
                    finding.rule_id,
                    finding.file_path,
                    finding.start_line
                ));
            }
            if self.findings.len() > 10 {
                lines.push(format!("  ... and {} more", self.findings.len() - 10));
            }
        }

        lines.join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CodeqlPersistedRun {
    pub run_id: String,
    pub findings_db: String,
}

fn parse_semgrep_config_input(input: &Value) -> Result<Option<Vec<String>>> {
    let Some(raw) = input.get("config").or_else(|| input.get("configFlag")) else {
        return Ok(None);
    };

    let configs = match raw {
        Value::String(value) => vec![value.trim().to_string()],
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
                    .map(ToString::to_string)
                    .with_context(|| {
                        "semgrep: config/configFlag array entries must be non-empty strings"
                    })
            })
            .collect::<Result<Vec<_>>>()?,
        _ => anyhow::bail!("semgrep: config/configFlag must be a string or string array"),
    };

    let configs = configs
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if configs.is_empty() {
        Ok(Some(vec!["auto".to_string()]))
    } else {
        Ok(Some(configs))
    }
}

impl ScanEngine for SemgrepScanner {
    fn id(&self) -> &'static str {
        "semgrep"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        self.scan_with_cancel(target, cancellation)
    }
}

#[derive(Debug)]
struct ProcessOutput {
    stdout: Vec<u8>,
}

fn read_pipe(mut pipe: impl Read) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    pipe.read_to_end(&mut output)?;
    Ok(output)
}

#[derive(Debug, Clone)]
pub struct ScanRun {
    pub id: String,
    pub target: PathBuf,
    pub findings_count: usize,
}

pub fn run_semgrep_scan(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanner: &SemgrepScanner,
) -> Result<ScanRun> {
    workspace.ensure_state_dir()?;

    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, workspace.root(), "running")?;

    let findings = scanner.scan(workspace.root())?;
    for finding in &findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;

    Ok(ScanRun {
        id: run_id,
        target: workspace.root().to_path_buf(),
        findings_count: findings.len(),
    })
}

pub fn default_scan_engines() -> Vec<Box<dyn ScanEngine>> {
    vec![
        Box::new(SemgrepScanner::default()),
        Box::new(DepHygieneScanner),
        Box::new(SecretScanScanner),
        Box::new(IacScanScanner::default()),
    ]
}

pub fn scan_engines_for_tasks(tasks: &[String]) -> Result<Vec<Box<dyn ScanEngine>>> {
    if tasks.is_empty() {
        return Ok(default_scan_engines());
    }

    let mut scanners: Vec<Box<dyn ScanEngine>> = Vec::new();
    for task in tasks {
        match task.trim() {
            "semgrep" | "semgrep:scan" => scanners.push(Box::new(SemgrepScanner::default())),
            "codeql" | "codeql:scan" => scanners.push(Box::new(CodeqlScanner::default())),
            "dep-hygiene" | "dep-hygiene:check" => scanners.push(Box::new(DepHygieneScanner)),
            "secret-scan" | "secret-scan:scan" => scanners.push(Box::new(SecretScanScanner)),
            "iac-scan" | "iac-scan:scan" => scanners.push(Box::new(IacScanScanner::default())),
            "" => {}
            other => anyhow::bail!(
                "unknown scan task {other:?}; supported tasks: semgrep, codeql, dep-hygiene, secret-scan, iac-scan, agentic, carlini-threat-hunt, taint-iris, taint-iris-next, systems-hunt"
            ),
        }
    }

    Ok(scanners)
}

pub fn run_scan_engines(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanners: &[Box<dyn ScanEngine>],
) -> Result<ScanRun> {
    run_scan_engines_with_options(workspace, store, scanners, &ScanRunOptions::default())
}

#[derive(Debug, Default, Clone)]
pub struct ScanRunOptions {
    pub severity: Option<Vec<Severity>>,
}

pub fn run_scan_engines_with_options(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanners: &[Box<dyn ScanEngine>],
    options: &ScanRunOptions,
) -> Result<ScanRun> {
    workspace.ensure_state_dir()?;

    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, workspace.root(), "running")?;

    let cancellation = ScanCancellation::default();
    let mut findings = Vec::new();
    for scanner in scanners {
        let mut scanner_findings = scanner.scan(workspace.root(), &cancellation)?;
        findings.append(&mut scanner_findings);
    }
    if let Some(allowed) = &options.severity {
        findings.retain(|finding| allowed.contains(&finding.severity));
    }

    for finding in &findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;

    Ok(ScanRun {
        id: run_id,
        target: workspace.root().to_path_buf(),
        findings_count: findings.len(),
    })
}

pub fn normalize_semgrep_json(raw: &str) -> Result<Vec<Finding>> {
    let report: SemgrepReport =
        serde_json::from_str(raw).context("Could not parse semgrep JSON")?;
    Ok(report
        .results
        .into_iter()
        .map(|result| {
            Finding::new_semgrep(
                result.check_id,
                result.path,
                result.start.line,
                result.end.map(|end| end.line),
                Severity::from_semgrep(result.extra.severity.as_deref().unwrap_or("UNKNOWN")),
                result
                    .extra
                    .message
                    .unwrap_or_else(|| "Semgrep finding".to_string()),
            )
        })
        .collect())
}

#[derive(Debug, Deserialize)]
struct SemgrepReport {
    #[serde(default)]
    results: Vec<SemgrepResult>,
}

#[derive(Debug, Deserialize)]
struct SemgrepResult {
    check_id: String,
    path: String,
    start: SemgrepLocation,
    #[serde(default)]
    end: Option<SemgrepLocation>,
    extra: SemgrepExtra,
}

#[derive(Debug, Deserialize)]
struct SemgrepLocation {
    line: u32,
}

#[derive(Debug, Deserialize)]
struct SemgrepExtra {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    severity: Option<String>,
}

pub fn normalize_codeql_sarif(raw: &str, repo_name: &str) -> Result<Vec<Finding>> {
    let report: CodeqlSarifOutput =
        serde_json::from_str(raw).context("Could not parse CodeQL SARIF output")?;
    let mut findings = Vec::new();

    for run in report.runs {
        let rules_by_id = run
            .tool
            .and_then(|tool| tool.driver)
            .map(|driver| {
                driver
                    .rules
                    .into_iter()
                    .filter_map(|rule| rule.id.clone().map(|id| (id, rule)))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();

        for result in run.results {
            let rule_id = result
                .rule_id
                .as_deref()
                .and_then(non_empty_string)
                .unwrap_or("codeql.unknown")
                .to_string();
            let rule = rules_by_id.get(&rule_id);
            let Some((file_path, start_line)) = extract_codeql_location(&result) else {
                continue;
            };
            let message = result
                .message
                .as_ref()
                .and_then(|message| message.text.as_deref().and_then(non_empty_string))
                .or_else(|| {
                    rule.and_then(|rule| {
                        rule.short_description
                            .as_ref()
                            .and_then(|description| description.text.as_deref())
                            .and_then(non_empty_string)
                    })
                })
                .unwrap_or(&rule_id)
                .to_string();
            let severity = map_codeql_severity(
                rule.and_then(|rule| rule.properties.as_ref())
                    .and_then(|properties| properties.problem.as_ref())
                    .and_then(|problem| problem.severity.as_deref()),
                result.level.as_deref(),
            );

            let message = match render_codeql_flow_evidence(&result) {
                Some(evidence) => format!("{message}\n\n{evidence}"),
                None => message,
            };

            findings.push(Finding::new_tool(
                "codeql", rule_id, file_path, start_line, None, severity, message,
            ));
        }
    }

    findings.sort_by(|left, right| {
        severity_rank(right.severity)
            .cmp(&severity_rank(left.severity))
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.start_line.cmp(&right.start_line))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    let _ = repo_name;
    Ok(findings)
}

#[derive(Debug, Deserialize)]
struct CodeqlSarifOutput {
    #[serde(default)]
    runs: Vec<CodeqlSarifRun>,
}

#[derive(Debug, Deserialize)]
struct CodeqlSarifRun {
    #[serde(default)]
    tool: Option<CodeqlSarifTool>,
    #[serde(default)]
    results: Vec<CodeqlSarifResult>,
}

#[derive(Debug, Deserialize)]
struct CodeqlSarifTool {
    #[serde(default)]
    driver: Option<CodeqlSarifDriver>,
}

#[derive(Debug, Deserialize)]
struct CodeqlSarifDriver {
    #[serde(default)]
    rules: Vec<CodeqlSarifRule>,
}

#[derive(Debug, Deserialize, Clone)]
struct CodeqlSarifRule {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "shortDescription")]
    short_description: Option<CodeqlSarifMessage>,
    #[serde(default)]
    properties: Option<CodeqlRuleProperties>,
}

#[derive(Debug, Deserialize, Clone)]
struct CodeqlRuleProperties {
    #[serde(default)]
    problem: Option<CodeqlProblemProperties>,
}

#[derive(Debug, Deserialize, Clone)]
struct CodeqlProblemProperties {
    #[serde(default)]
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CodeqlSarifResult {
    #[serde(default, rename = "ruleId")]
    rule_id: Option<String>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    message: Option<CodeqlSarifMessage>,
    #[serde(default)]
    locations: Vec<CodeqlSarifLocation>,
    #[serde(default, rename = "codeFlows")]
    code_flows: Vec<CodeqlCodeFlow>,
}

#[derive(Debug, Deserialize, Clone)]
struct CodeqlSarifMessage {
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CodeqlSarifLocation {
    #[serde(default, rename = "physicalLocation")]
    physical_location: Option<CodeqlPhysicalLocation>,
}

#[derive(Debug, Deserialize)]
struct CodeqlPhysicalLocation {
    #[serde(default, rename = "artifactLocation")]
    artifact_location: Option<CodeqlArtifactLocation>,
    #[serde(default)]
    region: Option<CodeqlRegion>,
}

#[derive(Debug, Deserialize)]
struct CodeqlArtifactLocation {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CodeqlRegion {
    #[serde(default, rename = "startLine")]
    start_line: Option<u32>,
    #[serde(default)]
    snippet: Option<CodeqlSarifMessage>,
}

#[derive(Debug, Deserialize)]
struct CodeqlCodeFlow {
    #[serde(default, rename = "threadFlows")]
    thread_flows: Vec<CodeqlThreadFlow>,
}

#[derive(Debug, Deserialize)]
struct CodeqlThreadFlow {
    #[serde(default)]
    locations: Vec<CodeqlThreadFlowLocation>,
}

#[derive(Debug, Deserialize)]
struct CodeqlThreadFlowLocation {
    #[serde(default)]
    message: Option<CodeqlSarifMessage>,
    #[serde(default)]
    location: Option<CodeqlNestedLocation>,
}

#[derive(Debug, Deserialize)]
struct CodeqlNestedLocation {
    #[serde(default)]
    message: Option<CodeqlSarifMessage>,
    #[serde(default, rename = "physicalLocation")]
    physical_location: Option<CodeqlPhysicalLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CodeqlFlowStep {
    file_path: String,
    line: u32,
    message: Option<String>,
    snippet: Option<String>,
}

fn extract_codeql_location(result: &CodeqlSarifResult) -> Option<(String, u32)> {
    for location in &result.locations {
        let physical = location.physical_location.as_ref()?;
        let uri = physical
            .artifact_location
            .as_ref()?
            .uri
            .as_deref()
            .and_then(non_empty_string)?;
        let file_path = normalize_artifact_uri(uri);
        let start_line = physical
            .region
            .as_ref()
            .and_then(|region| region.start_line)
            .filter(|line| *line > 0)
            .unwrap_or(1);
        return Some((file_path, start_line));
    }
    None
}

fn render_codeql_flow_evidence(result: &CodeqlSarifResult) -> Option<String> {
    let mut steps: Vec<CodeqlFlowStep> = Vec::new();
    for code_flow in &result.code_flows {
        for thread_flow in &code_flow.thread_flows {
            for location in &thread_flow.locations {
                let Some(nested) = location.location.as_ref() else {
                    continue;
                };
                let Some(physical) = nested.physical_location.as_ref() else {
                    continue;
                };
                let Some(artifact_location) = physical.artifact_location.as_ref() else {
                    continue;
                };
                let Some(uri) = artifact_location.uri.as_deref().and_then(non_empty_string) else {
                    continue;
                };
                let file_path = normalize_artifact_uri(uri);
                let line = physical
                    .region
                    .as_ref()
                    .and_then(|region| region.start_line)
                    .filter(|line| *line > 0)
                    .unwrap_or(1);
                let message = nested
                    .message
                    .as_ref()
                    .and_then(|message| message.text.as_deref())
                    .and_then(non_empty_string)
                    .or_else(|| {
                        location
                            .message
                            .as_ref()
                            .and_then(|message| message.text.as_deref())
                            .and_then(non_empty_string)
                    })
                    .map(ToString::to_string);
                let snippet = physical
                    .region
                    .as_ref()
                    .and_then(|region| region.snippet.as_ref())
                    .and_then(|snippet| snippet.text.as_deref())
                    .and_then(non_empty_string)
                    .map(ToString::to_string);
                let step = CodeqlFlowStep {
                    file_path,
                    line,
                    message,
                    snippet,
                };
                if steps.last() != Some(&step) {
                    steps.push(step);
                }
            }
        }
    }

    if steps.is_empty() {
        return None;
    }

    let mut segments = steps
        .iter()
        .take(16)
        .map(|step| match &step.message {
            Some(message) => format!("{}:{} ({message})", step.file_path, step.line),
            None => format!("{}:{}", step.file_path, step.line),
        })
        .collect::<Vec<_>>();
    if steps.len() > 16 {
        segments.push(format!("... {} more step(s)", steps.len() - 16));
    }
    Some(format!("Code flow: {}", segments.join(" -> ")))
}

fn map_codeql_severity(problem_severity: Option<&str>, result_level: Option<&str>) -> Severity {
    match problem_severity
        .and_then(non_empty_string)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("error") => return Severity::High,
        Some("warning") => return Severity::Medium,
        Some("recommendation") => return Severity::Low,
        _ => {}
    }

    match result_level
        .and_then(non_empty_string)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("error") => Severity::High,
        Some("warning") => Severity::Medium,
        Some("note") => Severity::Info,
        _ => Severity::Low,
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}

fn normalize_artifact_uri(uri: &str) -> String {
    let mut normalized = if let Some(rest) = uri.strip_prefix("file://") {
        percent_decode(rest)
    } else {
        uri.to_string()
    };

    normalized = normalized.replace('\\', "/");
    while normalized.starts_with('/') {
        normalized.remove(0);
    }
    if normalized.len() > 3
        && normalized.as_bytes()[1] == b':'
        && normalized.as_bytes()[2] == b'/'
        && normalized.as_bytes()[0].is_ascii_alphabetic()
    {
        normalized = normalized[3..].to_string();
    }
    normalized
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                decoded.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn resolve_codeql_binary(configured: Option<&str>) -> Result<String> {
    if let Some(binary) = configured.and_then(non_empty_string) {
        return Ok(binary.to_string());
    }

    if let Some(on_path) = find_executable_on_path("codeql") {
        return Ok(on_path.display().to_string());
    }

    if let Some(home) = dirs::home_dir() {
        let cached = home.join(".kuzushi").join("bin").join(if cfg!(windows) {
            "codeql.exe"
        } else {
            "codeql"
        });
        if cached.exists() {
            return Ok(cached.display().to_string());
        }
    }

    for candidate in ["/opt/homebrew/bin/codeql", "/usr/local/bin/codeql"] {
        let path = Path::new(candidate);
        if path.exists() {
            return Ok(path.display().to_string());
        }
    }

    anyhow::bail!(
        "CodeQL CLI not found. Install it with `gh extension install github/gh-codeql && gh codeql install-stub`, download it from https://github.com/github/codeql-cli-binaries/releases, or pass {{\"binary\":\"/path/to/codeql\"}} to codeql:scan."
    );
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    for dir in env::split_paths(&paths) {
        let candidate = dir.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = dir.join(format!("{name}.exe"));
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn detect_codeql_language(
    target: &Path,
    binary: &str,
    cancel: &ScanCancellation,
) -> Result<String> {
    if let Some(language) = detect_codeql_language_from_heuristics(target) {
        return Ok(language);
    }

    let scanner = CodeqlScanner {
        binary: Some(binary.to_string()),
        ..CodeqlScanner::default()
    };
    for args in [
        vec![
            "resolve".to_string(),
            "languages".to_string(),
            "--format=json".to_string(),
        ],
        vec!["resolve".to_string(), "languages".to_string()],
    ] {
        if let Ok(output) = scanner.run_codeql_command(binary, &args, None, cancel) {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(language) = parse_codeql_language_list(&stdout).into_iter().next() {
                return Ok(language);
            }
        }
    }

    anyhow::bail!("Unable to determine CodeQL language automatically. Pass {{\"language\":\"javascript\"}} or another supported CodeQL language to codeql:scan.");
}

fn detect_all_codeql_languages(
    target: &Path,
    binary: &str,
    cancel: &ScanCancellation,
) -> Result<Vec<String>> {
    let mut languages = Vec::new();
    if target.join("package.json").exists() {
        languages.push("javascript".to_string());
    }
    if target.join("go.mod").exists() {
        languages.push("go".to_string());
    }
    if target.join("pom.xml").exists()
        || target.join("build.gradle").exists()
        || target.join("build.gradle.kts").exists()
    {
        languages.push("java".to_string());
    }
    if target.join("requirements.txt").exists()
        || target.join("pyproject.toml").exists()
        || target.join("setup.py").exists()
    {
        languages.push("python".to_string());
    }
    if target.join("Cargo.toml").exists() {
        languages.push("rust".to_string());
    }
    if target.join("Gemfile").exists() {
        languages.push("ruby".to_string());
    }
    let top_level = fs::read_dir(target)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if top_level
        .iter()
        .any(|name| name.ends_with(".sln") || name.ends_with(".csproj"))
        && !languages.iter().any(|language| language == "csharp")
    {
        languages.push("csharp".to_string());
    }

    if languages.is_empty() {
        languages.push(detect_codeql_language(target, binary, cancel)?);
    }

    languages.sort();
    languages.dedup();
    Ok(languages)
}

fn detect_codeql_language_from_heuristics(target: &Path) -> Option<String> {
    if target.join("package.json").exists() {
        return Some("javascript".to_string());
    }
    if target.join("go.mod").exists() {
        return Some("go".to_string());
    }
    if target.join("pom.xml").exists()
        || target.join("build.gradle").exists()
        || target.join("build.gradle.kts").exists()
        || target.join("gradlew").exists()
        || target.join("mvnw").exists()
    {
        return Some("java".to_string());
    }
    if target.join("requirements.txt").exists()
        || target.join("pyproject.toml").exists()
        || target.join("setup.py").exists()
    {
        return Some("python".to_string());
    }
    if target.join("Cargo.toml").exists() {
        return Some("rust".to_string());
    }
    if target.join("Gemfile").exists() {
        return Some("ruby".to_string());
    }

    let top_level = fs::read_dir(target)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if top_level
        .iter()
        .any(|name| name.ends_with(".sln") || name.ends_with(".csproj"))
    {
        return Some("csharp".to_string());
    }
    if top_level.iter().any(|name| name.ends_with(".go")) {
        return Some("go".to_string());
    }
    if top_level.iter().any(|name| name.ends_with(".py")) {
        return Some("python".to_string());
    }
    None
}

fn detect_language_from_database(
    binary: &str,
    db_path: &Path,
    cancel: &ScanCancellation,
) -> Result<Option<String>> {
    let scanner = CodeqlScanner {
        binary: Some(binary.to_string()),
        ..CodeqlScanner::default()
    };
    let args = vec![
        "database".to_string(),
        "resolve".to_string(),
        "languages".to_string(),
        db_path.display().to_string(),
        "--format=json".to_string(),
    ];
    let output = scanner.run_codeql_command(binary, &args, None, cancel)?;
    let stdout =
        String::from_utf8(output.stdout).context("codeql emitted non-UTF8 language JSON")?;
    Ok(parse_codeql_language_list(&stdout).into_iter().next())
}

fn parse_codeql_language_list(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
        let mut languages = Vec::new();
        match parsed {
            Value::Array(values) => {
                for value in values {
                    if let Some(language) = language_from_value(&value) {
                        languages.push(language);
                    }
                }
            }
            Value::Object(map) => {
                if let Some(Value::Array(values)) = map.get("languages") {
                    for value in values {
                        if let Some(language) = language_from_value(value) {
                            languages.push(language);
                        }
                    }
                } else {
                    for key in map.keys() {
                        if let Some(language) = normalize_codeql_language(key) {
                            languages.push(language);
                        }
                    }
                }
            }
            _ => {}
        }
        languages.sort();
        languages.dedup();
        if !languages.is_empty() {
            return languages;
        }
    }

    let mut languages = trimmed
        .lines()
        .filter_map(normalize_codeql_language)
        .collect::<Vec<_>>();
    languages.sort();
    languages.dedup();
    languages
}

fn language_from_value(value: &Value) -> Option<String> {
    match value {
        Value::String(language) => normalize_codeql_language(language),
        Value::Object(map) => map
            .get("name")
            .and_then(Value::as_str)
            .and_then(normalize_codeql_language),
        _ => None,
    }
}

fn normalize_codeql_language(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if normalized.contains("javascript") || normalized.contains("typescript") {
        return Some("javascript".to_string());
    }
    if normalized.contains("python") {
        return Some("python".to_string());
    }
    if normalized == "c#" || normalized.contains("csharp") {
        return Some("csharp".to_string());
    }
    if normalized.contains("java") {
        return Some("java".to_string());
    }
    if normalized.contains("go") {
        return Some("go".to_string());
    }
    if normalized.contains("cpp") || normalized == "c++" || normalized.contains("c-cpp") {
        return Some("cpp".to_string());
    }
    if normalized.contains("swift") {
        return Some("swift".to_string());
    }
    if normalized.contains("ruby") {
        return Some("ruby".to_string());
    }
    if normalized.contains("rust") {
        return Some("rust".to_string());
    }
    None
}

fn is_compiled_codeql_language(language: &str) -> bool {
    matches!(
        language,
        "go" | "java" | "cpp" | "csharp" | "swift" | "rust"
    )
}

fn resolve_codeql_suite(configured_suite: Option<&str>, language: &str) -> Result<String> {
    let Some(suite) = configured_suite.and_then(non_empty_string) else {
        return Ok(format!(
            "codeql/{language}-queries:codeql-suites/{language}-security-and-quality.qls"
        ));
    };
    if suite.contains('/') || suite.contains(':') || suite.contains('.') {
        return Ok(suite.to_string());
    }
    Ok(format!(
        "codeql/{language}-queries:codeql-suites/{suite}.qls"
    ))
}

fn resolve_repo_path(repo_root: &Path, candidate: &str) -> PathBuf {
    let path = PathBuf::from(candidate);
    if path.is_absolute() {
        return path;
    }
    repo_root.join(path)
}

fn is_codeql_database_dir(db_path: &Path) -> bool {
    if !db_path.is_dir() {
        return false;
    }
    if db_path.join("codeql-database.yml").exists() {
        return true;
    }
    fs::read_dir(db_path)
        .map(|entries| {
            entries.filter_map(Result::ok).any(|entry| {
                entry
                    .file_type()
                    .map(|file_type| file_type.is_dir())
                    .unwrap_or(false)
                    && entry.path().join("codeql-database.yml").exists()
            })
        })
        .unwrap_or(false)
}

fn optional_string_any(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_str)
            .and_then(non_empty_string)
            .map(ToString::to_string)
    })
}

fn positive_u32(input: &Value, key: &str) -> Result<Option<u32>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let parsed = match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    };
    match parsed {
        Some(value) if value >= 1 => Ok(Some(value.min(u32::MAX as u64) as u32)),
        _ => anyhow::bail!("codeql: {key} must be a positive integer"),
    }
}

fn non_empty_string(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn shell_join(args: &[String]) -> String {
    args.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn normalizes_semgrep_json_to_findings() {
        let raw = r#"
        {
          "results": [
            {
              "check_id": "typescript.express.security.audit.xss",
              "path": "src/routes.ts",
              "start": { "line": 42 },
              "end": { "line": 44 },
              "extra": {
                "severity": "ERROR",
                "message": "Detected unescaped user input"
              }
            }
          ]
        }
        "#;

        let findings = normalize_semgrep_json(raw).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "typescript.express.security.audit.xss");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].start_line, 42);
        assert_eq!(findings[0].end_line, Some(44));
    }

    #[test]
    fn scan_runner_composes_multiple_engines() {
        struct StaticScanner;

        impl ScanEngine for StaticScanner {
            fn id(&self) -> &'static str {
                "static"
            }

            fn scan(
                &self,
                _target: &Path,
                _cancellation: &ScanCancellation,
            ) -> Result<Vec<Finding>> {
                Ok(vec![Finding::new_tool(
                    "static",
                    "static/demo",
                    "src/app.rs",
                    12,
                    None,
                    Severity::Low,
                    "static scanner finding",
                )])
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let scanners: Vec<Box<dyn ScanEngine>> =
            vec![Box::new(StaticScanner), Box::new(DepHygieneScanner)];

        let run = run_scan_engines(&workspace, &store, &scanners).unwrap();
        let findings = store.list_findings(10).unwrap();

        assert_eq!(run.findings_count, 2);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|finding| finding.tool == "static"));
        assert!(findings.iter().any(|finding| finding.tool == "dep-hygiene"));
    }

    #[test]
    fn default_scan_engines_include_native_secret_scan() {
        let engines = default_scan_engines();
        let ids = engines.iter().map(|engine| engine.id()).collect::<Vec<_>>();

        assert!(ids.contains(&"semgrep"));
        assert!(ids.contains(&"dep-hygiene"));
        assert!(ids.contains(&"secret-scan"));
        assert!(ids.contains(&"iac-scan"));
    }

    #[cfg(unix)]
    #[test]
    fn cancels_running_scanner_process() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let tmp = tempfile::tempdir().unwrap();
        let scanner_path = tmp.path().join("slow-scanner.sh");
        fs::write(
            &scanner_path,
            "#!/bin/sh\nsleep 5\nprintf '{\"results\":[]}'\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&scanner_path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&scanner_path, permissions).unwrap();

        let scanner = SemgrepScanner {
            binary: scanner_path.display().to_string(),
            config: vec!["ignored".to_string()],
        };
        let cancellation = ScanCancellation::default();
        let worker_cancellation = cancellation.clone();
        let target = tmp.path().to_path_buf();

        let started_at = Instant::now();
        let worker = thread::spawn(move || scanner.scan_with_cancel(&target, &worker_cancellation));
        thread::sleep(Duration::from_millis(200));
        cancellation.cancel();
        let err = worker.join().unwrap().unwrap_err();

        assert!(err.to_string().contains("cancelled"));
        assert!(
            started_at.elapsed() < Duration::from_secs(3),
            "cancellation should not wait for the scanner script's sleep"
        );
    }

    #[test]
    fn normalizes_codeql_sarif_to_findings() {
        let raw = r#"
        {
          "runs": [
            {
              "tool": {
                "driver": {
                  "rules": [
                    {
                      "id": "js/sql-injection",
                      "shortDescription": { "text": "SQL injection" },
                      "properties": {
                        "problem": { "severity": "error" },
                        "precision": "high",
                        "tags": ["security", "external/cwe/cwe-89"]
                      }
                    }
                  ]
                }
              },
              "results": [
                {
                  "ruleId": "js/sql-injection",
                  "message": { "text": "User input reaches SQL sink" },
                  "locations": [
                    {
                      "physicalLocation": {
                        "artifactLocation": { "uri": "src/db.ts" },
                        "region": { "startLine": 42 }
                      }
                    }
                  ],
                  "codeFlows": [
                    {
                      "threadFlows": [
                        {
                          "locations": [
                            {
                              "message": { "text": "user input enters handler" },
                              "location": {
                                "physicalLocation": {
                                  "artifactLocation": { "uri": "src/routes.ts" },
                                  "region": { "startLine": 5 }
                                }
                              }
                            },
                            {
                              "message": { "text": "query reaches db.query" },
                              "location": {
                                "physicalLocation": {
                                  "artifactLocation": { "uri": "src/db.ts" },
                                  "region": { "startLine": 42 }
                                }
                              }
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
        "#;

        let findings = normalize_codeql_sarif(raw, "repo").unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "codeql");
        assert_eq!(findings[0].rule_id, "js/sql-injection");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].file_path, "src/db.ts");
        assert_eq!(findings[0].start_line, 42);
        assert!(findings[0].message.contains("Code flow: src/routes.ts:5"));
    }

    #[cfg(unix)]
    fn fake_codeql_binary(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("codeql-fixture.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
if [ "$1" = "resolve" ] && [ "$2" = "languages" ]; then
  printf '["javascript"]'
  exit 0
fi
if [ "$1" = "database" ] && [ "$2" = "resolve" ]; then
  printf '["javascript"]'
  exit 0
fi
if [ "$1" = "database" ] && [ "$2" = "create" ]; then
  mkdir -p "$3"
  printf 'name: test\n' > "$3/codeql-database.yml"
  exit 0
fi
if [ "$1" = "database" ] && [ "$2" = "analyze" ]; then
  out=""
  for arg in "$@"; do
    case "$arg" in
      --output=*) out="${arg#--output=}" ;;
    esac
  done
  cat > "$out" <<'JSON'
{
  "runs": [
    {
      "tool": {
        "driver": {
          "rules": [
            {
              "id": "js/sql-injection",
              "properties": { "problem": { "severity": "error" } }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "js/sql-injection",
          "message": { "text": "User input reaches SQL sink" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "server.js" },
                "region": { "startLine": 9 }
              }
            }
          ]
        }
      ]
    }
  ]
}
JSON
  exit 0
fi
echo "unexpected codeql args: $*" >&2
exit 2
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    #[test]
    fn codeql_scanner_invokes_subprocess_and_normalizes_sarif() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("package.json"), "{}\n").unwrap();
        fs::write(tmp.path().join("server.js"), "db.query(req.query.q)\n").unwrap();
        let binary = fake_codeql_binary(tmp.path());
        let scanner = CodeqlScanner {
            binary: Some(binary.display().to_string()),
            language: Some("javascript".to_string()),
            ..CodeqlScanner::default()
        };

        let findings = scanner
            .scan_with_cancel(tmp.path(), &ScanCancellation::default())
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "codeql");
        assert_eq!(findings[0].rule_id, "js/sql-injection");
        assert!(tmp
            .path()
            .join(".kuzushi/codeql-db/codeql-database.yml")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn scan_runner_can_compose_codeql_with_other_engines() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        fs::write(tmp.path().join("server.js"), "db.query(req.query.q)\n").unwrap();
        let binary = fake_codeql_binary(tmp.path());
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let scanners: Vec<Box<dyn ScanEngine>> = vec![
            Box::new(CodeqlScanner {
                binary: Some(binary.display().to_string()),
                language: Some("javascript".to_string()),
                ..CodeqlScanner::default()
            }),
            Box::new(DepHygieneScanner),
        ];

        let run = run_scan_engines(&workspace, &store, &scanners).unwrap();
        let findings = store.list_findings(10).unwrap();

        assert_eq!(run.findings_count, 2);
        assert!(findings.iter().any(|finding| finding.tool == "codeql"));
        assert!(findings.iter().any(|finding| finding.tool == "dep-hygiene"));
    }

    #[test]
    fn scan_engines_for_tasks_resolves_codeql_task() {
        let engines = scan_engines_for_tasks(&["codeql".to_string()]).unwrap();
        let ids = engines.iter().map(|engine| engine.id()).collect::<Vec<_>>();

        assert_eq!(ids, vec!["codeql"]);
    }

    #[test]
    fn scan_engines_for_tasks_resolves_iac_scan_task() {
        let engines = scan_engines_for_tasks(&["iac-scan".to_string()]).unwrap();
        let ids = engines.iter().map(|engine| engine.id()).collect::<Vec<_>>();

        assert_eq!(ids, vec!["iac-scan"]);
    }

    #[cfg(unix)]
    #[test]
    fn cancels_running_codeql_process() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        fs::create_dir_all(&db).unwrap();
        fs::write(db.join("codeql-database.yml"), "name: test\n").unwrap();
        let binary = tmp.path().join("slow-codeql.sh");
        fs::write(
            &binary,
            "#!/bin/sh\nsleep 5\nout=\"\"\nfor arg in \"$@\"; do case \"$arg\" in --output=*) out=\"${arg#--output=}\" ;; esac; done\nprintf '{\"runs\":[]}' > \"$out\"\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();

        let scanner = CodeqlScanner {
            binary: Some(binary.display().to_string()),
            db_path: Some(db.display().to_string()),
            language: Some("javascript".to_string()),
            ..CodeqlScanner::default()
        };
        let cancellation = ScanCancellation::default();
        let worker_cancellation = cancellation.clone();
        let target = tmp.path().to_path_buf();

        let started_at = Instant::now();
        let worker = thread::spawn(move || scanner.scan_with_cancel(&target, &worker_cancellation));
        thread::sleep(Duration::from_millis(200));
        cancellation.cancel();
        let err = worker.join().unwrap().unwrap_err();

        assert!(err.to_string().contains("cancelled"));
        assert!(
            started_at.elapsed() < Duration::from_secs(3),
            "cancellation should not wait for the CodeQL script's sleep"
        );
    }
}
