use super::*;

impl SemgrepScanner {
    pub(in crate::scan) const SOURCE_EXCLUSION_GLOB: &'static str = "**/.kuzushi/**";

    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut scanner = Self::default();
        if let Some(binary) = input
            .get("binary")
            .or_else(|| input.get("scannerBin"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
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
        Ok(self.scan_outcome_with_cancel(target, cancel)?.findings)
    }

    /// Like [`Self::scan_with_cancel`], but also returns semgrep's reported
    /// scan errors so callers can disclose incomplete coverage.
    pub fn scan_outcome_with_cancel(
        &self,
        target: &Path,
        cancel: &ScanCancellation,
    ) -> Result<SemgrepScanOutcome> {
        self.scan_outcome_with_timeout(
            target,
            cancel,
            std::time::Duration::from_millis(DEFAULT_SEMGREP_JOB_TIMEOUT_MS),
            1,
        )
    }

    pub(in crate::scan) fn scan_outcome_with_timeout(
        &self,
        target: &Path,
        cancel: &ScanCancellation,
        timeout: std::time::Duration,
        jobs: usize,
    ) -> Result<SemgrepScanOutcome> {
        let (output, status) = self.run_semgrep_process(target, cancel, timeout, jobs)?;
        self.parse_semgrep_outcome(output, status)
    }

    pub(super) fn parse_semgrep_outcome(
        &self,
        output: ScannerProcessOutput,
        status: ExitStatus,
    ) -> Result<SemgrepScanOutcome> {
        let stdout = String::from_utf8(output.stdout).context("semgrep emitted non-UTF8 JSON")?;
        if !status.success() {
            anyhow::bail!(semgrep_run_failure(status, &stdout, &output.stderr));
        }
        let report = parse_semgrep_report(&stdout)?;
        Ok(SemgrepScanOutcome {
            scan_errors: semgrep_error_summaries(&report.errors),
            findings: semgrep_findings_from_report(report),
        })
    }

    fn run_semgrep_process(
        &self,
        target: &Path,
        cancel: &ScanCancellation,
        timeout: std::time::Duration,
        jobs: usize,
    ) -> Result<(ScannerProcessOutput, ExitStatus)> {
        if cancel.is_cancelled() {
            anyhow::bail!("semgrep scan cancelled");
        }

        let mut command = self.semgrep_command_with_jobs(target, jobs);
        self.run_semgrep_command_with_timeout(&mut command, cancel, timeout)
    }

    #[cfg(test)]
    pub(in crate::scan) fn semgrep_command(&self, target: &Path) -> Command {
        self.semgrep_command_with_jobs(target, 1)
    }

    fn semgrep_command_with_jobs(&self, target: &Path, jobs: usize) -> Command {
        let mut command = self.semgrep_base_command(target);
        command.args(["--jobs", &jobs.to_string()]).arg(".");
        command
    }

    pub(super) fn semgrep_base_command(&self, target: &Path) -> Command {
        let mut command = Command::new(&self.binary);
        command.args(["--metrics", "off", "--json"]);
        // Generated workspace evidence is not repository source. Semgrep may
        // ignore .gitignore in an unversioned target, so exclude it explicitly.
        command.args(["--exclude", Self::SOURCE_EXCLUSION_GLOB]);
        for config in &self.config {
            command.arg("--config").arg(config);
        }
        // Relative targets support wrappers that mount the working directory
        // and keep returned paths compatible with the findings ledger.
        command
            .current_dir(target)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_scanner_subprocess_env(&mut command);
        // Defense in depth: Semgrep documents both this environment setting
        // and `--metrics off`. Keep both fixed so a wrapper cannot re-enable
        // metrics by inheriting an operator environment value.
        command.env("SEMGREP_SEND_METRICS", "off");
        command
    }
}

/// Kuzushi never passes `--error`, so semgrep exits zero whenever the scan ran
/// (findings or not). A nonzero exit means semgrep itself reports a failed run
/// and must never be presented as a completed scan, even when partial JSON was
/// emitted. Prefer semgrep's own structured errors for the detail; fall back
/// to stderr.
fn semgrep_run_failure(status: ExitStatus, stdout: &str, stderr: &[u8]) -> String {
    format!(
        "semgrep failed with status {}: {}",
        status,
        semgrep_failure_detail(stdout, stderr)
    )
}

const MAX_REPORTED_SEMGREP_ERRORS: usize = 5;

fn semgrep_failure_detail(stdout: &str, stderr: &[u8]) -> String {
    let reported = parse_semgrep_report(stdout)
        .map(|report| semgrep_error_summaries(&report.errors))
        .unwrap_or_default();
    if reported.is_empty() {
        return String::from_utf8_lossy(stderr).trim().to_string();
    }
    let mut lines = reported;
    let remaining = lines.len().saturating_sub(MAX_REPORTED_SEMGREP_ERRORS);
    lines.truncate(MAX_REPORTED_SEMGREP_ERRORS);
    if remaining > 0 {
        lines.push(format!("... and {remaining} more semgrep errors"));
    }
    lines.join("; ")
}
