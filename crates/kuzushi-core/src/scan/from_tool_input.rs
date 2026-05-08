use super::*;

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
        configure_scanner_subprocess_env(&mut command);
        configure_scanner_process_group(&mut command);

        let mut child = command.spawn().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "semgrep: could not find scanner binary {:?}. Install Semgrep (for example `pipx install semgrep` or `brew install semgrep`) or pass {{\"binary\":\"/path/to/semgrep\"}}. Next: run semgrep:scan {{\"binary\":\"/path/to/semgrep\"}} or task block semgrep.",
                    self.binary
                )
            } else {
                anyhow::anyhow!("semgrep: could not start scanner {:?}: {error}", self.binary)
            }
        })?;
        let process_group_id = child_process_group_id(&child);
        let readers = capture_scanner_process_pipes(&mut child, "semgrep")?;
        let child = cancel.register_child(child, process_group_id)?;
        let status = wait_for_scanner_process(&child, cancel)?;
        let output = join_scanner_process_readers(readers, "semgrep")?;

        let Some(status) = status else {
            anyhow::bail!("semgrep scan cancelled");
        };

        if !status.success() && output.stdout.is_empty() {
            anyhow::bail!(
                "semgrep failed with status {}: {}",
                status,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(ProcessOutput {
            stdout: output.stdout,
        })
    }
}
