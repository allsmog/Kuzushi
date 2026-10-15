use super::*;
mod batches;
mod coverage;

impl SemgrepScanner {
    pub(in crate::scan) fn exact_file_batch_limits() -> Value {
        json!({"maxFilesPerProcess":batches::MAX_FILES_PER_PROCESS,
            "maxEncodedArgumentBytes":batches::MAX_ARGUMENT_BYTES,
            "includesExecutableAndFixedArguments":true})
    }

    pub(in crate::scan) fn scan_exact_source_files(
        &self,
        root: &Path,
        files: &[String],
        cancel: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        self.scan_exact_source_files_with_timeout(
            root,
            files,
            cancel,
            std::time::Duration::from_millis(DEFAULT_SEMGREP_JOB_TIMEOUT_MS),
            1,
        )
    }

    pub(in crate::scan) fn scan_exact_source_files_with_timeout(
        &self,
        root: &Path,
        files: &[String],
        cancel: &ScanCancellation,
        timeout: std::time::Duration,
        jobs: usize,
    ) -> Result<ScanEngineOutput> {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .context("Semgrep deadline is outside the supported clock range")?;
        let mut output = ScanEngineOutput::default();
        let command = self.semgrep_command_for_files_with_jobs(root, &[], jobs);
        let batches = batches::FileBatches::new(&command, files)?;
        let mut completed_files = 0;
        for batch in batches {
            let count = batch.as_ref().map_or(0, |files| files.len());
            match batch.and_then(|files| self.scan_file_batch(root, files, cancel, deadline, jobs))
            {
                Ok(batch) => {
                    completed_files += count;
                    output.findings.extend(batch.findings);
                    output.scan_errors.extend(batch.scan_errors);
                }
                Err(error) => {
                    let remaining = files.len().saturating_sub(completed_files);
                    output.scan_errors.push(format!(
                        "Semgrep stopped before completing {remaining} selected files: {error}"
                    ));
                    break;
                }
            }
        }
        Ok(output)
    }

    fn scan_file_batch(
        &self,
        root: &Path,
        files: &[String],
        cancel: &ScanCancellation,
        deadline: std::time::Instant,
        jobs: usize,
    ) -> Result<SemgrepScanOutcome> {
        let scopes = resolve_scan_scopes(root, files)?;
        anyhow::ensure!(
            scopes.iter().all(|scope| !scope.is_directory),
            "exact Semgrep discovery requires regular files"
        );
        let literal_files = scopes
            .into_iter()
            .map(|scope| scope.relative)
            .collect::<Vec<_>>();
        let mut command = self.semgrep_command_for_files_with_jobs(root, &literal_files, jobs);
        let timeout = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|left| !left.is_zero())
            .context("Semgrep job time allowance reached; no further process started")?;
        let (output, status) =
            self.run_semgrep_command_with_timeout(&mut command, cancel, timeout)?;
        let coverage = coverage::exact_file_coverage(root, &literal_files, &output.stdout);
        let mut outcome = self.parse_semgrep_outcome(output, status)?;
        outcome.scan_errors.extend(coverage?);
        Ok(outcome)
    }

    #[cfg(test)]
    fn semgrep_command_for_files(&self, root: &Path, files: &[String]) -> Command {
        self.semgrep_command_for_files_with_jobs(root, files, 1)
    }

    fn semgrep_command_for_files_with_jobs(
        &self,
        root: &Path,
        files: &[String],
        jobs: usize,
    ) -> Command {
        let mut command = self.semgrep_base_command(root);
        command.args(["--jobs", &jobs.to_string()]);
        command.arg("--").args(files);
        command
    }
}

#[cfg(test)]
mod tests;
