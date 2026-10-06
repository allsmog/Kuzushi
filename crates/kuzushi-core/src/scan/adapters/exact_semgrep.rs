use super::*;
mod coverage;

/// Bound argument volume without adding source outside the accepted set.
pub(in crate::scan) const SEMGREP_FILES_PER_PROCESS: usize = 64;

impl SemgrepScanner {
    pub(in crate::scan) fn scan_exact_source_files(
        &self,
        root: &Path,
        files: &[String],
        cancel: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        let mut output = ScanEngineOutput::default();
        let batches = files.chunks(SEMGREP_FILES_PER_PROCESS);
        for (index, batch) in batches.enumerate() {
            match self.scan_file_batch(root, batch, cancel) {
                Ok(batch) => {
                    output.findings.extend(batch.findings);
                    output.scan_errors.extend(batch.scan_errors);
                }
                Err(error) => {
                    let remaining = files
                        .len()
                        .saturating_sub(index * SEMGREP_FILES_PER_PROCESS);
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
        let mut command = self.semgrep_command_for_files(root, &literal_files);
        let (output, status) = self.run_semgrep_command(&mut command, cancel)?;
        let coverage = coverage::exact_file_coverage(root, &literal_files, &output.stdout);
        let mut outcome = self.parse_semgrep_outcome(output, status)?;
        outcome.scan_errors.extend(coverage?);
        Ok(outcome)
    }

    fn semgrep_command_for_files(&self, root: &Path, files: &[String]) -> Command {
        let mut command = self.semgrep_base_command(root);
        command.arg("--").args(files);
        command
    }
}

#[cfg(test)]
mod tests;
