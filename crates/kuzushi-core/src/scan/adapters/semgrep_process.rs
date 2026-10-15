use super::*;
use std::time::Duration;

impl SemgrepScanner {
    pub(in crate::scan) fn run_semgrep_command_with_timeout(
        &self,
        command: &mut Command,
        cancel: &ScanCancellation,
        timeout: Duration,
    ) -> Result<(ScannerProcessOutput, ExitStatus)> {
        let output = crate::bounded_subprocess::output_with_control(
            command,
            "semgrep scan",
            Some(cancel),
            timeout,
        )
        .map_err(|error| self.semgrep_process_error(error))?;
        Ok((
            ScannerProcessOutput {
                stdout: output.stdout,
                stderr: output.stderr,
            },
            output.status,
        ))
    }

    fn semgrep_process_error(&self, error: anyhow::Error) -> anyhow::Error {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
        {
            return semgrep_missing_binary_error(&self.binary);
        }
        anyhow::anyhow!(
            "semgrep: scanner {:?} could not complete: {error:#}",
            self.binary
        )
    }
}
