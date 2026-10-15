//! One prepared Semgrep engine shares its time allowance across job roots.
use super::*;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) struct ConfiguredSemgrepScanner {
    scanner: SemgrepScanner,
    timeout: Duration,
    jobs: usize,
    started: Mutex<Option<Instant>>,
}

impl ConfiguredSemgrepScanner {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            scanner: SemgrepScanner::from_tool_input(input)?,
            timeout: crate::bounded_subprocess::timeout_from_input(
                input,
                &["timeoutMs", "timeout_ms"],
                DEFAULT_SEMGREP_JOB_TIMEOUT_MS,
                MAX_SEMGREP_JOB_TIMEOUT_MS,
                "semgrep:scan timeoutMs",
            )?,
            started: Mutex::new(None),
            jobs: configured_jobs(input)?,
        })
    }

    fn remaining_timeout(&self) -> Result<Duration> {
        let mut started = self
            .started
            .lock()
            .map_err(|_| anyhow::anyhow!("Semgrep time accounting is unavailable"))?;
        let elapsed = started.get_or_insert_with(Instant::now).elapsed();
        self.timeout
            .checked_sub(elapsed)
            .filter(|left| !left.is_zero())
            .context("Semgrep job time allowance reached; no further process started")
    }

    pub(crate) fn scan_outcome_with_cancel(
        &self,
        target: &Path,
        cancel: &ScanCancellation,
    ) -> Result<SemgrepScanOutcome> {
        self.scanner
            .scan_outcome_with_timeout(target, cancel, self.remaining_timeout()?, self.jobs)
    }
}

impl ScanEngine for ConfiguredSemgrepScanner {
    fn id(&self) -> &'static str {
        "semgrep"
    }

    fn preflight(&self) -> Result<()> {
        self.scanner.preflight()
    }

    fn inspection_receipts(&self) -> Vec<Value> {
        let elapsed = match self.started.lock() {
            Ok(started) => started.map(|instant| instant.elapsed().as_millis() as u64),
            Err(_) => {
                return vec![json!({"engine":"semgrep","message":"Time accounting is unavailable"})]
            }
        };
        vec![
            json!({"engine":"semgrep", "configuredLimits":{"timeoutMs":self.timeout.as_millis() as u64,"jobs":self.jobs},
            "elapsedMs":elapsed, "started":elapsed.is_some(), "sourceAuthenticationIncluded":false,
            "exactFileBatching":SemgrepScanner::exact_file_batch_limits()}),
        ]
    }

    fn scan(&self, target: &Path, cancel: &ScanCancellation) -> Result<Vec<Finding>> {
        let output = self.scan_artifacts(target, cancel)?;
        output.ensure_empty_result_is_complete()?;
        Ok(output.findings)
    }

    fn scan_artifacts(&self, target: &Path, cancel: &ScanCancellation) -> Result<ScanEngineOutput> {
        let outcome = self.scan_outcome_with_cancel(target, cancel)?;
        Ok(ScanEngineOutput {
            findings: outcome.findings,
            scan_errors: outcome.scan_errors,
            codeql_sarif_documents: Vec::new(),
        })
    }

    fn supports_exact_files(&self) -> bool {
        true
    }

    fn scan_exact_files(
        &self,
        root: &Path,
        files: &[String],
        cancel: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        self.scanner.scan_exact_source_files_with_timeout(
            root,
            files,
            cancel,
            self.remaining_timeout()?,
            self.jobs,
        )
    }
}

fn configured_jobs(input: &Value) -> Result<usize> {
    let Some(value) = input.get("jobs") else {
        return Ok(1);
    };
    let jobs = value
        .as_u64()
        .context("semgrep jobs must be an integer from 1 to 256")?;
    anyhow::ensure!(
        (1..=256).contains(&jobs),
        "semgrep jobs must be an integer from 1 to 256"
    );
    Ok(jobs as usize)
}

#[cfg(test)]
mod tests;
