use crate::findings::Finding;
use crate::scan::{ScanCancellation, ScanEngine};
use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Command, Stdio};

const GOVULNCHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Default)]
pub struct GovulncheckScanner;

impl ScanEngine for GovulncheckScanner {
    fn id(&self) -> &'static str {
        "govulncheck"
    }

    fn preflight(&self) -> Result<()> {
        ensure_govulncheck_available()
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        if cancellation.is_cancelled() {
            anyhow::bail!("govulncheck scan cancelled");
        }
        ensure_govulncheck_available()?;
        let mut command = Command::new("govulncheck");
        command
            .args(["-json", "./..."])
            .current_dir(target)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = crate::bounded_subprocess::output_with_control(
            &mut command,
            "govulncheck",
            Some(cancellation),
            GOVULNCHECK_TIMEOUT,
        )
        .with_context(|| "govulncheck: failed to invoke `govulncheck -json ./...`")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("govulncheck failed: {}", stderr.trim());
        }
        let stdout = std::str::from_utf8(&output.stdout)
            .context("govulncheck returned invalid UTF-8 output")?;
        parse_govulncheck_json(target, &stdout)
    }
}

fn ensure_govulncheck_available() -> Result<()> {
    if crate::process_lookup::executable_on_path("govulncheck").is_some() {
        return Ok(());
    }
    anyhow::bail!(
        "govulncheck: binary not found. Install it with `go install golang.org/x/vuln/cmd/govulncheck@latest`, then rerun the focused component scan."
    )
}

mod output;
pub use output::parse_govulncheck_json;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_scan_stops_before_govulncheck_preflight() {
        let cancellation = ScanCancellation::default();
        cancellation.cancel();
        let error = GovulncheckScanner
            .scan(Path::new("."), &cancellation)
            .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
    }
}
