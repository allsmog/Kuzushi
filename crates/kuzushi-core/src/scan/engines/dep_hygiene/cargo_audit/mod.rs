use super::*;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) mod config;
use config::AuditConfig;
#[cfg(test)]
mod tests;

pub(crate) struct ConfiguredCargoAuditScanner {
    config: AuditConfig,
    state: Mutex<AuditState>,
}

#[derive(Default)]
struct AuditState {
    started: Option<Instant>,
    lockfiles: Vec<Value>,
}

impl ConfiguredCargoAuditScanner {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            config: AuditConfig::from_input(input)?,
            state: Mutex::new(AuditState::default()),
        })
    }

    fn remaining_timeout(&self) -> Result<Duration> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Cargo audit time accounting is unavailable"))?;
        let elapsed = state.started.get_or_insert_with(Instant::now).elapsed();
        self.config
            .timeout
            .checked_sub(elapsed)
            .filter(|left| !left.is_zero())
            .context("Cargo audit job time allowance reached; no further process started")
    }

    fn capture_lockfile(&self, target: &Path) -> Result<Vec<u8>> {
        let lockfile = target.join("Cargo.lock");
        let text = crate::workspace::read_workspace_text(target, &lockfile, self.config.max_lockfile_bytes)
            .context("cargo-audit requires a regular Cargo.lock in the selected directory. Choose its directory or inspect unlocked manifests with sbom-scan. No audit started")?;
        let digest = Sha256::digest(text.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let record = json!({"path":lockfile, "bytes":text.len(), "sha256":digest});
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("Cargo audit capture accounting is unavailable"))?
            .lockfiles
            .push(record);
        Ok(text.into_bytes())
    }

    fn command(&self, directory: &Path) -> Command {
        let mut command = Command::new(&self.config.binary);
        command
            .args(["audit", "--json", "--file", "-"])
            .current_dir(directory);
        if let Some(database) = &self.config.database {
            command.args(["--db", database]);
        }
        if self.config.offline {
            command.args(["--no-fetch", "--no-yanked"]);
        }
        if self.config.allow_stale {
            command.arg("--stale");
        }
        command
    }
}

impl ScanEngine for ConfiguredCargoAuditScanner {
    fn id(&self) -> &'static str {
        "cargo-audit"
    }

    fn rebind_scoped_finding(&self, finding: &mut Finding, file_path: String) {
        rebind_audit_finding(finding, file_path);
    }

    fn preflight(&self) -> Result<()> {
        anyhow::ensure!(crate::scan::domain::scanner_binary_available(&self.config.binary), "cargo-audit executable {:?} is unavailable. Select an installed standalone binary; no Cargo shim or replacement is used", self.config.binary);
        Ok(())
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        anyhow::ensure!(!cancellation.is_cancelled(), "cargo-audit scan cancelled");
        self.remaining_timeout()?;
        let lockfile = self.capture_lockfile(target)?;
        self.preflight()?;
        let directory = tempfile::Builder::new()
            .prefix("kuzushi-cargo-audit-")
            .tempdir()?;
        let output = crate::bounded_subprocess::output_with_input_and_control(
            &mut self.command(directory.path()),
            "cargo-audit lockfile inspection",
            lockfile,
            Some(cancellation),
            self.remaining_timeout()?,
        )?;
        super::id::cargo_audit_findings_from_output(output)
    }

    fn inspection_receipts(&self) -> Vec<Value> {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return vec![
                    json!({"engine":"cargo-audit","message":"Time accounting is unavailable"}),
                ]
            }
        };
        vec![
            json!({"engine":"cargo-audit", "configuredLimits":{"timeoutMs":self.config.timeout.as_millis() as u64,"maxLockfileBytes":self.config.max_lockfile_bytes},
            "elapsedMs":state.started.map(|s|s.elapsed().as_millis() as u64), "started":state.started.is_some(),
            "offline":self.config.offline, "allowStale":self.config.allow_stale, "advisoryDb":self.config.database,
            "capturedLockfiles":state.lockfiles, "sourceAuthenticationIncluded":false,
            "coverage":"Selected directory Cargo.lock only; nested lockfiles and source reachability are not inspected"}),
        ]
    }
}

pub(super) fn rebind_audit_finding(finding: &mut Finding, file_path: String) {
    let package = finding
        .symbol_locator
        .as_deref()
        .and_then(|locator| locator.split_once('#'))
        .map(|(_, package)| package.to_string());
    finding.file_path = file_path;
    if let Some(package) = package {
        *finding = finding
            .clone()
            .with_structural_locator(format!("{}#{package}", finding.file_path));
    }
}
