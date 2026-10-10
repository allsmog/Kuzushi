use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::process::Command;
use std::time::Duration;

const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const VERSION_OUTPUT_BYTES: usize = 64 * 1024;

/// Presence is distinct from an installed dependency whose inspection failed.
pub(super) fn probe(binary: impl AsRef<OsStr>) -> Result<bool> {
    let mut command = Command::new(binary);
    command.arg("--version");
    probe_command(&mut command)
}

fn probe_command(command: &mut Command) -> Result<bool> {
    let output = crate::bounded_subprocess::output_with_limits_and_control(
        command,
        "cargo-audit availability check",
        VERSION_OUTPUT_BYTES,
        VERSION_OUTPUT_BYTES,
        VERSION_PROBE_TIMEOUT,
    );
    let output = match output {
        Ok(output) => output,
        Err(error) if missing_executable(&error) => return Ok(false),
        Err(error) => return Err(error).context("Dependency inspection failed; review explicit engine choices before preparing another plan"),
    };
    anyhow::ensure!(output.status.success(), "cargo-audit version check failed; review explicit engine choices before preparing another plan");
    Ok(true)
}

fn missing_executable(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_probe_requires_no_cargo_shim() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.arg("--help");
        assert!(probe_command(&mut command).unwrap());
    }

    #[test]
    fn missing_dependency_is_not_an_inspection_failure() {
        assert!(!probe("kuzushi-definitely-missing-cargo-audit").unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn stalled_and_failed_dependencies_do_not_become_missing() {
        let mut stalled = Command::new("/bin/sh");
        stalled.args(["-c", "sleep 20"]);
        let started = std::time::Instant::now();
        let error = probe_command(&mut stalled).unwrap_err();
        assert!(error.to_string().contains("Dependency inspection failed"));
        assert!(started.elapsed() < Duration::from_secs(4));
        let mut failed = Command::new("/bin/sh");
        failed.args(["-c", "exit 7"]);
        assert!(probe_command(&mut failed)
            .unwrap_err()
            .to_string()
            .contains("version check failed"));
    }
}
