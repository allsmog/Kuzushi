use super::*;

impl CodeqlScanner {
    pub(in crate::scan) fn run_codeql_command(
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
        configure_scanner_subprocess_env(&mut command);
        configure_scanner_process_group(&mut command);

        let mut child = command.spawn().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "codeql: could not find CodeQL CLI {:?}. Install it with `gh extension install github/gh-codeql && gh codeql install-stub`, download it from https://github.com/github/codeql-cli-binaries/releases, or pass {{\"binary\":\"/path/to/codeql\"}}. Next: run codeql:scan {{\"binary\":\"/path/to/codeql\",\"language\":\"javascript\"}} or task block codeql.",
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
        let readers = capture_scanner_process_pipes(&mut child, "codeql")?;
        let child = cancel.register_child(child, process_group_id)?;
        let status = wait_for_scanner_process(&child, cancel)?;
        let output = join_scanner_process_readers(readers, "codeql")?;

        let Some(status) = status else {
            anyhow::bail!("codeql scan cancelled");
        };

        if !status.success() {
            let details = String::from_utf8_lossy(if output.stderr.is_empty() {
                &output.stdout
            } else {
                &output.stderr
            });
            anyhow::bail!(
                "CodeQL command failed with status {}: {} {}\n{}",
                status,
                binary,
                shell_join(args),
                details.trim()
            );
        }

        Ok(ProcessOutput {
            stdout: output.stdout,
        })
    }
}
