use super::*;

impl CodeqlScanner {
    pub(crate) fn run_codeql_command(
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

        let stdout = child
            .stdout
            .take()
            .context("Could not capture codeql stdout")?;
        let stderr = child
            .stderr
            .take()
            .context("Could not capture codeql stderr")?;
        let stdout_reader = thread::spawn(move || read_pipe(stdout));
        let stderr_reader = thread::spawn(move || read_pipe(stderr));

        let child = cancel.register_child(child, process_group_id)?;

        let status = loop {
            if cancel.is_cancelled() {
                child.kill_and_wait()?;
                break None;
            }

            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            thread::sleep(Duration::from_millis(75));
        };

        let stdout = stdout_reader
            .join()
            .map_err(|_| anyhow::anyhow!("codeql stdout reader panicked"))??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow::anyhow!("codeql stderr reader panicked"))??;

        let Some(status) = status else {
            anyhow::bail!("codeql scan cancelled");
        };

        if !status.success() {
            let details =
                String::from_utf8_lossy(if stderr.is_empty() { &stdout } else { &stderr });
            anyhow::bail!(
                "CodeQL command failed with status {}: {} {}\n{}",
                status,
                binary,
                shell_join(args),
                details.trim()
            );
        }

        Ok(ProcessOutput { stdout })
    }
}
