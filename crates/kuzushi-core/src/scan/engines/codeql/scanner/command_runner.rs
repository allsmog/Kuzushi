use super::*;

impl CodeqlScanner {
    pub(in crate::scan) fn run_codeql_command(
        &self,
        binary: &str,
        args: &[String],
        cwd: Option<&Path>,
        cancel: &ScanCancellation,
    ) -> Result<()> {
        let output = self.run_codeql_raw_output(binary, args, cwd, cancel)?;
        validate_codeql_command_output(binary, args, output)
    }

    pub(crate) fn run_codeql_raw_output(
        &self,
        binary: &str,
        args: &[String],
        cwd: Option<&Path>,
        cancel: &ScanCancellation,
    ) -> Result<std::process::Output> {
        if cancel.is_cancelled() {
            anyhow::bail!("codeql scan cancelled");
        }
        let mut command = codeql_command(binary, args, cwd);
        crate::bounded_subprocess::output_with_control(
            &mut command,
            "codeql command",
            Some(cancel),
            self.command_timeout,
        )
        .map_err(|error| codeql_command_execution_error(binary, args, error))
    }
}

fn codeql_command(binary: &str, args: &[String], cwd: Option<&Path>) -> Command {
    let mut command = Command::new(binary);
    command.args(args).stdin(Stdio::null());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    configure_scanner_subprocess_env(&mut command);
    command
}

fn codeql_command_execution_error(
    binary: &str,
    args: &[String],
    error: anyhow::Error,
) -> anyhow::Error {
    anyhow::anyhow!(
        "codeql: command {:?} {} could not complete: {error:#}",
        binary,
        shell_join(args)
    )
}

fn validate_codeql_command_output(
    binary: &str,
    args: &[String],
    output: std::process::Output,
) -> Result<()> {
    if !output.status.success() {
        anyhow::bail!("{}", codeql_exit_error(binary, args, &output));
    }
    Ok(())
}

fn codeql_exit_error(binary: &str, args: &[String], output: &std::process::Output) -> String {
    let details = String::from_utf8_lossy(if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    });
    format!(
        "CodeQL command failed with status {}: {} {}\n{}",
        output.status,
        binary,
        shell_join(args),
        details.trim()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn codeql_command_deadline_kills_sleeping_process() {
        let scanner = CodeqlScanner {
            command_timeout: std::time::Duration::from_millis(40),
            ..CodeqlScanner::default()
        };
        let cancel = ScanCancellation::default();
        let args = vec!["-c".to_string(), "sleep 60".to_string()];

        let error = scanner
            .run_codeql_command("sh", &args, None, &cancel)
            .unwrap_err()
            .to_string();

        assert!(error.contains("deadline"), "{error}");
    }
}
