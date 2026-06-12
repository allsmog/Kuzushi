use super::*;

impl CodeqlScanner {
    pub(crate) fn ensure_database(
        &self,
        target: &Path,
        binary: &str,
        cancel: &ScanCancellation,
    ) -> Result<CodeqlDatabase> {
        if let Some(configured_db_path) = &self.db_path {
            return self.configured_codeql_database(target, binary, cancel, configured_db_path);
        }

        let language = self.required_codeql_language(target, binary, cancel)?;
        let db_path = crate::workspace::workspace_codeql_db_path(target);
        if is_codeql_database_dir(&db_path) {
            return Ok(CodeqlDatabase { db_path, language });
        }

        remove_stale_codeql_database(&db_path)?;
        create_codeql_database_parent(&db_path)?;
        self.create_codeql_database(target, binary, cancel, &db_path, &language)?;
        Ok(CodeqlDatabase { db_path, language })
    }

    pub(crate) fn configured_codeql_database(
        &self,
        target: &Path,
        binary: &str,
        cancel: &ScanCancellation,
        configured_db_path: &str,
    ) -> Result<CodeqlDatabase> {
        let db_path = resolve_repo_path(target, configured_db_path);
        if !is_codeql_database_dir(&db_path) {
            anyhow::bail!(
                "Configured CodeQL database path is not valid: {}",
                db_path.display()
            );
        }
        Ok(CodeqlDatabase {
            language: self.configured_codeql_language(target, binary, cancel, &db_path),
            db_path,
        })
    }

    pub(crate) fn configured_codeql_language(
        &self,
        target: &Path,
        binary: &str,
        cancel: &ScanCancellation,
        db_path: &Path,
    ) -> String {
        self.language
            .clone()
            .or_else(|| {
                detect_language_from_database(binary, db_path, cancel)
                    .ok()
                    .flatten()
            })
            .or_else(|| detect_codeql_language_from_heuristics(target))
            .unwrap_or_else(|| "javascript".to_string())
    }

    pub(crate) fn required_codeql_language(
        &self,
        target: &Path,
        binary: &str,
        cancel: &ScanCancellation,
    ) -> Result<String> {
        match self.language.clone() {
            Some(language) => Ok(language),
            None => detect_codeql_language(target, binary, cancel),
        }
    }

    pub(crate) fn create_codeql_database(
        &self,
        target: &Path,
        binary: &str,
        cancel: &ScanCancellation,
        db_path: &Path,
        language: &str,
    ) -> Result<()> {
        let create_args = vec![
            "database".to_string(),
            "create".to_string(),
            db_path.display().to_string(),
            format!("--language={language}"),
            "--overwrite".to_string(),
            format!("--source-root={}", target.display()),
        ];

        let build_modes =
            crate::codeql_build_mode::codeql_build_mode_plan(language, self.build_mode.as_deref())?;
        self.run_codeql_create_plan(binary, target, cancel, db_path, &create_args, &build_modes)
    }

    fn run_codeql_create_plan(
        &self,
        binary: &str,
        target: &Path,
        cancel: &ScanCancellation,
        db_path: &Path,
        create_args: &[String],
        build_modes: &[String],
    ) -> Result<()> {
        let mut last_failure = None;
        for (index, build_mode) in build_modes.iter().enumerate() {
            if index > 0 {
                remove_stale_codeql_database(db_path)?;
                create_codeql_database_parent(db_path)?;
            }
            let args = codeql_create_args_with_build_mode(create_args, build_mode);
            match self.run_codeql_create_attempt(binary, &args, Some(target), cancel) {
                Ok(()) => return Ok(()),
                Err(failure) if failure.can_retry_with_next_mode() => {
                    last_failure = Some(failure);
                }
                Err(failure) => return Err(failure.into_error()),
            }
        }
        Err(last_failure
            .map(CodeqlCreateFailure::into_error)
            .unwrap_or_else(|| anyhow::anyhow!("codeql: no database create attempts were made")))
    }

    fn run_codeql_create_attempt(
        &self,
        binary: &str,
        args: &[String],
        cwd: Option<&Path>,
        cancel: &ScanCancellation,
    ) -> std::result::Result<(), CodeqlCreateFailure> {
        if cancel.is_cancelled() {
            return Err(CodeqlCreateFailure::Cancelled);
        }

        let command = codeql_create_command(binary, args, cwd);
        let mut child = spawn_codeql_create_child(command, binary, args)?;
        let process_group_id = child_process_group_id(&child);
        let readers = capture_scanner_process_pipes(&mut child, "codeql")
            .map_err(|error| CodeqlCreateFailure::Spawn(error.to_string()))?;
        let child = cancel
            .register_child(child, process_group_id)
            .map_err(|error| CodeqlCreateFailure::Spawn(error.to_string()))?;
        let status = wait_for_scanner_process(&child, cancel)
            .map_err(|error| CodeqlCreateFailure::Spawn(error.to_string()))?;
        let output = join_scanner_process_readers(readers, "codeql")
            .map_err(|error| CodeqlCreateFailure::Spawn(error.to_string()))?;

        let Some(status) = status else {
            return Err(CodeqlCreateFailure::Cancelled);
        };

        if !status.success() {
            return Err(codeql_create_exit_failure(
                binary,
                args,
                status,
                &output.stdout,
                &output.stderr,
            ));
        }

        Ok(())
    }
}

fn codeql_create_command(binary: &str, args: &[String], cwd: Option<&Path>) -> Command {
    let mut command = Command::new(binary);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    configure_scanner_subprocess_env(&mut command);
    configure_scanner_process_group(&mut command);
    command
}

fn spawn_codeql_create_child(
    mut command: Command,
    binary: &str,
    args: &[String],
) -> std::result::Result<std::process::Child, CodeqlCreateFailure> {
    command
        .spawn()
        .map_err(|error| CodeqlCreateFailure::Spawn(codeql_start_error(binary, args, error)))
}

enum CodeqlCreateFailure {
    Cancelled,
    Exit(String),
    Spawn(String),
}

impl CodeqlCreateFailure {
    fn can_retry_with_next_mode(&self) -> bool {
        matches!(self, Self::Exit(_))
    }

    fn into_error(self) -> anyhow::Error {
        match self {
            Self::Cancelled => anyhow::anyhow!("codeql scan cancelled"),
            Self::Exit(message) | Self::Spawn(message) => anyhow::anyhow!(message),
        }
    }
}

fn codeql_start_error(binary: &str, args: &[String], error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::NotFound {
        return format!(
            "codeql: could not find CodeQL CLI {:?}. Install it with `gh extension install github/gh-codeql && gh codeql install-stub`, download it from https://github.com/github/codeql-cli-binaries/releases, or pass {{\"binary\":\"/path/to/codeql\"}}. Next: run codeql:scan {{\"binary\":\"/path/to/codeql\",\"language\":\"javascript\"}} or task block codeql.",
            binary
        );
    }
    format!(
        "codeql: could not start {:?} {}: {error}",
        binary,
        shell_join(args)
    )
}

fn codeql_create_exit_failure(
    binary: &str,
    args: &[String],
    status: std::process::ExitStatus,
    stdout: &[u8],
    stderr: &[u8],
) -> CodeqlCreateFailure {
    let details = String::from_utf8_lossy(if stderr.is_empty() { stdout } else { stderr });
    CodeqlCreateFailure::Exit(format!(
        "CodeQL command failed with status {}: {} {}\n{}",
        status,
        binary,
        shell_join(args),
        details.trim()
    ))
}

fn codeql_create_args_with_build_mode(create_args: &[String], build_mode: &str) -> Vec<String> {
    let mut args = create_args.to_vec();
    if build_mode != "default" {
        args.push(format!("--build-mode={build_mode}"));
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn write_fake_codeql(root: &Path, script: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = root.join("codeql");
        fs::write(&path, script).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    #[cfg(unix)]
    fn fallback_fake_script(log: &Path) -> String {
        format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
db="$3"
printf '%s\n' "$*" >> "{log}"
case "$*" in
  *"--build-mode=autobuild"*)
    mkdir -p "$db"
    printf 'partial\n' > "$db/partial"
    printf 'autobuild failed\n' >&2
    exit 7
    ;;
  *"--build-mode=none"*)
    if [ -e "$db/partial" ]; then
      printf 'partial db was not removed\n' >&2
      exit 8
    fi
    mkdir -p "$db"
    printf 'primaryLanguage: cpp\n' > "$db/codeql-database.yml"
    exit 0
    ;;
  *)
    printf 'unexpected args: %s\n' "$*" >&2
    exit 9
    ;;
esac
"#,
            log = log.display()
        )
    }

    #[cfg(unix)]
    #[test]
    fn compiled_language_retries_none_after_autobuild_exit() {
        let temp = tempdir().unwrap();
        let repo = temp.path().join("repo");
        let db = temp.path().join("codeql-db");
        let log = temp.path().join("calls.log");
        fs::create_dir_all(&repo).unwrap();
        create_codeql_database_parent(&db).unwrap();
        let fake = write_fake_codeql(temp.path(), &fallback_fake_script(&log));

        CodeqlScanner {
            language: Some("cpp".to_string()),
            ..CodeqlScanner::default()
        }
        .create_codeql_database(
            &repo,
            fake.to_str().unwrap(),
            &ScanCancellation::default(),
            &db,
            "cpp",
        )
        .unwrap();

        let calls = fs::read_to_string(log).unwrap();
        assert!(calls.contains("--build-mode=autobuild"), "{calls}");
        assert!(calls.contains("--build-mode=none"), "{calls}");
        assert_eq!(calls.lines().count(), 2);
        assert!(db.join("codeql-database.yml").exists());
    }

    #[cfg(unix)]
    #[test]
    fn explicit_build_mode_does_not_fallback() {
        let temp = tempdir().unwrap();
        let repo = temp.path().join("repo");
        let db = temp.path().join("codeql-db");
        let log = temp.path().join("calls.log");
        fs::create_dir_all(&repo).unwrap();
        create_codeql_database_parent(&db).unwrap();
        let fake = write_fake_codeql(temp.path(), &fallback_fake_script(&log));

        let error = CodeqlScanner {
            build_mode: Some("autobuild".to_string()),
            ..CodeqlScanner::default()
        }
        .create_codeql_database(
            &repo,
            fake.to_str().unwrap(),
            &ScanCancellation::default(),
            &db,
            "cpp",
        )
        .unwrap_err()
        .to_string();

        let calls = fs::read_to_string(log).unwrap();
        assert!(error.contains("autobuild failed"), "{error}");
        assert!(calls.contains("--build-mode=autobuild"), "{calls}");
        assert!(!calls.contains("--build-mode=none"), "{calls}");
        assert_eq!(calls.lines().count(), 1);
    }
}
