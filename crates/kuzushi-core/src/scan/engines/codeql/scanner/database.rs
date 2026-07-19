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
        let db_path = managed_codeql_database_path(target)?;
        ensure_managed_codeql_database_exists(&db_path)?;
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
            language: self.configured_codeql_language(target, binary, cancel, &db_path)?,
            db_path,
        })
    }

    pub(crate) fn configured_codeql_language(
        &self,
        target: &Path,
        binary: &str,
        cancel: &ScanCancellation,
        db_path: &Path,
    ) -> Result<String> {
        if let Some(language) = self.language.clone() {
            return Ok(language);
        }
        detect_language_from_database(binary, db_path, cancel)?
            .or_else(|| detect_codeql_language_from_heuristics(target))
            .with_context(|| {
                format!(
                    "codeql: could not determine the language for configured database {}; pass an explicit language",
                    db_path.display()
                )
            })
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
}

fn managed_codeql_database_path(target: &Path) -> Result<PathBuf> {
    let declared = crate::workspace::workspace_codeql_db_path(target);
    let relative = declared
        .strip_prefix(target)
        .context("CodeQL database path escaped the workspace")?;
    crate::workspace::prepare_workspace_output_path(target, relative)
}

fn ensure_managed_codeql_database_exists(db_path: &Path) -> Result<()> {
    anyhow::ensure!(
        is_codeql_database_dir(db_path),
        "codeql: no valid managed database exists at {}. Run the separately authorized `codeql:create-db` tool first; scan tools never autobuild in the source checkout",
        db_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_managed_database_fails_closed_without_invoking_codeql() {
        let temp = tempdir().unwrap();
        let marker = temp.path().join("codeql-was-invoked");
        let binary = write_recording_codeql(temp.path(), &marker);
        let scanner = CodeqlScanner {
            binary: Some(binary.display().to_string()),
            language: Some("javascript".to_string()),
            ..CodeqlScanner::default()
        };

        let error = scanner
            .ensure_database(
                temp.path(),
                binary.to_str().unwrap(),
                &ScanCancellation::default(),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("codeql:create-db"), "{error}");
        assert!(error.contains("never autobuild"), "{error}");
        assert!(!marker.exists());
    }

    #[test]
    fn existing_managed_database_is_reused_without_invoking_codeql() {
        let temp = tempdir().unwrap();
        let db = crate::workspace::workspace_codeql_db_path(temp.path());
        fs::create_dir_all(&db).unwrap();
        fs::write(db.join("codeql-database.yml"), "primaryLanguage: javascript\n").unwrap();
        let marker = temp.path().join("codeql-was-invoked");
        let binary = write_recording_codeql(temp.path(), &marker);
        let scanner = CodeqlScanner {
            language: Some("javascript".to_string()),
            ..CodeqlScanner::default()
        };

        let resolved = scanner
            .ensure_database(
                temp.path(),
                binary.to_str().unwrap(),
                &ScanCancellation::default(),
            )
            .unwrap();

        assert_eq!(resolved.db_path, db);
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    fn write_recording_codeql(root: &Path, marker: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = root.join("recording-codeql");
        fs::write(
            &binary,
            format!("#!/bin/sh\nprintf invoked > '{}'\n", marker.display()),
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(not(unix))]
    fn write_recording_codeql(root: &Path, _marker: &Path) -> PathBuf {
        root.join("unused-codeql")
    }
}
