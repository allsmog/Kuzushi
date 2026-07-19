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

        let database = crate::codeql_repository_execution::resolve_managed_codeql_database(target)?
            .with_context(|| {
                format!(
                    "codeql: no valid managed database exists at {}. Run the separately authorized `codeql:create-db` tool first; scan tools never autobuild in the source checkout",
                    crate::workspace::workspace_codeql_db_path(target).display()
                )
            })?;
        let language = managed_database_language(self.language.as_deref(), &database)?;
        let db_path = database.path().to_path_buf();
        Ok(CodeqlDatabase {
            db_path,
            language,
            managed: Some(database),
        })
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
            managed: None,
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

}

fn managed_database_language(
    requested: Option<&str>,
    database: &crate::codeql_repository_execution::ValidatedManagedCodeqlDatabase,
) -> Result<String> {
    let provenance_language = database.provenance.language.clone();
    if let Some(requested) = requested {
        anyhow::ensure!(
            requested.eq_ignore_ascii_case(&provenance_language),
            "codeql: configured language {requested:?} does not match managed database language {provenance_language:?}"
        );
    }
    Ok(provenance_language)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_managed_database_fails_closed_without_invoking_codeql() {
        let temp = tempdir().unwrap();
        let marker = temp.path().join(".kuzushi/codeql-was-invoked");
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
        initialize_repository(temp.path());
        let db = crate::workspace::workspace_codeql_db_path(temp.path());
        fs::create_dir_all(&db).unwrap();
        fs::write(db.join("codeql-database.yml"), "primaryLanguage: javascript\n").unwrap();
        fs::create_dir(db.join("db-javascript")).unwrap();
        crate::codeql_repository_execution::write_test_codeql_database_provenance(
            &db,
            temp.path(),
            "javascript",
        );
        let marker = temp.path().join(".kuzushi/codeql-was-invoked");
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

    fn initialize_repository(root: &Path) {
        run_git(root, &["init", "-q"]);
        fs::write(root.join("tracked.js"), "const value = 1;\n").unwrap();
        run_git(root, &["add", "tracked.js"]);
        run_git(root, &["commit", "-qm", "initial"]);
    }

    fn run_git(root: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(["-c", "user.email=test@example.invalid"])
            .args(["-c", "user.name=Kuzushi Test"])
            .args(args)
            .current_dir(root)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    #[cfg(unix)]
    fn write_recording_codeql(root: &Path, marker: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = root.join(".kuzushi/recording-codeql");
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
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
