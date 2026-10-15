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
        Ok(CodeqlDatabase {
            language,
            managed: database,
        })
    }

    pub(crate) fn configured_codeql_database(
        &self,
        target: &Path,
        _binary: &str,
        _cancel: &ScanCancellation,
        configured_db_path: &str,
    ) -> Result<CodeqlDatabase> {
        let db_path = resolve_repo_path(target, configured_db_path);
        let database = crate::codeql_repository_execution::resolve_managed_codeql_database_at(
            target, &db_path,
        )?;
        let language = managed_database_language(self.language.as_deref(), &database)?;
        Ok(CodeqlDatabase {
            language,
            managed: database,
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
        fs::write(
            db.join("codeql-database.yml"),
            "primaryLanguage: javascript\n",
        )
        .unwrap();
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

        assert_eq!(resolved.managed.path(), db);
        assert!(!marker.exists());
    }

    #[test]
    fn configured_raw_database_cannot_bypass_source_authentication() {
        let root = tempdir().unwrap();
        let db = root.path().join(".kuzushi/raw-db");
        fs::create_dir_all(db.join("db-javascript")).unwrap();
        fs::write(
            db.join("codeql-database.yml"),
            "primaryLanguage: javascript\n",
        )
        .unwrap();
        let scanner = CodeqlScanner {
            db_path: Some(db.display().to_string()),
            language: Some("javascript".into()),
            ..Default::default()
        };
        let error = scanner
            .ensure_database(root.path(), "unused", &ScanCancellation::default())
            .unwrap_err();
        assert!(format!("{error:#}").contains("codeql:create-db"));
    }

    #[test]
    fn explicit_managed_path_authenticates_language_and_dirty_source() {
        let root = tempdir().unwrap();
        initialize_repository(root.path());
        let db = crate::workspace::workspace_codeql_db_path(root.path());
        fs::create_dir_all(db.join("db-javascript")).unwrap();
        fs::write(
            db.join("codeql-database.yml"),
            "primaryLanguage: javascript\n",
        )
        .unwrap();
        crate::codeql_repository_execution::write_test_codeql_database_provenance(
            &db,
            root.path(),
            "javascript",
        );
        let scanner = CodeqlScanner {
            db_path: Some(db.display().to_string()),
            ..Default::default()
        };
        let resolved = scanner
            .ensure_database(root.path(), "unused", &ScanCancellation::default())
            .unwrap();
        assert_eq!(resolved.language, "javascript");
        assert_eq!(resolved.managed.path(), db.canonicalize().unwrap());
        drop(resolved);
        let wrong_language = CodeqlScanner {
            language: Some("python".into()),
            ..scanner.clone()
        };
        assert!(wrong_language
            .ensure_database(root.path(), "unused", &ScanCancellation::default())
            .is_err());
        fs::write(root.path().join("tracked.js"), "changed owned text\n").unwrap();
        assert!(scanner
            .ensure_database(root.path(), "unused", &ScanCancellation::default())
            .is_err());
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
