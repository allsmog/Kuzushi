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

        if is_compiled_codeql_language(&language) {
            let mut autobuild_args = create_args.clone();
            autobuild_args.push("--build-mode=autobuild".to_string());
            match self.run_codeql_command(binary, &autobuild_args, Some(target), cancel) {
                Ok(_) => {}
                Err(error) if cancel.is_cancelled() => return Err(error),
                Err(_) => {
                    self.run_codeql_command(binary, &create_args, Some(target), cancel)?;
                }
            }
        } else {
            self.run_codeql_command(binary, &create_args, Some(target), cancel)?;
        }
        Ok(())
    }
}
