use super::*;

impl CodeqlScanner {
    pub(crate) fn scan_all_language_artifacts(
        &self,
        target: &Path,
        binary: &str,
        repo_name: &str,
        cancel: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        let languages = detect_all_codeql_languages(target, binary, cancel)?;
        let (output, errors) =
            self.collect_codeql_language_outputs(target, binary, repo_name, cancel, languages)?;
        codeql_multi_language_output(output, errors)
    }

    pub(crate) fn collect_codeql_language_outputs(
        &self,
        target: &Path,
        binary: &str,
        repo_name: &str,
        cancel: &ScanCancellation,
        languages: Vec<String>,
    ) -> Result<(ScanEngineOutput, Vec<String>)> {
        let mut output = ScanEngineOutput::default();
        let mut errors = Vec::new();
        for language in languages {
            self.scan_one_detected_language(
                target,
                binary,
                repo_name,
                cancel,
                &language,
                &mut output,
                &mut errors,
            )?;
        }
        Ok((output, errors))
    }

    pub(crate) fn scan_one_detected_language(
        &self,
        target: &Path,
        binary: &str,
        repo_name: &str,
        cancel: &ScanCancellation,
        language: &str,
        output: &mut ScanEngineOutput,
        errors: &mut Vec<String>,
    ) -> Result<()> {
        let mut scanner = self.clone();
        scanner.language = Some(language.to_string());
        scanner.multi_language = false;
        let result = scanner.scan_single_language_artifacts(target, binary, repo_name, cancel);
        merge_detected_language_output(result, language, cancel, output, errors)
    }

    pub(crate) fn scan_single_language_artifacts(
        &self,
        target: &Path,
        binary: &str,
        repo_name: &str,
        cancel: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        let database = self.ensure_database(target, binary, cancel)?;
        let suite = resolve_codeql_suite(self.suite.as_deref(), &database.language)?;
        let sarif = database.run_verified(|db_path| {
            self.run_codeql_analysis(binary, db_path, &suite, cancel)
        })?;
        let findings = normalize_codeql_sarif(&sarif, repo_name)?;
        Ok(ScanEngineOutput {
            findings,
            codeql_sarif_documents: vec![sarif],
        })
    }
}
