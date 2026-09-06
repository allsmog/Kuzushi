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
        let (output, tally) =
            self.collect_codeql_language_outputs(target, binary, repo_name, cancel, languages)?;
        codeql_multi_language_output(output, tally)
    }

    pub(crate) fn collect_codeql_language_outputs(
        &self,
        target: &Path,
        binary: &str,
        repo_name: &str,
        cancel: &ScanCancellation,
        languages: Vec<String>,
    ) -> Result<(ScanEngineOutput, LanguageAnalysisTally)> {
        let mut output = ScanEngineOutput::default();
        let mut tally = LanguageAnalysisTally::default();
        for language in languages {
            self.scan_one_detected_language(
                target,
                binary,
                repo_name,
                cancel,
                &language,
                &mut output,
                &mut tally,
            )?;
        }
        Ok((output, tally))
    }

    pub(crate) fn scan_one_detected_language(
        &self,
        target: &Path,
        binary: &str,
        repo_name: &str,
        cancel: &ScanCancellation,
        language: &str,
        output: &mut ScanEngineOutput,
        tally: &mut LanguageAnalysisTally,
    ) -> Result<()> {
        let mut scanner = self.clone();
        scanner.language = Some(language.to_string());
        scanner.multi_language = false;
        let result = scanner.scan_single_language_artifacts(target, binary, repo_name, cancel);
        merge_detected_language_output(result, language, cancel, output, tally)
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
            scan_errors: Vec::new(),
        })
    }
}
