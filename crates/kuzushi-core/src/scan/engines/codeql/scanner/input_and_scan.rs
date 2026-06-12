use super::*;

impl CodeqlScanner {
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut scanner = Self::default();
        scanner.binary = optional_string_any(
            input,
            &["binary", "codeqlBinary", "codeqlBin", "scannerBin"],
        );
        scanner.db_path = optional_string_any(input, &["dbPath", "database", "databasePath"]);
        scanner.language = optional_string_any(input, &["language"])
            .and_then(|language| normalize_codeql_language(&language));
        scanner.suite = optional_string_any(input, &["suite"]);
        scanner.build_mode = optional_string_any(input, &["buildMode", "build_mode"])
            .map(|mode| crate::codeql_build_mode::normalize_codeql_build_mode(&mode))
            .transpose()?;
        scanner.threads = positive_u32(input, "threads")?;
        scanner.ram = positive_u32(input, "ram")?;
        scanner.multi_language = input
            .get("multiLanguage")
            .or_else(|| input.get("multi_language"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(scanner)
    }

    pub fn scan(&self, target: &Path) -> Result<Vec<Finding>> {
        self.scan_with_cancel(target, &ScanCancellation::default())
    }

    pub fn scan_with_cancel(
        &self,
        target: &Path,
        cancel: &ScanCancellation,
    ) -> Result<Vec<Finding>> {
        Ok(self.scan_with_artifacts(target, cancel)?.findings)
    }

    pub fn scan_with_artifacts(
        &self,
        target: &Path,
        cancel: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        validate_codeql_scan_target(target, cancel)?;
        let binary = resolve_codeql_binary(self.binary.as_deref())?;
        let repo_name = codeql_repo_name(target);

        if self.should_scan_all_codeql_languages() {
            return self.scan_all_language_artifacts(target, &binary, &repo_name, cancel);
        }

        self.scan_single_language_artifacts(target, &binary, &repo_name, cancel)
    }

    pub(crate) fn should_scan_all_codeql_languages(&self) -> bool {
        self.multi_language && self.language.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_mode_alias_is_normalized() {
        let scanner = CodeqlScanner::from_tool_input(&json!({"build_mode": " NONE "})).unwrap();

        assert_eq!(scanner.build_mode.as_deref(), Some("none"));
    }

    #[test]
    fn invalid_build_mode_is_rejected_at_input_boundary() {
        let error = CodeqlScanner::from_tool_input(&json!({"buildMode": "fast"}))
            .unwrap_err()
            .to_string();

        assert!(error.contains("buildMode must be one of"));
    }
}
