use super::*;

impl CodeqlScanner {
    pub(crate) fn run_codeql_analysis(
        &self,
        binary: &str,
        db_path: &Path,
        suite: &str,
        cancel: &ScanCancellation,
    ) -> Result<String> {
        let tmp_dir = env::temp_dir().join(format!("kuzushi-codeql-{}", Uuid::new_v4()));
        fs::create_dir(&tmp_dir)
            .with_context(|| format!("codeql: could not create {}", tmp_dir.display()))?;
        let output_path = tmp_dir.join("results.sarif");

        let result = (|| {
            let args = self.analysis_args(db_path, suite, &output_path, &tmp_dir);
            self.run_codeql_command(binary, &args, None, cancel)?;
            crate::bounded_file::read_utf8_text(&output_path, 256 * 1024 * 1024).with_context(
                || {
                    format!(
                        "codeql: could not read SARIF output {}",
                        output_path.display()
                    )
                },
            )
        })();

        let _ = fs::remove_dir_all(&tmp_dir);
        result
    }

    fn analysis_args(
        &self,
        db_path: &Path,
        suite: &str,
        output_path: &Path,
        log_dir: &Path,
    ) -> Vec<String> {
        let mut args = vec![
            "database".to_string(),
            "analyze".to_string(),
            db_path.display().to_string(),
            suite.to_string(),
            "--format=sarif-latest".to_string(),
            format!("--output={}", output_path.display()),
        ];
        args.extend(
            crate::codeql_repository_execution::managed_codeql_analysis_safety_args(log_dir),
        );
        if let Some(threads) = self.threads {
            args.push(format!("--threads={threads}"));
        }
        if let Some(ram) = self.ram {
            args.push(format!("--ram={ram}"));
        }
        args
    }
}
