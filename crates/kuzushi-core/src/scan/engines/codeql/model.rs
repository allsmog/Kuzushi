#[derive(Debug, Clone)]
pub struct CodeqlScanner {
    pub binary: Option<String>,
    pub db_path: Option<String>,
    pub language: Option<String>,
    pub suite: Option<String>,
    pub build_mode: Option<String>,
    pub threads: Option<u32>,
    pub ram: Option<u32>,
    pub multi_language: bool,
    pub command_timeout: std::time::Duration,
}

pub(crate) const DEFAULT_CODEQL_SCAN_TIMEOUT_MS: u64 = 30 * 60 * 1000;
pub(crate) const MAX_CODEQL_SCAN_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

impl Default for CodeqlScanner {
    fn default() -> Self {
        Self {
            binary: None,
            db_path: None,
            language: None,
            suite: None,
            build_mode: None,
            threads: Some(1),
            ram: None,
            multi_language: false,
            command_timeout: std::time::Duration::from_millis(DEFAULT_CODEQL_SCAN_TIMEOUT_MS),
        }
    }
}
