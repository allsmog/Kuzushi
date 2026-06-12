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
}

impl Default for CodeqlScanner {
    fn default() -> Self {
        Self {
            binary: None,
            db_path: None,
            language: None,
            suite: None,
            build_mode: None,
            threads: None,
            ram: None,
            multi_language: false,
        }
    }
}
