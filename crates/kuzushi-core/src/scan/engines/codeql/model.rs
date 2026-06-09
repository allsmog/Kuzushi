#[derive(Debug, Clone)]
#[derive(Default)]
pub struct CodeqlScanner {
    pub binary: Option<String>,
    pub db_path: Option<String>,
    pub language: Option<String>,
    pub suite: Option<String>,
    pub threads: Option<u32>,
    pub ram: Option<u32>,
    pub multi_language: bool,
}

