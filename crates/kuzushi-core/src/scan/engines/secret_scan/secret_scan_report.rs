use super::*;

pub(crate) const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

pub(crate) const DEFAULT_MAX_FINDINGS: usize = 1000;

pub(crate) const DEFAULT_EXCLUDE_DIRS: &[&str] = &[
    ".kuzushi",
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "third_party",
    "third-party",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".cache",
    ".turbo",
    "coverage",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "target",
];

pub(crate) const DEFAULT_BINARY_EXTS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg", ".pdf", ".zip", ".gz",
    ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".class", ".jar", ".war", ".pyc", ".pyo", ".o", ".a", ".node", ".wasm", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".webm", ".lock",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretScanReport {
    pub target: String,
    pub findings: Vec<SecretScanFinding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
    /// Paths the walk reached but could not read. A clean report over a tree
    /// with gaps has not cleared the whole tree.
    #[serde(default)]
    pub coverage_gaps: CoverageGaps,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspection: Option<SecretScanInspection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretScanInspection {
    pub schema_version: u32,
    pub traversal_entries: Option<usize>,
    pub content_bytes_reserved: u64,
    pub max_entries: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_findings: usize,
    pub excluded_directories: Vec<String>,
    pub excluded_extensions: Vec<String>,
}
