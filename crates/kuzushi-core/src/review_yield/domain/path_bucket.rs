/// Coarse role of the file a finding sits in. The only thing the exporter ever
/// derives from a path: the raw path itself is dropped immediately after.
pub const PATH_BUCKETS: &[&str] = &[
    "application",
    "test",
    "generated",
    "vendor",
    "example",
    "config",
    "docs",
    "unknown",
];

const VENDOR_SEGMENTS: &[&str] = &[
    "node_modules",
    "vendor",
    "third_party",
    "third-party",
    "external",
    ".venv",
    "venv",
];
const GENERATED_SEGMENTS: &[&str] = &[
    "target",
    "dist",
    "build",
    "out",
    ".next",
    "coverage",
    "generated",
    "gen",
    "__pycache__",
];
const TEST_SEGMENTS: &[&str] = &[
    "test",
    "tests",
    "spec",
    "e2e",
    "__tests__",
    "testdata",
    "fixtures",
];
const EXAMPLE_SEGMENTS: &[&str] = &["example", "examples", "demo", "demos", "sample", "samples"];
const DOCS_SEGMENTS: &[&str] = &["docs", "doc"];

/// Directory rules, evaluated in order — first match wins. Vendor and
/// generated code outrank test layout so a vendored test tree stays vendor.
const DIRECTORY_RULES: &[(&str, &[&str])] = &[
    ("vendor", VENDOR_SEGMENTS),
    ("generated", GENERATED_SEGMENTS),
    ("test", TEST_SEGMENTS),
    ("example", EXAMPLE_SEGMENTS),
    ("docs", DOCS_SEGMENTS),
];

const TEST_FILE_MARKERS: &[&str] = &["_test.", ".test.", ".spec.", "test_"];
const CONFIG_FILENAMES: &[&str] = &["dockerfile", "makefile", ".env", ".gitignore"];
const CONFIG_EXTENSIONS: &[&str] = &["toml", "yaml", "yml", "ini", "cfg", "conf"];

/// Buckets a repository-relative path. An empty path is `unknown` rather than
/// a guessed default.
pub fn path_bucket(path: &str) -> &'static str {
    let lower = path.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return "unknown";
    }
    let segments: Vec<&str> = lower.split('/').filter(|part| !part.is_empty()).collect();
    let file_name = segments.last().copied().unwrap_or_default();
    matching_bucket(&segments, file_name)
}

fn matching_bucket(segments: &[&str], file_name: &str) -> &'static str {
    DIRECTORY_RULES
        .iter()
        .find(|(_, needles)| segments.iter().any(|segment| needles.contains(segment)))
        .map(|(bucket, _)| *bucket)
        .or_else(|| is_test_file_name(file_name).then_some("test"))
        .or_else(|| is_config_file_name(file_name).then_some("config"))
        .unwrap_or("application")
}

fn is_test_file_name(file_name: &str) -> bool {
    TEST_FILE_MARKERS
        .iter()
        .any(|marker| file_name.contains(marker))
}

fn is_config_file_name(file_name: &str) -> bool {
    CONFIG_FILENAMES.contains(&file_name)
        || file_name
            .rsplit_once('.')
            .is_some_and(|(_, extension)| CONFIG_EXTENSIONS.contains(&extension))
}
