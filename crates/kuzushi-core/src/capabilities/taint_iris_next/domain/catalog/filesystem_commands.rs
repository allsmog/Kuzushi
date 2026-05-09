use super::*;

pub(super) const PATH_TRAVERSAL: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-22",
    name: "Path Traversal",
    taint_class: "path-traversal",
    languages: TAINT_IRIS_NEXT_ANY,
    source_signals: &["req.query", "request path", "filename", "archive entry"],
    sink_signals: &["readFile", "writeFile", "open(", "File.open", "send_file"],
    sanitizer_signals: &["basename", "realpath", "canonicalize", "safe_join"],
    structural_queries: &["../", "path.join", "readFile", "PathBuf", "send_file"],
};

pub(super) const COMMAND_INJECTION: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-78",
    name: "OS Command Injection",
    taint_class: "os-command-injection",
    languages: TAINT_IRIS_NEXT_ANY,
    source_signals: &[
        "req.query",
        "request.",
        "process.argv",
        "os.environ",
        "env::args",
    ],
    sink_signals: &[
        "child_process.exec",
        "subprocess",
        "Popen",
        "Command::new",
        "shell=True",
    ],
    sanitizer_signals: &["execFile", "argument vector", "allowlist", "shellwords"],
    structural_queries: &[
        "child_process",
        "Runtime.exec",
        "subprocess",
        "Popen",
        "shell=True",
    ],
};
