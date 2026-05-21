#[derive(Debug, Clone)]
pub(super) struct LeadPattern {
    pub(super) id: &'static str,
    pub(super) source: &'static str,
    pub(super) sink: &'static str,
    pub(super) source_terms: &'static [&'static str],
    pub(super) sink_terms: &'static [&'static str],
    pub(super) trigger_terms: &'static [&'static str],
    pub(super) cwes: &'static [&'static str],
}

pub(super) const LEAD_PATTERNS: &[LeadPattern] = &[
    LeadPattern {
        id: "remote-path-to-local-write",
        source: "remote peer controls URL, directory-listing metadata, headers, or response names",
        sink: "local filesystem write/open path",
        source_terms: &[
            "url", "remote", "server", "ftp", "http", "protocol", "filename", "path",
        ],
        sink_terms: &["fopen", "open(", "write", "rename", "unlink", "file"],
        trigger_terms: &[
            "file",
            "path",
            "filename",
            "overwrite",
            "traversal",
            "url",
            "helper",
        ],
        cwes: &["CWE-22", "CWE-73"],
    },
    LeadPattern {
        id: "remote-parser-resource-exhaustion",
        source: "remote peer controls protocol bytes, headers, or response bodies",
        sink: "parser loop, allocation, decompression, or buffering",
        source_terms: &["remote", "server", "protocol", "header", "response", "body"],
        sink_terms: &[
            "parse", "alloc", "malloc", "realloc", "loop", "timeout", "size",
        ],
        trigger_terms: &["parser", "resource", "exhaustion", "hang", "crash", "dos"],
        cwes: &["CWE-400", "CWE-770"],
    },
    LeadPattern {
        id: "credential-or-request-data-leak",
        source: "local credentials, tokens, auth headers, cookies, or request data",
        sink: "remote endpoint, proxy, redirect, log, or diagnostic output",
        source_terms: &["credential", "token", "auth", "cookie", "header", "secret"],
        sink_terms: &["send", "proxy", "redirect", "log", "verbose", "trace"],
        trigger_terms: &[
            "credential",
            "token",
            "leak",
            "disclosure",
            "remote",
            "endpoint",
        ],
        cwes: &["CWE-200", "CWE-201", "CWE-359"],
    },
    LeadPattern {
        id: "ci-build-supply-chain",
        source: "workflow, build script, dependency lookup, or package metadata",
        sink: "CI execution, artifact generation, dependency loading, or release output",
        source_terms: &[
            "workflow",
            "action",
            "dependency",
            "cmake",
            "configure",
            "pkg-config",
        ],
        sink_terms: &["run", "exec", "script", "artifact", "upload", "link"],
        trigger_terms: &[
            "workflow",
            "ci",
            "dependency",
            "build",
            "artifact",
            "supply",
        ],
        cwes: &["CWE-829", "CWE-345"],
    },
];
