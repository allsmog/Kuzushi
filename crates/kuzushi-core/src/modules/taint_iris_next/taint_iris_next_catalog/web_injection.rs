use super::*;

pub(super) const CROSS_SITE_SCRIPTING: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-79",
    name: "Cross-Site Scripting",
    taint_class: "xss",
    languages: TAINT_IRIS_NEXT_WEB,
    source_signals: &[
        "req.query",
        "request.body",
        "query parameter",
        "profile field",
    ],
    sink_signals: &[
        "innerHTML",
        "dangerouslySetInnerHTML",
        "res.send",
        "html_safe",
        "render(",
    ],
    sanitizer_signals: &["escapeHtml", "sanitize", "DOMPurify"],
    structural_queries: &[
        "innerHTML",
        "dangerouslySetInnerHTML",
        "res.send",
        "html_safe",
    ],
};

pub(super) const SQL_INJECTION: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-89",
    name: "SQL Injection",
    taint_class: "sql-injection",
    languages: TAINT_IRIS_NEXT_ANY,
    source_signals: &[
        "req.query",
        "request.args",
        "request.query",
        "route parameter",
        "params[",
    ],
    sink_signals: &[
        "query(",
        "execute(",
        "find_by_sql",
        "Sequelize.literal",
        "raw(",
    ],
    sanitizer_signals: &[
        "prepared statement",
        "bind parameter",
        "parameterized query",
    ],
    structural_queries: &["SELECT", "WHERE", "db.query", "execute(", "raw("],
};

pub(super) const CODE_INJECTION: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-94",
    name: "Code Injection",
    taint_class: "code-injection",
    languages: &["javascript", "typescript", "python", "ruby", "php", "java"],
    source_signals: &[
        "req.query",
        "request.",
        "template expression",
        "workflow expression",
    ],
    sink_signals: &["eval(", "Function(", "exec(", "compile(", "class_eval"],
    sanitizer_signals: &["allowlist expression", "sandbox", "parser restriction"],
    structural_queries: &["eval(", "new Function", "compile(", "class_eval"],
};
