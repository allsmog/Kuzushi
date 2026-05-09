use super::*;

pub(super) const LOG_INJECTION: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-117",
    name: "Log Injection",
    taint_class: "log-injection",
    languages: TAINT_IRIS_NEXT_ANY,
    source_signals: &["req.query", "username", "header", "job payload"],
    sink_signals: &[
        "logger.",
        "log.info",
        "println",
        "tracing::",
        "Rails.logger",
    ],
    sanitizer_signals: &["strip CRLF", "structured logging", "JSON encoding"],
    structural_queries: &["logger.", "log.info", "println", "tracing::"],
};

pub(super) const DESERIALIZATION: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-502",
    name: "Deserialization of Untrusted Data",
    taint_class: "deserialization",
    languages: TAINT_IRIS_NEXT_ANY,
    source_signals: &["req.body", "request body", "message payload", "cookie"],
    sink_signals: &[
        "deserialize",
        "pickle.loads",
        "yaml.load",
        "Marshal.load",
        "readObject",
    ],
    sanitizer_signals: &["safe_load", "allowed classes", "schema validation"],
    structural_queries: &["pickle.loads", "yaml.load", "deserialize", "readObject"],
};

pub(super) const XML_EXTERNAL_ENTITY: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-611",
    name: "XML External Entity",
    taint_class: "xxe",
    languages: TAINT_IRIS_NEXT_WEB,
    source_signals: &["request body", "xml upload", "SOAP payload"],
    sink_signals: &[
        "DocumentBuilderFactory",
        "SAXParserFactory",
        "lxml",
        "xml2js",
    ],
    sanitizer_signals: &["disable doctype", "external entity disabled"],
    structural_queries: &[
        "DocumentBuilderFactory",
        "SAXParserFactory",
        "lxml",
        "xml2js",
    ],
};
