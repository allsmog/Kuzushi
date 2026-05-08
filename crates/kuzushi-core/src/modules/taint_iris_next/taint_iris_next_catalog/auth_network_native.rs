use super::*;

pub(super) const INTEGER_OVERFLOW: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-190",
    name: "Integer Overflow",
    taint_class: "integer-overflow",
    languages: TAINT_IRIS_NEXT_NATIVE,
    source_signals: &["length", "size", "count", "offset"],
    sink_signals: &["malloc", "resize", "capacity", "copy", "slice"],
    sanitizer_signals: &["checked_add", "saturating", "bounds check"],
    structural_queries: &["checked_add", "saturating_", "malloc", "resize", "capacity"],
};

pub(super) const MISSING_AUTHORIZATION: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-862",
    name: "Missing Authorization",
    taint_class: "missing-authorization",
    languages: TAINT_IRIS_NEXT_WEB,
    source_signals: &["route", "handler", "controller", "mutation"],
    sink_signals: &["delete", "update", "admin", "owner", "tenant"],
    sanitizer_signals: &["authorize", "policy", "permission", "current_user"],
    structural_queries: &["router.", "delete", "update", "authorize", "current_user"],
};

pub(super) const SERVER_SIDE_REQUEST_FORGERY: TaintIrisNextCatalogEntry =
    TaintIrisNextCatalogEntry {
        cwe: "CWE-918",
        name: "Server-Side Request Forgery",
        taint_class: "ssrf",
        languages: TAINT_IRIS_NEXT_WEB,
        source_signals: &[
            "req.query.url",
            "request url",
            "webhook URL",
            "callback URL",
        ],
        sink_signals: &["fetch(", "axios.", "http.get", "requests.get", "Net::HTTP"],
        sanitizer_signals: &["URL allowlist", "block private IP", "hostname allowlist"],
        structural_queries: &["fetch(", "axios.", "http.get", "requests.get", "Net::HTTP"],
    };
