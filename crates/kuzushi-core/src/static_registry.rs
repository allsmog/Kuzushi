use serde::Serialize;

use crate::findings::StaticProofState;

pub const STATIC_REGISTRY_VERSION: &str = "2026-05-06.1";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StaticRegistryKind {
    Source,
    Sink,
    Sanitizer,
    Guard,
}

impl StaticRegistryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Sink => "sink",
            Self::Sanitizer => "sanitizer",
            Self::Guard => "guard",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StaticRegistryPatternKind {
    SymbolEquals,
    SymbolContains,
    PathContains,
    TextContains,
}

impl StaticRegistryPatternKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SymbolEquals => "symbol_equals",
            Self::SymbolContains => "symbol_contains",
            Self::PathContains => "path_contains",
            Self::TextContains => "text_contains",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticRegistryEntry {
    pub id: &'static str,
    pub version: &'static str,
    pub language: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<&'static str>,
    pub kind: StaticRegistryKind,
    pub pattern_kind: StaticRegistryPatternKind,
    pub pattern: &'static str,
    pub cwe: &'static [&'static str],
    pub rationale: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticRegistryQuery<'a> {
    pub language: &'a str,
    pub framework: Option<&'a str>,
    pub path: Option<&'a str>,
    pub symbol: Option<&'a str>,
    pub text: Option<&'a str>,
}

impl<'a> StaticRegistryQuery<'a> {
    pub fn new(language: &'a str) -> Self {
        Self {
            language,
            framework: None,
            path: None,
            symbol: None,
            text: None,
        }
    }

    pub fn framework(mut self, framework: &'a str) -> Self {
        self.framework = Some(framework);
        self
    }

    pub fn path(mut self, path: &'a str) -> Self {
        self.path = Some(path);
        self
    }

    pub fn symbol(mut self, symbol: &'a str) -> Self {
        self.symbol = Some(symbol);
        self
    }

    pub fn text(mut self, text: &'a str) -> Self {
        self.text = Some(text);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticRegistryMatch {
    pub entry: &'static StaticRegistryEntry,
    pub static_proof_state: StaticProofState,
    pub vulnerability_proof: bool,
}

pub fn static_registry_version() -> &'static str {
    STATIC_REGISTRY_VERSION
}

pub fn default_static_registry() -> &'static [StaticRegistryEntry] {
    DEFAULT_STATIC_REGISTRY
}

pub fn match_static_registry(query: &StaticRegistryQuery<'_>) -> Vec<StaticRegistryMatch> {
    DEFAULT_STATIC_REGISTRY
        .iter()
        .filter(|entry| entry_matches_query(entry, query))
        .map(|entry| StaticRegistryMatch {
            entry,
            static_proof_state: StaticProofState::SignalOnly,
            vulnerability_proof: false,
        })
        .collect()
}

fn entry_matches_query(entry: &StaticRegistryEntry, query: &StaticRegistryQuery<'_>) -> bool {
    if !eq_ignore_ascii_case(entry.language, query.language) {
        return false;
    }

    if let Some(framework) = entry.framework {
        let Some(query_framework) = query.framework else {
            return false;
        };
        if !eq_ignore_ascii_case(framework, query_framework) {
            return false;
        }
    }

    match entry.pattern_kind {
        StaticRegistryPatternKind::SymbolEquals => query
            .symbol
            .is_some_and(|symbol| eq_ignore_ascii_case(symbol, entry.pattern)),
        StaticRegistryPatternKind::SymbolContains => query.symbol.is_some_and(|symbol| {
            contains_ignore_ascii_case(symbol, entry.pattern)
                || query
                    .text
                    .is_some_and(|text| contains_ignore_ascii_case(text, entry.pattern))
        }),
        StaticRegistryPatternKind::PathContains => query
            .path
            .is_some_and(|path| contains_ignore_ascii_case(path, entry.pattern)),
        StaticRegistryPatternKind::TextContains => query
            .text
            .is_some_and(|text| contains_ignore_ascii_case(text, entry.pattern)),
    }
}

fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

const DEFAULT_STATIC_REGISTRY: &[StaticRegistryEntry] = &[
    StaticRegistryEntry {
        id: "node.express.source.req-query",
        version: STATIC_REGISTRY_VERSION,
        language: "TypeScript",
        framework: Some("Express"),
        kind: StaticRegistryKind::Source,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "req.query",
        cwe: &["CWE-20"],
        rationale: "Express query parameters are externally controlled request input.",
    },
    StaticRegistryEntry {
        id: "node.express.source.req-body",
        version: STATIC_REGISTRY_VERSION,
        language: "TypeScript",
        framework: Some("Express"),
        kind: StaticRegistryKind::Source,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "req.body",
        cwe: &["CWE-20"],
        rationale: "Express request bodies are externally controlled request input.",
    },
    StaticRegistryEntry {
        id: "node.express.source.req-params",
        version: STATIC_REGISTRY_VERSION,
        language: "TypeScript",
        framework: Some("Express"),
        kind: StaticRegistryKind::Source,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "req.params",
        cwe: &["CWE-20"],
        rationale: "Express route parameters are externally controlled request input.",
    },
    StaticRegistryEntry {
        id: "node.sink.child-process-exec",
        version: STATIC_REGISTRY_VERSION,
        language: "TypeScript",
        framework: None,
        kind: StaticRegistryKind::Sink,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "child_process.exec",
        cwe: &["CWE-78"],
        rationale: "child_process.exec invokes a shell and can become command injection when fed untrusted input.",
    },
    StaticRegistryEntry {
        id: "node.sink.sql-query",
        version: STATIC_REGISTRY_VERSION,
        language: "TypeScript",
        framework: None,
        kind: StaticRegistryKind::Sink,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: ".query(",
        cwe: &["CWE-89"],
        rationale: "Database query construction is a SQL injection sink unless parameterization is proven.",
    },
    StaticRegistryEntry {
        id: "node.sanitizer.zod-parse",
        version: STATIC_REGISTRY_VERSION,
        language: "TypeScript",
        framework: None,
        kind: StaticRegistryKind::Sanitizer,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: ".parse(",
        cwe: &["CWE-20"],
        rationale: "Schema parsing can validate shape and type, subject to the schema contents.",
    },
    StaticRegistryEntry {
        id: "node.sanitizer.dompurify",
        version: STATIC_REGISTRY_VERSION,
        language: "TypeScript",
        framework: None,
        kind: StaticRegistryKind::Sanitizer,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "DOMPurify.sanitize",
        cwe: &["CWE-79"],
        rationale: "DOMPurify sanitization can neutralize HTML/script content when configured correctly.",
    },
    StaticRegistryEntry {
        id: "node.guard.require-auth",
        version: STATIC_REGISTRY_VERSION,
        language: "TypeScript",
        framework: Some("Express"),
        kind: StaticRegistryKind::Guard,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "requireAuth",
        cwe: &["CWE-862"],
        rationale: "Authentication middleware or guard calls can gate access to route handlers.",
    },
    StaticRegistryEntry {
        id: "python.flask.source.request-args",
        version: STATIC_REGISTRY_VERSION,
        language: "Python",
        framework: Some("Flask"),
        kind: StaticRegistryKind::Source,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "request.args",
        cwe: &["CWE-20"],
        rationale: "Flask query arguments are externally controlled request input.",
    },
    StaticRegistryEntry {
        id: "python.flask.source-request-json",
        version: STATIC_REGISTRY_VERSION,
        language: "Python",
        framework: Some("Flask"),
        kind: StaticRegistryKind::Source,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "request.get_json",
        cwe: &["CWE-20"],
        rationale: "Flask JSON bodies are externally controlled request input.",
    },
    StaticRegistryEntry {
        id: "python.sink-subprocess-shell",
        version: STATIC_REGISTRY_VERSION,
        language: "Python",
        framework: None,
        kind: StaticRegistryKind::Sink,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "shell=True",
        cwe: &["CWE-78"],
        rationale: "Python subprocess shell execution can become command injection when fed untrusted input.",
    },
    StaticRegistryEntry {
        id: "python.sink-sql-execute",
        version: STATIC_REGISTRY_VERSION,
        language: "Python",
        framework: None,
        kind: StaticRegistryKind::Sink,
        pattern_kind: StaticRegistryPatternKind::SymbolContains,
        pattern: ".execute",
        cwe: &["CWE-89"],
        rationale: "Database execute calls are SQL injection sinks unless parameterization is proven.",
    },
    StaticRegistryEntry {
        id: "python.sanitizer-html-escape",
        version: STATIC_REGISTRY_VERSION,
        language: "Python",
        framework: None,
        kind: StaticRegistryKind::Sanitizer,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "html.escape",
        cwe: &["CWE-79"],
        rationale: "HTML escaping can neutralize markup when used at the correct output boundary.",
    },
    StaticRegistryEntry {
        id: "python.guard-login-required",
        version: STATIC_REGISTRY_VERSION,
        language: "Python",
        framework: Some("Flask"),
        kind: StaticRegistryKind::Guard,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "login_required",
        cwe: &["CWE-862"],
        rationale: "Flask login_required decorators can gate route access.",
    },
    StaticRegistryEntry {
        id: "go.source-http-query",
        version: STATIC_REGISTRY_VERSION,
        language: "Go",
        framework: None,
        kind: StaticRegistryKind::Source,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "r.URL.Query",
        cwe: &["CWE-20"],
        rationale: "net/http URL query values are externally controlled request input.",
    },
    StaticRegistryEntry {
        id: "go.sink-os-exec-command",
        version: STATIC_REGISTRY_VERSION,
        language: "Go",
        framework: None,
        kind: StaticRegistryKind::Sink,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "exec.Command",
        cwe: &["CWE-78"],
        rationale: "Command construction is security-sensitive when arguments include untrusted data.",
    },
    StaticRegistryEntry {
        id: "go.sanitizer-template-escape",
        version: STATIC_REGISTRY_VERSION,
        language: "Go",
        framework: None,
        kind: StaticRegistryKind::Sanitizer,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "template.HTMLEscapeString",
        cwe: &["CWE-79"],
        rationale: "HTML escaping can neutralize markup when used at the correct output boundary.",
    },
    StaticRegistryEntry {
        id: "go.guard-auth-middleware",
        version: STATIC_REGISTRY_VERSION,
        language: "Go",
        framework: None,
        kind: StaticRegistryKind::Guard,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "AuthMiddleware",
        cwe: &["CWE-862"],
        rationale: "Auth middleware can gate access to HTTP handlers.",
    },
    StaticRegistryEntry {
        id: "rust.source-std-env-args",
        version: STATIC_REGISTRY_VERSION,
        language: "Rust",
        framework: None,
        kind: StaticRegistryKind::Source,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "std::env::args",
        cwe: &["CWE-20"],
        rationale: "CLI arguments are externally controlled process input.",
    },
    StaticRegistryEntry {
        id: "rust.sink-process-command",
        version: STATIC_REGISTRY_VERSION,
        language: "Rust",
        framework: None,
        kind: StaticRegistryKind::Sink,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "std::process::Command",
        cwe: &["CWE-78"],
        rationale: "Process command construction is security-sensitive when arguments include untrusted data.",
    },
    StaticRegistryEntry {
        id: "rust.sanitizer-ammonia-clean",
        version: STATIC_REGISTRY_VERSION,
        language: "Rust",
        framework: None,
        kind: StaticRegistryKind::Sanitizer,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "ammonia::clean",
        cwe: &["CWE-79"],
        rationale: "ammonia HTML sanitization can neutralize markup when used at the correct output boundary.",
    },
    StaticRegistryEntry {
        id: "rust.guard-require-user",
        version: STATIC_REGISTRY_VERSION,
        language: "Rust",
        framework: None,
        kind: StaticRegistryKind::Guard,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "require_user",
        cwe: &["CWE-862"],
        rationale: "Explicit user guards can gate privileged handlers.",
    },
    StaticRegistryEntry {
        id: "path.config-env",
        version: STATIC_REGISTRY_VERSION,
        language: "TypeScript",
        framework: None,
        kind: StaticRegistryKind::Source,
        pattern_kind: StaticRegistryPatternKind::PathContains,
        pattern: ".env",
        cwe: &["CWE-200"],
        rationale: "Environment files often contain sensitive configuration and should not be exposed.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn static_registry_entries_include_required_metadata() {
        assert!(!static_registry_version().is_empty());
        assert!(default_static_registry().len() >= 20);

        let mut ids = BTreeSet::new();
        for entry in default_static_registry() {
            assert!(ids.insert(entry.id), "duplicate registry id {}", entry.id);
            assert_eq!(entry.version, STATIC_REGISTRY_VERSION);
            assert!(!entry.language.trim().is_empty());
            assert!(!entry.kind.as_str().trim().is_empty());
            assert!(!entry.pattern_kind.as_str().trim().is_empty());
            assert!(!entry.pattern.trim().is_empty());
            assert!(
                !entry.cwe.is_empty(),
                "{} must include CWE mapping",
                entry.id
            );
            assert!(
                entry.cwe.iter().all(|cwe| cwe.starts_with("CWE-")),
                "{} has invalid CWE list {:?}",
                entry.id,
                entry.cwe
            );
            assert!(
                !entry.rationale.trim().is_empty(),
                "{} must include rationale",
                entry.id
            );
        }
    }

    #[test]
    fn static_registry_deterministically_matches_source_sink_sanitizer_and_guard() {
        let query = StaticRegistryQuery::new("TypeScript")
            .framework("Express")
            .path("src/routes/search.ts")
            .symbol("searchHandler")
            .text(
                "app.get('/search', requireAuth, (req, res) => {
                   const q = schema.parse(req.query.q);
                   const html = DOMPurify.sanitize(q);
                   return db.query(`select * from users where name = ${html}`);
                 });",
            );

        let first = match_static_registry(&query);
        let second = match_static_registry(&query);
        assert_eq!(first, second);

        let ids = first.iter().map(|item| item.entry.id).collect::<Vec<_>>();
        assert!(ids.contains(&"node.express.source.req-query"));
        assert!(ids.contains(&"node.sink.sql-query"));
        assert!(ids.contains(&"node.sanitizer.zod-parse"));
        assert!(ids.contains(&"node.sanitizer.dompurify"));
        assert!(ids.contains(&"node.guard.require-auth"));
    }

    #[test]
    fn static_registry_respects_language_framework_symbol_and_path_patterns() {
        let flask = StaticRegistryQuery::new("Python")
            .framework("Flask")
            .symbol("cursor.execute")
            .text("@login_required\ndef search():\n  q = request.args['q']\n  cursor.execute(q)");
        let flask_ids = match_static_registry(&flask)
            .iter()
            .map(|item| item.entry.id)
            .collect::<Vec<_>>();
        assert!(flask_ids.contains(&"python.flask.source.request-args"));
        assert!(flask_ids.contains(&"python.sink-sql-execute"));
        assert!(flask_ids.contains(&"python.guard-login-required"));
        assert!(!flask_ids.contains(&"node.express.source.req-query"));

        let config_file = StaticRegistryQuery::new("TypeScript").path("config/.env.local");
        let config_ids = match_static_registry(&config_file)
            .iter()
            .map(|item| item.entry.id)
            .collect::<Vec<_>>();
        assert_eq!(config_ids, vec!["path.config-env"]);
    }

    #[test]
    fn static_registry_match_alone_is_signal_only_not_vulnerability_proof() {
        let query = StaticRegistryQuery::new("Go").text(
            "func handler(w http.ResponseWriter, r *http.Request) {
               value := r.URL.Query().Get(\"cmd\")
               exec.Command(\"sh\", \"-c\", value)
             }",
        );
        let matches = match_static_registry(&query);
        assert!(matches
            .iter()
            .any(|item| item.entry.kind == StaticRegistryKind::Source));
        assert!(matches
            .iter()
            .any(|item| item.entry.kind == StaticRegistryKind::Sink));

        for item in matches {
            assert_eq!(item.static_proof_state, StaticProofState::SignalOnly);
            assert!(
                !item.vulnerability_proof,
                "registry match {} must not be treated as proof",
                item.entry.id
            );
        }
    }
}
