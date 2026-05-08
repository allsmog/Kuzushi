#[cfg(test)]
mod tests {
    use super::super::*;
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
