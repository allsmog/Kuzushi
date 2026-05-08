#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::config::V2Config;
    use crate::findings::{FindingStore, TriageOutcome};
    use crate::modules::ModuleRegistry;
    use crate::runtime::{AgentQueryResponse, TriageRequest};
    use crate::workspace::WorkspaceTarget;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct MockRuntime {
        queries: Mutex<Vec<AgentQueryRequest>>,
    }

    impl MockRuntime {
        fn new() -> Self {
            Self {
                queries: Mutex::new(Vec::new()),
            }
        }
    }

    impl AgentRuntime for MockRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            let system = request.system_prompt.clone();
            self.queries.lock().unwrap().push(request);
            if system.contains("pattern lifter") {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "source": "HTTP request body",
                        "sink": "child_process.exec",
                        "missingGuard": "no allowlist",
                        "languages": ["typescript"],
                        "keywords": ["exec", "child_process"],
                        "description": "Untrusted input reaches shell execution."
                    })),
                    ..Default::default()
                });
            }
            if system.contains("variant analysis") {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "variants": [{
                            "filePath": "src/other.ts",
                            "startLine": 9,
                            "severity": "ERROR",
                            "message": "exec with untrusted input",
                            "confidence": "HIGH",
                            "rationale": "same source reaches exec",
                            "cwe": ["CWE-78"]
                        }, {
                            "filePath": "src/weak.ts",
                            "startLine": 12,
                            "severity": "WARNING",
                            "message": "low confidence",
                            "confidence": "LOW",
                            "rationale": "unclear"
                        }]
                    })),
                    ..Default::default()
                });
            }
            if system.contains("fix-pattern extractor") {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "fixShape": "adds a bounds check before memcpy",
                        "vulnerableShape": "memcpy uses attacker-controlled length without a bounds check",
                        "cwe": ["CWE-787"],
                        "languages": ["c"],
                        "keywords": ["memcpy", "len"],
                        "detectionQuery": "rg 'memcpy\\('",
                        "description": "Search copies guarded by no length cap.",
                        "confidence": "HIGH"
                    })),
                    ..Default::default()
                });
            }
            if system.contains("N-day variant hunter") {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "variants": [{
                            "filePath": "src/parser.c",
                            "startLine": 7,
                            "severity": "ERROR",
                            "message": "memcpy without bounds check",
                            "confidence": "HIGH",
                            "rationale": "length reaches memcpy",
                            "cwe": ["CWE-787"]
                        }]
                    })),
                    ..Default::default()
                });
            }
            anyhow::bail!("unexpected query")
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            anyhow::bail!("triage not used")
        }
    }

    #[test]
    fn fetch_patch_text_prefers_fixture_then_offline_then_local_file() {
        let fixture = fetch_patch_text(
            "https://example.test/fix.patch",
            &json!({
                "patchFixtures": {
                    "https://example.test/fix.patch": "diff --git a/file b/file"
                },
                "offline": true
            }),
        )
        .unwrap();
        assert_eq!(fixture.as_deref(), Some("diff --git a/file b/file"));

        let offline = fetch_patch_text(
            "https://example.test/missing.patch",
            &json!({"offline": true}),
        )
        .unwrap();
        assert_eq!(offline, None);

        let temp = tempdir().unwrap();
        let patch_path = temp.path().join("local.patch");
        fs::write(&patch_path, "local diff").unwrap();
        let local = fetch_patch_text(&patch_path.display().to_string(), &json!({})).unwrap();
        assert_eq!(local.as_deref(), Some("local diff"));
    }

    #[test]
    fn advisory_source_and_urls_cover_cve_ghsa_and_unknown_ids() {
        assert_eq!(
            advisory_source_for_id("CVE-2024-1234").unwrap(),
            AdvisorySource::Nvd
        );
        assert_eq!(
            advisory_source_for_id("ghsa-abcd-efgh-ijkl").unwrap(),
            AdvisorySource::Ghsa
        );
        assert!(advisory_source_for_id("OSV-2024-1")
            .unwrap_err()
            .to_string()
            .contains("expected CVE-* or GHSA-*"));
        assert_eq!(
            nvd_advisory_url("CVE-2024-1234"),
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1234"
        );
        assert_eq!(
            ghsa_advisory_url("ghsa-abcd-efgh-ijkl"),
            "https://api.github.com/advisories/ghsa-abcd-efgh-ijkl"
        );
        assert!(input_is_offline(&json!({"offline": true})));
        assert!(!input_is_offline(&json!({})));
    }

    #[test]
    fn fetch_cve_or_advisory_prefers_inline_and_fixture_records_before_offline_gate() {
        let inline = fetch_cve_or_advisory(
            "CVE-2024-1234",
            &json!({
                "record": {
                    "id": "CVE-2024-1234",
                    "description": "inline",
                    "cwes": ["CWE-79"],
                    "severity": "HIGH",
                    "cvssScore": 7.5,
                    "affected": [],
                    "patches": [],
                    "source": "fixture",
                    "raw": {}
                },
                "offline": true
            }),
        )
        .unwrap()
        .unwrap();
        assert_eq!(inline.description, "inline");

        let fixture = fetch_cve_or_advisory(
            "ghsa-abcd-efgh-ijkl",
            &json!({
                "fixtures": {
                    "GHSA-ABCD-EFGH-IJKL": {
                        "id": "GHSA-ABCD-EFGH-IJKL",
                        "description": "fixture",
                        "cwes": [],
                        "affected": [],
                        "patches": [],
                        "source": "fixture",
                        "raw": {}
                    }
                },
                "offline": true
            }),
        )
        .unwrap()
        .unwrap();
        assert_eq!(fixture.description, "fixture");
        assert!(
            fetch_cve_or_advisory("not-an-advisory", &json!({"offline": true}))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn nvd_patch_reference_detection_covers_tags_and_patch_url_shapes() {
        assert!(is_nvd_patch_reference(
            "https://example.test/advisory",
            &["Patch".to_string()]
        ));
        assert!(is_nvd_patch_reference(
            "https://github.com/org/repo/commit/abc",
            &[]
        ));
        assert!(is_nvd_patch_reference(
            "https://github.com/org/repo/pull/1",
            &[]
        ));
        assert!(is_nvd_patch_reference("https://example.test/fix.diff", &[]));
        assert!(is_nvd_patch_reference(
            "https://example.test/fix.patch",
            &[]
        ));
        assert!(!is_nvd_patch_reference(
            "https://example.test/release-notes",
            &[]
        ));
    }

    fn seeded_workspace() -> (tempfile::TempDir, WorkspaceTarget, FindingStore, String) {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/app.ts"), "exec(req.body.cmd)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let run_id = "run-variant";
        store
            .insert_scan_run(run_id, workspace.root(), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "javascript.express.command-injection",
            "src/app.ts",
            1,
            None,
            Severity::High,
            "Command injection via child_process.exec",
        );
        let fingerprint = finding.fingerprint.clone();
        let finding_id = store.insert_finding(run_id, &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.91,
                    rationale: "user input reaches exec".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        store.complete_scan_run(run_id, "completed", 1).unwrap();
        (temp, workspace, store, fingerprint)
    }

    #[test]
    fn whitebox_variants_derive_pattern_from_confirmed_evidence_and_find_siblings() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/users.ts"),
            "app.get('/users', (req, res) => {\n  const q = req.query.q;\n  return db.query(`select * from users where name = ${q}`);\n});\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/admin.ts"),
            "app.get('/admin', (req, res) => {\n  const q = req.query.q;\n  return db.query(`select * from admins where name = ${q}`);\n});\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/safe.ts"),
            "app.get('/safe', (req, res) => {\n  const q = sanitize(req.query.q);\n  return db.query(`select * from safe where name = ${q}`);\n});\n",
        )
        .unwrap();
        let finding = Finding::new_tool(
            "agentic-sast",
            "js/sql-injection",
            "src/users.ts",
            3,
            Some(3),
            Severity::High,
            "req.query reaches db.query without sanitizer",
        )
        .with_static_proof_state(StaticProofState::StaticallyConfirmed);
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let evidence = StaticEvidenceNode::new(
            crate::static_evidence::StaticEvidenceNodeKind::CodeSpan,
            "confirmed SQL flow",
            "const q = req.query.q;\nreturn db.query(`select * from users where name = ${q}`);",
        )
        .with_finding_fingerprint(finding.fingerprint.clone())
        .with_source_span("src/users.ts", 2, Some(3));
        store.upsert_node(&evidence).unwrap();

        let report =
            hunt_whitebox_static_variants(temp.path(), &[finding], Some(&store), 10).unwrap();

        assert_eq!(report.patterns.len(), 1);
        assert_eq!(report.patterns[0].source_tokens, vec!["req.query"]);
        assert!(report.patterns[0]
            .sink_tokens
            .contains(&"db.query".to_string()));
        assert_eq!(report.count, 1);
        let variant = &report.variants[0];
        assert_eq!(variant.tool, "whitebox-variant-search");
        assert_eq!(variant.file_path, "src/admin.ts");
        assert_eq!(
            variant.static_proof_state,
            Some(StaticProofState::CodeCited)
        );
        assert_ne!(
            variant.static_proof_state,
            Some(StaticProofState::StaticallyConfirmed)
        );
        assert!(variant.message.contains("requires independent validation"));
    }

    #[test]
    fn whitebox_variants_ignore_non_confirmed_and_guarded_candidates() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/source.ts"),
            "const q = req.query.q;\nreturn db.query(q);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/sibling.ts"),
            "const q = validate(req.query.q);\nreturn db.query(q);\n",
        )
        .unwrap();
        let unconfirmed = Finding::new_tool(
            "semgrep",
            "js/sql-injection",
            "src/source.ts",
            2,
            Some(2),
            Severity::High,
            "req.query reaches db.query",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);
        let confirmed = unconfirmed
            .clone()
            .with_static_proof_state(StaticProofState::StaticallyConfirmed);

        let no_patterns =
            derive_whitebox_variant_patterns(&[unconfirmed], None).expect("pattern derivation");
        assert!(no_patterns.is_empty());

        let report = hunt_whitebox_static_variants(temp.path(), &[confirmed], None, 10).unwrap();

        assert_eq!(report.count, 0);
        assert!(report
            .patterns
            .iter()
            .all(|pattern| pattern.original_fingerprint != ""));
    }

    #[test]
    fn registry_dispatches_variant_lift_and_hunt_through_runtime() {
        let (_temp, workspace, store, fingerprint) = seeded_workspace();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let runtime = MockRuntime::new();

        let lift = registry
            .execute_tool_with_runtime(
                "variant:lift-pattern",
                json!({"fingerprint": fingerprint}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();
        assert_eq!(lift.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            lift.pointer("/data/signature/sink").and_then(Value::as_str),
            Some("child_process.exec")
        );

        let hunt = registry
            .execute_tool_with_runtime(
                "variant:hunt",
                json!({"fingerprint": fingerprint, "maxFindings": 5}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();
        assert_eq!(hunt.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            hunt.pointer("/data/variants")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            1
        );
        assert!(hunt
            .pointer("/data/persisted/findingsDb")
            .and_then(Value::as_str)
            .is_some());
    }

    #[test]
    fn variant_hunt_rejects_non_true_positive_findings() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-variant", workspace.root(), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "demo",
            "src/app.ts",
            1,
            None,
            Severity::High,
            "demo",
        );
        let fingerprint = finding.fingerprint.clone();
        let finding_id = store.insert_finding("run-variant", &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::NeedsReview,
                    confidence: 0.4,
                    rationale: "not confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
        };
        let result = run_variant_hunt(
            json!({"fingerprint": fingerprint}),
            &ctx,
            Some(&MockRuntime::new()),
        )
        .unwrap();
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(false));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .unwrap()
            .contains("confirmed TP"));
    }

    #[test]
    fn ndiff_fetch_uses_offline_fixture_and_selects_primary_patch() {
        let result = run_ndiff_fetch_cve(json!({
            "id": "CVE-2024-1234",
            "offline": true,
            "fixtures": {
                "CVE-2024-1234": {
                    "id": "CVE-2024-1234",
                    "description": "Missing bounds check allows OOB write.",
                    "cwes": ["CWE-787"],
                    "severity": "HIGH",
                    "cvssScore": 7.8,
                    "affected": [],
                    "patches": [{"url":"https://github.com/o/r/commit/abc1234","kind":"nvd"}],
                    "publishedAt": "2024-01-15T00:00:00.000Z",
                    "source": "nvd",
                    "raw": {}
                }
            }
        }))
        .unwrap();
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/primaryPatchUrl")
                .and_then(Value::as_str),
            Some("https://github.com/o/r/commit/abc1234")
        );
    }

    #[test]
    fn registry_dispatches_ndiff_extract_and_hunt_through_runtime() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/parser.c"), "memcpy(dst, src, len);\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let runtime = MockRuntime::new();

        let extract = registry
            .execute_tool_with_runtime(
                "ndiff:extract-fix-pattern",
                json!({"patchText": "--- a/parser.c\n+++ b/parser.c\n+if (len > cap) return -1;\n"}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();
        assert_eq!(extract.get("ok").and_then(Value::as_bool), Some(true));
        let pattern = extract.pointer("/data/pattern").cloned().unwrap();

        let hunt = registry
            .execute_tool_with_runtime(
                "ndiff:hunt-variants",
                json!({"pattern": pattern, "advisoryId": "CVE-2024-1234"}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();
        assert_eq!(hunt.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            hunt.pointer("/data/findings")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            hunt.pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("n-day/CVE-2024-1234")
        );
        assert!(hunt
            .pointer("/data/persisted/findingsDb")
            .and_then(Value::as_str)
            .is_some());
    }

    #[test]
    fn ndiff_hunt_requires_explicit_model_without_fallback() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
        };
        let err = run_ndiff_hunt_variants(
            json!({"pattern": {"fixShape":"guard","vulnerableShape":"unguarded"}}),
            &ctx,
            Some(&MockRuntime::new()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("requires an explicit model"));
    }
}
