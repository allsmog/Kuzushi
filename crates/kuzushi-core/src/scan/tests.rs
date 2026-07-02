#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::static_evidence::{StaticEvidenceEdgeKind, StaticEvidenceNodeKind};
    use std::fs;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

    static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = env::var_os(key);
            env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                env::set_var(self.key, previous);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn normalizes_semgrep_json_to_findings() {
        let raw = r#"
        {
          "results": [
            {
              "check_id": "typescript.express.security.audit.xss",
              "path": "src/routes.ts",
              "start": { "line": 42 },
              "end": { "line": 44 },
              "extra": {
                "severity": "ERROR",
                "message": "Detected unescaped user input"
              }
            }
          ]
        }
        "#;

        let findings = normalize_semgrep_json(raw).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "typescript.express.security.audit.xss");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].start_line, 42);
        assert_eq!(findings[0].end_line, Some(44));
        assert_eq!(
            findings[0].static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
    }

    #[test]
    fn scan_runner_composes_multiple_engines() {
        struct StaticScanner;

        impl ScanEngine for StaticScanner {
            fn id(&self) -> &'static str {
                "static"
            }

            fn scan(
                &self,
                _target: &Path,
                _cancellation: &ScanCancellation,
            ) -> Result<Vec<Finding>> {
                Ok(vec![Finding::new_tool(
                    "static",
                    "static/demo",
                    "src/app.rs",
                    12,
                    None,
                    Severity::Low,
                    "static scanner finding",
                )])
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let scanners: Vec<Box<dyn ScanEngine>> =
            vec![Box::new(StaticScanner), Box::new(DepHygieneScanner)];

        let run = run_scan_engines(&workspace, &store, &scanners).unwrap();
        let findings = store.list_findings(10).unwrap();

        assert_eq!(run.findings_count, 2);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|finding| finding.tool == "static"));
        assert!(findings.iter().any(|finding| finding.tool == "dep-hygiene"));
    }

    #[test]
    fn scan_runner_uses_supplied_run_id_for_native_findings() {
        struct StaticScanner;

        impl ScanEngine for StaticScanner {
            fn id(&self) -> &'static str {
                "static"
            }

            fn scan(
                &self,
                _target: &Path,
                _cancellation: &ScanCancellation,
            ) -> Result<Vec<Finding>> {
                Ok(vec![Finding::new_tool(
                    "static",
                    "static/demo",
                    "src/app.rs",
                    12,
                    None,
                    Severity::Low,
                    "static scanner finding",
                )])
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let scanners: Vec<Box<dyn ScanEngine>> = vec![Box::new(StaticScanner)];
        let options = ScanRunOptions {
            run_id: Some("scan-fixed".to_string()),
            severity: None,
            paths: Vec::new(),
            tasks: None,
            static_proof_state: None,
            index_static_evidence: false,
        };

        let run = run_scan_engines_with_options(&workspace, &store, &scanners, &options).unwrap();
        let findings = store.list_findings_for_scan_id("scan-fixed").unwrap();

        assert_eq!(run.id, "scan-fixed");
        assert_eq!(findings.len(), 1);
        assert!(store.list_findings_for_scan_id(&run.id).unwrap().len() == 1);
    }

    #[test]
    fn scan_runner_preflights_before_creating_scan_run() {
        struct MissingBinaryScanner;

        impl ScanEngine for MissingBinaryScanner {
            fn id(&self) -> &'static str {
                "missing"
            }

            fn preflight(&self) -> Result<()> {
                anyhow::bail!("missing scanner binary")
            }

            fn scan(
                &self,
                _target: &Path,
                _cancellation: &ScanCancellation,
            ) -> Result<Vec<Finding>> {
                panic!("scan should not run after failed preflight")
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let scanners: Vec<Box<dyn ScanEngine>> = vec![Box::new(MissingBinaryScanner)];

        let error = run_scan_engines(&workspace, &store, &scanners)
            .unwrap_err()
            .to_string();

        assert!(error.contains("missing preflight failed"));
        assert!(error.contains("missing scanner binary"));
        assert_eq!(store.latest_scan_run_id().unwrap(), None);
    }

    #[test]
    fn subprocess_scanners_report_missing_configured_binary_in_preflight() {
        let tmp = tempfile::tempdir().unwrap();
        let missing_semgrep = tmp.path().join("missing-semgrep");
        let semgrep = SemgrepScanner {
            binary: missing_semgrep.display().to_string(),
            config: vec!["auto".to_string()],
        };

        let error = semgrep.preflight().unwrap_err().to_string();

        assert!(error.contains("semgrep"));
        assert!(error.contains("could not find scanner binary"));

        let missing_codeql = tmp.path().join("missing-codeql");
        let codeql = CodeqlScanner {
            binary: Some(missing_codeql.display().to_string()),
            ..CodeqlScanner::default()
        };

        let error = codeql.preflight().unwrap_err().to_string();

        assert!(error.contains("codeql"));
        assert!(error.contains("could not find CodeQL CLI"));
    }

    #[test]
    fn scan_runner_scopes_paths_and_reprefixes_findings() {
        struct ScopedScanner;

        impl ScanEngine for ScopedScanner {
            fn id(&self) -> &'static str {
                "scoped"
            }

            fn scan(
                &self,
                target: &Path,
                _cancellation: &ScanCancellation,
            ) -> Result<Vec<Finding>> {
                assert!(target.ends_with("web"));
                Ok(vec![Finding::new_tool(
                    "static",
                    "static/demo",
                    "src/app.ts",
                    7,
                    None,
                    Severity::Medium,
                    "scoped scanner finding",
                )])
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("web/src")).unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let scanners: Vec<Box<dyn ScanEngine>> = vec![Box::new(ScopedScanner)];
        let options = ScanRunOptions {
            run_id: Some("scan-scoped".to_string()),
            severity: None,
            paths: vec!["web".to_string()],
            tasks: None,
            static_proof_state: None,
            index_static_evidence: false,
        };

        run_scan_engines_with_options(&workspace, &store, &scanners, &options).unwrap();
        let findings = store.list_findings_for_scan_id("scan-scoped").unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "web/src/app.ts");
    }

    #[test]
    fn semgrep_static_evidence_scan_runner_indexes_whitebox_signals() {
        struct StaticSemgrepScanner;

        impl ScanEngine for StaticSemgrepScanner {
            fn id(&self) -> &'static str {
                "semgrep"
            }

            fn scan(
                &self,
                _target: &Path,
                _cancellation: &ScanCancellation,
            ) -> Result<Vec<Finding>> {
                Ok(vec![Finding::new_semgrep(
                    "javascript.express.security.audit.xss",
                    "src/routes.ts",
                    2,
                    Some(2),
                    Severity::High,
                    "Detected unescaped user input",
                )])
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(
            tmp.path().join("src/routes.ts"),
            "import express from 'express';\nres.send(req.query.name);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let scanners: Vec<Box<dyn ScanEngine>> = vec![Box::new(StaticSemgrepScanner)];
        let options = ScanRunOptions {
            run_id: None,
            severity: None,
            paths: Vec::new(),
            tasks: None,
            static_proof_state: Some(StaticProofState::SignalOnly),
            index_static_evidence: true,
        };

        let run = run_scan_engines_with_options(&workspace, &store, &scanners, &options).unwrap();
        let finding = store.list_findings(10).unwrap().pop().unwrap();
        let evidence_store = StaticEvidenceStore::open(&workspace).unwrap();
        let nodes = evidence_store
            .list_nodes_for_finding(&finding.fingerprint)
            .unwrap();

        assert_eq!(run.findings_count, 1);
        assert_eq!(
            finding.static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
        assert_eq!(nodes.len(), 2);
        assert!(nodes
            .iter()
            .any(|node| node.kind == StaticEvidenceNodeKind::ScannerSignal
                && node
                    .metadata
                    .pointer("/truePositiveByDefault")
                    .and_then(Value::as_bool)
                    == Some(false)));
        assert!(nodes
            .iter()
            .any(|node| node.kind == StaticEvidenceNodeKind::CodeSpan
                && node.body == "res.send(req.query.name);"));
    }

    #[test]
    fn default_scan_engines_include_native_deterministic_scanners() {
        let engines = default_scan_engines();
        let ids = engines.iter().map(|engine| engine.id()).collect::<Vec<_>>();

        assert!(ids.contains(&"semgrep"));
        assert!(ids.contains(&"dep-hygiene"));
        assert!(ids.contains(&"cargo-audit"));
        assert!(ids.contains(&"secret-scan"));
        assert!(ids.contains(&"iac-scan"));
    }

    #[test]
    fn scanner_env_helper_filters_credential_shaped_variables() {
        use super::super::subprocess::is_safe_scanner_env_key;

        assert!(!is_safe_scanner_env_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!is_safe_scanner_env_key("GITHUB_TOKEN"));
        assert!(!is_safe_scanner_env_key("DATABASE_URL"));
        assert!(!is_safe_scanner_env_key("OPENAI_API_KEY"));
        assert!(is_safe_scanner_env_key("PATH"));
        assert!(is_safe_scanner_env_key("TMPDIR"));
        assert!(is_safe_scanner_env_key("LC_ALL"));
    }

    #[cfg(unix)]
    #[test]
    fn scanner_env_scrubs_credentials_from_semgrep_subprocess() {
        use std::os::unix::fs::PermissionsExt;

        let _lock = ENV_TEST_LOCK.lock().unwrap();
        let _aws = EnvVarGuard::set("AWS_SECRET_ACCESS_KEY", "do-not-leak-aws");
        let _github = EnvVarGuard::set("GITHUB_TOKEN", "do-not-leak-github");
        let _database = EnvVarGuard::set("DATABASE_URL", "postgres://do-not-leak");

        let tmp = tempfile::tempdir().unwrap();
        let scanner_path = tmp.path().join("semgrep-env-fixture.sh");
        fs::write(
            &scanner_path,
            r#"#!/bin/sh
if [ "${AWS_SECRET_ACCESS_KEY+x}" = "x" ] || [ "${GITHUB_TOKEN+x}" = "x" ] || [ "${DATABASE_URL+x}" = "x" ]; then
  echo "credential env leaked to semgrep" >&2
  exit 44
fi
printf '{"results":[]}'
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&scanner_path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&scanner_path, permissions).unwrap();

        let scanner = SemgrepScanner {
            binary: scanner_path.display().to_string(),
            config: vec!["ignored".to_string()],
        };

        let findings = scanner
            .scan_with_cancel(tmp.path(), &ScanCancellation::default())
            .unwrap();

        assert!(findings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn cancels_running_scanner_process() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let tmp = tempfile::tempdir().unwrap();
        let scanner_path = tmp.path().join("slow-scanner.sh");
        fs::write(
            &scanner_path,
            "#!/bin/sh\nsleep 5\nprintf '{\"results\":[]}'\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&scanner_path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&scanner_path, permissions).unwrap();

        let scanner = SemgrepScanner {
            binary: scanner_path.display().to_string(),
            config: vec!["ignored".to_string()],
        };
        let cancellation = ScanCancellation::default();
        let worker_cancellation = cancellation.clone();
        let target = tmp.path().to_path_buf();

        let started_at = Instant::now();
        let worker = thread::spawn(move || scanner.scan_with_cancel(&target, &worker_cancellation));
        thread::sleep(Duration::from_millis(200));
        cancellation.cancel();
        let err = worker.join().unwrap().unwrap_err();

        assert!(err.to_string().contains("cancelled"));
        assert!(
            started_at.elapsed() < Duration::from_secs(3),
            "cancellation should not wait for the scanner script's sleep"
        );
    }

    #[test]
    fn normalizes_codeql_sarif_to_findings() {
        let raw = r#"
        {
          "runs": [
            {
              "tool": {
                "driver": {
                  "rules": [
                    {
                      "id": "js/sql-injection",
                      "shortDescription": { "text": "SQL injection" },
                      "properties": {
                        "problem": { "severity": "error" },
                        "precision": "high",
                        "tags": ["security", "external/cwe/cwe-89"]
                      }
                    }
                  ]
                }
              },
              "results": [
                {
                  "ruleId": "js/sql-injection",
                  "message": { "text": "User input reaches SQL sink" },
                  "locations": [
                    {
                      "physicalLocation": {
                        "artifactLocation": { "uri": "src/db.ts" },
                        "region": { "startLine": 42 }
                      }
                    }
                  ],
                  "codeFlows": [
                    {
                      "threadFlows": [
                        {
                          "locations": [
                            {
                              "message": { "text": "user input enters handler" },
                              "location": {
                                "physicalLocation": {
                                  "artifactLocation": { "uri": "src/routes.ts" },
                                  "region": { "startLine": 5 }
                                }
                              }
                            },
                            {
                              "message": { "text": "query reaches db.query" },
                              "location": {
                                "physicalLocation": {
                                  "artifactLocation": { "uri": "src/db.ts" },
                                  "region": { "startLine": 42 }
                                }
                              }
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
        "#;

        let findings = normalize_codeql_sarif(raw, "repo").unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "codeql");
        assert_eq!(findings[0].rule_id, "js/sql-injection");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].file_path, "src/db.ts");
        assert_eq!(findings[0].start_line, 42);
        assert_eq!(
            findings[0].static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
        assert!(findings[0].message.contains("Code flow: src/routes.ts:5"));
    }

    #[test]
    fn codeql_static_evidence_indexes_signal_code_span_and_flow_steps() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            [
                "export function route(req, db) {",
                "  const q = req.query.q;",
                "  return loadUser(db, q);",
                "}",
            ]
            .join("\n"),
        )
        .unwrap();
        fs::write(
            temp.path().join("src/db.ts"),
            [
                "export function loadUser(db, q) {",
                "  return db.query(`select * from users where name = ${q}`);",
                "}",
            ]
            .join("\n"),
        )
        .unwrap();
        let raw = r#"
        {
          "runs": [
            {
              "tool": {
                "driver": {
                  "rules": [
                    {
                      "id": "js/sql-injection",
                      "properties": { "problem": { "severity": "error" } }
                    }
                  ]
                }
              },
              "results": [
                {
                  "ruleId": "js/sql-injection",
                  "message": { "text": "User input reaches SQL sink" },
                  "locations": [
                    {
                      "physicalLocation": {
                        "artifactLocation": { "uri": "src/db.ts" },
                        "region": { "startLine": 2 }
                      }
                    }
                  ],
                  "codeFlows": [
                    {
                      "threadFlows": [
                        {
                          "locations": [
                            {
                              "message": { "text": "user input enters handler" },
                              "location": {
                                "physicalLocation": {
                                  "artifactLocation": { "uri": "src/routes.ts" },
                                  "region": {
                                    "startLine": 2,
                                    "snippet": { "text": "const q = req.query.q;" }
                                  }
                                }
                              }
                            },
                            {
                              "message": { "text": "query reaches db.query" },
                              "location": {
                                "physicalLocation": {
                                  "artifactLocation": { "uri": "src/db.ts" },
                                  "region": {
                                    "startLine": 2,
                                    "snippet": { "text": "return db.query(...);" }
                                  }
                                }
                              }
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
        "#;

        let findings = normalize_codeql_sarif(raw, "repo").unwrap();
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let report = index_codeql_sarif_as_static_evidence(&store, temp.path(), raw).unwrap();
        let nodes = store
            .list_nodes_for_finding(&findings[0].fingerprint)
            .unwrap();
        let scanner_signal = nodes
            .iter()
            .find(|node| node.kind == StaticEvidenceNodeKind::ScannerSignal)
            .unwrap();
        let dataflow_steps = nodes
            .iter()
            .filter(|node| node.kind == StaticEvidenceNodeKind::DataflowStep)
            .collect::<Vec<_>>();
        let first_step = dataflow_steps
            .iter()
            .find(|node| node.source_path.as_deref() == Some("src/routes.ts"))
            .unwrap();

        assert_eq!(report.findings_indexed, 1);
        assert_eq!(nodes.len(), 4);
        assert!(nodes
            .iter()
            .any(|node| node.kind == StaticEvidenceNodeKind::CodeSpan
                && node.source_path.as_deref() == Some("src/db.ts")
                && node.body.contains("db.query")));
        assert_eq!(
            scanner_signal
                .metadata
                .pointer("/truePositiveByDefault")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            scanner_signal
                .metadata
                .pointer("/staticProofState")
                .and_then(Value::as_str),
            Some("signal_only")
        );
        assert_eq!(dataflow_steps.len(), 2);
        assert!(store
            .edges_for_node(&first_step.id)
            .unwrap()
            .iter()
            .any(|edge| edge.kind == StaticEvidenceEdgeKind::FlowsTo));
    }

    #[test]
    fn severity_rank_orders_all_core_severities() {
        assert_eq!(severity_rank(Severity::Critical), 5);
        assert_eq!(severity_rank(Severity::High), 4);
        assert_eq!(severity_rank(Severity::Medium), 3);
        assert_eq!(severity_rank(Severity::Low), 2);
        assert_eq!(severity_rank(Severity::Info), 1);
        assert_eq!(severity_rank(Severity::Unknown), 0);
    }

    #[test]
    fn codeql_uri_normalization_decodes_file_urls_and_windows_drives() {
        assert_eq!(
            normalize_artifact_uri("file:///Users/me/src%20dir/app.js"),
            "Users/me/src dir/app.js"
        );
        assert_eq!(
            normalize_artifact_uri("file:///C:/repo/src%2Fmain.cpp"),
            "repo/src/main.cpp"
        );
        assert_eq!(percent_decode("a%2Fb%ZZ"), "a/b%ZZ");
        assert_eq!(hex_value(b'f'), Some(15));
        assert_eq!(hex_value(b'F'), Some(15));
        assert_eq!(hex_value(b'9'), Some(9));
        assert_eq!(hex_value(b'g'), None);
    }

    #[test]
    fn codeql_language_json_accepts_arrays_objects_and_aliases() {
        let from_array = languages_from_codeql_json(json!([
            "JavaScript",
            {"name": "python"},
            {"name": "c++"},
            {"name": "unknown"},
            7
        ]));
        assert_eq!(from_array, vec!["javascript", "python", "cpp"]);

        let from_languages_key = languages_from_codeql_json(json!({
            "languages": [{"name": "c#"}, "go"]
        }));
        assert_eq!(from_languages_key, vec!["csharp", "go"]);

        let from_object_keys = languages_from_codeql_json(json!({
            "ruby": {},
            "typescript": true,
            "not-a-language": {}
        }));
        assert_eq!(from_object_keys, vec!["ruby", "javascript"]);

        assert_eq!(
            language_from_value(&json!(" java ")),
            Some("java".to_string())
        );
        assert_eq!(
            language_from_value(&json!({"name": "ruby"})),
            Some("ruby".to_string())
        );
        assert_eq!(language_from_value(&json!({})), None);
    }

    #[test]
    fn codeql_binary_resolution_prefers_config_then_path() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let bin_dir = tmp.path().join("bin");
        fs::create_dir(&bin_dir).unwrap();
        let codeql = bin_dir.join(if cfg!(windows) {
            "codeql.exe"
        } else {
            "codeql"
        });
        fs::write(&codeql, "").unwrap();
        let _path = EnvVarGuard::set("PATH", &bin_dir.display().to_string());

        assert_eq!(
            resolve_codeql_binary(Some(" /custom/codeql ")).unwrap(),
            "/custom/codeql"
        );
        assert_eq!(
            resolve_codeql_binary(None).unwrap(),
            codeql.display().to_string()
        );
    }

    #[test]
    fn cached_codeql_binary_path_uses_workspace_state_root() {
        let home = Path::new("/home/kuzushi");

        assert_eq!(
            cached_codeql_binary_path(home),
            crate::workspace::workspace_state_root(home)
                .join("bin")
                .join(codeql_binary_name())
        );
    }

    #[test]
    fn merge_detected_language_output_accumulates_success_errors_and_cancellation() {
        let mut output = ScanEngineOutput::default();
        let mut errors = Vec::new();
        let cancel = ScanCancellation::default();

        merge_detected_language_output(
            Ok(ScanEngineOutput {
                findings: Vec::new(),
                codeql_sarif_documents: vec!["sarif".to_string()],
            }),
            "rust",
            &cancel,
            &mut output,
            &mut errors,
        )
        .unwrap();
        assert_eq!(output.codeql_sarif_documents, vec!["sarif"]);

        merge_detected_language_output(
            Err(anyhow::anyhow!("missing db")),
            "go",
            &cancel,
            &mut output,
            &mut errors,
        )
        .unwrap();
        assert_eq!(errors, vec!["go: missing db"]);

        let cancel = ScanCancellation::default();
        cancel.cancel();
        let err = merge_detected_language_output(
            Err(anyhow::anyhow!("cancelled")),
            "c",
            &cancel,
            &mut output,
            &mut errors,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "cancelled");
    }

    #[test]
    fn codeql_positive_u32_accepts_numbers_strings_and_rejects_bad_values() {
        assert_eq!(
            positive_u32(&json!({"threads": 4}), "threads").unwrap(),
            Some(4)
        );
        assert_eq!(
            positive_u32(&json!({"threads": " 6 "}), "threads").unwrap(),
            Some(6)
        );
        assert_eq!(positive_u32(&json!({}), "threads").unwrap(), None);
        assert_eq!(
            positive_u32(&json!({"threads": u64::MAX}), "threads").unwrap(),
            Some(u32::MAX)
        );
        assert!(positive_u32(&json!({"threads": 0}), "threads").is_err());
        assert!(positive_u32(&json!({"threads": "nope"}), "threads").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn run_semgrep_scan_persists_findings_and_scan_run() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let scanner_path = tmp.path().join("semgrep-persist-fixture.sh");
        fs::write(
            &scanner_path,
            r#"#!/bin/sh
cat <<'JSON'
{
  "results": [
    {
      "check_id": "javascript.express.security.audit.xss",
      "path": "server.js",
      "start": { "line": 9 },
      "end": { "line": 9 },
      "extra": {
        "severity": "ERROR",
        "message": "Detected unescaped user input"
      }
    }
  ]
}
JSON
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&scanner_path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&scanner_path, permissions).unwrap();

        fs::write(tmp.path().join("server.js"), "res.send(req.query.name)\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let scanner = SemgrepScanner {
            binary: scanner_path.display().to_string(),
            config: vec!["ignored".to_string()],
        };

        let run = run_semgrep_scan(&workspace, &store, &scanner).unwrap();
        let findings = store.list_findings(10).unwrap();

        assert_eq!(run.findings_count, 1);
        assert_eq!(run.target, workspace.root());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "semgrep");
    }

    #[cfg(unix)]
    fn fake_codeql_binary(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("codeql-fixture.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
if [ "$1" = "resolve" ] && [ "$2" = "languages" ]; then
  printf '["javascript"]'
  exit 0
fi
if [ "$1" = "database" ] && [ "$2" = "resolve" ]; then
  printf '["javascript"]'
  exit 0
fi
if [ "$1" = "database" ] && [ "$2" = "create" ]; then
  mkdir -p "$3"
  printf 'name: test\n' > "$3/codeql-database.yml"
  exit 0
fi
if [ "$1" = "database" ] && [ "$2" = "analyze" ]; then
  out=""
  for arg in "$@"; do
    case "$arg" in
      --output=*) out="${arg#--output=}" ;;
    esac
  done
  cat > "$out" <<'JSON'
{
  "runs": [
    {
      "tool": {
        "driver": {
          "rules": [
            {
              "id": "js/sql-injection",
              "properties": { "problem": { "severity": "error" } }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "js/sql-injection",
          "message": { "text": "User input reaches SQL sink" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "server.js" },
                "region": { "startLine": 9 }
              }
            }
          ]
        }
      ]
    }
  ]
}
JSON
  exit 0
fi
echo "unexpected codeql args: $*" >&2
exit 2
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    #[test]
    fn codeql_scanner_invokes_subprocess_and_normalizes_sarif() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("package.json"), "{}\n").unwrap();
        fs::write(tmp.path().join("server.js"), "db.query(req.query.q)\n").unwrap();
        let binary = fake_codeql_binary(tmp.path());
        let scanner = CodeqlScanner {
            binary: Some(binary.display().to_string()),
            language: Some("javascript".to_string()),
            ..CodeqlScanner::default()
        };

        let findings = scanner
            .scan_with_cancel(tmp.path(), &ScanCancellation::default())
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "codeql");
        assert_eq!(findings[0].rule_id, "js/sql-injection");
        assert!(crate::workspace::workspace_codeql_db_path(tmp.path())
            .join("codeql-database.yml")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn scan_runner_can_compose_codeql_with_other_engines() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        fs::write(tmp.path().join("server.js"), "db.query(req.query.q)\n").unwrap();
        let binary = fake_codeql_binary(tmp.path());
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let scanners: Vec<Box<dyn ScanEngine>> = vec![
            Box::new(CodeqlScanner {
                binary: Some(binary.display().to_string()),
                language: Some("javascript".to_string()),
                ..CodeqlScanner::default()
            }),
            Box::new(DepHygieneScanner),
        ];

        let run = run_scan_engines(&workspace, &store, &scanners).unwrap();
        let findings = store.list_findings(10).unwrap();

        assert_eq!(run.findings_count, 2);
        assert!(findings.iter().any(|finding| finding.tool == "codeql"));
        assert!(findings.iter().any(|finding| finding.tool == "dep-hygiene"));
    }

    #[test]
    fn codeql_static_evidence_scan_runner_indexes_whitebox_code_flows() {
        struct StaticCodeqlScanner {
            raw: String,
            findings: Vec<Finding>,
        }

        impl ScanEngine for StaticCodeqlScanner {
            fn id(&self) -> &'static str {
                "codeql"
            }

            fn scan(
                &self,
                _target: &Path,
                _cancellation: &ScanCancellation,
            ) -> Result<Vec<Finding>> {
                Ok(self.findings.clone())
            }

            fn scan_artifacts(
                &self,
                _target: &Path,
                _cancellation: &ScanCancellation,
            ) -> Result<ScanEngineOutput> {
                Ok(ScanEngineOutput {
                    findings: self.findings.clone(),
                    codeql_sarif_documents: vec![self.raw.clone()],
                })
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(
            tmp.path().join("src/routes.ts"),
            "export function route(req, db) {\n  return db.query(req.query.q);\n}\n",
        )
        .unwrap();
        let raw = r#"
        {
          "runs": [
            {
              "tool": { "driver": { "rules": [{ "id": "js/sql-injection" }] } },
              "results": [
                {
                  "ruleId": "js/sql-injection",
                  "message": { "text": "User input reaches SQL sink" },
                  "locations": [
                    {
                      "physicalLocation": {
                        "artifactLocation": { "uri": "src/routes.ts" },
                        "region": { "startLine": 2 }
                      }
                    }
                  ],
                  "codeFlows": [
                    {
                      "threadFlows": [
                        {
                          "locations": [
                            {
                              "message": { "text": "source" },
                              "location": {
                                "physicalLocation": {
                                  "artifactLocation": { "uri": "src/routes.ts" },
                                  "region": { "startLine": 1 }
                                }
                              }
                            },
                            {
                              "message": { "text": "sink" },
                              "location": {
                                "physicalLocation": {
                                  "artifactLocation": { "uri": "src/routes.ts" },
                                  "region": { "startLine": 2 }
                                }
                              }
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
        "#;
        let findings = normalize_codeql_sarif(raw, "repo").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let scanners: Vec<Box<dyn ScanEngine>> = vec![Box::new(StaticCodeqlScanner {
            raw: raw.to_string(),
            findings,
        })];
        let options = ScanRunOptions {
            run_id: None,
            severity: None,
            paths: Vec::new(),
            tasks: None,
            static_proof_state: Some(StaticProofState::SignalOnly),
            index_static_evidence: true,
        };

        let run = run_scan_engines_with_options(&workspace, &store, &scanners, &options).unwrap();
        let finding = store.list_findings(10).unwrap().pop().unwrap();
        let evidence_store = StaticEvidenceStore::open(&workspace).unwrap();
        let nodes = evidence_store
            .list_nodes_for_finding(&finding.fingerprint)
            .unwrap();

        assert_eq!(run.findings_count, 1);
        assert_eq!(
            finding.static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
        assert!(nodes
            .iter()
            .any(|node| node.kind == StaticEvidenceNodeKind::ScannerSignal));
        assert!(nodes
            .iter()
            .any(|node| node.kind == StaticEvidenceNodeKind::DataflowStep));
    }

    #[cfg(unix)]
    #[test]
    fn scanner_env_scrubs_credentials_from_codeql_subprocesses() {
        use std::os::unix::fs::PermissionsExt;

        let _lock = ENV_TEST_LOCK.lock().unwrap();
        let _aws = EnvVarGuard::set("AWS_SECRET_ACCESS_KEY", "do-not-leak-aws");
        let _github = EnvVarGuard::set("GITHUB_TOKEN", "do-not-leak-github");
        let _database = EnvVarGuard::set("DATABASE_URL", "postgres://do-not-leak");

        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("package.json"), "{}\n").unwrap();
        fs::write(tmp.path().join("server.js"), "db.query(req.query.q)\n").unwrap();
        let binary = tmp.path().join("codeql-env-fixture.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
if [ "${AWS_SECRET_ACCESS_KEY+x}" = "x" ] || [ "${GITHUB_TOKEN+x}" = "x" ] || [ "${DATABASE_URL+x}" = "x" ]; then
  echo "credential env leaked to codeql" >&2
  exit 44
fi
if [ "$1" = "database" ] && [ "$2" = "create" ]; then
  mkdir -p "$3"
  printf 'name: test\n' > "$3/codeql-database.yml"
  exit 0
fi
if [ "$1" = "database" ] && [ "$2" = "analyze" ]; then
  out=""
  for arg in "$@"; do
    case "$arg" in
      --output=*) out="${arg#--output=}" ;;
    esac
  done
  printf '{"runs":[]}' > "$out"
  exit 0
fi
echo "unexpected codeql args: $*" >&2
exit 2
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();

        let scanner = CodeqlScanner {
            binary: Some(binary.display().to_string()),
            language: Some("javascript".to_string()),
            ..CodeqlScanner::default()
        };

        let findings = scanner
            .scan_with_cancel(tmp.path(), &ScanCancellation::default())
            .unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn scan_engines_for_tasks_resolves_codeql_task() {
        let engines = scan_engines_for_tasks(&["codeql".to_string()]).unwrap();
        let ids = engines.iter().map(|engine| engine.id()).collect::<Vec<_>>();

        assert_eq!(ids, vec!["codeql"]);
    }

    #[test]
    fn scan_engines_for_tasks_resolves_iac_scan_task() {
        let engines = scan_engines_for_tasks(&["iac-scan".to_string()]).unwrap();
        let ids = engines.iter().map(|engine| engine.id()).collect::<Vec<_>>();

        assert_eq!(ids, vec!["iac-scan"]);
    }

    #[test]
    fn scan_engines_for_tasks_resolves_cargo_audit_task() {
        let engines = scan_engines_for_tasks(&["cargo-audit".to_string()]).unwrap();
        let ids = engines.iter().map(|engine| engine.id()).collect::<Vec<_>>();

        assert_eq!(ids, vec!["cargo-audit"]);
    }

    #[test]
    fn scan_engines_for_tasks_resolves_license_scan_task() {
        let engines = scan_engines_for_tasks(&["license-scan".to_string()]).unwrap();
        let ids = engines.iter().map(|engine| engine.id()).collect::<Vec<_>>();

        assert_eq!(ids, vec!["license-scan"]);
    }

    #[cfg(unix)]
    #[test]
    fn cancels_running_codeql_process() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        fs::create_dir_all(&db).unwrap();
        fs::write(db.join("codeql-database.yml"), "name: test\n").unwrap();
        let binary = tmp.path().join("slow-codeql.sh");
        fs::write(
            &binary,
            "#!/bin/sh\nsleep 5\nout=\"\"\nfor arg in \"$@\"; do case \"$arg\" in --output=*) out=\"${arg#--output=}\" ;; esac; done\nprintf '{\"runs\":[]}' > \"$out\"\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();

        let scanner = CodeqlScanner {
            binary: Some(binary.display().to_string()),
            db_path: Some(db.display().to_string()),
            language: Some("javascript".to_string()),
            ..CodeqlScanner::default()
        };
        let cancellation = ScanCancellation::default();
        let worker_cancellation = cancellation.clone();
        let target = tmp.path().to_path_buf();

        let started_at = Instant::now();
        let worker = thread::spawn(move || scanner.scan_with_cancel(&target, &worker_cancellation));
        thread::sleep(Duration::from_millis(200));
        cancellation.cancel();
        let err = worker.join().unwrap().unwrap_err();

        assert!(err.to_string().contains("cancelled"));
        assert!(
            started_at.elapsed() < Duration::from_secs(3),
            "cancellation should not wait for the CodeQL script's sleep"
        );
    }
}
