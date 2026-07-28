#[cfg(test)]
mod tests {
    use super::super::classification::{
        sink_marker_path, stderr_has_sanitizer_crash, SINK_MARKER_CONTENT,
    };
    use super::super::unsupported::enforce_empirical_provenance;
    use super::super::*;
    use crate::findings::Severity;
    use kuzushi_sandbox::{ExitOutcome, SandboxExecResult};
    use serde_json::json;

    fn finding_for(path: &str) -> Finding {
        Finding::new_tool(
            "verify-test",
            "rule.test",
            path,
            42,
            Some(43),
            Severity::Medium,
            "synthetic finding for verify tests",
        )
    }

    fn finding_in_workspace(path: &str, source: &str) -> (tempfile::TempDir, Finding) {
        let workspace = tempfile::tempdir().unwrap();
        let source_path = workspace.path().join(path);
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        std::fs::write(source_path, source).unwrap();
        (workspace, finding_for(path))
    }

    fn sandbox_result(
        outcome: ExitOutcome,
        exit_code: Option<i32>,
        signal: Option<i32>,
    ) -> SandboxExecResult {
        SandboxExecResult {
            backend: SandboxBackend::Bwrap,
            outcome,
            exit_code,
            signal,
            stdout: String::new(),
            stderr: "stderr text".to_string(),
            stdout_truncated: false,
            stderr_truncated: false,
            duration_ms: 100,
        }
    }

    #[test]
    fn classification_requires_matching_reached_sink_evidence() {
        struct Case {
            name: &'static str,
            result: SandboxExecResult,
            marker: Option<&'static str>,
            expected_level: u8,
            expected_verdict: ProofVerdict,
        }

        let mut sanitizer_without_marker = sandbox_result(ExitOutcome::Exited, Some(1), None);
        sanitizer_without_marker.stderr =
            "==99==ERROR: AddressSanitizer: stack-buffer-overflow".to_string();
        let mut wrapped_crash = sandbox_result(ExitOutcome::Exited, Some(101), None);
        wrapped_crash.stderr =
            "test failed, process didn't exit successfully (signal: 11, SIGSEGV: invalid memory reference)"
                .to_string();
        let cases = [
            Case {
                name: "no-marker crash",
                result: sandbox_result(ExitOutcome::Signaled, None, Some(11)),
                marker: None,
                expected_level: 1,
                expected_verdict: ProofVerdict::InfrastructureError,
            },
            Case {
                name: "marker clean",
                result: sandbox_result(ExitOutcome::Exited, Some(0), None),
                marker: Some(SINK_MARKER_CONTENT),
                expected_level: 2,
                expected_verdict: ProofVerdict::NotReproduced,
            },
            Case {
                name: "marker matching crash",
                result: sandbox_result(ExitOutcome::Signaled, None, Some(11)),
                marker: Some(SINK_MARKER_CONTENT),
                expected_level: 4,
                expected_verdict: ProofVerdict::Exploited,
            },
            Case {
                name: "timeout after marker",
                result: sandbox_result(ExitOutcome::TimedOut, None, None),
                marker: Some(SINK_MARKER_CONTENT),
                expected_level: 1,
                expected_verdict: ProofVerdict::InfrastructureError,
            },
            Case {
                name: "unexplained nonzero after marker",
                result: sandbox_result(ExitOutcome::Exited, Some(101), None),
                marker: Some(SINK_MARKER_CONTENT),
                expected_level: 1,
                expected_verdict: ProofVerdict::InfrastructureError,
            },
            Case {
                name: "sanitizer crash without marker",
                result: sanitizer_without_marker,
                marker: None,
                expected_level: 1,
                expected_verdict: ProofVerdict::InfrastructureError,
            },
            Case {
                name: "marker matching wrapped crash",
                result: wrapped_crash,
                marker: Some(SINK_MARKER_CONTENT),
                expected_level: 4,
                expected_verdict: ProofVerdict::Exploited,
            },
        ];

        for case in cases {
            let project = tempfile::tempdir().unwrap();
            if let Some(marker) = case.marker {
                std::fs::write(sink_marker_path(project.path()), marker).unwrap();
            }
            let outcome = classify_run_result(
                &case.result,
                SandboxBackend::Bwrap,
                project.path(),
                HarnessFidelity::Faithful,
            );
            assert_eq!(outcome.proof_level, case.expected_level, "{}", case.name);
            assert_eq!(
                outcome.proof_verdict, case.expected_verdict,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn runtime_evidence_is_redacted_and_bounded() {
        let redacted =
            bounded_runtime_evidence("Authorization: Bearer secret-token-value-1234567890")
                .unwrap();
        let bounded = bounded_runtime_evidence(&"x".repeat(20 * 1024)).unwrap();

        assert!(!redacted.contains("secret-token-value"));
        assert!(redacted.contains("[REDACTED]"));
        assert!(bounded.contains("evidence truncated"));
        assert!(bounded.chars().count() < 17 * 1024);
    }

    #[tokio::test]
    async fn placeholder_languages_are_not_executed() {
        let (_workspace, finding) = finding_in_workspace("src/app.py", "# verify fixture\n");
        let options = VerifyOptions::default();
        let outcomes = [
            (
                "Python",
                verify_python(&finding, SandboxBackend::Bwrap, &options)
                    .await
                    .unwrap(),
            ),
            (
                "Node.js",
                verify_node(&finding, SandboxBackend::Bwrap, &options, "js")
                    .await
                    .unwrap(),
            ),
            (
                "TypeScript",
                verify_node(&finding, SandboxBackend::Bwrap, &options, "ts")
                    .await
                    .unwrap(),
            ),
        ];
        for (label, outcome) in outcomes {
            assert_eq!(outcome.proof_verdict, ProofVerdict::NotAttempted, "{label}");
            assert_eq!(outcome.duration_ms, 0, "{label}");
            assert!(outcome.harness_path.is_none(), "{label}");
        }
    }

    #[tokio::test]
    async fn plain_backend_is_refused_even_when_legacy_trust_flag_is_true() {
        let workspace = tempfile::tempdir().unwrap();
        let finding = finding_for("../outside.rs");
        let outcome = verify_finding(
            &finding,
            VerifyOptions {
                backend: Some(SandboxBackend::Plain),
                trust_plain_backend: true,
                ..VerifyOptions::default()
            },
            workspace.path(),
        )
        .await
        .unwrap();

        assert_eq!(outcome.proof_verdict, ProofVerdict::NotAttempted);
        assert_eq!(outcome.backend, SandboxBackend::Plain);
        assert_eq!(outcome.duration_ms, 0);
        assert!(outcome.harness_path.is_none());
        assert!(outcome
            .notes
            .iter()
            .any(|note| note.contains("not executed")));
    }

    #[tokio::test]
    async fn verify_rust_reaches_a_terminal_outcome() {
        let (workspace, finding) = finding_in_workspace(
            "src/lib.rs",
            "pub fn parse(input: &[u8]) { let _ = input; }\n",
        );
        let outcome = verify_finding(&finding, VerifyOptions::default(), workspace.path())
            .await
            .unwrap();
        assert_eq!(outcome.language.as_deref(), Some("rust"));
        assert!(matches!(
            outcome.proof_verdict,
            ProofVerdict::NotAttempted
                | ProofVerdict::Exploited
                | ProofVerdict::NotReproduced
                | ProofVerdict::HarnessFailedToBuild
                | ProofVerdict::InfrastructureError
        ));
    }

    #[tokio::test]
    async fn verify_c_reaches_a_terminal_outcome() {
        let (workspace, finding) = finding_in_workspace(
            "src/x.c",
            "#include <stddef.h>\nvoid parse(const unsigned char *p, size_t n) { (void)p; (void)n; }\n",
        );
        let outcome = verify_finding(&finding, VerifyOptions::default(), workspace.path())
            .await
            .unwrap();
        assert_eq!(outcome.language.as_deref(), Some("c"));
        assert!(matches!(
            outcome.proof_verdict,
            ProofVerdict::NotAttempted
                | ProofVerdict::Exploited
                | ProofVerdict::NotReproduced
                | ProofVerdict::HarnessFailedToBuild
                | ProofVerdict::InfrastructureError
        ));
    }

    #[tokio::test]
    async fn verify_node_returns_not_attempted() {
        let (workspace, finding) = finding_in_workspace("src/x.js", "// verify fixture\n");
        let outcome = verify_finding(&finding, VerifyOptions::default(), workspace.path())
            .await
            .unwrap();
        assert_eq!(outcome.language.as_deref(), Some("javascript"));
        assert_eq!(outcome.proof_verdict, ProofVerdict::NotAttempted);
    }

    #[test]
    fn proof_verdict_strings_are_stable() {
        assert_eq!(ProofVerdict::NotAttempted.as_str(), "not_attempted");
        assert_eq!(ProofVerdict::Exploited.as_str(), "exploited");
        assert_eq!(ProofVerdict::NotReproduced.as_str(), "not_reproduced");
        assert_eq!(
            ProofVerdict::LanguageUnsupportedYet.as_str(),
            "language_unsupported_yet"
        );
    }

    #[test]
    fn synthesized_payload_is_fixed_and_does_not_embed_finding_prose() {
        let finding = finding_for("src/x.rs");
        let payload = synth_payload_from_finding(&finding);
        assert_eq!(payload, vec![0xff; 72]);
        assert!(!String::from_utf8_lossy(&payload).contains("synthetic finding"));
    }

    #[test]
    fn rust_and_c_harnesses_accept_an_explicit_internal_payload() {
        let (rust_workspace, rust_finding) = finding_in_workspace(
            "src/x.rs",
            "pub fn parse(input: &[u8]) { let _ = input; }\n",
        );
        let rust =
            build_rust_trigger_with_payload(&rust_finding, rust_workspace.path(), &[1, 2, 3, 4])
                .unwrap();
        assert_eq!(rust.payload, vec![1, 2, 3, 4]);
        assert!(rust.trigger_test.contains("vec![1, 2, 3, 4]"));

        let (c_workspace, c_finding) = finding_in_workspace(
            "src/x.c",
            "#include <stdint.h>\nvoid parse(const uint8_t *p) { (void)p; }\n",
        );
        let c =
            build_c_trigger_with_payload(&c_finding, c_workspace.path(), &[1, 2, 3, 4]).unwrap();
        assert_eq!(c.payload, vec![1, 2, 3, 4]);
        assert!(c.trigger_c.contains("0x01, 0x02, 0x03, 0x04"));
    }

    #[tokio::test]
    async fn scaffold_writes_cargo_project_layout() {
        let (workspace, finding) = finding_in_workspace("src/x.rs", "// no signature\n");
        let src = build_rust_trigger(&finding, workspace.path()).unwrap();
        let project = scaffold_rust_project(&src).await.unwrap();
        assert!(project.path.join("Cargo.toml").exists());
        assert!(project.path.join("src").join("lib.rs").exists());
        let trigger = tokio::fs::read_to_string(project.path.join("tests").join("trigger.rs"))
            .await
            .unwrap();
        assert!(trigger.contains("#[test]"));
        assert!(trigger.contains("fn trigger()"));
    }

    #[tokio::test]
    async fn verifier_command_helpers_mount_project_read_write() {
        let (workspace, finding) = finding_in_workspace("src/x.rs", "// no signature\n");
        let src = build_rust_trigger(&finding, workspace.path()).unwrap();
        let project = scaffold_rust_project(&src).await.unwrap();
        let opts = VerifyOptions {
            timeout_ms: 1234,
            ..VerifyOptions::default()
        };

        let command = rust_compile_command(&project, &opts);
        assert_eq!(command.timeout_ms, 1234);
        assert_eq!(command.workdir.as_deref(), Some(project.path.as_path()));
        assert_eq!(command.read_write_mounts.len(), 1);
        assert_eq!(command.read_write_mounts[0].host_path, project.path);

        let run_command = rust_run_command(&project, &opts);
        assert_eq!(
            run_command.env.get("KUZUSHI_SINK_MARKER"),
            Some(&sink_marker_path(&project.path).display().to_string())
        );
    }

    #[tokio::test]
    async fn compile_failure_outcome_maps_nonzero_exit_to_harness_failure() {
        let (workspace, finding) = finding_in_workspace("src/x.rs", "// no signature\n");
        let src = build_rust_trigger(&finding, workspace.path()).unwrap();
        let project = scaffold_rust_project(&src).await.unwrap();
        let compile = sandbox_result(ExitOutcome::Exited, Some(1), None);

        let outcome = compile_failure_outcome(SandboxBackend::Bwrap, &project, &compile).unwrap();
        assert_eq!(outcome.proof_verdict, ProofVerdict::HarnessFailedToBuild);
        assert_eq!(
            outcome.harness_path.as_deref(),
            Some(project.path.as_path())
        );
    }

    #[test]
    fn outcome_unsupported_constructor_marks_level_1() {
        let o = VerificationOutcome::unsupported(SandboxBackend::Bwrap, "go");
        assert_eq!(o.proof_level, 1);
        assert_eq!(o.proof_verdict, ProofVerdict::LanguageUnsupportedYet);
        assert!(o.notes.iter().any(|n| n.contains("go")));
    }

    #[test]
    fn outcome_insufficient_constructor_marks_level_1() {
        let o = VerificationOutcome::insufficient(SandboxBackend::Plain, "no file");
        assert_eq!(o.proof_level, 1);
        assert_eq!(o.proof_verdict, ProofVerdict::InsufficientFindingDetail);
    }

    #[test]
    fn to_tool_json_returns_ok_envelope() {
        let finding = finding_for("src/x.rs");
        let outcome = VerificationOutcome::unsupported(SandboxBackend::Bwrap, "rs");
        let v = to_tool_json(&finding, &outcome);
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["status"], json!("completed"));
        assert_eq!(v["artifacts"], json!([]));
        assert_eq!(v["warnings"], json!([]));
        assert_eq!(v["errors"], json!([]));
        assert_eq!(v["proof"]["fingerprint"], json!(finding.fingerprint));
        assert_eq!(v["proof"]["proofLevel"], json!(1));
        assert_eq!(v["data"]["fingerprint"], json!(finding.fingerprint));
        assert_eq!(v["data"]["proof"]["ruleId"], json!(finding.rule_id));
        assert!(v["data"]["verification"].is_object());
    }

    // ----- language inference --------------------------------------

    #[test]
    fn language_inference_covers_supported_extensions() {
        assert_eq!(infer_language("a.rs"), Lang::Rust);
        assert_eq!(infer_language("a.c"), Lang::C);
        assert_eq!(infer_language("a.h"), Lang::C);
        assert_eq!(infer_language("a.cpp"), Lang::Cpp);
        assert_eq!(infer_language("a.cxx"), Lang::Cpp);
        assert_eq!(infer_language("a.hpp"), Lang::Cpp);
        assert_eq!(infer_language("a.py"), Lang::Python);
        assert_eq!(infer_language("a.js"), Lang::JavaScript);
        assert_eq!(infer_language("a.mjs"), Lang::JavaScript);
        assert_eq!(infer_language("a.ts"), Lang::TypeScript);
        assert_eq!(infer_language("a.tsx"), Lang::TypeScript);
        assert_eq!(infer_language("a.go"), Lang::Other("go".to_string()));
        assert_eq!(
            infer_language("Makefile"),
            Lang::Other("unknown".to_string())
        );
    }

    // ----- function-signature heuristic -----------------------------

    #[test]
    fn looks_like_signature_recognises_rust_fn() {
        assert!(looks_like_function_signature("fn foo() {"));
        assert!(looks_like_function_signature("pub fn foo() {"));
        assert!(looks_like_function_signature("pub async fn foo() {"));
        assert!(looks_like_function_signature("    fn nested() -> i32 {"));
    }

    #[test]
    fn looks_like_signature_recognises_python_def() {
        assert!(looks_like_function_signature("def foo():"));
        assert!(looks_like_function_signature("async def foo(x):"));
    }

    #[test]
    fn looks_like_signature_recognises_javascript() {
        assert!(looks_like_function_signature("function foo() {"));
        assert!(looks_like_function_signature("async function foo(x) {"));
        assert!(looks_like_function_signature("export function foo(x) {"));
    }

    #[test]
    fn looks_like_signature_recognises_c_style() {
        assert!(looks_like_function_signature("int foo(void) {"));
        assert!(looks_like_function_signature(
            "static char *bar(int x, int y) {"
        ));
        assert!(looks_like_function_signature("void quux(struct s *p) {"));
    }

    #[test]
    fn looks_like_signature_rejects_control_flow_and_calls() {
        assert!(!looks_like_function_signature(""));
        assert!(!looks_like_function_signature("// comment"));
        assert!(!looks_like_function_signature("# comment"));
        assert!(!looks_like_function_signature("/* block */"));
        assert!(!looks_like_function_signature("if (x > 0) {"));
        assert!(!looks_like_function_signature("while (true) {"));
        assert!(!looks_like_function_signature("for (i = 0; i < 10; i++) {"));
        assert!(!looks_like_function_signature("return foo(x);"));
        assert!(!looks_like_function_signature("foo(x);"));
    }

    // ----- enclosing-function extraction ---------------------------

    #[test]
    fn extract_enclosing_function_finds_rust_signature_above_line() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lib.rs");
        std::fs::write(
            &path,
            "// header comment\n\
             pub fn target(input: &[u8]) -> usize {\n\
                 let n = input.len();\n\
                 // suspect line\n\
                 n + 1\n\
             }\n",
        )
        .unwrap();
        let f = extract_enclosing_function(&path, 4).expect("should find target");
        assert!(f.signature.contains("pub fn target"));
        assert_eq!(f.line, 4);
    }

    #[test]
    fn extract_enclosing_function_finds_c_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("foo.c");
        std::fs::write(
            &path,
            "#include <stddef.h>\n\
             static int parse_packet(const char *p, size_t n) {\n\
                 size_t i = 0;\n\
                 char c = p[n];   // suspect: OOB\n\
                 return c;\n\
             }\n",
        )
        .unwrap();
        let f = extract_enclosing_function(&path, 4).expect("should find parse_packet");
        assert!(f.signature.contains("parse_packet"));
    }

    #[test]
    fn extract_enclosing_function_returns_none_when_no_signature_in_window() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("notes.txt");
        std::fs::write(&path, "just some text\nnot a function\nat all\n").unwrap();
        assert!(extract_enclosing_function(&path, 2).is_none());
    }

    #[test]
    fn extract_enclosing_function_returns_none_when_file_missing() {
        let path = std::path::Path::new("/this/path/does/not/exist.rs");
        assert!(extract_enclosing_function(path, 1).is_none());
    }

    // ----- persistence round-trip ----------------------------------

    #[test]
    fn outcome_to_persisted_round_trips_fields() {
        let outcome = VerificationOutcome {
            proof_level: 4,
            proof_verdict: ProofVerdict::Exploited,
            backend: SandboxBackend::Bwrap,
            language: Some("rust".to_string()),
            harness_path: Some(PathBuf::from("/tmp/harness")),
            crash_evidence: Some("SIGSEGV".to_string()),
            duration_ms: 1500,
            cost_usd: 0.0,
            notes: vec!["one".to_string(), "two".to_string()],
            provenance: None,
        };
        let p = outcome.to_persisted();
        assert_eq!(p.proof_level, 4);
        assert_eq!(p.proof_verdict, PersistedProofVerdict::Exploited);
        assert_eq!(p.backend, PersistedSandboxBackend::Bwrap);
        assert_eq!(p.language.as_deref(), Some("rust"));
        assert!(p.harness_path.is_none());
        assert_eq!(p.crash_evidence.as_deref(), Some("SIGSEGV"));
        assert_eq!(p.duration_ms, 1500);
        assert_eq!(p.notes, vec!["one".to_string(), "two".to_string()]);
    }

    #[test]
    fn empirical_reproducer_is_durable_deterministic_and_source_bound() {
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = crate::WorkspaceTarget::new(workspace_dir.path()).unwrap();
        workspace.ensure_state_dir().unwrap();
        let invocation = ReproducerInvocation {
            compile_argv: vec!["compiler".to_string(), "source.c".to_string()],
            execute_argv: vec!["./proof".to_string()],
        };
        let first_ref = {
            let project = tempfile::tempdir().unwrap();
            std::fs::write(
                project.path().join("source.c"),
                "int main(void) { return 0; }\n",
            )
            .unwrap();
            persist_empirical_reproducer(
                workspace.root(),
                project.path(),
                "c",
                invocation.clone(),
                &["source.c"],
                &[0xff; 72],
            )
            .unwrap()
        };

        let store = crate::content_store::ContentStore::open(workspace.objects_dir()).unwrap();
        let bytes = store.get_object(&first_ref).unwrap();
        let snapshot: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(snapshot["schemaVersion"], 2);
        assert_eq!(snapshot["files"][0]["path"], "source.c");
        assert_eq!(snapshot["cases"].as_array().unwrap().len(), 5);
        assert_eq!(snapshot["cases"][0]["kind"], "original_attack");
        assert_eq!(snapshot["cases"][1]["kind"], "benign_control");
        assert!(!snapshot
            .to_string()
            .contains(workspace.root().to_string_lossy().as_ref()));

        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("source.c"),
            "int main(void) { return 0; }\n",
        )
        .unwrap();
        let same_ref = persist_empirical_reproducer(
            workspace.root(),
            project.path(),
            "c",
            invocation.clone(),
            &["source.c"],
            &[0xff; 72],
        )
        .unwrap();
        assert_eq!(first_ref.hash, same_ref.hash);

        std::fs::write(
            project.path().join("source.c"),
            "int main(void) { return 1; }\n",
        )
        .unwrap();
        let changed_ref = persist_empirical_reproducer(
            workspace.root(),
            project.path(),
            "c",
            invocation,
            &["source.c"],
            &[0xff; 72],
        )
        .unwrap();
        assert_ne!(first_ref.hash, changed_ref.hash);
    }

    #[test]
    fn empirical_reproducer_read_rejects_case_count_and_size_bounds() {
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = crate::WorkspaceTarget::new(workspace_dir.path()).unwrap();
        workspace.ensure_state_dir().unwrap();
        let store = crate::content_store::ContentStore::open(workspace.objects_dir()).unwrap();
        let base = serde_json::json!({
            "schemaVersion": 2,
            "language": "c",
            "invocation": {
                "compileArgv": ["cc", "source.c"],
                "executeArgv": ["./proof"]
            },
            "files": [{"path": "source.c", "source": "int main(void) { return 0; }"}],
            "cases": [
                empirical_case_json("original", "original_attack", vec![0xff]),
                empirical_case_json("control", "benign_control", vec![0]),
                empirical_case_json("variant-1", "variant", vec![0xfe])
            ]
        });

        let valid_ref = store
            .put_json(crate::content_store::ObjectKind::ProofSnapshot, &base)
            .unwrap();
        assert!(load_empirical_reproducer(workspace.root(), &valid_ref).is_ok());

        let mut too_many = base.clone();
        let cases = too_many["cases"].as_array_mut().unwrap();
        cases.push(empirical_case_json("variant-2", "variant", vec![0xfd]));
        cases.push(empirical_case_json("variant-3", "variant", vec![0xfb]));
        cases.push(empirical_case_json("variant-4", "variant", vec![0xf7]));
        let too_many_ref = store
            .put_json(crate::content_store::ObjectKind::ProofSnapshot, &too_many)
            .unwrap();
        assert!(load_empirical_reproducer(workspace.root(), &too_many_ref).is_err());

        let mut oversized = base;
        oversized["cases"][0]["payload"] =
            serde_json::to_value(vec![0xff; MAX_EMPIRICAL_CASE_BYTES + 1]).unwrap();
        let oversized_ref = store
            .put_json(crate::content_store::ObjectKind::ProofSnapshot, &oversized)
            .unwrap();
        assert!(load_empirical_reproducer(workspace.root(), &oversized_ref).is_err());
    }

    fn empirical_case_json(id: &str, kind: &str, payload: Vec<u8>) -> Value {
        let vulnerable = if kind == "benign_control" {
            "clean_exit"
        } else {
            "exploited"
        };
        serde_json::json!({
            "id": id,
            "kind": kind,
            "payload": payload,
            "oracle": {"vulnerable": vulnerable, "patched": "clean_exit"}
        })
    }

    #[test]
    fn unavailable_source_identity_cannot_produce_runtime_proof() {
        let mut outcome = VerificationOutcome {
            proof_level: 4,
            proof_verdict: ProofVerdict::Exploited,
            backend: SandboxBackend::Bwrap,
            language: Some("rust".to_string()),
            harness_path: None,
            crash_evidence: None,
            duration_ms: 1,
            cost_usd: 0.0,
            notes: Vec::new(),
            provenance: Some(crate::findings::VerificationProvenance {
                source_identity: crate::workflow_attempts::TargetContentIdentity::Unavailable {
                    reason: crate::run_lifecycle::SafeText::operator_visible("capture failed"),
                },
                reproducer: Some(crate::content_store::ObjectRef {
                    kind: crate::content_store::ObjectKind::ProofSnapshot,
                    hash: crate::identity::Blake3Hash::new("d".repeat(64)).unwrap(),
                    size_bytes: 1,
                }),
            }),
        };

        enforce_empirical_provenance(&mut outcome);

        assert_eq!(outcome.proof_level, 1);
        assert_eq!(outcome.proof_verdict, ProofVerdict::InfrastructureError);
    }

    #[test]
    fn podman_without_an_image_contract_cannot_produce_runtime_proof() {
        let mut outcome = VerificationOutcome {
            proof_level: 4,
            proof_verdict: ProofVerdict::Exploited,
            backend: SandboxBackend::Podman,
            language: Some("rust".to_string()),
            harness_path: None,
            crash_evidence: None,
            duration_ms: 1,
            cost_usd: 0.0,
            notes: Vec::new(),
            provenance: Some(crate::findings::VerificationProvenance {
                source_identity:
                    crate::workflow_attempts::TargetContentIdentity::IndexedSnapshot {
                        snapshot_hash: crate::run_lifecycle::SafeText::operator_visible(
                            "a".repeat(64),
                        ),
                        tree_hash: Some(crate::run_lifecycle::SafeText::operator_visible(
                            "b".repeat(64),
                        )),
                    },
                reproducer: Some(crate::content_store::ObjectRef {
                    kind: crate::content_store::ObjectKind::ProofSnapshot,
                    hash: crate::identity::Blake3Hash::new("c".repeat(64)).unwrap(),
                    size_bytes: 1,
                }),
            }),
        };

        enforce_empirical_provenance(&mut outcome);

        assert_eq!(outcome.proof_level, 1);
        assert_eq!(outcome.proof_verdict, ProofVerdict::InfrastructureError);
    }

    #[test]
    fn outcome_to_persisted_redacts_and_bounds_runtime_evidence() {
        let mut outcome = VerificationOutcome::unsupported(SandboxBackend::Bwrap, "rust");
        outcome.crash_evidence = Some(format!(
            "api_key=secret-token-value-1234567890\n{}",
            "x".repeat(20 * 1024)
        ));

        let evidence = outcome.to_persisted().crash_evidence.unwrap();

        assert!(!evidence.contains("secret-token-value"));
        assert!(evidence.contains("[REDACTED]"));
        assert!(evidence.contains("evidence truncated"));
        assert!(evidence.chars().count() < 17 * 1024);
    }

    #[test]
    fn outcome_to_persisted_maps_all_verdicts() {
        for (v, expected) in [
            (
                ProofVerdict::NotAttempted,
                PersistedProofVerdict::NotAttempted,
            ),
            (ProofVerdict::Exploited, PersistedProofVerdict::Exploited),
            (
                ProofVerdict::NotReproduced,
                PersistedProofVerdict::NotReproduced,
            ),
            (
                ProofVerdict::HarnessFailedToBuild,
                PersistedProofVerdict::HarnessFailedToBuild,
            ),
            (
                ProofVerdict::InfrastructureError,
                PersistedProofVerdict::InfrastructureError,
            ),
            (
                ProofVerdict::LanguageUnsupportedYet,
                PersistedProofVerdict::LanguageUnsupportedYet,
            ),
            (
                ProofVerdict::InsufficientFindingDetail,
                PersistedProofVerdict::InsufficientFindingDetail,
            ),
        ] {
            let mut o = VerificationOutcome::unsupported(SandboxBackend::Plain, "rs");
            o.proof_verdict = v;
            assert_eq!(o.to_persisted().proof_verdict, expected);
        }
    }

    #[test]
    fn persisted_proof_verdict_string_round_trip() {
        for v in [
            PersistedProofVerdict::NotAttempted,
            PersistedProofVerdict::Exploited,
            PersistedProofVerdict::NotReproduced,
            PersistedProofVerdict::HarnessFailedToBuild,
            PersistedProofVerdict::InfrastructureError,
            PersistedProofVerdict::LanguageUnsupportedYet,
            PersistedProofVerdict::InsufficientFindingDetail,
        ] {
            assert_eq!(PersistedProofVerdict::from_str(v.as_str()), Some(v));
        }
        assert_eq!(PersistedProofVerdict::from_str("garbage"), None);
    }

    #[test]
    fn persisted_sandbox_backend_string_round_trip() {
        for b in [
            PersistedSandboxBackend::Bwrap,
            PersistedSandboxBackend::Podman,
            PersistedSandboxBackend::Plain,
            PersistedSandboxBackend::Model,
        ] {
            assert_eq!(PersistedSandboxBackend::from_str(b.as_str()), Some(b));
        }
        assert_eq!(PersistedSandboxBackend::from_str("nope"), None);
    }

    // ----- multi-language harness scaffolding ----------------------

    #[tokio::test]
    async fn scaffold_c_project_writes_trigger_and_target() {
        let (workspace, finding) = finding_in_workspace(
            "src/x.c",
            "#include <stdint.h>\n#include <stddef.h>\nvoid parse(const uint8_t *data, size_t len) { (void)data; (void)len; }\n",
        );
        let project = scaffold_c_project(&finding, CCompiler::Gcc, workspace.path())
            .await
            .unwrap();
        let trigger = std::fs::read_to_string(project.path.join("trigger.c")).unwrap();
        let target = std::fs::read_to_string(project.path.join("target.c")).unwrap();
        assert!(trigger.contains("kuzushi_verify_call_target"));
        assert!(trigger.contains("0xff")); // payload bytes
        assert!(target.contains("kuzushi_verify_call_target"));
    }

    // ----- C signature parsing -------------------------------------

    #[test]
    fn parse_c_signature_extracts_name_and_arg_types() {
        let sig = parse_c_signature("static int parse_packet(const char *p, size_t n) {")
            .expect("should parse");
        assert_eq!(sig.fn_name, "parse_packet");
        assert_eq!(sig.return_type.as_deref(), Some("static int"));
        assert_eq!(sig.args.len(), 2);
        assert!(sig.args[0].contains("const char"));
        assert!(sig.args[1].contains("size_t"));
    }

    #[test]
    fn parse_c_signature_handles_void_return_and_zero_args() {
        let sig = parse_c_signature("void shutdown_handler(void)").expect("should parse");
        assert_eq!(sig.fn_name, "shutdown_handler");
        assert_eq!(sig.return_type.as_deref(), Some("void"));
        assert!(sig.args.is_empty(), "void argument list should be empty");
    }

    #[test]
    fn parse_c_signature_strips_trailing_open_brace() {
        let sig = parse_c_signature("int recv_msg(int fd) {").expect("should parse");
        assert_eq!(sig.fn_name, "recv_msg");
    }

    #[test]
    fn parse_c_signature_handles_pointer_return() {
        let sig = parse_c_signature("static char *str_dup(const char *src)").expect("should parse");
        assert_eq!(sig.fn_name, "str_dup");
        assert!(sig.return_type.as_deref().unwrap().contains("char"));
    }

    #[test]
    fn parse_c_signature_rejects_control_flow() {
        assert!(parse_c_signature("if (x > 0) {").is_none());
        assert!(parse_c_signature("while (cur != NULL)").is_none());
        assert!(parse_c_signature("switch (kind) {").is_none());
    }

    #[test]
    fn parse_c_signature_rejects_comments_and_macros() {
        assert!(parse_c_signature("// comment").is_none());
        assert!(parse_c_signature("#include <stdio.h>").is_none());
        assert!(parse_c_signature("/* block */").is_none());
    }

    #[test]
    fn parse_c_signature_rejects_call_sites() {
        // A call has no return type before the name and our heuristic
        // requires whitespace in the head — confirm `foo(x);` doesn't
        // get misread as a definition.
        let head_only = parse_c_signature("foo(x)");
        // Single-token head: either parsed as function with empty
        // return type (which we'd also accept) or rejected. The
        // contract that matters for build_c_trigger: don't synthesize
        // a call when there's no return type — covered by
        // plan_c_call_expression's behaviour.
        if let Some(sig) = head_only {
            assert_eq!(sig.fn_name, "foo");
            assert!(sig.return_type.is_none());
        }
    }

    // ----- C call-plan synthesis -----------------------------------

    #[test]
    fn plan_c_call_zero_args() {
        let sig = parse_c_signature("void run(void)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("run()"));
        assert!(plan.call_kind.contains("zero-argument"));
    }

    #[test]
    fn plan_c_call_const_uint8_ptr_single_arg() {
        let sig = parse_c_signature("int parse(const uint8_t *buf)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(plan
            .call_expression
            .contains("parse((const uint8_t *)data)"));
    }

    #[test]
    fn plan_c_call_size_t_single_arg() {
        let sig = parse_c_signature("int handle(size_t n)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("handle(len)"));
    }

    #[test]
    fn plan_c_call_buf_len_pair() {
        let sig = parse_c_signature("void copy(const uint8_t *src, size_t len)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(plan
            .call_expression
            .contains("copy((const uint8_t *)data, len)"));
        assert_eq!(plan.call_kind, "(buf, len) C-FFI-style call");
    }

    #[test]
    fn plan_c_call_const_char_ptr_buf_with_int_len() {
        let sig = parse_c_signature("int strn_dup(const char *p, int n)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(plan
            .call_expression
            .contains("strn_dup((const char *)data, (int)len)"));
    }

    #[test]
    fn plan_c_call_returns_none_for_unsupported_signatures() {
        let sig = parse_c_signature("int complex(struct timeval *t, double f)").unwrap();
        assert!(plan_c_call_expression(&sig).is_none());
    }

    #[test]
    fn plan_c_call_uses_void_cast_when_return_type_present() {
        let sig = parse_c_signature("int parse(const uint8_t *p)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("(void)parse"));
    }

    #[test]
    fn plan_c_call_does_not_void_cast_for_void_return() {
        let sig = parse_c_signature("void parse(const uint8_t *p)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(!plan.call_expression.contains("(void)parse"));
        assert!(plan
            .call_expression
            .contains("parse((const uint8_t *)data)"));
    }

    // ----- C self-contained heuristic ------------------------------

    #[test]
    fn c_self_contained_accepts_system_includes() {
        let src = "#include <stdint.h>\n#include <stddef.h>\nvoid foo(void) {}\n";
        assert!(c_source_appears_self_contained(src));
    }

    #[test]
    fn c_self_contained_rejects_project_includes() {
        let src = "#include \"private.h\"\nvoid foo(void) {}\n";
        assert!(!c_source_appears_self_contained(src));
    }

    #[test]
    fn c_self_contained_accepts_no_includes() {
        let src = "void foo(void) { return; }\n";
        assert!(c_source_appears_self_contained(src));
    }

    // ----- end-to-end harness shape --------------------------------

    #[tokio::test]
    async fn scaffold_c_project_wires_trampoline_when_source_self_contained() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vuln.c");
        std::fs::write(
            &path,
            "#include <stdint.h>\n#include <string.h>\n\
             void copy_attacker(const uint8_t *src, size_t len) {\n\
                 char dest[16];\n\
                 memcpy(dest, src, len);\n\
                 (void)dest;\n\
             }\n",
        )
        .unwrap();
        let mut finding = finding_for(path.to_str().unwrap());
        finding.start_line = 4;
        let project = scaffold_c_project(&finding, CCompiler::Gcc, tmp.path())
            .await
            .unwrap();

        let target = std::fs::read_to_string(project.path.join("target.c")).unwrap();
        assert!(target.contains("#include \"suspect_source.c\""));
        assert!(target.contains("copy_attacker((const uint8_t *)data, len)"));
        assert!(target.contains("kuzushi_verify_mark_sink_reached();"));
        assert_eq!(project.fidelity, HarnessFidelity::Faithful);
        let suspect_path = project.path.join("suspect_source.c");
        assert!(
            suspect_path.exists(),
            "trampoline path should write suspect_source.c"
        );
        let suspect_src = std::fs::read_to_string(suspect_path).unwrap();
        assert!(suspect_src.contains("copy_attacker"));
    }

    #[tokio::test]
    async fn scaffold_c_project_falls_back_when_source_not_self_contained() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vuln.c");
        std::fs::write(
            &path,
            "#include \"private.h\"\nvoid foo(const uint8_t *p, size_t n) { (void)p; (void)n; }\n",
        )
        .unwrap();
        let mut finding = finding_for(path.to_str().unwrap());
        finding.start_line = 2;
        let project = scaffold_c_project(&finding, CCompiler::Gcc, tmp.path())
            .await
            .unwrap();

        let target = std::fs::read_to_string(project.path.join("target.c")).unwrap();
        // Fallback stub keeps the no-op body.
        assert!(target.contains("(void)data;"));
        assert_eq!(project.fidelity, HarnessFidelity::PayloadOnly);
        assert!(!project.path.join("suspect_source.c").exists());
    }

    #[test]
    fn build_c_trigger_rejects_source_outside_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "void outside(void) {}\n").unwrap();
        let mut finding = finding_for(outside.path().to_str().unwrap());
        finding.start_line = 99;
        let error = build_c_trigger(&finding, workspace.path()).unwrap_err();
        assert!(error.to_string().contains("inside workspace"));
    }

    // ----- sanitizer-stderr detection ------------------------------

    #[test]
    fn stderr_detector_recognises_asan_stack_buffer_overflow() {
        let stderr = "==123==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f...";
        assert!(stderr_has_sanitizer_crash(stderr));
    }

    #[test]
    fn stderr_detector_recognises_ubsan_runtime_error() {
        let stderr = "runtime error: signed integer overflow: ...";
        assert!(stderr_has_sanitizer_crash(stderr));
    }

    #[test]
    fn stderr_detector_recognises_use_after_free() {
        assert!(stderr_has_sanitizer_crash(
            "AddressSanitizer: heap-use-after-free on address 0x..."
        ));
        assert!(stderr_has_sanitizer_crash("==1==ERROR: use-after-free"));
    }

    #[test]
    fn stderr_detector_ignores_clean_output() {
        assert!(!stderr_has_sanitizer_crash(""));
        assert!(!stderr_has_sanitizer_crash(
            "clean stderr output\nno errors here\n"
        ));
        assert!(!stderr_has_sanitizer_crash("Compiled with -Wall -Werror"));
    }

    #[test]
    fn classify_promotes_to_4_on_marker_backed_asan_output() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(sink_marker_path(project.path()), SINK_MARKER_CONTENT).unwrap();
        let mut result = sandbox_result(ExitOutcome::Exited, Some(1), None);
        result.stderr =
            "==99==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...".to_string();
        let outcome = classify_run_result(
            &result,
            SandboxBackend::Bwrap,
            project.path(),
            HarnessFidelity::Faithful,
        );
        assert_eq!(outcome.proof_level, 4);
        assert_eq!(outcome.proof_verdict, ProofVerdict::Exploited);
    }

    #[test]
    fn sink_marker_preparation_deletes_only_stale_regular_marker() {
        let project = tempfile::tempdir().unwrap();
        let marker = sink_marker_path(project.path());
        std::fs::write(&marker, "stale").unwrap();

        prepare_sink_marker(project.path()).unwrap();

        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn sink_marker_preparation_rejects_stale_symlink() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let marker = sink_marker_path(project.path());
        symlink(outside.path(), &marker).unwrap();

        let error = prepare_sink_marker(project.path()).unwrap_err().to_string();

        assert!(error.contains("non-regular stale sink marker"));
        assert!(marker.symlink_metadata().is_ok());
    }

    #[tokio::test]
    async fn scaffold_python_project_writes_runnable_module() {
        let finding = finding_for("src/x.py");
        let project = scaffold_python_project(&finding).await.unwrap();
        let body = std::fs::read_to_string(project.path.join("trigger.py")).unwrap();
        assert!(body.contains("def trigger"));
        assert!(body.contains("test_trigger"));
        assert!(body.contains("PAYLOAD = bytes("));
    }

    #[tokio::test]
    async fn scaffold_node_project_writes_runnable_script() {
        let finding = finding_for("src/x.js");
        let project = scaffold_node_project(&finding, "js").await.unwrap();
        let body = std::fs::read_to_string(project.path.join("trigger.js")).unwrap();
        assert!(body.contains("Uint8Array.from"));
        assert!(body.contains("function trigger"));
        assert!(body.contains("process.exit(0)"));
    }

    #[test]
    fn node_runner_metadata_tracks_extension_and_script_name() {
        assert!(is_typescript_extension("tsx"));
        assert!(!is_typescript_extension("js"));

        let ts = NodeRunner {
            argv: vec!["tsx".to_string()],
            typescript: true,
        };
        let js = NodeRunner {
            argv: vec!["node".to_string()],
            typescript: false,
        };
        assert_eq!(ts.trigger_name(), "trigger.ts");
        assert_eq!(js.trigger_name(), "trigger.js");
        assert!(missing_node_runner(SandboxBackend::Plain, "ts")
            .crash_evidence
            .unwrap()
            .contains("JS/TS runner"));
    }

    #[test]
    fn c_compiler_availability_prefers_asan_then_present_toolchain() {
        let availability = CCompilerAvailability {
            preferred: "clang",
            fallback: "gcc",
            preferred_present: true,
            fallback_present: true,
            preferred_has_asan: false,
            fallback_has_asan: true,
        };
        assert_eq!(availability.pick().as_deref(), Some("gcc"));

        let availability = CCompilerAvailability {
            preferred_has_asan: false,
            fallback_has_asan: false,
            ..availability
        };
        assert_eq!(availability.pick().as_deref(), Some("clang"));

        let availability = CCompilerAvailability {
            preferred_present: false,
            fallback_present: false,
            ..availability
        };
        assert_eq!(availability.pick(), None);
    }

    // ----- new language paths return BackendUnavailable when no toolchain

    #[tokio::test]
    async fn verify_node_placeholder_ignores_runner_availability() {
        let (workspace, finding) = finding_in_workspace(
            "src/x.js",
            "export function parse(value) { return value; }\n",
        );
        let outcome = verify_finding(&finding, VerifyOptions::default(), workspace.path())
            .await
            .unwrap();
        assert_eq!(outcome.proof_verdict, ProofVerdict::NotAttempted);
        assert!(outcome.crash_evidence.is_none());
    }

    #[tokio::test]
    async fn verify_c_reports_infrastructure_error_when_no_compiler() {
        if kuzushi_sandbox::which("clang").is_some() || kuzushi_sandbox::which("gcc").is_some() {
            return;
        }
        let (workspace, mut finding) = finding_in_workspace("src/x.c", "void parse(void) {}\n");
        finding.start_line = 1;
        let source_identity = capture_verification_source_identity(workspace.path()).unwrap();
        let outcome = verify_c_like(
            &finding,
            SandboxBackend::Bwrap,
            &VerifyOptions::default(),
            CCompiler::Gcc,
            workspace.path(),
            &source_identity,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.proof_verdict, ProofVerdict::InfrastructureError);
    }

    // ----- harness body is shaped by extracted signature -----------

    #[test]
    fn build_rust_trigger_embeds_located_signature_in_comment() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lib.rs");
        std::fs::write(
            &path,
            "pub fn parse(p: &[u8]) -> u32 {\n    let _ = p;\n    0\n}\n",
        )
        .unwrap();
        let mut finding = finding_for(path.to_str().unwrap());
        finding.start_line = 2;
        let trigger = build_rust_trigger(&finding, tmp.path()).unwrap();
        // Either the located-function header or the synthesized-call
        // header should appear; both name the function.
        assert!(trigger.trigger_test.contains("parse"));
        assert!(
            trigger.trigger_test.contains("Suspect:")
                || trigger.trigger_test.contains("Located enclosing function")
        );
    }

    #[test]
    fn build_rust_trigger_rejects_source_outside_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "pub fn outside() {}\n").unwrap();
        let mut finding = finding_for(outside.path().to_str().unwrap());
        finding.start_line = 99;
        let error = build_rust_trigger(&finding, workspace.path()).unwrap_err();
        assert!(error.to_string().contains("inside workspace"));
    }

    #[test]
    fn build_rust_trigger_resolves_relative_source_from_explicit_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(workspace.path().join("src")).unwrap();
        std::fs::write(
            workspace.path().join("src/lib.rs"),
            "pub fn parse(input: &[u8]) -> usize { input.len() }\n",
        )
        .unwrap();
        let finding = finding_for("src/lib.rs");

        let trigger = build_rust_trigger(&finding, workspace.path()).unwrap();

        assert!(trigger.trigger_test.contains("suspect::parse"));
    }

    #[test]
    fn build_rust_trigger_rejects_parent_traversal() {
        let parent = tempfile::tempdir().unwrap();
        let workspace = parent.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(parent.path().join("outside.rs"), "pub fn outside() {}\n").unwrap();
        let finding = finding_for("../outside.rs");

        let error = build_rust_trigger(&finding, &workspace).unwrap_err();

        assert!(error.to_string().contains("inside workspace"));
    }

    #[cfg(unix)]
    #[test]
    fn build_rust_trigger_rejects_symlinked_source() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let workspace = parent.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let outside = parent.path().join("outside.rs");
        std::fs::write(&outside, "pub fn outside() {}\n").unwrap();
        symlink(&outside, workspace.join("linked.rs")).unwrap();
        let finding = finding_for("linked.rs");

        let error = build_rust_trigger(&finding, &workspace).unwrap_err();

        assert!(error.to_string().contains("inside workspace"));
    }

    #[test]
    fn build_rust_trigger_reports_oversized_source() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("large.rs");
        std::fs::File::create(&source)
            .unwrap()
            .set_len(8 * 1024 * 1024 + 1)
            .unwrap();
        let finding = finding_for("large.rs");

        let error = build_rust_trigger(&finding, workspace.path()).unwrap_err();

        assert!(error.to_string().contains("inside workspace"));
    }

    // ----- Rust signature parsing ----------------------------------

    #[test]
    fn parse_rust_signature_extracts_name_and_arg_types() {
        let sig = parse_rust_signature("pub fn parse_packet(input: &[u8], n: usize) -> u32 {")
            .expect("should parse");
        assert_eq!(sig.fn_name, "parse_packet");
        assert_eq!(sig.args, vec!["&[u8]".to_string(), "usize".to_string()]);
        assert_eq!(sig.return_type.as_deref(), Some("u32"));
    }

    #[test]
    fn parse_rust_signature_handles_zero_args() {
        let sig = parse_rust_signature("fn run() {").expect("should parse");
        assert_eq!(sig.fn_name, "run");
        assert!(sig.args.is_empty());
        assert!(sig.return_type.is_none());
    }

    #[test]
    fn parse_rust_signature_handles_generics() {
        let sig =
            parse_rust_signature("pub async fn decode<T: AsRef<[u8]>>(input: T) -> Result<u32, E>")
                .expect("should parse");
        assert_eq!(sig.fn_name, "decode");
        assert_eq!(sig.args, vec!["T".to_string()]);
    }

    #[test]
    fn parse_rust_signature_skips_self_receiver() {
        let sig =
            parse_rust_signature("pub fn parse(&self, input: &[u8]) -> u32").expect("should parse");
        // self is dropped; only the &[u8] remains.
        assert_eq!(sig.args, vec!["&[u8]".to_string()]);
    }

    #[test]
    fn parse_rust_signature_handles_nested_tuple_arg() {
        let sig =
            parse_rust_signature("fn pair(input: (u8, u8), bytes: &[u8])").expect("should parse");
        assert_eq!(sig.args, vec!["(u8, u8)".to_string(), "&[u8]".to_string()]);
    }

    #[test]
    fn parse_rust_signature_returns_none_for_non_function() {
        assert!(parse_rust_signature("if foo { bar }").is_none());
        assert!(parse_rust_signature("struct S { ... }").is_none());
    }

    // ----- call-plan synthesis -------------------------------------

    #[test]
    fn plan_call_zero_args() {
        let sig = parse_rust_signature("fn run()").unwrap();
        let plan = plan_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("suspect::run()"));
        assert!(plan.call_kind.contains("zero-argument"));
    }

    #[test]
    fn plan_call_byte_slice_arg() {
        let sig = parse_rust_signature("fn parse(input: &[u8])").unwrap();
        let plan = plan_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("suspect::parse(&payload)"));
    }

    #[test]
    fn plan_call_buf_len_pair_synthesizes_c_ffi_call() {
        let sig = parse_rust_signature("fn copy(buf: &[u8], len: usize)").unwrap();
        let plan = plan_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("&payload, payload.len()"));
        assert_eq!(plan.call_kind, "(buf, len) C-FFI-style call");
    }

    #[test]
    fn plan_call_raw_pointer_buf_uses_as_ptr() {
        let sig = parse_rust_signature("fn read(buf: *const u8, len: usize)").unwrap();
        let plan = plan_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("payload.as_ptr()"));
    }

    #[test]
    fn plan_call_returns_none_for_unsupported_signatures() {
        let sig = parse_rust_signature("fn complex(a: u32, b: f64, c: &MyStruct)").unwrap();
        assert!(plan_call_expression(&sig).is_none());
    }

    #[test]
    fn plan_call_uses_let_binding_when_return_type_present() {
        let sig = parse_rust_signature("fn parse(input: &[u8]) -> u32").unwrap();
        let plan = plan_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("let _ ="));
    }

    // ----- self-contained source heuristic --------------------------

    #[test]
    fn self_contained_accepts_simple_file() {
        let src = "use std::ops::Range;\npub fn f() {}";
        assert!(rust_source_appears_self_contained(src));
    }

    #[test]
    fn self_contained_rejects_extern_crate() {
        let src = "extern crate libc;\npub fn f() {}";
        assert!(!rust_source_appears_self_contained(src));
    }

    #[test]
    fn self_contained_rejects_crate_relative_use() {
        let src = "use crate::other::T;\npub fn f() {}";
        assert!(!rust_source_appears_self_contained(src));
    }

    #[test]
    fn self_contained_rejects_non_std_derive() {
        let src = "#[derive(serde::Serialize)]\npub struct S;";
        assert!(!rust_source_appears_self_contained(src));
    }

    #[test]
    fn self_contained_accepts_std_derives() {
        let src = "#[derive(Debug, Clone, PartialEq)]\npub struct S;";
        assert!(rust_source_appears_self_contained(src));
    }

    // ----- end-to-end harness shape ---------------------------------

    #[tokio::test]
    async fn scaffolder_writes_suspect_rs_when_source_is_self_contained() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lib.rs");
        std::fs::write(
            &path,
            "pub fn parse(input: &[u8]) -> usize { input.len() }\n",
        )
        .unwrap();
        let mut finding = finding_for(path.to_str().unwrap());
        finding.start_line = 1;
        let trigger = build_rust_trigger(&finding, tmp.path()).unwrap();
        assert!(trigger.suspect_source.is_some());
        let project = scaffold_rust_project(&trigger).await.unwrap();
        let suspect = std::fs::read_to_string(project.path.join("src").join("suspect.rs")).unwrap();
        assert!(suspect.contains("pub fn parse"));
        let lib = std::fs::read_to_string(project.path.join("src").join("lib.rs")).unwrap();
        assert!(lib.contains("pub mod suspect"));
        let test = std::fs::read_to_string(project.path.join("tests").join("trigger.rs")).unwrap();
        assert!(test.contains("suspect::parse(&payload)"));
        assert!(test.contains("kuzushi_verify_mark_sink_reached();"));
        assert_eq!(project.fidelity, HarnessFidelity::Faithful);
    }

    #[test]
    fn build_rust_trigger_skips_sink_call_for_non_self_contained_source() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lib.rs");
        std::fs::write(
            &path,
            "use crate::other::Helper;\npub fn parse(input: &[u8]) {}\n",
        )
        .unwrap();
        let mut finding = finding_for(path.to_str().unwrap());
        finding.start_line = 2;
        let trigger = build_rust_trigger(&finding, tmp.path()).unwrap();
        // No sink call — payload-only fallback because the file uses
        // `crate::` paths.
        assert!(trigger.trigger_test.contains("Payload-only harness"));
        assert_eq!(trigger.fidelity, HarnessFidelity::PayloadOnly);
    }

    #[tokio::test]
    async fn payload_only_rust_and_c_harnesses_stop_before_compile_or_run() {
        let (rust_workspace, mut rust_finding) = finding_in_workspace(
            "src/lib.rs",
            "use crate::other::Helper;\npub fn parse(input: &[u8]) { let _ = input; }\n",
        );
        rust_finding.start_line = 2;
        let rust_source_identity =
            capture_verification_source_identity(rust_workspace.path()).unwrap();
        let rust = verify_rust(
            &rust_finding,
            SandboxBackend::Bwrap,
            &VerifyOptions::default(),
            rust_workspace.path(),
            &rust_source_identity,
            None,
        )
        .await
        .unwrap();

        let (c_workspace, mut c_finding) = finding_in_workspace(
            "src/x.c",
            "#include \"private.h\"\nvoid parse(const uint8_t *p, size_t n) { (void)p; (void)n; }\n",
        );
        c_finding.start_line = 2;
        let c_source_identity = capture_verification_source_identity(c_workspace.path()).unwrap();
        let c = verify_c_like(
            &c_finding,
            SandboxBackend::Bwrap,
            &VerifyOptions::default(),
            CCompiler::Gcc,
            c_workspace.path(),
            &c_source_identity,
            None,
        )
        .await
        .unwrap();

        for (language, outcome) in [("rust", rust), ("c", c)] {
            assert_eq!(
                outcome.proof_verdict,
                ProofVerdict::NotAttempted,
                "{language}"
            );
            assert_eq!(outcome.duration_ms, 0, "{language}");
            assert!(
                outcome
                    .notes
                    .iter()
                    .any(|note| note.contains("payload-only")),
                "{language}"
            );
        }
    }
}
