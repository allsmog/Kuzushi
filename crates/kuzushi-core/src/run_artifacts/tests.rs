#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::artifact_contract::{
        CANONICAL_RUN_ARTIFACTS, OPTIONAL_RUN_ARTIFACTS, SCAN_PIPELINE_ARTIFACTS,
        TOOL_INPUT_ARTIFACTS, TOOL_RESULT_ARTIFACTS,
    };
    use crate::runtime::{RuntimeCost, RuntimeCostReport};
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use std::process::Command;
    use std::sync::{Arc, Barrier};

    fn relative_run_artifact_path(target: &Path, run_id: &str, leaf: &str) -> String {
        run_artifact_path(target, run_id, leaf)
            .strip_prefix(target)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/")
    }

    fn representative_run_artifact_path(run_id: &str, leaf: &str) -> String {
        relative_run_artifact_path(Path::new("workspace"), run_id, leaf)
    }

    #[test]
    fn run_ids_and_artifact_paths_reject_traversal() {
        assert!(RunId::parse("../outside").is_err());
        assert!(RunId::parse("run/child").is_err());
        assert!(ArtifactPath::parse("../outside.json").is_err());
        assert!(ArtifactPath::parse("/outside.json").is_err());

        let tmp = tempfile::tempdir().unwrap();
        assert!(write_run_artifact_json(
            tmp.path(),
            "run-safe",
            "../outside.json",
            "outside",
            &serde_json::json!({"unsafe": true}),
        )
        .is_err());
        assert!(!tmp.path().join(".kuzushi/v3/runs/outside.json").exists());
    }

    #[test]
    fn typed_run_artifact_reader_reports_ready_missing_and_non_file_states() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-artifact-reader";
        let artifact = run_artifact_path(tmp.path(), run_id, "nested/result.txt");
        fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        fs::write(&artifact, "evidence").unwrap();

        assert!(matches!(
            read_run_artifact_bytes(tmp.path(), run_id, "nested/result.txt"),
            RunArtifactRead::Ready { value, .. } if value == b"evidence"
        ));
        let text = read_run_artifact_text(tmp.path(), run_id, "nested/result.txt");
        assert!(matches!(
            &text,
            RunArtifactRead::Ready { value, .. } if value == "evidence"
        ));
        let resolved = resolve_run_artifact_path(tmp.path(), run_id, "nested/result.txt").unwrap();
        assert_eq!(text.display_path(), resolved.display().to_string());
        assert!(matches!(
            read_run_artifact_text(tmp.path(), run_id, "missing.txt"),
            RunArtifactRead::Missing { .. }
        ));

        fs::create_dir_all(run_artifact_path(tmp.path(), run_id, "directory")).unwrap();
        assert!(matches!(
            read_run_artifact_text(tmp.path(), run_id, "directory"),
            RunArtifactRead::NonFile { .. }
        ));

        let controlled = run_artifact_path(tmp.path(), run_id, "line\nbreak.txt");
        fs::write(&controlled, "safe").unwrap();
        let controlled = read_run_artifact_text(tmp.path(), run_id, "line\nbreak.txt");
        assert!(controlled.display_path().contains(r"line\nbreak.txt"));
        assert!(!controlled.display_path().contains('\n'));
    }

    #[test]
    fn typed_run_artifact_reader_rejects_run_and_artifact_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside.txt");
        fs::write(&outside, "secret").unwrap();

        let invalid_run = read_run_artifact_text(tmp.path(), "../outside", "outside.txt");
        let invalid_artifact = read_run_artifact_text(tmp.path(), "run-safe", "../../outside.txt");

        assert!(matches!(&invalid_run, RunArtifactRead::Unsafe { .. }));
        assert!(matches!(invalid_artifact, RunArtifactRead::Unsafe { .. }));
        assert_eq!(invalid_run.display_path(), "<unsafe run artifact path>");
        assert_eq!(fs::read_to_string(outside).unwrap(), "secret");
    }

    #[cfg(unix)]
    #[test]
    fn typed_run_artifact_reader_rejects_symlink_without_reading_target() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-symlink-reader";
        let outside = tmp.path().join("outside.txt");
        fs::write(&outside, "secret").unwrap();
        let artifact = run_artifact_path(tmp.path(), run_id, "result.txt");
        fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        symlink(&outside, &artifact).unwrap();

        let state = read_run_artifact_text(tmp.path(), run_id, "result.txt");

        assert!(matches!(state, RunArtifactRead::Unsafe { .. }));
        assert_eq!(fs::read_to_string(outside).unwrap(), "secret");
    }

    #[test]
    fn typed_run_artifact_text_reader_reports_invalid_utf8_as_unreadable() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-invalid-text";
        let artifact = run_artifact_path(tmp.path(), run_id, "result.bin");
        fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        fs::write(artifact, [0xff, 0xfe]).unwrap();

        assert!(matches!(
            read_run_artifact_text(tmp.path(), run_id, "result.bin"),
            RunArtifactRead::Unreadable { error, .. }
                if error.contains("not valid UTF-8")
        ));
    }

    #[test]
    fn typed_run_artifact_reader_refuses_oversized_files_before_allocating() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-oversized-artifact";
        let artifact = run_artifact_path(tmp.path(), run_id, "oversized.bin");
        fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        fs::File::create(artifact)
            .unwrap()
            .set_len(MAX_RUN_ARTIFACT_READ_BYTES + 1)
            .unwrap();

        assert!(matches!(
            read_run_artifact_bytes(tmp.path(), run_id, "oversized.bin"),
            RunArtifactRead::Unreadable { error, .. } if error.contains("read limit")
        ));
    }

    #[test]
    fn manifest_reader_rejects_declared_artifacts_outside_target() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-escaped-manifest";
        let manifest = run_artifact_path(tmp.path(), run_id, "artifacts.json");
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(
            manifest,
            serde_json::to_string(&serde_json::json!({
                "runId": run_id,
                "artifacts": [{"label": "escape", "path": "/etc/passwd", "kind": "json"}]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();

        assert!(error.to_string().contains("escapes target"));
    }

    #[cfg(unix)]
    #[test]
    fn manifest_reader_rejects_symlinked_known_artifact_even_when_omitted() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let run_id = "run-known-symlink";
        let manifest = run_artifact_path(target.path(), run_id, "artifacts.json");
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(
            &manifest,
            serde_json::to_string(&serde_json::json!({
                "runId": run_id,
                "artifacts": []
            }))
            .unwrap(),
        )
        .unwrap();
        let secret = outside.path().join("secret.json");
        fs::write(&secret, "secret").unwrap();
        symlink(
            &secret,
            run_artifact_path(target.path(), run_id, "result.json"),
        )
        .unwrap();

        let error = load_run_artifacts(target.path(), run_id).unwrap_err();

        assert!(error.to_string().contains("must not be a symlink"));
        assert_eq!(fs::read_to_string(secret).unwrap(), "secret");
    }

    #[cfg(unix)]
    #[test]
    fn manifest_reader_rejects_absolute_artifact_below_symlinked_parent() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let run_id = "run-parent-symlink";
        let real_dir = target.path().join("real-artifacts");
        fs::create_dir(&real_dir).unwrap();
        fs::write(real_dir.join("report.json"), "{}").unwrap();
        let linked_dir = target.path().join("linked-artifacts");
        symlink(&real_dir, &linked_dir).unwrap();
        let declared_path = linked_dir.join("report.json");
        let manifest = run_artifact_path(target.path(), run_id, "artifacts.json");
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(
            &manifest,
            serde_json::to_string(&serde_json::json!({
                "runId": run_id,
                "artifacts": [{
                    "label": "report",
                    "path": declared_path,
                    "kind": "json"
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(target.path(), run_id).unwrap_err();

        assert!(error.to_string().contains("must not be a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn run_writes_reject_symlinked_workspace_state() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), tmp.path().join(".kuzushi")).unwrap();

        let error = write_run_summary(
            tmp.path(),
            &RunSummary::running("run-safe", "tool", None, "target"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("must not be a symlink"));
        assert!(!outside.path().join("v3/runs/run-safe/run.json").exists());
    }

    #[test]
    fn summary_entries_preserve_invalid_state_as_explicit_issues() {
        let tmp = tempfile::tempdir().unwrap();
        let runs = runs_root(tmp.path());
        fs::create_dir_all(runs.join("run-missing")).unwrap();
        fs::write(runs.join("not-a-directory"), "bad").unwrap();
        fs::create_dir_all(runs.join("run-invalid")).unwrap();
        fs::write(runs.join("run-invalid/run.json"), "{not-json").unwrap();

        let entries = list_run_summary_entries(tmp.path()).unwrap();

        assert!(entries.iter().any(|entry| {
            entry.run_id == "run-missing"
                && matches!(
                    entry.state,
                    RunSummaryEntryState::Issue(RunSummaryIssue::MissingMetadata)
                )
        }));
        assert!(entries.iter().any(|entry| {
            entry.run_id == "not-a-directory"
                && matches!(
                    entry.state,
                    RunSummaryEntryState::Issue(RunSummaryIssue::NotDirectory)
                )
        }));
        assert!(entries.iter().any(|entry| {
            entry.run_id == "run-invalid"
                && matches!(
                    entry.state,
                    RunSummaryEntryState::Issue(RunSummaryIssue::InvalidMetadata(_))
                )
        }));
    }

    #[test]
    fn typed_latest_pointer_distinguishes_missing_ready_and_invalid_states() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            read_latest_run_pointer(tmp.path()).unwrap(),
            LatestRunPointerState::Missing
        );

        let run_id = "run-latest-typed";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", None, "target"),
        )
        .unwrap();
        assert_eq!(
            read_latest_run_pointer(tmp.path()).unwrap(),
            LatestRunPointerState::Ready(RunId::parse(run_id).unwrap())
        );

        fs::write(latest_run_path(tmp.path()), "../escape\n").unwrap();
        assert!(matches!(
            read_latest_run_pointer(tmp.path()).unwrap(),
            LatestRunPointerState::Invalid(LatestRunPointerIssue::InvalidRunId(_))
        ));
        fs::write(latest_run_path(tmp.path()), "run-missing\n").unwrap();
        assert_eq!(
            read_latest_run_pointer(tmp.path()).unwrap(),
            LatestRunPointerState::Invalid(LatestRunPointerIssue::MissingRunMetadata)
        );
    }

    #[cfg(unix)]
    #[test]
    fn typed_latest_pointer_rejects_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        fs::write(&outside, "run-outside\n").unwrap();
        let latest = latest_run_path(tmp.path());
        fs::create_dir_all(latest.parent().unwrap()).unwrap();
        symlink(&outside, &latest).unwrap();

        assert!(matches!(
            read_latest_run_pointer(tmp.path()).unwrap(),
            LatestRunPointerState::Invalid(LatestRunPointerIssue::UnsafePath(_))
        ));
        assert_eq!(fs::read_to_string(outside).unwrap(), "run-outside\n");
    }

    #[test]
    fn typed_latest_pointer_rejects_oversized_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let latest = latest_run_path(tmp.path());
        fs::create_dir_all(latest.parent().unwrap()).unwrap();
        fs::File::create(&latest)
            .unwrap()
            .set_len(1024 * 1024)
            .unwrap();

        assert!(matches!(
            read_latest_run_pointer(tmp.path()).unwrap(),
            LatestRunPointerState::Invalid(LatestRunPointerIssue::Unreadable(_))
        ));
    }

    #[test]
    fn trace_step_v2_round_trip_preserves_new_fields() {
        let step = RunTraceStep::new(7, "tool", "semgrep started")
            .with_latency_ms(Some(143))
            .with_cost_usd(Some(0.0021))
            .with_module_id("semgrep")
            .with_verb("scan")
            .with_parent_step(3)
            .with_severity("warn")
            .with_started_at_ms(1_700_000_000_000)
            .with_model_metadata("openai:gpt-test", "openai", "fnv1a64:abc123");

        let json = serde_json::to_string(&step).unwrap();
        let parsed: RunTraceStep = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed, step);
        assert!(json.contains("\"module_id\":\"semgrep\""));
        assert!(json.contains("\"parent_step\":3"));
        assert!(json.contains("\"started_at_ms\":1700000000000"));
        assert!(json.contains("\"model\":\"openai:gpt-test\""));
        assert!(json.contains("\"provider\":\"openai\""));
        assert!(json.contains("\"prompt_hash\":\"fnv1a64:abc123\""));
    }

    #[test]
    fn trace_step_v1_forward_compat_leaves_new_fields_none() {
        let v1 = "{\"n\":1,\"kind\":\"tool\",\"label\":\"context:build started\"}";
        let parsed: RunTraceStep = serde_json::from_str(v1).unwrap();

        assert_eq!(parsed.n, 1);
        assert_eq!(parsed.kind, "tool");
        assert_eq!(parsed.label, "context:build started");
        assert!(parsed.module_id.is_none());
        assert!(parsed.verb.is_none());
        assert!(parsed.parent_step.is_none());
        assert!(parsed.severity.is_none());
        assert!(parsed.started_at_ms.is_none());
        assert!(parsed.model.is_none());
        assert!(parsed.provider.is_none());
        assert!(parsed.prompt_hash.is_none());
    }

    #[test]
    fn trace_step_rejects_obsolete_camel_case_reader_aliases() {
        let json = serde_json::json!({
            "n": 4,
            "kind": "reasoning",
            "label": "query",
            "latencyMs": 25,
            "costUsd": 0.02,
            "moduleId": "triage",
            "verb": "run",
            "parentStep": 3,
            "severity": "info",
            "startedAtMs": 1_700_000_000_000u64,
            "model": "openai:gpt-test",
            "provider": "openai",
            "promptHash": "fnv1a64:abc"
        });

        let error = serde_json::from_value::<RunTraceStep>(json).unwrap_err();

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn trace_step_v2_omits_unset_optional_fields_from_serialized_form() {
        let step = RunTraceStep::new(1, "tool", "context:build started");
        let json = serde_json::to_string(&step).unwrap();

        assert!(!json.contains("module_id"));
        assert!(!json.contains("verb"));
        assert!(!json.contains("parent_step"));
        assert!(!json.contains("severity"));
        assert!(!json.contains("started_at_ms"));
        assert!(!json.contains("model"));
        assert!(!json.contains("provider"));
        assert!(!json.contains("prompt_hash"));
    }

    #[test]
    fn trace_step_can_derive_module_and_verb_from_tool_name() {
        let step =
            RunTraceStep::new(1, "tool", "semgrep:scan started").with_tool_name("semgrep:scan");

        assert_eq!(step.module_id.as_deref(), Some("semgrep"));
        assert_eq!(step.verb.as_deref(), Some("scan"));
    }

    #[test]
    fn run_event_numbering_counts_malformed_rows_and_uses_max_n() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-event-numbering";
        let events_path = run_artifact_path(tmp.path(), run_id, "events.jsonl");
        fs::create_dir_all(events_path.parent().unwrap()).unwrap();
        fs::write(
            &events_path,
            [
                r#"{"n":1,"kind":"tool","status":"started","message":"start","atUnix":1}"#,
                "",
                "not-json",
                r#"{"n":7,"kind":"tool","status":"completed","message":"done","atUnix":2}"#,
            ]
            .join("\n"),
        )
        .unwrap();

        assert_eq!(next_run_event_number(tmp.path(), run_id), 8);
    }

    #[test]
    fn run_event_numbering_advances_past_malformed_tail_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-event-malformed-tail";
        let events_path = run_artifact_path(tmp.path(), run_id, "events.jsonl");
        fs::create_dir_all(events_path.parent().unwrap()).unwrap();
        fs::write(
            &events_path,
            [
                r#"{"n":1,"kind":"tool","status":"started","message":"start","atUnix":1}"#,
                "{not-json",
            ]
            .join("\n"),
        )
        .unwrap();

        assert_eq!(next_run_event_number(tmp.path(), run_id), 3);
    }

    #[test]
    fn run_trace_numbering_advances_past_malformed_tail_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-trace-malformed-tail";
        let trace_path = run_artifact_path(tmp.path(), run_id, "trace.jsonl");
        fs::create_dir_all(trace_path.parent().unwrap()).unwrap();
        fs::write(
            &trace_path,
            [r#"{"n":1,"kind":"reasoning","label":"query"}"#, "{not-json"].join("\n"),
        )
        .unwrap();

        assert_eq!(next_run_trace_step_number(tmp.path(), run_id), 3);
    }

    #[test]
    fn trace_append_paths_reject_invalid_cost_before_write() {
        let tmp = tempfile::tempdir().unwrap();
        for (index, invalid) in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY]
            .into_iter()
            .enumerate()
        {
            let direct_id = format!("invalid-trace-direct-{index}");
            let numbered_id = format!("invalid-trace-numbered-{index}");
            let step = RunTraceStep::new(1, "reasoning", "invalid").with_cost_usd(Some(invalid));

            assert!(append_run_trace_step(tmp.path(), &direct_id, &step).is_err());
            assert!(
                append_run_trace_step_with_next_number(tmp.path(), &numbered_id, &step).is_err()
            );
            assert!(!run_artifact_path(tmp.path(), &direct_id, "trace.jsonl").exists());
            assert!(!run_artifact_path(tmp.path(), &numbered_id, "trace.jsonl").exists());
        }
    }

    #[test]
    fn trace_loaders_count_negative_cost_as_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-invalid-trace-cost";
        let trace_path = run_artifact_path(tmp.path(), run_id, "trace.jsonl");
        fs::create_dir_all(trace_path.parent().unwrap()).unwrap();
        fs::write(
            &trace_path,
            [
                r#"{"n":1,"kind":"reasoning","label":"invalid","cost_usd":-1.0,"latency_ms":1,"model":"m","provider":"p","prompt_hash":"h"}"#,
                r#"{"n":2,"kind":"reasoning","label":"valid","cost_usd":0.0,"latency_ms":1,"model":"m","provider":"p","prompt_hash":"h"}"#,
            ]
            .join("\n"),
        )
        .unwrap();

        let trace = load_run_trace(tmp.path(), run_id).unwrap();
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", None, "target").complete(),
        )
        .unwrap();
        let summary = load_run_summary(tmp.path(), run_id).unwrap();

        assert_eq!(trace.steps.len(), 1);
        assert_eq!(trace.malformed_lines, 1);
        assert_eq!(summary.llm_calls.len(), 1);
        assert_eq!(summary.trace_malformed_lines, Some(1));
    }

    #[test]
    fn typed_run_readers_report_malformed_rows_without_hiding_valid_records() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-typed-readers";
        append_run_event(
            tmp.path(),
            run_id,
            &RunEvent::new(0, "tool", "started", "start"),
        )
        .unwrap();
        append_run_trace_step_with_next_number(
            tmp.path(),
            run_id,
            &RunTraceStep::new(0, "tool", "start"),
        )
        .unwrap();
        let events_path = run_artifact_path(tmp.path(), run_id, "events.jsonl");
        let trace_path = run_artifact_path(tmp.path(), run_id, "trace.jsonl");
        fs::OpenOptions::new()
            .append(true)
            .open(events_path)
            .unwrap()
            .write_all(b"{not-json\n")
            .unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(trace_path)
            .unwrap()
            .write_all(b"[]\n")
            .unwrap();

        let events = load_run_events(tmp.path(), run_id).unwrap();
        let trace = load_run_trace(tmp.path(), run_id).unwrap();

        assert_eq!(events.events.len(), 1);
        assert_eq!(events.malformed_lines, 1);
        assert_eq!(trace.steps.len(), 1);
        assert_eq!(trace.malformed_lines, 1);
    }

    #[test]
    fn concurrent_run_event_writers_assign_unique_monotonic_numbers() {
        const WRITERS: usize = 16;
        let tmp = tempfile::tempdir().unwrap();
        let target = Arc::new(tmp.path().to_path_buf());
        let barrier = Arc::new(Barrier::new(WRITERS));
        let handles = (0..WRITERS)
            .map(|writer| {
                let target = Arc::clone(&target);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    append_run_event(
                        target.as_path(),
                        "run-concurrent-events",
                        &RunEvent::new(0, "tool", "progress", format!("writer {writer}")),
                    )
                    .unwrap();
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle.join().unwrap();
        }

        let body = fs::read_to_string(run_artifact_path(
            tmp.path(),
            "run-concurrent-events",
            "events.jsonl",
        ))
        .unwrap();
        let events = body
            .lines()
            .map(|line| serde_json::from_str::<RunEvent>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), WRITERS);
        assert_eq!(
            events.iter().map(|event| event.n).collect::<Vec<_>>(),
            (1..=WRITERS).collect::<Vec<_>>()
        );
    }

    #[test]
    fn cross_process_run_ledger_preserves_events_and_manifest_entries() {
        const CHILD_FLAG: &str = "KUZUSHI_RUN_LEDGER_CHILD";
        const ROOT: &str = "KUZUSHI_RUN_LEDGER_ROOT";
        const CHILD_ID: &str = "KUZUSHI_RUN_LEDGER_CHILD_ID";
        if std::env::var_os(CHILD_FLAG).is_some() {
            let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
            let child_id = std::env::var(CHILD_ID).unwrap();
            append_run_event(
                &root,
                "run-process-ledger",
                &RunEvent::new(0, "tool", "progress", format!("child {child_id}")),
            )
            .unwrap();
            write_run_artifact_json(
                &root,
                "run-process-ledger",
                &format!("child-{child_id}.json"),
                format!("child {child_id}"),
                &serde_json::json!({"child": child_id}),
            )
            .unwrap();
            return;
        }

        const WRITERS: usize = 4;
        let tmp = tempfile::tempdir().unwrap();
        let module = module_path!().trim_start_matches("kuzushi_core::");
        let test_name =
            format!("{module}::cross_process_run_ledger_preserves_events_and_manifest_entries");
        let executable = std::env::current_exe().unwrap();
        let children = (0..WRITERS)
            .map(|child_id| {
                Command::new(&executable)
                    .arg("--exact")
                    .arg(&test_name)
                    .arg("--nocapture")
                    .env(CHILD_FLAG, "1")
                    .env(ROOT, tmp.path())
                    .env(CHILD_ID, child_id.to_string())
                    .spawn()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }

        let events = load_run_events(tmp.path(), "run-process-ledger").unwrap();
        assert_eq!(events.malformed_lines, 0);
        assert_eq!(events.events.len(), WRITERS);
        assert_eq!(
            events
                .events
                .iter()
                .map(|event| event.n)
                .collect::<Vec<_>>(),
            (1..=WRITERS).collect::<Vec<_>>()
        );
        let manifest = load_run_artifacts(tmp.path(), "run-process-ledger").unwrap();
        for child_id in 0..WRITERS {
            assert_manifest_has(&manifest, &format!("child-{child_id}.json"));
        }
    }

    #[test]
    fn run_jsonl_numbering_advances_past_non_object_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-jsonl-non-object-tail";
        let events_path = run_artifact_path(tmp.path(), run_id, "events.jsonl");
        let trace_path = run_artifact_path(tmp.path(), run_id, "trace.jsonl");
        fs::create_dir_all(events_path.parent().unwrap()).unwrap();
        fs::write(
            &events_path,
            [
                r#"{"n":1,"kind":"tool","status":"started","message":"start","atUnix":1}"#,
                "[]",
            ]
            .join("\n"),
        )
        .unwrap();
        fs::write(
            &trace_path,
            [r#"{"n":1,"kind":"reasoning","label":"query"}"#, "[]"].join("\n"),
        )
        .unwrap();

        assert_eq!(next_run_event_number(tmp.path(), run_id), 3);
        assert_eq!(next_run_trace_step_number(tmp.path(), run_id), 3);
    }

    #[test]
    fn run_event_rejects_obsolete_tool_and_time_aliases() {
        let obsolete = serde_json::from_str::<RunEvent>(
            r#"{"n":1,"kind":"tool","status":"started","message":"ask","at_unix":1,"tool_name":"agent:ask"}"#,
        )
        .unwrap_err();
        let canonical: RunEvent = serde_json::from_str(
            r#"{"n":2,"kind":"tool","status":"completed","message":"scan","atUnix":2,"tool":"sast:scan"}"#,
        )
        .unwrap();

        assert!(obsolete.to_string().contains("unknown field `at_unix`"));
        assert_eq!(canonical.tool.as_deref(), Some("sast:scan"));
    }

    #[test]
    fn run_event_accepts_canonical_artifact_object() {
        let event: RunEvent = serde_json::from_str(
            r#"{"n":1,"kind":"tool","status":"started","message":"scan","atUnix":1,"artifact":{"label":"tool input","path":" input.json ","kind":" JSON "}}"#,
        )
        .unwrap();

        let artifact = event.artifact.as_ref().unwrap();
        assert_eq!(artifact.label, "tool input");
        assert_eq!(artifact.path, "input.json");
        assert_eq!(artifact.kind, "json");
    }

    #[test]
    fn run_event_with_artifact_normalizes_direct_artifact_values() {
        let event = RunEvent::new(1, "tool", "completed", "done").with_artifact(RunArtifact {
            label: " result ".to_string(),
            path: " result.json ".to_string(),
            kind: " JSON ".to_string(),
        });

        let artifact = event.artifact.as_ref().unwrap();
        assert_eq!(artifact.label, "result");
        assert_eq!(artifact.path, "result.json");
        assert_eq!(artifact.kind, "json");
    }

    #[test]
    fn run_event_with_artifact_drops_blank_direct_artifact_path() {
        let event = RunEvent::new(1, "tool", "completed", "done").with_artifact(RunArtifact {
            label: "empty".to_string(),
            path: "   ".to_string(),
            kind: "json".to_string(),
        });

        assert!(event.artifact.is_none());
    }

    #[test]
    fn run_summary_rolls_up_llm_audit_metadata_from_trace() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-llm-audit";
        append_run_trace_step(
            tmp.path(),
            run_id,
            &RunTraceStep::new(2, "tool-progress", "query · starting")
                .with_verb("query")
                .with_model_metadata("openai:gpt-test", "openai", "fnv1a64:abc123"),
        )
        .unwrap();
        append_run_trace_step(
            tmp.path(),
            run_id,
            &RunTraceStep::new(3, "reasoning", "query · answer")
                .with_verb("query")
                .with_latency_ms(Some(42))
                .with_cost_usd(Some(0.0042))
                .with_model_metadata("openai:gpt-test", "openai", "fnv1a64:abc123"),
        )
        .unwrap();

        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete()
                .with_cost(Some(0.0042)),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(loaded.llm_calls.len(), 1);
        assert_eq!(loaded.llm_calls[0].model, "openai:gpt-test");
        assert_eq!(loaded.llm_calls[0].provider, "openai");
        assert_eq!(loaded.llm_calls[0].prompt_hash, "fnv1a64:abc123");
        assert_eq!(loaded.llm_calls[0].cost_usd, Some(0.0042));

        let metadata =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "run.json")).unwrap();
        assert!(metadata.contains("\"llmCalls\""));
        assert!(metadata.contains("\"promptHash\": \"fnv1a64:abc123\""));
        assert!(!metadata.contains("query · answer"));
    }

    #[test]
    fn run_summary_records_malformed_trace_line_count() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-llm-audit-malformed";
        let trace_path = run_artifact_path(tmp.path(), run_id, "trace.jsonl");
        fs::create_dir_all(trace_path.parent().unwrap()).unwrap();
        fs::write(
            &trace_path,
            [
                serde_json::to_string(
                    &RunTraceStep::new(1, "reasoning", "query").with_model_metadata(
                        "openai:gpt-test",
                        "openai",
                        "fnv1a64:abc123",
                    ),
                )
                .unwrap(),
                "{not-json".to_string(),
            ]
            .join("\n"),
        )
        .unwrap();

        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(loaded.llm_calls.len(), 1);
        assert_eq!(loaded.trace_malformed_lines, Some(1));

        let metadata =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "run.json")).unwrap();
        assert!(metadata.contains("\"traceMalformedLines\": 1"));
    }

    #[test]
    fn run_summary_records_non_object_trace_line_count() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-llm-audit-non-object";
        let trace_path = run_artifact_path(tmp.path(), run_id, "trace.jsonl");
        fs::create_dir_all(trace_path.parent().unwrap()).unwrap();
        fs::write(
            &trace_path,
            [
                serde_json::to_string(
                    &RunTraceStep::new(1, "reasoning", "query").with_model_metadata(
                        "openai:gpt-test",
                        "openai",
                        "fnv1a64:abc123",
                    ),
                )
                .unwrap(),
                "[]".to_string(),
            ]
            .join("\n"),
        )
        .unwrap();

        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(loaded.llm_calls.len(), 1);
        assert_eq!(loaded.trace_malformed_lines, Some(1));

        let metadata =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "run.json")).unwrap();
        assert!(metadata.contains("\"traceMalformedLines\": 1"));
    }

    #[test]
    fn run_trace_audit_marks_non_file_trace_artifact_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-llm-audit-non-file";
        fs::create_dir_all(run_artifact_path(tmp.path(), run_id, "trace.jsonl")).unwrap();

        let audit = crate::run_artifacts::llm_audit::load_run_trace_audit(tmp.path(), run_id);

        assert!(audit.llm_calls.is_empty());
        assert_eq!(audit.malformed_lines, 1);
    }

    #[test]
    fn run_summary_records_available_reproducibility_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-repro-metadata";
        let summary =
            RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete()
                .with_model(Some(" openai:gpt-test ".to_string()))
                .with_config_hash(Some(" sha256:abc123 ".to_string()));

        write_run_summary(tmp.path(), &summary).unwrap();

        let loaded = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(
            loaded.kuzushi_version.as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            loaded.prompt_spine_version.as_deref(),
            Some(crate::prompts::PROMPT_SPINE_VERSION)
        );
        assert_eq!(loaded.platform, Some(runtime_platform_label()));
        assert_eq!(loaded.model.as_deref(), Some("openai:gpt-test"));
        assert_eq!(loaded.config_hash.as_deref(), Some("sha256:abc123"));
        assert!(!loaded.cli_args.is_empty());

        let metadata =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "run.json")).unwrap();
        assert!(metadata.contains("\"kuzushiVersion\""));
        assert!(metadata.contains("\"platform\""));
        assert!(metadata.contains("\"model\": \"openai:gpt-test\""));
        assert!(metadata.contains("\"configHash\": \"sha256:abc123\""));
        assert!(metadata.contains("\"cliArgs\""));
    }

    #[test]
    fn terminal_summary_preserves_start_time_reproducibility_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-start-snapshot";
        write_reproducibility_inputs(tmp.path(), "start-time rule", "start-time prompt");
        write_run_summary(tmp.path(), &start_time_summary(run_id)).unwrap();
        let snapshot = load_run_summary(tmp.path(), run_id).unwrap();
        write_reproducibility_inputs(
            tmp.path(),
            "changed terminal-time rule",
            "changed terminal-time prompt",
        );
        write_run_summary(tmp.path(), &terminal_time_summary(run_id)).unwrap();
        let loaded = load_run_summary(tmp.path(), run_id).unwrap();
        assert_start_time_snapshot(&loaded, &snapshot);
    }

    fn write_reproducibility_inputs(target: &Path, house_rule: &str, prompt: &str) {
        write_house_rule(target, "triage", house_rule);
        write_prompt_override(target, "triage", "run", prompt);
    }

    fn start_time_summary(run_id: &str) -> RunSummary {
        let mut summary =
            RunSummary::running(run_id, "scan", Some("sast:scan".to_string()), "target")
                .with_model(Some("openai:gpt-start".to_string()))
                .with_config_hash(Some("sha256:start-config".to_string()))
                .with_loaded_modules(vec!["builtin:sast".to_string()]);
        summary.started_at_unix = 123;
        summary
    }

    fn terminal_time_summary(run_id: &str) -> RunSummary {
        let mut summary =
            RunSummary::running(run_id, "scan", Some("sast:scan".to_string()), "target")
                .complete()
                .with_model(Some("openai:gpt-terminal".to_string()))
                .with_config_hash(Some("sha256:terminal-config".to_string()))
                .with_loaded_modules(vec!["builtin:changed".to_string()]);
        summary.started_at_unix = 999;
        summary
    }

    fn assert_start_time_snapshot(loaded: &RunSummary, snapshot: &RunSummary) {
        assert_eq!(loaded.started_at_unix, 123);
        assert_eq!(loaded.model.as_deref(), Some("openai:gpt-start"));
        assert_eq!(loaded.config_hash.as_deref(), Some("sha256:start-config"));
        assert_eq!(loaded.loaded_modules, vec!["builtin:sast"]);
        assert_eq!(loaded.house_rules, snapshot.house_rules);
        assert_eq!(loaded.prompt_overrides, snapshot.prompt_overrides);
    }

    #[test]
    fn run_summary_schema_matches_serialized_metadata_keys() {
        let schema = run_summary_schema();
        let value = serde_json::to_value(representative_run_summary()).unwrap();

        assert_required_schema_fields_exist(&schema, &value);
        assert_serialized_fields_are_declared(&schema, &value);
        assert_run_summary_llm_entries_match_schema(&schema, &value);
    }

    #[test]
    fn run_summary_schema_declares_only_canonical_metadata_fields() {
        let schema = run_summary_schema();
        let value = serde_json::to_value(representative_run_summary()).unwrap();

        assert_serialized_fields_are_declared(&schema, &value);
        assert_run_summary_llm_entries_match_schema(&schema, &value);
        assert_schema_requires_fields(&schema, &["runId", "startedAtUnix"]);
        assert_additional_properties_disabled(&schema);
        assert_additional_properties_disabled(&schema["definitions"]["llmCall"]);
        assert_schema_declares_no_fields(
            &schema,
            &[
                "run_id",
                "started_at_unix",
                "completed_at_unix",
                "cost_usd",
                "cli_args",
                "scanArgs",
                "loaded_module_specifiers",
            ],
        );
        assert_llm_call_schema_requires_canonical_prompt_hash(&schema);
    }

    #[test]
    fn run_summary_schema_declares_canonical_artifact_fields() {
        let schema = run_summary_schema();
        let artifact_schema = &schema["definitions"]["artifact"];

        assert_canonical_artifact_schema(artifact_schema);
    }

    #[test]
    fn run_artifact_manifest_schema_matches_serialized_keys() {
        let schema = run_artifact_manifest_schema();
        let value = serde_json::to_value(representative_artifact_manifest()).unwrap();

        assert_required_schema_fields_exist(&schema, &value);
        assert_serialized_fields_are_declared(&schema, &value);
        assert_artifact_entries_match_schema(&schema, &value);
    }

    #[test]
    fn run_artifact_manifest_schema_declares_only_canonical_run_id() {
        let schema = run_artifact_manifest_schema();
        let properties = schema["properties"].as_object().unwrap();

        assert!(properties.contains_key("runId"));
        assert!(!properties.contains_key("run_id"));
        assert_eq!(
            schema["required"],
            serde_json::json!(["runId", "artifacts"])
        );
    }

    #[test]
    fn run_artifact_manifest_schema_rejects_blank_run_id() {
        let schema = run_artifact_manifest_schema();

        assert_manifest_fields_reference_non_empty_string(&schema, &["runId"]);
    }

    #[test]
    fn run_artifact_manifest_schema_declares_only_canonical_artifact_fields() {
        let schema = run_artifact_manifest_schema();
        let artifact_schema = &schema["definitions"]["artifact"];
        let properties = artifact_schema["properties"].as_object().unwrap();

        assert_eq!(
            artifact_schema["required"],
            serde_json::json!(["label", "path", "kind"])
        );
        assert_eq!(properties.len(), 3);
        assert!(properties.contains_key("label"));
        assert!(properties.contains_key("path"));
        assert!(properties.contains_key("kind"));
    }

    #[test]
    fn run_artifact_manifest_schema_rejects_blank_artifact_strings() {
        let schema = run_artifact_manifest_schema();
        let artifact_schema = &schema["definitions"]["artifact"];

        assert_artifact_fields_reference_non_empty_string(artifact_schema, &["label", "path"]);
        assert_eq!(schema["definitions"]["nonEmptyString"]["minLength"], 1);
        assert_eq!(schema["definitions"]["nonEmptyString"]["pattern"], "\\S");
    }

    #[test]
    fn run_artifact_manifest_schema_constrains_canonical_path_metadata() {
        let schema = run_artifact_manifest_schema();
        let rules = schema["definitions"]["canonicalArtifactMetadata"]["allOf"]
            .as_array()
            .unwrap();

        for spec in CANONICAL_RUN_ARTIFACTS {
            assert_schema_rule_matches_artifact_spec(rules, &spec);
        }
    }

    #[test]
    fn run_artifact_manifest_schema_constrains_optional_and_tool_path_metadata() {
        let schema = run_artifact_manifest_schema();
        let rules = schema["definitions"]["canonicalArtifactMetadata"]["allOf"]
            .as_array()
            .unwrap();

        for spec in OPTIONAL_RUN_ARTIFACTS {
            assert_schema_rule_matches_artifact_spec(rules, &spec);
        }
        for spec in TOOL_INPUT_ARTIFACTS {
            assert_schema_rule_matches_artifact_spec(rules, &spec);
        }
        for spec in TOOL_RESULT_ARTIFACTS {
            assert_schema_rule_matches_artifact_spec(rules, &spec);
        }
    }

    #[test]
    fn run_failures_schema_matches_serialized_keys() {
        let schema = run_failures_schema();
        let value = serde_json::to_value(representative_run_failures()).unwrap();

        assert_required_schema_fields_exist(&schema, &value);
        assert_serialized_fields_are_declared(&schema, &value);
        assert_failure_entries_match_schema(&schema, &value);
    }

    #[test]
    fn run_failures_schema_declares_only_canonical_failure_fields() {
        let schema = run_failures_schema();

        assert_schema_requires_fields(&schema, &["runId"]);
        assert_schema_declares_no_fields(&schema, &["run_id"]);
        assert_failure_schema_requires_canonical_context_key(&schema);
        assert_failure_context_schema_requires_canonical_fields(&schema);
    }

    #[test]
    fn run_failures_schema_declares_canonical_available_artifact_fields() {
        let schema = run_failures_schema();
        let artifact_schema = &schema["definitions"]["artifact"];

        assert_canonical_artifact_schema(artifact_schema);
    }

    #[test]
    fn run_event_schema_matches_serialized_keys() {
        let schema = run_event_schema();
        let value = serde_json::to_value(representative_run_event()).unwrap();

        assert_required_schema_fields_exist(&schema, &value);
        assert_serialized_fields_are_declared(&schema, &value);
        assert_event_artifact_matches_schema(&schema, &value);
    }

    #[test]
    fn run_event_schema_declares_only_canonical_event_fields() {
        let schema = run_event_schema();

        assert_schema_requires_fields(&schema, &["atUnix"]);
        assert_schema_declares_no_fields(&schema, &["at_unix", "toolName", "tool_name"]);
    }

    #[test]
    fn run_event_schema_declares_canonical_artifact_fields() {
        let schema = run_event_schema();
        let artifact_schema = &schema["definitions"]["artifact"];

        assert_canonical_artifact_schema(artifact_schema);
    }

    #[test]
    fn run_trace_schema_matches_serialized_keys() {
        let schema = run_trace_schema();
        let value = serde_json::to_value(representative_trace_step()).unwrap();

        assert_required_schema_fields_exist(&schema, &value);
        assert_serialized_fields_are_declared(&schema, &value);
    }

    #[test]
    fn run_trace_schema_declares_only_canonical_fields() {
        let schema = run_trace_schema();

        assert_schema_declares_fields(
            &schema,
            &[
                "latency_ms",
                "cost_usd",
                "module_id",
                "parent_step",
                "started_at_ms",
                "prompt_hash",
            ],
        );
        assert_schema_declares_no_fields(
            &schema,
            &[
                "latencyMs",
                "costUsd",
                "moduleId",
                "parentStep",
                "startedAtMs",
                "promptHash",
            ],
        );
    }

    #[test]
    fn run_summary_records_house_rule_fingerprints() {
        let tmp = tempfile::tempdir().unwrap();
        write_house_rule(tmp.path(), "semgrep", "prefer reachable sinks");
        write_house_rule(tmp.path(), "triage", "mark evidence-only findings");

        write_run_summary(
            tmp.path(),
            &RunSummary::running("run-house-rules", "tool", None, "target").complete(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), "run-house-rules").unwrap();
        assert_eq!(loaded.house_rules.len(), 2);
        assert_eq!(loaded.house_rules[0].module, "semgrep");
        assert_eq!(
            loaded.house_rules[0].path,
            crate::relative_house_rule_path("semgrep").to_string_lossy()
        );
        assert!(loaded.house_rules[0].sha256.starts_with("sha256:"));
        let metadata =
            fs::read_to_string(run_artifact_path(tmp.path(), "run-house-rules", "run.json"))
                .unwrap();
        assert!(metadata.contains("\"houseRules\""));
    }

    #[test]
    fn run_summary_records_invalid_house_rule_fingerprint_state() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(crate::house_rule_path(tmp.path(), "triage")).unwrap();

        write_run_summary(
            tmp.path(),
            &RunSummary::running("run-invalid-house-rule", "tool", None, "target").complete(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), "run-invalid-house-rule").unwrap();

        assert_eq!(loaded.house_rules.len(), 1);
        assert_eq!(loaded.house_rules[0].module, "triage");
        assert_eq!(loaded.house_rules[0].sha256, "invalid:not-a-file");
    }

    #[test]
    fn run_summary_records_invalid_house_rule_root_state() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(crate::workspace::workspace_state_root(tmp.path())).unwrap();
        fs::write(crate::house_rules_root(tmp.path()), "not a directory").unwrap();

        write_run_summary(
            tmp.path(),
            &RunSummary::running("run-invalid-house-root", "tool", None, "target").complete(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), "run-invalid-house-root").unwrap();

        assert_eq!(loaded.house_rules.len(), 1);
        assert_eq!(loaded.house_rules[0].module, "<house-rules>");
        assert_eq!(
            loaded.house_rules[0].path,
            crate::relative_house_rules_root().to_string_lossy()
        );
        assert_eq!(loaded.house_rules[0].sha256, "invalid:not-a-directory");
    }

    #[test]
    fn run_summary_records_prompt_override_fingerprints() {
        let tmp = tempfile::tempdir().unwrap();
        write_prompt_override(tmp.path(), "triage", "run", "prioritize critical sinks");
        write_prompt_override(tmp.path(), "verify", "finding", "require runtime proof");

        write_run_summary(
            tmp.path(),
            &RunSummary::running("run-prompts", "tool", None, "target").complete(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), "run-prompts").unwrap();
        assert_eq!(loaded.prompt_overrides.len(), 2);
        assert_eq!(loaded.prompt_overrides[0].module, "triage");
        assert_eq!(loaded.prompt_overrides[0].verb, "run");
        assert_eq!(
            loaded.prompt_overrides[0].path,
            crate::relative_prompt_override_path("triage", "run").to_string_lossy()
        );
        assert!(loaded.prompt_overrides[0].sha256.starts_with("sha256:"));
        let metadata =
            fs::read_to_string(run_artifact_path(tmp.path(), "run-prompts", "run.json")).unwrap();
        assert!(metadata.contains("\"promptOverrides\""));
    }

    #[test]
    fn run_summary_records_invalid_prompt_override_fingerprint_state() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(crate::prompt_override_path(tmp.path(), "triage", "run")).unwrap();

        write_run_summary(
            tmp.path(),
            &RunSummary::running("run-invalid-prompt", "tool", None, "target").complete(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), "run-invalid-prompt").unwrap();

        assert_eq!(loaded.prompt_overrides.len(), 1);
        assert_eq!(loaded.prompt_overrides[0].module, "triage");
        assert_eq!(loaded.prompt_overrides[0].verb, "run");
        assert_eq!(loaded.prompt_overrides[0].sha256, "invalid:not-a-file");
    }

    #[test]
    fn run_summary_records_invalid_prompt_root_state() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(crate::workspace::workspace_state_root(tmp.path())).unwrap();
        fs::write(crate::prompt_overrides_root(tmp.path()), "not a directory").unwrap();

        write_run_summary(
            tmp.path(),
            &RunSummary::running("run-invalid-prompt-root", "tool", None, "target").complete(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), "run-invalid-prompt-root").unwrap();

        assert_eq!(loaded.prompt_overrides.len(), 1);
        assert_eq!(loaded.prompt_overrides[0].module, "<prompts>");
        assert_eq!(loaded.prompt_overrides[0].verb, "<root>");
        assert_eq!(
            loaded.prompt_overrides[0].path,
            crate::relative_prompt_overrides_root().to_string_lossy()
        );
        assert_eq!(loaded.prompt_overrides[0].sha256, "invalid:not-a-directory");
    }

    #[test]
    fn run_summary_records_invalid_prompt_module_root_state() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(crate::prompt_overrides_root(tmp.path())).unwrap();
        fs::write(
            crate::module_prompt_root(tmp.path(), "triage"),
            "not a directory",
        )
        .unwrap();

        write_run_summary(
            tmp.path(),
            &RunSummary::running("run-invalid-prompt-module", "tool", None, "target").complete(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), "run-invalid-prompt-module").unwrap();

        assert_eq!(loaded.prompt_overrides.len(), 1);
        assert_eq!(loaded.prompt_overrides[0].module, "triage");
        assert_eq!(loaded.prompt_overrides[0].verb, "<module>");
        assert_eq!(
            loaded.prompt_overrides[0].path,
            crate::relative_module_prompt_root("triage").to_string_lossy()
        );
        assert_eq!(loaded.prompt_overrides[0].sha256, "invalid:not-a-directory");
    }

    #[test]
    fn run_summary_records_threat_model_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let threat_model_path = crate::capabilities::persistent_threat_model_path(tmp.path());
        fs::create_dir_all(threat_model_path.parent().unwrap()).unwrap();
        fs::write(threat_model_path, r#"{"methodology":"STRIDE"}"#).unwrap();

        write_run_summary(
            tmp.path(),
            &RunSummary::running("run-threat-digest", "tool", None, "target").complete(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), "run-threat-digest").unwrap();
        assert!(loaded
            .threat_model_sha256
            .as_deref()
            .is_some_and(|hash| hash.starts_with("sha256:")));
        let metadata = fs::read_to_string(run_artifact_path(
            tmp.path(),
            "run-threat-digest",
            "run.json",
        ))
        .unwrap();
        assert!(metadata.contains("\"threatModelSha256\""));
    }

    #[test]
    fn run_summary_records_invalid_threat_model_digest_state() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(crate::capabilities::persistent_threat_model_path(
            tmp.path(),
        ))
        .unwrap();

        write_run_summary(
            tmp.path(),
            &RunSummary::running("run-threat-invalid", "tool", None, "target").complete(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), "run-threat-invalid").unwrap();

        assert_eq!(
            loaded.threat_model_sha256.as_deref(),
            Some("invalid:not-a-file")
        );
    }

    #[test]
    fn run_summary_records_target_git_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        if !init_git_repo(tmp.path()) {
            return;
        }

        write_run_summary(
            tmp.path(),
            &RunSummary::running("run-target-git", "tool", None, "target").complete(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), "run-target-git").unwrap();
        let git = loaded.target_git.expect("target git metadata");
        assert_eq!(git.branch.as_deref(), Some("main"));
        assert!(!git.dirty);
        assert!(git.sha.len() >= 7);

        fs::write(tmp.path().join("tracked.txt"), "changed\n").unwrap();
        write_run_summary(
            tmp.path(),
            &RunSummary::running("run-target-git-dirty", "tool", None, "target").complete(),
        )
        .unwrap();
        let dirty = load_run_summary(tmp.path(), "run-target-git-dirty").unwrap();
        assert!(dirty.target_git.expect("target git metadata").dirty);
    }

    #[test]
    fn tool_run_complete_records_output_model_in_run_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-output-model";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "triage:run");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "data": {
                    "model": "openai:gpt-test",
                    "findingsCount": 0
                }
            }),
        );

        let loaded = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(loaded.model.as_deref(), Some("openai:gpt-test"));
        assert_eq!(loaded.findings, Some(0));
    }

    #[test]
    fn terminal_receipt_replaces_profile_model_with_models_toml_role_model() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi")).unwrap();
        fs::write(
            home.join(".kuzushi/models.toml"),
            "[roles.deep_auditor]\nprimary = \"anthropic:claude-opus-4-7\"\n",
        )
        .unwrap();
        let router = crate::agent_router::AgentRouter::load(&crate::config::ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();
        let routed = receipt_routed_runtime(router, None);
        let actual = routed
            .resolve_model_for_role(crate::agent_router::AgentRole::DeepAuditor, 0, None)
            .unwrap();

        complete_run_with_observed_models(
            tmp.path(),
            "tool-models-toml",
            "openai:profile-default",
            &[actual.as_str()],
        );

        let summary = load_run_summary(tmp.path(), "tool-models-toml").unwrap();
        assert_eq!(summary.model.as_deref(), Some("anthropic:claude-opus-4-7"));
        assert_eq!(summary.llm_calls[0].model, "anthropic:claude-opus-4-7");
    }

    #[test]
    fn terminal_receipt_replaces_profile_model_with_role_option_override() {
        let tmp = tempfile::tempdir().unwrap();
        let mut options = crate::options::ToolOptionStore::new();
        options.set_value(
            crate::options::OptionScope::Global,
            crate::options::OptionTarget::All,
            "MODEL_DEEP_AUDITOR",
            serde_json::json!("openai:setg-deep-auditor"),
        );
        let routed =
            receipt_routed_runtime(crate::agent_router::AgentRouter::empty(), Some(&options));
        let actual = routed
            .resolve_model_for_role(crate::agent_router::AgentRole::DeepAuditor, 0, None)
            .unwrap();

        complete_run_with_observed_models(
            tmp.path(),
            "tool-model-option",
            "openai:profile-default",
            &[actual.as_str()],
        );

        let summary = load_run_summary(tmp.path(), "tool-model-option").unwrap();
        assert_eq!(summary.model.as_deref(), Some("openai:setg-deep-auditor"));
        assert_eq!(summary.llm_calls[0].model, "openai:setg-deep-auditor");
    }

    #[test]
    fn multi_model_receipt_uses_llm_calls_instead_of_claiming_one_primary_model() {
        let tmp = tempfile::tempdir().unwrap();
        complete_run_with_observed_models(
            tmp.path(),
            "tool-multi-model",
            "openai:profile-default",
            &["openai:triage", "anthropic:deep-auditor"],
        );

        let summary = load_run_summary(tmp.path(), "tool-multi-model").unwrap();
        assert_eq!(summary.model, None);
        assert_eq!(
            summary
                .llm_calls
                .iter()
                .map(|call| call.model.as_str())
                .collect::<Vec<_>>(),
            vec!["openai:triage", "anthropic:deep-auditor"]
        );
    }

    struct ReceiptNoopRuntime;

    impl crate::runtime::AgentRuntime for ReceiptNoopRuntime {
        fn triage_finding_blocking(
            &self,
            _request: crate::runtime::TriageRequest,
        ) -> anyhow::Result<crate::findings::TriageOutcome> {
            anyhow::bail!("unused receipt test runtime")
        }
    }

    fn receipt_routed_runtime(
        router: crate::agent_router::AgentRouter,
        options: Option<&crate::options::ToolOptionStore>,
    ) -> crate::agent_router::RoutedRuntime<'static> {
        let routed = crate::agent_router::RoutedRuntime::new(
            Arc::new(ReceiptNoopRuntime),
            Arc::new(router),
            Some("openai:profile-default".to_string()),
        );
        match options {
            Some(options) => routed.with_option_store(options),
            None => routed,
        }
    }

    fn complete_run_with_observed_models(
        target: &Path,
        run_id: &str,
        predicted_model: &str,
        observed_models: &[&str],
    ) {
        let record = ToolRunRecord::new(target, run_id, "tool", "deep-audit:run");
        record_tool_run_started_with_metadata(
            record,
            &serde_json::json!({}),
            Some(predicted_model.to_string()),
            None,
        );
        for (index, model) in observed_models.iter().enumerate() {
            append_run_trace_step(
                target,
                run_id,
                &RunTraceStep::new(index + 1, "reasoning", "role-routed model call")
                    .with_model_metadata(
                        *model,
                        crate::runtime::model_provider(model),
                        format!("fnv1a64:receipt-{index}"),
                    ),
            )
            .unwrap();
        }
        record_tool_run_complete(record, &serde_json::json!({"status": "completed"}));
    }

    #[test]
    fn summary_survives_torn_write_leftover_and_next_read_recovers() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-torn-write";
        // A committed, well-formed summary written through the atomic path.
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();

        // Simulate a crash mid-write: a truncated temp sibling left in the run
        // directory that was never renamed into place. Because `write_atomic`
        // only publishes via rename, this leftover must never be observed by a
        // reader — the previously committed file stays authoritative.
        let run_json = run_artifact_path(tmp.path(), run_id, "run.json");
        let dir = run_json.parent().unwrap();
        fs::write(
            dir.join(".run.json.tmp-999999-0-0"),
            "{ this is a torn writ",
        )
        .unwrap();

        // The committed summary is still fully intact and parseable.
        let loaded = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(loaded.run_id, run_id);
        assert_eq!(loaded.status, "completed");

        // Listing ignores the temp leftover and returns exactly one run.
        let all = list_run_summaries(tmp.path()).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].run_id, run_id);
    }

    fn write_house_rule(target: &Path, module: &str, body: &str) {
        let path = crate::house_rule_path(target, module);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn write_prompt_override(target: &Path, module: &str, verb: &str, body: &str) {
        let path = crate::prompt_override_path(target, module, verb);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn init_git_repo(target: &Path) -> bool {
        run_git(target, &["init", "-b", "main"])
            && run_git(target, &["config", "user.email", "test@example.com"])
            && run_git(target, &["config", "user.name", "Kuzushi Test"])
            && write_initial_commit(target)
    }

    fn write_initial_commit(target: &Path) -> bool {
        fs::write(target.join("tracked.txt"), "initial\n").is_ok()
            && run_git(target, &["add", "tracked.txt"])
            && run_git(target, &["commit", "-m", "initial"])
    }

    fn run_git(target: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .arg("-C")
            .arg(target)
            .args(args)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn assert_git_status_clean(target: &Path, operation: &str) {
        let output = Command::new("git")
            .arg("-C")
            .arg(target)
            .args(["status", "--porcelain", "--untracked-files=all"])
            .output()
            .unwrap();
        assert!(output.status.success(), "git status failed for {operation}");
        assert!(
            output.stdout.is_empty(),
            "{operation} dirtied fresh repository: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    fn load_run_summary_rejects_unknown_metadata_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-snake-metadata";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "run.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "run_id": run_id,
                "kind": "tool",
                "status": "completed",
                "tool": "agentic:test",
                "target": "target",
                "startedAtUnix": 1,
                "completedAtUnix": 2,
                "findings": 3,
                "costUsd": 0.5,
                "processId": 99,
                "kuzushiVersion": "1.2.3-test",
                "gitSha": "abc123",
                "gitBranch": "main",
                "model": "openai:gpt-test",
                "configHash": "sha256:def456",
                "platform": "darwin-arm64",
                "loadedModules": ["builtin:agentic-sast", "builtin:context"],
                "llmCalls": [
                    {
                        "n": 1,
                        "kind": "reasoning",
                        "verb": "query",
                        "model": "openai:gpt-test",
                        "provider": "openai",
                        "promptHash": "fnv1a64:abc123",
                        "latencyMs": 42,
                        "costUsd": 0.25
                    }
                ],
                "artifacts": []
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_summary(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Run metadata is not canonical"));
        assert!(message.contains("unknown field `run_id`"));
    }

    #[test]
    fn load_run_artifacts_accepts_canonical_manifest_run_id() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-snake-manifest";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": "run metadata",
                        "path": "run.json",
                        "kind": "json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let artifacts = load_run_artifacts(tmp.path(), run_id).unwrap();

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].label, "run metadata");
        assert_eq!(artifacts[0].path, "run.json");
    }

    #[test]
    fn load_run_artifacts_rejects_unknown_manifest_artifact_field() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-unknown-artifact-field";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": "run metadata",
                        "path": "run.json",
                        "filePath": "trace.jsonl",
                        "kind": "json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest is not canonical"));
        assert!(message.contains("unknown field `filePath`"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_unknown_manifest_object_field() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-unknown-object-field";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [],
                "objects": [{
                    "label": "context snapshot",
                    "path": "context.json",
                    "objectRef": {
                        "kind": "ContextSnapshot",
                        "hash": "blake3:abc",
                        "sizeBytes": 12
                    },
                    "legacy": true
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest is not canonical"));
        assert!(message.contains("unknown field `legacy`"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_non_string_manifest_artifact_label() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-non-string-artifact-label";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": ["run metadata"],
                        "path": "run.json",
                        "kind": "json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message
            .contains("Artifact manifest artifact at index 0 label is not a non-empty string"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_missing_manifest_artifact_label() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-missing-artifact-label";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "path": "run.json",
                        "kind": "json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest artifact at index 0 is missing label"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_missing_manifest_artifact_path() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-missing-artifact-path";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": "run metadata",
                        "kind": "json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest artifact at index 0 is missing path"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_missing_manifest_artifact_kind() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-missing-artifact-kind";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": "run metadata",
                        "path": "run.json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest artifact at index 0 is missing kind"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_blank_manifest_artifact_path() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-blank-path";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": "run metadata",
                        "path": "   ",
                        "kind": "json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message
            .contains("Artifact manifest artifact at index 0 path is not a non-empty string"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_blank_manifest_artifact_label() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-blank-label";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": "   ",
                        "path": "run.json",
                        "kind": "json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message
            .contains("Artifact manifest artifact at index 0 label is not a non-empty string"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_blank_manifest_artifact_kind() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-blank-kind";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": "run metadata",
                        "path": "run.json",
                        "kind": "   "
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message
            .contains("Artifact manifest artifact at index 0 kind is not a non-empty string"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_manifest_canonical_artifact_label_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-canonical-label-mismatch";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": "runtime trace",
                        "path": "run.json",
                        "kind": "json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains(
            "Artifact manifest artifact at index 0 label does not match canonical artifact contract"
        ));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_manifest_canonical_artifact_kind_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-canonical-kind-mismatch";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": "run metadata",
                        "path": "run.json",
                        "kind": "jsonl"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains(
            "Artifact manifest artifact at index 0 kind does not match canonical artifact contract"
        ));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_manifest_tool_input_artifact_metadata_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-tool-input-mismatch";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": "tool result",
                        "path": "input.json",
                        "kind": "json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains(
            "Artifact manifest artifact at index 0 label does not match canonical artifact contract"
        ));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_non_file_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-non-file";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        let manifest_path = run_artifact_path(tmp.path(), run_id, "artifacts.json");
        fs::remove_file(&manifest_path).unwrap();
        fs::create_dir(&manifest_path).unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();

        assert!(error
            .to_string()
            .contains("Artifact manifest is not a file"));
        assert!(error.to_string().contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_non_object_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-non-object";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            "[]",
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest is not a JSON object"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_non_array_manifest_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-non-array-artifacts";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": {}
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest artifacts is not a JSON array"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_manifest_missing_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-missing-artifacts";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest is missing artifacts array"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_manifest_missing_run_id() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-missing-run-id";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "artifacts": []
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest is missing runId"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_manifest_blank_run_id() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-blank-run-id";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": "   ",
                "artifacts": []
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest runId is not a non-empty string"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_unknown_manifest_field() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-unknown-field";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "run_id": "other-run",
                "artifacts": []
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest is not canonical"));
        assert!(message.contains("unknown field `run_id`"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_manifest_run_id_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-run-id-mismatch";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": "other-run",
                "artifacts": []
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest runId does not match requested run id"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_accepts_single_canonical_manifest_run_id() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-canonical-run-id";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": "run metadata",
                        "path": "run.json",
                        "kind": "json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let artifacts = load_run_artifacts(tmp.path(), run_id).unwrap();

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].label, "run metadata");
    }

    #[test]
    fn load_run_artifacts_rejects_non_object_manifest_artifact_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-non-object-artifact-entry";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "runId": run_id,
                "artifacts": [
                    {
                        "label": "run metadata",
                        "path": "run.json",
                        "kind": "json"
                    },
                    []
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest artifact at index 1 is not a JSON object"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn record_run_artifact_normalizes_direct_artifact_values() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-direct-artifact-normalization";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();

        super::super::artifact_manifest::record_run_artifact(
            tmp.path(),
            run_id,
            &RunArtifact {
                label: " report json ".to_string(),
                path: " reports/report.json ".to_string(),
                kind: " JSON ".to_string(),
            },
        )
        .unwrap();

        let artifacts = load_run_artifacts(tmp.path(), run_id).unwrap();

        assert!(artifacts.iter().any(|artifact| {
            artifact.label == "report json"
                && artifact.path == "reports/report.json"
                && artifact.kind == "json"
        }));
    }

    #[test]
    fn record_run_artifact_rejects_blank_direct_artifact_path() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-direct-artifact-empty-path";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();

        let error = super::super::artifact_manifest::record_run_artifact(
            tmp.path(),
            run_id,
            &RunArtifact {
                label: "empty".to_string(),
                path: "   ".to_string(),
                kind: "json".to_string(),
            },
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("run artifact path must not be empty"));
        assert!(!load_run_artifacts(tmp.path(), run_id)
            .unwrap()
            .iter()
            .any(|artifact| artifact.label == "empty"));
    }

    #[test]
    fn artifact_writers_return_normalized_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-writer-artifact-normalization";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("report:build".to_string()), "target")
                .complete(),
        )
        .unwrap();

        let json = write_run_artifact_json(
            tmp.path(),
            run_id,
            "result.json",
            " tool result ",
            &serde_json::json!({"ok": true}),
        )
        .unwrap();
        let markdown = super::super::write_run_artifact_text(
            tmp.path(),
            run_id,
            "report.md",
            " report ",
            " Markdown ",
            "# Report",
        )
        .unwrap();

        assert_eq!(json.label, "tool result");
        assert_eq!(json.kind, "json");
        assert_eq!(markdown.label, "report");
        assert_eq!(markdown.kind, "markdown");

        let manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(run_artifact_path(tmp.path(), run_id, "artifacts.json")).unwrap(),
        )
        .unwrap();
        let objects = manifest["objects"].as_array().unwrap();
        assert_eq!(objects.len(), 2);
        let result_object = objects
            .iter()
            .find(|object| object["label"] == "tool result")
            .unwrap();
        assert_eq!(result_object["objectRef"]["kind"], "blob");
        let report_object = objects
            .iter()
            .find(|object| object["label"] == "report")
            .unwrap();
        assert_eq!(report_object["objectRef"]["kind"], "report-markdown");
        let hash = result_object["objectRef"]["hash"].as_str().unwrap();
        assert!(cas_object_path(tmp.path(), hash).is_file());
    }

    #[test]
    fn concurrent_artifact_writers_preserve_every_manifest_entry() {
        const WRITERS: usize = 12;
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-concurrent-manifest";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("report:build".to_string()), "target"),
        )
        .unwrap();
        let target = Arc::new(tmp.path().to_path_buf());
        let barrier = Arc::new(Barrier::new(WRITERS));
        let handles = (0..WRITERS)
            .map(|writer| {
                let target = Arc::clone(&target);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    write_run_artifact_json(
                        target.as_path(),
                        run_id,
                        &format!("artifact-{writer}.json"),
                        format!("artifact {writer}"),
                        &serde_json::json!({"writer": writer}),
                    )
                    .unwrap();
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle.join().unwrap();
        }

        let artifacts = load_run_artifacts(tmp.path(), run_id).unwrap();
        for writer in 0..WRITERS {
            assert_manifest_has(&artifacts, &format!("artifact-{writer}.json"));
        }
        let manifest: RunArtifactManifest = serde_json::from_str(
            &fs::read_to_string(run_artifact_path(tmp.path(), run_id, "artifacts.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.objects.len(), WRITERS);
    }

    #[test]
    fn concurrent_same_leaf_writers_keep_file_and_manifest_object_consistent() {
        const WRITERS: usize = 8;
        let tmp = tempfile::tempdir().unwrap();
        let target = Arc::new(tmp.path().to_path_buf());
        let barrier = Arc::new(Barrier::new(WRITERS));
        let run_id = "run-concurrent-same-artifact";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", None, "target"),
        )
        .unwrap();
        let handles = (0..WRITERS)
            .map(|writer| {
                let target = Arc::clone(&target);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    write_run_artifact_json(
                        target.as_path(),
                        run_id,
                        "shared.json",
                        "shared",
                        &serde_json::json!({"writer": writer}),
                    )
                    .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }

        let artifact_path = resolve_run_artifact_path(tmp.path(), run_id, "shared.json").unwrap();
        let disk: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&artifact_path).unwrap()).unwrap();
        let manifest: RunArtifactManifest = serde_json::from_str(
            &fs::read_to_string(run_artifact_path(tmp.path(), run_id, "artifacts.json")).unwrap(),
        )
        .unwrap();
        let object = manifest
            .objects
            .iter()
            .find(|object| object.path == artifact_path.display().to_string())
            .unwrap();
        let stored = crate::content_store::ContentStore::open(
            crate::workspace::workspace_objects_dir(tmp.path()),
        )
        .unwrap()
        .get_object(&object.object_ref)
        .unwrap();
        let stored: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(disk, stored);
    }

    fn cas_object_path(target: &Path, hash: &str) -> PathBuf {
        crate::workspace::workspace_objects_dir(target)
            .join("blake3")
            .join(&hash[0..2])
            .join(&hash[2..4])
            .join(hash)
    }

    #[test]
    fn load_run_failures_accepts_canonical_artifact_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-failure-canonical-artifacts";
        let triage_path = relative_run_artifact_path(tmp.path(), run_id, "triage.json");
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("triage:run".to_string()), "target")
                .failed("runtime unavailable"),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "failures.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                    "runId": run_id,
                    "status": "failed",
                    "failures": [{
                        "tool": "triage:run",
                        "status": "failed",
                        "error": "runtime unavailable",
                    "agentThreadContext": {
                        "failedStage": "triage:run",
                        "cause": "runtime unavailable",
                        "whatFailed": "triage did not complete",
                        "artifactsAvailable": [{
                            "label": " triage transcript ",
                            "path": format!(" {triage_path} "),
                            "kind": " JSON "
                        }],
                        "missingArtifacts": ["proof.json"],
                        "allowedProofLevel": "artifact-review-only",
                        "nextFilesOrArtifactsToInspect": ["failures.json"],
                        "recoveryOptions": ["rerun triage"],
                        "fallbackPrompt": "continue the run",
                        "claimsForbidden": ["verified claim"]
                    }
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let failures = load_run_failures(tmp.path(), run_id).unwrap();
        let artifact = &failures.failures[0]
            .agent_thread_context
            .artifacts_available[0];

        assert_eq!(artifact.label, "triage transcript");
        assert_eq!(artifact.path, triage_path);
        assert_eq!(artifact.kind, "json");
    }

    #[test]
    fn failure_handoff_excludes_declared_artifacts_outside_target() {
        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let run_id = "run-contained-failure-handoff";
        let safe = target.path().join("safe.json");
        let escaped = outside.path().join("secret.json");
        fs::write(&safe, "{}").unwrap();
        fs::write(&escaped, "secret").unwrap();
        let artifacts = vec![
            RunArtifact {
                label: "safe".to_string(),
                path: safe.display().to_string(),
                kind: "json".to_string(),
            },
            RunArtifact {
                label: "outside".to_string(),
                path: escaped.display().to_string(),
                kind: "json".to_string(),
            },
            RunArtifact {
                label: "traversal".to_string(),
                path: "../secret.json".to_string(),
                kind: "json".to_string(),
            },
        ];

        write_run_failures(
            target.path(),
            run_id,
            "triage:run",
            "failed",
            "boom",
            &artifacts,
        )
        .unwrap();
        let context = load_run_failure_context(target.path(), run_id)
            .unwrap()
            .unwrap();

        assert_eq!(context.artifacts_available.len(), 1);
        assert_eq!(context.artifacts_available[0].label, "safe");
        assert!(!context
            .next_files_or_artifacts_to_inspect
            .iter()
            .any(|path| path.contains("secret.json")));
        assert_eq!(fs::read_to_string(escaped).unwrap(), "secret");
    }

    #[cfg(unix)]
    #[test]
    fn failure_handoff_excludes_symlinked_declared_artifact() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let run_id = "run-symlink-failure-handoff";
        let secret = outside.path().join("secret.json");
        let link = target.path().join("linked.json");
        fs::write(&secret, "secret").unwrap();
        symlink(&secret, &link).unwrap();
        let artifact = RunArtifact {
            label: "linked".to_string(),
            path: link.display().to_string(),
            kind: "json".to_string(),
        };

        write_run_failures(
            target.path(),
            run_id,
            "triage:run",
            "failed",
            "boom",
            &[artifact],
        )
        .unwrap();
        let context = load_run_failure_context(target.path(), run_id)
            .unwrap()
            .unwrap();

        assert!(context.artifacts_available.is_empty());
        assert!(!context
            .next_files_or_artifacts_to_inspect
            .iter()
            .any(|path| path.contains("linked.json")));
        assert_eq!(fs::read_to_string(secret).unwrap(), "secret");
    }

    #[test]
    fn load_run_failures_rejects_unknown_failure_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-failure-unknown-field";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("triage:run".to_string()), "target")
                .failed("runtime unavailable"),
        )
        .unwrap();
        let mut failures = serde_json::to_value(representative_run_failures()).unwrap();
        failures["failures"][0]["agentThreadContext"]
            .as_object_mut()
            .unwrap()
            .insert("failed_stage".to_string(), serde_json::json!("triage:run"));
        fs::write(
            run_artifact_path(tmp.path(), run_id, "failures.json"),
            serde_json::to_string_pretty(&failures).unwrap(),
        )
        .unwrap();

        let error = load_run_failures(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Run failures artifact is not canonical"));
        assert!(message.contains("unknown field `failed_stage`"));
        assert!(message.contains("failures.json"));
    }

    #[test]
    fn load_run_failures_rejects_non_file_failures_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-file-failures";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("triage:run".to_string()), "target")
                .failed("runtime unavailable"),
        )
        .unwrap();
        let path = run_artifact_path(tmp.path(), run_id, "failures.json");
        fs::remove_file(&path).unwrap();
        fs::create_dir_all(&path).unwrap();

        let error = load_run_failures(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Run failures artifact is not a file"));
        assert!(message.contains("failures.json"));
    }

    #[test]
    fn load_run_failures_rejects_non_object_failures_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-object-failures";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("triage:run".to_string()), "target")
                .failed("runtime unavailable"),
        )
        .unwrap();
        fs::write(run_artifact_path(tmp.path(), run_id, "failures.json"), "[]").unwrap();

        let error = load_run_failures(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Run failures artifact is not a JSON object"));
        assert!(message.contains("failures.json"));
    }

    #[test]
    fn writes_summary_artifact_and_trace_under_run_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = new_run_id("tool");
        let summary = RunSummary::running(
            run_id.clone(),
            "tool",
            Some("context:build".to_string()),
            tmp.path().display().to_string(),
        );

        let summary_path = write_run_summary(tmp.path(), &summary).unwrap();
        assert!(summary_path.ends_with("run.json"));
        assert_canonical_run_files_exist(tmp.path(), &run_id);
        let running_manifest_artifacts = load_run_artifacts(tmp.path(), &run_id).unwrap();
        assert_manifest_has_canonical_run_artifacts(&running_manifest_artifacts);
        assert!(!run_artifact_path(tmp.path(), &run_id, "context.json").exists());
        let placeholder_report =
            fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "report.md")).unwrap();
        assert!(placeholder_report.contains(&format!("# Kuzushi Run {run_id}")));
        assert!(placeholder_report.contains("No report was recorded for this run."));
        assert_eq!(
            fs::read_to_string(tmp.path().join(".kuzushi/v3/latest")).unwrap(),
            format!("{run_id}\n")
        );
        let result = serde_json::json!({"ok": true});
        let artifact =
            write_run_artifact_json(tmp.path(), &run_id, "result.json", "tool result", &result)
                .unwrap();
        append_run_trace_step(
            tmp.path(),
            &run_id,
            &RunTraceStep::new(1, "tool", "context:build started"),
        )
        .unwrap();
        write_run_summary(tmp.path(), &summary.complete().with_artifact(artifact)).unwrap();

        let loaded = load_run_summary(tmp.path(), &run_id).unwrap();
        assert_eq!(loaded.status, "completed");
        assert_eq!(loaded.tool.as_deref(), Some("context:build"));
        assert_eq!(loaded.artifacts.len(), 1);
        let metadata =
            fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "run.json")).unwrap();
        assert!(metadata.contains("\"status\": \"completed\""));
        assert!(!run_artifact_path(tmp.path(), &run_id, "context.json").exists());
        let placeholder_report =
            fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "report.md")).unwrap();
        assert!(placeholder_report.contains("Status: completed"));
        assert!(load_run_failures(tmp.path(), &run_id)
            .unwrap()
            .failures
            .is_empty());
        assert_eq!(
            load_run_failures(tmp.path(), &run_id).unwrap().status,
            "completed"
        );
        let manifest_artifacts = load_run_artifacts(tmp.path(), &run_id).unwrap();
        assert_manifest_has(&manifest_artifacts, "run.json");
        assert_manifest_has_canonical_run_artifacts(&manifest_artifacts);
        assert_manifest_has(&manifest_artifacts, "result.json");
        let trace =
            fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "trace.jsonl")).unwrap();
        assert!(trace.contains("context:build started"));
    }

    #[test]
    fn write_run_summary_ignores_non_file_derived_snapshot_target() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-file-snapshot-marker";
        fs::create_dir_all(run_artifact_path(tmp.path(), run_id, "context.json")).unwrap();
        let summary =
            RunSummary::running(run_id, "tool", Some("context:build".to_string()), "target");

        write_run_summary(tmp.path(), &summary).unwrap();

        assert!(run_artifact_path(tmp.path(), run_id, "run.json").is_file());
    }

    #[test]
    fn write_run_summary_rejects_non_file_report_marker_target() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-file-report-marker";
        fs::create_dir_all(run_artifact_path(tmp.path(), run_id, "report.md")).unwrap();
        let summary =
            RunSummary::running(run_id, "tool", Some("report:build".to_string()), "target");

        let error = write_run_summary(tmp.path(), &summary).unwrap_err();

        assert!(error
            .to_string()
            .contains("Canonical report marker is not a file"));
        assert!(error.to_string().contains("report.md"));
    }

    #[test]
    fn write_run_summary_rejects_non_file_manifest_placeholder_target() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-file-manifest-placeholder";
        fs::create_dir_all(run_artifact_path(tmp.path(), run_id, "artifacts.json")).unwrap();
        let summary =
            RunSummary::running(run_id, "tool", Some("context:build".to_string()), "target");

        let error = write_run_summary(tmp.path(), &summary).unwrap_err();

        assert!(error
            .to_string()
            .contains("Canonical JSON artifact target is not a file"));
        assert!(error.to_string().contains("artifacts.json"));
    }

    #[test]
    fn write_run_summary_rejects_non_file_jsonl_placeholder_target() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-file-jsonl-placeholder";
        fs::create_dir_all(run_artifact_path(tmp.path(), run_id, "events.jsonl")).unwrap();
        let summary =
            RunSummary::running(run_id, "tool", Some("context:build".to_string()), "target");

        let error = write_run_summary(tmp.path(), &summary).unwrap_err();

        assert!(error
            .to_string()
            .contains("Canonical text artifact target is not a file"));
        assert!(error.to_string().contains("events.jsonl"));
    }

    #[test]
    fn write_run_summary_rejects_non_file_metadata_target() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-file-metadata";
        fs::create_dir_all(run_artifact_path(tmp.path(), run_id, "run.json")).unwrap();
        let summary =
            RunSummary::running(run_id, "tool", Some("context:build".to_string()), "target");

        let error = write_run_summary(tmp.path(), &summary).unwrap_err();

        assert!(error
            .to_string()
            .contains("Run metadata target is not a file"));
        assert!(error.to_string().contains("run.json"));
    }

    #[test]
    fn load_run_summary_rejects_non_file_run_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-load-non-file-metadata";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("context:build".to_string()), "target")
                .complete(),
        )
        .unwrap();
        let path = run_artifact_path(tmp.path(), run_id, "run.json");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();

        let error = load_run_summary(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Run metadata is not a file"));
        assert!(message.contains("run.json"));
    }

    #[test]
    fn load_run_summary_rejects_missing_run_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-load-missing-metadata";
        let dir = run_dir(tmp.path(), run_id);
        fs::create_dir_all(&dir).unwrap();

        let error = load_run_summary(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Run metadata is missing"));
        assert!(message.contains("run.json"));
    }

    #[test]
    fn load_run_summary_rejects_mismatched_metadata_run_id() {
        let target = tempfile::tempdir().unwrap();
        let requested = "run-requested";
        let path = run_artifact_path(target.path(), requested, "run.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            serde_json::to_string(&RunSummary::running("run-forged", "tool", None, "target"))
                .unwrap(),
        )
        .unwrap();

        let error = load_run_summary(target.path(), requested).unwrap_err();

        assert!(error
            .to_string()
            .contains("does not match requested run id"));
    }

    #[test]
    fn load_run_summary_rejects_non_object_run_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-load-non-object-metadata";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("context:build".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(run_artifact_path(tmp.path(), run_id, "run.json"), "[]").unwrap();

        let error = load_run_summary(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Run metadata is not a JSON object"));
        assert!(message.contains("run.json"));
    }

    #[test]
    fn write_run_summary_rejects_non_file_latest_pointer_target() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-file-latest-pointer";
        fs::create_dir_all(tmp.path().join(".kuzushi/v3/latest")).unwrap();
        let summary =
            RunSummary::running(run_id, "tool", Some("context:build".to_string()), "target");

        let error = write_run_summary(tmp.path(), &summary).unwrap_err();

        assert!(error
            .to_string()
            .contains("Latest run pointer target is not a file"));
        assert!(error.to_string().contains(".kuzushi/v3/latest"));
    }

    #[test]
    fn append_run_event_rejects_non_file_event_log_target() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-file-events";
        fs::create_dir_all(run_artifact_path(tmp.path(), run_id, "events.jsonl")).unwrap();
        let event = RunEvent::new(1, "tool", "started", "context:build");

        let error = append_run_event(tmp.path(), run_id, &event).unwrap_err();

        assert!(error
            .to_string()
            .contains("Run event log target is not a file"));
        assert!(error.to_string().contains("events.jsonl"));
    }

    #[test]
    fn append_run_trace_step_rejects_non_file_trace_target() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-file-trace";
        fs::create_dir_all(run_artifact_path(tmp.path(), run_id, "trace.jsonl")).unwrap();
        let step = RunTraceStep::new(1, "tool", "context:build");

        let error = append_run_trace_step(tmp.path(), run_id, &step).unwrap_err();

        assert!(error.to_string().contains("Run trace target is not a file"));
        assert!(error.to_string().contains("trace.jsonl"));
    }

    #[test]
    fn run_summary_with_artifact_normalizes_direct_artifact_values() {
        let summary = RunSummary::running("run-summary-artifact", "tool", None, "target")
            .with_artifact(RunArtifact {
                label: " result ".to_string(),
                path: " result.json ".to_string(),
                kind: " JSON ".to_string(),
            });

        assert_eq!(summary.artifacts.len(), 1);
        assert_eq!(summary.artifacts[0].label, "result");
        assert_eq!(summary.artifacts[0].path, "result.json");
        assert_eq!(summary.artifacts[0].kind, "json");
    }

    #[test]
    fn run_summary_with_artifact_drops_blank_direct_artifact_path() {
        let summary = RunSummary::running("run-summary-artifact", "tool", None, "target")
            .with_artifact(RunArtifact {
                label: "empty".to_string(),
                path: "   ".to_string(),
                kind: "json".to_string(),
            });

        assert!(summary.artifacts.is_empty());
    }

    #[test]
    fn final_summary_preserves_producer_owned_declared_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = new_run_id("marker-refresh");
        let summary = RunSummary::running(
            run_id.clone(),
            "tool",
            Some("context:build".to_string()),
            tmp.path().display().to_string(),
        );

        write_run_summary(tmp.path(), &summary).unwrap();
        write_run_artifact_json(
            tmp.path(),
            &run_id,
            "findings.json",
            "findings",
            &serde_json::json!({"status": "skipped", "summary": "producer-owned"}),
        )
        .unwrap();
        write_run_summary(tmp.path(), &summary.complete()).unwrap();

        let findings =
            fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "findings.json")).unwrap();

        assert!(!run_artifact_path(tmp.path(), &run_id, "context.json").exists());
        assert!(findings.contains("producer-owned"));
        assert!(!findings.contains("\"runStatus\": \"completed\""));
    }

    #[test]
    fn paused_summary_propagates_status_to_durable_run_files() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = new_run_id("paused");
        let mut summary = RunSummary::running(
            run_id.clone(),
            "shell",
            None,
            tmp.path().display().to_string(),
        );
        summary.status = "paused".to_string();

        write_run_summary(tmp.path(), &summary).unwrap();

        let metadata =
            fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "run.json")).unwrap();
        let placeholder_report =
            fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "report.md")).unwrap();
        let failures = load_run_failures(tmp.path(), &run_id).unwrap();
        let manifest_artifacts = load_run_artifacts(tmp.path(), &run_id).unwrap();

        assert!(metadata.contains("\"status\": \"paused\""));
        for leaf in [
            "context.json",
            "attack-surface.json",
            "threat-model.json",
            "recommendations.json",
            "strategy.json",
            "findings.json",
            "proof.json",
        ] {
            assert!(
                !run_artifact_path(tmp.path(), &run_id, leaf).exists(),
                "{leaf}"
            );
        }
        assert!(placeholder_report.contains("Status: paused"));
        assert_eq!(failures.status, "paused");
        assert!(failures.failures.is_empty());
        assert_manifest_has_canonical_run_artifacts(&manifest_artifacts);
    }

    #[test]
    fn canceled_summary_is_terminal_and_preserves_run_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = new_run_id("canceled");
        let summary = RunSummary::running(
            run_id.clone(),
            "shell",
            Some("sast:scan".to_string()),
            tmp.path().display().to_string(),
        )
        .with_cost(Some(0.42))
        .with_findings(Some(3))
        .canceled("operator cancel");

        write_run_summary(tmp.path(), &summary).unwrap();

        let loaded = load_run_summary(tmp.path(), &run_id).unwrap();
        let failures = load_run_failures(tmp.path(), &run_id).unwrap();
        let report =
            fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "report.md")).unwrap();
        assert_eq!(loaded.status, "canceled");
        assert_eq!(loaded.tool.as_deref(), Some("sast:scan"));
        assert_eq!(loaded.cost_usd, Some(0.42));
        assert_eq!(loaded.findings, Some(3));
        assert!(loaded.completed_at_unix.is_some());
        assert_eq!(loaded.process_id, None);
        assert_eq!(failures.status, "canceled");
        assert!(failures.failures.is_empty());
        assert!(report.contains("Status: canceled"));
    }

    #[test]
    fn invalid_summary_cost_cannot_replace_prior_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-summary-invalid-cost";
        let valid = RunSummary::running(run_id, "tool", None, "target").with_cost(Some(0.25));
        write_run_summary(tmp.path(), &valid).unwrap();

        for invalid in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let error = write_run_summary(tmp.path(), &valid.clone().with_cost(Some(invalid)))
                .unwrap_err()
                .to_string();
            assert!(error.contains("finite non-negative"), "{error}");
            assert_eq!(
                load_run_summary(tmp.path(), run_id).unwrap().cost_usd,
                Some(0.25)
            );
        }

        let mut contradictory = valid.clone().with_cost(None);
        contradictory.observed_cost_usd = Some(0.1);
        assert!(write_run_summary(tmp.path(), &contradictory).is_err());
        contradictory.provider_spend_unresolved = true;
        contradictory.cost_usd = Some(0.2);
        assert!(write_run_summary(tmp.path(), &contradictory).is_err());
    }

    #[test]
    fn invalid_llm_call_cost_is_rejected_before_summary_write() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-summary-invalid-llm-cost";
        let mut summary = RunSummary::running(run_id, "tool", None, "target");
        summary.llm_calls.push(RunLlmCallAudit {
            n: 1,
            kind: "reasoning".to_string(),
            verb: None,
            model: "openai:gpt-test".to_string(),
            provider: "openai".to_string(),
            prompt_hash: "hash".to_string(),
            latency_ms: Some(1),
            cost_usd: Some(-1.0),
            observed_cost_usd: None,
            provider_spend_unresolved: false,
            call_attempted: Some(true),
        });

        assert!(write_run_summary(tmp.path(), &summary).is_err());
        assert!(!run_artifact_path(tmp.path(), run_id, "run.json").exists());
    }

    #[test]
    fn explicitly_unattempted_llm_call_cannot_carry_spend() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-summary-unattempted-spend";
        let mut summary = RunSummary::running(run_id, "tool", None, "target");
        let mut call = valid_llm_call(Some(0.1));
        call.call_attempted = Some(false);
        summary.llm_calls.push(call);

        let error = write_run_summary(tmp.path(), &summary)
            .unwrap_err()
            .to_string();

        assert!(error.contains("explicitly unattempted"), "{error}");
        assert!(!run_artifact_path(tmp.path(), run_id, "run.json").exists());
    }

    #[test]
    fn invalid_on_disk_summary_and_llm_costs_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        for (run_id, pointer) in [
            ("invalid-summary-disk", "/costUsd"),
            ("invalid-llm-disk", "/llmCalls/0/costUsd"),
        ] {
            let mut summary = RunSummary::running(run_id, "tool", None, "target");
            summary.llm_calls.push(valid_llm_call(Some(0.0)));
            let mut value = serde_json::to_value(summary).unwrap();
            if pointer == "/costUsd" {
                value
                    .as_object_mut()
                    .unwrap()
                    .insert("costUsd".to_string(), serde_json::json!(-1.0));
            } else {
                *value.pointer_mut(pointer).unwrap() = serde_json::json!(-1.0);
            }
            let path = run_artifact_path(tmp.path(), run_id, "run.json");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();

            assert!(load_run_summary(tmp.path(), run_id).is_err());
        }
    }

    #[test]
    fn summary_cost_preserves_unavailable_exact_zero_and_incomplete_observed() {
        let tmp = tempfile::tempdir().unwrap();
        for (run_id, cost) in [
            ("summary-cost-absent", None),
            ("summary-cost-zero", Some(0.0)),
        ] {
            write_run_summary(
                tmp.path(),
                &RunSummary::running(run_id, "tool", None, "target").with_cost(cost),
            )
            .unwrap();
            assert_eq!(load_run_summary(tmp.path(), run_id).unwrap().cost_usd, cost);
        }

        let observed = RuntimeCost::from_usd(0.125, "test observed cost").unwrap();
        let incomplete = RunSummary::running("summary-cost-incomplete", "tool", None, "target")
            .with_cost_report(RuntimeCostReport::incomplete(observed));
        write_run_summary(tmp.path(), &incomplete).unwrap();
        let loaded = load_run_summary(tmp.path(), "summary-cost-incomplete").unwrap();
        assert_eq!(loaded.cost_usd, None);
        assert_eq!(loaded.observed_cost_usd, Some(0.125));
        assert!(loaded.provider_spend_unresolved);
        assert_eq!(
            loaded
                .checked_cost_report()
                .unwrap()
                .observed_usd_if_available(),
            Some(0.125)
        );
    }

    fn valid_llm_call(cost_usd: Option<f64>) -> RunLlmCallAudit {
        RunLlmCallAudit {
            n: 1,
            kind: "reasoning".to_string(),
            verb: None,
            model: "openai:gpt-test".to_string(),
            provider: "openai".to_string(),
            prompt_hash: "hash".to_string(),
            latency_ms: Some(1),
            cost_usd,
            observed_cost_usd: None,
            provider_spend_unresolved: false,
            call_attempted: Some(true),
        }
    }

    fn assert_canonical_run_files_exist(target: &Path, run_id: &str) {
        let dir = run_dir(target, run_id);
        for leaf in [
            "run.json",
            "events.jsonl",
            "trace.jsonl",
            "failures.json",
            "report.md",
            "artifacts.json",
        ] {
            assert!(dir.join(leaf).exists(), "missing canonical artifact {leaf}");
        }
    }

    fn assert_retired_snapshot_artifacts_absent(target: &Path, run_id: &str) {
        let dir = run_dir(target, run_id);
        let summary = load_run_summary(target, run_id).unwrap();
        let manifest = load_run_artifacts(target, run_id).unwrap();
        for leaf in RETIRED_SNAPSHOT_LEAVES {
            assert!(
                !dir.join(leaf).exists(),
                "retired artifact {leaf} was written"
            );
            assert!(
                !summary
                    .artifacts
                    .iter()
                    .any(|artifact| artifact.path.ends_with(leaf)),
                "summary contains retired artifact {leaf}"
            );
            assert!(
                !manifest
                    .iter()
                    .any(|artifact| artifact.path.ends_with(leaf)),
                "manifest contains retired artifact {leaf}"
            );
        }
    }

    fn assert_manifest_has(artifacts: &[RunArtifact], leaf: &str) {
        assert!(
            artifacts
                .iter()
                .any(|artifact| artifact.path.ends_with(leaf)),
            "manifest missing artifact {leaf}"
        );
    }

    fn assert_manifest_has_path(artifacts: &[RunArtifact], path: &str) {
        assert!(
            artifacts.iter().any(|artifact| artifact.path == path),
            "manifest missing artifact path {path}"
        );
    }

    fn assert_manifest_has_canonical_run_artifacts(artifacts: &[RunArtifact]) {
        for spec in CANONICAL_RUN_ARTIFACTS {
            assert!(
                artifacts.iter().any(|artifact| {
                    artifact.path.ends_with(spec.leaf)
                        && artifact.label == spec.label
                        && artifact.kind == spec.kind
                }),
                "manifest missing canonical artifact {} ({}, {})",
                spec.leaf,
                spec.label,
                spec.kind
            );
        }
    }

    fn assert_manifest_has_sarif_report_artifact(artifacts: &[RunArtifact]) {
        for spec in OPTIONAL_RUN_ARTIFACTS {
            assert!(
                artifacts.iter().any(|artifact| {
                    artifact.path.ends_with(spec.leaf)
                        && artifact.label == spec.label
                        && artifact.kind == spec.kind
                }),
                "manifest missing optional artifact {} ({}, {})",
                spec.leaf,
                spec.label,
                spec.kind
            );
        }
    }

    fn assert_manifest_has_tool_result_artifact(artifacts: &[RunArtifact]) {
        for spec in TOOL_RESULT_ARTIFACTS {
            assert!(
                artifacts.iter().any(|artifact| {
                    artifact.path.ends_with(spec.leaf)
                        && artifact.label == spec.label
                        && artifact.kind == spec.kind
                }),
                "manifest missing tool-result artifact {} ({}, {})",
                spec.leaf,
                spec.label,
                spec.kind
            );
        }
    }

    fn assert_manifest_has_tool_input_artifact(artifacts: &[RunArtifact]) {
        for spec in TOOL_INPUT_ARTIFACTS {
            assert!(
                artifacts.iter().any(|artifact| {
                    artifact.path.ends_with(spec.leaf)
                        && artifact.label == spec.label
                        && artifact.kind == spec.kind
                }),
                "manifest missing tool-input artifact {} ({}, {})",
                spec.leaf,
                spec.label,
                spec.kind
            );
        }
    }

    const RETIRED_SNAPSHOT_LEAVES: &[&str] = &[
        "context.json",
        "attack-surface.json",
        "threat-model.json",
        "strategy.json",
        "recommendations.json",
        "findings.json",
        "proof.json",
    ];

    fn runtime_platform_label() -> String {
        format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
    }

    #[test]
    fn writes_events_and_failure_handoff_context_under_run_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-failure";
        let input = write_run_artifact_json(
            tmp.path(),
            run_id,
            "input.json",
            "tool input",
            &serde_json::json!({"enrichment": true}),
        )
        .unwrap();
        append_run_event(
            tmp.path(),
            run_id,
            &RunEvent::new(1, "tool", "started", "context:build started")
                .with_tool("context:build")
                .with_artifact(input.clone()),
        )
        .unwrap();
        let failure = write_run_failures(
            tmp.path(),
            run_id,
            "context:build",
            "failed",
            "LLM enrichment is unsupported",
            &[input],
        )
        .unwrap();

        assert!(failure.path.ends_with("failures.json"));
        let manifest_artifacts = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert_manifest_has(&manifest_artifacts, "input.json");
        assert_manifest_has(&manifest_artifacts, "failures.json");
        let events =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "events.jsonl")).unwrap();
        assert!(events.contains("\"status\":\"started\""));

        let failures =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "failures.json")).unwrap();
        assert!(failures.contains("context:build did not complete successfully"));
        assert!(failures.contains("artifact-review-only"));
        assert!(failures.contains("input.json"));

        let loaded = load_run_failures(tmp.path(), run_id).unwrap();
        let context = &loaded.failures[0].agent_thread_context;
        assert_eq!(
            context.allowed_proof_level,
            "artifact-review-only; runtime verification did not run"
        );
        assert_eq!(context.failed_stage, "context:build");
        assert_eq!(context.cause, "LLM enrichment is unsupported");
        assert!(context
            .missing_artifacts
            .contains(&"trace.jsonl".to_string()));
        assert!(!context
            .missing_artifacts
            .contains(&"context.json".to_string()));
        assert!(!context
            .missing_artifacts
            .contains(&"artifacts.json".to_string()));
        assert!(context
            .recovery_options
            .iter()
            .any(|option| option.contains("context:build")));
        assert!(context
            .next_files_or_artifacts_to_inspect
            .iter()
            .any(|path| path.ends_with("failures.json")));
        assert!(context
            .next_files_or_artifacts_to_inspect
            .iter()
            .any(|path| path.ends_with("result.json")));
        assert!(context
            .next_files_or_artifacts_to_inspect
            .iter()
            .any(|path| path.ends_with("input.json")));
        assert!(context.next_files_or_artifacts_to_inspect.len() <= 12);
        assert!(context.fallback_prompt.contains("context:build"));
        assert!(context.fallback_prompt.contains("artifact-review-only"));
        assert!(context.fallback_prompt.contains("Inspect next:"));
        assert!(context.fallback_prompt.contains("failures.json"));
        assert!(context
            .claims_forbidden
            .contains(&"empirical proof claim".to_string()));
        assert_forbidden_success_claims(&context.claims_forbidden);
    }

    #[test]
    fn failure_handoff_normalizes_available_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-failure-artifact-normalization";
        let artifact = RunArtifact {
            label: " result ".to_string(),
            path: " result.json ".to_string(),
            kind: " JSON ".to_string(),
        };

        write_run_failures(
            tmp.path(),
            run_id,
            "context:build",
            "failed",
            "artifact unavailable",
            &[artifact],
        )
        .unwrap();

        let context = load_run_failure_context(tmp.path(), run_id)
            .unwrap()
            .expect("failure context");

        assert_eq!(context.artifacts_available[0].label, "result");
        assert_eq!(context.artifacts_available[0].path, "result.json");
        assert_eq!(context.artifacts_available[0].kind, "json");
        assert!(context
            .next_files_or_artifacts_to_inspect
            .contains(&"result.json".to_string()));
    }

    #[test]
    fn run_failures_offer_existing_sarif_as_optional_follow_up() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-failed-sarif";
        let dir = run_dir(tmp.path(), run_id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("report.md"), "# Failed Scan\n").unwrap();
        fs::write(dir.join("report.sarif"), r#"{"version":"2.1.0","runs":[]}"#).unwrap();

        write_run_failures(
            tmp.path(),
            run_id,
            "semgrep:scan",
            "failed",
            "scanner exited",
            &[],
        )
        .unwrap();

        let context = load_run_failure_context(tmp.path(), run_id)
            .unwrap()
            .expect("failure context");
        assert!(!context
            .missing_artifacts
            .contains(&"report.sarif".to_string()));
        assert!(!context.missing_artifacts.contains(&"report.md".to_string()));
        assert!(context
            .next_files_or_artifacts_to_inspect
            .iter()
            .any(|path| path.ends_with("report.md")));
        assert!(context
            .next_files_or_artifacts_to_inspect
            .iter()
            .any(|path| path.ends_with("report.sarif")));
    }

    #[test]
    fn run_failures_treat_non_file_canonical_artifacts_as_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-failed-non-file-artifact";
        let dir = run_dir(tmp.path(), run_id);
        fs::create_dir_all(dir.join("report.md")).unwrap();
        let declared = RunArtifact {
            label: "report".to_string(),
            path: dir.join("report.md").display().to_string(),
            kind: "markdown".to_string(),
        };

        write_run_failures(
            tmp.path(),
            run_id,
            "verify:finding",
            "failed",
            "proof artifact is invalid",
            &[declared],
        )
        .unwrap();

        let context = load_run_failure_context(tmp.path(), run_id)
            .unwrap()
            .expect("failure context");
        assert!(context.missing_artifacts.contains(&"report.md".to_string()));
        assert!(context.fallback_prompt.contains("Missing artifacts:"));
        assert!(context.fallback_prompt.contains("report.md"));
    }

    #[test]
    fn run_failures_prioritize_follow_up_files_under_inspection_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-failed-many-artifacts";
        let artifacts = (0..20)
            .map(|index| RunArtifact {
                label: format!("artifact {index}"),
                path: relative_run_artifact_path(
                    tmp.path(),
                    run_id,
                    &format!("extra-{index}.json"),
                ),
                kind: "json".to_string(),
            })
            .collect::<Vec<_>>();

        write_run_failures(
            tmp.path(),
            run_id,
            "semgrep:scan",
            "failed",
            "scanner exited",
            &artifacts,
        )
        .unwrap();

        let context = load_run_failure_context(tmp.path(), run_id)
            .unwrap()
            .expect("failure context");
        assert!(context.next_files_or_artifacts_to_inspect.len() <= 12);
        assert_eq!(context.artifacts_available.len(), 12);
        assert_eq!(context.artifacts_available[11].label, "artifact 11");
        assert!(context.next_files_or_artifacts_to_inspect[0].ends_with("failures.json"));
        assert!(context.next_files_or_artifacts_to_inspect[1].ends_with("result.json"));
        assert!(context.next_files_or_artifacts_to_inspect[2].ends_with("input.json"));
    }

    #[test]
    fn failed_tool_run_records_result_envelope_with_fallback_context() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-failed-result";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "semgrep:scan");

        record_tool_run_started(record, &serde_json::json!({"target": "."}));
        record_tool_run_failed(record, "semgrep binary missing");

        let dir = run_dir(tmp.path(), run_id);
        let result_body = fs::read_to_string(dir.join("result.json")).unwrap();
        let result = serde_json::from_str::<serde_json::Value>(&result_body).unwrap();

        assert_eq!(result["ok"], serde_json::json!(false));
        assert_eq!(result["status"], serde_json::json!("failed"));
        assert_eq!(
            result["errors"][0],
            serde_json::json!("semgrep binary missing")
        );
        assert_eq!(
            result["fallback_context"]["failedStage"],
            serde_json::json!("semgrep:scan")
        );
        assert!(result["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|artifact| artifact["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("failures.json"))));

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "failed");
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("result.json")));
        let manifest = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert_manifest_has_canonical_run_artifacts(&manifest);
        assert_manifest_has_tool_result_artifact(&manifest);
    }

    #[test]
    fn tool_run_start_records_input_summary_event_and_trace() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-start";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "context:build");

        record_tool_run_started(record, &serde_json::json!({"target": "."}));

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "running");
        assert_eq!(summary.tool.as_deref(), Some("context:build"));
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("input.json")));
        let manifest_artifacts = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert_manifest_has(&manifest_artifacts, "run.json");
        assert_manifest_has_tool_input_artifact(&manifest_artifacts);
        let events =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "events.jsonl")).unwrap();
        assert!(events.contains("\"status\":\"started\""));
        assert!(events.contains("\"artifact\""));
        let trace =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "trace.jsonl")).unwrap();
        assert!(trace.contains("context:build started"));
    }

    #[test]
    fn tool_run_complete_keeps_domain_snapshots_inside_result_json() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-snapshots";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "context:build");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "summary": "snapshots ready",
                "recommendations": [{"tool": "semgrep:scan"}],
                "data": {
                    "snapshot": {
                        "repoContext": {"languages": ["Rust"]},
                        "attackSurfaceMap": {
                            "summary": {
                                "total": 2,
                                "byKind": {"file_upload_parse_path": 1, "http_route": 1}
                            },
                            "surfaces": [
                                {"kind": "http_route", "path": "/login"},
                                {"kind": "file_upload_parse_path", "path": "/upload"}
                            ]
                        }
                    },
                    "document": {"methodology": "STRIDE"},
                    "findings": [{"ruleId": "demo"}],
                    "proof": {"states": ["code_cited"]},
                    "reportMarkdown": "# Snapshot Report",
                    "reportSarif": {"version": "2.1.0", "runs": []}
                }
            }),
        );

        let dir = run_dir(tmp.path(), run_id);
        let result =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&result).unwrap();

        assert_eq!(
            output["data"]["snapshot"]["repoContext"]["languages"],
            serde_json::json!(["Rust"])
        );
        assert_eq!(
            output["data"]["snapshot"]["attackSurfaceMap"]["surfaces"][1]["path"],
            serde_json::json!("/upload")
        );
        assert_eq!(
            output["data"]["document"]["methodology"],
            serde_json::json!("STRIDE")
        );
        assert_eq!(
            output["recommendations"][0]["tool"],
            serde_json::json!("semgrep:scan")
        );
        assert_eq!(
            output["data"]["findings"][0]["ruleId"],
            serde_json::json!("demo")
        );
        assert_eq!(
            output["data"]["proof"]["states"][0],
            serde_json::json!("code_cited")
        );
        assert!(fs::read_to_string(dir.join("report.md"))
            .unwrap()
            .contains("Snapshot Report"));
        assert!(fs::read_to_string(dir.join("report.sarif"))
            .unwrap()
            .contains("\"version\": \"2.1.0\""));
        assert_retired_snapshot_artifacts_absent(tmp.path(), run_id);

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("report.md")));
        assert!(summary.artifacts.iter().any(|artifact| {
            artifact.path.ends_with("report.sarif") && artifact.kind == "sarif"
        }));
        assert!(summary.artifacts.iter().any(|artifact| {
            artifact.path.ends_with("report.sarif") && artifact.label == "SARIF report"
        }));

        let manifest_artifacts = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert_manifest_has_sarif_report_artifact(&manifest_artifacts);
    }

    #[test]
    fn try_tool_complete_surfaces_report_write_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-report-write-failure";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "report:build");
        try_record_tool_run_started_with_reproducibility(
            record,
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let report = run_artifact_path(tmp.path(), run_id, "report.md");
        fs::remove_file(&report).unwrap();
        fs::create_dir(&report).unwrap();

        let error = try_record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "data": {"reportMarkdown": "# Report"}
            }),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("report.md"), "{error}");
        assert_eq!(
            load_run_summary(tmp.path(), run_id).unwrap().status,
            "running"
        );
    }

    #[test]
    fn try_tool_complete_surfaces_declared_artifact_manifest_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-manifest-write-failure";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "context:build");
        try_record_tool_run_started_with_reproducibility(
            record,
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let manifest = run_artifact_path(tmp.path(), run_id, "artifacts.json");
        fs::remove_file(&manifest).unwrap();
        fs::create_dir(&manifest).unwrap();

        let error = try_record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "artifacts": [{"path": "evidence.json", "label": "evidence"}]
            }),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("artifacts.json"), "{error}");
        assert_eq!(
            load_run_summary(tmp.path(), run_id).unwrap().status,
            "running"
        );
    }

    #[test]
    fn repeated_terminalization_is_idempotent_and_does_not_duplicate_events() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-idempotent-terminal";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "context:build");
        let output = serde_json::json!({
            "ok": true,
            "status": "completed",
            "summary": "done",
            "data": {}
        });
        try_record_tool_run_started_with_reproducibility(
            record,
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();

        try_record_tool_run_complete(record, &output).unwrap();
        try_record_tool_run_complete(record, &output).unwrap();

        let events =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "events.jsonl")).unwrap();
        let terminal_events = events
            .lines()
            .filter(|line| line.contains("\"status\":\"completed\""))
            .count();
        let trace =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "trace.jsonl")).unwrap();
        assert_eq!(terminal_events, 1, "{events}");
        assert_eq!(
            trace.matches("context:build complete").count(),
            1,
            "{trace}"
        );
    }

    #[test]
    fn same_status_retry_rejects_different_result_content() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-divergent-terminal";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "context:build");
        record_tool_run_started(record, &serde_json::json!({}));
        try_record_tool_run_complete(
            record,
            &serde_json::json!({"ok": true, "status": "completed", "data": {"value": 1}}),
        )
        .unwrap();

        let error = try_record_tool_run_complete(
            record,
            &serde_json::json!({"ok": true, "status": "completed", "data": {"value": 2}}),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("different result content"), "{error}");
        let result: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(result.pointer("/data/value"), Some(&serde_json::json!(1)));
    }

    #[test]
    fn concurrent_same_status_terminalizations_commit_only_one_result() {
        let tmp = tempfile::tempdir().unwrap();
        let target = Arc::new(tmp.path().to_path_buf());
        let run_id = "tool-concurrent-result";
        record_tool_run_started(
            ToolRunRecord::new(target.as_path(), run_id, "tool", "context:build"),
            &serde_json::json!({}),
        );
        let barrier = Arc::new(Barrier::new(2));
        let handles = [1, 2].map(|value| {
            let target = Arc::clone(&target);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                try_record_tool_run_complete(
                    ToolRunRecord::new(target.as_path(), run_id, "tool", "context:build"),
                    &serde_json::json!({
                        "ok": true,
                        "status": "completed",
                        "data": {"value": value}
                    }),
                )
            })
        });

        let outcomes = handles.map(|handle| handle.join().unwrap());

        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert!(outcomes
            .iter()
            .filter_map(|outcome| outcome.as_ref().err())
            .any(|error| error.to_string().contains("different result content")));
        let events = load_run_events(target.as_path(), run_id).unwrap();
        assert_eq!(
            events
                .events
                .iter()
                .filter(|event| event.status == "completed")
                .count(),
            1
        );
    }

    #[test]
    fn terminalization_rejects_missing_invalid_and_non_file_run_metadata() {
        for corruption in ["missing", "invalid", "non-file"] {
            let tmp = tempfile::tempdir().unwrap();
            let run_id = format!("tool-terminal-{corruption}");
            let record = ToolRunRecord::new(tmp.path(), &run_id, "tool", "context:build");
            record_tool_run_started(record, &serde_json::json!({}));
            let metadata = run_artifact_path(tmp.path(), &run_id, "run.json");
            fs::remove_file(&metadata).unwrap();
            match corruption {
                "invalid" => fs::write(&metadata, "{").unwrap(),
                "non-file" => fs::create_dir(&metadata).unwrap(),
                _ => {}
            }

            let error = try_record_tool_run_complete(
                record,
                &serde_json::json!({"ok": true, "status": "completed"}),
            )
            .unwrap_err()
            .to_string();

            assert!(error.contains("terminal state"), "{corruption}: {error}");
            assert!(error.contains("run.json"), "{corruption}: {error}");
        }
    }

    #[test]
    fn concurrent_conflicting_terminalizations_commit_exactly_one_truth() {
        let tmp = tempfile::tempdir().unwrap();
        let target = Arc::new(tmp.path().to_path_buf());
        let run_id = "tool-concurrent-terminal";
        let record = ToolRunRecord::new(target.as_path(), run_id, "tool", "context:build");
        try_record_tool_run_started_with_reproducibility(
            record,
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let completed_target = Arc::clone(&target);
        let completed_barrier = Arc::clone(&barrier);
        let completed = std::thread::spawn(move || {
            completed_barrier.wait();
            try_record_tool_run_complete(
                ToolRunRecord::new(completed_target.as_path(), run_id, "tool", "context:build"),
                &serde_json::json!({"ok": true, "status": "completed", "data": {}}),
            )
        });
        let failed_target = Arc::clone(&target);
        let failed_barrier = Arc::clone(&barrier);
        let failed = std::thread::spawn(move || {
            failed_barrier.wait();
            try_record_tool_run_failed(
                ToolRunRecord::new(failed_target.as_path(), run_id, "tool", "context:build"),
                "boom",
            )
        });

        let outcomes = [completed.join().unwrap(), failed.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        let summary = load_run_summary(target.as_path(), run_id).unwrap();
        assert!(matches!(summary.status.as_str(), "completed" | "failed"));
        let events = load_run_events(target.as_path(), run_id).unwrap();
        let terminals = events
            .events
            .iter()
            .filter(|event| matches!(event.status.as_str(), "completed" | "failed"))
            .collect::<Vec<_>>();
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0].status, summary.status);
    }

    #[test]
    fn repeated_terminalization_repairs_missing_result_and_trace_without_duplicate_event() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-repair-terminal";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "context:build");
        let output = serde_json::json!({
            "ok": true,
            "status": "completed",
            "summary": "done",
            "data": {}
        });
        try_record_tool_run_started_with_reproducibility(
            record,
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        try_record_tool_run_complete(record, &output).unwrap();

        fs::remove_file(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let trace_path = run_artifact_path(tmp.path(), run_id, "trace.jsonl");
        let trace = fs::read_to_string(&trace_path).unwrap();
        let trace_without_terminal = trace
            .lines()
            .filter(|line| !line.contains("context:build complete"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&trace_path, format!("{trace_without_terminal}\n")).unwrap();

        try_record_tool_run_complete(record, &output).unwrap();

        assert!(run_artifact_path(tmp.path(), run_id, "result.json").is_file());
        let events =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "events.jsonl")).unwrap();
        let trace = fs::read_to_string(trace_path).unwrap();
        assert_eq!(
            events.matches("\"status\":\"completed\"").count(),
            1,
            "{events}"
        );
        assert_eq!(
            trace.matches("context:build complete").count(),
            1,
            "{trace}"
        );
    }

    #[test]
    fn tool_run_complete_rejects_snake_case_report_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-snake-report";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "report:build");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "data": {
                    "report_markdown": "# Snake Report",
                    "report_sarif": {"version": "2.1.0", "runs": [{"results": []}]}
                }
            }),
        );

        let dir = run_dir(tmp.path(), run_id);
        let report = fs::read_to_string(dir.join("report.md")).unwrap();
        assert!(report.contains("No report was recorded for this run."));
        assert!(!report.contains("Snake Report"));
        assert!(!dir.join("report.sarif").exists());

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert!(!summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("report.sarif")));

        let manifest_artifacts = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert!(!manifest_artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("report.sarif")));
    }

    #[test]
    fn tool_run_complete_keeps_core_findings_inside_result_json() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-core-findings";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "dep-hygiene:check");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "data": {
                    "verification": {"verified": 0, "results": []},
                    "findings": [{"packageName": "lodash"}],
                    "coreFindings": [{
                        "fingerprint": "dep-fp",
                        "tool": "dep-hygiene",
                        "ruleId": "dep-hygiene/package-json",
                        "filePath": "package.json",
                        "startLine": 1,
                        "staticProofState": "signal_only"
                    }]
                }
            }),
        );

        let body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(
            output["data"]["coreFindings"][0]["fingerprint"],
            serde_json::json!("dep-fp")
        );
        assert_eq!(
            output["data"]["coreFindings"][0]["tool"],
            serde_json::json!("dep-hygiene")
        );
        assert_eq!(
            output["data"]["findings"][0]["packageName"],
            serde_json::json!("lodash")
        );
        assert_eq!(
            output["data"]["coreFindings"][0]["staticProofState"],
            serde_json::json!("signal_only")
        );
        assert_retired_snapshot_artifacts_absent(tmp.path(), run_id);
    }

    #[test]
    fn tool_run_complete_keeps_root_core_findings_inside_result_json() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-root-core-findings";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "codeql:scan");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "coreFindings": [{
                    "fingerprint": "codeql-fp",
                    "tool": "codeql",
                    "ruleId": "js/sql-injection",
                    "filePath": "src/app.ts",
                    "startLine": 7,
                    "staticProofState": "source_sink_linked"
                }]
            }),
        );

        let body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&body).unwrap();
        assert_eq!(
            output["coreFindings"][0]["fingerprint"],
            serde_json::json!("codeql-fp")
        );
        assert_eq!(
            output["coreFindings"][0]["filePath"],
            serde_json::json!("src/app.ts")
        );
        assert_retired_snapshot_artifacts_absent(tmp.path(), run_id);
    }

    #[test]
    fn tool_run_complete_ignores_obsolete_proof_state_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-proof-state-alias";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "sast:scan");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "data": {
                    "coreFindings": [
                        {"fingerprint": "a", "tool": "sast", "proofState": "execution_confirmed"},
                        {"fingerprint": "b", "tool": "sast", "proof_state": "code_cited"},
                        {"fingerprint": "c", "tool": "sast", "proof_state": "code-cited"}
                    ]
                }
            }),
        );

        assert!(
            !run_artifact_path(tmp.path(), run_id, "proof.json").exists(),
            "obsolete proof aliases must not create derived proof exports"
        );
    }

    #[test]
    fn tool_run_complete_keeps_runtime_proof_states_inside_result_json() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-runtime-proof-state";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "verify:finding");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "data": {
                    "coreFindings": [
                        {"fingerprint": "reviewed", "tool": "verify", "staticProofState": "runtime_reviewed"},
                        {"fingerprint": "attempted", "tool": "verify", "staticProofState": "execution_attempted"},
                        {"fingerprint": "rejected", "tool": "verify", "staticProofState": "execution_rejected"}
                    ]
                }
            }),
        );

        let body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(
            output["data"]["coreFindings"][0]["staticProofState"],
            serde_json::json!("runtime_reviewed")
        );
        assert_eq!(
            output["data"]["coreFindings"][1]["staticProofState"],
            serde_json::json!("execution_attempted")
        );
        assert_eq!(
            output["data"]["coreFindings"][2]["staticProofState"],
            serde_json::json!("execution_rejected")
        );
        assert_retired_snapshot_artifacts_absent(tmp.path(), run_id);
    }

    #[test]
    fn tool_run_complete_keeps_nested_properties_proof_state_inside_result_json() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-proof-state-properties";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "codeql:scan");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "data": {
                    "coreFindings": [
                        {
                            "fingerprint": "codeql-a",
                            "tool": "codeql",
                            "ruleId": "js/sql-injection",
                            "filePath": "src/app.ts",
                            "staticProofState": "source-sink-linked"
                        },
                        {
                            "fingerprint": "codeql-b",
                            "tool": "codeql",
                            "ruleId": "js/xss",
                            "filePath": "src/app.ts",
                            "properties": {"proof_state": "runtime_confirmed"}
                        }
                    ]
                }
            }),
        );

        let body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(
            output["data"]["coreFindings"][0]["staticProofState"],
            serde_json::json!("source-sink-linked")
        );
        assert_eq!(
            output["data"]["coreFindings"][1]["properties"]["proof_state"],
            serde_json::json!("runtime_confirmed")
        );
        assert_retired_snapshot_artifacts_absent(tmp.path(), run_id);
    }

    #[test]
    fn tool_run_complete_keeps_root_proof_inside_result_json() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-root-proof";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "verify:finding");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "proof": {
                    "proofLevel": 3,
                    "proofVerdict": "needs-runtime-evidence"
                }
            }),
        );

        let body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(output["proof"]["proofLevel"], serde_json::json!(3));
        assert_eq!(
            output["proof"]["proofVerdict"],
            serde_json::json!("needs-runtime-evidence")
        );
        assert_retired_snapshot_artifacts_absent(tmp.path(), run_id);
    }

    #[test]
    fn tool_run_complete_ignores_root_verification_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-root-verification";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "verify:finding");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "verification": {
                    "verified": 1,
                    "results": [{"findingId": "F-1", "verdict": "confirmed"}]
                }
            }),
        );

        assert!(
            !run_artifact_path(tmp.path(), run_id, "proof.json").exists(),
            "root verification aliases must not create derived proof exports"
        );
    }

    #[test]
    fn tool_run_complete_ignores_snake_case_verification_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-snake-verification";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "verify:finding");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "verification": {
                    "verified_count": 1,
                    "verification_results": [{"finding_id": "F-1", "verdict": "confirmed"}]
                }
            }),
        );

        assert!(
            !run_artifact_path(tmp.path(), run_id, "proof.json").exists(),
            "snake_case verification aliases must not create derived proof exports"
        );
    }

    #[test]
    fn tool_run_complete_keeps_root_recommendation_report_inside_result_json() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-recommendations";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "module-recommender:recommend");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "summary": "2 recommendations for /repo",
                "target": "/repo",
                "signals": {
                    "sourceFiles": 12,
                    "languages": ["Python"],
                    "frameworks": ["Falcon", "Litestar", "Sanic"],
                    "attackSurfaceHighRisk": 2
                },
                "capabilities": {
                    "availableToolCount": 5,
                    "recommendedToolCount": 2,
                    "skippedMissingTools": []
                },
                "recommendations": [
                    {
                        "moduleId": "semgrep",
                        "tool": "threat-model:build",
                        "priority": "medium",
                        "reason": "attack-surface signals exist",
                        "signals": ["frameworks: Falcon, Litestar, Sanic"],
                        "requiresRuntime": false,
                        "nextInput": {"target": "/repo"}
                    }
                ],
                "warnings": [],
                "errors": []
            }),
        );

        let body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(
            output["summary"],
            serde_json::json!("2 recommendations for /repo")
        );
        assert_eq!(output["signals"]["sourceFiles"], serde_json::json!(12));
        assert_eq!(
            output["capabilities"]["availableToolCount"],
            serde_json::json!(5)
        );
        assert_eq!(
            output["recommendations"][0]["tool"],
            serde_json::json!("threat-model:build")
        );
        assert_eq!(
            output["recommendations"][0]["signals"][0],
            serde_json::json!("frameworks: Falcon, Litestar, Sanic")
        );
        assert_retired_snapshot_artifacts_absent(tmp.path(), run_id);
    }

    #[test]
    fn tool_run_complete_rejects_snake_case_recommendation_report() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-snake-recommendations";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "module-recommender:recommend");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "data": {
                    "recommendation_report": {
                        "summary": "1 recommendation for /repo",
                        "target": "/repo",
                        "signals": {"source_files": 3},
                        "capabilities": {
                            "available_tool_count": 4,
                            "recommended_tool_count": 1,
                            "skipped_missing_tools": []
                        },
                        "recommendations": [{
                            "module_id": "semgrep",
                            "tool": "semgrep:scan",
                            "priority": "high",
                            "reason": "source files are present",
                            "signals": ["3 source files"],
                            "requires_runtime": false,
                            "next_input": {"target": "/repo"}
                        }],
                        "warnings": [],
                        "errors": []
                    }
                }
            }),
        );

        assert!(
            !run_artifact_path(tmp.path(), run_id, "recommendations.json").exists(),
            "snake_case recommendation aliases must not create derived recommendation exports"
        );
    }

    #[test]
    fn tool_run_complete_keeps_data_wrapped_recommendation_report_inside_result_json() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-data-recommendations";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "module-recommender:recommend");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "data": {
                    "summary": "1 recommendation for /repo",
                    "target": "/repo",
                    "signals": {"frameworks": ["Falcon", "Litestar", "Sanic"]},
                    "capabilities": {
                        "availableToolCount": 4,
                        "recommendedToolCount": 1,
                        "skippedMissingTools": []
                    },
                    "recommendations": [{
                        "moduleId": "threat-model",
                        "tool": "threat-model:build",
                        "priority": "medium",
                        "reason": "framework route signals are present",
                        "signals": ["frameworks: Falcon, Litestar, Sanic"],
                        "requiresRuntime": false,
                        "nextInput": {"target": "/repo"}
                    }],
                    "warnings": [],
                    "errors": []
                }
            }),
        );

        let body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(
            output["data"]["summary"],
            serde_json::json!("1 recommendation for /repo")
        );
        assert_eq!(
            output["data"]["signals"]["frameworks"],
            serde_json::json!(["Falcon", "Litestar", "Sanic"])
        );
        assert_eq!(
            output["data"]["recommendations"][0]["signals"][0],
            serde_json::json!("frameworks: Falcon, Litestar, Sanic")
        );
        assert_retired_snapshot_artifacts_absent(tmp.path(), run_id);
    }

    #[test]
    fn tool_run_complete_records_output_declared_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-declared-artifacts";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "sast:scan");
        let report = tmp.path().join("report.md");
        let analysis_json = tmp.path().join("analysis.json");
        fs::write(&report, "# Report\n").unwrap();
        fs::write(&analysis_json, "{}\n").unwrap();

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "artifacts": [
                    {"label": "report", "path": report.display().to_string(), "kind": "markdown"}
                ],
                "data": {
                    "artifacts": {
                        "analysis": analysis_json.display().to_string()
                    }
                }
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert!(summary.artifacts.iter().any(|artifact| {
            artifact.label == "report" && artifact.path == report.display().to_string()
        }));
        assert!(summary.artifacts.iter().any(|artifact| {
            artifact.label == "analysis" && artifact.path == analysis_json.display().to_string()
        }));
        let manifest = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert!(manifest
            .iter()
            .any(|artifact| artifact.path == report.display().to_string()));
        assert!(manifest
            .iter()
            .any(|artifact| artifact.path == analysis_json.display().to_string()));
    }

    #[test]
    fn tool_run_complete_preserves_existing_artifact_metadata_for_duplicate_output_path() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-declared-duplicate-artifact";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "sast:scan");

        record_tool_run_started(record, &serde_json::json!({}));
        let artifact = write_run_artifact_json(
            tmp.path(),
            run_id,
            "sast-summary.json",
            "sast summary",
            &serde_json::json!({"ok": true}),
        )
        .unwrap();
        let summary = load_run_summary(tmp.path(), run_id)
            .unwrap()
            .with_artifact(artifact.clone());
        write_run_summary(tmp.path(), &summary).unwrap();

        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "data": {"artifacts": {"summary": artifact.path.clone()}}
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert!(summary.artifacts.iter().any(|recorded| {
            recorded.path == artifact.path && recorded.label == "sast summary"
        }));
        let manifest = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert!(manifest.iter().any(|recorded| {
            recorded.path == artifact.path && recorded.label == "sast summary"
        }));
    }

    #[test]
    fn tool_run_complete_records_canonical_declared_artifact_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-declared-canonical-artifacts";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "sast:scan");
        let report_json = tmp.path().join("report.json");
        let prompts_dir = tmp.path().join("prompts");
        fs::write(&report_json, "{}\n").unwrap();
        fs::create_dir(&prompts_dir).unwrap();

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "artifacts": [
                    {
                        "label": " report json ",
                        "path": report_json.display().to_string(),
                        "kind": " JSON "
                    }
                ],
                "data": {
                    "artifacts": {
                        "prompts": {
                            "label": " prompt overrides ",
                            "path": prompts_dir.display().to_string(),
                            "kind": " Directory "
                        }
                    }
                }
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert!(summary.artifacts.iter().any(|artifact| {
            artifact.label == "report json"
                && artifact.path == report_json.display().to_string()
                && artifact.kind == "json"
        }));
        assert!(summary.artifacts.iter().any(|artifact| {
            artifact.label == "prompt overrides"
                && artifact.path == prompts_dir.display().to_string()
                && artifact.kind == "directory"
        }));
        let manifest = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert_manifest_has_path(&manifest, &report_json.display().to_string());
        assert_manifest_has_path(&manifest, &prompts_dir.display().to_string());
    }

    #[test]
    fn tool_run_complete_records_contract_complete_result_envelope() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-result-envelope";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "context:build");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(record, &serde_json::json!({"ok": true}));

        let result =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&result).unwrap();

        assert_eq!(output["ok"], serde_json::json!(true));
        assert_eq!(output["status"], serde_json::json!("completed"));
        assert_eq!(output["summary"], serde_json::json!("tool completed"));
        assert!(output["artifacts"].as_array().is_some());
        assert!(output["warnings"].as_array().unwrap().is_empty());
        assert!(output["errors"].as_array().unwrap().is_empty());
        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert!(summary.artifacts.iter().any(|artifact| {
            artifact.path.ends_with("result.json")
                && artifact.label == "tool result"
                && artifact.kind == "json"
        }));
        let manifest = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert_manifest_has_canonical_run_artifacts(&manifest);
        assert_manifest_has_tool_result_artifact(&manifest);
    }

    #[test]
    fn skipped_tool_result_preserves_skipped_status_without_failure_handoff() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-skipped";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "semgrep:scan");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "skipped",
                "summary": "scanner disabled by task policy",
                "warnings": [],
                "errors": [],
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "skipped");
        assert_eq!(
            summary.error.as_deref(),
            Some("scanner disabled by task policy")
        );
        let failures = load_run_failures(tmp.path(), run_id).unwrap();
        assert_eq!(failures.status, "skipped");
        assert!(failures.failures.is_empty());
        let manifest = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert_manifest_has_canonical_run_artifacts(&manifest);
        assert_manifest_has_tool_result_artifact(&manifest);
    }

    #[test]
    fn partial_tool_result_writes_failure_handoff_and_warn_trace() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-partial";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "semgrep:scan");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "partial",
                "summary": "semgrep binary missing",
                "warnings": ["scanner unavailable"],
                "fallbackContext": {"legacy": true},
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "partial");
        assert_eq!(summary.error.as_deref(), Some("semgrep binary missing"));
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("failures.json")));
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("result.json")));
        let manifest = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert_manifest_has_canonical_run_artifacts(&manifest);
        assert_manifest_has_tool_result_artifact(&manifest);
        let failures =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "failures.json")).unwrap();
        assert!(failures.contains("semgrep:scan did not complete successfully"));
        let result =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&result).unwrap();
        assert_eq!(
            output["fallback_context"]["failedStage"],
            serde_json::json!("semgrep:scan")
        );
        assert!(output["fallback_context"]["claimsForbidden"]
            .as_array()
            .unwrap()
            .iter()
            .any(|claim| claim == "verified claim"));
        let trace =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "trace.jsonl")).unwrap();
        assert!(trace.contains("\"kind\":\"tool-progress\""));
        assert!(trace.contains("\"severity\":\"warn\""));
    }

    #[test]
    fn tool_run_failed_status_writes_failure_handoff() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-status-alias";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "semgrep:scan");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": false,
                "status": "failed",
                "summary": "scanner failed",
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "failed");
        assert_eq!(summary.error.as_deref(), Some("scanner failed"));
        let result =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&result).unwrap();
        assert_eq!(output["status"], serde_json::json!("failed"));
        assert_eq!(output["errors"][0], serde_json::json!("scanner failed"));
        let failures = load_run_failures(tmp.path(), run_id).unwrap();
        assert_eq!(failures.status, "failed");
        assert_eq!(
            failures.failures[0].agent_thread_context.failed_stage,
            "semgrep:scan"
        );
    }

    #[test]
    fn completed_tool_summary_preserves_incomplete_observed_result_cost() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-completed-incomplete-cost";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "triage:run");
        record_tool_run_started(record, &serde_json::json!({}));

        try_record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "observedCostUsd": 0.125,
                "providerSpendUnresolved": true,
                "data": {
                    "observedCostUsd": 0.125,
                    "providerSpendUnresolved": true
                }
            }),
        )
        .unwrap();

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.cost_usd, None);
        assert_eq!(summary.observed_cost_usd, Some(0.125));
        assert!(summary.provider_spend_unresolved);
        let (_, body) = read_run_artifact_text(tmp.path(), run_id, "run.json")
            .require("Run metadata")
            .unwrap();
        assert!(body.contains("\"observedCostUsd\": 0.125"));
        assert!(body.contains("\"providerSpendUnresolved\": true"));
    }

    #[test]
    fn failed_tool_summary_uses_exact_costed_model_steps_from_its_trace() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-failed-costed-trace";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "triage:run");
        record_tool_run_started(record, &serde_json::json!({}));
        append_terminal_model_trace(tmp.path(), run_id, 1, Some(0.01));
        append_terminal_model_trace(tmp.path(), run_id, 2, Some(0.02));

        try_record_tool_run_failed(record, "provider parse failed").unwrap();

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert!((summary.cost_usd.unwrap() - 0.03).abs() < 1e-9);
        let trace = load_run_trace(tmp.path(), run_id).unwrap();
        assert_eq!(
            trace
                .steps
                .iter()
                .filter_map(|step| step.cost_usd)
                .sum::<f64>(),
            0.03
        );
    }

    #[test]
    fn canceled_tool_summary_uses_exact_trace_cost_without_terminal_double_count() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-canceled-costed-trace";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "triage:run");
        record_tool_run_started(record, &serde_json::json!({}));
        append_model_preflight_trace(tmp.path(), run_id, 1);
        append_terminal_model_trace(tmp.path(), run_id, 1, Some(0.04));

        try_record_tool_run_canceled(record, "operator canceled").unwrap();

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.cost_usd, Some(0.04));
        let trace = load_run_trace(tmp.path(), run_id).unwrap();
        assert_eq!(
            trace.steps.iter().filter_map(|step| step.cost_usd).count(),
            1,
            "terminal trace must not repeat the derived cost"
        );
    }

    #[test]
    fn canceled_tool_summary_preserves_incomplete_trace_subtotal() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-canceled-incomplete-trace";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "triage:run");
        record_tool_run_started(record, &serde_json::json!({}));
        append_terminal_model_trace(tmp.path(), run_id, 1, Some(0.04));
        append_terminal_model_trace(tmp.path(), run_id, 2, None);

        try_record_tool_run_canceled(record, "operator canceled").unwrap();

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.cost_usd, None);
        assert_eq!(summary.observed_cost_usd, Some(0.04));
        assert!(summary.provider_spend_unresolved);
    }

    #[test]
    fn failed_tool_distinguishes_pre_runtime_from_incomplete_trace_cost() {
        let tmp = tempfile::tempdir().unwrap();
        for (run_id, add_unpriced_call) in [("pre-runtime", false), ("unpriced", true)] {
            let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "triage:run");
            record_tool_run_started(record, &serde_json::json!({}));
            if add_unpriced_call {
                append_terminal_model_trace(tmp.path(), run_id, 1, Some(0.02));
                append_terminal_model_trace(tmp.path(), run_id, 2, None);
            }
            try_record_tool_run_failed(record, "failed").unwrap();
            let summary = load_run_summary(tmp.path(), run_id).unwrap();
            assert_eq!(summary.cost_usd, None);
            if add_unpriced_call {
                assert_eq!(summary.observed_cost_usd, Some(0.02));
                assert!(summary.provider_spend_unresolved);
            } else {
                assert_eq!(summary.observed_cost_usd, None);
                assert!(!summary.provider_spend_unresolved);
                assert!(summary.checked_cost_report().unwrap().is_unavailable());
            }
        }
    }

    #[test]
    fn trace_cost_overflow_refuses_terminal_summary_persistence() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-trace-cost-overflow";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "triage:run");
        record_tool_run_started(record, &serde_json::json!({}));
        append_terminal_model_trace(tmp.path(), run_id, 1, Some(f64::MAX));
        append_terminal_model_trace(tmp.path(), run_id, 2, Some(f64::MAX));

        let error = try_record_tool_run_failed(record, "failed")
            .unwrap_err()
            .to_string();

        assert!(error.contains("could not add"), "{error}");
        assert_eq!(
            load_run_summary(tmp.path(), run_id).unwrap().status,
            "running"
        );
    }

    #[test]
    fn tool_result_rejects_negative_cost_before_summary_persistence() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-invalid-result-cost";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "triage:run");
        record_tool_run_started(record, &serde_json::json!({}));

        let error = try_record_tool_run_complete(
            record,
            &serde_json::json!({"ok": true, "costUsd": -0.01}),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("finite non-negative"), "{error}");
        assert_eq!(
            load_run_summary(tmp.path(), run_id).unwrap().status,
            "running"
        );
    }

    fn append_terminal_model_trace(target: &Path, run_id: &str, n: usize, cost_usd: Option<f64>) {
        append_run_trace_step_with_next_number(
            target,
            run_id,
            &RunTraceStep::new(n, "reasoning", format!("model call {n}"))
                .with_latency_ms(Some(1))
                .with_model_metadata("openai:gpt-test", "openai", format!("hash-{n}"))
                .with_cost_usd(cost_usd),
        )
        .unwrap();
    }

    fn append_model_preflight_trace(target: &Path, run_id: &str, n: usize) {
        append_run_trace_step_with_next_number(
            target,
            run_id,
            &RunTraceStep::new(n, "tool-progress", "tool-loop preflight ok")
                .with_verb("next-step")
                .with_latency_ms(Some(1))
                .with_model_metadata("openai:gpt-test", "openai", format!("hash-{n}")),
        )
        .unwrap();
    }

    #[test]
    fn ok_false_tool_result_writes_failure_handoff_without_explicit_status() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-ok-false";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "semgrep:scan");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": false,
                "summary": "scanner failed",
                "errors": ["scanner missing"],
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "failed");
        assert_eq!(summary.error.as_deref(), Some("scanner missing"));
        let failures = load_run_failures(tmp.path(), run_id).unwrap();
        assert_eq!(failures.status, "failed");
        assert_eq!(failures.failures[0].error, "scanner missing");
        let result =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&result).unwrap();
        assert_eq!(
            output["fallback_context"]["failedStage"],
            serde_json::json!("semgrep:scan")
        );
    }

    #[test]
    fn lists_run_summaries_sorted_and_ignores_incomplete_entries() {
        let tmp = tempfile::tempdir().unwrap();

        assert!(list_run_summaries(tmp.path()).unwrap().is_empty());

        let mut first = RunSummary::running("run-a", "scan", None, "target-a").complete();
        first.started_at_unix = 100;
        let mut second =
            RunSummary::running("run-b", "tool", Some("ctx:build".to_string()), "target-b")
                .complete();
        second.started_at_unix = 200;
        write_run_summary(tmp.path(), &first).unwrap();
        write_run_summary(tmp.path(), &second).unwrap();

        let root = runs_root(tmp.path());
        fs::write(root.join("not-a-run"), "ignored").unwrap();
        fs::create_dir_all(root.join("missing-summary")).unwrap();
        fs::create_dir_all(root.join("invalid-run-metadata")).unwrap();
        fs::write(root.join("invalid-run-metadata").join("run.json"), "{").unwrap();
        fs::create_dir_all(root.join("run-c")).unwrap();
        let mut third = RunSummary::running("run-c", "tool", None, "target-c");
        third.started_at_unix = 300;
        fs::write(
            root.join("run-c").join("run.json"),
            serde_json::to_string(&third).unwrap(),
        )
        .unwrap();
        assert_eq!(load_run_summary(tmp.path(), "run-c").unwrap().kind, "tool");

        let run_ids = list_run_summaries(tmp.path())
            .unwrap()
            .into_iter()
            .map(|summary| summary.run_id)
            .collect::<Vec<_>>();

        assert_eq!(run_ids, vec!["run-c", "run-b", "run-a"]);
    }

    #[test]
    fn run_summary_pages_preserve_canonical_order_and_issue_visibility() {
        let tmp = tempfile::tempdir().unwrap();
        for (run_id, started_at) in [("run-a", 100), ("run-b", 200), ("run-c", 300)] {
            let mut summary = RunSummary::running(run_id, "tool", None, "target").complete();
            summary.started_at_unix = started_at;
            write_run_summary(tmp.path(), &summary).unwrap();
        }
        fs::create_dir_all(runs_root(tmp.path()).join("broken-run")).unwrap();

        let first = list_run_summary_entries_page(tmp.path(), 0, 2).unwrap();
        let second = list_run_summary_entries_page(tmp.path(), 2, 2).unwrap();
        let recent = list_recent_run_summary_entries(tmp.path(), 2).unwrap();

        assert_eq!(
            first
                .iter()
                .map(|entry| entry.run_id.as_str())
                .collect::<Vec<_>>(),
            vec!["run-c", "run-b"]
        );
        assert_eq!(recent, first);
        assert_eq!(second[0].run_id, "run-a");
        assert_eq!(second[1].run_id, "broken-run");
        assert!(matches!(second[1].state, RunSummaryEntryState::Issue(_)));
    }

    #[test]
    fn direct_history_and_pointer_reads_initialize_ignored_state() {
        for operation in ["offset", "cursor", "repair-latest"] {
            let tmp = tempfile::tempdir().unwrap();
            if !init_git_repo(tmp.path()) {
                return;
            }

            match operation {
                "offset" => {
                    assert!(list_run_summary_entries_page(tmp.path(), 0, 10)
                        .unwrap()
                        .is_empty());
                }
                "cursor" => {
                    assert!(list_run_summary_entries_cursor_page(tmp.path(), None, 10)
                        .unwrap()
                        .entries
                        .is_empty());
                }
                "repair-latest" => {
                    assert_eq!(repair_latest_run_pointer(tmp.path()).unwrap(), None);
                }
                _ => unreachable!(),
            }

            assert_git_status_clean(tmp.path(), operation);
        }
    }

    #[test]
    fn run_history_page_rebuilds_legacy_and_malformed_indexes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = runs_root(tmp.path());
        fs::create_dir_all(root.join("legacy-a")).unwrap();
        let mut summary = RunSummary::running("legacy-a", "tool", None, "target").complete();
        summary.started_at_unix = 42;
        fs::write(
            root.join("legacy-a/run.json"),
            serde_json::to_string(&summary).unwrap(),
        )
        .unwrap();
        fs::create_dir_all(root.join("legacy-broken")).unwrap();
        let legacy_path =
            crate::run_artifacts::checked_legacy_run_history_index_path(tmp.path()).unwrap();
        fs::write(&legacy_path, "legacy jsonl index\n").unwrap();

        let migrated = list_run_summary_entries_page(tmp.path(), 0, 10).unwrap();
        assert_eq!(run_entry_ids(&migrated), vec!["legacy-a", "legacy-broken"]);
        assert!(!legacy_path.exists());
        let index_path = crate::run_artifacts::checked_run_history_index_path(tmp.path()).unwrap();
        assert!(index_path.is_file());
        fs::write(&index_path, "not-json\n").unwrap();

        let rebuilt = list_run_summary_entries_page(tmp.path(), 0, 10).unwrap();
        assert_eq!(run_entry_ids(&rebuilt), vec!["legacy-a", "legacy-broken"]);
        assert!(matches!(rebuilt[1].state, RunSummaryEntryState::Issue(_)));
    }

    #[test]
    fn run_history_dirty_marker_recovers_summary_index_crash_window() {
        let tmp = tempfile::tempdir().unwrap();
        let mut first = RunSummary::running("run-a", "tool", None, "target").complete();
        first.started_at_unix = 10;
        write_run_summary(tmp.path(), &first).unwrap();
        let mut second = RunSummary::running("run-b", "tool", None, "target").complete();
        second.started_at_unix = 20;
        write_run_summary(tmp.path(), &second).unwrap();
        first.started_at_unix = 30;
        fs::write(
            run_artifact_path(tmp.path(), "run-a", "run.json"),
            serde_json::to_string(&first).unwrap(),
        )
        .unwrap();
        let dirty = crate::run_artifacts::checked_run_history_dirty_path(tmp.path()).unwrap();
        fs::write(&dirty, "dirty\n").unwrap();

        let page = list_run_summary_entries_page(tmp.path(), 0, 10).unwrap();

        assert_eq!(run_entry_ids(&page), vec!["run-a", "run-b"]);
        assert!(!dirty.exists());
    }

    #[test]
    fn next_indexed_write_preserves_an_unmarked_canonical_run() {
        let tmp = tempfile::tempdir().unwrap();
        let mut first = RunSummary::running("run-first", "tool", None, "target").complete();
        first.started_at_unix = 1;
        write_run_summary(tmp.path(), &first).unwrap();
        let mut external = RunSummary::running("run-external", "tool", None, "target").complete();
        external.started_at_unix = 2;
        let external_path = run_artifact_path(tmp.path(), "run-external", "run.json");
        fs::create_dir_all(external_path.parent().unwrap()).unwrap();
        fs::write(&external_path, serde_json::to_vec(&external).unwrap()).unwrap();
        let mut next = RunSummary::running("run-next", "tool", None, "target").complete();
        next.started_at_unix = 3;

        write_run_summary(tmp.path(), &next).unwrap();
        let page = list_recent_run_summary_entries(tmp.path(), 10).unwrap();

        assert_eq!(
            run_entry_ids(&page),
            vec!["run-next", "run-external", "run-first"]
        );
    }

    #[test]
    fn recent_run_page_reconciles_changed_unrequested_history() {
        let tmp = tempfile::tempdir().unwrap();
        for (run_id, started_at) in [("run-old", 1), ("run-new", 2)] {
            let mut summary = RunSummary::running(run_id, "tool", None, "target").complete();
            summary.started_at_unix = started_at;
            write_run_summary(tmp.path(), &summary).unwrap();
        }
        fs::write(
            run_artifact_path(tmp.path(), "run-old", "run.json"),
            "{ invalid legacy metadata",
        )
        .unwrap();

        let recent = list_recent_run_summary_entries(tmp.path(), 1).unwrap();

        assert_eq!(run_entry_ids(&recent), vec!["run-new"]);
    }

    #[test]
    fn repeated_summary_upserts_keep_one_index_version_per_run() {
        let tmp = tempfile::tempdir().unwrap();
        let running = RunSummary::running("run-one", "tool", None, "target");
        write_run_summary(tmp.path(), &running).unwrap();
        write_run_summary(tmp.path(), &running.clone().complete()).unwrap();
        write_run_summary(tmp.path(), &running.complete()).unwrap();

        let index_path = crate::run_artifacts::checked_run_history_index_path(tmp.path()).unwrap();
        let connection = rusqlite::Connection::open(index_path).unwrap();
        let count: i64 = connection
            .query_row("SELECT count(*) FROM run_history_entries", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn bounded_history_reports_truncation_and_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        for (run_id, started_at) in [("run-a", 1), ("run-b", 2), ("run-c", 3)] {
            write_completed_summary_at(tmp.path(), run_id, started_at);
        }
        crate::run_artifacts::run_history_index::rebuild_with_policy(tmp.path(), 2, 1_024).unwrap();

        let indexed = crate::run_artifacts::run_history_index::load_run_history_cursor_page(
            tmp.path(),
            None,
            10,
        )
        .unwrap();
        let error = list_run_summary_entries_cursor_page(tmp.path(), None, 10).unwrap_err();

        assert_eq!(indexed_run_ids(&indexed.entries), vec!["run-c", "run-b"]);
        assert_eq!(indexed.info.canonical_total, 3);
        assert_eq!(indexed.info.retained_count, 2);
        assert!(indexed.info.truncated);
        assert_truncated_page_error(&error);
        assert_eq!(list_run_summary_entries(tmp.path()).unwrap().len(), 3);
        assert!(indexed.info.oldest_retained.is_some());
        assert!(indexed.info.canonical_digest.starts_with("sha256:"));
        assert!(indexed.info.table_digest.starts_with("sha256:"));
    }

    #[test]
    fn byte_retention_keeps_a_canonical_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        for (run_id, started_at) in [("run-a", 1), ("run-b", 2), ("run-c", 3)] {
            write_completed_summary_at(tmp.path(), run_id, started_at);
        }
        crate::run_artifacts::run_history_index::rebuild_with_policy(tmp.path(), 10, 75).unwrap();

        let indexed = crate::run_artifacts::run_history_index::load_run_history_cursor_page(
            tmp.path(),
            None,
            10,
        )
        .unwrap();
        let error = list_run_summary_entries_cursor_page(tmp.path(), None, 10).unwrap_err();

        assert_eq!(indexed_run_ids(&indexed.entries), vec!["run-c"]);
        assert_eq!(indexed.info.retained_count, 1);
        assert!(indexed.info.retained_bytes <= 75);
        assert!(indexed.info.truncated);
        assert_truncated_page_error(&error);
    }

    #[test]
    fn repeated_upsert_of_an_evicted_run_does_not_increment_total() {
        let tmp = tempfile::tempdir().unwrap();
        for (run_id, started_at) in [("run-a", 1), ("run-b", 2), ("run-c", 3)] {
            write_completed_summary_at(tmp.path(), run_id, started_at);
        }
        crate::run_artifacts::run_history_index::rebuild_with_policy(tmp.path(), 2, 1_024).unwrap();
        write_completed_summary_at(tmp.path(), "run-a", 999);

        let indexed = crate::run_artifacts::run_history_index::load_run_history_cursor_page(
            tmp.path(),
            None,
            10,
        )
        .unwrap();

        assert_eq!(indexed.info.canonical_total, 3);
        assert_eq!(indexed.info.retained_count, 2);
        assert!(indexed.info.truncated);
        assert_eq!(indexed_run_ids(&indexed.entries), vec!["run-c", "run-b"]);
    }

    #[test]
    fn keyset_pages_are_stable_across_timestamp_ties() {
        let tmp = tempfile::tempdir().unwrap();
        for run_id in ["run-a", "run-c", "run-b"] {
            write_completed_summary_at(tmp.path(), run_id, 7);
        }
        fs::create_dir_all(runs_root(tmp.path()).join("broken-run")).unwrap();

        let first = list_run_summary_entries_cursor_page(tmp.path(), None, 2).unwrap();
        let second =
            list_run_summary_entries_cursor_page(tmp.path(), first.next_cursor.as_ref(), 2)
                .unwrap();

        assert_eq!(run_entry_ids(&first.entries), vec!["run-c", "run-b"]);
        assert_eq!(run_entry_ids(&second.entries), vec!["run-a", "broken-run"]);
        assert!(second.next_cursor.is_none());
    }

    #[test]
    fn cursor_from_an_old_generation_fails_explicitly() {
        let tmp = tempfile::tempdir().unwrap();
        write_completed_summary_at(tmp.path(), "run-a", 1);
        write_completed_summary_at(tmp.path(), "run-b", 2);
        let first = list_run_summary_entries_cursor_page(tmp.path(), None, 1).unwrap();
        let cursor = first.next_cursor.unwrap();
        write_completed_summary_at(tmp.path(), "run-c", 3);

        let error = list_run_summary_entries_cursor_page(tmp.path(), Some(&cursor), 1).unwrap_err();

        assert!(error.to_string().contains("older index generation"));
    }

    #[test]
    fn corrupt_index_rebuild_uses_a_fresh_cursor_generation() {
        let tmp = tempfile::tempdir().unwrap();
        write_completed_summary_at(tmp.path(), "run-a", 1);
        write_completed_summary_at(tmp.path(), "run-b", 2);
        let before = list_run_summary_entries_cursor_page(tmp.path(), None, 1).unwrap();
        let old_generation = before.history.generation;
        let index_path = crate::run_artifacts::checked_run_history_index_path(tmp.path()).unwrap();
        fs::write(&index_path, "corrupt index").unwrap();

        let after = list_run_summary_entries_cursor_page(tmp.path(), None, 1).unwrap();

        assert_ne!(after.history.generation, old_generation);
        assert!(
            list_run_summary_entries_cursor_page(tmp.path(), before.next_cursor.as_ref(), 1,)
                .is_err()
        );
    }

    #[test]
    fn invalid_metadata_to_valid_summary_rebuilds_canonical_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let path = run_artifact_path(tmp.path(), "run-broken", "run.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{ invalid").unwrap();
        let initial = list_run_summary_entries_cursor_page(tmp.path(), None, 10).unwrap();
        assert!(matches!(
            initial.entries[0].state,
            RunSummaryEntryState::Issue(_)
        ));

        write_completed_summary_at(tmp.path(), "run-broken", 11);
        let repaired = list_run_summary_entries_cursor_page(tmp.path(), None, 10).unwrap();

        assert!(matches!(
            repaired.entries[0].state,
            RunSummaryEntryState::Ready(_)
        ));
        assert_ne!(
            repaired.history.canonical_digest,
            initial.history.canonical_digest
        );
    }

    #[test]
    fn concurrent_creators_count_one_canonical_run() {
        let tmp = Arc::new(tempfile::tempdir().unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let target = Arc::clone(&tmp);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                write_completed_summary_at(target.path(), "run-shared", 1);
            }));
        }
        barrier.wait();
        for worker in workers {
            worker.join().unwrap();
        }

        let page = list_run_summary_entries_cursor_page(tmp.path(), None, 10).unwrap();

        assert_eq!(page.history.canonical_total, 1);
        assert_eq!(run_entry_ids(&page.entries), vec!["run-shared"]);
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_new_runs_update_the_existing_index_in_place() {
        use std::os::unix::fs::MetadataExt;

        let tmp = tempfile::tempdir().unwrap();
        let first = RunSummary::running("run-first", "tool", None, "target").complete();
        write_run_summary(tmp.path(), &first).unwrap();
        let index_path = crate::run_artifacts::checked_run_history_index_path(tmp.path()).unwrap();
        let original_inode = fs::metadata(&index_path).unwrap().ino();

        let second = RunSummary::running("run-second", "tool", None, "target").complete();
        write_run_summary(tmp.path(), &second).unwrap();

        assert_eq!(fs::metadata(index_path).unwrap().ino(), original_inode);
        assert_eq!(
            run_entry_ids(&list_recent_run_summary_entries(tmp.path(), 2).unwrap()),
            vec!["run-second", "run-first"]
        );
    }

    #[test]
    fn run_history_pages_bound_untrusted_header_and_window_sizes() {
        let tmp = tempfile::tempdir().unwrap();
        write_run_summary(
            tmp.path(),
            &RunSummary::running("run-one", "tool", None, "target").complete(),
        )
        .unwrap();
        let index_path = crate::run_artifacts::checked_run_history_index_path(tmp.path()).unwrap();
        let connection = rusqlite::Connection::open(&index_path).unwrap();
        connection
            .execute(
                "UPDATE run_history_meta SET retained_count = 1000001 WHERE singleton = 1",
                [],
            )
            .unwrap();
        drop(connection);

        assert_eq!(
            run_entry_ids(&list_run_summary_entries_page(tmp.path(), 0, 1).unwrap()),
            vec!["run-one"]
        );
        assert!(list_run_summary_entries_page(tmp.path(), usize::MAX, 1).is_err());
        assert!(list_run_summary_entries_page(tmp.path(), 0, usize::MAX).is_err());

        let oversized = fs::File::create(&index_path).unwrap();
        oversized.set_len(512 * 1024 * 1024 + 1).unwrap();
        drop(oversized);
        assert_eq!(
            run_entry_ids(&list_run_summary_entries_page(tmp.path(), 0, 1).unwrap()),
            vec!["run-one"]
        );
    }

    #[test]
    fn run_history_rejects_schema_triggers_and_rebuilds_from_canonical_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = RunSummary::running("run-one", "tool", None, "target").complete();
        write_run_summary(tmp.path(), &summary).unwrap();
        let index_path = crate::run_artifacts::checked_run_history_index_path(tmp.path()).unwrap();
        let connection = rusqlite::Connection::open(index_path).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER untrusted_history_trigger
                 AFTER UPDATE ON run_history_meta BEGIN
                   UPDATE run_history_meta SET retained_count = 999;
                 END;",
            )
            .unwrap();
        drop(connection);

        let page = list_recent_run_summary_entries(tmp.path(), 1).unwrap();

        assert_eq!(run_entry_ids(&page), vec!["run-one"]);
    }

    #[test]
    fn run_history_restores_deleted_and_timestamp_tampered_rows() {
        let tmp = tempfile::tempdir().unwrap();
        write_completed_summary_at(tmp.path(), "run-a", 1);
        write_completed_summary_at(tmp.path(), "run-b", 2);
        let index_path = crate::run_artifacts::checked_run_history_index_path(tmp.path()).unwrap();
        let connection = rusqlite::Connection::open(&index_path).unwrap();
        connection
            .execute(
                "UPDATE run_history_entries SET started_at_unix = 999 WHERE run_id = 'run-a'",
                [],
            )
            .unwrap();
        connection
            .execute("DELETE FROM run_history_entries WHERE run_id = 'run-b'", [])
            .unwrap();
        drop(connection);

        let page = list_recent_run_summary_entries(tmp.path(), 10).unwrap();

        assert_eq!(run_entry_ids(&page), vec!["run-b", "run-a"]);
        let connection = rusqlite::Connection::open(index_path).unwrap();
        let restored: Vec<(String, i64)> = connection
            .prepare("SELECT run_id, started_at_unix FROM run_history_entries ORDER BY run_id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(restored, vec![("run-a".into(), 1), ("run-b".into(), 2)]);
    }

    #[test]
    fn hidden_ordering_key_tamper_forces_rebuild() {
        let tmp = tempfile::tempdir().unwrap();
        write_completed_summary_at(tmp.path(), "run-a", 1);
        write_completed_summary_at(tmp.path(), "run-b", 2);
        let index_path = crate::run_artifacts::checked_run_history_index_path(tmp.path()).unwrap();
        let connection = rusqlite::Connection::open(&index_path).unwrap();
        connection
            .pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        connection
            .execute(
                "UPDATE run_history_entries SET ready_run_id = 'run-z' WHERE run_id = 'run-a'",
                [],
            )
            .unwrap();
        drop(connection);

        let page = list_recent_run_summary_entries(tmp.path(), 10).unwrap();

        assert_eq!(run_entry_ids(&page), vec!["run-b", "run-a"]);
        let connection = rusqlite::Connection::open(index_path).unwrap();
        let restored: String = connection
            .query_row(
                "SELECT ready_run_id FROM run_history_entries WHERE run_id = 'run-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(restored, "run-a");
    }

    #[test]
    fn canonical_timestamp_change_is_not_blessed_by_index_upsert() {
        let tmp = tempfile::tempdir().unwrap();
        write_completed_summary_at(tmp.path(), "run-a", 1);
        write_completed_summary_at(tmp.path(), "run-b", 2);
        let path = run_artifact_path(tmp.path(), "run-a", "run.json");
        let mut changed: RunSummary = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        changed.started_at_unix = 3;
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();

        let page = list_recent_run_summary_entries(tmp.path(), 10).unwrap();

        assert_eq!(run_entry_ids(&page), vec!["run-a", "run-b"]);
    }

    #[test]
    fn off_page_canonical_timestamp_change_reorders_a_small_page() {
        let tmp = tempfile::tempdir().unwrap();
        for (run_id, started_at) in [("run-a", 1), ("run-b", 2), ("run-c", 3)] {
            write_completed_summary_at(tmp.path(), run_id, started_at);
        }
        assert_eq!(
            run_entry_ids(&list_recent_run_summary_entries(tmp.path(), 1).unwrap()),
            vec!["run-c"]
        );
        let path = run_artifact_path(tmp.path(), "run-a", "run.json");
        let mut changed: RunSummary = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        changed.started_at_unix = 4;
        fs::write(path, serde_json::to_vec(&changed).unwrap()).unwrap();

        let page = list_recent_run_summary_entries(tmp.path(), 1).unwrap();

        assert_eq!(run_entry_ids(&page), vec!["run-a"]);
    }

    #[test]
    fn offset_page_fails_closed_when_an_evicted_run_moves_above_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let generation = rewrite_evicted_run_above_retention(tmp.path());

        let error = list_run_summary_entries_page(tmp.path(), 0, 1).unwrap_err();

        assert_truncated_page_error(&error);
        assert_eq!(run_history_generation(tmp.path()), generation);
        assert_eq!(
            run_entry_ids(&list_run_summary_entries(tmp.path()).unwrap()),
            vec!["run-a", "run-c", "run-b"]
        );
    }

    #[test]
    fn cursor_page_fails_closed_when_an_evicted_run_moves_above_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let generation = rewrite_evicted_run_above_retention(tmp.path());

        let error = list_run_summary_entries_cursor_page(tmp.path(), None, 1).unwrap_err();

        assert_truncated_page_error(&error);
        assert_eq!(run_history_generation(tmp.path()), generation);
        assert_eq!(
            run_entry_ids(&list_run_summary_entries(tmp.path()).unwrap()),
            vec!["run-a", "run-c", "run-b"]
        );
    }

    #[test]
    fn failed_dirty_marker_quarantine_is_a_stable_error() {
        let tmp = tempfile::tempdir().unwrap();
        write_completed_summary_at(tmp.path(), "run-a", 1);
        let dirty = crate::run_artifacts::checked_run_history_dirty_path(tmp.path()).unwrap();
        fs::create_dir(&dirty).unwrap();
        fs::create_dir(
            dirty
                .parent()
                .unwrap()
                .join("run-history.index.dirty.invalid"),
        )
        .unwrap();
        let generation_before = run_history_generation(tmp.path());

        let first = list_recent_run_summary_entries(tmp.path(), 10).unwrap_err();
        let second = list_recent_run_summary_entries(tmp.path(), 10).unwrap_err();

        assert!(first.to_string().contains("quarantine already exists"));
        assert!(second.to_string().contains("quarantine already exists"));
        assert_eq!(run_history_generation(tmp.path()), generation_before);
    }

    #[test]
    fn canonical_summary_write_survives_derived_index_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let initial = RunSummary::running("run-first", "tool", None, "target").complete();
        write_run_summary(tmp.path(), &initial).unwrap();
        let index_path = crate::run_artifacts::checked_run_history_index_path(tmp.path()).unwrap();
        fs::remove_file(&index_path).unwrap();
        fs::create_dir(&index_path).unwrap();
        let next = RunSummary::running("run-next", "tool", None, "target").complete();

        let summary_path = write_run_summary(tmp.path(), &next).unwrap();

        assert!(summary_path.is_file());
        let loaded = load_run_summary(tmp.path(), "run-next").unwrap();
        assert_eq!(loaded.run_id, next.run_id);
        assert_eq!(loaded.status, next.status);
    }

    #[test]
    fn dirty_marker_failure_does_not_hide_a_new_canonical_run() {
        let tmp = tempfile::tempdir().unwrap();
        let initial = RunSummary::running("run-first", "tool", None, "target").complete();
        write_run_summary(tmp.path(), &initial).unwrap();
        let dirty = crate::run_artifacts::checked_run_history_dirty_path(tmp.path()).unwrap();
        fs::create_dir(&dirty).unwrap();
        let next = RunSummary::running("run-next", "tool", None, "target").complete();

        write_run_summary(tmp.path(), &next).unwrap();
        let page = list_recent_run_summary_entries(tmp.path(), 2).unwrap();

        assert_eq!(run_entry_ids(&page), vec!["run-next", "run-first"]);
        assert!(!dirty.exists());
        assert!(dirty
            .parent()
            .unwrap()
            .join("run-history.index.dirty.invalid")
            .is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn derived_index_symlink_is_never_followed_or_overwritten() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let initial = RunSummary::running("run-first", "tool", None, "target").complete();
        write_run_summary(tmp.path(), &initial).unwrap();
        let index_path = crate::run_artifacts::checked_run_history_index_path(tmp.path()).unwrap();
        let outside = tmp.path().join("outside.sqlite3");
        fs::rename(&index_path, &outside).unwrap();
        let outside_before = fs::read(&outside).unwrap();
        symlink(&outside, &index_path).unwrap();

        let next = RunSummary::running("run-next", "tool", None, "target").complete();
        write_run_summary(tmp.path(), &next).unwrap();

        assert_eq!(fs::read(outside).unwrap(), outside_before);
        let loaded = load_run_summary(tmp.path(), "run-next").unwrap();
        assert_eq!(loaded.run_id, next.run_id);
        assert_eq!(loaded.status, next.status);
    }

    fn run_entry_ids(entries: &[RunSummaryEntry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.run_id.as_str()).collect()
    }

    fn indexed_run_ids(entries: &[run_history_index::RunHistoryIndexEntry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.run_id.as_str()).collect()
    }

    fn assert_truncated_page_error(error: &anyhow::Error) {
        let message = error.to_string();
        assert!(message.contains("retention is truncated"), "{message}");
        assert!(message.contains("list_run_summary_entries"), "{message}");
    }

    fn rewrite_evicted_run_above_retention(target: &Path) -> i64 {
        for (run_id, started_at) in [("run-a", 1), ("run-b", 2), ("run-c", 3)] {
            write_completed_summary_at(target, run_id, started_at);
        }
        run_history_index::rebuild_with_policy(target, 2, 1_024).unwrap();
        let generation = run_history_generation(target);
        let root_modified = fs::metadata(runs_root(target)).unwrap().modified().unwrap();
        let path = run_artifact_path(target, "run-a", "run.json");
        let mut changed: RunSummary = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        changed.started_at_unix = 4;
        fs::write(path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_eq!(
            fs::metadata(runs_root(target)).unwrap().modified().unwrap(),
            root_modified
        );
        generation
    }

    fn write_completed_summary_at(target: &Path, run_id: &str, started_at_unix: u64) {
        let mut summary = RunSummary::running(run_id, "tool", None, "target").complete();
        summary.started_at_unix = started_at_unix;
        write_run_summary(target, &summary).unwrap();
    }

    fn run_history_generation(target: &Path) -> i64 {
        let index = crate::run_artifacts::checked_run_history_index_path(target).unwrap();
        rusqlite::Connection::open(index)
            .unwrap()
            .query_row(
                "SELECT generation FROM run_history_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn latest_pointer_is_chronological_and_never_regresses_on_old_completion() {
        let tmp = tempfile::tempdir().unwrap();
        let target = Arc::new(tmp.path().to_path_buf());
        let barrier = Arc::new(Barrier::new(2));
        let mut older = RunSummary::running("scan-older", "scan", None, "target");
        older.started_at_unix = 100;
        let mut newer = RunSummary::running("tool-newer", "tool", None, "target");
        newer.started_at_unix = 200;

        let handles = [older.clone(), newer.clone()]
            .into_iter()
            .map(|summary| {
                let target = Arc::clone(&target);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    write_run_summary(target.as_path(), &summary).unwrap();
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(
            fs::read_to_string(latest_run_path(tmp.path())).unwrap(),
            "tool-newer\n"
        );
        write_run_summary(tmp.path(), &older.complete()).unwrap();
        assert_eq!(
            fs::read_to_string(latest_run_path(tmp.path())).unwrap(),
            "tool-newer\n"
        );
        assert_eq!(
            list_run_summaries(tmp.path())
                .unwrap()
                .into_iter()
                .map(|summary| summary.run_id)
                .collect::<Vec<_>>(),
            vec!["tool-newer", "scan-older"]
        );
    }

    #[test]
    fn latest_pointer_uses_persisted_start_time_when_terminal_summary_is_rebuilt() {
        let tmp = tempfile::tempdir().unwrap();
        let mut older = RunSummary::running("scan-rebuilt", "scan", None, "target");
        older.started_at_unix = 100;
        write_run_summary(tmp.path(), &older).unwrap();
        let mut newer = RunSummary::running("tool-current", "tool", None, "target");
        newer.started_at_unix = 200;
        write_run_summary(tmp.path(), &newer).unwrap();

        let rebuilt = RunSummary::running("scan-rebuilt", "scan", None, "target").complete();
        write_run_summary(tmp.path(), &rebuilt).unwrap();

        assert_eq!(
            fs::read_to_string(latest_run_path(tmp.path())).unwrap(),
            "tool-current\n"
        );
        assert_eq!(
            load_run_summary(tmp.path(), "scan-rebuilt")
                .unwrap()
                .started_at_unix,
            100
        );
    }

    fn run_summary_schema() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../schemas/run.summary.schema.json")).unwrap()
    }

    fn run_artifact_manifest_schema() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../schemas/run.artifacts.schema.json"
        ))
        .unwrap()
    }

    fn run_failures_schema() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../schemas/run.failures.schema.json")).unwrap()
    }

    fn run_event_schema() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../schemas/run.events.schema.json")).unwrap()
    }

    fn run_trace_schema() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../schemas/run.trace.schema.json")).unwrap()
    }

    #[test]
    fn published_schemas_cover_real_scan_and_agent_producer_kinds() {
        let event_kinds = &run_event_schema()["definitions"]["eventKind"]["enum"];
        for kind in ["tool", "scan", "run", "shell"] {
            assert!(event_kinds
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(kind)));
        }

        let trace_schema = run_trace_schema();
        let trace_kinds = &trace_schema["definitions"]["traceKind"]["enum"];
        let summary_schema = run_summary_schema();
        let llm_kinds = &summary_schema["definitions"]["llmCallKind"]["enum"];
        for kind in ["plan", "llm", "critic"] {
            assert!(trace_kinds
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(kind)));
            assert!(llm_kinds
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(kind)));
        }
    }

    #[test]
    fn published_scan_pipeline_contract_declares_distinct_patch_log() {
        let leaves = SCAN_PIPELINE_ARTIFACTS
            .iter()
            .map(|spec| spec.leaf)
            .collect::<Vec<_>>();

        assert_eq!(
            leaves,
            vec![
                "scan-input.json",
                "triage.jsonl",
                "verify.jsonl",
                "patch.jsonl",
                "phase-stages.jsonl"
            ]
        );
        for spec in SCAN_PIPELINE_ARTIFACTS {
            let published = scan_pipeline_artifact_spec(spec.leaf).unwrap();
            assert_eq!(published.label, spec.label);
            assert_eq!(published.kind, spec.kind);
        }
    }

    fn representative_run_summary() -> RunSummary {
        RunSummary::running(
            "run-schema",
            "tool",
            Some("agentic:test".to_string()),
            "target",
        )
        .complete()
        .with_findings(Some(2))
        .with_cost(Some(0.42))
        .with_model(Some("openai:gpt-test".to_string()))
        .with_config_hash(Some("sha256:cfg".to_string()))
        .with_house_rules(vec![RunHouseRuleFingerprint {
            module: "triage".to_string(),
            path: ".kuzushi/house-rules/triage.md".to_string(),
            sha256: "sha256:rules".to_string(),
        }])
        .with_prompt_overrides(vec![RunPromptOverrideFingerprint {
            module: "triage".to_string(),
            verb: "run".to_string(),
            path: ".kuzushi/prompts/triage/run.md".to_string(),
            sha256: "sha256:prompt".to_string(),
        }])
        .with_threat_model_sha256(Some("sha256:threat".to_string()))
        .with_env_fingerprint(vec![RunEnvFingerprint {
            key: "KUZUSHI_TEST".to_string(),
            fingerprint: "sha256:env".to_string(),
        }])
        .with_target_git(Some(RunTargetGitMetadata {
            sha: "abcdef123456".to_string(),
            branch: Some("main".to_string()),
            dirty: true,
        }))
        .with_cli_args(vec![
            "kuzushi".to_string(),
            "run".to_string(),
            "context:build".to_string(),
        ])
        .with_loaded_modules(vec![
            "builtin:agentic-sast".to_string(),
            "builtin:context".to_string(),
        ])
        .with_llm_calls(vec![RunLlmCallAudit {
            n: 1,
            kind: "reasoning".to_string(),
            verb: Some("run".to_string()),
            model: "openai:gpt-test".to_string(),
            provider: "openai".to_string(),
            prompt_hash: "fnv1a64:abc".to_string(),
            latency_ms: Some(12),
            cost_usd: Some(0.01),
            observed_cost_usd: None,
            provider_spend_unresolved: false,
            call_attempted: Some(true),
        }])
        .with_trace_malformed_lines(Some(1))
        .with_artifact(RunArtifact {
            label: "result".to_string(),
            path: representative_run_artifact_path("run-schema", "result.json"),
            kind: "json".to_string(),
        })
    }

    fn representative_artifact_manifest() -> RunArtifactManifest {
        RunArtifactManifest {
            run_id: "run-schema".to_string(),
            artifacts: vec![RunArtifact {
                label: "run metadata".to_string(),
                path: representative_run_artifact_path("run-schema", "run.json"),
                kind: "json".to_string(),
            }],
            objects: Vec::new(),
        }
    }

    fn representative_run_failures() -> RunFailures {
        RunFailures {
            run_id: "run-failed".to_string(),
            status: "failed".to_string(),
            failures: vec![RunFailure {
                tool: "triage:run".to_string(),
                status: "failed".to_string(),
                error: "runtime unavailable".to_string(),
                agent_thread_context: FailureToLlmContext {
                    failed_stage: "triage:run".to_string(),
                    cause: "runtime unavailable".to_string(),
                    what_failed: "triage:run did not complete successfully".to_string(),
                    artifacts_available: vec![RunArtifact {
                        label: "run metadata".to_string(),
                        path: representative_run_artifact_path("run-failed", "run.json"),
                        kind: "json".to_string(),
                    }],
                    missing_artifacts: vec!["proof.json".to_string()],
                    allowed_proof_level: "artifact-review-only".to_string(),
                    next_files_or_artifacts_to_inspect: vec!["failures.json".to_string()],
                    recovery_options: vec!["rerun triage".to_string()],
                    fallback_prompt: "continue failed run".to_string(),
                    claims_forbidden: vec!["verified claim".to_string()],
                },
            }],
        }
    }

    fn representative_run_event() -> RunEvent {
        RunEvent::new(1, "tool", "started", "triage started")
            .with_tool("triage:run")
            .with_artifact(RunArtifact {
                label: "input".to_string(),
                path: representative_run_artifact_path("run-event", "input.json"),
                kind: "json".to_string(),
            })
    }

    fn representative_trace_step() -> RunTraceStep {
        RunTraceStep::new(2, "reasoning", "triage query")
            .with_latency_ms(Some(120))
            .with_cost_usd(Some(0.02))
            .with_module_id("triage")
            .with_verb("run")
            .with_parent_step(1)
            .with_severity("info")
            .with_started_at_ms(1_700_000_000_000)
            .with_model_metadata("openai:gpt-test", "openai", "fnv1a64:abc")
    }

    fn assert_required_schema_fields_exist(schema: &serde_json::Value, value: &serde_json::Value) {
        for field in schema["required"].as_array().unwrap() {
            let field = field.as_str().unwrap();
            assert!(value.get(field).is_some(), "missing required field {field}");
        }
    }

    fn assert_schema_requires_fields(schema: &serde_json::Value, fields: &[&str]) {
        let required = required_fields(schema);
        for field in fields {
            assert!(
                required.contains(field),
                "schema missing required field {field}"
            );
        }
    }

    fn assert_failure_schema_requires_canonical_context_key(schema: &serde_json::Value) {
        let failure_schema = &schema["definitions"]["failure"];
        assert_schema_requires_fields(failure_schema, &["agentThreadContext"]);
        assert_schema_declares_no_fields(failure_schema, &["agent_thread_context"]);
    }

    fn assert_failure_context_schema_requires_canonical_fields(schema: &serde_json::Value) {
        let context_schema = &schema["definitions"]["failureContext"];
        assert_schema_requires_fields(
            context_schema,
            &[
                "failedStage",
                "cause",
                "whatFailed",
                "artifactsAvailable",
                "missingArtifacts",
                "allowedProofLevel",
                "nextFilesOrArtifactsToInspect",
                "recoveryOptions",
                "fallbackPrompt",
                "claimsForbidden",
            ],
        );
        assert_schema_declares_no_fields(
            context_schema,
            &[
                "failed_stage",
                "what_failed",
                "artifacts_available",
                "missing_artifacts",
                "allowed_proof_level",
                "next_files_or_artifacts_to_inspect",
                "recovery_options",
                "fallback_prompt",
                "claims_forbidden",
            ],
        );
    }

    fn required_fields(schema: &serde_json::Value) -> Vec<&str> {
        schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field.as_str().unwrap())
            .collect()
    }

    fn assert_serialized_fields_are_declared(
        schema: &serde_json::Value,
        value: &serde_json::Value,
    ) {
        let properties = schema["properties"].as_object().unwrap();
        for field in value.as_object().unwrap().keys() {
            assert!(
                properties.contains_key(field),
                "schema missing field {field}"
            );
        }
    }

    fn assert_schema_declares_fields(schema: &serde_json::Value, fields: &[&str]) {
        let properties = schema["properties"].as_object().unwrap();
        for field in fields {
            assert!(
                properties.contains_key(*field),
                "schema missing field {field}"
            );
        }
    }

    fn assert_schema_declares_no_fields(schema: &serde_json::Value, fields: &[&str]) {
        let properties = schema["properties"].as_object().unwrap();
        for field in fields {
            assert!(
                !properties.contains_key(*field),
                "schema still declares obsolete field {field}"
            );
        }
    }

    fn assert_additional_properties_disabled(schema: &serde_json::Value) {
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&serde_json::Value::Bool(false))
        );
    }

    fn assert_canonical_artifact_schema(schema: &serde_json::Value) {
        let properties = schema["properties"].as_object().unwrap();

        assert_eq!(
            schema["required"],
            serde_json::json!(["label", "path", "kind"])
        );
        assert_eq!(properties.len(), 3);
        assert_eq!(properties["label"]["type"], "string");
        assert_eq!(properties["label"]["minLength"], 1);
        assert_eq!(properties["path"]["type"], "string");
        assert_eq!(properties["path"]["minLength"], 1);
        assert_eq!(properties["kind"]["$ref"], "#/definitions/artifactKind");
    }

    fn assert_manifest_fields_reference_non_empty_string(
        schema: &serde_json::Value,
        fields: &[&str],
    ) {
        let properties = schema["properties"].as_object().unwrap();
        for field in fields {
            assert_eq!(
                properties[*field]["$ref"], "#/definitions/nonEmptyString",
                "manifest field {field} must reject blank strings"
            );
        }
    }

    fn assert_artifact_fields_reference_non_empty_string(
        artifact_schema: &serde_json::Value,
        fields: &[&str],
    ) {
        let properties = artifact_schema["properties"].as_object().unwrap();
        for field in fields {
            assert_eq!(
                properties[*field]["$ref"], "#/definitions/nonEmptyString",
                "artifact field {field} must reject empty strings"
            );
        }
    }

    fn assert_schema_rule_matches_artifact_spec(
        rules: &[serde_json::Value],
        spec: &crate::artifact_contract::CanonicalRunArtifactSpec,
    ) {
        let rule = artifact_schema_rule(rules, spec.leaf);

        assert_schema_rule_path(rule, spec.leaf);
        assert_eq!(schema_rule_const(rule, "label"), spec.label);
        assert_eq!(schema_rule_const(rule, "kind"), spec.kind);
    }

    fn artifact_schema_rule<'a>(
        rules: &'a [serde_json::Value],
        leaf: &str,
    ) -> &'a serde_json::Value {
        let expected = artifact_path_pattern(leaf);
        rules
            .iter()
            .find(|rule| schema_rule_matches_path(rule, &expected))
            .unwrap_or_else(|| panic!("missing schema metadata rule for {leaf}"))
    }

    fn artifact_path_pattern(leaf: &str) -> String {
        format!("(^|/){}$", leaf.replace('.', "\\."))
    }

    fn assert_schema_rule_path(rule: &serde_json::Value, leaf: &str) {
        let expected = artifact_path_pattern(leaf);
        assert!(
            schema_rule_matches_path(rule, &expected),
            "schema metadata rule for {leaf} must cover canonical path"
        );
    }

    fn schema_rule_matches_path(rule: &serde_json::Value, expected: &str) -> bool {
        required_fields(&rule["if"]).contains(&"path")
            && rule["if"]["properties"]["path"]["pattern"] == expected
    }

    fn schema_rule_const<'a>(rule: &'a serde_json::Value, field: &str) -> &'a str {
        rule["then"]["properties"][field]["const"].as_str().unwrap()
    }

    fn assert_artifact_entries_match_schema(schema: &serde_json::Value, value: &serde_json::Value) {
        let artifact_schema = schema["definitions"]["artifact"]["properties"]
            .as_object()
            .unwrap();
        for artifact in value["artifacts"].as_array().unwrap() {
            for field in artifact.as_object().unwrap().keys() {
                assert!(
                    artifact_schema.contains_key(field),
                    "artifact schema missing field {field}"
                );
            }
        }
    }

    fn assert_run_summary_llm_entries_match_schema(
        schema: &serde_json::Value,
        value: &serde_json::Value,
    ) {
        let llm_schema = schema["definitions"]["llmCall"]["properties"]
            .as_object()
            .unwrap();
        let calls = value
            .get("llmCalls")
            .or_else(|| value.get("llm_calls"))
            .unwrap()
            .as_array()
            .unwrap();
        for call in calls {
            for field in call.as_object().unwrap().keys() {
                assert!(
                    llm_schema.contains_key(field),
                    "llm call schema missing field {field}"
                );
            }
        }
    }

    fn assert_llm_call_schema_requires_canonical_prompt_hash(schema: &serde_json::Value) {
        let llm_schema = &schema["definitions"]["llmCall"];
        assert_schema_requires_fields(llm_schema, &["promptHash"]);
        assert_schema_declares_no_fields(llm_schema, &["prompt_hash", "latency_ms", "cost_usd"]);
    }

    fn assert_failure_entries_match_schema(schema: &serde_json::Value, value: &serde_json::Value) {
        let failure_schema = schema["definitions"]["failure"]["properties"]
            .as_object()
            .unwrap();
        let context_schema = schema["definitions"]["failureContext"]["properties"]
            .as_object()
            .unwrap();
        for failure in value["failures"].as_array().unwrap() {
            for field in failure.as_object().unwrap().keys() {
                assert!(
                    failure_schema.contains_key(field),
                    "failure schema missing field {field}"
                );
            }
            let context = failure.get("agentThreadContext").unwrap();
            for field in context.as_object().unwrap().keys() {
                assert!(
                    context_schema.contains_key(field),
                    "failure context schema missing field {field}"
                );
            }
        }
    }

    fn assert_event_artifact_matches_schema(schema: &serde_json::Value, value: &serde_json::Value) {
        let artifact_schema = schema["definitions"]["artifact"]["properties"]
            .as_object()
            .unwrap();
        for field in value["artifact"].as_object().unwrap().keys() {
            assert!(
                artifact_schema.contains_key(field),
                "event artifact schema missing field {field}"
            );
        }
    }

    fn assert_forbidden_success_claims(claims: &[String]) {
        for claim in [
            "success claim without explicit verification",
            "verified claim",
            "exploited claim",
            "fixed claim",
            "false positive verdict",
            "no vulnerability verdict",
        ] {
            assert!(claims.contains(&claim.to_string()), "missing claim {claim}");
        }
    }

    #[test]
    fn list_run_summaries_marks_dead_process_running_summary_interrupted() {
        let tmp = tempfile::tempdir().unwrap();
        if !std::path::Path::new("/proc").exists() {
            return;
        }
        let summary =
            RunSummary::running("run-stale", "tool", None, "target").with_process_id(u32::MAX);
        write_run_summary(tmp.path(), &summary).unwrap();

        let loaded = list_run_summaries(tmp.path()).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].status, "interrupted");
        assert!(loaded[0].completed_at_unix.is_some());
        assert!(loaded[0].process_id.is_none());
        assert!(loaded[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("no longer running"));
        assert_eq!(
            load_run_failures(tmp.path(), "run-stale").unwrap().status,
            "interrupted"
        );
        assert!(
            fs::read_to_string(run_artifact_path(tmp.path(), "run-stale", "report.md"))
                .unwrap()
                .contains("Status: interrupted")
        );
        assert!(
            fs::read_to_string(run_artifact_path(tmp.path(), "run-stale", "events.jsonl"))
                .unwrap()
                .contains("\"kind\":\"run\"")
        );
        assert!(
            fs::read_to_string(run_artifact_path(tmp.path(), "run-stale", "trace.jsonl"))
                .unwrap()
                .contains("\"kind\":\"refused\"")
        );
    }
}
