#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::artifact_contract::{
        ARTIFACT_KIND_KEYS, ARTIFACT_LABEL_KEYS, ARTIFACT_PATH_KEYS, CANONICAL_RUN_ARTIFACTS,
        OPTIONAL_RUN_ARTIFACTS, TOOL_INPUT_ARTIFACTS, TOOL_RESULT_ARTIFACTS,
    };
    use std::fs;
    use std::path::Path;
    use std::process::Command;

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
    fn trace_step_accepts_camel_case_reader_aliases() {
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

        let parsed: RunTraceStep = serde_json::from_value(json).unwrap();

        assert_eq!(parsed.latency_ms, Some(25));
        assert_eq!(parsed.cost_usd, Some(0.02));
        assert_eq!(parsed.module_id.as_deref(), Some("triage"));
        assert_eq!(parsed.parent_step, Some(3));
        assert_eq!(parsed.started_at_ms, Some(1_700_000_000_000));
        assert_eq!(parsed.prompt_hash.as_deref(), Some("fnv1a64:abc"));
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
                r#"{"n":7,"kind":"tool","status":"completed","message":"done","at_unix":2}"#,
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
            [
                r#"{"n":1,"kind":"reasoning","label":"query"}"#,
                "{not-json",
            ]
            .join("\n"),
        )
        .unwrap();

        assert_eq!(next_run_trace_step_number(tmp.path(), run_id), 3);
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
    fn run_event_accepts_tool_name_aliases() {
        let camel: RunEvent = serde_json::from_str(
            r#"{"n":1,"kind":"tool","status":"started","message":"ask","atUnix":1,"toolName":"agent:ask"}"#,
        )
        .unwrap();
        let snake: RunEvent = serde_json::from_str(
            r#"{"n":2,"kind":"tool","status":"completed","message":"scan","at_unix":2,"tool_name":"sast:scan"}"#,
        )
        .unwrap();

        assert_eq!(camel.tool.as_deref(), Some("agent:ask"));
        assert_eq!(snake.tool.as_deref(), Some("sast:scan"));
    }

    #[test]
    fn run_event_accepts_artifact_path_aliases() {
        let camel: RunEvent = serde_json::from_str(
            r#"{"n":1,"kind":"tool","status":"started","message":"scan","atUnix":1,"artifactPath":" input.json "}"#,
        )
        .unwrap();
        let snake: RunEvent = serde_json::from_str(
            r#"{"n":2,"kind":"tool","status":"completed","message":"done","at_unix":2,"artifact_path":"result.jsonl"}"#,
        )
        .unwrap();

        assert_eq!(camel.artifact.as_ref().map(|artifact| artifact.path.as_str()), Some("input.json"));
        assert_eq!(camel.artifact.as_ref().map(|artifact| artifact.kind.as_str()), Some("json"));
        assert_eq!(snake.artifact.as_ref().map(|artifact| artifact.path.as_str()), Some("result.jsonl"));
        assert_eq!(snake.artifact.as_ref().map(|artifact| artifact.kind.as_str()), Some("jsonl"));
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

        let metadata = fs::read_to_string(run_artifact_path(tmp.path(), run_id, "run.json")).unwrap();
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
                    &RunTraceStep::new(1, "reasoning", "query")
                        .with_model_metadata("openai:gpt-test", "openai", "fnv1a64:abc123"),
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

        let metadata = fs::read_to_string(run_artifact_path(tmp.path(), run_id, "run.json")).unwrap();
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
                    &RunTraceStep::new(1, "reasoning", "query")
                        .with_model_metadata("openai:gpt-test", "openai", "fnv1a64:abc123"),
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

        let metadata = fs::read_to_string(run_artifact_path(tmp.path(), run_id, "run.json")).unwrap();
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
        let summary = RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
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

        let metadata = fs::read_to_string(run_artifact_path(tmp.path(), run_id, "run.json")).unwrap();
        assert!(metadata.contains("\"kuzushiVersion\""));
        assert!(metadata.contains("\"platform\""));
        assert!(metadata.contains("\"model\": \"openai:gpt-test\""));
        assert!(metadata.contains("\"configHash\": \"sha256:abc123\""));
        assert!(metadata.contains("\"cliArgs\""));
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
    fn run_summary_schema_covers_snake_case_metadata_aliases() {
        let schema = run_summary_schema();
        let value = representative_snake_case_run_summary();

        assert_serialized_fields_are_declared(&schema, &value);
        assert_run_summary_llm_entries_match_schema(&schema, &value);
        assert_schema_allows_required_alias_pair(&schema, ["runId", "run_id"]);
        assert_schema_allows_required_alias_pair(
            &schema,
            ["startedAtUnix", "started_at_unix"],
        );
        assert_llm_call_schema_requires_prompt_hash_aliases(&schema);
    }

    #[test]
    fn run_summary_schema_covers_artifact_reader_aliases() {
        let schema = run_summary_schema();
        let artifact_schema = &schema["definitions"]["artifact"];

        assert_schema_declares_definition_fields(
            &schema,
            "artifact",
            &[
                "name",
                "title",
                "filePath",
                "file_path",
                "reportJsonPath",
                "report_json_path",
                "promptsDir",
                "prompts_dir",
                "type",
            ],
        );
        assert_schema_allows_required_alias_set(artifact_schema, &ARTIFACT_LABEL_KEYS);
        assert_schema_allows_required_alias_set(artifact_schema, &ARTIFACT_KIND_KEYS);
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
    fn run_artifact_manifest_schema_covers_snake_case_run_id_alias() {
        let schema = run_artifact_manifest_schema();
        let value = representative_snake_case_artifact_manifest();

        assert_serialized_fields_are_declared(&schema, &value);
        assert_artifact_entries_match_schema(&schema, &value);
        assert_schema_requires_any_field(&schema, &["runId", "run_id"]);
    }

    #[test]
    fn run_artifact_manifest_schema_rejects_blank_run_identity_aliases() {
        let schema = run_artifact_manifest_schema();

        assert_manifest_fields_reference_non_empty_string(&schema, &["runId", "run_id"]);
    }

    #[test]
    fn run_artifact_manifest_schema_covers_artifact_reader_aliases() {
        let schema = run_artifact_manifest_schema();
        let artifact_schema = &schema["definitions"]["artifact"];

        assert_schema_declares_definition_fields(
            &schema,
            "artifact",
            &[
                "name",
                "title",
                "file",
                "filePath",
                "file_path",
                "reportPath",
                "report_path",
                "reportJsonPath",
                "report_json_path",
                "scopePath",
                "scope_path",
                "dir",
                "outputDir",
                "output_dir",
                "promptsDir",
                "prompts_dir",
                "type",
            ],
        );
        assert_schema_allows_required_alias_set(artifact_schema, &ARTIFACT_LABEL_KEYS);
        assert_schema_allows_required_alias_set(artifact_schema, &ARTIFACT_KIND_KEYS);
    }

    #[test]
    fn run_artifact_manifest_schema_rejects_blank_artifact_alias_strings() {
        let schema = run_artifact_manifest_schema();
        let artifact_schema = &schema["definitions"]["artifact"];

        assert_artifact_aliases_reference_non_empty_string(
            artifact_schema,
            &ARTIFACT_LABEL_KEYS,
        );
        assert_artifact_aliases_reference_non_empty_string(artifact_schema, &ARTIFACT_PATH_KEYS);
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
    fn run_failures_schema_covers_snake_case_aliases() {
        let schema = run_failures_schema();
        let value = representative_snake_case_run_failures();

        assert_serialized_fields_are_declared(&schema, &value);
        assert_failure_entries_match_schema(&schema, &value);
        assert_schema_requires_any_field(&schema, &["runId", "run_id"]);
        assert_failure_schema_requires_any_context_key(&schema);
        assert_failure_context_schema_requires_alias_pairs(&schema);
    }

    #[test]
    fn run_failures_schema_covers_available_artifact_aliases() {
        let schema = run_failures_schema();
        let artifact_schema = &schema["definitions"]["artifact"];

        assert_schema_declares_definition_fields(
            &schema,
            "artifact",
            &[
                "name",
                "title",
                "file",
                "filePath",
                "file_path",
                "reportJsonPath",
                "report_json_path",
                "promptsDir",
                "prompts_dir",
                "type",
            ],
        );
        assert_schema_allows_required_alias_set(artifact_schema, &ARTIFACT_LABEL_KEYS);
        assert_schema_allows_required_alias_set(artifact_schema, &ARTIFACT_KIND_KEYS);
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
    fn run_event_schema_covers_reader_aliases() {
        let schema = run_event_schema();

        assert_schema_allows_required_alias_pair(&schema, ["atUnix", "at_unix"]);
        assert_schema_declares_fields(
            &schema,
            &[
                "toolName",
                "tool_name",
                "artifactPath",
                "artifact_path",
            ],
        );
    }

    #[test]
    fn run_event_schema_covers_artifact_reader_aliases() {
        let schema = run_event_schema();
        let artifact_schema = &schema["definitions"]["artifact"];

        assert_schema_declares_definition_fields(
            &schema,
            "artifact",
            &[
                "name",
                "title",
                "filePath",
                "file_path",
                "reportJsonPath",
                "report_json_path",
                "promptsDir",
                "prompts_dir",
                "type",
            ],
        );
        assert_schema_allows_required_alias_set(artifact_schema, &ARTIFACT_LABEL_KEYS);
        assert_schema_allows_required_alias_set(artifact_schema, &ARTIFACT_KIND_KEYS);
    }

    #[test]
    fn run_trace_schema_matches_serialized_keys() {
        let schema = run_trace_schema();
        let value = serde_json::to_value(representative_trace_step()).unwrap();

        assert_required_schema_fields_exist(&schema, &value);
        assert_serialized_fields_are_declared(&schema, &value);
    }

    #[test]
    fn run_trace_schema_covers_reader_aliases() {
        let schema = run_trace_schema();

        assert_schema_declares_fields(
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
    fn run_context_schema_covers_marker_and_rich_snapshot_keys() {
        let schema = run_context_schema();
        let marker = representative_missing_context_snapshot();
        let rich = representative_rich_context_snapshot();

        assert_snapshot_marker_fields_are_declared(&schema);
        assert_serialized_fields_are_declared(&schema, &marker);
        assert_serialized_fields_are_declared(&schema, &rich);
    }

    #[test]
    fn run_attack_surface_schema_covers_marker_and_rich_snapshot_keys() {
        let schema = run_attack_surface_schema();
        let marker = representative_missing_attack_surface_snapshot();
        let rich = representative_rich_attack_surface_snapshot();

        assert_snapshot_marker_fields_are_declared(&schema);
        assert_serialized_fields_are_declared(&schema, &marker);
        assert_serialized_fields_are_declared(&schema, &rich);
    }

    #[test]
    fn run_threat_model_schema_covers_marker_and_rich_snapshot_keys() {
        let schema = run_threat_model_schema();
        let marker = representative_missing_threat_model_snapshot();
        let rich = representative_rich_threat_model_snapshot();

        assert_snapshot_marker_fields_are_declared(&schema);
        assert_serialized_fields_are_declared(&schema, &marker);
        assert_serialized_fields_are_declared(&schema, &rich);
    }

    #[test]
    fn run_recommendations_schema_covers_marker_and_rich_snapshot_keys() {
        let schema = run_recommendations_schema();
        let marker = representative_missing_recommendations_snapshot();
        let rich = representative_rich_recommendations_snapshot();
        let enveloped = representative_data_wrapped_recommendations_snapshot();

        assert_snapshot_marker_fields_are_declared(&schema);
        assert_serialized_fields_are_declared(&schema, &marker);
        assert_serialized_fields_are_declared(&schema, &rich);
        assert_serialized_fields_are_declared(&schema, &enveloped);
        assert_recommendation_entries_match_schema(&schema, &rich);
        assert_recommendation_report_matches_schema(&schema, &enveloped["data"]);
        assert_recommendation_report_envelope_aliases_match_schema(&schema);
    }

    #[test]
    fn run_strategy_schema_covers_marker_and_rich_snapshot_keys() {
        let schema = run_strategy_schema();
        let marker = representative_missing_strategy_snapshot();
        let rich = representative_rich_strategy_snapshot();

        assert_snapshot_marker_fields_are_declared(&schema);
        assert_serialized_fields_are_declared(&schema, &marker);
        assert_serialized_fields_are_declared(&schema, &rich);
        assert_strategy_proposal_entries_match_schema(&schema, &rich);
    }

    #[test]
    fn run_findings_schema_covers_marker_and_rich_snapshot_keys() {
        let schema = run_findings_schema();
        let marker = representative_missing_findings_snapshot();
        let rich = representative_rich_findings_snapshot();

        assert_snapshot_marker_fields_are_declared(&schema);
        assert_serialized_fields_are_declared(&schema, &marker);
        assert_finding_entries_match_schema(&schema, &rich);
    }

    #[test]
    fn run_proof_schema_covers_marker_and_rich_snapshot_keys() {
        let schema = run_proof_schema();
        let marker = representative_missing_proof_snapshot();
        let rich = representative_rich_proof_snapshot();
        let verification = representative_verification_proof_snapshot();
        let snake_verification = representative_snake_case_verification_proof_snapshot();

        assert_snapshot_marker_fields_are_declared(&schema);
        assert_serialized_fields_are_declared(&schema, &marker);
        assert_serialized_fields_are_declared(&schema, &rich);
        assert_serialized_fields_are_declared(&schema, &verification);
        assert_serialized_fields_are_declared(&schema, &snake_verification);
        assert_proof_finding_entries_match_schema(&schema, &rich);
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
        fs::write(crate::module_prompt_root(tmp.path(), "triage"), "not a directory").unwrap();

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
        let metadata =
            fs::read_to_string(run_artifact_path(tmp.path(), "run-threat-digest", "run.json"))
                .unwrap();
        assert!(metadata.contains("\"threatModelSha256\""));
    }

    #[test]
    fn run_summary_records_invalid_threat_model_digest_state() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(crate::capabilities::persistent_threat_model_path(tmp.path())).unwrap();

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
        fs::write(dir.join(".run.json.tmp-999999-0-0"), "{ this is a torn writ").unwrap();

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

    #[test]
    fn load_run_summary_accepts_snake_case_metadata_aliases() {
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
                "run_id": run_id,
                "kind": "tool",
                "status": "completed",
                "tool": "agentic:test",
                "target": "target",
                "started_at_unix": 1,
                "completed_at_unix": 2,
                "findings": 3,
                "cost_usd": 0.5,
                "process_id": 99,
                "kuzushi_version": "1.2.3-test",
                "git_sha": "abc123",
                "git_branch": "main",
                "model": "openai:gpt-test",
                "config_hash": "sha256:def456",
                "platform": "darwin-arm64",
                "loaded_module_specifiers": ["builtin:agentic-sast", "builtin:context"],
                "llm_calls": [
                    {
                        "n": 1,
                        "kind": "reasoning",
                        "verb": "query",
                        "model": "openai:gpt-test",
                        "provider": "openai",
                        "prompt_hash": "fnv1a64:abc123",
                        "latency_ms": 42,
                        "cost_usd": 0.25
                    }
                ],
                "artifacts": []
            }))
            .unwrap(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), run_id).unwrap();

        assert_eq!(loaded.run_id, run_id);
        assert_eq!(loaded.started_at_unix, 1);
        assert_eq!(loaded.completed_at_unix, Some(2));
        assert_eq!(loaded.cost_usd, Some(0.5));
        assert_eq!(loaded.process_id, Some(99));
        assert_eq!(loaded.kuzushi_version.as_deref(), Some("1.2.3-test"));
        assert_eq!(loaded.git_sha.as_deref(), Some("abc123"));
        assert_eq!(loaded.git_branch.as_deref(), Some("main"));
        assert_eq!(loaded.model.as_deref(), Some("openai:gpt-test"));
        assert_eq!(loaded.config_hash.as_deref(), Some("sha256:def456"));
        assert_eq!(loaded.platform.as_deref(), Some("darwin-arm64"));
        assert_eq!(
            loaded.loaded_modules,
            vec!["builtin:agentic-sast", "builtin:context"]
        );
        assert_eq!(loaded.llm_calls[0].prompt_hash, "fnv1a64:abc123");
        assert_eq!(loaded.llm_calls[0].latency_ms, Some(42));
        assert_eq!(loaded.llm_calls[0].cost_usd, Some(0.25));
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
    fn load_run_artifacts_rejects_obsolete_manifest_artifact_field_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-artifact-aliases";
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
                        "name": " report json ",
                        "report_json_path": " reports/report.json ",
                        "type": " JSON "
                    },
                    {
                        "title": " prompts ",
                        "prompts_dir": " .kuzushi/prompts ",
                        "type": " Directory "
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest artifact at index 0 uses obsolete name alias"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_redundant_manifest_artifact_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-matching-artifact-aliases";
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
                        "label": " run metadata ",
                        "name": "run metadata",
                        "path": " run.json ",
                        "filePath": "run.json",
                        "kind": " JSON ",
                        "type": "json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest artifact at index 0 uses obsolete name alias"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_conflicting_manifest_artifact_label_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-conflicting-artifact-label-aliases";
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
                        "name": "runtime trace",
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

        assert!(message.contains("Artifact manifest artifact at index 0 uses obsolete name alias"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_conflicting_manifest_artifact_path_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-conflicting-artifact-path-aliases";
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

        assert!(message.contains("Artifact manifest artifact at index 0 uses obsolete filePath alias"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_conflicting_manifest_artifact_kind_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-conflicting-artifact-kind-aliases";
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
                        "kind": "json",
                        "type": "jsonl"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest artifact at index 0 uses obsolete type alias"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_non_string_manifest_artifact_label_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-non-string-artifact-label-alias";
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

        assert!(message.contains("Artifact manifest artifact at index 0 label is not a non-empty string"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_non_string_manifest_artifact_path_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-non-string-artifact-path-alias";
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
                        "filePath": ["run.json"],
                        "kind": "json"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest artifact at index 0 uses obsolete filePath alias"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_non_string_manifest_artifact_kind_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-non-string-artifact-kind-alias";
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
                        "type": ["json"]
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest artifact at index 0 uses obsolete type alias"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_missing_manifest_artifact_label_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-missing-artifact-label-alias";
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

        assert!(
            message.contains("Artifact manifest artifact at index 0 is missing label")
        );
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_missing_manifest_artifact_path_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-missing-artifact-path-alias";
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
    fn load_run_artifacts_rejects_missing_manifest_artifact_kind_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-missing-artifact-kind-alias";
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
    fn load_run_artifacts_rejects_blank_manifest_artifact_path_alias() {
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

        assert!(message.contains("Artifact manifest artifact at index 0 path is not a non-empty string"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_blank_manifest_artifact_label_alias() {
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

        assert!(message.contains("Artifact manifest artifact at index 0 label is not a non-empty string"));
        assert!(message.contains("artifacts.json"));
    }

    #[test]
    fn load_run_artifacts_rejects_blank_manifest_artifact_kind_alias() {
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

        assert!(message.contains("Artifact manifest artifact at index 0 kind is not a non-empty string"));
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

        assert!(error.to_string().contains("Artifact manifest is not a file"));
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
        fs::write(run_artifact_path(tmp.path(), run_id, "artifacts.json"), "[]").unwrap();

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
    fn load_run_artifacts_rejects_manifest_blank_snake_case_run_id() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-blank-snake-run-id";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete(),
        )
        .unwrap();
        fs::write(
            run_artifact_path(tmp.path(), run_id, "artifacts.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "run_id": "   ",
                "artifacts": []
            }))
            .unwrap(),
        )
        .unwrap();

        let error = load_run_artifacts(tmp.path(), run_id).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Artifact manifest uses obsolete run_id alias; use runId"));
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
        let run_id = "run-manifest-matching-run-id-aliases";
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
    fn load_run_artifacts_rejects_conflicting_manifest_run_id_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-manifest-conflicting-run-id-aliases";
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

        assert!(message.contains("Artifact manifest uses obsolete run_id alias; use runId"));
        assert!(message.contains("artifacts.json"));
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

        assert!(error.to_string().contains("run artifact path must not be empty"));
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
    fn canonical_snapshot_artifacts_record_domain_object_kinds() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-domain-object-kinds";
        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("sast:scan".to_string()), "target")
                .complete(),
        )
        .unwrap();

        for (leaf, expected_kind) in [
            ("context.json", "context-snapshot"),
            ("attack-surface.json", "attack-surface-snapshot"),
            ("findings.json", "finding-observation-batch"),
            ("proof.json", "proof-snapshot"),
            ("failures.json", "diagnostic-bundle"),
        ] {
            let spec = crate::artifact_contract::canonical_run_artifact_spec(leaf).unwrap();
            write_run_artifact_json(
                tmp.path(),
                run_id,
                leaf,
                spec.label,
                &serde_json::json!({"status": "recorded"}),
            )
            .unwrap();
            let manifest: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(run_artifact_path(tmp.path(), run_id, "artifacts.json"))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                manifest_object_kind_for_path(&manifest, leaf),
                Some(expected_kind)
            );
        }
    }

    fn cas_object_path(target: &Path, hash: &str) -> PathBuf {
        crate::workspace::workspace_objects_dir(target)
            .join("blake3")
            .join(&hash[0..2])
            .join(&hash[2..4])
            .join(hash)
    }

    fn manifest_object_kind_for_path<'a>(
        manifest: &'a serde_json::Value,
        leaf: &str,
    ) -> Option<&'a str> {
        manifest["objects"]
            .as_array()?
            .iter()
            .find(|object| object["path"].as_str().is_some_and(|path| path.ends_with(leaf)))?
            .pointer("/objectRef/kind")?
            .as_str()
    }

    #[test]
    fn load_run_failures_accepts_artifact_field_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-failure-artifact-aliases";
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
                "run_id": run_id,
                "status": "failed",
                "failures": [{
                    "tool": "triage:run",
                    "status": "failed",
                    "error": "runtime unavailable",
                    "agent_thread_context": {
                        "failed_stage": "triage:run",
                        "cause": "runtime unavailable",
                        "what_failed": "triage did not complete",
                        "artifacts_available": [{
                            "title": " triage transcript ",
                            "file_path": format!(" {triage_path} "),
                            "type": " JSON "
                        }],
                        "missing_artifacts": ["proof.json"],
                        "allowed_proof_level": "artifact-review-only",
                        "next_files_or_artifacts_to_inspect": ["failures.json"],
                        "recovery_options": ["rerun triage"],
                        "fallback_prompt": "continue the run",
                        "claims_forbidden": ["verified claim"]
                    }
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let failures = load_run_failures(tmp.path(), run_id).unwrap();
        let artifact = &failures.failures[0].agent_thread_context.artifacts_available[0];

        assert_eq!(artifact.label, "triage transcript");
        assert_eq!(artifact.path, triage_path);
        assert_eq!(artifact.kind, "json");
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
        let context_marker =
            fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "context.json")).unwrap();
        assert!(context_marker.contains(&format!("\"run_id\": \"{run_id}\"")));
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
        let metadata = fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "run.json")).unwrap();
        assert!(metadata.contains("\"status\": \"completed\""));
        let context_marker =
            fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "context.json")).unwrap();
        assert!(context_marker.contains("\"runStatus\": \"completed\""));
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
        assert_manifest_has(&manifest_artifacts, "context.json");
        assert_manifest_has(&manifest_artifacts, "result.json");
        let trace = fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "trace.jsonl")).unwrap();
        assert!(trace.contains("context:build started"));
    }

    #[test]
    fn write_run_summary_rejects_non_file_snapshot_marker_target() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-file-snapshot-marker";
        fs::create_dir_all(run_artifact_path(tmp.path(), run_id, "context.json")).unwrap();
        let summary = RunSummary::running(run_id, "tool", Some("context:build".to_string()), "target");

        let error = write_run_summary(tmp.path(), &summary).unwrap_err();

        assert!(error
            .to_string()
            .contains("Canonical marker target is not a file"));
        assert!(error.to_string().contains("context.json"));
    }

    #[test]
    fn write_run_summary_rejects_non_file_report_marker_target() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-file-report-marker";
        fs::create_dir_all(run_artifact_path(tmp.path(), run_id, "report.md")).unwrap();
        let summary = RunSummary::running(run_id, "tool", Some("report:build".to_string()), "target");

        let error = write_run_summary(tmp.path(), &summary).unwrap_err();

        assert!(error
            .to_string()
            .contains("Canonical marker target is not a file"));
        assert!(error.to_string().contains("report.md"));
    }

    #[test]
    fn write_run_summary_rejects_non_file_manifest_placeholder_target() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-non-file-manifest-placeholder";
        fs::create_dir_all(run_artifact_path(tmp.path(), run_id, "artifacts.json")).unwrap();
        let summary = RunSummary::running(run_id, "tool", Some("context:build".to_string()), "target");

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
        let summary = RunSummary::running(run_id, "tool", Some("context:build".to_string()), "target");

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
        let summary = RunSummary::running(run_id, "tool", Some("context:build".to_string()), "target");

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
        let summary = RunSummary::running(run_id, "tool", Some("context:build".to_string()), "target");

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

        assert!(error
            .to_string()
            .contains("Run trace target is not a file"));
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
    fn final_summary_refreshes_only_generated_absence_markers() {
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

        let context_marker =
            fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "context.json")).unwrap();
        let findings = fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "findings.json"))
            .unwrap();

        assert!(context_marker.contains("\"runStatus\": \"completed\""));
        assert!(findings.contains("producer-owned"));
        assert!(!findings.contains("\"runStatus\": \"completed\""));
    }

    #[test]
    fn paused_summary_propagates_status_to_canonical_placeholders() {
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

        let metadata = fs::read_to_string(run_artifact_path(tmp.path(), &run_id, "run.json")).unwrap();
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
            let marker = fs::read_to_string(run_artifact_path(tmp.path(), &run_id, leaf)).unwrap();
            assert!(marker.contains("\"runStatus\": \"paused\""), "{leaf}");
        }
        assert!(placeholder_report.contains("Status: paused"));
        assert_eq!(failures.status, "paused");
        assert!(failures.failures.is_empty());
        assert_manifest_has_canonical_run_artifacts(&manifest_artifacts);
    }

    fn assert_canonical_run_files_exist(target: &Path, run_id: &str) {
        let dir = run_dir(target, run_id);
        for leaf in [
            "run.json",
            "events.jsonl",
            "trace.jsonl",
            "context.json",
            "attack-surface.json",
            "threat-model.json",
            "recommendations.json",
            "strategy.json",
            "findings.json",
            "proof.json",
            "failures.json",
            "report.md",
            "artifacts.json",
        ] {
            assert!(dir.join(leaf).exists(), "missing canonical artifact {leaf}");
        }
    }

    fn assert_manifest_has(artifacts: &[RunArtifact], leaf: &str) {
        assert!(
            artifacts.iter().any(|artifact| artifact.path.ends_with(leaf)),
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
        let events = fs::read_to_string(run_artifact_path(tmp.path(), run_id, "events.jsonl")).unwrap();
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
        assert!(context.missing_artifacts.contains(&"trace.jsonl".to_string()));
        assert!(context.missing_artifacts.contains(&"context.json".to_string()));
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
        assert!(!context
            .missing_artifacts
            .contains(&"report.md".to_string()));
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
        fs::create_dir_all(dir.join("proof.json")).unwrap();
        let declared = RunArtifact {
            label: "proof".to_string(),
            path: dir.join("proof.json").display().to_string(),
            kind: "json".to_string(),
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
        assert!(context.missing_artifacts.contains(&"proof.json".to_string()));
        assert!(context.fallback_prompt.contains("Missing artifacts:"));
        assert!(context.fallback_prompt.contains("proof.json"));
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
        assert_eq!(result["errors"][0], serde_json::json!("semgrep binary missing"));
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
        let events = fs::read_to_string(run_artifact_path(tmp.path(), run_id, "events.jsonl")).unwrap();
        assert!(events.contains("\"status\":\"started\""));
        assert!(events.contains("\"artifact\""));
        let trace = fs::read_to_string(run_artifact_path(tmp.path(), run_id, "trace.jsonl")).unwrap();
        assert!(trace.contains("context:build started"));
    }

    #[test]
    fn tool_run_complete_promotes_result_snapshots_to_canonical_files() {
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
        assert!(fs::read_to_string(dir.join("context.json"))
            .unwrap()
            .contains("repoContext"));
        let attack_surface = fs::read_to_string(dir.join("attack-surface.json")).unwrap();
        assert!(attack_surface.contains("/login"));
        assert!(attack_surface.contains("/upload"));
        assert!(attack_surface.contains("file_upload_parse_path"));
        assert!(fs::read_to_string(dir.join("threat-model.json"))
            .unwrap()
            .contains("STRIDE"));
        assert!(fs::read_to_string(dir.join("recommendations.json"))
            .unwrap()
            .contains("semgrep:scan"));
        assert!(fs::read_to_string(dir.join("findings.json"))
            .unwrap()
            .contains("demo"));
        assert!(fs::read_to_string(dir.join("proof.json"))
            .unwrap()
            .contains("code_cited"));
        assert!(fs::read_to_string(dir.join("report.md"))
            .unwrap()
            .contains("Snapshot Report"));
        assert!(fs::read_to_string(dir.join("report.sarif"))
            .unwrap()
            .contains("\"version\": \"2.1.0\""));

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("context.json")));
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
    fn tool_run_complete_promotes_snake_case_report_artifacts() {
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
        assert!(fs::read_to_string(dir.join("report.md"))
            .unwrap()
            .contains("Snake Report"));
        assert!(fs::read_to_string(dir.join("report.sarif"))
            .unwrap()
            .contains("\"version\": \"2.1.0\""));

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
    fn tool_run_complete_prefers_core_findings_snapshot() {
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

        let body = fs::read_to_string(run_artifact_path(tmp.path(), run_id, "findings.json"))
            .unwrap();
        let findings = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(findings[0]["fingerprint"], serde_json::json!("dep-fp"));
        assert_eq!(findings[0]["tool"], serde_json::json!("dep-hygiene"));
        assert!(findings[0].get("packageName").is_none());

        let proof_body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "proof.json")).unwrap();
        let proof = serde_json::from_str::<serde_json::Value>(&proof_body).unwrap();

        assert_eq!(proof["source"], serde_json::json!("normalized-findings"));
        assert_eq!(proof["runtimeVerification"], serde_json::json!(false));
        assert_eq!(proof["countsByState"]["signal_only"], serde_json::json!(1));
        assert_eq!(
            proof["findings"][0]["staticProofState"],
            serde_json::json!("signal_only")
        );
    }

    #[test]
    fn tool_run_complete_promotes_root_core_findings_snapshot() {
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

        let findings_body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "findings.json")).unwrap();
        let findings = serde_json::from_str::<serde_json::Value>(&findings_body).unwrap();
        assert_eq!(findings[0]["fingerprint"], serde_json::json!("codeql-fp"));
        assert_eq!(findings[0]["ruleId"], serde_json::json!("js/sql-injection"));

        let proof_body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "proof.json")).unwrap();
        let proof = serde_json::from_str::<serde_json::Value>(&proof_body).unwrap();
        assert_eq!(
            proof["countsByState"]["source_sink_linked"],
            serde_json::json!(1)
        );
        assert_eq!(
            proof["findings"][0]["filePath"],
            serde_json::json!("src/app.ts")
        );
    }

    #[test]
    fn tool_run_complete_promotes_proof_state_aliases() {
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

        let proof_body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "proof.json")).unwrap();
        let proof = serde_json::from_str::<serde_json::Value>(&proof_body).unwrap();

        assert_eq!(
            proof["countsByState"]["execution_confirmed"],
            serde_json::json!(1)
        );
        assert_eq!(proof["countsByState"]["code_cited"], serde_json::json!(2));
        assert!(proof["countsByState"].get("code-cited").is_none());
        assert_eq!(proof["runtimeVerification"], serde_json::json!(true));
        assert_eq!(proof["proofLevel"], serde_json::json!("runtime-and-static"));
    }

    #[test]
    fn tool_run_complete_marks_runtime_reviewed_and_attempted_states_as_runtime_proof() {
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
                        {"fingerprint": "reviewed", "tool": "verify", "proof_state": "runtime_reviewed"},
                        {"fingerprint": "attempted", "tool": "verify", "proof_state": "execution_attempted"},
                        {"fingerprint": "rejected", "tool": "verify", "proof_state": "execution_rejected"}
                    ]
                }
            }),
        );

        let proof_body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "proof.json")).unwrap();
        let proof = serde_json::from_str::<serde_json::Value>(&proof_body).unwrap();

        assert_eq!(proof["runtimeVerification"], serde_json::json!(true));
        assert_eq!(proof["proofLevel"], serde_json::json!("runtime-and-static"));
        assert_eq!(proof["countsByState"]["runtime_reviewed"], serde_json::json!(1));
        assert_eq!(
            proof["countsByState"]["execution_attempted"],
            serde_json::json!(1)
        );
        assert_eq!(
            proof["countsByState"]["execution_rejected"],
            serde_json::json!(1)
        );
    }

    #[test]
    fn tool_run_complete_promotes_nested_properties_proof_state() {
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
                            "properties": {"staticProofState": "source-sink-linked"}
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

        let proof_body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "proof.json")).unwrap();
        let proof = serde_json::from_str::<serde_json::Value>(&proof_body).unwrap();

        assert_eq!(
            proof["countsByState"]["source_sink_linked"],
            serde_json::json!(1)
        );
        assert_eq!(
            proof["countsByState"]["runtime_confirmed"],
            serde_json::json!(1)
        );
        assert_eq!(proof["runtimeVerification"], serde_json::json!(true));
        assert_eq!(
            proof["findings"][0]["staticProofState"],
            serde_json::json!("source_sink_linked")
        );
    }

    #[test]
    fn tool_run_complete_promotes_root_proofs_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-root-proofs";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "verify:finding");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "proofs": {
                    "proofLevel": 3,
                    "proofVerdict": "needs-runtime-evidence"
                }
            }),
        );

        let proof_body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "proof.json")).unwrap();
        let proof = serde_json::from_str::<serde_json::Value>(&proof_body).unwrap();

        assert_eq!(proof["proofLevel"], serde_json::json!(3));
        assert_eq!(
            proof["proofVerdict"],
            serde_json::json!("needs-runtime-evidence")
        );
    }

    #[test]
    fn tool_run_complete_promotes_root_verification_snapshot() {
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

        let proof_body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "proof.json")).unwrap();
        let proof = serde_json::from_str::<serde_json::Value>(&proof_body).unwrap();

        assert_eq!(proof["verified"], serde_json::json!(1));
        assert_eq!(proof["results"][0]["findingId"], serde_json::json!("F-1"));
    }

    #[test]
    fn tool_run_complete_promotes_snake_case_verification_snapshot() {
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

        let proof_body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "proof.json")).unwrap();
        let proof = serde_json::from_str::<serde_json::Value>(&proof_body).unwrap();

        assert_eq!(proof["verified_count"], serde_json::json!(1));
        assert_eq!(proof["verification_results"][0]["finding_id"], serde_json::json!("F-1"));
    }

    #[test]
    fn tool_run_complete_promotes_full_module_recommendation_report() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-recommendations";
        let record = ToolRunRecord::new(
            tmp.path(),
            run_id,
            "tool",
            "module-recommender:recommend",
        );

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
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "recommendations.json")).unwrap();
        let report = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(report["summary"], serde_json::json!("2 recommendations for /repo"));
        assert_eq!(report["signals"]["sourceFiles"], serde_json::json!(12));
        assert_eq!(
            report["capabilities"]["availableToolCount"],
            serde_json::json!(5)
        );
        assert_eq!(
            report["recommendations"][0]["tool"],
            serde_json::json!("threat-model:build")
        );
        assert_eq!(
            report["recommendations"][0]["signals"][0],
            serde_json::json!("frameworks: Falcon, Litestar, Sanic")
        );
    }

    #[test]
    fn tool_run_complete_promotes_snake_case_recommendation_report() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-snake-recommendations";
        let record = ToolRunRecord::new(
            tmp.path(),
            run_id,
            "tool",
            "module-recommender:recommend",
        );

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

        let body =
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "recommendations.json")).unwrap();
        let report = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(report["summary"], serde_json::json!("1 recommendation for /repo"));
        assert_eq!(report["signals"]["source_files"], serde_json::json!(3));
        assert_eq!(
            report["capabilities"]["available_tool_count"],
            serde_json::json!(4)
        );
        assert_eq!(
            report["recommendations"][0]["tool"],
            serde_json::json!("semgrep:scan")
        );
    }

    #[test]
    fn tool_run_complete_promotes_data_wrapped_recommendation_report() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-data-recommendations";
        let record = ToolRunRecord::new(
            tmp.path(),
            run_id,
            "tool",
            "module-recommender:recommend",
        );

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
            fs::read_to_string(run_artifact_path(tmp.path(), run_id, "recommendations.json")).unwrap();
        let report = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(report["summary"], serde_json::json!("1 recommendation for /repo"));
        assert_eq!(
            report["signals"]["frameworks"],
            serde_json::json!(["Falcon", "Litestar", "Sanic"])
        );
        assert_eq!(
            report["recommendations"][0]["signals"][0],
            serde_json::json!("frameworks: Falcon, Litestar, Sanic")
        );
    }

    #[test]
    fn tool_run_complete_records_output_declared_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-declared-artifacts";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "sast:scan");
        let report = tmp.path().join("report.md");
        let analysis_json = tmp.path().join("analysis.json");

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
    fn tool_run_complete_records_snake_case_declared_artifact_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-declared-snake-artifacts";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "sast:scan");
        let report_json = tmp.path().join("report.json");
        let prompts_dir = tmp.path().join("prompts");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "artifacts": [
                    {
                        "name": " report json ",
                        "report_json_path": report_json.display().to_string(),
                        "type": " JSON "
                    }
                ],
                "data": {
                    "artifacts": {
                        "prompts": {
                            "title": " prompt overrides ",
                            "prompts_dir": prompts_dir.display().to_string(),
                            "type": " Directory "
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
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "partial");
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
        let trace = fs::read_to_string(run_artifact_path(tmp.path(), run_id, "trace.jsonl")).unwrap();
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

        let first = RunSummary::running("run-a", "scan", None, "target-a").complete();
        let second =
            RunSummary::running("run-b", "tool", Some("ctx:build".to_string()), "target-b")
                .complete();
        write_run_summary(tmp.path(), &first).unwrap();
        write_run_summary(tmp.path(), &second).unwrap();

        let root = runs_root(tmp.path());
        fs::write(root.join("not-a-run"), "ignored").unwrap();
        fs::create_dir_all(root.join("missing-summary")).unwrap();
        fs::create_dir_all(root.join("invalid-run-metadata")).unwrap();
        fs::write(root.join("invalid-run-metadata").join("run.json"), "{").unwrap();
        fs::create_dir_all(root.join("run-c")).unwrap();
        fs::write(
            root.join("run-c").join("run.json"),
            serde_json::to_string(&RunSummary::running("run-c", "tool", None, "target-c")).unwrap(),
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

    fn run_summary_schema() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../schemas/run.summary.schema.json"
        ))
        .unwrap()
    }

    fn run_artifact_manifest_schema() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../schemas/run.artifacts.schema.json"
        ))
        .unwrap()
    }

    fn run_failures_schema() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../schemas/run.failures.schema.json"
        ))
        .unwrap()
    }

    fn run_event_schema() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../schemas/run.events.schema.json")).unwrap()
    }

    fn run_trace_schema() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../schemas/run.trace.schema.json")).unwrap()
    }

    fn run_context_schema() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../schemas/run.context.schema.json")).unwrap()
    }

    fn run_attack_surface_schema() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../schemas/run.attack-surface.schema.json"
        ))
        .unwrap()
    }

    fn run_threat_model_schema() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../schemas/run.threat-model.schema.json"
        ))
        .unwrap()
    }

    fn run_recommendations_schema() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../schemas/run.recommendations.schema.json"
        ))
        .unwrap()
    }

    fn run_strategy_schema() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../schemas/run.strategy.schema.json")).unwrap()
    }

    fn run_findings_schema() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../schemas/run.findings.schema.json"
        ))
        .unwrap()
    }

    fn run_proof_schema() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../schemas/run.proof.schema.json")).unwrap()
    }

    fn representative_run_summary() -> RunSummary {
        RunSummary::running("run-schema", "tool", Some("agentic:test".to_string()), "target")
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

    fn representative_snake_case_artifact_manifest() -> serde_json::Value {
        serde_json::json!({
            "run_id": "run-schema",
            "artifacts": [{
                "label": "run metadata",
                "path": representative_run_artifact_path("run-schema", "run.json"),
                "kind": "json"
            }]
        })
    }

    fn representative_snake_case_run_summary() -> serde_json::Value {
        serde_json::json!({
            "run_id": "run-schema",
            "kind": "tool",
            "status": "completed",
            "tool": "agentic:test",
            "target": "target",
            "started_at_unix": 1,
            "completed_at_unix": 2,
            "cost_usd": 0.42,
            "process_id": 42,
            "kuzushi_version": "0.24.0-alpha.0",
            "git_sha": "abcdef123456",
            "git_branch": "main",
            "model": "openai:gpt-test",
            "config_hash": "sha256:cfg",
            "platform": "darwin-arm64",
            "house_rules": [{
                "module": "triage",
                "path": ".kuzushi/house-rules/triage.md",
                "sha256": "sha256:rules"
            }],
            "prompt_overrides": [{
                "module": "triage",
                "verb": "run",
                "path": ".kuzushi/prompts/triage/run.md",
                "sha256": "sha256:prompt"
            }],
            "threat_model_sha256": "sha256:threat",
            "env_fingerprint": [{"key": "KUZUSHI_TEST", "fingerprint": "sha256:env"}],
            "target_git": {"sha": "abcdef123456", "branch": "main", "dirty": true},
            "cli_args": ["kuzushi", "run", "context:build"],
            "loaded_modules": ["builtin:agentic-sast", "builtin:context"],
            "trace_malformed_lines": 1,
            "llm_calls": [{
                "n": 1,
                "kind": "reasoning",
                "verb": "run",
                "model": "openai:gpt-test",
                "provider": "openai",
                "prompt_hash": "fnv1a64:abc",
                "latency_ms": 12,
                "cost_usd": 0.01
            }],
            "artifacts": [{
                "label": "result",
                "path": representative_run_artifact_path("run-schema", "result.json"),
                "kind": "json"
            }]
        })
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

    fn representative_snake_case_run_failures() -> serde_json::Value {
        serde_json::json!({
            "run_id": "run-failed",
            "status": "failed",
            "failures": [{
                "tool": "triage:run",
                "status": "failed",
                "error": "runtime unavailable",
                "agent_thread_context": {
                    "failed_stage": "triage:run",
                    "cause": "runtime unavailable",
                    "what_failed": "triage:run did not complete successfully",
                    "artifacts_available": [{
                        "label": "run metadata",
                        "path": representative_run_artifact_path("run-failed", "run.json"),
                        "kind": "json"
                    }],
                    "missing_artifacts": ["proof.json"],
                    "allowed_proof_level": "artifact-review-only",
                    "next_files_or_artifacts_to_inspect": ["failures.json"],
                    "recovery_options": ["rerun triage"],
                    "fallback_prompt": "continue failed run",
                    "claims_forbidden": ["verified claim"]
                }
            }]
        })
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

    fn representative_missing_context_snapshot() -> serde_json::Value {
        serde_json::json!({
            "runId": "run-context",
            "status": "skipped",
            "runStatus": "completed",
            "summary": "No context snapshot was recorded for this run.",
            "artifacts": [],
            "warnings": ["No context snapshot was recorded for this run."],
            "errors": []
        })
    }

    fn representative_rich_context_snapshot() -> serde_json::Value {
        serde_json::json!({
            "filesIndexed": 42,
            "repoContext": {
                "languages": ["TypeScript", "Rust"],
                "frameworks": ["Django", "Spring"]
            },
            "appModel": {
                "routes": [{"id": "route-users"}],
                "outboundClients": [{"id": "stripe"}],
                "dataStores": [{"id": "postgres"}],
                "backgroundJobs": [{"id": "sync"}]
            }
        })
    }

    fn representative_missing_attack_surface_snapshot() -> serde_json::Value {
        serde_json::json!({
            "runId": "run-attack-surface",
            "status": "skipped",
            "runStatus": "completed",
            "summary": "No attack-surface snapshot was recorded for this run.",
            "artifacts": [],
            "warnings": ["No attack-surface snapshot was recorded for this run."],
            "errors": []
        })
    }

    fn representative_rich_attack_surface_snapshot() -> serde_json::Value {
        serde_json::json!({
            "summary": {
                "surfaceCount": 1,
                "highRisk": 1,
                "maxRiskScore": 82,
                "byRiskTier": {"high": 1},
                "byKind": {"http_route": 1}
            },
            "surfaces": [{
                "id": "route-users",
                "kind": "http_route",
                "framework": "Spring",
                "risk": {
                    "rank": 1,
                    "score": 82,
                    "tier": "high",
                    "reasons": ["auth boundary"]
                }
            }],
            "attackSurfaces": [],
            "attack_surfaces": []
        })
    }

    fn representative_missing_threat_model_snapshot() -> serde_json::Value {
        serde_json::json!({
            "runId": "run-threat-model",
            "status": "skipped",
            "runStatus": "completed",
            "summary": "No threat-model snapshot was recorded for this run.",
            "artifacts": [],
            "warnings": ["No threat-model snapshot was recorded for this run."],
            "errors": []
        })
    }

    fn representative_rich_threat_model_snapshot() -> serde_json::Value {
        serde_json::json!({
            "version": "2.0",
            "methodology": "stride",
            "dfd": {
                "nodes": [{"id": "app"}],
                "flows": [{"id": "flow-public"}],
                "trust_boundaries": [{"id": "tb-public"}]
            },
            "threats": [{
                "id": "T-001",
                "related_cwe": ["CWE-20"],
                "affectedFiles": [{"filePath": "src/app.ts"}]
            }],
            "attackSurface": {
                "entryPoints": [{"name": "handle_request"}]
            },
            "narrative": {
                "overview": "deterministic model",
                "input_categories": {
                    "data_egress_flows": ["GET /reports/download"]
                }
            },
            "degradation": {
                "mode": "deterministic-no-runtime"
            }
        })
    }

    fn representative_missing_recommendations_snapshot() -> serde_json::Value {
        serde_json::json!({
            "runId": "run-recommendations",
            "status": "skipped",
            "runStatus": "completed",
            "summary": "No module recommendations were recorded for this run.",
            "artifacts": [],
            "warnings": ["No module recommendations were recorded for this run."],
            "errors": []
        })
    }

    fn representative_rich_recommendations_snapshot() -> serde_json::Value {
        serde_json::json!({
            "summary": "1 recommendation for /repo",
            "target": "/repo",
            "signals": {
                "sourceFiles": 12,
                "frameworks": ["Falcon", "Litestar", "Sanic"],
                "attackSurfaceHighRisk": 2
            },
            "capabilities": {
                "availableToolCount": 5,
                "recommendedToolCount": 1,
                "skippedMissingTools": []
            },
            "recommendations": [{
                "moduleId": "semgrep",
                "tool": "threat-model:build",
                "priority": "medium",
                "reason": "attack-surface signals exist",
                "signals": ["frameworks: Falcon, Litestar, Sanic"],
                "requiresRuntime": false,
                "nextInput": {"target": "/repo"}
            }],
            "warnings": [],
            "errors": []
        })
    }

    fn representative_data_wrapped_recommendations_snapshot() -> serde_json::Value {
        serde_json::json!({
            "status": "completed",
            "runStatus": "completed",
            "data": representative_rich_recommendations_snapshot()
        })
    }

    fn representative_missing_strategy_snapshot() -> serde_json::Value {
        serde_json::json!({
            "runId": "run-strategy",
            "status": "skipped",
            "runStatus": "completed",
            "summary": "No strategy proposals were recorded for this run.",
            "artifacts": [],
            "warnings": ["No strategy proposals were recorded for this run."],
            "errors": []
        })
    }

    fn representative_rich_strategy_snapshot() -> serde_json::Value {
        serde_json::json!({
            "source": "module-recommender:recommend",
            "strategyProposals": [{
                "id": "review-codeql-scan",
                "phase": "review",
                "baseStrategy": "module recommender defaults",
                "recommendedStrategy": "run codeql:scan",
                "correctedStrategy": "run codeql:scan with authz focus",
                "appliedCorrections": [{
                    "id": "correction-review-1-authz",
                    "scope": "workspace",
                    "author": "operator",
                    "reason": "tighten review phase",
                    "fromStrategy": "run codeql:scan",
                    "toStrategy": "run codeql:scan with authz focus"
                }],
                "rationale": "small enough repository with CodeQL language coverage",
                "expectedCostUsd": null,
                "expectedRuntime": "local pass",
                "preflight": {
                    "status": "ready",
                    "notes": ["language: TypeScript"]
                },
                "resourceRisk": "low",
                "status": "proposed",
                "sourceRunId": "run-recommend",
                "tool": "codeql:scan",
                "nextInput": {"target": "/repo"},
                "createdAtMs": 1,
                "updatedAtMs": 2
            }]
        })
    }

    fn representative_missing_findings_snapshot() -> serde_json::Value {
        serde_json::json!({
            "runId": "run-findings",
            "status": "skipped",
            "runStatus": "completed",
            "summary": "No findings snapshot was recorded for this run.",
            "artifacts": [],
            "warnings": ["No findings snapshot was recorded for this run."],
            "errors": []
        })
    }

    fn representative_rich_findings_snapshot() -> serde_json::Value {
        serde_json::json!([{
            "id": "F-1",
            "fingerprint": "semgrep:src/app.ts:7",
            "tool": "semgrep",
            "ruleId": "js/sql-injection",
            "title": "SQL injection",
            "message": "query uses request input",
            "severity": "high",
            "confidence": "medium",
            "filePath": "src/app.ts",
            "startLine": 7,
            "endLine": 9,
            "staticProofState": "source_sink_linked",
            "properties": {"proofState": "source_sink_linked"},
            "cwe": ["CWE-89"],
            "evidence": "source to sink",
            "suppressed": false,
            "snoozedUntil": "2026-06-01T00:00:00Z",
            "remediation": "parameterize the query",
            "references": ["https://cwe.mitre.org/data/definitions/89.html"]
        }])
    }

    fn representative_missing_proof_snapshot() -> serde_json::Value {
        serde_json::json!({
            "runId": "run-proof",
            "status": "skipped",
            "runStatus": "completed",
            "summary": "No proof snapshot was recorded for this run.",
            "artifacts": [],
            "warnings": ["No proof snapshot was recorded for this run."],
            "errors": []
        })
    }

    fn representative_rich_proof_snapshot() -> serde_json::Value {
        serde_json::json!({
            "status": "completed",
            "summary": "1 proof state(s) recorded from normalized findings",
            "source": "normalized-findings",
            "proofLevel": "runtime-and-static",
            "runtimeVerification": true,
            "countsByState": {
                "runtime_confirmed": 1
            },
            "findings": [{
                "fingerprint": "semgrep:src/app.ts:7",
                "tool": "semgrep",
                "ruleId": "js/sql-injection",
                "filePath": "src/app.ts",
                "startLine": 7,
                "staticProofState": "runtime_confirmed"
            }]
        })
    }

    fn representative_verification_proof_snapshot() -> serde_json::Value {
        serde_json::json!({
            "kind": "verification",
            "proofLevel": 4,
            "proofVerdict": "exploited",
            "verified": 1,
            "results": [{"findingId": "F-1", "verdict": "confirmed"}]
        })
    }

    fn representative_snake_case_verification_proof_snapshot() -> serde_json::Value {
        serde_json::json!({
            "kind": "verification",
            "proof_level": 2,
            "proof_verdict": "needs-runtime-evidence",
            "verified_count": 1,
            "verification_results": [{"finding_id": "F-1", "verdict": "confirmed"}]
        })
    }

    fn assert_required_schema_fields_exist(schema: &serde_json::Value, value: &serde_json::Value) {
        for field in schema["required"].as_array().unwrap() {
            let field = field.as_str().unwrap();
            assert!(value.get(field).is_some(), "missing required field {field}");
        }
    }

    fn assert_schema_requires_any_field(schema: &serde_json::Value, fields: &[&str]) {
        let any_of = schema["anyOf"].as_array().unwrap();
        for field in fields {
            assert!(
                any_of
                    .iter()
                    .any(|entry| required_fields(entry).contains(field)),
                "schema missing alias requirement for {field}"
            );
        }
    }

    fn assert_failure_schema_requires_any_context_key(schema: &serde_json::Value) {
        let failure_schema = &schema["definitions"]["failure"];
        assert_schema_requires_any_field(
            failure_schema,
            &["agentThreadContext", "agent_thread_context"],
        );
    }

    fn assert_failure_context_schema_requires_alias_pairs(schema: &serde_json::Value) {
        let context_schema = &schema["definitions"]["failureContext"];
        for field_pair in [
            ["failedStage", "failed_stage"],
            ["whatFailed", "what_failed"],
            ["artifactsAvailable", "artifacts_available"],
            ["missingArtifacts", "missing_artifacts"],
            ["allowedProofLevel", "allowed_proof_level"],
            [
                "nextFilesOrArtifactsToInspect",
                "next_files_or_artifacts_to_inspect",
            ],
            ["recoveryOptions", "recovery_options"],
            ["fallbackPrompt", "fallback_prompt"],
            ["claimsForbidden", "claims_forbidden"],
        ] {
            assert_schema_allows_required_alias_pair(context_schema, field_pair);
        }
    }

    fn assert_schema_allows_required_alias_pair(schema: &serde_json::Value, fields: [&str; 2]) {
        let all_of = schema["allOf"].as_array().unwrap();
        assert!(
            all_of.iter().any(|entry| {
                let any_of = entry["anyOf"].as_array().unwrap();
                fields
                    .iter()
                    .all(|field| any_of.iter().any(|branch| required_fields(branch).contains(field)))
            }),
            "schema missing alias requirement pair {fields:?}"
        );
    }

    fn assert_schema_allows_required_alias_set(schema: &serde_json::Value, fields: &[&str]) {
        let all_of = schema["allOf"].as_array().unwrap();
        assert!(
            all_of.iter().any(|entry| {
                let any_of = entry["anyOf"].as_array().unwrap();
                fields
                    .iter()
                    .all(|field| any_of.iter().any(|branch| required_fields(branch).contains(field)))
            }),
            "schema missing alias requirement set {fields:?}"
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

    fn assert_serialized_fields_are_declared(schema: &serde_json::Value, value: &serde_json::Value) {
        let properties = schema["properties"].as_object().unwrap();
        for field in value.as_object().unwrap().keys() {
            assert!(properties.contains_key(field), "schema missing field {field}");
        }
    }

    fn assert_schema_declares_fields(schema: &serde_json::Value, fields: &[&str]) {
        let properties = schema["properties"].as_object().unwrap();
        for field in fields {
            assert!(properties.contains_key(*field), "schema missing field {field}");
        }
    }

    fn assert_snapshot_marker_fields_are_declared(schema: &serde_json::Value) {
        assert_schema_declares_fields(schema, &["runId", "run_id", "status", "runStatus"]);
    }

    fn assert_schema_declares_definition_fields(
        schema: &serde_json::Value,
        definition: &str,
        fields: &[&str],
    ) {
        let properties = schema["definitions"][definition]["properties"]
            .as_object()
            .unwrap();
        for field in fields {
            assert!(properties.contains_key(*field), "schema missing field {field}");
        }
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

    fn assert_artifact_aliases_reference_non_empty_string(
        artifact_schema: &serde_json::Value,
        fields: &[&str],
    ) {
        let properties = artifact_schema["properties"].as_object().unwrap();
        for field in fields {
            assert_eq!(
                properties[*field]["$ref"], "#/definitions/nonEmptyString",
                "artifact alias {field} must reject empty strings"
            );
        }
    }

    fn assert_schema_rule_matches_artifact_spec(
        rules: &[serde_json::Value],
        spec: &crate::artifact_contract::CanonicalRunArtifactSpec,
    ) {
        let rule = artifact_schema_rule(rules, spec.leaf);

        for alias in ARTIFACT_PATH_KEYS {
            assert_schema_rule_path_alias(rule, alias, spec.leaf);
        }
        assert_eq!(schema_rule_const(rule, "label"), spec.label);
        assert_eq!(schema_rule_const(rule, "name"), spec.label);
        assert_eq!(schema_rule_const(rule, "title"), spec.label);
        assert_eq!(schema_rule_const(rule, "kind"), spec.kind);
        assert_eq!(schema_rule_const(rule, "type"), spec.kind);
    }

    fn artifact_schema_rule<'a>(
        rules: &'a [serde_json::Value],
        leaf: &str,
    ) -> &'a serde_json::Value {
        let expected = artifact_path_pattern(leaf);
        rules
            .iter()
            .find(|rule| schema_rule_matches_path_alias(rule, "path", &expected))
            .unwrap_or_else(|| panic!("missing schema metadata rule for {leaf}"))
    }

    fn artifact_path_pattern(leaf: &str) -> String {
        format!("(^|/){}$", leaf.replace('.', "\\."))
    }

    fn assert_schema_rule_path_alias(rule: &serde_json::Value, alias: &str, leaf: &str) {
        let expected = artifact_path_pattern(leaf);
        assert!(
            schema_rule_matches_path_alias(rule, alias, &expected),
            "schema metadata rule for {leaf} must cover {alias}"
        );
    }

    fn schema_rule_matches_path_alias(
        rule: &serde_json::Value,
        alias: &str,
        expected: &str,
    ) -> bool {
        rule["if"]["anyOf"]
            .as_array()
            .is_some_and(|branches| branches.iter().any(|branch| path_alias_branch(branch, alias, expected)))
    }

    fn path_alias_branch(branch: &serde_json::Value, alias: &str, expected: &str) -> bool {
        required_fields(branch).contains(&alias) && branch["properties"][alias]["pattern"] == expected
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

    fn assert_llm_call_schema_requires_prompt_hash_aliases(schema: &serde_json::Value) {
        let llm_schema = &schema["definitions"]["llmCall"];
        assert_schema_requires_any_field(llm_schema, &["promptHash", "prompt_hash"]);
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
            let context = failure
                .get("agentThreadContext")
                .or_else(|| failure.get("agent_thread_context"))
                .unwrap();
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

    fn assert_recommendation_entries_match_schema(
        schema: &serde_json::Value,
        value: &serde_json::Value,
    ) {
        let recommendations = value["recommendations"].as_array().unwrap();
        assert_recommendations_match_schema(schema, recommendations);
    }

    fn assert_recommendation_report_matches_schema(
        schema: &serde_json::Value,
        report: &serde_json::Value,
    ) {
        let report_schema = schema["definitions"]["recommendationReport"]["properties"]
            .as_object()
            .unwrap();
        for field in report.as_object().unwrap().keys() {
            assert!(
                report_schema.contains_key(field),
                "recommendation report schema missing field {field}"
            );
        }
        let recommendations = report["recommendations"].as_array().unwrap();
        assert_recommendations_match_schema(schema, recommendations);
    }

    fn assert_recommendation_report_envelope_aliases_match_schema(schema: &serde_json::Value) {
        let report_schema = schema["definitions"]["recommendationReport"]["properties"]
            .as_object()
            .unwrap();

        assert_eq!(
            report_schema["recommendationReport"]["$ref"],
            serde_json::json!("#/definitions/recommendationReport")
        );
        assert_eq!(
            report_schema["recommendation_report"]["$ref"],
            serde_json::json!("#/definitions/recommendationReport")
        );
    }

    fn assert_recommendations_match_schema(
        schema: &serde_json::Value,
        recommendations: &[serde_json::Value],
    ) {
        let recommendation_schema = schema["definitions"]["recommendation"]["properties"]
            .as_object()
            .unwrap();
        for recommendation in recommendations {
            for field in recommendation.as_object().unwrap().keys() {
                assert!(
                    recommendation_schema.contains_key(field),
                    "recommendation schema missing field {field}"
                );
            }
        }
    }

    fn assert_strategy_proposal_entries_match_schema(
        schema: &serde_json::Value,
        value: &serde_json::Value,
    ) {
        let proposal_schema = schema["definitions"]["strategyProposal"]["properties"]
            .as_object()
            .unwrap();
        for proposal in value["strategyProposals"].as_array().unwrap() {
            for field in proposal.as_object().unwrap().keys() {
                assert!(
                    proposal_schema.contains_key(field),
                    "strategy proposal schema missing field {field}"
                );
            }
            let correction_schema = schema["definitions"]["appliedCorrection"]["properties"]
                .as_object()
                .unwrap();
            for correction in proposal["appliedCorrections"].as_array().unwrap() {
                for field in correction.as_object().unwrap().keys() {
                    assert!(
                        correction_schema.contains_key(field),
                        "applied strategy correction schema missing field {field}"
                    );
                }
            }
        }
    }

    fn assert_finding_entries_match_schema(schema: &serde_json::Value, value: &serde_json::Value) {
        let finding_schema = schema["definitions"]["finding"]["properties"]
            .as_object()
            .unwrap();
        for finding in value.as_array().unwrap() {
            for field in finding.as_object().unwrap().keys() {
                assert!(
                    finding_schema.contains_key(field),
                    "finding schema missing field {field}"
                );
            }
        }
    }

    fn assert_proof_finding_entries_match_schema(
        schema: &serde_json::Value,
        value: &serde_json::Value,
    ) {
        let finding_schema = schema["definitions"]["proofFinding"]["properties"]
            .as_object()
            .unwrap();
        for finding in value["findings"].as_array().unwrap() {
            for field in finding.as_object().unwrap().keys() {
                assert!(
                    finding_schema.contains_key(field),
                    "proof finding schema missing field {field}"
                );
            }
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
    }
}
