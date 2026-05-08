#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn whitebox_static_policy_disables_execution_features_and_proof_states() {
        let (sanitized, policy) = apply_whitebox_static_sast_policy(json!({
            "mode": "whitebox-static",
            "verify": true,
            "autoPatch": true,
            "pocHarness": true,
            "pocExecution": true,
            "dynamicAnalysis": true,
            "cryptoBehavioralTesting": true,
            "patching": true,
            "proofState": "execution_confirmed",
            "proofStates": ["signal_only", "runtime_confirmed"]
        }))
        .unwrap();
        let policy = policy.unwrap();

        assert!(policy.enabled);
        assert!(!policy.verify);
        assert!(!policy.poc_harness);
        assert!(!policy.poc_execution);
        assert!(!policy.dynamic_analysis);
        assert!(!policy.crypto_behavioral_testing);
        assert!(!policy.patching);
        assert!(!policy.auto_patch);
        assert!(!policy.execution_proof_states);
        assert!(!policy.runtime_exploitability_claims);
        assert_eq!(sanitized["verify"], json!(false));
        assert_eq!(sanitized["autoPatch"], json!(false));
        assert_eq!(sanitized["proofState"], json!("needs_runtime_evidence"));
        assert_eq!(sanitized["proofStates"], json!(["needs_runtime_evidence"]));
        assert!(!serde_json::to_string(&sanitized)
            .unwrap()
            .contains("execution_confirmed"));
    }

    #[test]
    fn standard_mode_preserves_input() {
        let input = json!({"mode": "standard", "verify": true});
        let (sanitized, policy) = apply_whitebox_static_sast_policy(input.clone()).unwrap();

        assert_eq!(sanitized, input);
        assert!(policy.is_none());
    }

    #[test]
    fn whitebox_agent_tools_are_read_only_repo_tools() {
        let policy = default_whitebox_static_agent_tool_policy();

        assert_eq!(policy.profile, "whitebox-static");
        assert_eq!(policy.tools, vec!["Read", "Glob", "Grep", "LS"]);
        validate_whitebox_static_agent_tool_policy(&policy).unwrap();
    }

    #[test]
    fn whitebox_agent_tools_reject_shell_write_and_patch_tools() {
        for forbidden in ["Bash", "shell", "Write", "Edit", "patch", "apply_patch"] {
            let policy = AgentToolPolicy::new("whitebox-static", ["Read", forbidden]);
            let err = validate_whitebox_static_agent_tool_policy(&policy)
                .unwrap_err()
                .to_string();

            assert!(err.contains("cannot include execution or write tool"));
        }
    }

    #[test]
    fn whitebox_agent_tools_reject_non_repo_read_only_tools() {
        let policy = AgentToolPolicy::new("whitebox-static", ["Read", "Fetch"]);
        let err = validate_whitebox_static_agent_tool_policy(&policy)
            .unwrap_err()
            .to_string();

        assert!(err.contains("can only include read-only repo tools"));
    }

    #[test]
    fn standard_mode_gets_default_empty_agent_tool_policy() {
        let policy = agent_tool_policy_for_input(&json!({"mode": "standard"})).unwrap();

        assert!(policy.is_default());
    }

    #[test]
    fn whitebox_mode_gets_read_only_agent_tool_policy() {
        let policy = agent_tool_policy_for_input(&json!({"mode": "whitebox-static"})).unwrap();

        assert_eq!(policy.profile, "whitebox-static");
        assert_eq!(policy.tools, vec!["Read", "Glob", "Grep", "LS"]);
    }

    #[test]
    fn whitebox_triage_prompt_schema_names_static_fields_and_forbids_dynamic_work() {
        let system = whitebox_static_triage_system_prompt();
        let prompt_block = whitebox_static_triage_prompt_block();

        for field in [
            "\"verdict\"",
            "\"staticProofState\"",
            "\"source\"",
            "\"sink\"",
            "\"path\"",
            "\"sanitizerAssessment\"",
            "\"guardAssessment\"",
            "\"citations\"",
            "\"assumptions\"",
            "\"missingEvidence\"",
            "\"triggerNarrative\"",
            "\"impactNarrative\"",
            "\"recommendedFix\"",
        ] {
            assert!(system.contains(field), "missing schema field {field}");
        }

        for forbidden in [
            "Do not include payloads",
            "PoCs",
            "exploit execution",
            "runtime exploitability claims",
            "no active exploitation",
            "no HTTP replay",
            "no fuzzing",
            "no live target scanning",
            "no PoC generation",
            "no PoC execution",
        ] {
            assert!(
                system.contains(forbidden) || prompt_block.contains(forbidden),
                "whitebox triage prompt did not forbid {forbidden}"
            );
        }
    }

    #[test]
    fn static_proof_state_from_whitebox_input_downgrades_execution_confirmation() {
        let state = whitebox_static_proof_state_from_input(&json!({
            "staticProofState": "execution_confirmed"
        }))
        .unwrap();

        assert_eq!(state, Some(StaticProofState::NeedsRuntimeEvidence));
    }

    #[test]
    fn static_proof_marking_sets_default_without_execution_states() {
        let mut findings = vec![
            Finding::new_semgrep(
                "demo.signal",
                "src/app.ts",
                1,
                Some(1),
                crate::findings::Severity::High,
                "scanner signal",
            ),
            Finding::new_semgrep(
                "demo.linked",
                "src/db.ts",
                5,
                Some(5),
                crate::findings::Severity::High,
                "source reaches sink",
            )
            .with_static_proof_state(StaticProofState::SourceSinkLinked),
        ];

        mark_whitebox_static_findings(&mut findings, StaticProofState::SignalOnly).unwrap();

        assert_eq!(
            findings[0].static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
        assert_eq!(
            findings[1].static_proof_state,
            Some(StaticProofState::SourceSinkLinked)
        );
    }
}
